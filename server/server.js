require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3002;
const OPENSEARCH_URL = process.env.OPENSEARCH_URL;
const WAZUH_USER = process.env.WAZUH_USER;
const WAZUH_PASSWORD = process.env.WAZUH_PASSWORD;
const WAZUH_SERVER_API_URL = process.env.WAZUH_SERVER_API_URL;
// Use environment variable for the LLM API URL
const LLM_API_URL = process.env.LLM_API_URL;

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

let wazuhToken = null;
let tokenExpiresAt = 0; // Epoch time

async function getWazuhToken() {
  if (wazuhToken && Date.now() < tokenExpiresAt) {
    return wazuhToken;
  }
  
  try {
    const authString = Buffer.from(`${WAZUH_USER}:${WAZUH_PASSWORD}`).toString('base64');
    const response = await axios.post(`${WAZUH_SERVER_API_URL}/security/user/authenticate?raw=true`, null, {
      headers: {
        Authorization: `Basic ${authString}`
      },
      httpsAgent
    });
    wazuhToken = response.data;
    tokenExpiresAt = Date.now() + 14 * 60 * 1000; // 14 mins
    return wazuhToken;
  } catch (error) {
    console.error("Failed to authenticate with Wazuh API:", error.message);
    throw new Error("Wazuh API Authentication Failed");
  }
}

/**
 * Single LLM Call for Summarization using custom foundation-sec-8b-instruct
 */
async function askLLM(prompt, systemInstruction, conversationHistory = []) {
  try {
    // Build the messages array with conversation memory
    const messages = [
      { role: "system", content: systemInstruction }
    ];

    // Inject previous conversation history so the AI remembers context
    for (const msg of conversationHistory) {
      messages.push({ role: msg.role, content: msg.content });
    }

    // Add the current question
    messages.push({ role: "user", content: prompt });

    const response = await axios.post(LLM_API_URL, {
      model: 'foundation-sec-8b-instruct',
      messages
    }, { timeout: 0 });
    
    return response.data.choices[0].message.content.trim();
  } catch (error) {
    console.warn("Custom LLM Unreachable. Falling back to rule-based logic.", error.message);
    return null;
  }
}

/**
 * Handle chat queries efficiently
 */
app.post('/api/chat', async (req, res) => {
  const { text, sources, history = [] } = req.body;

  try {
    if (!sources || (!sources.includes('wazuh') && !sources.includes('all'))) {
      return res.json({
        type: 'text',
        text: 'Please select Wazuh from the Agents dropdown to query security data.'
      });
    }

    const lowerText = text.toLowerCase().trim();
    
    // ==========================================
    // ZERO-LATENCY CONVERSATIONAL FAST-PATH
    // Catches ALL non-SIEM messages before they hit OpenSearch
    // ==========================================
    
    // 1. Direct greetings and small talk
    const greetings = ['hi', 'hello', 'hey', 'help', 'who are you', 'what can you do', 
      'good morning', 'good afternoon', 'good evening', 'thanks', 'thank you', 
      'ok', 'okay', 'yes', 'no', 'bye', 'goodbye', 'sure'];
    
    if (greetings.includes(lowerText) || (greetings.some(g => lowerText.startsWith(g)) && lowerText.length < 20)) {
      return res.json({
        type: 'text',
        text: 'Hello! I am your AI SOC Assistant powered by Cisco Foundation Sec 8B. I am directly connected to the Wazuh SIEM Indexer. Here is what I can do:\n\n• **Check an IP:** "Check this IP 190.03.12.56"\n• **Find attacks:** "Show me brute force attacks"\n• **Count alerts:** "How many authentication failures today?"\n• **Find vulnerabilities:** "Show recent CVEs"\n• **Investigate users:** "Show login failures for admin"'
      });
    }

    // 2. Catch general conversational phrases that are NOT security queries
    const conversationalPatterns = [
      'i need', 'can you', 'could you', 'please help', 'assist me', 'i want',
      'tell me about yourself', 'what are you', 'how do you work', 'are you',
      'do you', 'i have a question', 'i was wondering', 'how are you',
      'what is your', 'who made you', 'explain', 'teach me'
    ];
    
    const hasSecurityKeyword = /\b(ip|alert|attack|brute|fail|login|auth|cve|vulnerab|threat|malware|firewall|intrusion|port|scan|agent|log|event|wazuh|siem|rule|mitre|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/i.test(lowerText);
    
    if (conversationalPatterns.some(p => lowerText.includes(p)) && !hasSecurityKeyword) {
      return res.json({
        type: 'text',
        text: 'I am your AI SOC Assistant, and I am here to help! I specialize in analyzing your Wazuh SIEM security data in real-time. Try asking me something like:\n\n• "Check this IP address 41.203.12.56"\n• "Show me the total authentication failures for the last 24 hours"\n• "What are the latest vulnerability alerts?"\n• "Find brute force attacks targeting our network"\n\nJust type your security question and I will query the live database for you!'
      });
    }

    // ==========================================
    // INSTANT INTENT & ENTITY EXTRACTION
    // ==========================================
    let intent = 'alerts'; // Default
    if (lowerText.includes('brute') || lowerText.includes('fail') || lowerText.includes('login') || lowerText.includes('auth')) intent = 'brute_force';
    else if (lowerText.includes('vulnerab') || lowerText.includes('cve')) intent = 'vulnerabilities';
    else if (/\b(agent|agents|endpoint|endpoints)\b/.test(lowerText) || /\b(connected|disconnected|active)\b/.test(lowerText)) intent = 'agent_inventory';
    else if (/\b(manager|server status|daemons)\b/.test(lowerText)) intent = 'manager_status';

    // Extract IPv4 addresses
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    const extractedIPs = text.match(ipRegex) || [];

    // Extract Severity Level Constraint
    let minSeverity = null;
    const severityMatch = lowerText.match(/(?:level|severity)\s*(\d+)(?:\s*(?:and|or)?\s*(?:above|higher|up|\+))?/i);
    if (severityMatch) {
      minSeverity = parseInt(severityMatch[1], 10);
    } else if (/\bsevere\b/i.test(lowerText) || /\bhigh severity\b/i.test(lowerText)) {
      minSeverity = 7; // Wazuh level 7 is 'High'
    } else if (/\bcritical\b/i.test(lowerText)) {
      minSeverity = 12; // Wazuh level 12 is 'Critical'
    }

    // Extract Dynamic Time Window (Default: Last 24 Hours)
    let timeRange = 'now-24h';
    let lteTime = null;
    let timeLabel = 'Last 24 Hours';
    let chronoTimeStr = '';

    const chrono = require('chrono-node');
    const parsedDates = chrono.parse(text);

    if (parsedDates.length > 0) {
      const result = parsedDates[0];
      timeRange = result.start.date().toISOString();
      if (result.end) {
        lteTime = result.end.date().toISOString();
      }
      timeLabel = result.text;
      chronoTimeStr = result.text.toLowerCase();
    } else {
      if (/\b(1h|1\s*hr|1\s*hour|past\s*hour|last\s*hour|60\s*m|60\s*min)\b/i.test(lowerText)) {
        timeRange = 'now-1h';
        timeLabel = 'Past 1 Hour';
      } else if (/\b(30m|30\s*min|30\s*mins|past\s*30\s*min)\b/i.test(lowerText)) {
        timeRange = 'now-30m';
        timeLabel = 'Past 30 Minutes';
      } else if (/\b(12h|12\s*hr|12\s*hours)\b/i.test(lowerText)) {
        timeRange = 'now-12h';
        timeLabel = 'Past 12 Hours';
      } else if (/\b(7d|7\s*days|week|past\s*week|last\s*week)\b/i.test(lowerText)) {
        timeRange = 'now-7d';
        timeLabel = 'Past 7 Days';
      } else if (/\b(30d|30\s*days|month|past\s*month|last\s*month)\b/i.test(lowerText)) {
        timeRange = 'now-30d';
        timeLabel = 'Past 30 Days';
      } else if (/\b(24h|24\s*hr|24\s*hours|today|last\s*24\s*hours)\b/i.test(lowerText)) {
        timeRange = 'now-24h';
        timeLabel = 'Last 24 Hours';
      }
    }

    // Strip ONLY grammatical/question filler words and time phrases (PRESERVE security terms like auth, failure, login, cve, ip)
    const stopWords = /\b(what|is|are|the|for|past|last|show|me|get|give|total|find|check|count|many|how|all|any|recent|hours|hour|hr|hrs|mins|min|minutes|days|day|today|yesterday|from|to|pm|am|please|can|you|could|level|severity|severe|critical|high|above|higher|up)\b/gi;
    let cleanedSearchText = lowerText.replace(stopWords, '');
    if (chronoTimeStr) {
      cleanedSearchText = cleanedSearchText.replace(chronoTimeStr, '');
    }
    cleanedSearchText = cleanedSearchText.replace(/\s+/g, ' ').trim();

    // ==========================================
    // WAZUH SERVER API (Agents / Manager Status)
    // ==========================================
    if (intent === 'agent_inventory' || intent === 'manager_status') {
      try {
        const token = await getWazuhToken();
        let apiUrl = '';
        let apiQuery = {};
        
        if (intent === 'agent_inventory') {
          let wqlStatus = '';
          if (lowerText.includes('disconnected')) wqlStatus = 'status=disconnected';
          else if (lowerText.includes('active') || lowerText.includes('connected')) wqlStatus = 'status=active';
          
          apiUrl = `${WAZUH_SERVER_API_URL}/agents`;
          apiQuery = { limit: 500, pretty: true, select: 'id,name,status,ip,os.name,os.version' };
          if (wqlStatus) apiQuery.q = wqlStatus;
          
        } else if (intent === 'manager_status') {
          apiUrl = `${WAZUH_SERVER_API_URL}/manager/status`;
          apiQuery = { pretty: true };
        }
        
        const apiResponse = await axios.get(apiUrl, {
          headers: { Authorization: `Bearer ${token}` },
          params: apiQuery,
          httpsAgent
        });
        
        const rawData = apiResponse.data.data.affected_items || [apiResponse.data.data];
        const totalHits = apiResponse.data.data.total_affected_items || rawData.length;
        
        const sourceLabel = `wazuh-server-api ${new URL(apiUrl).pathname}`;
        let summary = '';
        
        if (totalHits === 0) {
          summary = `I checked the Wazuh Server API, but found zero results for your query.`;
        } else {
          const systemInstruction = `You are a strict SIEM AI Analyst answering a question about the Wazuh system status or agent inventory.
1. Use the EXACT data from the API response below.
2. State the exact counts of agents or daemon statuses.
3. Be concise and professional.`;

          const summaryPrompt = `User asked: "${text}"
          
API ENDPOINT: ${apiUrl}
TOTAL RESULTS: ${totalHits}
API DATA:
${JSON.stringify(rawData)}`;
          
          const llamaSummary = await askLLM(summaryPrompt, systemInstruction, history);
          summary = llamaSummary || `Successfully retrieved ${totalHits} items from the Wazuh Server API.`;
        }
        
        return res.json({
          type: 'agent_response',
          source: sourceLabel,
          summary: summary,
          raw_logs: rawData,
          total_hits: totalHits,
          footer: 'Analyzed by foundation-sec-8b'
        });
      } catch (error) {
        console.error('Server API Error:', error.message);
        return res.status(500).json({
          type: 'text',
          text: `⚠️ Wazuh Server API Connection Error: ${error.message}. Please ensure port 55000 is reachable.`
        });
      }
    }

    // ==========================================
    // BUILD HIGHLY ACCURATE OPENSEARCH QUERY WITH TIME FILTER
    // ==========================================
    const timeFilter = { gte: timeRange };
    if (lteTime) timeFilter.lte = lteTime;

    let esQuery = {
      query: {
        bool: {
          must: [],
          filter: [
            { range: { "@timestamp": timeFilter } }
          ]
        }
      },
      sort: [{ "@timestamp": { order: "desc" } }],
      size: 10000, // Fetch up to 10000 logs for frontend pagination
      track_total_hits: true // Force OpenSearch to count exact total
    };

    if (minSeverity !== null) {
      esQuery.query.bool.filter.push({ range: { "rule.level": { gte: minSeverity } } });
    }

    // If an IP was found, force OpenSearch to only return logs containing this IP!
    if (extractedIPs.length > 0) {
      esQuery.query.bool.must.push({ multi_match: { query: extractedIPs[0], fields: ["*ip*", "*ip", "ip", "full_log", "agent.ip", "data.win.eventdata.ipAddress"], lenient: true } });
    }

    // Add specific SIEM filters based on intent
    if (intent === 'brute_force') {
      esQuery.query.bool.must.push({
        bool: {
          should: [
            { match: { "rule.groups": "authentication_failed" } },
            { match: { "rule.groups": "authentication_failures" } },
            { match: { "rule.groups": "sshd" } },
            { match_phrase: { "rule.description": "failed" } },
            { match_phrase: { "rule.description": "failure" } }
          ],
          minimum_should_match: 1
        }
      });
    } else if (intent === 'vulnerabilities') {
      esQuery.query.bool.must.push({
        bool: {
          should: [
            { match: { "rule.groups": "vulnerability-detector" } },
            { match_phrase: { "rule.description": "vulnerability" } },
            { match_phrase: { "rule.description": "cve" } }
          ],
          minimum_should_match: 1
        }
      });
    } else if (cleanedSearchText.length > 2 && extractedIPs.length === 0) {
      // General search on remaining security terms
      esQuery.query.bool.must.push({ multi_match: { query: cleanedSearchText, fields: ["rule.description", "full_log"], lenient: true } });
    }

    // ==========================================
    // FETCH REAL DATA (Official Wazuh Indexer Specs)
    // ==========================================
    const authString = Buffer.from(`${WAZUH_USER}:${WAZUH_PASSWORD}`).toString('base64');
    
    // Choose index based on intent according to official Wazuh docs:
    // Alerts -> /wazuh-alerts-*/_search
    // Vulnerabilities -> /wazuh-states-vulnerabilities-*/_search,wazuh-alerts-*/_search
    let targetIndex = `${OPENSEARCH_URL}/wazuh-alerts-*/_search`;
    if (intent === 'vulnerabilities') {
      targetIndex = `${OPENSEARCH_URL}/wazuh-states-vulnerabilities-*,wazuh-alerts-*/_search`;
    }

    const osResponse = await axios.post(targetIndex, esQuery, {
      headers: { Authorization: `Basic ${authString}`, 'Content-Type': 'application/json' },
      httpsAgent
    });
    const rawData = osResponse.data.hits.hits.map(hit => hit._source);
    // Extract true total from OpenSearch
    const totalHits = osResponse.data.hits.total.value || rawData.length;
    
    let sourceLabel = `wazuh-indexer /wazuh-alerts-* [${timeLabel}]`;
    if (extractedIPs.length > 0) sourceLabel += ` (Target: ${extractedIPs[0]})`;

    // ==========================================
    // LLM SUMMARIZATION WITH TIME WINDOW CONSTRAINTS
    // ==========================================
    let summary = '';
    
    if (rawData.length === 0) {
      summary = extractedIPs.length > 0 
        ? `I scanned the SIEM logs for the ${timeLabel}, but found zero alerts for IP ${extractedIPs[0]}. You can ask for a wider window (e.g. "past 7 days").` 
        : `I searched the database for the ${timeLabel}, but found zero matching alerts. You can try adjusting the time range (e.g. "past 7 days").`;
    } else {
      // 1. Minify logs according to official Wazuh alert & vulnerability index schemas
      // ONLY pass the top 50 logs to the LLM to avoid exceeding 8K token context window!
      const minifiedLogs = rawData.slice(0, 50).map(log => ({
        time: log['@timestamp'] || log.vulnerability?.detected_at || 'N/A',
        level: typeof log.rule?.level === 'number' ? log.rule.level : log.vulnerability?.severity || 0,
        desc: log.rule?.description || log.vulnerability?.description || 'N/A',
        srcip: log.data?.srcip || log.srcip || log.agent?.ip || 'N/A',
        user: log.data?.srcuser || log.data?.dstuser || log.data?.user || 'N/A',
        agent: log.agent?.name || log.agent?.id || 'N/A',
        cve: log.vulnerability?.id || 'N/A'
      }));

      // 2. Strict RAG System Prompt
      const systemInstruction = `You are an elite AI SOC Security Analyst. Your job is to analyze Wazuh SIEM logs and provide highly refined, actionable insights. Rules:
1. The "TOTAL MATCHES" number is the exact, verified count for the ${timeLabel}. Always state this count and explicitly state that the data is from the ${timeLabel}.
2. Use the SAMPLE LOGS to deeply analyze the situation. Do NOT just mechanically list IPs. Explain WHAT the attack or pattern is, HOW it works, and WHY it is happening. Provide a detailed and refined explanation of the security context.
3. Provide clear, actionable REMEDIATION STEPS (e.g., "Block these IPs", "Investigate this user account").
4. Never say "based on 50 logs". Speak authoritatively as if analyzing the complete dataset for this time window.
5. If severity constraints (e.g., level 3+) were requested, confirm you are showing the severe incidents.`;

      // 3. Inject True Count and Time Window into Prompt
      const summaryPrompt = `User asked: "${text}"

TIME WINDOW ANALYZED: ${timeLabel} (${timeRange})
EXACT TOTAL MATCHES IN ${timeLabel.toUpperCase()}: ${totalHits}
SAMPLE LOGS (TOP ${minifiedLogs.length}):
${JSON.stringify(minifiedLogs)}`;
      
      const llamaSummary = await askLLM(summaryPrompt, systemInstruction, history);
      
      if (llamaSummary) {
        summary = llamaSummary;
      } else {
        // CPU fallback
        summary = `Successfully retrieved ${totalHits} alerts from the Wazuh Indexer matching your query. Click "View Full Details" to see the raw JSON logs.`;
      }
    }

    return res.json({
      type: 'agent_response',
      source: sourceLabel,
      summary: summary,
      raw_logs: rawData,
      total_hits: totalHits,
      footer: summary.includes('SIEM logs found') || rawData.length === 0 ? 'Processed Instantly' : 'Analyzed by foundation-sec-8b'
    });

  } catch (error) {
    console.error('API Error:', error.message);
    res.status(500).json({
      type: 'text',
      text: `⚠️ Wazuh Indexer Connection Error: ${error.message}. Please ensure port 9200 is reachable.`
    });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 AI SOC Proxy Server running on port ${PORT}`);
  console.log(`OpenSearch URL: ${OPENSEARCH_URL}`);
});
