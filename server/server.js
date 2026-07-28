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
// Use environment variable for the LLM API URL
const LLM_API_URL = process.env.LLM_API_URL;

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

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
    // INSTANT INTENT & ENTITY EXTRACTION (NO LLAMA DELAY)
    // ==========================================
    let intent = 'alerts'; // Default
    if (lowerText.includes('brute') || lowerText.includes('fail') || lowerText.includes('login')) intent = 'brute_force';
    else if (lowerText.includes('vulnerab') || lowerText.includes('cve')) intent = 'vulnerabilities';

    // Extract IPv4 addresses
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    const extractedIPs = text.match(ipRegex) || [];

    // ==========================================
    // BUILD HIGHLY ACCURATE OPENSEARCH QUERY
    // ==========================================
    let esQuery = {
      query: { bool: { must: [] } },
      sort: [{ "@timestamp": { order: "desc" } }],
      size: 50, // Max safe limit for 8K token context window. Do not exceed this or the LLM throws HTTP 400!
      track_total_hits: true // Force OpenSearch to count past 10,000 to infinity!
    };

    // If an IP was found, force OpenSearch to only return logs containing this IP!
    if (extractedIPs.length > 0) {
      esQuery.query.bool.must.push({ query_string: { query: extractedIPs[0] } });
    } else {
      // If no IP, just search their whole sentence text
      esQuery.query.bool.must.push({ query_string: { query: text, default_operator: "OR" } });
    }

    // Add specific SIEM filters
    if (intent === 'brute_force') {
      esQuery.query.bool.must.push({ match: { "rule.groups": "authentication_failures" } });
    } else if (intent === 'vulnerabilities') {
      esQuery.query.bool.must.push({ match: { "rule.groups": "vulnerability-detector" } });
    }

    // ==========================================
    // FETCH REAL DATA
    // ==========================================
    const authString = Buffer.from(`${WAZUH_USER}:${WAZUH_PASSWORD}`).toString('base64');
    const osResponse = await axios.post(`${OPENSEARCH_URL}/wazuh-alerts-*/_search`, esQuery, {
      headers: { Authorization: `Basic ${authString}`, 'Content-Type': 'application/json' },
      httpsAgent
    });
    const rawData = osResponse.data.hits.hits.map(hit => hit._source);
    // Extract true total from OpenSearch
    const totalHits = osResponse.data.hits.total.value || rawData.length;
    
    let sourceLabel = `wazuh-indexer /wazuh-alerts-*`;
    if (extractedIPs.length > 0) sourceLabel += ` (Target: ${extractedIPs[0]})`;

    // ==========================================
    // SINGLE LLAMA 3 SUMMARIZATION
    // ==========================================
    let summary = '';
    
    if (rawData.length === 0) {
      // Fast path if nothing was found! No need to ask Llama.
      summary = extractedIPs.length > 0 
        ? `I scanned the SIEM logs, but I did not find any alerts related to the IP address ${extractedIPs[0]}.` 
        : `I could not find any alerts matching your request in the SIEM database.`;
    } else {
      // 1. Minify logs to prevent JSON breakage and token bloat
      const minifiedLogs = rawData.map(log => ({
        time: log['@timestamp'],
        level: log.rule?.level,
        desc: log.rule?.description,
        srcip: log.data?.srcip || log.srcip || 'N/A',
        user: log.data?.srcuser || log.data?.dstuser || log.data?.user || 'N/A'
      }));

      // 2. Strict RAG System Prompt
      const systemInstruction = `You are a SIEM AI Analyst. Rules:
1. The "TOTAL MATCHES" number is the exact, verified count from the database. Always use it as fact.
2. The "SAMPLE LOGS" below are a representative snapshot. Analyze them for patterns (top IPs, attack types, affected users).
3. Never say "based on the 50 logs" or "I can only see X logs". Speak as if you analyzed the full dataset.
4. Answer the user's question directly and comprehensively.`;

      // 3. Inject True Count into Prompt
      const summaryPrompt = `User asked: "${text}"

TOTAL MATCHES: ${totalHits}
SAMPLE LOGS:
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
