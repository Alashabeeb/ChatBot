require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3002;
const OPENSEARCH_URL = 'https://10.0.126.250:9200';
const WAZUH_USER = process.env.WAZUH_USER;
const WAZUH_PASSWORD = process.env.WAZUH_PASSWORD;
// Use environment variable for the LLM API URL (Fallback to port 8081 if not set)
const LLM_API_URL = process.env.LLM_API_URL || 'http://127.0.0.1:8081/v1/chat/completions';

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

/**
 * Single LLM Call for Summarization using custom foundation-sec-8b-instruct
 */
async function askLLM(prompt, systemInstruction) {
  try {
    const response = await axios.post(LLM_API_URL, {
      model: 'foundation-sec-8b-instruct',
      messages: [
        { role: "system", content: systemInstruction },
        { role: "user", content: prompt }
      ]
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
  const { text, sources } = req.body;

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
    // ==========================================
    const greetings = ['hi', 'hello', 'hey', 'help', 'who are you', 'what can you do', 'good morning', 'good afternoon'];
    // If the text is exactly a greeting or starts with a greeting and is very short
    if (greetings.includes(lowerText) || (greetings.some(g => lowerText.startsWith(g)) && lowerText.length < 15)) {
      return res.json({
        type: 'text',
        text: 'Hello! I am your AI SOC Assistant. I am directly connected to the Wazuh SIEM Indexer. You can ask me to "check this IP 190.03.12.56", "find brute force attacks", or "show recent vulnerabilities".'
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
      size: 10000, // Pulling the absolute maximum allowed by OpenSearch in a single request
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
      const systemInstruction = `You are a strict SIEM AI Analyst. You MUST answer the user's question using ONLY the provided OpenSearch Context. If the user asks for a total count or 'how many', you MUST use the explicitly provided 'total matching alerts' number as the exact and absolute answer. Do NOT manually count the logs.`;

      // 3. Inject True Count into Prompt
      const summaryPrompt = `User asked: "${text}"\n\nOpenSearch returned an exact total of ${totalHits} matching alerts in the entire database. Here is a sample of the top ${minifiedLogs.length} most recent logs to analyze for patterns:\n${JSON.stringify(minifiedLogs)}`;
      
      const llamaSummary = await askLLM(summaryPrompt, systemInstruction);
      
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
