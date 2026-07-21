require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3002;
// Use port 9200 for OpenSearch instead of the blocked Wazuh API
const OPENSEARCH_URL = 'https://10.0.126.250:9200';
const WAZUH_USER = process.env.WAZUH_USER;
const WAZUH_PASSWORD = process.env.WAZUH_PASSWORD;
const LLAMA_API_URL = process.env.LLAMA_API_URL || 'http://localhost:11434/api/generate';

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

/**
 * 1. Ask Llama 3 (Graceful Fallback if Llama is down)
 */
async function askLlama(prompt, systemInstruction) {
  try {
    const response = await axios.post(LLAMA_API_URL, {
      model: 'llama3',
      prompt: prompt,
      system: systemInstruction,
      stream: false
    }, { timeout: 10000 });
    return response.data.response.trim();
  } catch (error) {
    console.warn("Llama 3 Unreachable. Falling back to rule-based logic.");
    return null;
  }
}

/**
 * Handle chat queries using OpenSearch (Wazuh Indexer)
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

    const lowerText = text.toLowerCase();
    
    // Step 1: Intelligent Intent Classification
    const classificationPrompt = `User asked: "${text}". Which Wazuh log category should I query? Reply with exactly one word: [brute_force, vulnerabilities, alerts, unknown].`;
    let intent = await askLlama(classificationPrompt, "You are a classifier.");
    
    // Fallback if Llama 3 is down or returns junk
    if (!intent || intent.length > 20) {
      if (lowerText.includes('brute') || lowerText.includes('fail') || lowerText.includes('login')) intent = 'brute_force';
      else if (lowerText.includes('vulnerab') || lowerText.includes('cve')) intent = 'vulnerabilities';
      else intent = 'alerts'; // Default to generic alerts
    }
    intent = intent.toLowerCase();

    // Step 2: Build OpenSearch Query DSL
    let esQuery = {
      query: { match_all: {} },
      sort: [{ "@timestamp": { order: "desc" } }],
      size: 15
    };

    if (intent.includes('brute')) {
      esQuery = {
        query: { match: { "rule.groups": "authentication_failures" } },
        sort: [{ "@timestamp": { order: "desc" } }],
        size: 15
      };
    } else if (intent.includes('vulnerab')) {
      esQuery = {
        query: { match: { "rule.groups": "vulnerability-detector" } },
        sort: [{ "@timestamp": { order: "desc" } }],
        size: 15
      };
    }

    // Step 3: Fetch REAL data from OpenSearch (Wazuh Indexer)
    const authString = Buffer.from(`${WAZUH_USER}:${WAZUH_PASSWORD}`).toString('base64');
    const osResponse = await axios.post(`${OPENSEARCH_URL}/wazuh-alerts-*/_search`, esQuery, {
      headers: { 
        Authorization: `Basic ${authString}`,
        'Content-Type': 'application/json'
      },
      httpsAgent
    });
    
    // Extract the raw source documents from the OpenSearch hits
    const rawData = osResponse.data.hits.hits.map(hit => hit._source);
    const sourceLabel = `wazuh-indexer /wazuh-alerts-* (${intent})`;

    // Step 4: Summarize the data (Llama or Fallback)
    let summary = '';
    const summaryPrompt = `User asked: "${text}". Here is the raw SIEM JSON data from OpenSearch: ${JSON.stringify(rawData).substring(0, 1500)}. Write a concise, 2-sentence summary answering the user. Do not say "based on the JSON".`;
    
    const llamaSummary = await askLlama(summaryPrompt, "You are a senior SOC analyst. Summarize security data clearly.");
    
    if (llamaSummary) {
      summary = llamaSummary;
    } else {
      // Hardcoded fallback summary if Llama isn't running
      if (rawData.length === 0) {
        summary = `No recent ${intent} alerts found in the Wazuh Indexer.`;
      } else {
        summary = `Successfully retrieved ${rawData.length} recent ${intent} alerts from the Wazuh Indexer. Click "View Full Details" to see the raw JSON logs.`;
      }
    }

    // Step 5: Return Summary + REAL Raw Data to React UI
    return res.json({
      type: 'agent_response',
      source: sourceLabel,
      summary: summary,
      raw_logs: rawData,
      footer: llamaSummary ? 'Analyzed by Llama 3 (via OpenSearch)' : 'Retrieved via OpenSearch (Llama 3 offline)'
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
