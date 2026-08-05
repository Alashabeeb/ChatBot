import axios from 'axios';
import { OPENSEARCH_URL, WAZUH_USER, WAZUH_PASSWORD } from '../config/env.js';
import { httpsAgent } from '../config/https.js';

/**
 * Capability: searchSecurityLogs
 * Searches underlying data lakes or SIEM indexes for security logs matching specific criteria.
 */
export async function searchSecurityLogs(params) {
    const { timeRange, lteTime, minSeverity, extractedIPs, intent, cleanedSearchText } = params;

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
        size: 10000,
        track_total_hits: true
    };

    if (minSeverity !== null) {
        esQuery.query.bool.filter.push({ range: { "rule.level": { gte: minSeverity } } });
    }

    if (extractedIPs && extractedIPs.length > 0) {
        esQuery.query.bool.must.push({ multi_match: { query: extractedIPs[0], fields: ["*ip*", "*ip", "ip", "full_log", "agent.ip", "data.win.eventdata.ipAddress"], lenient: true } });
    }

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
    } else if (cleanedSearchText && cleanedSearchText.length > 2 && (!extractedIPs || extractedIPs.length === 0)) {
        esQuery.query.bool.must.push({ multi_match: { query: cleanedSearchText, fields: ["rule.description", "full_log"], lenient: true } });
    }

    const authString = Buffer.from(`${WAZUH_USER}:${WAZUH_PASSWORD}`).toString('base64');
    
    let targetIndex = `${OPENSEARCH_URL}/wazuh-alerts-*/_search`;
    if (intent === 'vulnerabilities') {
        targetIndex = `${OPENSEARCH_URL}/wazuh-states-vulnerabilities-*,wazuh-alerts-*/_search`;
    }

    const osResponse = await axios.post(targetIndex, esQuery, {
        headers: { Authorization: `Basic ${authString}`, 'Content-Type': 'application/json' },
        httpsAgent
    });

    const rawData = osResponse.data.hits.hits.map(hit => hit._source);
    const totalHits = osResponse.data.hits.total.value || rawData.length;

    return {
        rawData,
        totalHits,
        targetIndex
    };
}
