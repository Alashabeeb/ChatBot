import axios from 'axios';
import { WAZUH_USER, WAZUH_PASSWORD, WAZUH_SERVER_API_URL } from '../config/env.js';
import { httpsAgent } from '../config/https.js';
import { runLog } from '../observability/runContext.js';
import { fixturesEnabled, replayHttp } from '../recording/replay.js';
import { pathFromBase } from '../recording/common.js';

let wazuhToken = null;
let tokenExpiresAt = 0; // Epoch time

/**
 * Internal helper to manage Wazuh auth tokens.
 */
async function getWazuhToken() {
    // FIXTURES=1: API calls are replayed, so no real token is needed (and none was recorded).
    if (fixturesEnabled()) {
        return 'fixture-replay-token';
    }
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
        runLog.error("Failed to authenticate with Wazuh API:", error.message);
        throw new Error("Wazuh API Authentication Failed");
    }
}

/**
 * Capability: getEndpointStatus
 * Retrieves inventory and status of endpoints from the underlying security system (Wazuh).
 */
export async function getEndpointStatus(wqlStatus) {
    const token = await getWazuhToken();
    const apiUrl = `${WAZUH_SERVER_API_URL}/agents`;
    const apiQuery = { limit: 500, pretty: true, select: 'id,name,status,ip,os.name,os.version' };
    
    if (wqlStatus) {
        apiQuery.q = wqlStatus;
    }
    
    const apiResponse = fixturesEnabled()
        ? replayHttp('wazuh', pathFromBase(apiUrl, WAZUH_SERVER_API_URL), apiQuery)
        : await axios.get(apiUrl, {
            headers: { Authorization: `Bearer ${token}` },
            params: apiQuery,
            httpsAgent
        });
    
    return {
        url: apiUrl,
        query: apiQuery,
        data: apiResponse.data.data.affected_items || [apiResponse.data.data],
        total: apiResponse.data.data.total_affected_items || 0
    };
}

/**
 * Capability: getManagerStatus
 * Retrieves the status of the security manager daemons.
 */
export async function getManagerStatus() {
    const token = await getWazuhToken();
    const apiUrl = `${WAZUH_SERVER_API_URL}/manager/status`;
    const apiQuery = { pretty: true };
    
    const apiResponse = fixturesEnabled()
        ? replayHttp('wazuh', pathFromBase(apiUrl, WAZUH_SERVER_API_URL), apiQuery)
        : await axios.get(apiUrl, {
            headers: { Authorization: `Bearer ${token}` },
            params: apiQuery,
            httpsAgent
        });
    
    const data = apiResponse.data.data.affected_items || [apiResponse.data.data];
    return {
        url: apiUrl,
        query: apiQuery,
        data,
        total: apiResponse.data.data.total_affected_items || data.length
    };
}
