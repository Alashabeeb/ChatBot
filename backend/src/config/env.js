import dotenv from 'dotenv';

dotenv.config();

export const PORT = process.env.PORT || 3002;
export const OPENSEARCH_URL = process.env.OPENSEARCH_URL;
export const WAZUH_USER = process.env.WAZUH_USER;
export const WAZUH_PASSWORD = process.env.WAZUH_PASSWORD;
export const WAZUH_SERVER_API_URL = process.env.WAZUH_SERVER_API_URL;
export const LLM_API_URL = process.env.LLM_API_URL;

if (!OPENSEARCH_URL || !WAZUH_USER || !WAZUH_PASSWORD || !WAZUH_SERVER_API_URL || !LLM_API_URL) {
    console.warn("⚠️ Warning: One or more critical environment variables are missing.");
}
