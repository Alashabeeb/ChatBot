import dotenv from 'dotenv';

dotenv.config();

export const PORT = process.env.PORT || 3002;
export const OPENSEARCH_URL = process.env.OPENSEARCH_URL;
export const WAZUH_USER = process.env.WAZUH_USER;
export const WAZUH_PASSWORD = process.env.WAZUH_PASSWORD;
export const WAZUH_SERVER_API_URL = process.env.WAZUH_SERVER_API_URL;
export const LLM_API_URL = process.env.LLM_API_URL;
// No fallback: a default secret in source code lets anyone forge tokens. See startupCheck.js.
export const JWT_SECRET = process.env.JWT_SECRET;
export const ADMIN_INITIAL_USER = process.env.ADMIN_INITIAL_USER || 'admin';
export const ADMIN_INITIAL_PASSWORD = process.env.ADMIN_INITIAL_PASSWORD || 'Password12$';

/**
 * Settings the server must not start without. Returns one message per problem; empty when OK.
 */
export function findFatalConfigErrors(env = process.env) {
    const errors = [];
    if (!env.JWT_SECRET || !env.JWT_SECRET.trim()) {
        errors.push(
            'JWT_SECRET is not set. It signs and verifies every login token, and there is no default. ' +
            'Set it in backend/.env or the process environment to a long random value, e.g. the output of: ' +
            `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
        );
    }
    return errors;
}

if (!OPENSEARCH_URL || !WAZUH_USER || !WAZUH_PASSWORD || !WAZUH_SERVER_API_URL || !LLM_API_URL) {
    console.warn("⚠️ Warning: One or more critical environment variables are missing.");
}
