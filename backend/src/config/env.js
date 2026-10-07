import dotenv from 'dotenv';
import { createHash } from 'crypto';

dotenv.config();

export const PORT = process.env.PORT || 3002;
export const OPENSEARCH_URL = process.env.OPENSEARCH_URL;
export const WAZUH_USER = process.env.WAZUH_USER;
export const WAZUH_PASSWORD = process.env.WAZUH_PASSWORD;
export const WAZUH_SERVER_API_URL = process.env.WAZUH_SERVER_API_URL;
export const LLM_API_URL = process.env.LLM_API_URL;

// General chat (POST /api/chat/stream). All optional; defaults suit an 8B model.
const numberSetting = (name, fallback) => {
    const value = Number(process.env[name]);
    return Number.isFinite(value) && value > 0 ? value : fallback;
};
export const LLM_CHAT_MAX_TOKENS = numberSetting('LLM_CHAT_MAX_TOKENS', 1024);
export const LLM_CHAT_TEMPERATURE = Number.isFinite(Number(process.env.LLM_CHAT_TEMPERATURE)) && process.env.LLM_CHAT_TEMPERATURE !== ''
    ? Number(process.env.LLM_CHAT_TEMPERATURE) : 0.5;
// How long to wait for the first token, and for each next token, before giving up (F-03).
export const LLM_STREAM_FIRST_TOKEN_TIMEOUT_MS = numberSetting('LLM_STREAM_FIRST_TOKEN_TIMEOUT_MS', 60000);
export const LLM_STREAM_IDLE_TIMEOUT_MS = numberSetting('LLM_STREAM_IDLE_TIMEOUT_MS', 30000);
// Conversation history sent with each message, in characters (~4 characters per token).
export const LLM_CHAT_HISTORY_CHAR_BUDGET = numberSetting('LLM_CHAT_HISTORY_CHAR_BUDGET', 24000);
export const CHAT_MAX_MESSAGE_CHARS = 40000;

// Hard limits for each non-streamed model call (F-03). A hung model can never stall a request.
export const LLM_PLANNER_TIMEOUT_MS = numberSetting('LLM_PLANNER_TIMEOUT_MS', 45000);
export const LLM_REPORT_TIMEOUT_MS = numberSetting('LLM_REPORT_TIMEOUT_MS', 120000);
export const LLM_MEMORY_TIMEOUT_MS = numberSetting('LLM_MEMORY_TIMEOUT_MS', 45000);
export const LLM_CONVERSATION_TIMEOUT_MS = numberSetting('LLM_CONVERSATION_TIMEOUT_MS', 60000);
// Used only if a caller forgets to pass one; never "no timeout".
export const LLM_DEFAULT_TIMEOUT_MS = numberSetting('LLM_DEFAULT_TIMEOUT_MS', 60000);
// No fallback: a default secret in source code lets anyone forge tokens. See startupCheck.js.
export const JWT_SECRET = process.env.JWT_SECRET;
export const ADMIN_INITIAL_USER = process.env.ADMIN_INITIAL_USER || 'admin';
// The seeded admin's password if ADMIN_INITIAL_PASSWORD is unset. It is public (it's in this file), so
// the admin is forced to change it on first login (F-08b).
export const PUBLISHED_DEFAULT_ADMIN_PASSWORD = 'Password12$';
export const ADMIN_INITIAL_PASSWORD = process.env.ADMIN_INITIAL_PASSWORD || PUBLISHED_DEFAULT_ADMIN_PASSWORD;

// JWT_SECRET strength (F-23). Tokens are signed with HS256, so anyone holding one captured token can
// test candidate secrets offline as fast as their hardware allows; a short or guessable secret lets
// them forge a login for any user. 32 random characters is far beyond brute force.
export const JWT_SECRET_MIN_LENGTH = 32;
// SHA-256 of known, published values (stored as hashes so the old secret never appears in source):
// the old hard-coded fallback from git history, and common placeholders (secret, changeme, change-me,
// password, jwt_secret, jwtsecret, your_jwt_secret).
const KNOWN_WEAK_SECRET_HASHES = new Set([
    '9be4201f17acf828380f58b61c8a3d4418817768c90d869f1e88efc85fa9edfa',
    '2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b',
    '057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86',
    'e2186dbdb1bb4193608605e84f33208765b5693b55edd4f730a719a100eeea6f',
    '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    'e88040e7d0052eeb5dcf0fd834e4835ff329b275e6a9889058e8d16c38da9514',
    'f44ef9e360834c4e49dc3cc321d8fa6f9750212362e90166e0c4bcd99d87e81a',
    '5906f93b26ee80461424a3efe65f89731e50c3228035db85a81439f9ba00a572'
]);

/**
 * Settings the server must not start without. Returns one message per problem; empty when OK.
 */
export function findFatalConfigErrors(env = process.env) {
    const errors = [];
    const generate = `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`;
    const secret = env.JWT_SECRET?.trim();
    if (!secret) {
        errors.push(
            'JWT_SECRET is not set. It signs and verifies every login token, and there is no default. ' +
            `Set it in backend/.env or the process environment to a long random value, e.g. the output of: ${generate}`
        );
    } else if (KNOWN_WEAK_SECRET_HASHES.has(createHash('sha256').update(secret.toLowerCase()).digest('hex'))) {
        errors.push(`JWT_SECRET is a known, published value, so anyone could forge login tokens. Replace it with a random value, e.g. the output of: ${generate}`);
    } else if (secret.length < JWT_SECRET_MIN_LENGTH) {
        errors.push(
            `JWT_SECRET is too short (${secret.length} characters; at least ${JWT_SECRET_MIN_LENGTH} required). ` +
            'Anyone with one captured token can guess a short secret offline and then forge logins for any user. ' +
            `Use a random value, e.g. the output of: ${generate}`
        );
    } else if (new Set(secret).size < 8) {
        errors.push(`JWT_SECRET is too repetitive to be random (${new Set(secret).size} distinct characters). Use a random value, e.g. the output of: ${generate}`);
    }
    return errors;
}

if (!OPENSEARCH_URL || !WAZUH_USER || !WAZUH_PASSWORD || !WAZUH_SERVER_API_URL || !LLM_API_URL) {
    console.warn("⚠️ Warning: One or more critical environment variables are missing.");
}
