import * as chrono from 'chrono-node';

export const GREETINGS = ['hi', 'hello', 'hey', 'help', 'who are you', 'what can you do', 
    'good morning', 'good afternoon', 'good evening', 'thanks', 'thank you', 
    'ok', 'okay', 'yes', 'no', 'bye', 'goodbye', 'sure'];

export const CONVERSATIONAL_PATTERNS = [
    'i need', 'can you', 'could you', 'please help', 'assist me', 'i want',
    'tell me about yourself', 'what are you', 'how do you work', 'are you',
    'do you', 'i have a question', 'i was wondering', 'how are you',
    'what is your', 'who made you', 'explain', 'teach me'
];

/**
 * Checks if the text has any security keywords
 */
export function hasSecurityKeyword(lowerText) {
    return /\b(ip|alert|attack|brute|fail|login|auth|cve|vulnerab|threat|malware|firewall|intrusion|port|scan|agent|log|event|wazuh|siem|rule|mitre|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/i.test(lowerText);
}

/**
 * Extracts intent from the raw text for backward compatibility (Legacy Routing).
 * The future architecture will rely on LLM-driven tool selection.
 */
export function extractLegacyIntent(lowerText) {
    if (lowerText.includes('brute') || lowerText.includes('fail') || lowerText.includes('login') || lowerText.includes('auth')) return 'brute_force';
    if (lowerText.includes('vulnerab') || lowerText.includes('cve')) return 'vulnerabilities';
    if (/\b(agent|agents|endpoint|endpoints)\b/.test(lowerText) || /\b(connected|disconnected|active)\b/.test(lowerText)) return 'agent_inventory';
    if (/\b(manager|server status|daemons)\b/.test(lowerText)) return 'manager_status';
    return 'alerts';
}

/**
 * Extracts IPv4 addresses from text
 */
export function extractIPs(text) {
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    return text.match(ipRegex) || [];
}

/**
 * Extracts severity constraints from text
 */
export function extractSeverity(lowerText) {
    const severityMatch = lowerText.match(/(?:level|severity)\s*(\d+)(?:\s*(?:and|or)?\s*(?:above|higher|up|\+))?/i);
    if (severityMatch) {
        return parseInt(severityMatch[1], 10);
    } 
    if (/\bsevere\b/i.test(lowerText) || /\bhigh severity\b/i.test(lowerText)) {
        return 7; // Wazuh level 7 is 'High'
    } 
    if (/\bcritical\b/i.test(lowerText)) {
        return 12; // Wazuh level 12 is 'Critical'
    }
    return null;
}

/**
 * Extracts time ranges using chrono-node and regex fallbacks
 */
export function extractTimeRange(text, lowerText) {
    let timeRange = 'now-24h';
    let lteTime = null;
    let timeLabel = 'Last 24 Hours';
    let chronoTimeStr = '';

    if (/\b(right now|currently|current(?:ly)?|just now)\b/i.test(lowerText)) {
        return { timeRange: 'now-15m', lteTime, timeLabel: 'Past 15 Minutes', chronoTimeStr: 'right now' };
    }

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

    return { timeRange, lteTime, timeLabel, chronoTimeStr };
}

/**
 * Cleans the search text for OpenSearch full-text queries
 */
export function cleanSearchQuery(lowerText, chronoTimeStr) {
    const stopWords = /\b(what|is|are|the|for|past|last|show|me|get|give|total|find|check|count|many|how|all|any|recent|hours|hour|hr|hrs|mins|min|minutes|days|day|today|yesterday|from|to|pm|am|please|can|you|could|level|severity|severe|critical|high|above|higher|up)\b/gi;
    let cleanedSearchText = lowerText.replace(stopWords, '');
    if (chronoTimeStr) {
        cleanedSearchText = cleanedSearchText.replace(chronoTimeStr, '');
    }
    return cleanedSearchText.replace(/\s+/g, ' ').trim();
}
