import path from 'path';
import { fileURLToPath } from 'url';

export const FIXTURE_VERSION = 1;

export const BACKEND_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Gitignored. Fixtures contain real security telemetry and must never be committed. */
export const DEFAULT_FIXTURES_DIR = path.join(BACKEND_DIR, 'fixtures');

export const DEFAULT_QUESTIONS = [
    'what is going on right now',
    'anything unusual on the AD servers',
    'show me failed logons today',
    'what are the top alerts this week'
];

export function normalizeQuestion(question) {
    return String(question).trim().replace(/\s+/g, ' ').toLowerCase();
}

/** Windows- and macOS-safe file name derived from the question. */
export function fixtureFileName(question) {
    const slug = normalizeQuestion(question).replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
    return `${slug || 'question'}.json`;
}

/**
 * The part of a request URL after the configured base URL (e.g. '/wazuh-alerts-*\/_search').
 * Base URLs differ between the capture host and the replay machine; paths do not.
 * String(base) makes an unset base ('undefined') behave the same way the integrations build URLs.
 */
export function pathFromBase(url, base) {
    const prefix = String(base);
    const value = String(url);
    return value.startsWith(prefix) ? value.slice(prefix.length) : value;
}

/** JSON with object keys sorted, so equal payloads compare equal regardless of key order. */
export function canonicalJson(value) {
    return JSON.stringify(sortKeys(value));
}

function sortKeys(value) {
    if (Array.isArray(value)) return value.map(sortKeys);
    if (value && typeof value === 'object') {
        const sorted = {};
        for (const key of Object.keys(value).sort()) {
            if (value[key] !== undefined) sorted[key] = sortKeys(value[key]);
        }
        return sorted;
    }
    return value;
}

/** Applies fn to every string value (never to object keys), returning a new structure. */
export function mapStrings(value, fn) {
    if (typeof value === 'string') return fn(value);
    if (Array.isArray(value)) return value.map(v => mapStrings(v, fn));
    if (value && typeof value === 'object') {
        const out = {};
        for (const [key, v] of Object.entries(value)) out[key] = mapStrings(v, fn);
        return out;
    }
    return value;
}
