import { mapStrings } from './common.js';

/**
 * Optional redaction for captured fixtures (--redact). Off by default: fixtures are captured
 * unredacted for fidelity. See docs/CAPTURE_RUNBOOK.md for what this does and does not mask.
 *
 * 1. Internal IPv4 addresses (RFC 1918, loopback, link-local, CGNAT) are masked wherever they appear.
 * 2. Hostnames and usernames are collected from recognized fields, then masked wherever those exact
 *    values appear in any string (full_log, descriptions, prompts, the report).
 * 3. Extra terms passed by the caller (e.g. the AD domain name) are masked wherever they appear.
 * Masks are consistent within a fixture (the same value always becomes the same token). The mapping
 * back to real values is not stored.
 */

const INTERNAL_IPV4 = /(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})(?![\d.]*\d)/g;

// Field names (compared case-insensitively) whose string values are hostnames or domains.
const HOST_FIELDS = new Set([
    'hostname', 'host', 'computer', 'computername', 'machinename', 'workstation', 'workstationname',
    'srchost', 'dsthost', 'srcname', 'dstname', 'targetservername', 'fqdn',
    'domain', 'domainname', 'targetdomainname', 'subjectdomainname'
]);
// `<parent>.name` is a hostname for these parents (agent.name, manager.name, ...).
const HOST_NAME_PARENTS = new Set(['agent', 'manager', 'cluster', 'host', 'predecoder']);

// Field names whose string values are user or account names.
const USER_FIELDS = new Set([
    'user', 'username', 'srcuser', 'dstuser', 'targetusername', 'subjectusername', 'accountname',
    'samaccountname', 'userprincipalname', 'upn', 'logonuser', 'uname', 'login', 'owner'
]);

// Placeholder or generic values that identify nobody and would cause noisy replacements.
const IGNORED = new Set(['', '-', 'n/a', 'na', 'null', '(null)', 'none', 'unknown', 'localhost', 'system', 'local service', 'network service', 'anonymous logon']);

const escapeRegex = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function collect(value, parentKey, found) {
    if (Array.isArray(value)) {
        for (const item of value) collect(item, parentKey, found);
        return;
    }
    if (!value || typeof value !== 'object') return;

    for (const [rawKey, child] of Object.entries(value)) {
        const key = rawKey.toLowerCase();
        if (typeof child === 'string') {
            if (HOST_FIELDS.has(key) || (key === 'name' && HOST_NAME_PARENTS.has(parentKey))) addHost(child, found);
            else if (USER_FIELDS.has(key)) addUser(child, found);
        } else {
            collect(child, key, found);
        }
    }
}

function usable(value) {
    const v = value.trim();
    return v.length >= 3 && !/^\d+$/.test(v) && !IGNORED.has(v.toLowerCase());
}

function addHost(value, found) {
    if (usable(value)) found.hosts.add(value.trim());
}

function addUser(value, found) {
    const v = value.trim();
    if (v.includes('\\')) {
        // DOMAIN\user
        const [domain, user] = v.split('\\', 2);
        addHost(domain, found);
        addUser(user, found);
    } else if (v.includes('@')) {
        // user@domain
        const [user, domain] = v.split('@', 2);
        addHost(domain, found);
        addUser(user, found);
    } else if (v.endsWith('$')) {
        // Machine account: DC01$ -> host DC01
        addHost(v.slice(0, -1), found);
    } else if (usable(v)) {
        found.users.add(v);
    }
}

/**
 * Returns a redacted copy of the fixture. `question` is left as-is (it is the replay lookup key).
 */
export function redactFixture(fixture, { extraTerms = [] } = {}) {
    const found = { hosts: new Set(), users: new Set() };
    collect(fixture, null, found);

    // Longest first, so 'dc01.corp.local' is replaced before 'dc01'. Case-insensitive: Windows names are.
    const replacements = [];
    const tokenFor = new Map();
    const addReplacement = (value, prefix, counter) => {
        const lower = value.toLowerCase();
        if (tokenFor.has(lower)) return;
        const token = `${prefix}_${++counter.n}`;
        tokenFor.set(lower, token);
        replacements.push({ value, token });
    };
    const termCounter = { n: 0 };
    const hostCounter = { n: 0 };
    const userCounter = { n: 0 };
    for (const term of extraTerms.filter(t => t && t.trim().length >= 2)) addReplacement(term.trim(), 'REDACTED_TERM', termCounter);
    for (const host of found.hosts) addReplacement(host, 'HOST', hostCounter);
    for (const user of found.users) addReplacement(user, 'USER', userCounter);
    replacements.sort((a, b) => b.value.length - a.value.length);

    const patterns = replacements.map(({ value, token }) => ({
        regex: new RegExp(`(?<![A-Za-z0-9_])${escapeRegex(value)}(?![A-Za-z0-9_])`, 'gi'),
        token
    }));

    const ipTokens = new Map();
    const { question, ...rest } = fixture;
    const redacted = mapStrings(rest, text => {
        let out = text.replace(INTERNAL_IPV4, ip => {
            if (!ipTokens.has(ip)) ipTokens.set(ip, `INTERNAL_IP_${ipTokens.size + 1}`);
            return ipTokens.get(ip);
        });
        for (const { regex, token } of patterns) out = out.replace(regex, token);
        return out;
    });

    return {
        question,
        ...redacted,
        redaction: {
            applied: true,
            counts: { internalIps: ipTokens.size, hosts: hostCounter.n, users: userCounter.n, extraTerms: termCounter.n }
        }
    };
}
