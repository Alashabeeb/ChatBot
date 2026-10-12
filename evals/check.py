#!/usr/bin/env python3
"""Scores SOC ChatBot answers against evals/STANDARD.md.

Input: case files in the capture fixture format (backend/src/recording/capture.js): the question, every
HTTP exchange the run made (the evidence), result.tools and result.report (the answer).

    python3 evals/check.py <file-or-dir> [...]            score every case, print a table
    python3 evals/check.py <dir> --json scores.json        also write per-case details as JSON
    python3 evals/check.py <dir> --strict                  exit 1 if any hard check fails
    python3 evals/check.py evals/synthetic --expect        validate the checker on its synthetic cases

Standard library only. Reads files; never calls a network service.
"""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

WEIGHTS = {
    'time_window': 10,
    'rule_ids_with_counts': 20,
    'outlier': 15,
    'mitre': 10,
    'recommendations': 20,
    'sources': 15,
    'evidence_honesty': 10,
}
FABRICATION_CHECKS = {
    'H2_rule_ids_grounded', 'H3_rule_counts_match', 'H4_mitre_grounded', 'H5_ips_grounded',
    'H6_hosts_grounded', 'H7_no_known_fabrications', 'H9_evidence_honesty',
}

# ---------------------------------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------------------------------

SOURCE_KEYWORDS = {
    'Wazuh alerts': r'\balerts?\b',
    'firewall': r'\bfirewall\b',
    'agent status': r'\bagents?\b|\bendpoints?\b',
    'threat intelligence': r'\bthreat[- ]intel(?:ligence)?\b|\breputation\b',
    'process data': r'\bprocess(?:es)?\b',
}
TOOL_SOURCES = {
    'getEndpointStatus': 'agent status',
    'lookupThreatIntel': 'threat intelligence',
    'checkProcessList': 'process data',
}


def get(obj, *path, default=None):
    for key in path:
        if isinstance(obj, dict) and key in obj:
            obj = obj[key]
        elif isinstance(obj, list) and isinstance(key, int) and -len(obj) <= key < len(obj):
            obj = obj[key]
        else:
            return default
    return obj


def is_firewall_query(request):
    return '"iptables"' in json.dumps(get(request, 'query', 'bool', 'must', default=[]))


def time_range_of(request):
    for clause in get(request, 'query', 'bool', 'filter', default=[]) or []:
        rng = get(clause, 'range', '@timestamp')
        if isinstance(rng, dict):
            return {'gte': rng.get('gte'), 'lte': rng.get('lte')}
    return None


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def strings_in(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings_in(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings_in(v)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield str(value)


SRC_IP_FIELDS = [('data', 'srcip'), ('data', 'src_ip'), ('data', 'win', 'eventdata', 'ipAddress')]
USER_FIELDS = [('data', 'srcuser'), ('data', 'dstuser'), ('data', 'win', 'eventdata', 'targetUserName')]


class Evidence:
    def __init__(self, case):
        self.captured_at = parse_iso(case.get('capturedAt'))
        self.searches = []
        self.agents = []
        self.unavailable = []
        self.searched_ok = set()

        for call in case.get('calls') or []:
            kind = call.get('kind')
            if kind == 'opensearch':
                request = call.get('request') or {}
                label = 'firewall' if is_firewall_query(request) else 'Wazuh alerts'
                search = {'label': label, 'range': time_range_of(request), 'failed': bool(call.get('error')),
                          'total': 0, 'hits': []}
                if not search['failed']:
                    hits = get(call, 'response', 'data', 'hits', default={}) or {}
                    search['hits'] = [h.get('_source') or {} for h in hits.get('hits') or []]
                    total = hits.get('total')
                    search['total'] = total.get('value', len(search['hits'])) if isinstance(total, dict) else (total or len(search['hits']))
                    self.searched_ok.add(label)
                else:
                    self.unavailable.append({'source': label, 'why': call['error'].get('message') or 'request failed'})
                self.searches.append(search)
            elif kind == 'wazuh' and str(call.get('path', '')).startswith('/agents'):
                if call.get('error'):
                    self.unavailable.append({'source': 'agent status', 'why': call['error'].get('message') or 'request failed'})
                else:
                    self.agents.extend(get(call, 'response', 'data', 'data', 'affected_items', default=[]) or [])
                    self.searched_ok.add('agent status')

        for tool in get(case, 'result', 'tools', default=[]) or []:
            source = TOOL_SOURCES.get(tool.get('tool'))
            if not source:
                continue
            if tool.get('success') is False or tool.get('available') is False:
                if not any(u['source'] == source for u in self.unavailable):
                    self.unavailable.append({'source': source, 'why': tool.get('reason') or tool.get('error') or 'no data'})
                self.searched_ok.discard(source)

        self.hits = [h for s in self.searches for h in s['hits']]
        self.total_hits = sum(s['total'] for s in self.searches if not s['failed'])
        self.sampled = any(s['total'] > len(s['hits']) for s in self.searches if not s['failed'])

        self.rule_counts = Counter(str(get(h, 'rule', 'id')) for h in self.hits if get(h, 'rule', 'id') is not None)
        self.rule_bounds = {}
        for rule in self.rule_counts:
            low, high = 0, 0
            for s in self.searches:
                n = sum(1 for h in s['hits'] if str(get(h, 'rule', 'id')) == rule)
                if n:
                    low += n
                    high += s['total'] - len(s['hits']) + n
            self.rule_bounds[rule] = (low, high)
        self.mitre = {m for h in self.hits for m in as_list(get(h, 'rule', 'mitre', 'id'))}
        self.agent_counts = Counter(get(h, 'agent', 'name') for h in self.hits if get(h, 'agent', 'name'))
        self.ip_counts = Counter()
        for h in self.hits:
            for path in SRC_IP_FIELDS:
                ip = get(h, *path)
                if isinstance(ip, str) and IPV4.fullmatch(ip):
                    self.ip_counts[ip] += 1
                    break

        self.text = '\n'.join(strings_in([self.hits, self.agents])).lower()
        users = {str(get(h, *p)) for h in self.hits for p in USER_FIELDS if get(h, *p)}
        names = {str(get(h, 'agent', 'name')) for h in self.hits if get(h, 'agent', 'name')}
        names |= {str(a.get('name')) for a in self.agents if a.get('name')}
        ips = {m.group(0) for m in IPV4.finditer(self.text)}
        self.entities = {e.lower() for e in (users | names | ips | self.mitre | set(self.rule_counts)) if e}

    def contains(self, token):
        return re.search(r'(?<![\w.-])' + re.escape(token.lower()) + r'(?![\w-]|\.\d)', self.text) is not None

    def windows_hours(self):
        out = []
        for s in self.searches:
            hours = window_hours(s['range'], self.captured_at)
            if hours:
                out.append(hours)
        return out


def parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None


UNIT_HOURS = {'s': 1 / 3600, 'm': 1 / 60, 'h': 1, 'H': 1, 'd': 24, 'w': 168, 'M': 720, 'y': 8760}


def window_hours(rng, captured_at):
    if not rng or not rng.get('gte'):
        return None
    gte = str(rng['gte'])
    m = re.fullmatch(r'now-(\d+)([smhHdwMy])(?:/[smhHdwMy])?', gte)
    if m:
        return int(m.group(1)) * UNIT_HOURS[m.group(2)]
    if re.fullmatch(r'now/d', gte):
        return 24
    start, end = parse_iso(gte), parse_iso(rng.get('lte')) or captured_at
    if start and end:
        return max((end - start).total_seconds() / 3600, 0) or None
    return None

# ---------------------------------------------------------------------------------------------------
# Reading the answer
# ---------------------------------------------------------------------------------------------------

IPV4 = re.compile(r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]*\d)')
MITRE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
RULE_LIST = re.compile(r'\brules?(?:[\s_-]*ids?)?\s*[:#]?\s*((?:\d{2,6})(?:\s*(?:,|/|&|\band\b|\bor\b)\s*\d{2,6})*)\b', re.I)
COUNT_UNITS = r'(?:alerts?|events?|times|occurrences?|hits|matches|attempts?|failures?|logon failures?|failed logons?|detections?)'
HOST = re.compile(r'(?<![\w.-])(?:[A-Za-z][A-Za-z0-9]*[-_][A-Za-z0-9-_]*\d[A-Za-z0-9]*|[A-Z]{2,}\d+[A-Z0-9]*)(?![\w-])')
HOST_IGNORE = re.compile(r'^(?:T\d{4}|CVE-\d{4}-\d+|SHA\d+|MD\d|AES\d+|HTTP\d|TLS\d.*|IPV\d|X\d+|UTF-?\d+|WIN\d+|W\d+|ISO-?\d+|RFC\d+|SMBV?\d|NTLMV?\d|E\d+|COVID-19)$', re.I)
SENTENCE_SPLIT = re.compile(r'(?<=[.!?])\s+(?=[A-Z*`])|\n')

NUMBER_WORDS = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6, 'seven': 7, 'eight': 8,
                'nine': 9, 'ten': 10, 'twelve': 12, 'fourteen': 14, 'thirty': 30, 'twenty-four': 24}
WINDOW_PHRASES = [
    (re.compile(r'\b(?:last|past|previous|preceding|prior)\s+(\d+|' + '|'.join(NUMBER_WORDS) + r')\s*'
                r'(minutes?|mins?|hours?|hrs?|h|days?|d|weeks?|w|months?)\b', re.I), None),
    (re.compile(r'\bnow-(\d+)([mhdw])\b'), None),
    (re.compile(r'\b(?:last|past|previous)\s+(hour)\b', re.I), 1),
    (re.compile(r'\b(?:last|past|previous)\s+(day)\b', re.I), 24),
    (re.compile(r'\btoday\b', re.I), 'today'),
    (re.compile(r'\b(?:this|last|past|previous)\s+week\b', re.I), 168),
    (re.compile(r'\b(?:this|last|past|previous)\s+month\b', re.I), 720),
]
UNIT_WORD_HOURS = {'m': 1 / 60, 'min': 1 / 60, 'h': 1, 'hr': 1, 'hour': 1, 'd': 24, 'day': 24, 'w': 168,
                   'week': 168, 'month': 720}

NO_DATA = re.compile(
    r"\b(?:no|zero|0)\s+(?:matching\s+|relevant\s+|security\s+)?(?:alerts?|events?|logs?|results?|records?|hits|"
    r"failed logons?|logon failures?|activity|data)\b|\bfound no\b|\bdid not find\b|\bdidn't find\b|"
    r"\bnothing (?:was )?(?:found|returned|matched)\b|\b(?:not enough|insufficient) (?:data|evidence)\b|"
    r"\breturned no\b", re.I)
GLOBAL_NOTHING_FOUND = re.compile(
    r"\b(?:no|zero)\s+(?:alerts|events|results|logs|records|hits)\s+(?:were\s+|was\s+)?(?:found|returned|matched|detected)\b|"
    r"\bfound no (?:alerts|events|results|logs|records)\b|\bnothing (?:was )?(?:found|returned|matched)\b", re.I)
# 'in' is left out on purpose: "no alerts were found in the last 7 days" is a global claim.
SCOPED = re.compile(r'^\s*(?:on|for|from|against|by|involving|matching|about|targeting)\b', re.I)
UNAVAILABLE_WORDS = re.compile(
    r"\b(?:unavailable|not available|isn't available|is not available|could not|couldn't|cannot|can't|failed|error|"
    r"not searched|wasn't searched|were not searched|was not searched|no access|unreachable|did not respond|"
    r"incomplete|not (?:yet )?(?:supported|integrated|implemented|connected|configured))\b", re.I)
KNOWN_FABRICATIONS = [
    (re.compile(r'\bIP_BLOCKED\b'), 'IP_BLOCKED'),
    (re.compile(r'\bunknown_miner\b', re.I), 'unknown_miner'),
    (re.compile(r'successfully added\b[^\n]{0,60}?\bto the firewall blocklist', re.I), 'blocklist success claim'),
    (re.compile(r'\b(?:IP|address)\b[^\n]{0,40}?\b(?:has been|was|is now)\s+(?:successfully\s+)?blocked\b', re.I), 'claimed IP block'),
    (re.compile(r'\bthreat score(?: of)?:?\s*10\b', re.I), 'mock threat score'),
    (re.compile(r'\bnot (?:known to be )?malicious\b[^\n]{0,80}\bthreat intel', re.I), 'mock threat-intel verdict'),
]
REC_HEADING = re.compile(r'^\s*(?:#{1,6}\s*|\*\*|__)?[^\n]{0,40}\b(?:recommend\w*|next steps?|actions?|remediation)\b[^\n]{0,40}$', re.I)
BULLET = re.compile(r'^\s*(?:[-*•]|\d+[.)])\s+(.*)$')
HEADING = re.compile(r'^\s*(?:#{1,6}\s+\S|\*\*[^*]+\*\*\s*:?\s*$|__[^_]+__\s*:?\s*$|[A-Z][^.!?]{0,60}:\s*$)')


def sentences(text):
    return [s for s in SENTENCE_SPLIT.split(text) if s.strip()]


def table_rows(text):
    """Yields (header_cells, row_cells) for each Markdown table body row."""
    lines = text.splitlines()
    i = 0
    while i < len(lines) - 1:
        if lines[i].strip().startswith('|') and re.fullmatch(r'\s*\|?\s*:?-{2,}.*', lines[i + 1]):
            header = [c.strip().strip('*').lower() for c in lines[i].strip().strip('|').split('|')]
            j = i + 2
            while j < len(lines) and lines[j].strip().startswith('|'):
                yield header, [c.strip().strip('*`') for c in lines[j].strip().strip('|').split('|')]
                j += 1
            i = j
        else:
            i += 1


def to_int(text):
    try:
        return int(str(text).replace(',', ''))
    except ValueError:
        return None


def rule_mentions(answer):
    """Returns (rule IDs mentioned, [(rule, count, where)] for counts tied to a rule)."""
    ids, counts = [], []
    for header, row in table_rows(answer):
        rule_col = next((k for k, h in enumerate(header) if re.fullmatch(r'rule(?:\s*id)?|rule\s*#|id', h)), None)
        count_col = next((k for k, h in enumerate(header) if re.search(r'count|alerts|events|hits|occurrences|total', h)), None)
        if rule_col is None or rule_col >= len(row):
            continue
        rule = row[rule_col].strip()
        if not re.fullmatch(r'\d{2,6}', rule):
            continue
        ids.append(rule)
        if count_col is not None and count_col < len(row) and to_int(row[count_col]) is not None:
            counts.append((rule, to_int(row[count_col]), 'table'))
    prose = '\n'.join(l for l in answer.splitlines() if not l.strip().startswith('|'))
    for sentence in sentences(prose):
        for m in RULE_LIST.finditer(sentence):
            found = re.findall(r'\d{2,6}', m.group(1))
            ids.extend(found)
            if len(found) != 1:
                continue
            after = sentence[m.end():m.end() + 80]
            c = re.match(r'^(?:[^\d]{0,50}?)(?:\(|:|—|-|–)?\s*(\d[\d,]*)\s*(?:\)|' + COUNT_UNITS + r')', after, re.I)
            if c and to_int(c.group(1)) is not None:
                counts.append((found[0], to_int(c.group(1)), 'prose'))
    return ids, counts


DATE = re.compile(r'\b(20\d\d-[01]\d-[0-3]\d)(?:[T ]([0-2]\d:[0-5]\d)(?::[0-5]\d(?:\.\d+)?)?Z?)?\b')
SINCE_DATE = re.compile(r'\bsince\s+' + DATE.pattern, re.I)


def parse_date(day, clock):
    try:
        return datetime.fromisoformat(f'{day}T{clock or "00:00"}:00+00:00')
    except ValueError:
        return None


def stated_windows(answer, captured_at=None):
    """Returns (text, hours, tolerance_hours or None) for each time window the answer states."""
    out = []
    for pattern, fixed in WINDOW_PHRASES:
        for m in pattern.finditer(answer):
            if fixed is not None:
                out.append((m.group(0), fixed, None))
                continue
            n = m.group(1).lower()
            n = NUMBER_WORDS.get(n, None) if not n.isdigit() else int(n)
            unit = m.group(2).lower().rstrip('s')
            unit = {'min': 'min', 'minute': 'min', 'hr': 'hr', 'hour': 'hour'}.get(unit, unit)
            if n and unit in UNIT_WORD_HOURS:
                out.append((m.group(0), n * UNIT_WORD_HOURS[unit], None))
    # Explicit dates: a range ("from 2026-10-05 to 2026-10-12") or "since <date>". A date without a
    # time of day is only precise to a day, so those get a day of tolerance.
    since = SINCE_DATE.search(answer)
    if since and captured_at:
        start = parse_date(since.group(1), since.group(2))
        if start:
            out.append((since.group(0), (captured_at - start).total_seconds() / 3600, 0 if since.group(2) else 24))
    else:
        dates = [(parse_date(m.group(1), m.group(2)), m) for m in DATE.finditer(answer)]
        dates = [(d, m) for d, m in dates if d]
        if len(dates) >= 2:
            first, last = min(dates, key=lambda x: x[0]), max(dates, key=lambda x: x[0])
            precise = first[1].group(2) and last[1].group(2)
            out.append((f'{first[1].group(0)} to {last[1].group(0)}', (last[0] - first[0]).total_seconds() / 3600, 0 if precise else 24))
    return out


def window_matches(stated, tolerance, searched):
    if stated == 'today':
        return any(h <= 24 for h in searched)
    return any(abs(stated - h) <= 0.1 * h + (tolerance or 0) for h in searched)


REC_KEYWORD = re.compile(r'\b(?:recommend\w*|next steps?|actions?|remediation)\b', re.I)
# A bullet that starts with a bold label, as the report prompt asks for: "- **Next steps**: ...".
LABELLED_BULLET = re.compile(r'^\s*(?:[-*•]|\d+[.)])\s+(?:\*\*|__)([^*_]{1,40})(?:\*\*|__)\s*:?\s*(.*)$')


def recommendations(answer):
    recs, in_section = [], False
    for line in answer.splitlines():
        labelled = LABELLED_BULLET.match(line)
        if labelled:
            in_section = REC_KEYWORD.search(labelled.group(1)) is not None
            if in_section and labelled.group(2).strip():
                recs.append(labelled.group(2).strip())
            continue
        if REC_HEADING.match(line) and not BULLET.match(line):
            in_section = True
            continue
        if in_section:
            b = BULLET.match(line)
            if b:
                recs.append(b.group(1))
            elif line.strip() and HEADING.match(line):
                in_section = False
    return recs

# ---------------------------------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------------------------------


def check_case(case):
    ev = Evidence(case)
    answer = str(get(case, 'result', 'report') or '')
    hard = []

    def hard_check(check_id, ok, detail=''):
        hard.append({'id': check_id, 'pass': bool(ok), 'detail': '' if ok else detail})

    hard_check('H1_answer_present', answer.strip(), 'empty answer')

    ids, counts = rule_mentions(answer)
    ungrounded_rules = sorted({r for r in ids if r not in ev.rule_counts})
    hard_check('H2_rule_ids_grounded', not ungrounded_rules, f'rule IDs not in evidence: {", ".join(ungrounded_rules)}')

    bad_counts = []
    for rule, n, where in counts:
        if rule not in ev.rule_bounds:
            continue
        low, high = ev.rule_bounds[rule]
        if not (low <= n <= high):
            expected = str(low) if low == high else f'{low}–{high}'
            bad_counts.append(f'rule {rule}: answer says {n}, evidence {expected} ({where})')
    hard_check('H3_rule_counts_match', not bad_counts, '; '.join(bad_counts))

    mitre = set(MITRE.findall(answer))
    ungrounded_mitre = sorted(m for m in mitre if m not in ev.mitre)
    hard_check('H4_mitre_grounded', not ungrounded_mitre, f'techniques not in rule.mitre.id: {", ".join(ungrounded_mitre)}')

    ips = {m.group(0) for m in IPV4.finditer(answer)}
    ungrounded_ips = sorted(ip for ip in ips if not ev.contains(ip))
    hard_check('H5_ips_grounded', not ungrounded_ips, f'IPs not in evidence: {", ".join(ungrounded_ips)}')

    hosts = {m.group(0) for m in HOST.finditer(answer)} - ips
    hosts = {h for h in hosts if not HOST_IGNORE.match(h) and not MITRE.fullmatch(h)}
    ungrounded_hosts = sorted(h for h in hosts if not ev.contains(h))
    hard_check('H6_hosts_grounded', not ungrounded_hosts, f'host-like names not in evidence: {", ".join(ungrounded_hosts)}')

    fabrications = [label for pattern, label in KNOWN_FABRICATIONS if pattern.search(answer)]
    hard_check('H7_no_known_fabrications', not fabrications, ', '.join(fabrications))

    windows = stated_windows(answer, ev.captured_at)
    searched = ev.windows_hours()
    matching = [w for w in windows if searched and window_matches(w[1], w[2], searched)]
    if not windows:
        hard_check('H8_time_window', False, 'no time window stated')
    else:
        hard_check('H8_time_window', matching or not searched,
                   f'stated {", ".join(repr(w[0]) for w in windows)}; searched {", ".join(fmt_hours(h) for h in searched)}')

    any_search_ok = any(not s['failed'] for s in ev.searches)
    no_hits = ev.total_hits == 0 and not ev.agents
    if no_hits and not any_search_ok:
        # Nothing could be searched: the answer must not present findings (H10 covers saying so).
        honest = not ids and not mitre
        hard_check('H9_evidence_honesty', honest, 'no search succeeded, but the answer cites rule IDs or techniques')
    elif no_hits:
        says_no_data = NO_DATA.search(answer) is not None
        honest = says_no_data and not ids and not mitre
        hard_check('H9_evidence_honesty', honest,
                   'no hits, but the answer ' + ('cites rule IDs or techniques' if says_no_data else "doesn't say so"))
    else:
        false_negative = None
        if ev.total_hits > 0:
            for m in GLOBAL_NOTHING_FOUND.finditer(answer):
                if not SCOPED.match(answer[m.end():]):
                    false_negative = m.group(0)
                    break
        honest = false_negative is None
        hard_check('H9_evidence_honesty', honest, f'{ev.total_hits} hits, but the answer says "{false_negative}"')

    undisclosed = []
    for u in ev.unavailable:
        keyword = re.compile(SOURCE_KEYWORDS[u['source']], re.I)
        if not any(keyword.search(s) and UNAVAILABLE_WORDS.search(s) for s in sentences(answer)):
            undisclosed.append(u['source'])
    hard_check('H10_unavailable_disclosed', not undisclosed, f'not disclosed as unavailable: {", ".join(undisclosed)}')

    # ----- graded -----
    grades = {}
    grades['time_window'] = 1.0 if (windows and (matching or not searched)) else 0.0

    if ev.rule_counts:
        top = [r for r, _ in ev.rule_counts.most_common(3)]
        with_count = {r for r, _, _ in counts}
        named = set(ids)
        grades['rule_ids_with_counts'] = sum(1.0 if r in with_count else 0.5 if r in named else 0.0 for r in top) / len(top)

    if ev.agent_counts or ev.ip_counts:
        tops = set()
        for counter in (ev.agent_counts, ev.ip_counts):
            if counter:
                best = counter.most_common(1)[0][1]
                tops |= {k for k, v in counter.items() if v == best}
        grades['outlier'] = 1.0 if any(re.search(r'(?<![\w.-])' + re.escape(t) + r'(?![\w-])', answer, re.I) for t in tops) else 0.0

    if ungrounded_mitre:
        grades['mitre'] = 0.0
    elif ev.mitre:
        grades['mitre'] = 1.0 if mitre & ev.mitre else 0.5
    else:
        grades['mitre'] = 1.0

    recs = recommendations(answer)
    if recs:
        anchored = [r for r in recs if any(re.search(r'(?<![\w.-])' + re.escape(e) + r'(?![\w-])', r, re.I) for e in ev.entities)]
        grades['recommendations'] = len(anchored) / len(recs)
    # No recommendations: the criterion doesn't apply (it measures grounding, not quantity).

    expected_sources = sorted(ev.searched_ok) + sorted({u['source'] for u in ev.unavailable})
    if expected_sources:
        named_ok = [s for s in ev.searched_ok if re.search(SOURCE_KEYWORDS[s], answer, re.I)]
        disclosed = [u for u in {u['source'] for u in ev.unavailable} if u not in undisclosed]
        grades['sources'] = (len(named_ok) + len(disclosed)) / len(expected_sources)

    grades['evidence_honesty'] = 1.0 if honest else 0.0

    total_weight = sum(WEIGHTS[k] for k in grades)
    score = round(100 * sum(WEIGHTS[k] * v for k, v in grades.items()) / total_weight, 1) if total_weight else 0.0
    if not answer.strip():
        score = 0.0
    failed = [h['id'] for h in hard if not h['pass']]
    return {
        'question': case.get('question'),
        'synthetic': bool(case.get('synthetic')),
        'model_generated': get(case, 'result', 'modelGenerated'),
        'evidence': {
            'total_hits': ev.total_hits,
            'hits_returned': len(ev.hits),
            'sampled': ev.sampled,
            'rules': dict(ev.rule_counts.most_common()),
            'windows_searched': [fmt_hours(h) for h in searched],
            'sources_searched': sorted(ev.searched_ok),
            'sources_unavailable': [u['source'] for u in ev.unavailable],
        },
        'pass': not failed,
        'failed_checks': failed,
        'fabrications': sum(1 for f in failed if f in FABRICATION_CHECKS),
        'hard_checks': hard,
        'score': score,
        'grades': {k: round(v, 3) for k, v in grades.items()},
    }


def fmt_hours(hours):
    if hours >= 24 and hours % 24 == 0:
        return f'{int(hours // 24)}d'
    return f'{hours:g}h'

# ---------------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------------


def case_files(paths):
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(f for f in p.glob('*.json') if f.name not in ('manifest.json', 'scores.json')))
        else:
            files.append(p)
    return files


def compare_expectation(result, expect):
    problems = []
    want_fail = set(expect.get('hard_fail', []))
    got_fail = set(result['failed_checks'])
    if want_fail != got_fail:
        problems.append(f'hard failures: expected {sorted(want_fail) or "none"}, got {sorted(got_fail) or "none"}')
    if 'score_min' in expect and result['score'] < expect['score_min']:
        problems.append(f'score {result["score"]} < expected minimum {expect["score_min"]}')
    if 'score_max' in expect and result['score'] > expect['score_max']:
        problems.append(f'score {result["score"]} > expected maximum {expect["score_max"]}')
    for key, value in (expect.get('grades') or {}).items():
        if result['grades'].get(key) != value:
            problems.append(f'grade {key}: expected {value}, got {result["grades"].get(key)}')
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description='Score SOC ChatBot answers against evals/STANDARD.md.')
    parser.add_argument('paths', nargs='+', help='case files or directories of case files')
    parser.add_argument('--json', help='write per-case results to this file')
    parser.add_argument('--strict', action='store_true', help='exit 1 if any hard check fails')
    parser.add_argument('--expect', action='store_true', help="compare each case with its own 'expect' block (checker self-test)")
    args = parser.parse_args(argv)

    results, mismatches = [], 0
    for f in case_files(args.paths):
        case = json.loads(f.read_text(encoding='utf-8'))
        result = check_case(case)
        result['file'] = f.name
        if args.expect:
            if not case.get('synthetic') or 'expect' not in case:
                print(f'{f.name}: --expect needs a SYNTHETIC case with an expect block', file=sys.stderr)
                return 2
            result['expectation_problems'] = compare_expectation(result, case['expect'])
            mismatches += bool(result['expectation_problems'])
        results.append(result)

    if not results:
        print('No case files found.', file=sys.stderr)
        return 2

    width = max(len(r['file']) for r in results)
    for r in results:
        label = 'SYNTHETIC ' if r['synthetic'] else ''
        status = 'PASS' if r['pass'] else 'FAIL'
        line = f'{label}{r["file"]:<{width}}  {status}  score {r["score"]:5.1f}  fabrications {r["fabrications"]}'
        if args.expect:
            line += '  expectation ' + ('OK' if not r['expectation_problems'] else 'MISMATCH')
        print(line)
        for h in r['hard_checks']:
            if not h['pass']:
                print(f'    {h["id"]}: {h["detail"]}')
        for p in r.get('expectation_problems', []):
            print(f'    !! {p}')

    real = [r for r in results if not r['synthetic']]
    if real:
        mean = sum(r['score'] for r in real) / len(real)
        print(f'\n{len(real)} case(s): mean score {mean:.1f}, {sum(not r["pass"] for r in real)} failing a hard check, '
              f'{sum(r["fabrications"] for r in real)} fabrication(s)')
    if args.expect:
        print(f'\nChecker self-test: {len(results) - mismatches}/{len(results)} synthetic case(s) behaved as expected')

    if args.json:
        Path(args.json).write_text(json.dumps({'standard': 'evals/STANDARD.md', 'results': results}, indent=2) + '\n', encoding='utf-8')
    if mismatches:
        return 1
    if args.strict and any(not r['pass'] for r in results):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
