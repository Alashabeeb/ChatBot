import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// The UI must never claim activity or state that isn't real (Phase 2.14). Each phrase below was
// once shown without anything behind it: the app talks to the backend over plain HTTP (F-10),
// nothing checks system status, and no threat intelligence source exists.
const FALSE_CLAIMS = [
  /ENCRYPTED SESSION/i,
  /TLS 1\.\d/i,
  /SYSTEM ONLINE/i,
  /Live Monitoring/i,
  /Connected to Wazuh SIEM/i,
  /Fetching threat intelligence/i,
  /Correlating security events/i
];

const srcDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const uiFiles = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap(e =>
  e.isDirectory() ? uiFiles(path.join(dir, e.name)) : /\.(jsx|js)$/.test(e.name) && !e.name.endsWith('.test.js') ? [path.join(dir, e.name)] : []);

test('no UI file shows a status claim that nothing backs', () => {
  const offenders = [];
  for (const file of uiFiles(srcDir)) {
    const text = fs.readFileSync(file, 'utf8');
    for (const claim of FALSE_CLAIMS) if (claim.test(text)) offenders.push(`${path.relative(srcDir, file)}: ${claim}`);
  }
  assert.deepEqual(offenders, []);
});

test('the scripted fake terminal feed is gone', () => {
  assert.equal(fs.existsSync(path.join(srcDir, 'components', 'TerminalFeed.jsx')), false);
});
