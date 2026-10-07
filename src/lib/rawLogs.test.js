import { test } from 'node:test';
import assert from 'node:assert/strict';
import { labelRawLogs, sourceLabel } from './rawLogs.js';

test('source labels for every raw_logs key the runtime produces', () => {
  assert.equal(sourceLabel('searchSecurityLogs'), 'Wazuh alerts');
  assert.equal(sourceLabel('searchSecurityLogs:firewall'), 'Firewall (Wazuh)');
  assert.equal(sourceLabel('getEndpointStatus'), 'Wazuh agents');
  assert.equal(sourceLabel('searchSecurityLogs#2'), 'Wazuh alerts (query 2)');
  assert.equal(sourceLabel('searchSecurityLogs#2:firewall'), 'Firewall (Wazuh) (query 2)');
  assert.equal(sourceLabel('somethingNew'), 'somethingNew');
});

test('every record keeps its source, in key order; nothing dropped or duplicated', () => {
  const alerts = [{ rule: { description: 'a' } }, { rule: { description: 'b' } }];
  const firewall = [{ rule: { description: 'fw' } }];
  const agents = [{ name: 'web-01', status: 'active' }];
  const entries = labelRawLogs({ searchSecurityLogs: alerts, 'searchSecurityLogs:firewall': firewall, getEndpointStatus: agents });
  assert.deepEqual(entries.map(e => e.source), ['Wazuh alerts', 'Wazuh alerts', 'Firewall (Wazuh)', 'Wazuh agents']);
  assert.deepEqual(entries.map(e => e.record), [...alerts, ...firewall, ...agents]);
});

test('older messages (a plain array) and bad values are handled', () => {
  assert.deepEqual(labelRawLogs([{ x: 1 }]), [{ record: { x: 1 }, source: null }]);
  assert.deepEqual(labelRawLogs(null), []);
  assert.deepEqual(labelRawLogs({ searchSecurityLogs: 'not-an-array' }), []);
});
