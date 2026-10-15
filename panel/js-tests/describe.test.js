// panel.js's status rendering (describe), with Node's own test runner and
// no dependencies:  node --test panel/js-tests/describe.test.js
// The cases and the wording come from the real server
// (internal/panel/payloads_test.go), which also says how it renders each one, so
// the browser and the server are checked against each other.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { serverPayloads } = require('./server');
const { describe, checkText } = require('../static/panel.js');

const { text: TEXT, cases } = serverPayloads();

test('the browser describes every case exactly as the server does', () => {
  assert.ok(Object.keys(cases).length >= 15);
  for (const [name, { payload, describe: server }] of Object.entries(cases)) {
    assert.deepEqual(describe(payload, TEXT), server, name);
  }
});

test('each case shows the verdict the server judged, with no tier of its own', () => {
  const expect = {
    'legacy-ok': ['ok', 'connected', 'provider-confirmed'],
    'overlay-ok': ['ok', 'connected', 'provider-confirmed'],
    'overlay-gluetun-tunnel-tier': ['ok', 'connected', 'tunnel checks only'],
    'sidecar-provider-tier': ['ok', 'connected', 'provider-confirmed'],
    'sidecar-tunnel-tier': ['unknown', 'switched, egress unverified', 'not confirmed'],
    'sidecar-native-pia': ['ok', 'connected', 'provider-confirmed'],
    'sidecar-native-firewall-failed': ['failed', 'failed', 'not confirmed'],
    'sidecar-native-routing-failed': ['failed', 'failed', 'not confirmed'],
    'target-disagreement': ['failed', 'verification failed', 'not confirmed'],
    'stale': ['unknown', 'status stale', 'not confirmed'],
    'request-pending': ['applying', 'switching', 'not confirmed'],
  };
  for (const [name, [state, label, tier]] of Object.entries(expect)) {
    const view = describe(cases[name].payload, TEXT);
    assert.deepEqual([view.state, view.label, view.fields.egress_tier], [state, label, tier], name);
  }
  // A failed exit's tier, or one an old record claims, never shows.
  const failed = structuredClone(cases['overlay-ok'].payload);
  failed.verdict.state = 'failed';
  assert.equal(describe(failed, TEXT).tier, null);
  assert.equal(describe(failed, TEXT).fields.egress_tier, 'not confirmed');
  assert.equal(describe(failed, TEXT).ip, '—');
});

test('not-checked and n/a are never shown as passed', () => {
  const sidecar = describe(cases['sidecar-provider-tier'].payload, TEXT);
  const byName = Object.fromEntries(sidecar.checks.map((c) => [c.name, c]));
  assert.equal(byName.traffic_protection.text, "not checked by Molebridge (gluetun's firewall)");
  assert.equal(byName.app_attachment.text, 'not checked by Molebridge (the host doctor)');
  for (const name of ['routing', 'netbird', 'owner_record']) assert.equal(byName[name].text, 'not applicable');
  assert.equal(byName.peer.text, 'passed');
  assert.equal(byName.handshake.text, 'passed, 12 s old');
  for (const { payload } of Object.values(cases)) {
    for (const check of describe(payload, TEXT).checks) {
      if (check.state !== 'pass') assert.ok(!check.text.startsWith(TEXT.check_state.pass), JSON.stringify(check));
    }
  }
  // A legacy record's checks aren't reported one by one.
  const legacy = describe(cases['legacy-ok'].payload, TEXT).checks.find((c) => c.name === 'routing');
  assert.equal(legacy.text, 'not reported individually');
});

test('notes: the failure, the unverified switch, and when the applier acts next', () => {
  const sidecar = describe(cases['sidecar-tunnel-tier'].payload, TEXT);
  assert.equal(sidecar.note, "Switched; the egress couldn't be compared with this host's address.");
  assert.equal(sidecar.next, 'Re-checking at 18:01:00 UTC.');
  assert.equal(sidecar.connection, 'Connection unverified');
  const retrying = describe(cases['overlay-retrying'].payload, TEXT);
  assert.equal(retrying.next, 'Retrying at 18:02:30 UTC.');
  assert.equal(retrying.note, 'Tunnel egress is not confirmed.');
  const silent = structuredClone(cases['overlay-retrying'].payload);
  silent.verdict.message = null;
  assert.equal(describe(silent, TEXT).note, TEXT.failed);
  assert.equal(describe(cases.stale.payload, TEXT).note, TEXT.stale);
  assert.equal(describe(cases['kind-mismatch'].payload, TEXT).note, TEXT.unverified);
  assert.equal(describe(cases['overlay-ok'].payload, TEXT).note, '');
  const switching = structuredClone(cases['request-pending'].payload);
  switching.verdict.kind = 'sidecar';
  assert.equal(describe(switching, TEXT).connection, 'Switching server');
  assert.equal(describe(cases['request-pending'].payload, TEXT).connection, 'Switching route');
});

test('record text is shown only where it is data, and reasons only from the vocabulary', () => {
  const result = { checks: { peer: { state: 'fail', reason: '<b>made up</b>' }, egress: { reason: 'unanswered' } } };
  assert.equal(checkText('peer', 'fail', result, {}, TEXT), 'failed');
  assert.equal(checkText('egress', 'fail', result, {}, TEXT), 'failed: the check got no answer');
  assert.equal(checkText('egress', 'pass', result, {}, TEXT), 'passed');
  assert.equal(checkText('peer', '__proto__', result, {}, TEXT), 'unknown');
  assert.equal(checkText('handshake', 'fail', { checks: { handshake: { age_s: true } } }, {}, TEXT), 'failed');
  const odd = structuredClone(cases['overlay-ok'].payload);
  Object.assign(odd.result, { status: 7, egress_city: null, forwarded_port: '80', checked_at: {} });
  assert.deepEqual(describe(odd, TEXT).fields, {
    status: '(unknown)', message: 'Healthy.', egress: '(unknown), Sweden', egress_tier: 'provider-confirmed',
    forwarded_port: 'none', checked_at: '(unknown)',
  });
});

test('a native sidecar: its protection is checked by Molebridge, and PIA\'s forwarded port shows', () => {
  const view = describe(cases['sidecar-native-pia'].payload, TEXT);
  const byName = Object.fromEntries(view.checks.map((c) => [c.name, c]));
  assert.equal(view.kind, 'sidecar');
  assert.equal(view.connection, 'Secure connection');
  assert.equal(view.fields.forwarded_port, '43210');
  for (const name of ['routing', 'traffic_protection', 'peer', 'egress']) assert.equal(byName[name].text, 'passed', name);
  assert.equal(byName.handshake.text, 'passed, 12 s old');
  for (const name of ['netbird', 'owner_record']) assert.equal(byName[name].text, 'not applicable', name);
  assert.equal(byName.app_attachment.text, 'not checked by Molebridge (the host doctor)');
  // The firewall failing: traffic protection failed, the contract still passed, and nothing reads as passed.
  const firewall = describe(cases['sidecar-native-firewall-failed'].payload, TEXT);
  const failed = Object.fromEntries(firewall.checks.map((c) => [c.name, c]));
  assert.equal(failed.traffic_protection.text, 'failed');
  assert.equal(failed.routing.text, 'passed');
  assert.equal(firewall.connection, 'Connection needs attention');
  assert.equal(firewall.note, 'The sidecar firewall is not as installed.');
  const routing = describe(cases['sidecar-native-routing-failed'].payload, TEXT);
  assert.deepEqual(routing.checks.filter((c) => c.state === 'fail').map((c) => c.name), ['routing', 'traffic_protection']);
});
