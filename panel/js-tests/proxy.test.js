// panel.js's proxy view (describeProxy), against the real server's answers
// and descriptions for each testdata/proxy fixture
// (internal/panel/payloads_test.go):  node --test panel/js-tests/proxy.test.js
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { serverPayloads } = require('./server');
const { describeProxy } = require('../static/panel.js');

const { text: TEXT, proxy_cases: cases } = serverPayloads();

test('the browser describes every proxy case exactly as the server does', () => {
  assert.ok(Object.keys(cases).length >= 6);
  for (const [name, { payload, describe: server }] of Object.entries(cases)) {
    assert.deepEqual(describeProxy(payload, TEXT), server, name);
  }
});

test('the guarantee comes with every state, and unknown shows nothing of the file', () => {
  for (const { payload } of Object.values(cases)) {
    assert.equal(describeProxy(payload, TEXT).guarantee,
      'Opt-in: connections sent to the proxy leave through the tunnel or fail; nothing else is covered.');
  }
  const stale = describeProxy(cases.stale.payload, TEXT);
  assert.equal(stale.state, 'unknown');
  assert.equal(stale.note, "The proxy's status is more than 30 seconds old.");
  assert.deepEqual(Object.values(stale.fields), Array(6).fill('—'));
  assert.deepEqual(stale.benched, []);
  const ok = describeProxy(cases.ok.payload, TEXT);
  assert.equal(ok.fields.connections, '7 open, 1204 total, 12 failed');
  assert.deepEqual(ok.benched, [{ server: 'de-fra-wg-003', until: 'until 18:02:00 UTC', reason: 'handshake timed out' }]);
  assert.equal(describeProxy(cases.refusing.payload, TEXT).note,
    "The exit's verdict isn't ok, so the proxy refuses new connections.");
});

test('the stand-in for an unreachable panel, and junk, read as unknown', () => {
  const away = describeProxy({ state: 'unknown', label: TEXT.proxy.unavailable, reasons: [] }, TEXT);
  assert.equal(away.label, 'status unavailable');
  assert.equal(away.note, '');
  const junk = describeProxy({ state: 'serving', reasons: ['nope', 3], sessions: 1.5, servers: { known: 1, benched: 'x' } }, TEXT);
  assert.equal(junk.state, 'unknown');
  assert.equal(junk.note, '');
  assert.equal(junk.fields.sessions, '—');
  assert.equal(junk.fields.servers, '—');
  assert.equal(describeProxy(null, TEXT).state, 'unknown');
});

test('a long bench list shows fifty and counts the rest', () => {
  const benched = Array.from({ length: 53 }, (_, i) => ({ server: `s${i}`, until: '2026-11-19T18:02:00Z', reason: 'r' }));
  const view = describeProxy({ ...cases.ok.payload, servers: { known: 512, benched } }, TEXT);
  assert.equal(view.benched.length, 50);
  assert.equal(view.more, 'and 3 more');
  assert.equal(view.fields.servers, '512 known, 53 benched');
});
