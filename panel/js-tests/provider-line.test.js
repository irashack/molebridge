// panel.js's status line for a multi-provider exit (providerLine), against
// the real server's for every verdict label of the consumer matrix
// (internal/panel/payloads_test.go):  node --test panel/js-tests/provider-line.test.js
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { serverPayloads } = require('./server');
const { providerLine } = require('../static/panel.js');

const { provider_lines: lines } = serverPayloads();

test('the browser writes every status line exactly as the server does', () => {
  assert.ok(lines.length >= 30);
  for (const { label, provider, server, line } of lines) {
    assert.equal(providerLine(label, provider, server), line, `${label} / ${provider} / ${server}`);
  }
});

test('the line names the provider with the server', () => {
  assert.equal(providerLine('connected', 'PIA', 'us_chicago'), 'Connected: PIA, us_chicago');
  assert.equal(providerLine('switching', 'NordVPN', ''), 'Switching: NordVPN');
  assert.equal(providerLine('awaiting status', '', 'se-sto-wg-001'), 'Awaiting status');
});
