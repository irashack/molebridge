// A browser that still has a 0.6 page open keeps running 0.6.1's panel.js
// against a 0.7 panel until it reloads. The promise is limited: the
// aggregate state, label and tier stay correct, because they come from
// /api/status's deprecated `view`; Diagnostics reads the deprecated fields
// the panel derives for schema-2 records, so an unknown confirmation shows
// as false and an unknown routing check or fallback shows blank. "Not
// applicable" and "not checked" need the reload (the script's URL carries
// its content hash, so the reloaded page gets the new script).
//
// 0.6.1's script, kept as panel/fixtures/panel-0.6.1.js, is not changed.
// Its status paint path (paintStatus through pollStatus) is cut out of it by
// two marker lines and run against a small stand-in for the page: the
// elements it writes to, and recorders for the helpers it calls. The rest
// of the script (latency, saved servers, tabs) doesn't read /api/status.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { serverPayloads } = require('./server');

const SOURCE = fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'panel-0.6.1.js'), 'utf8');
const START = "  function paintStatus(state, label, message = '') {";
const END = '  // -- exit tabs: every exit\'s state, kept current';

function oldPollStatus(env) {
  const start = SOURCE.indexOf(START);
  const end = SOURCE.indexOf(END);
  assert.ok(start > 0 && end > start, 'the 0.6.1 paint path is where it was');
  // eslint-disable-next-line no-new-func
  const factory = new Function('env', `'use strict';
    const { pill, page, rememberSwitch, paintNotes, paintPin, paintCopy, fetch, withExit, location, configured,
            paintChecked, markCurrent, paintCurrent, noteRecent, renderFastest, renderSaved, transition } = env;
    let desired = env.desired;
    ${SOURCE.slice(start, end)}
    return pollStatus;`);
  return factory(env);
}

// What a DOM element does with what 0.6.1 writes: textContent becomes text.
class Element {
  constructor(dataset = {}) {
    this.dataset = dataset;
    this.className = '';
    this.hidden = false;
    this.text = '';
  }

  set textContent(value) { this.text = value == null ? '' : String(value); }

  get textContent() { return this.text; }
}

// The Diagnostics hooks of 0.6.1's page (panel/app.py at v0.6.1).
const HOOKS = ['status', 'message', 'egress', 'exit_confirmed', 'egress_tier', 'forwarded_port', 'handshake_age_s',
  'unreachable_fallback', 'routing_ok', 'checked_at'];

async function paintWithOldScript(payload) {
  const fields = HOOKS.map((f) => new Element({ f }));
  const single = {
    '[data-connection-label]': new Element(), '[data-current-ip]': new Element(),
    '[data-tier-note]': new Element(), '[data-requested-at]': new Element(),
  };
  const server = payload.result?.server || '';
  const page = {
    dataset: { state: 'ok', actual: server, desired: server, request: '', requested: '', checked: '' },
    querySelector: (selector) => single[selector] ?? null,
    querySelectorAll: (selector) => (selector === '[data-f]' ? fields : []),
  };
  const pill = new Element();
  const seen = { notes: null, reloaded: false };
  const noop = () => {};
  const pollStatus = oldPollStatus({
    pill, page, configured: '', desired: server,
    fetch: async () => ({ ok: true, status: 200, json: async () => structuredClone(payload) }),
    withExit: () => new URLSearchParams(), location: { reload: () => { seen.reloaded = true; } },
    rememberSwitch: noop, paintPin: noop, paintCopy: noop, paintChecked: noop, markCurrent: noop,
    paintCurrent: noop, noteRecent: noop, renderFastest: noop, renderSaved: noop, transition: (update) => update(),
    paintNotes: (state, message) => { seen.notes = message; },
  });
  const delay = await pollStatus();
  return {
    reloaded: seen.reloaded, delay,
    pill: `${pill.className} | ${pill.textContent}`,
    connection: single['[data-connection-label]'].textContent,
    ip: single['[data-current-ip]'].textContent,
    tierNote: !single['[data-tier-note]'].hidden,
    note: seen.notes,
    fields: Object.fromEntries(fields.map((el) => [el.dataset.f, el.textContent])),
  };
}

const { cases } = serverPayloads();

test('0.6.1 paints a connected schema-2 overlay exit correctly', async () => {
  const { payload } = cases['overlay-ok'];
  assert.deepEqual(await paintWithOldScript(payload), {
    reloaded: false, delay: 30000, pill: 'pill pill-ok | connected', connection: 'Secure connection',
    ip: '203.0.113.7', tierNote: false, note: '',
    fields: {
      status: 'ok', message: 'Healthy.', egress: 'Stockholm, Sweden', exit_confirmed: 'true',
      egress_tier: 'provider-confirmed', forwarded_port: 'none', handshake_age_s: '12s at last check',
      unreachable_fallback: 'true', routing_ok: 'true', checked_at: payload.result.checked_at,
    },
  });
});

test('0.6.1 keeps the tunnel tier from view', async () => {
  const { payload } = cases['overlay-gluetun-tunnel-tier'];
  const painted = await paintWithOldScript(payload);
  assert.equal(painted.pill, 'pill pill-ok | connected');
  assert.equal(painted.tierNote, true);
  assert.equal(painted.fields.egress_tier, 'tunnel checks only');
  // No provider confirmation exists for this tier: false, as 0.6 showed it.
  assert.equal(painted.fields.exit_confirmed, 'false');
});

test('0.6.1 shows a routing failure, with the unmeasured confirmation as false', async () => {
  const { payload } = cases['overlay-routing-failed'];
  assert.deepEqual(await paintWithOldScript(payload), {
    reloaded: false, delay: 30000, pill: 'pill pill-failed | failed', connection: 'Connection needs attention',
    ip: '—', tierNote: false, note: 'Tunnel egress is not confirmed.',
    fields: {
      status: 'failed', message: 'Tunnel egress is not confirmed.', egress: 'Stockholm, Sweden',
      exit_confirmed: 'false', egress_tier: 'not confirmed', forwarded_port: 'none',
      handshake_age_s: '12s at last check', unreachable_fallback: 'true', routing_ok: 'false',
      checked_at: payload.result.checked_at,
    },
  });
});

test('0.6.1 shows unknown checks blank, and unknown confirmation as false', async () => {
  const { payload } = cases.stale;
  assert.deepEqual(await paintWithOldScript(payload), {
    reloaded: false, delay: 30000, pill: 'pill pill-unknown | status stale', connection: 'Connection unverified',
    ip: '—', tierNote: false, note: 'Status is stale or unavailable. Details are from the last check.',
    fields: {
      status: 'ok', message: 'Healthy.', egress: 'Stockholm, Sweden', exit_confirmed: 'false',
      egress_tier: 'not confirmed', forwarded_port: 'none', handshake_age_s: '(unknown)s at last check',
      unreachable_fallback: '', routing_ok: '', checked_at: '2000-01-01T00:00:00Z',
    },
  });
});

test('0.6.1 still reads a 0.6 record through a 0.7 panel unchanged', async () => {
  const { payload } = cases['legacy-ok'];
  const painted = await paintWithOldScript(payload);
  assert.equal(painted.pill, 'pill pill-ok | connected');
  assert.deepEqual([painted.fields.exit_confirmed, painted.fields.routing_ok, painted.fields.unreachable_fallback],
    ['true', 'true', 'true']);
});

test('0.6.1 still reloads when configuration takes the exit', async () => {
  const painted = await paintWithOldScript(cases.configured.payload);
  assert.equal(painted.reloaded, true);
  assert.equal(painted.delay, 0);
});
