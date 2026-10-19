// panel.js's polling loop (makePoller), which the status and the exit tabs
// run on: it rests while the page is hidden and catches up when the page is
// visible again.  node --test panel/js-tests/poller.test.js
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makePoller } = require('../static/panel.js');

// A clock the test advances: timers fire in order, and each fired callback's
// promise is awaited before the next.
function fakeClock() {
  let now = 0;
  let next = 1;
  const pending = new Map();
  return {
    timers: {
      set(fn, ms) {
        const id = next++;
        pending.set(id, { fn, at: now + ms });
        return id;
      },
      clear(id) { pending.delete(id); },
    },
    pending: () => pending.size,
    async advance(ms) {
      const until = now + ms;
      for (;;) {
        const due = [...pending.entries()].filter(([, t]) => t.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        pending.delete(due[0]);
        now = due[1].at;
        await due[1].fn();
      }
      now = until;
    },
  };
}

function setup(delays) {
  const clock = fakeClock();
  const page = { hidden: false, runs: 0 };
  const run = async () => {
    page.runs++;
    return delays ? delays.shift() ?? 30000 : 30000;
  };
  const poller = makePoller(run, clock.timers, () => page.hidden);
  return { clock, page, poller };
}

test('it runs on the delay each run answers', async () => {
  const { clock, page, poller } = setup([2000, 2000, 30000]);
  poller.start(2000);
  await clock.advance(1999);
  assert.equal(page.runs, 0);
  await clock.advance(1);
  assert.equal(page.runs, 1);
  await clock.advance(4000);
  assert.equal(page.runs, 3);
  await clock.advance(29999);
  assert.equal(page.runs, 3);
  await clock.advance(1);
  assert.equal(page.runs, 4);
});

test('nothing runs while the page is hidden, and it catches up when visible', async () => {
  const { clock, page, poller } = setup();
  poller.start(15000);
  await clock.advance(15000);
  assert.equal(page.runs, 1);
  page.hidden = true;
  await clock.advance(10 * 60000);
  assert.equal(page.runs, 1);
  assert.equal(clock.pending(), 0, 'a hidden page keeps no timer');
  poller.resume(); // still hidden: nothing
  assert.equal(page.runs, 1);
  page.hidden = false;
  poller.resume();
  await clock.advance(0);
  assert.equal(page.runs, 2, 'runs at once on becoming visible');
  await clock.advance(30000);
  assert.equal(page.runs, 3, 'and the loop goes on');
  assert.equal(clock.pending(), 1);
});

test('a resume while a timer is pending keeps one loop', async () => {
  const { clock, page, poller } = setup();
  poller.start(30000);
  await clock.advance(10000);
  poller.resume();
  poller.resume();
  await clock.advance(0);
  assert.equal(page.runs, 2);
  assert.equal(clock.pending(), 1);
  await clock.advance(30000);
  assert.equal(page.runs, 3);
  assert.equal(clock.pending(), 1);
});

test('a run that answers 0 stops the loop', async () => {
  const { clock, page, poller } = setup([0]);
  poller.start(1000);
  await clock.advance(1000);
  assert.equal(page.runs, 1);
  assert.equal(clock.pending(), 0);
  poller.resume();
  await clock.advance(60000);
  assert.equal(page.runs, 1);
});
