// Progressive enhancement for the Molebridge panel. Without it the page
// still switches servers through the plain form POST.
(() => {
  'use strict';

  const page = document.querySelector('.page');
  const form = document.getElementById('select-form');
  if (!page || !form) return;

  const embed = document.body.classList.contains('embed');
  const FASTEST_COUNT = embed ? 5 : 8;
  const SAVED_COUNT = embed ? 3 : 5;
  const chips = Array.from(document.querySelectorAll('.relay'));
  const chipByHost = new Map(chips.map((c) => [c.dataset.host, c]));
  const latency = new Map();
  let desired = page.dataset.desired;
  const live = page.querySelector('[data-announce]');
  // The button awaiting a confirming second click.
  let armed = null;
  let armTimer = 0;

  function announce(text) {
    if (live) live.textContent = text;
  }

  // -- per-browser storage ---------------------------------------------------
  // Saved servers and filters stay in this browser; the panel only ever
  // receives a switch request. Stored values are untrusted: anything not
  // shaped like a relay name is dropped, and only catalogued relays are shown.

  const HOST_RE = /^[a-z0-9-]{1,40}-wg-[0-9]{3}$/;
  const PINNED_KEY = 'molebridge.pinned';
  const RECENT_KEY = 'molebridge.recent';
  const FILTERS_KEY = 'molebridge.filters';

  function load(key) {
    try {
      const value = JSON.parse(localStorage.getItem(key) || '[]');
      return Array.isArray(value) ? value.filter((v) => typeof v === 'string').slice(0, 20) : [];
    } catch {
      return [];
    }
  }

  function save(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // Private mode or blocked storage: saving is a convenience only.
    }
  }

  let pinned = load(PINNED_KEY).filter((h) => HOST_RE.test(h));
  let recent = load(RECENT_KEY).filter((h) => HOST_RE.test(h));

  const relayLabel = (host) => host.slice(host.lastIndexOf('-wg-') + 1);
  const placeOf = (host) => {
    const chip = chipByHost.get(host);
    return chip ? `${chip.dataset.city} (${host})` : host;
  };

  // -- latency -------------------------------------------------------------

  const msClass = (ms) =>
    ms == null ? 'ms-down' : ms < 60 ? 'ms-fast' : ms < 150 ? 'ms-ok' : 'ms-slow';
  const msText = (ms) => (ms == null ? 'timeout' : `${Math.round(ms)} ms`);

  function paintMs(el, ms) {
    if (!el) return;
    el.textContent = msText(ms);
    el.className = `ms ${msClass(ms)}`;
  }

  function bestOf(hosts) {
    let best;
    for (const h of hosts) {
      const ms = latency.get(h);
      if (ms != null && (best === undefined || ms < best)) best = ms;
    }
    return best;
  }

  function paint() {
    for (const [host, ms] of latency) {
      const chip = chipByHost.get(host);
      if (chip) paintMs(chip.querySelector('[data-ms]'), ms);
    }
    for (const city of document.querySelectorAll('.city')) {
      const cityChips = Array.from(city.querySelectorAll('.relay'));
      const measured = cityChips.filter((c) => latency.has(c.dataset.host));
      if (!measured.length) continue;
      const best = bestOf(measured.map((c) => c.dataset.host));
      paintMs(city.querySelector('[data-city-ms]'), best ?? null);
      // Fastest relays first once the whole city is measured.
      if (measured.length === cityChips.length) {
        const rank = (c) => latency.get(c.dataset.host) ?? Infinity;
        const sorted = [...cityChips].sort((a, b) => rank(a) - rank(b));
        if (sorted.some((c, i) => c !== cityChips[i])) city.querySelector('.relays').append(...sorted);
      }
    }
    for (const country of document.querySelectorAll('.country')) {
      const hosts = Array.from(country.querySelectorAll('.relay'), (c) => c.dataset.host);
      if (!hosts.some((h) => latency.has(h))) continue;
      const best = bestOf(hosts);
      paintMs(country.querySelector('[data-country-ms]'), best ?? null);
    }
    if (latency.has(desired)) paintMs(page.querySelector('[data-current-ms]'), latency.get(desired));
    renderFastest();
    renderSaved();
    renderCountryFastest();
  }

  async function measure(params) {
    const res = await fetch(`/api/latency?${new URLSearchParams(params)}`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`latency ${res.status}`);
    const data = await res.json();
    for (const [host, ms] of Object.entries(data.latency || {})) latency.set(host, ms);
    paint();
  }

  // -- list rows -------------------------------------------------------------

  // One row: optional mark, flag, place, latency, and a Switch button unless
  // the row is the connected server.
  function buildRow(host, ms, { current = false, mark = '', markLabel = '', prefix = '', relay = false } = {}) {
    const chip = chipByHost.get(host);
    const li = document.createElement('li');
    li.className = 'fastest-item';
    if (current) li.classList.add('is-current');

    if (mark) {
      const m = document.createElement('span');
      m.className = 'saved-mark';
      m.textContent = mark;
      m.title = markLabel;
      m.setAttribute('aria-label', markLabel);
      li.append(m);
    }

    const flag = document.createElement('span');
    flag.className = 'flag';
    flag.textContent = chip.dataset.flag;

    const place = document.createElement('span');
    place.className = 'fastest-place';
    const city = document.createElement('span');
    city.className = 'city';
    city.textContent = chip.dataset.city;
    const rest = document.createElement('span');
    rest.className = 'subdue';
    rest.textContent = relay ? ` · ${relayLabel(host)}` : `, ${chip.dataset.country}`;
    if (prefix) place.append(prefix);
    place.append(city, rest);

    const msEl = document.createElement('span');
    msEl.className = 'ms';
    if (latency.has(host)) paintMs(msEl, ms);

    li.append(flag, place, msEl);
    // Connected, or already being switched to: nothing to request.
    if (!current || !['ok', 'applying'].includes(page.dataset.state)) {
      const btn = document.createElement('button');
      btn.type = 'submit';
      btn.name = 'server';
      btn.value = host;
      btn.className = 'relay-switch';
      btn.textContent = 'Switch';
      li.append(btn);
    }
    return li;
  }

  // Re-rendering a list would silently drop an armed confirmation.
  function replaceRows(list, rows) {
    if (armed && list.contains(armed)) return;
    list.replaceChildren(...rows);
  }

  // -- fastest list --------------------------------------------------------

  const fastestSection = document.getElementById('fastest');
  const fastestList = page.querySelector('[data-fastest]');
  const retest = page.querySelector('[data-retest]');

  function renderFastest() {
    // Best measured relay per city.
    const perCity = new Map();
    for (const [host, ms] of latency) {
      const chip = chipByHost.get(host);
      if (!chip || ms == null) continue;
      const key = `${chip.dataset.country}|${chip.dataset.city}`;
      const prev = perCity.get(key);
      if (!prev || ms < prev.ms) perCity.set(key, { host, ms, chip });
    }
    const top = [...perCity.values()].sort((a, b) => a.ms - b.ms).slice(0, FASTEST_COUNT);
    if (!top.length) return;
    const currentCity = chipByHost.get(desired);
    replaceRows(
      fastestList,
      top.map(({ host, ms, chip }) =>
        buildRow(host, ms, {
          current:
            !!currentCity &&
            currentCity.dataset.city === chip.dataset.city &&
            currentCity.dataset.country === chip.dataset.country,
        }),
      ),
    );
  }

  async function sweep(force) {
    if (!fastestSection) return;
    fastestSection.hidden = false;
    retest.disabled = true;
    if (force) {
      fastestList.innerHTML = '<li class="subdue">Measuring…</li>';
      latency.clear();
    }
    const hosts = [desired, ...savedHosts()].filter(Boolean);
    try {
      await measure({ scope: 'cities', hosts: [...new Set(hosts)].join(','), ...(force ? { fresh: '1' } : {}) });
      if (!fastestList.querySelector('.fastest-item')) {
        fastestList.innerHTML = '<li class="subdue">No relays answered.</li>';
      }
    } catch {
      fastestList.innerHTML = '<li class="subdue">Latency check failed.</li>';
    } finally {
      retest.disabled = false;
    }
    // Countries opened before the sweep finished get their full measurement.
    for (const d of document.querySelectorAll('.country[open]')) measureCountry(d);
  }

  retest?.addEventListener('click', () => sweep(true));

  // -- saved: pinned and recent servers --------------------------------------

  const savedSection = document.getElementById('saved');
  const savedList = page.querySelector('[data-saved]');
  const pinButton = page.querySelector('[data-pin]');

  function savedRows() {
    const actual = page.dataset.actual;
    const rows = pinned.filter((h) => chipByHost.has(h)).map((h) => [h, '★', 'Pinned']);
    for (const h of recent) {
      if (chipByHost.has(h) && h !== actual && !pinned.includes(h)) rows.push([h, '↺', 'Recent']);
    }
    return rows.slice(0, SAVED_COUNT);
  }

  const savedHosts = () => savedRows().map(([h]) => h);

  function renderSaved() {
    if (!savedSection) return;
    const rows = savedRows();
    savedSection.hidden = !rows.length;
    replaceRows(
      savedList,
      rows.map(([h, mark, label]) =>
        buildRow(h, latency.get(h), { current: h === desired, mark, markLabel: label, relay: true }),
      ),
    );
  }

  // The server shown in Current exit.
  const shownServer = () => (page.dataset.state === 'applying' ? desired : page.dataset.actual);

  function paintPin() {
    const host = shownServer();
    if (!pinButton) return;
    pinButton.hidden = !chipByHost.has(host);
    const on = pinned.includes(host);
    pinButton.textContent = on ? '★' : '☆';
    pinButton.setAttribute('aria-pressed', String(on));
    const label = on ? 'Unpin this server' : 'Pin this server';
    pinButton.setAttribute('aria-label', label);
    pinButton.title = label;
  }

  pinButton?.addEventListener('click', () => {
    const host = shownServer();
    if (!chipByHost.has(host)) return;
    const on = pinned.includes(host);
    pinned = on ? pinned.filter((h) => h !== host) : [host, ...pinned].slice(0, 10);
    save(PINNED_KEY, pinned);
    announce(on ? `Unpinned ${placeOf(host)}` : `Pinned ${placeOf(host)}`);
    paintPin();
    renderSaved();
    if (!on && !latency.has(host)) measure({ hosts: host }).catch(() => {});
  });

  // A verified connection is remembered as recent.
  if (page.dataset.state === 'ok' && chipByHost.has(page.dataset.actual)) {
    const actual = page.dataset.actual;
    recent = [actual, ...recent.filter((h) => h !== actual)].slice(0, 5);
    save(RECENT_KEY, recent);
  }

  // -- countries: measure lazily on open ----------------------------------

  const countryMeasured = new WeakSet();
  function measureCountry(details) {
    if (countryMeasured.has(details)) return;
    countryMeasured.add(details);
    for (const el of details.querySelectorAll('.relay [data-ms]')) {
      if (!el.textContent) {
        el.textContent = '…';
        el.className = 'ms ms-pending';
      }
    }
    measure({ country: details.dataset.country }).catch(() => countryMeasured.delete(details));
  }

  // Only a person opening a country probes it; the filter opening every
  // match must not fan out across the whole relay list.
  for (const details of document.querySelectorAll('.country')) {
    details.querySelector('summary').addEventListener('click', () => {
      if (!details.open) measureCountry(details);
    });
    details.addEventListener('toggle', renderCountryFastest);
  }

  // One "Fastest" line in an open, fully measured country with a choice to make.
  function renderCountryFastest() {
    for (const details of document.querySelectorAll('.country')) {
      const cities = details.querySelector('.cities');
      let list = cities.querySelector('[data-country-fastest]');
      const shown = Array.from(details.querySelectorAll('.relay:not(.is-filtered)'), (c) => c.dataset.host);
      const measured = shown.filter((h) => latency.has(h));
      let best = null;
      for (const h of measured) {
        const ms = latency.get(h);
        if (ms != null && (best === null || ms < latency.get(best))) best = h;
      }
      if (!details.open || shown.length < 2 || measured.length < shown.length || best === null) {
        list?.remove();
        continue;
      }
      if (!list) {
        list = document.createElement('ol');
        list.className = 'fastest-list country-fastest';
        list.dataset.countryFastest = '';
        cities.prepend(list);
      }
      replaceRows(list, [buildRow(best, latency.get(best), { current: best === desired, prefix: 'Fastest: ', relay: true })]);
    }
  }

  // -- filters ---------------------------------------------------------------

  const filter = page.querySelector('[data-filter]');
  const countries = Array.from(document.querySelectorAll('.country'));
  const initiallyOpen = new Set(countries.filter((d) => d.open));
  const filtersToggle = page.querySelector('[data-filters-toggle]');
  const filtersRow = document.getElementById('relay-filters');
  const attrChips = Array.from(page.querySelectorAll('[data-attr-filter]'));
  const active = new Set(load(FILTERS_KEY).filter((k) => attrChips.some((c) => c.dataset.attrFilter === k)));

  const chipAllowed = (chip) => [...active].every((key) => chip.dataset[key] === '1');

  function applyFilter() {
    const q = filter ? filter.value.trim().toLowerCase() : '';
    for (const chip of chips) chip.classList.toggle('is-filtered', !chipAllowed(chip));
    for (const d of countries) {
      const countryHit = !q || d.dataset.search.includes(q);
      const nameHit = !q || d.dataset.country.toLowerCase().includes(q);
      let any = false;
      for (const c of d.querySelectorAll('.city')) {
        const show = (nameHit || c.dataset.search.includes(q)) && !!c.querySelector('.relay:not(.is-filtered)');
        c.classList.toggle('is-filtered', !show);
        any ||= show;
      }
      d.classList.toggle('is-filtered', !countryHit || !any);
      d.open = q ? countryHit && any : initiallyOpen.has(d);
    }
    renderCountryFastest();
  }

  function paintFilters() {
    for (const c of attrChips) c.setAttribute('aria-pressed', String(active.has(c.dataset.attrFilter)));
    if (filtersToggle) filtersToggle.textContent = active.size ? `Filters (${active.size})` : 'Filters';
  }

  if (filtersToggle && filtersRow) {
    filtersToggle.hidden = false;
    // A saved filter hides servers, so show why.
    if (active.size) {
      filtersRow.hidden = false;
      filtersToggle.setAttribute('aria-expanded', 'true');
    }
    filtersToggle.addEventListener('click', () => {
      const open = filtersRow.hidden;
      filtersRow.hidden = !open;
      filtersToggle.setAttribute('aria-expanded', String(open));
    });
    for (const c of attrChips) {
      c.addEventListener('click', () => {
        const key = c.dataset.attrFilter;
        if (active.has(key)) active.delete(key);
        else active.add(key);
        save(FILTERS_KEY, [...active]);
        paintFilters();
        applyFilter();
      });
    }
    paintFilters();
    if (active.size) applyFilter();
  }

  filter?.addEventListener('input', applyFilter);
  // A narrow filter (at most one probe batch of relays) measures what it shows.
  let filterTimer = 0;
  filter?.addEventListener('input', () => {
    clearTimeout(filterTimer);
    if (!filter.value.trim()) return;
    filterTimer = setTimeout(() => {
      const visible = chips
        .filter((c) => !c.closest('.is-filtered') && !latency.has(c.dataset.host))
        .map((c) => c.dataset.host);
      if (visible.length && visible.length <= 64) measure({ hosts: visible.join(',') }).catch(() => {});
    }, 400);
  });

  // -- switching: click once to arm, again to confirm -----------------------

  function disarm() {
    if (!armed) return;
    const btn = armed;
    armed = null;
    clearTimeout(armTimer);
    btn.classList.remove('is-armed');
    btn.removeEventListener('blur', disarm);
    if (btn.dataset.label) {
      if (btn.classList.contains('relay')) btn.firstChild.textContent = btn.dataset.label;
      else btn.textContent = btn.dataset.label;
    }
  }

  // Delegated from the document: Retry sits outside the form element.
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[name="server"]');
    if (!btn || btn.form !== form) return;
    // Re-requesting the server being switched to would restart that switch.
    if (btn.value === desired && ['ok', 'applying'].includes(page.dataset.state)) {
      e.preventDefault();
      return;
    }
    if (armed === btn) return; // second click submits
    e.preventDefault();
    disarm();
    armed = btn;
    btn.classList.add('is-armed');
    if (btn.classList.contains('relay')) {
      btn.dataset.label = btn.firstChild.textContent;
      btn.firstChild.textContent = 'switch?';
    } else {
      btn.dataset.label = btn.textContent;
      btn.textContent = 'Confirm';
    }
    announce(`Press again to switch to ${placeOf(btn.value)}. Escape cancels.`);
    btn.addEventListener('blur', disarm);
    armTimer = setTimeout(disarm, 8000);
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && armed) {
      disarm();
      announce('Switch cancelled.');
    } else if (e.key === '/' && document.activeElement !== filter) {
      e.preventDefault();
      filter?.focus();
    } else if (e.key === 'Escape' && document.activeElement === filter) {
      filter.value = '';
      filter.dispatchEvent(new Event('input'));
      filter.blur();
    }
  });

  // -- status: notes, progress and polling ------------------------------------

  const pill = page.querySelector('[data-state-pill]');
  const notes = page.querySelector('[data-notes]');
  let progress = null;

  function paintProgress() {
    if (!progress) return;
    const from = page.dataset.actual;
    const started = Date.parse(page.dataset.requested);
    const seconds = Number.isNaN(started) ? null : Math.max(0, Math.round((Date.now() - started) / 1000));
    const route = from && from !== desired ? `Leaving ${from} → ${desired}` : `Switching to ${desired}`;
    progress.firstChild.textContent = seconds === null ? route : `${route} · ${seconds} s`;
  }

  function paintNotes(state, message) {
    if (!notes) return;
    progress = null;
    const children = [];
    if (state === 'applying' && desired) {
      progress = document.createElement('p');
      progress.className = 'note';
      progress.append('');
      const hint = document.createElement('span');
      hint.className = 'subdue small';
      hint.textContent = ' Open connections through the exit will drop. Verification gives up after about a minute.';
      progress.append(document.createElement('br'), hint);
      children.push(progress);
    }
    if (message) {
      const note = document.createElement('p');
      note.className = 'note note-negative';
      note.textContent = message;
      if (state === 'failed' && chipByHost.has(desired)) {
        const retry = document.createElement('button');
        retry.type = 'submit';
        retry.name = 'server';
        retry.value = desired;
        retry.className = 'relay-switch';
        retry.dataset.retry = '';
        retry.setAttribute('form', 'select-form');
        retry.textContent = 'Retry';
        note.append(' ', retry);
      }
      children.push(note);
    }
    if (armed && notes.contains(armed)) return;
    notes.replaceChildren(...children);
    paintProgress();
  }

  setInterval(() => {
    if (page.dataset.state === 'applying') paintProgress();
  }, 1000);

  function paintStatus(state, label, message = '') {
    if (pill) {
      pill.className = `pill pill-${state}`;
      pill.textContent = label;
    }
    page.dataset.state = state;
    paintNotes(state, message);
    paintPin();
  }

  let polling = false;
  async function pollStatus() {
    if (polling) return 30000;
    polling = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    let data;
    try {
      const res = await fetch('/api/status', { cache: 'no-store', signal: controller.signal });
      if (!res.ok) throw new Error('status unavailable');
      data = await res.json();
      if (!data.view || !['ok', 'failed', 'applying', 'unknown'].includes(data.view.state)) {
        throw new Error('invalid status');
      }
    } catch {
      paintStatus('unknown', 'status unavailable', 'Cannot reach the panel. Connection status is unknown.');
      const ip = page.querySelector('[data-current-ip]');
      if (ip) ip.textContent = '—';
      return 30000;
    } finally {
      clearTimeout(timeout);
      polling = false;
    }
    const want = data.desired?.server || '';
    const request = data.desired?.request_id || '';
    const result = data.result || {};
    const state = data.view.state;
    if (want !== desired || request !== page.dataset.request ||
        (state !== 'applying' && (result.server || '') !== page.dataset.actual)) {
      location.reload();
      return 0;
    }
    for (const el of page.querySelectorAll('[data-f]')) {
      const key = el.dataset.f;
      if (key === 'egress') el.textContent = `${result.egress_city ?? '(unknown)'}, ${result.egress_country ?? '(unknown)'}`;
      else if (key === 'handshake_age_s') el.textContent = `${result.handshake_age_s ?? '(unknown)'}s at last check`;
      else el.textContent = result[key] ?? '';
    }
    const ip = page.querySelector('[data-current-ip]');
    if (ip) ip.textContent = state === 'ok' ? (result.egress_ip || '—') : '—';
    const message = state === 'unknown' ? 'Status is stale or unavailable. Details are from the last check.' :
      state === 'failed' ? (result.message || 'Tunnel verification failed.') : '';
    const previousState = page.dataset.state;
    paintStatus(state, data.view.label, message);
    if (previousState === 'applying' && state === 'ok') {
      location.reload();
      return 0;
    }
    renderFastest();
    renderSaved();
    return state === 'applying' ? 2000 : 30000;
  }

  async function pollLoop() {
    const delay = await pollStatus();
    if (delay) setTimeout(pollLoop, delay);
  }
  setTimeout(pollLoop, page.dataset.state === 'applying' ? 2000 : 30000);

  // A home-screen app resumes without reloading and has no pull-to-refresh:
  // catch up on status as soon as it is visible again.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') pollStatus();
  });

  if (page.dataset.state === 'applying') paintNotes('applying', '');
  paintPin();
  renderSaved();

  // Lazily: nothing is probed until someone actually has the page open.
  sweep(false);
})();
