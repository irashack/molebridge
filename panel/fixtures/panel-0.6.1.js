// Progressive enhancement for the Molebridge panel. Without it the page
// still switches servers through the plain form POST.
(() => {
  'use strict';

  const page = document.querySelector('.page');
  const form = document.getElementById('select-form');
  if (!page) return;
  const configured = page.dataset.configured || '';

  const embed = document.body.classList.contains('embed');
  // Set when this panel serves several exits: every request names the exit.
  const exitId = page.dataset.exit || '';
  const withExit = (params = {}) => new URLSearchParams(exitId ? { exit: exitId, ...params } : params);
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

  // Animate a change of the page in place when the browser can and the
  // viewer hasn't asked for less motion; otherwise just make it.
  const lessMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)');
  function transition(update) {
    if (document.startViewTransition && !lessMotion?.matches && document.visibilityState === 'visible') {
      // A skipped transition still runs the update; nothing to report.
      const t = document.startViewTransition(update);
      for (const done of [t.ready, t.updateCallbackDone, t.finished]) done?.catch(() => {});
    } else {
      update();
    }
  }

  // -- per-browser storage ---------------------------------------------------
  // Saved servers and filters stay in this browser; the panel only ever
  // receives a switch request. Stored values are untrusted: anything not
  // shaped like a relay name is dropped, and only catalogued relays are shown.

  // The provider's server names (Mullvad relay hostnames, PIA region ids),
  // from the registry's pattern; without one nothing stored is trusted.
  const HOST_RE = new RegExp(`^(?:${page.dataset.serverPattern || '(?!)'})$`);
  // Each exit keeps its own saved servers; a single-exit panel keeps the
  // original keys so nothing saved before is lost.
  const KEY_PREFIX = exitId ? `molebridge.${exitId}.` : 'molebridge.';
  const PINNED_KEY = `${KEY_PREFIX}pinned`;
  const RECENT_KEY = `${KEY_PREFIX}recent`;
  const FILTERS_KEY = `${KEY_PREFIX}filters`;
  const SWITCH_KEY = `${KEY_PREFIX}switching`;

  // A short, per-tab success moment only after this request was seen applying.
  // Storage is optional; verification continues to come from the applier.
  function rememberSwitch(state) {
    try {
      if (state === 'applying') sessionStorage.setItem(SWITCH_KEY, page.dataset.request);
      else {
        const request = sessionStorage.getItem(SWITCH_KEY);
        sessionStorage.removeItem(SWITCH_KEY);
        if (state === 'ok' && request && request === page.dataset.request) {
          page.classList.add('just-verified');
          announce('Exit switch verified.');
          setTimeout(() => page.classList.remove('just-verified'), 1400);
        }
      }
    } catch { /* Storage can be disabled in an iframe or private browser. */ }
  }
  rememberSwitch(page.dataset.state);

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

  // The provider's short name for a server ('wg-001', 'us9001'), as rendered.
  const relayLabel = (host) => chipByHost.get(host)?.dataset.label || host;
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
    const text = msText(ms);
    const tone = msClass(ms);
    if (el.textContent === text && el.classList.contains(tone)) return;
    // The bars grow in once, when a value first arrives.
    const first = el.dataset.measured !== '1';
    el.dataset.measured = '1';
    el.textContent = text;
    el.className = `ms ${tone}${first && ms != null ? ' ms-arrived' : ''}`;
  }

  function clearMs(el) {
    el.textContent = '';
    el.className = 'ms';
    delete el.dataset.measured;
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
    for (const city of document.querySelectorAll('.city[data-search]')) {
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
    const shown = shownServer();
    if (latency.has(shown)) paintMs(page.querySelector('[data-current-ms]'), latency.get(shown));
    renderFastest();
    renderSaved();
    renderCountryFastest();
  }

  // One latency request at a time from this page, in order: the panel runs
  // one per exit and answers 429 while it is busy, so a request that still
  // meets 429 (another tab) waits and tries again a few times.
  let latencyQueue = Promise.resolve();
  function measure(params) {
    const run = latencyQueue.then(() => measureNow(params));
    latencyQueue = run.catch(() => {});
    return run;
  }

  async function measureNow(params) {
    for (let attempt = 0; ; attempt += 1) {
      const res = await fetch(`/api/latency?${withExit(params)}`, { cache: 'no-store' });
      if (res.status === 429 && attempt < 4) {
        await new Promise((resolve) => setTimeout(resolve, 1500 * (attempt + 1)));
        continue;
      }
      if (!res.ok) throw new Error(`latency ${res.status}`);
      const data = await res.json();
      for (const [host, ms] of Object.entries(data.latency || {})) latency.set(host, ms);
      paint();
      return data;
    }
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
    city.className = 'fastest-city';
    city.textContent = chip.dataset.city;
    const rest = document.createElement('span');
    rest.className = 'subdue';
    // A place named for its whole country (PIA's "Switzerland") says it once.
    rest.textContent = relay ? ` · ${relayLabel(host)}` :
      chip.dataset.city === chip.dataset.country ? '' : `, ${chip.dataset.country}`;
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

  // Re-rendering a list would silently drop an armed confirmation, or pull
  // a focused button out from under the keyboard; the next render catches up.
  function replaceRows(list, rows) {
    if (armed && list.contains(armed)) return;
    if (list.contains(document.activeElement) && document.activeElement !== list) return;
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

  function message(list, text) {
    const li = document.createElement('li');
    li.className = 'subdue';
    li.textContent = text;
    list.replaceChildren(li);
  }

  // Placeholder rows the size of the answer, so the list doesn't jump.
  function showSkeleton() {
    const places = new Set(chips.map((c) => `${c.dataset.country}|${c.dataset.city}`));
    const rows = Array.from({ length: Math.max(1, Math.min(FASTEST_COUNT, places.size)) }, () => {
      const li = document.createElement('li');
      li.className = 'fastest-item';
      li.dataset.skeleton = '';
      li.setAttribute('aria-hidden', 'true');
      const line = document.createElement('span');
      line.className = 'skeleton-line';
      li.append(line);
      return li;
    });
    fastestList.replaceChildren(...rows);
  }

  async function sweep(force) {
    if (!fastestSection) return;
    fastestSection.hidden = false;
    retest.disabled = true;
    fastestList.setAttribute('aria-busy', 'true');
    if (force) {
      // Keep the old rows in view, dimmed, until the new answers replace
      // them; every other measurement starts over.
      fastestList.classList.add('is-refreshing');
      latency.clear();
      for (const el of page.querySelectorAll('[data-ms], [data-city-ms], [data-country-ms], [data-current-ms]')) clearMs(el);
      countryMeasured.clear();
    }
    if (!fastestList.querySelector('.fastest-item:not([data-skeleton])')) showSkeleton();
    const hosts = [shownServer(), ...savedHosts()].filter(Boolean);
    try {
      await measure({ scope: 'cities', hosts: [...new Set(hosts)].join(','), ...(force ? { fresh: '1' } : {}) });
      if (![...latency.values()].some((ms) => ms != null)) message(fastestList, 'No relays answered.');
    } catch {
      message(fastestList, 'Latency check failed.');
    } finally {
      retest.disabled = false;
      fastestList.classList.remove('is-refreshing');
      fastestList.removeAttribute('aria-busy');
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
  function noteRecent() {
    const actual = page.dataset.actual;
    if (page.dataset.state !== 'ok' || !chipByHost.has(actual) || recent[0] === actual) return;
    recent = [actual, ...recent.filter((h) => h !== actual)].slice(0, 5);
    save(RECENT_KEY, recent);
  }
  noteRecent();

  // -- countries: measure lazily on open ----------------------------------

  const countryMeasured = new Set();
  function measureCountry(details) {
    if (countryMeasured.has(details)) return;
    countryMeasured.add(details);
    for (const el of details.querySelectorAll('.relay [data-ms]')) {
      if (!el.textContent) {
        el.textContent = '…';
        el.className = 'ms ms-pending';
      }
    }
    measure({ country: details.dataset.country }).then((data) => {
      // Servers left out of a sample are not pending any more.
      for (const chip of details.querySelectorAll('.relay')) {
        const el = chip.querySelector('[data-ms]');
        if (el && !latency.has(chip.dataset.host) && el.classList.contains('ms-pending')) {
          el.textContent = '';
          el.className = 'ms';
        }
      }
      // A large country is timed on a sample; say so beside its size.
      const sample = data && data.country;
      const meta = details.querySelector('.country-meta');
      if (!meta || !sample || !(sample.probed < sample.total) || meta.dataset.sampled) return;
      meta.dataset.sampled = '1';
      details.dataset.sampled = '1';
      meta.textContent += ` · ${sample.probed} timed`;
      meta.title = `Latency measured for ${sample.probed} of ${sample.total} servers`;
      renderCountryFastest();
    }).catch(() => countryMeasured.delete(details));
  }

  // Only a person opening a country probes it; the filter opening every
  // match must not fan out across the whole relay list.
  for (const details of document.querySelectorAll('.country')) {
    details.querySelector('summary').addEventListener('click', () => {
      // Only a country someone opens animates; search opens many at once.
      details.classList.add('motion-disclosure');
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
      // A sampled country ranks the servers it timed.
      const complete = measured.length === shown.length || details.dataset.sampled === '1';
      if (!details.open || shown.length < 2 || !complete || best === null) {
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
  if (filter) filter.hidden = false;
  const filterEmpty = page.querySelector('[data-filter-empty]');
  const countries = Array.from(document.querySelectorAll('.country'));
  const regionRows = chips.filter((c) => c.classList.contains('region'));
  const initiallyOpen = new Set(countries.filter((d) => d.open));
  const filtersToggle = page.querySelector('[data-filters-toggle]');
  const filtersRow = document.getElementById('relay-filters');
  const attrChips = Array.from(page.querySelectorAll('[data-attr-filter]'));
  const active = new Set(load(FILTERS_KEY).filter((k) => attrChips.some((c) => c.dataset.attrFilter === k)));

  const chipAllowed = (chip) => [...active].every((key) => chip.dataset[key] === '1');

  function applyFilter() {
    const q = filter ? filter.value.trim().toLowerCase() : '';
    for (const d of countries) d.classList.remove('motion-disclosure');
    for (const chip of chips) chip.classList.toggle('is-filtered', !chipAllowed(chip));
    // Region rows stand alone, outside any country.
    for (const row of regionRows) {
      if (q && !row.dataset.search.includes(q)) row.classList.add('is-filtered');
    }
    for (const d of countries) {
      const countryHit = !q || d.dataset.search.includes(q);
      const nameHit = !q || d.dataset.country.toLowerCase().includes(q);
      let any = false;
      for (const c of d.querySelectorAll('.city[data-search]')) {
        const show = (nameHit || c.dataset.search.includes(q)) && !!c.querySelector('.relay:not(.is-filtered)');
        c.classList.toggle('is-filtered', !show);
        any ||= show;
      }
      d.classList.toggle('is-filtered', !countryHit || !any);
      d.open = q ? countryHit && any : initiallyOpen.has(d);
    }
    if (filterEmpty) filterEmpty.hidden = !chips.length || chips.some((c) => !c.closest('.is-filtered'));
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
    btn.style.minInlineSize = '';
    btn.removeEventListener('blur', disarm);
    if ('label' in btn.dataset) {
      (btn.querySelector('[data-arm-text]') || btn).textContent = btn.dataset.label;
      delete btn.dataset.label;
    }
  }

  // Delegated from the document: Retry sits outside the form element.
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[name="server"]');
    if (!btn || btn.form !== form) return;
    // Re-requesting the server being switched to would restart that switch.
    // A connected PIA region may be chosen again: PIA registers anew.
    const again = page.dataset.layout === 'regions' && page.dataset.state === 'ok';
    if (btn.value === desired && (page.dataset.state === 'applying' || (page.dataset.state === 'ok' && !again))) {
      e.preventDefault();
      return;
    }
    if (armed === btn) return; // second click submits
    e.preventDefault();
    disarm();
    armed = btn;
    // Hold the button's width so the prompt doesn't move what's beside it.
    btn.style.minInlineSize = `${Math.ceil(btn.getBoundingClientRect().width)}px`;
    btn.classList.add('is-armed');
    // A relay chip or region row shows the prompt in its own label slot.
    const slot = btn.querySelector('[data-arm-text]');
    btn.dataset.label = (slot || btn).textContent;
    const reconnect = btn.value === desired;
    (slot || btn).textContent = slot ? (reconnect ? 'reconnect?' : 'switch?') : 'Confirm';
    announce(reconnect ? `Press again to register ${placeOf(btn.value)} again. Escape cancels.` :
      `Press again to switch to ${placeOf(btn.value)}. Escape cancels.`);
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
  const switchTimeout = Number(page.dataset.switchTimeout) || 60;
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
      hint.textContent = ` Open connections through the exit will drop. Verification gives up after ${switchTimeout} seconds.`;
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
    if (notes.contains(document.activeElement)) return;
    notes.replaceChildren(...children);
    paintProgress();
  }

  // "checked 12 s ago": how old the applier's last verdict is, kept live.
  const checkedAgo = page.querySelector('[data-checked-ago]');
  function paintChecked() {
    if (!checkedAgo) return;
    const at = Date.parse(page.dataset.checked || '');
    checkedAgo.hidden = Number.isNaN(at);
    if (Number.isNaN(at)) return;
    const s = Math.max(0, Math.round((Date.now() - at) / 1000));
    checkedAgo.textContent = s < 5 ? 'checked just now' : s < 60 ? `checked ${s} s ago` :
      s < 3600 ? `checked ${Math.floor(s / 60)} min ago` : 'checked over an hour ago';
    checkedAgo.dateTime = page.dataset.checked;
  }
  paintChecked();

  setInterval(() => {
    if (page.dataset.state === 'applying') paintProgress();
    paintChecked();
  }, 1000);

  // -- current exit: who it is, kept in place as status changes -------------

  function markCurrent(from, to) {
    chipByHost.get(from)?.classList.remove('is-current');
    chipByHost.get(from)?.closest('.country')?.classList.remove('is-current');
    chipByHost.get(to)?.classList.add('is-current');
    chipByHost.get(to)?.closest('.country')?.classList.add('is-current');
  }

  function paintCurrent() {
    const host = shownServer();
    const chip = chipByHost.get(host);
    const placeEl = page.querySelector('[data-current-place]');
    const flagEl = page.querySelector('[data-current-flag]');
    if (placeEl) {
      if (chip) {
        const city = document.createElement('span');
        city.className = 'current-city';
        city.textContent = chip.dataset.city;
        const country = document.createElement('span');
        country.className = 'current-country';
        const comma = document.createElement('span');
        comma.className = 'place-comma';
        comma.textContent = ', ';
        country.append(comma, chip.dataset.country);
        placeEl.replaceChildren(city, country);
      } else {
        placeEl.textContent = host || 'Awaiting verified server';
      }
    }
    if (flagEl) flagEl.textContent = chip ? chip.dataset.flag || '🌐' : '';
    const hostEl = page.querySelector('[data-current-host]');
    if (hostEl) hostEl.textContent = host || '—';
    const details = page.querySelector('[data-current-details]');
    if (details) details.textContent = chip?.dataset.details || '(unknown)';
    const ms = page.querySelector('[data-current-ms]');
    if (ms) {
      if (latency.has(host)) paintMs(ms, latency.get(host));
      else clearMs(ms);
    }
  }

  // The egress address, copied on request; only a verified one is offered.
  const copyIp = page.querySelector('[data-copy-ip]');
  function paintCopy() {
    if (!copyIp) return;
    const ip = page.querySelector('[data-current-ip]')?.textContent || '';
    copyIp.hidden = page.dataset.state !== 'ok' || !/^[0-9a-f.:]+$/i.test(ip);
  }
  copyIp?.addEventListener('click', async () => {
    const ip = page.querySelector('[data-current-ip]')?.textContent || '';
    try {
      await navigator.clipboard.writeText(ip);
      copyIp.textContent = 'Copied';
      announce('Egress address copied.');
    } catch {
      // No clipboard here (an iframe, an old browser): select it instead.
      const range = document.createRange();
      range.selectNodeContents(page.querySelector('[data-current-ip]'));
      getSelection()?.removeAllRanges();
      getSelection()?.addRange(range);
      copyIp.textContent = 'Selected';
    }
    setTimeout(() => { copyIp.textContent = 'Copy'; }, 1600);
  });
  paintCopy();

  function paintStatus(state, label, message = '') {
    if (pill) {
      pill.className = `pill pill-${state}`;
      pill.textContent = label;
    }
    page.dataset.state = state;
    const connectionLabel = page.querySelector('[data-connection-label]');
    if (connectionLabel) connectionLabel.textContent = {
      ok: 'Secure connection', applying: 'Switching route',
      failed: 'Connection needs attention', unknown: 'Connection unverified',
    }[state];
    if (state === 'applying') rememberSwitch(state);
    paintNotes(state, message);
    paintPin();
    paintCopy();
  }

  // How the egress was confirmed, worded as the server renders it. The
  // server decides which tiers count for this provider (view.tier).
  const TIER_TEXT = { provider: 'provider-confirmed', tunnel: 'tunnel checks only', none: 'not confirmed' };
  function egressTier(result) {
    if ((result.exit_confirmed ?? result.mullvad_exit_ip) === true) return 'provider';
    return result.egress_tier === 'tunnel' ? 'tunnel' : 'none';
  }

  let polling = false;
  async function pollStatus() {
    if (polling) return 30000;
    polling = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    let data;
    try {
      const res = await fetch(`/api/status?${withExit()}`, { cache: 'no-store', signal: controller.signal });
      // The session ended: reloading leads to sign-in, or to the embed's link.
      if (res.status === 401) {
        location.reload();
        return 0;
      }
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
    if ((data.view.configured_server || '') !== configured) {
      location.reload();
      return 0;
    }
    const want = configured || data.desired?.server || '';
    const request = data.desired?.request_id || '';
    const result = data.result || {};
    const state = data.view.state;
    const actual = result.server || '';
    const previousState = page.dataset.state;
    // Read-only pages have no relay chips to paint location details from.
    // Reload on a server/presentation change to get the applier's catalogue;
    // ordinary health and egress updates still happen in place.
    if (configured && (actual !== page.dataset.actual ||
        (state === 'applying') !== (previousState === 'applying'))) {
      location.reload();
      return 0;
    }
    // Who the exit is, as of this answer. A change (a switch finishing, one
    // started elsewhere, gluetun putting a server back) is painted in place.
    const moved = want !== desired || actual !== page.dataset.actual ||
      (state === 'applying') !== (previousState === 'applying');
    page.dataset.checked = result.checked_at || '';
    paintChecked();
    for (const el of page.querySelectorAll('[data-f]')) {
      const key = el.dataset.f;
      if (key === 'egress') el.textContent = `${result.egress_city ?? '(unknown)'}, ${result.egress_country ?? '(unknown)'}`;
      else if (key === 'handshake_age_s') el.textContent = `${result.handshake_age_s ?? '(unknown)'}s at last check`;
      else if (key === 'exit_confirmed') el.textContent = String((result.exit_confirmed ?? result.mullvad_exit_ip) === true);
      else if (key === 'egress_tier') el.textContent = TIER_TEXT[egressTier(result)];
      else if (key === 'forwarded_port') el.textContent = result.forwarded_port ?? 'none';
      else el.textContent = result[key] ?? '';
    }
    const ip = page.querySelector('[data-current-ip]');
    if (ip) ip.textContent = state === 'ok' ? (result.egress_ip || '—') : '—';
    const tierNote = page.querySelector('[data-tier-note]');
    if (tierNote) tierNote.hidden = !(state === 'ok' && data.view.tier === 'tunnel');
    const message = state === 'unknown' ? 'Status is stale or unavailable. Details are from the last check.' :
      state === 'failed' ? (result.message || 'Tunnel verification failed.') : '';
    const requested = page.querySelector('[data-requested-at]');
    if (requested) requested.textContent = data.desired?.requested_at || '';
    const update = () => {
      if (want !== desired) {
        markCurrent(desired, want);
        desired = want;
        page.dataset.desired = want;
      }
      page.dataset.request = request;
      page.dataset.requested = data.desired?.requested_at || '';
      page.dataset.actual = actual;
      paintStatus(state, data.view.label, message);
      if (!configured) paintCurrent();
      if (previousState === 'applying' && state !== 'applying') {
        // The success moment, only for the request this tab saw applying.
        rememberSwitch(state);
        noteRecent();
      }
      renderFastest();
      renderSaved();
    };
    if (moved) transition(update);
    else update();
    return state === 'applying' ? 2000 : 30000;
  }

  // -- exit tabs: every exit's state, kept current ----------------------------

  const tabs = new Map(Array.from(page.querySelectorAll('.exit-tab'), (t) => [t.dataset.exit, t]));
  const TAB_STATES = ['ok', 'failed', 'applying', 'unknown'];

  function paintTab(tab, state, status, place) {
    tab.querySelector('[data-exit-dot]').className = `exit-dot dot-${state}`;
    tab.querySelector('[data-exit-status]').textContent = status;
    tab.querySelector('[data-exit-place]').textContent = place;
  }

  async function pollExits() {
    if (!tabs.size) return;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const seen = new Set();
    try {
      const res = await fetch('/api/exits', { cache: 'no-store', signal: controller.signal });
      if (!res.ok) throw new Error('exits unavailable');
      const data = await res.json();
      for (const summary of Array.isArray(data.exits) ? data.exits : []) {
        const tab = tabs.get(summary.id);
        if (!tab || !TAB_STATES.includes(summary.state)) continue;
        paintTab(tab, summary.state, String(summary.status || ''), String(summary.place || ''));
        seen.add(summary.id);
      }
    } catch {
      // Handled below: a tab that was not refreshed cannot claim a state.
    } finally {
      clearTimeout(timeout);
    }
    // No stale green: an exit missing from a valid answer, or every exit when
    // the panel did not answer, shows as unknown until a refresh succeeds.
    for (const [id, tab] of tabs) {
      if (!seen.has(id)) paintTab(tab, 'unknown', 'status unavailable', '');
    }
  }

  if (tabs.size) {
    setInterval(pollExits, 15000);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') pollExits();
    });
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
