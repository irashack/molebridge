// Progressive enhancement for the Mullvad exit panel. Without it the page
// still switches servers through the plain form POST.
(() => {
  'use strict';

  const page = document.querySelector('.page');
  const form = document.getElementById('select-form');
  if (!page || !form) return;

  const FASTEST_COUNT = document.body.classList.contains('embed') ? 5 : 8;
  const chips = Array.from(document.querySelectorAll('.relay'));
  const chipByHost = new Map(chips.map((c) => [c.dataset.host, c]));
  const latency = new Map();
  let desired = page.dataset.desired;

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
  }

  async function measure(params) {
    const res = await fetch(`/api/latency?${new URLSearchParams(params)}`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`latency ${res.status}`);
    const data = await res.json();
    for (const [host, ms] of Object.entries(data.latency || {})) latency.set(host, ms);
    paint();
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
    fastestList.replaceChildren(
      ...top.map(({ host, ms, chip }) => {
        const li = document.createElement('li');
        li.className = 'fastest-item';
        const currentCity = chipByHost.get(desired);
        const isCurrent =
          currentCity &&
          currentCity.dataset.city === chip.dataset.city &&
          currentCity.dataset.country === chip.dataset.country;
        if (isCurrent) li.classList.add('is-current');

        const flag = document.createElement('span');
        flag.className = 'flag';
        flag.textContent = chip.dataset.flag;

        const place = document.createElement('span');
        place.className = 'fastest-place';
        const city = document.createElement('span');
        city.className = 'city';
        city.textContent = chip.dataset.city;
        const country = document.createElement('span');
        country.className = 'subdue';
        country.textContent = `, ${chip.dataset.country}`;
        place.append(city, country);

        const msEl = document.createElement('span');
        paintMs(msEl, ms);

        li.append(flag, place, msEl);
        if (!isCurrent) {
          const btn = document.createElement('button');
          btn.type = 'submit';
          btn.name = 'server';
          btn.value = host;
          btn.className = 'relay-switch';
          btn.textContent = 'Switch';
          btn.dataset.place = `${chip.dataset.city} (${host})`;
          li.append(btn);
        }
        return li;
      }),
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
    try {
      await measure({ scope: 'cities', hosts: desired || '', ...(force ? { fresh: '1' } : {}) });
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
  }

  // -- filter ---------------------------------------------------------------

  const filter = page.querySelector('[data-filter]');
  const countries = Array.from(document.querySelectorAll('.country'));
  const initiallyOpen = new Set(countries.filter((d) => d.open));
  filter?.addEventListener('input', () => {
    const q = filter.value.trim().toLowerCase();
    for (const d of countries) {
      if (!q) {
        d.classList.remove('is-filtered');
        d.open = initiallyOpen.has(d);
        for (const c of d.querySelectorAll('.city')) c.classList.remove('is-filtered');
        continue;
      }
      const countryHit = d.dataset.search.includes(q);
      d.classList.toggle('is-filtered', !countryHit);
      if (!countryHit) continue;
      const nameHit = d.dataset.country.toLowerCase().includes(q);
      for (const c of d.querySelectorAll('.city')) {
        c.classList.toggle('is-filtered', !nameHit && !c.dataset.search.includes(q));
      }
      d.open = true;
    }
  });
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

  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== filter) {
      e.preventDefault();
      filter?.focus();
    } else if (e.key === 'Escape' && document.activeElement === filter) {
      filter.value = '';
      filter.dispatchEvent(new Event('input'));
      filter.blur();
    }
  });

  // -- switching: click once to arm, again to confirm -----------------------

  let armed = null;
  let armTimer = 0;
  function disarm() {
    if (!armed) return;
    armed.classList.remove('is-armed');
    if (armed.dataset.label) armed.firstChild.textContent = armed.dataset.label;
    armed = null;
    clearTimeout(armTimer);
  }

  form.addEventListener('click', (e) => {
    const btn = e.target.closest('button[name="server"]');
    if (!btn) return;
    if (btn.value === desired) {
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
    armTimer = setTimeout(disarm, 4000);
  });

  // -- status polling ---------------------------------------------------------

  const pill = page.querySelector('[data-state-pill]');
  async function pollStatus() {
    let data;
    try {
      const res = await fetch('/api/status', { cache: 'no-store' });
      data = await res.json();
    } catch {
      return 30000;
    }
    const want = data.desired?.server || '';
    const result = data.result || {};
    const settled = want && result.server === want && result.status !== 'applying';
    // Once a switch lands (or another tab changed the server), redraw from the server.
    if (page.dataset.state === 'applying' ? settled : want !== desired) {
      location.reload();
      return 0;
    }
    for (const el of page.querySelectorAll('[data-f]')) {
      const key = el.dataset.f;
      if (key === 'egress') el.textContent = `${result.egress_city ?? '(unknown)'}, ${result.egress_country ?? '(unknown)'}`;
      else if (key === 'handshake_age_s') el.textContent = `${result.handshake_age_s ?? '(unknown)'}s ago`;
      else el.textContent = result[key] ?? '';
    }
    const ip = page.querySelector('[data-current-ip]');
    if (ip && result.egress_ip) ip.textContent = result.egress_ip;
    if (pill && page.dataset.state !== 'applying') {
      const state = result.status === 'ok' ? 'ok' : result.status === 'failed' ? 'failed' : 'unknown';
      pill.className = `pill pill-${state}`;
      pill.textContent = state === 'ok' ? 'connected' : state;
    }
    desired = want;
    return page.dataset.state === 'applying' ? 2000 : 30000;
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

  // Lazily: nothing is probed until someone actually has the page open.
  sweep(false);
})();
