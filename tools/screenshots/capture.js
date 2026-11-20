#!/usr/bin/env node
// Retake the README's Switchyard screenshots and the social preview at 2x.
// Run from anywhere in the repository: node tools/screenshots/capture.js
// Needs the Go toolchain and Playwright with Chromium; see README.md here.
'use strict';

const { execFileSync, spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const ROOT = path.join(__dirname, '..', '..');
const ASSETS = path.join(ROOT, 'docs', 'assets');
const VIEWPORT = { width: 1280, height: 860 };
const SCALE = 2;

// Each screenshot: the scene TestWriteScreenshotState seeds, and the exit
// whose page is shown ('' for a single-exit panel).
const SHOTS = [
  { scene: 'switchyard', exit: 'mullvad' },
  { scene: 'switchyard-gluetun', exit: 'mullvad-gluetun' },
  { scene: 'switchyard-configured', exit: '' },
];

function seed(dir) {
  execFileSync('go', ['test', '-count=1', '-run', '^TestWriteScreenshotState$', './internal/panel'], {
    cwd: ROOT,
    env: { ...process.env, MOLEBRIDGE_SCREENSHOT_STATE: dir },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
}

function build(dir) {
  const binary = path.join(dir, 'molebridge');
  execFileSync('go', ['build', '-o', binary, './cmd/molebridge'], { cwd: ROOT, stdio: 'inherit' });
  return binary;
}

function healthy(url) {
  return new Promise((resolve) => {
    http.get(url + '/healthz', (res) => { res.resume(); resolve(res.statusCode === 200); })
      .on('error', () => resolve(false));
  });
}

// Start the panel on a loopback port with only the scene's environment.
async function startPanel(binary, env, port) {
  const child = spawn(binary, ['panel'], {
    env: {
      ...env,
      PATH: process.env.PATH,
      MOLEBRIDGE_PANEL_LISTEN: `127.0.0.1:${port}`,
      // Outside a container the panel cannot show its isolation; the check
      // is for deployed panels (docs/configuration.md).
      MOLEBRIDGE_PANEL_ISOLATION_CHECK: 'off',
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`panel exited: ${stderr}`);
    if (await healthy(url)) return { child, url };
    await new Promise((r) => setTimeout(r, 100));
  }
  child.kill();
  throw new Error(`panel did not start: ${stderr}`);
}

// The panel times each server with a TCP handshake; the seeded servers are
// documentation addresses that answer nothing, so the screenshot's numbers
// come from the scene's table, keyed by the hostnames the panel answers for.
async function fakeLatency(page, table) {
  await page.route('**/api/latency?**', async (route) => {
    const exit = new URL(route.request().url()).searchParams.get('exit') || '';
    const response = await route.fetch();
    const body = await response.json();
    for (const host of Object.keys(body.latency || {})) {
      body.latency[host] = (table[exit] || {})[host] ?? null;
    }
    await route.fulfill({ response, json: body });
  });
}

async function shoot(browser, binary, stateDir, shot, port) {
  const scene = JSON.parse(fs.readFileSync(path.join(stateDir, shot.scene, 'scene.json'), 'utf8'));
  const { child, url } = await startPanel(binary, scene.env, port);
  try {
    const context = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: SCALE, colorScheme: 'dark' });
    const page = await context.newPage();
    await fakeLatency(page, scene.latency);
    await page.goto(shot.exit ? `${url}/?exit=${shot.exit}` : `${url}/`, { waitUntil: 'networkidle' });
    // Let the latency answers land and the entrance motion finish.
    await page.waitForTimeout(1500);
    const out = path.join(ASSETS, `${shot.scene}.png`);
    await page.screenshot({ path: out });
    await context.close();
    console.log(`wrote ${path.relative(ROOT, out)}`);
  } finally {
    child.kill();
  }
}

async function socialPreview(browser) {
  const svg = path.join(ASSETS, 'brand', 'social-preview.svg');
  const context = await browser.newContext({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: SCALE });
  const page = await context.newPage();
  await page.setContent(`<!doctype html><style>html,body{margin:0;background:#030C1B}img{display:block}</style>` +
    `<img src="data:image/svg+xml;base64,${fs.readFileSync(svg).toString('base64')}" width="1280" height="640">`);
  await page.waitForLoadState('networkidle');
  const out = path.join(ASSETS, 'brand', 'social-preview.png');
  await page.screenshot({ path: out });
  await context.close();
  console.log(`wrote ${path.relative(ROOT, out)}`);
}

// Chromium on Linux finds fonts through fontconfig. A fontconfig without the
// usual alias files (a minimal container, a Nix profile) resolves sans-serif
// to whatever font comes first, often a serif one. This file keeps the
// host's configuration and states the generic families, so the panel's
// system font stack lands on a sans-serif face wherever one is installed.
function fontConfig(dir) {
  const base = process.env.FONTCONFIG_FILE || '/etc/fonts/fonts.conf';
  const prefer = (family, fonts) => `<alias binding="strong"><family>${family}</family><prefer>` +
    fonts.map((f) => `<family>${f}</family>`).join('') + '</prefer></alias>';
  const file = path.join(dir, 'fonts.conf');
  fs.writeFileSync(file, '<?xml version="1.0"?>\n<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">\n<fontconfig>' +
    `<include ignore_missing="yes">${base}</include>` +
    prefer('system-ui', ['Cantarell', 'Noto Sans', 'DejaVu Sans', 'Liberation Sans']) +
    prefer('sans-serif', ['Noto Sans', 'DejaVu Sans', 'Liberation Sans', 'Arial']) +
    prefer('serif', ['Noto Serif', 'DejaVu Serif', 'Liberation Serif']) +
    prefer('monospace', ['Noto Sans Mono', 'DejaVu Sans Mono', 'Liberation Mono']) +
    '</fontconfig>\n');
  return file;
}

async function main() {
  const only = process.argv.slice(2);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'molebridge-shots-'));
  const browser = await chromium.launch({ env: { ...process.env, FONTCONFIG_FILE: fontConfig(dir) } });
  try {
    const binary = build(dir);
    // Seeded last, so every record is a minute old when its page is taken.
    const stateDir = path.join(dir, 'state');
    seed(stateDir);
    let port = 18480;
    for (const shot of SHOTS) {
      if (only.length && !only.includes(shot.scene)) continue;
      await shoot(browser, binary, stateDir, shot, port++);
    }
    if (!only.length || only.includes('social-preview')) await socialPreview(browser);
  } finally {
    await browser.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
