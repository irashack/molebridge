// What the real panel serves for the fixture cases (the consumer matrix of
// panel/fixtures/records.py). The panel is the Go one when MOLEBRIDGE_PANEL=go
// (needs the Go toolchain; run from anywhere inside the repository), else the
// Python one, for which PYTHON chooses the interpreter (python3 by default).
// Remove the Python path with panel/*.py.
'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

let cached;

function pythonPayloads() {
  const script = path.join(__dirname, '..', 'fixtures', 'payloads.py');
  // A clean environment: no PANEL_EXITS, sign-in or provider from the caller.
  const output = execFileSync(process.env.PYTHON || 'python3', [script], {
    env: { PATH: process.env.PATH, PYTHONDONTWRITEBYTECODE: '1' },
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  return JSON.parse(output);
}

function goPayloads() {
  const repository = path.join(__dirname, '..', '..');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-payloads-'));
  const out = path.join(dir, 'payloads.json');
  try {
    // The test builds its own clean panel configuration; only the toolchain's
    // variables are passed through.
    execFileSync('go', ['test', '-count=1', '-run', '^TestWritePayloads$', './internal/panel'], {
      cwd: repository,
      env: { ...process.env, PANEL_PAYLOADS_OUT: out },
      stdio: ['ignore', 'ignore', 'inherit'],
    });
    return JSON.parse(fs.readFileSync(out, 'utf8'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function serverPayloads() {
  if (!cached) cached = process.env.MOLEBRIDGE_PANEL === 'go' ? goPayloads() : pythonPayloads();
  return cached;
}

module.exports = { serverPayloads };
