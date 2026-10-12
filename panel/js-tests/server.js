// What the real panel serves for the fixture cases (the consumer matrix of
// internal/panel/fixtures_test.go). The panel is the Go one: `go test` runs
// TestWritePayloads in internal/panel, which writes the document. Needs the Go
// toolchain; run from anywhere inside the repository.
'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

let cached;

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
  if (!cached) cached = goPayloads();
  return cached;
}

module.exports = { serverPayloads };
