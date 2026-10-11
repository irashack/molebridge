// What the real panel serves for the fixture cases, from
// panel/fixtures/payloads.py. Python is the panel's own runtime; set PYTHON
// to choose the interpreter (python3 by default).
'use strict';

const { execFileSync } = require('node:child_process');
const path = require('node:path');

let cached;

function serverPayloads() {
  if (!cached) {
    const script = path.join(__dirname, '..', 'fixtures', 'payloads.py');
    // A clean environment: no PANEL_EXITS, sign-in or provider from the caller.
    const output = execFileSync(process.env.PYTHON || 'python3', [script], {
      env: { PATH: process.env.PATH, PYTHONDONTWRITEBYTECODE: '1' },
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
    cached = JSON.parse(output);
  }
  return cached;
}

module.exports = { serverPayloads };
