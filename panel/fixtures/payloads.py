"""Print, as JSON, what the panel serves for every case in records.CASES:
the page's wording table, and per case /api/status's answer and the
server's own `describe` of it. panel/js-tests reads this, so the browser
script is tested against the real server, not a copy of it.

    python3 panel/fixtures/payloads.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import app  # noqa: E402
import records  # noqa: E402


def main() -> None:
    cases = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name, (provider, kind, record, desired, *_expected) in records.CASES.items():
            ex = app.Exit.under(name, provider, 'Example', Path(tmp) / name, kind)
            result, request = record(), desired()
            if result is not None:
                app.write_json_atomic(ex.result_path, result)
            if request is not None:
                app.write_json_atomic(ex.desired_path, request)
            payload = app.status_payload(ex)
            cases[name] = {'payload': payload, 'describe': app.describe(payload['verdict'], payload['result'])}
    json.dump({'text': app.TEXT, 'cases': cases}, sys.stdout, indent=1)


if __name__ == '__main__':
    main()
