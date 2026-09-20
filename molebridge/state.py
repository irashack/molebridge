"""Bounded state-file I/O and the status contract shared by the panel/applier."""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HOSTNAME_RE = re.compile(r'[a-z0-9-]{1,40}-wg-[0-9]{3}')
STATUS_MAX_AGE = 150
CATALOG_MAX_AGE = 24 * 60 * 60
MAX_CATALOG_BYTES = 10 * 1024 * 1024


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def age_seconds(value, now=None):
    if not isinstance(value, str):
        return None
    try:
        when = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        return ((now or datetime.now(timezone.utc)) - when).total_seconds()
    except ValueError:
        return None


def recent(value, max_age=STATUS_MAX_AGE, now=None):
    age = age_seconds(value, now)
    return age is not None and 0 <= age <= max_age


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate JSON field')
        obj[key] = value
    return obj


def decode_json(raw):
    def invalid_constant(_value):
        raise ValueError('non-finite JSON number')
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=invalid_constant)


def read_json(path: Path, limit=MAX_CATALOG_BYTES):
    """Reject special files, symlinks, oversized/duplicate-key JSON and bad UTF-8."""
    try:
        if path.is_symlink():
            return None
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                return None
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            return None
        return decode_json(raw)
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None


def write_json_atomic(path: Path, obj, *, public=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            # The non-root panel must be able to read the applier's public state.
            if hasattr(os, 'fchmod'):
                os.fchmod(stream.fileno(), 0o644 if public else 0o600)
            json.dump(obj, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def desired_request(value):
    """Accept the old two-field request and the new retry-aware request schema."""
    if not isinstance(value, dict) or set(value) - {'server', 'requested_at', 'request_id'}:
        return None
    server = value.get('server')
    if not isinstance(server, str) or not HOSTNAME_RE.fullmatch(server):
        return None
    if age_seconds(value.get('requested_at')) is None:
        return None
    request_id = value.get('request_id')
    if request_id is not None and (not isinstance(request_id, str) or not re.fullmatch(r'[0-9a-f]{32}', request_id)):
        return None
    return dict(value)


def request_token(request):
    return request.get('request_id') or f"{request['server']}@{request['requested_at']}"


def status_view(desired, result):
    """One interpretation for HTML, API, monitoring and browser polling."""
    desired = desired if isinstance(desired, dict) else {}
    result = result if isinstance(result, dict) else {}
    if not recent(result.get('checked_at')):
        return 'unknown', 'status stale' if result else 'awaiting status'
    request = desired_request(desired)
    if request and result.get('request_id') != request_token(request):
        if recent(desired.get('requested_at')):
            return 'applying', 'switching'
        return 'unknown', 'request not acknowledged'
    status = result.get('status')
    if status == 'ok':
        if result.get('routing_ok') is not True or result.get('mullvad_exit_ip') is not True:
            return 'failed', 'verification failed'
        return 'ok', 'connected'
    if status == 'applying':
        return 'applying', 'switching'
    if status == 'failed':
        return 'failed', 'failed'
    return 'unknown', 'unknown'
