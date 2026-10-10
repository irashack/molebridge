"""Bounded state-file I/O and the status contract shared by the panel/applier."""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from molebridge import providers
from molebridge.validate import _unique_object, decode_json  # noqa: F401 - re-exported

# Compatibility names; the registry (molebridge/providers.py) is the source.
PROVIDERS = providers.PROVIDERS
HOSTNAME_RE = providers.get('mullvad').server_name_re
SERVER_NAME_RE = {p.id: p.server_name_re for p in providers.REGISTRY.values()}
PROVIDER_LABEL = {p.id: p.label for p in providers.REGISTRY.values()}
STATUS_MAX_AGE = 150
CATALOG_MAX_AGE = 24 * 60 * 60
# The default download cap and the bound on reading a validated snapshot back.
# A provider's download cap is its registry entry's catalog_max_bytes.
MAX_CATALOG_BYTES = providers.DEFAULT_CATALOG_BYTES


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


def write_json_atomic(path: Path, obj, *, public=False, max_bytes=None):
    """Replace `path` atomically, encoding incrementally into a temporary file.
    With max_bytes, encoding stops with ValueError as soon as the output passes
    the limit; the temporary file is removed and the old file stays in place.
    Memory stays bounded by the encoder's chunks, whatever the document's size."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            # The non-root panel must be able to read the applier's public state.
            if hasattr(os, 'fchmod'):
                os.fchmod(stream.fileno(), 0o644 if public else 0o600)
            written = 0
            # The same output json.dump gives; iterencode yields small chunks.
            for chunk in json.JSONEncoder(allow_nan=False).iterencode(obj):
                written += len(chunk.encode('utf-8'))
                if max_bytes is not None and written > max_bytes:
                    raise ValueError('state file exceeds its size limit')
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def provider_from_env(env):
    return providers.from_env(env).id


def valid_server_name(value, provider='mullvad'):
    spec = providers.REGISTRY.get(provider)
    return spec is not None and spec.valid_server_name(value)


def exit_confirmed(result):
    """The provider-side egress confirmation; older results carry the Mullvad field."""
    if 'exit_confirmed' in result:
        return result.get('exit_confirmed') is True
    return result.get('mullvad_exit_ip') is True


def egress_tier(result, provider='mullvad'):
    """How the result's egress was confirmed: 'provider' (the provider's own
    endpoint said so), 'tunnel' (the tunnel checks in molebridge/egress.py,
    accepted only for a provider whose registry entry has no stronger check),
    or None. Results written before tiers existed have only exit_confirmed."""
    if exit_confirmed(result):
        return 'provider'
    spec = providers.REGISTRY.get(provider)
    if result.get('egress_tier') == 'tunnel' and spec is not None and spec.egress_tier == 'tunnel':
        return 'tunnel'
    return None


def desired_request(value, provider='mullvad'):
    """Accept the old two-field request and the new retry-aware request schema."""
    if not isinstance(value, dict) or set(value) - {'server', 'requested_at', 'request_id'}:
        return None
    server = value.get('server')
    if not valid_server_name(server, provider):
        return None
    if age_seconds(value.get('requested_at')) is None:
        return None
    request_id = value.get('request_id')
    if request_id is not None and (not isinstance(request_id, str) or not re.fullmatch(r'[0-9a-f]{32}', request_id)):
        return None
    return dict(value)


def request_token(request):
    return request.get('request_id') or f"{request['server']}@{request['requested_at']}"


def status_view(desired, result, provider='mullvad'):
    """One interpretation for HTML, API, monitoring and browser polling."""
    desired = desired if isinstance(desired, dict) else {}
    result = result if isinstance(result, dict) else {}
    if configured_server(result) is not None:
        desired = {}
    if not recent(result.get('checked_at')):
        return 'unknown', 'status stale' if result else 'awaiting status'
    request = desired_request(desired, provider)
    if request and result.get('request_id') != request_token(request):
        if recent(desired.get('requested_at')):
            return 'applying', 'switching'
        return 'unknown', 'request not acknowledged'
    status = result.get('status')
    if status == 'ok':
        # Results written before the NetBird mode check have no such field.
        if (result.get('routing_ok') is not True or egress_tier(result, provider) is None
                or result.get('netbird_native', True) is not True
                or (configured_server(result) is not None
                    and result.get('server') != configured_server(result))):
            return 'failed', 'verification failed'
        return 'ok', 'connected'
    if status == 'applying':
        return 'applying', 'switching'
    if status == 'failed':
        return 'failed', 'failed'
    return 'unknown', 'unknown'


def configured_server(result):
    """Configuration authority survives stale status; freshness only governs health.
    Invalid SERVER names still lock the exit. Older snapshots have no setting."""
    if isinstance(result, dict):
        value = result.get('configured_server')
        if isinstance(value, str) and value:
            # A malformed name (a lone surrogate, a control character) keeps
            # the lock but is shown escaped, so rendering it can't fail.
            value = value.encode('utf-8', 'backslashreplace').decode('utf-8')
            value = ''.join(c if c.isprintable() else f'\\x{ord(c):02x}' for c in value)
            return value[:256]
    return None
