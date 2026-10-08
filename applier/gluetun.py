"""A bounded, loopback-only client for gluetun v3.41.3's control server.

This module does not read VPN settings or control routes. An API key reaches
curl only through a temporary mode-0600 header file. The caller supplies the
key file; there is no environment or command-line credential interface.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
import unicodedata

from applier.apply import command
from molebridge.gluetun_catalog import valid_server_id
from molebridge.state import decode_json

MAX_KEY_BYTES = 1024
MAX_RESPONSE_BYTES = 16384
MAX_OUTCOME_CHARS = 1024
BASE_URL_RE = re.compile(r'http://(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})')
ROLE_NAME_RE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}')
# GET and PUT /v1/updater/status let the applier start one refresh of
# gluetun's server list (internal/server/updater.go at v3.41.3): gluetun's own
# updater first runs one period after start, never at start.
ROUTES = ('PUT /v1/vpn/settings', 'GET /v1/vpn/status', 'GET /v1/publicip/ip',
          'GET /v1/updater/status', 'PUT /v1/updater/status')
VPN_STATUSES = ('starting', 'running', 'stopping', 'stopped', 'crashed', 'completed')
LIST_FILTERS = ('countries', 'regions', 'cities', 'names', 'numbers', 'categories', 'isps', 'hostnames')
BOOL_FILTERS = ('owned_only', 'free_only', 'premium_only', 'stream_only', 'multi_hop_only',
                'port_forward_only', 'secure_core_only', 'tor_only')


def read_api_key(path):
    """Read one printable ASCII key, with an optional single trailing newline."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & ~0o600
                    or info.st_size > MAX_KEY_BYTES):
                raise ValueError('invalid gluetun key file')
            raw = stream.read(MAX_KEY_BYTES + 1)
        if len(raw) > MAX_KEY_BYTES:
            raise ValueError('gluetun key file exceeds limit')
        value = raw.decode('ascii', errors='strict')
        if value.endswith('\n'):
            value = value[:-1]
            if value.endswith('\r'):
                value = value[:-1]
        if not value or any(not 33 <= ord(c) <= 126 for c in value):
            raise ValueError('invalid gluetun API key')
        return value
    except (OSError, ValueError, UnicodeError):
        raise ValueError('cannot read gluetun API key') from None


def gluetun_auth_config(role_name):
    """Return a single-role TOML template; the caller must fill `apikey`.

    The empty key is deliberately unusable until the caller writes its key as
    a TOML string. No credential is generated or returned here. gluetun's
    internal/server/middlewares/auth/configfile_test.go:33-43 shows this format;
    settings.go:116-132 defines auth = "apikey" and the apikey field.
    """
    if not isinstance(role_name, str) or not ROLE_NAME_RE.fullmatch(role_name):
        raise ValueError('invalid gluetun role name')
    return (f'[[roles]]\nname = "{role_name}"\nauth = "apikey"\napikey = ""\n'
            f'routes = {json.dumps(list(ROUTES))}\n')


API_KEY_RE = re.compile(r'[A-Za-z0-9_-]{32,128}')


def gluetun_auth_file(api_key, role_name='molebridge'):
    """The complete auth config file: one role, apikey authentication, and
    exactly ROUTES. With any role in the file gluetun answers no other route
    (internal/server/middlewares/auth/settings.go:72-90, middleware.go:67-72
    at v3.41.3); with none it applies a public default role that includes
    PUT /v1/vpn/status, so the file must always be there. The key must be
    URL-safe base64 text, which needs no escaping in TOML."""
    if not isinstance(api_key, str) or not API_KEY_RE.fullmatch(api_key):
        raise ValueError('invalid gluetun API key')
    return gluetun_auth_config(role_name).replace('apikey = ""', f'apikey = "{api_key}"', 1)


def default_role_allowed(value):
    """gluetun's HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE as routing/gluetun-preflight
    accepts it: unset, empty or `{}` (gluetun's image default, no default
    role), with surrounding spaces or tabs at most."""
    return value is None or (isinstance(value, str) and value.strip(' \t') in ('', '{}'))


def valid_auth_file(text):
    """True for exactly what gluetun_auth_file writes, the structure
    routing/gluetun-preflight accepts before gluetun starts."""
    if not isinstance(text, str) or len(text.encode('utf-8', 'replace')) > 4096 or '\r' in text or '\0' in text:
        return False
    lines = text[:-1].split('\n') if text.endswith('\n') else text.split('\n')
    if len(lines) != 5:
        return False
    name = re.fullmatch(r'name = "([^"]*)"', lines[1])
    key = re.fullmatch(r'apikey = "([^"]*)"', lines[3])
    return (lines[0] == '[[roles]]' and name is not None and ROLE_NAME_RE.fullmatch(name[1]) is not None
            and lines[2] == 'auth = "apikey"' and key is not None and API_KEY_RE.fullmatch(key[1]) is not None
            and lines[4] == f'routes = {json.dumps(list(ROUTES))}')


class GluetunClient:
    def __init__(self, base_url, api_key_file, *, run=command):
        match = BASE_URL_RE.fullmatch(base_url) if isinstance(base_url, str) else None
        if match is None or int(match[1]) > 65535:
            raise ValueError('invalid gluetun control URL')
        self.base_url, self.run = base_url, run
        self._api_key = read_api_key(api_key_file)

    def _request(self, method, path, *, body=None):
        """Only the three authorized routes; GET settings is refused before I/O."""
        if f'{method} {path}' not in ROUTES:
            raise ValueError('gluetun control route refused')
        if (method == 'PUT') != (body is not None):
            raise ValueError('invalid gluetun request body')
        try:
            # A private directory also keeps the header path inaccessible to
            # other users between creation, invocation and cleanup.
            with tempfile.TemporaryDirectory(prefix='.gluetun-') as directory:
                header = os.path.join(directory, 'headers')
                fd = os.open(header, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w', encoding='ascii') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write('X-API-Key: ' + self._api_key + '\n')
                # -q must be first: ignore .curlrc (including tracing, proxies
                # and redirects). No redirect following or remote destination.
                args = ['curl', '-q', '--noproxy', '*', '--proto', '=http', '-fsS',
                        '--connect-timeout', '2', '--max-time', '10', '--max-redirs', '0',
                        '--max-filesize', str(MAX_RESPONSE_BYTES), '-X', method, '-H', '@' + header]
                if body is not None:
                    args.extend(['-H', 'Content-Type: application/json', '--data-binary', body])
                args.append(self.base_url + path)
                raw = self.run(args, timeout=12, limit=MAX_RESPONSE_BYTES)
            if not isinstance(raw, str) or len(raw.encode('utf-8')) > MAX_RESPONSE_BYTES:
                raise ValueError('invalid gluetun response')
        except (OSError, RuntimeError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            raise RuntimeError('gluetun control request failed') from None
        return raw

    def _json(self, path):
        raw = self._request('GET', path)
        try:
            data = decode_json(raw)
            if not isinstance(data, dict):
                raise ValueError('invalid gluetun response')
        except (ValueError, UnicodeError, RecursionError):
            raise ValueError('invalid gluetun JSON response') from None
        return data

    def updater_status(self):
        """gluetun's server-list updater: GET /v1/updater/status, the same
        loop statuses as the VPN's ('completed' after a finished run)."""
        data = self._json('/v1/updater/status')
        status = data.get('status')
        if not isinstance(status, str) or status not in VPN_STATUSES:
            raise ValueError('invalid gluetun updater status')
        return status

    def start_update(self):
        """Ask gluetun to refresh its server list now: PUT /v1/updater/status
        with {"status":"running"} (internal/server/updater.go:62-84,
        wrappers.go:11-26). gluetun answers {"outcome": ...} once the run has
        started, or 'already <status>'. Returns the outcome, bounded."""
        raw = self._request('PUT', '/v1/updater/status', body='{"status":"running"}')
        try:
            data = decode_json(raw)
            outcome = data.get('outcome') if isinstance(data, dict) else None
        except (ValueError, UnicodeError, RecursionError):
            outcome = None
        if not isinstance(outcome, str) or not 0 < len(outcome) <= 64 or not outcome.isprintable():
            raise ValueError('invalid gluetun updater outcome')
        return outcome

    def vpn_status(self):
        data = self._json('/v1/vpn/status')
        status = data.get('status')
        if not isinstance(status, str) or status not in VPN_STATUSES:
            raise ValueError('invalid gluetun VPN status')
        return status

    def select_server(self, relay_or_id, selection_filter=None):
        """Set one exact ID filter, clearing location, tier and feature filters.

        Accept a validated catalogue relay, or its ID and explicit filter name.
        Catalogue uniqueness authorizes exact selection; this client checks the
        ID/filter syntax, not membership in a catalogue.

        v3.41.3 internal/configuration/settings/serverselection.go:24-65 defines
        the filter tags; :316-336 uses OverrideWithSlice/OverrideWithPointer.
        An explicit [] is a non-nil Go slice and replaces the old list; null
        decodes to nil and retains it. false supplies a non-nil *bool and
        clears a boolean filter, whereas null retains it. Do not send null.
        wireguardselection.go:17-33,122-125 holds endpoint/key overrides, not
        list filters; these and all other VPN settings are deliberately omitted.
        internal/server/vpn.go:126-127 returns the outcome as plain text.
        """
        if isinstance(relay_or_id, dict):
            relay_filter = relay_or_id.get('selection_filter')
            if selection_filter is not None and selection_filter != relay_filter:
                raise ValueError('conflicting gluetun server selection filter')
            selection_filter, server_id = relay_filter, relay_or_id.get('id')
        else:
            server_id = relay_or_id
        if not valid_server_id(server_id, selection_filter):
            raise ValueError('invalid gluetun server selection')
        selection = {field: [] for field in LIST_FILTERS}
        selection.update({field: False for field in BOOL_FILTERS})
        selection[selection_filter] = [server_id]
        body = json.dumps({'provider': {'server_selection': selection}}, separators=(',', ':'))
        raw = self._request('PUT', '/v1/vpn/settings', body=body)
        if not 0 < len(raw) <= MAX_OUTCOME_CHARS:
            raise ValueError('invalid gluetun selection outcome')
        outcome = ''.join(c for c in raw if unicodedata.category(c) not in ('Cc', 'Cf', 'Cs')).strip()
        if not outcome:
            raise ValueError('invalid gluetun selection outcome')
        return outcome

    def public_ip(self):
        """Return a canonical IPv4 or IPv6 address, ignoring geolocation fields."""
        data = self._json('/v1/publicip/ip')
        value = data.get('public_ip')
        try:
            if not isinstance(value, str) or len(value) > 45 or '%' in value:
                raise ValueError('invalid gluetun public IP')
            address = ipaddress.ip_address(value)
            if str(address) != value:
                raise ValueError('invalid gluetun public IP')
        except ValueError:
            raise ValueError('invalid gluetun public IP') from None
        return str(address)
