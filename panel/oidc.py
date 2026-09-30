"""Optional OpenID Connect sign-in for Switchyard.

Authorization code flow with PKCE (S256), as a public client unless a client
secret file is configured. Python standard library only.

The ID token is taken from the issuer's token endpoint over a verified TLS
connection, in exchange for a single-use code and a PKCE verifier that only
this process knows. OpenID Connect Core 1.0 section 3.1.3.7 allows TLS server
validation in place of checking the token's signature in exactly this case,
which is what lets the panel stay free of a cryptography dependency. Its
issuer, audience, authorized party, expiry, issue time and nonce are still
checked. The groups claim comes from that ID token; when the ID token has no
groups claim the userinfo endpoint is asked instead, and its subject must
match. See docs/architecture.md, "Sign-in".

Sessions live in this process's memory only: a restart signs everyone out.
Each has a fixed lifetime from sign-in (PANEL_SESSION_TTL), after which the
browser goes back to the issuer and group membership is read again. A sign-in
in progress is held by the browser, in a cookie this process signs, so
nobody can crowd out someone else's sign-in by starting many of their own.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, NamedTuple, Optional, Sequence, Tuple

SESSION_COOKIE = '__Host-molebridge_session'
LOGIN_COOKIE = '__Host-molebridge_login'

DEFAULT_SCOPES = 'openid profile email groups'
DEFAULT_SESSION_TTL = 3600
MIN_SESSION_TTL = 300
MAX_SESSION_TTL = 7 * 24 * 3600
LOGIN_TTL = 600
MAX_SESSIONS = 4096
MAX_SESSIONS_PER_SUBJECT = 16
MAX_CONSUMED_LOGINS = 65536
DISCOVERY_TTL = 3600
HTTP_TIMEOUT_S = 10
MAX_RESPONSE_BYTES = 256 * 1024
CLOCK_SKEW_S = 120
MAX_GROUPS = 256

GROUP_RE = re.compile(r'[^\s,=]{1,128}')
SESSION_ID_RE = re.compile(r'[A-Za-z0-9_-]{43}')
LOGIN_COOKIE_RE = re.compile(r'[A-Za-z0-9_-]{1,2048}\.[A-Za-z0-9_-]{43}')
LOG_NAME_RE = re.compile(r'[^A-Za-z0-9._@+-]')


class AuthError(Exception):
    """A sign-in that cannot complete. The message is fixed text, safe to
    show and to log; it never carries a token or an issuer response body."""


def _is_loopback_host(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    if hostname == 'localhost':
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def secure_url(value: str) -> bool:
    """https, or http to a loopback address (a local test issuer)."""
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    if parts.username or parts.password or parts.fragment or not parts.hostname:
        return False
    return parts.scheme == 'https' or (parts.scheme == 'http' and _is_loopback_host(parts.hostname))


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

class AuthConfig(NamedTuple):
    issuer: str
    client_id: str
    client_secret: Optional[str]
    public_url: str            # canonical https origin, no trailing slash
    scopes: str
    groups_claim: str
    admin_groups: FrozenSet[str]
    access: Mapping[str, FrozenSet[str]]   # group -> exit ids
    session_ttl: int

    @property
    def redirect_uri(self) -> str:
        return self.public_url + '/auth/callback'

    @property
    def public_host(self) -> Tuple[str, Optional[int]]:
        parts = urllib.parse.urlsplit(self.public_url)
        return (parts.hostname or '').lower(), parts.port

    def exits_for(self, groups: FrozenSet[str], all_exit_ids: Sequence[str]) -> Tuple[bool, FrozenSet[str]]:
        """(is admin, granted exit ids) for a set of group names."""
        if groups & self.admin_groups:
            return True, frozenset(all_exit_ids)
        granted = set()
        for group in groups:
            granted |= self.access.get(group, frozenset())
        return False, frozenset(granted)


def _split_list(raw: str) -> List[str]:
    return [item.strip() for item in raw.split(',') if item.strip()]


def parse_access(raw: str, exit_ids: Sequence[str]) -> Dict[str, FrozenSet[str]]:
    """PANEL_ACCESS: comma-separated `group=exit` pairs. Repeat a group to
    grant it several exits. Every exit must be one the panel serves."""
    access: Dict[str, set] = {}
    for entry in _split_list(raw):
        group, sep, exit_id = entry.partition('=')
        group, exit_id = group.strip(), exit_id.strip()
        if not sep or not GROUP_RE.fullmatch(group):
            raise ValueError(f'PANEL_ACCESS: entries are group=exit, with no spaces, commas or = in the group, in {entry!r}')
        if exit_id not in exit_ids:
            raise ValueError(f'PANEL_ACCESS: {exit_id!r} is not an exit in PANEL_EXITS, in {entry!r}')
        access.setdefault(group, set()).add(exit_id)
    return {group: frozenset(ids) for group, ids in access.items()}


def config_from_env(env: Mapping[str, str], exit_ids: Sequence[str]) -> Optional[AuthConfig]:
    """None when PANEL_OIDC_ISSUER is unset: the panel has no login. Raises
    ValueError, which stops the panel, for any incomplete or unsafe setting."""
    issuer = env.get('PANEL_OIDC_ISSUER', '').strip()
    if not issuer:
        for name in ('PANEL_OIDC_CLIENT_ID', 'PANEL_ACCESS', 'PANEL_ADMIN_GROUPS', 'PANEL_PUBLIC_URL'):
            if env.get(name, '').strip():
                raise ValueError(f'{name} is set but PANEL_OIDC_ISSUER is not; set both or neither')
        return None
    if not secure_url(issuer) or urllib.parse.urlsplit(issuer).query:
        raise ValueError('PANEL_OIDC_ISSUER must be an https URL (http only for a loopback test issuer)')
    client_id = env.get('PANEL_OIDC_CLIENT_ID', '').strip()
    if not client_id or len(client_id) > 255 or not client_id.isprintable():
        raise ValueError('PANEL_OIDC_CLIENT_ID is required with PANEL_OIDC_ISSUER')
    client_secret = None
    secret_file = env.get('PANEL_OIDC_CLIENT_SECRET_FILE', '').strip()
    if secret_file:
        try:
            client_secret = Path(secret_file).read_text(encoding='utf-8').strip()
        except OSError as exc:
            raise ValueError(f'PANEL_OIDC_CLIENT_SECRET_FILE cannot be read: {exc.strerror}') from None
        if not client_secret:
            raise ValueError('PANEL_OIDC_CLIENT_SECRET_FILE is empty')
    public_url = env.get('PANEL_PUBLIC_URL', '').strip().rstrip('/')
    parts = urllib.parse.urlsplit(public_url) if public_url else None
    if not parts or not secure_url(public_url) or parts.path or parts.query:
        raise ValueError('PANEL_PUBLIC_URL must be the https origin people open, such as https://exit.example.net')
    scopes = ' '.join(env.get('PANEL_OIDC_SCOPES', DEFAULT_SCOPES).split())
    if 'openid' not in scopes.split():
        raise ValueError('PANEL_OIDC_SCOPES must include openid')
    groups_claim = env.get('PANEL_OIDC_GROUPS_CLAIM', 'groups').strip() or 'groups'
    admin_groups = frozenset(_split_list(env.get('PANEL_ADMIN_GROUPS', '')))
    for group in admin_groups:
        if not GROUP_RE.fullmatch(group):
            raise ValueError(f'PANEL_ADMIN_GROUPS: {group!r} is not a valid group name')
    access = parse_access(env.get('PANEL_ACCESS', ''), exit_ids)
    if not admin_groups and not access:
        raise ValueError('With PANEL_OIDC_ISSUER set, PANEL_ADMIN_GROUPS or PANEL_ACCESS must name at least one group')
    try:
        session_ttl = int(env.get('PANEL_SESSION_TTL', str(DEFAULT_SESSION_TTL)))
    except ValueError:
        raise ValueError('PANEL_SESSION_TTL must be a whole number of seconds') from None
    if not MIN_SESSION_TTL <= session_ttl <= MAX_SESSION_TTL:
        raise ValueError(f'PANEL_SESSION_TTL must be between {MIN_SESSION_TTL} and {MAX_SESSION_TTL} seconds')
    return AuthConfig(issuer, client_id, client_secret, public_url, scopes, groups_claim,
                      admin_groups, access, session_ttl)


# --------------------------------------------------------------------------
# Outbound HTTPS to the issuer
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _opener() -> urllib.request.OpenerDirector:
    # No proxy from the environment and no redirects: the panel talks only to
    # the URLs the issuer's discovery document names.
    context = ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                       urllib.request.HTTPSHandler(context=context))


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _loads(raw: bytes) -> Any:
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_no_duplicates)


def http_json(url: str, *, data: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None,
              what: str) -> Dict[str, Any]:
    """GET (or form POST, with data) a JSON object from the issuer. Raises
    AuthError with a fixed message naming `what`; nothing from the response
    reaches the message."""
    if not secure_url(url):
        raise AuthError(f'{what}: the issuer named an insecure URL')
    body = urllib.parse.urlencode(data).encode('ascii') if data is not None else None
    request = urllib.request.Request(url, data=body, method='POST' if body is not None else 'GET')
    request.add_header('Accept', 'application/json')
    if body is not None:
        request.add_header('Content-Type', 'application/x-www-form-urlencoded')
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with _opener().open(request, timeout=HTTP_TIMEOUT_S) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise AuthError(f'{what}: the issuer answered HTTP {exc.code}') from None
    except (urllib.error.URLError, OSError, ValueError):
        raise AuthError(f'{what}: the issuer could not be reached') from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AuthError(f'{what}: the issuer response is too large')
    try:
        value = _loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise AuthError(f'{what}: the issuer response is not valid JSON') from None
    if not isinstance(value, dict):
        raise AuthError(f'{what}: the issuer response is not a JSON object')
    return value


class Endpoints(NamedTuple):
    authorization: str
    token: str
    userinfo: Optional[str]


def parse_discovery(doc: Dict[str, Any], issuer: str) -> Endpoints:
    if doc.get('issuer') != issuer:
        raise AuthError('discovery: the issuer in the discovery document does not match PANEL_OIDC_ISSUER')
    authorization, token, userinfo = (doc.get(k) for k in
                                      ('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint'))
    for value in (authorization, token):
        if not isinstance(value, str) or not secure_url(value):
            raise AuthError('discovery: the authorization and token endpoints must be https URLs')
    if userinfo is not None and (not isinstance(userinfo, str) or not secure_url(userinfo)):
        userinfo = None
    methods = doc.get('code_challenge_methods_supported')
    if isinstance(methods, list) and 'S256' not in methods:
        raise AuthError('discovery: the issuer does not support PKCE with S256')
    return Endpoints(authorization, token, userinfo)


# --------------------------------------------------------------------------
# PKCE and the ID token
# --------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(text: str) -> bytes:
    if not re.fullmatch(r'[A-Za-z0-9_-]*', text):
        raise ValueError('not base64url')
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode('ascii')).digest())


def id_token_claims(token: Any, *, issuer: str, client_id: str, nonce: str, now: float) -> Dict[str, Any]:
    """Decode and check an ID token received directly from the token
    endpoint over TLS (see the module docstring for why the signature is not
    checked). Raises AuthError on any mismatch."""
    if not isinstance(token, str) or len(token) > 64 * 1024:
        raise AuthError('token: the issuer returned no ID token')
    parts = token.split('.')
    if len(parts) != 3:
        raise AuthError('token: the ID token is malformed')
    try:
        header = _loads(_b64url_decode(parts[0]))
        claims = _loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError):
        raise AuthError('token: the ID token is malformed') from None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise AuthError('token: the ID token is malformed')
    if str(header.get('alg', '')).lower() in ('', 'none') or not parts[2]:
        raise AuthError('token: the ID token is unsigned')
    if claims.get('iss') != issuer:
        raise AuthError('token: the ID token was issued by another issuer')
    audience = claims.get('aud')
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or client_id not in audiences:
        raise AuthError('token: the ID token is for another client')
    if (len(audiences) > 1 or 'azp' in claims) and claims.get('azp') != client_id:
        raise AuthError('token: the ID token is for another client')
    exp, iat = claims.get('exp'), claims.get('iat')
    if not isinstance(exp, (int, float)) or isinstance(exp, bool) or exp + CLOCK_SKEW_S < now:
        raise AuthError('token: the ID token has expired')
    if not isinstance(iat, (int, float)) or isinstance(iat, bool) or iat - CLOCK_SKEW_S > now:
        raise AuthError('token: the ID token was issued in the future')
    claim_nonce = claims.get('nonce')
    if not isinstance(claim_nonce, str) or not hmac.compare_digest(claim_nonce, nonce):
        raise AuthError('token: the ID token does not belong to this sign-in')
    sub = claims.get('sub')
    if not isinstance(sub, str) or not sub or len(sub) > 255:
        raise AuthError('token: the ID token has no subject')
    return claims


def groups_from(claims: Mapping[str, Any], claim: str) -> Optional[FrozenSet[str]]:
    """The group names in a claim; None when the claim is absent. A single
    string counts as one group; anything else that is not a list of strings
    is refused."""
    if claim not in claims:
        return None
    value = claims[claim]
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or len(value) > MAX_GROUPS or not all(isinstance(g, str) for g in value):
        raise AuthError('token: the groups claim is malformed')
    return frozenset(g for g in value if g)


def display_name(claims: Mapping[str, Any]) -> str:
    """A short name for the page and the switch log: preferred_username,
    else email, else the subject. Reduced to a safe character set."""
    for key in ('preferred_username', 'email', 'sub'):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            cleaned = LOG_NAME_RE.sub('_', value.strip())[:64]
            if cleaned.strip('_'):
                return cleaned
    return 'unknown'


# --------------------------------------------------------------------------
# Sign-in state
# --------------------------------------------------------------------------

class PendingLogin(NamedTuple):
    state: str
    nonce: str
    verifier: str
    next_path: str
    created: int


class Session(NamedTuple):
    sub: str
    name: str
    groups: FrozenSet[str]
    admin: bool
    exits: FrozenSet[str]
    expires: float
    csrf_key: str


class Authenticator:
    """Discovery cache, pending sign-ins and sessions for one panel process."""

    def __init__(self, config: AuthConfig, exit_ids: Sequence[str], clock=time.time):
        self.config = config
        self.exit_ids = list(exit_ids)
        self.clock = clock
        self._lock = threading.Lock()
        self._sessions: Dict[str, Session] = {}
        # Signs the pending sign-in cookie; a new key per process.
        self._login_key = secrets.token_bytes(32)
        # state -> created, for sign-ins already finished or refused, so a
        # callback cannot be replayed with the same cookie.
        self._consumed: Dict[str, int] = {}
        self._endpoints: Optional[Tuple[Endpoints, float]] = None

    # -- discovery -----------------------------------------------------------

    def endpoints(self) -> Endpoints:
        now = self.clock()
        with self._lock:
            cached = self._endpoints
        if cached and now - cached[1] < DISCOVERY_TTL:
            return cached[0]
        doc = http_json(self.config.issuer.rstrip('/') + '/.well-known/openid-configuration', what='discovery')
        endpoints = parse_discovery(doc, self.config.issuer)
        with self._lock:
            self._endpoints = (endpoints, now)
        return endpoints

    # -- sign-in ---------------------------------------------------------------

    def begin(self, next_path: str) -> Tuple[str, str]:
        """(value for the pending sign-in cookie, authorization URL)."""
        endpoints = self.endpoints()
        pending = PendingLogin(secrets.token_urlsafe(32), secrets.token_urlsafe(32),
                               secrets.token_urlsafe(48), next_path, int(self.clock()))
        query = urllib.parse.urlencode({
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scopes,
            'state': pending.state,
            'nonce': pending.nonce,
            'code_challenge': pkce_challenge(pending.verifier),
            'code_challenge_method': 'S256',
        })
        separator = '&' if urllib.parse.urlsplit(endpoints.authorization).query else '?'
        return self._seal(pending), f'{endpoints.authorization}{separator}{query}'

    def _seal(self, pending: PendingLogin) -> str:
        body = _b64url(json.dumps(pending._asdict(), separators=(',', ':')).encode('utf-8'))
        mac = _b64url(hmac.new(self._login_key, body.encode('ascii'), hashlib.sha256).digest())
        return f'{body}.{mac}'

    def _open(self, value: Optional[str]) -> PendingLogin:
        """The pending sign-in a cookie holds, if this process signed it and
        it has not expired or been used."""
        expired = AuthError('callback: this browser did not start a sign-in, or it expired')
        if not isinstance(value, str) or not LOGIN_COOKIE_RE.fullmatch(value):
            raise expired
        body, mac = value.split('.')
        expected = _b64url(hmac.new(self._login_key, body.encode('ascii'), hashlib.sha256).digest())
        if not hmac.compare_digest(mac, expected):
            raise expired
        try:
            fields = _loads(_b64url_decode(body))
            pending = PendingLogin(**fields)
        except (ValueError, TypeError, UnicodeDecodeError):
            raise expired from None
        now = self.clock()
        if not isinstance(pending.created, int) or not 0 <= now - pending.created <= LOGIN_TTL:
            raise expired
        with self._lock:
            self._prune(now)
            if pending.state in self._consumed:
                raise expired
            if len(self._consumed) >= MAX_CONSUMED_LOGINS:
                del self._consumed[min(self._consumed, key=self._consumed.__getitem__)]
            self._consumed[pending.state] = pending.created
        return pending

    def finish(self, login_cookie: Optional[str], state: Optional[str], code: Optional[str]) -> Tuple[str, Session, str]:
        """Complete a sign-in: (session id, session, next path). The pending
        sign-in is used up whatever the outcome."""
        pending = self._open(login_cookie)
        if not isinstance(state, str) or not hmac.compare_digest(state, pending.state):
            raise AuthError('callback: the sign-in state does not match')
        if not isinstance(code, str) or not code or len(code) > 4096:
            raise AuthError('callback: the issuer returned no code')
        endpoints = self.endpoints()
        form = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': self.config.redirect_uri,
                'code_verifier': pending.verifier, 'client_id': self.config.client_id}
        headers = {}
        if self.config.client_secret is not None:
            pair = (urllib.parse.quote(self.config.client_id, safe='') + ':' +
                    urllib.parse.quote(self.config.client_secret, safe=''))
            headers['Authorization'] = 'Basic ' + base64.b64encode(pair.encode('utf-8')).decode('ascii')
        tokens = http_json(endpoints.token, data=form, headers=headers, what='token')
        claims = id_token_claims(tokens.get('id_token'), issuer=self.config.issuer,
                                 client_id=self.config.client_id, nonce=pending.nonce, now=self.clock())
        groups = groups_from(claims, self.config.groups_claim)
        if groups is None:
            groups = self._userinfo_groups(endpoints, tokens.get('access_token'), claims['sub'])
        admin, exits = self.config.exits_for(groups, self.exit_ids)
        if not admin and not exits:
            raise AuthError('access: this account is not in a group that may use this panel')
        session = Session(claims['sub'], display_name(claims), groups, admin, exits,
                          self.clock() + self.config.session_ttl, secrets.token_urlsafe(32))
        session_id = secrets.token_urlsafe(32)
        with self._lock:
            self._prune(self.clock())
            # One person's many sign-ins replace their own oldest session,
            # not somebody else's.
            own = sorted((k for k, s in self._sessions.items() if s.sub == session.sub),
                         key=lambda k: self._sessions[k].expires)
            for key in own[:max(0, len(own) - MAX_SESSIONS_PER_SUBJECT + 1)]:
                del self._sessions[key]
            if len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions, key=lambda k: self._sessions[k].expires)
                del self._sessions[oldest]
            self._sessions[session_id] = session
        return session_id, session, pending.next_path

    def discard(self, login_cookie: Optional[str]) -> None:
        """Use up a pending sign-in the issuer refused."""
        try:
            self._open(login_cookie)
        except AuthError:
            pass

    def _userinfo_groups(self, endpoints: Endpoints, access_token: Any, sub: str) -> FrozenSet[str]:
        if endpoints.userinfo is None or not isinstance(access_token, str) or not access_token:
            raise AuthError(f'token: the issuer sent no {self.config.groups_claim} claim')
        info = http_json(endpoints.userinfo, headers={'Authorization': f'Bearer {access_token}'}, what='userinfo')
        if info.get('sub') != sub:
            raise AuthError('userinfo: the subject does not match the ID token')
        groups = groups_from(info, self.config.groups_claim)
        if groups is None:
            raise AuthError(f'userinfo: the issuer sent no {self.config.groups_claim} claim')
        return groups

    # -- sessions --------------------------------------------------------------

    def session(self, session_id: Optional[str]) -> Optional[Session]:
        if not session_id or not SESSION_ID_RE.fullmatch(session_id):
            return None
        now = self.clock()
        with self._lock:
            found = self._sessions.get(session_id)
            if found is not None and found.expires <= now:
                del self._sessions[session_id]
                found = None
        return found

    def end(self, session_id: Optional[str]) -> None:
        if session_id:
            with self._lock:
                self._sessions.pop(session_id, None)

    def _prune(self, now: float) -> None:
        """Drop expired sessions and sign-ins. Caller holds the lock."""
        for key in [k for k, s in self._sessions.items() if s.expires <= now]:
            del self._sessions[key]
        for key in [k for k, created in self._consumed.items() if now - created > LOGIN_TTL]:
            del self._consumed[key]
