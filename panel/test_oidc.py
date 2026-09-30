"""Tests for the panel's optional OpenID Connect sign-in (oidc.py and the
sign-in paths of app.py).

Unit tests exercise oidc.py directly. The Authenticator and HTTP tests talk to
a fake issuer (discovery, token and userinfo endpoints) on 127.0.0.1, which
oidc allows over plain http for tests; the panel runs as a real
ThreadingHTTPServer. All names and addresses are fictitious.
"""
import base64
import http.client
import http.server
import io
import json
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import app  # noqa: E402
import oidc  # noqa: E402

CLIENT_ID = 'switchyard-test'
ISSUER = 'https://idp.example.test'
PUBLIC_URL = 'https://exit.example.test'
EXIT_IDS = ['mine', 'a', 'b']
VALID_PUBKEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='


def env_for(issuer=ISSUER, **overrides):
    """A valid sign-in environment; a value of None removes that setting."""
    env = {'PANEL_OIDC_ISSUER': issuer, 'PANEL_OIDC_CLIENT_ID': CLIENT_ID, 'PANEL_PUBLIC_URL': PUBLIC_URL,
           'PANEL_ADMIN_GROUPS': 'admins', 'PANEL_ACCESS': 'friends-a=a,friends-b=b'}
    env.update(overrides)
    return {k: v for k, v in env.items() if v is not None}


def b64(data):
    if not isinstance(data, bytes):
        data = json.dumps(data).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def make_token(claims, header=None, signature='c2ln'):
    return '.'.join([b64({'alg': 'RS256'} if header is None else header), b64(claims), signature])


class FakeClock:
    """Real time plus an offset the test advances, so tokens the fake issuer
    stamps with real time stay valid while sessions and sign-ins age."""

    def __init__(self):
        self.offset = 0.0

    def __call__(self):
        return time.time() + self.offset

    def advance(self, seconds):
        self.offset += seconds


# --------------------------------------------------------------------------
# The fake issuer
# --------------------------------------------------------------------------

class FakeIssuer:
    ACCESS_TOKEN = 'at-not-a-real-token-7f3a'

    def __init__(self, clock=time.time):
        self.clock = clock                # stamps iat and exp, like the panel's clock
        self.nonce = None                 # the test copies it from the authorization URL
        self.groups = ['friends-a']
        self.include_groups = True
        self.sub = 'user-1'
        self.username = 'jo'
        self.claims_extra = {}
        self.claims_drop = set()
        self.advertise_userinfo = True
        self.userinfo_sub = None          # None: the ID token's subject
        self.userinfo_groups = ['friends-a']
        self.userinfo_include_groups = True
        self.token_status = 200
        self.token_body = None            # raw bytes to send instead of the token response
        self.discovery_hits = 0
        self.requests = []                # (path, form fields, headers)
        self.last_id_token = None
        issuer = self
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send_json(self, obj, status=200):
                self.send_raw(json.dumps(obj).encode(), status)

            def send_raw(self, data, status=200):
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.requests.append((self.path, {}, dict(self.headers)))
                if self.path == '/.well-known/openid-configuration':
                    outer.discovery_hits += 1
                    doc = {'issuer': issuer.url, 'authorization_endpoint': issuer.url + '/authorize',
                           'token_endpoint': issuer.url + '/token',
                           'code_challenge_methods_supported': ['S256']}
                    if outer.advertise_userinfo:
                        doc['userinfo_endpoint'] = issuer.url + '/userinfo'
                    self.send_json(doc)
                elif self.path == '/userinfo':
                    info = {'sub': outer.userinfo_sub if outer.userinfo_sub is not None else outer.sub}
                    if outer.userinfo_include_groups:
                        info['groups'] = outer.userinfo_groups
                    self.send_json(info)
                else:
                    self.send_json({}, 404)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers['Content-Length'])).decode()
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                outer.requests.append((self.path, form, dict(self.headers)))
                if self.path != '/token':
                    self.send_json({}, 404)
                    return
                if outer.token_body is not None or outer.token_status != 200:
                    self.send_raw(outer.token_body if outer.token_body is not None else b'{}', outer.token_status)
                    return
                now = outer.clock()
                claims = {'iss': issuer.url, 'aud': CLIENT_ID, 'sub': outer.sub, 'exp': now + 300, 'iat': now,
                          'nonce': outer.nonce, 'preferred_username': outer.username}
                if outer.include_groups:
                    claims['groups'] = outer.groups
                claims.update(outer.claims_extra)
                for name in outer.claims_drop:
                    claims.pop(name, None)
                outer.last_id_token = make_token(claims)
                self.send_json({'id_token': outer.last_id_token, 'access_token': outer.ACCESS_TOKEN,
                                'token_type': 'Bearer'})

        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.httpd.server_address[1]}'
        threading.Thread(target=self.httpd.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def token_requests(self):
        return [(form, headers) for path, form, headers in self.requests if path == '/token']

    def userinfo_requests(self):
        return [headers for path, form, headers in self.requests if path == '/userinfo']


class Reply:
    """One response from the panel: status, body and headers."""

    def __init__(self, resp, body):
        self.status = resp.status
        self.body = body
        self.headers = resp.getheaders()

    def header(self, name):
        return next((v for k, v in self.headers if k.lower() == name.lower()), None)

    @property
    def location(self):
        return self.header('Location')

    @property
    def set_cookies(self):
        """name -> (value, set of lowercase attributes, with max-age as 'max-age=N')."""
        found = {}
        for key, value in self.headers:
            if key.lower() != 'set-cookie':
                continue
            parts = [p.strip() for p in value.split(';')]
            name, _, val = parts[0].partition('=')
            found[name] = (val, {p.lower() for p in parts[1:]})
        return found

    def signature(self):
        """What must be identical between two answers that may not differ."""
        return self.status, self.body, sorted((k, v) for k, v in self.headers if k.lower() != 'date')


# --------------------------------------------------------------------------
# config_from_env
# --------------------------------------------------------------------------

class ConfigTests(unittest.TestCase):
    def cfg(self, **overrides):
        return oidc.config_from_env(env_for(**overrides), EXIT_IDS)

    def assertRejects(self, fragment=None, **overrides):
        with self.assertRaises(ValueError) as ctx:
            self.cfg(**overrides)
        if fragment:
            self.assertIn(fragment, str(ctx.exception))

    def test_no_issuer_means_no_sign_in(self):
        self.assertIsNone(oidc.config_from_env({}, EXIT_IDS))
        self.assertIsNone(oidc.config_from_env({'PANEL_OIDC_ISSUER': '   '}, EXIT_IDS))
        # Settings that only matter with sign-in do not count as setting it up.
        self.assertIsNone(oidc.config_from_env({'PANEL_SESSION_TTL': '600', 'PANEL_OIDC_SCOPES': 'x'}, EXIT_IDS))

    def test_sign_in_settings_without_an_issuer_are_an_error(self):
        for name, value in (('PANEL_OIDC_CLIENT_ID', CLIENT_ID), ('PANEL_ACCESS', 'friends-a=a'),
                            ('PANEL_ADMIN_GROUPS', 'admins'), ('PANEL_PUBLIC_URL', PUBLIC_URL)):
            with self.subTest(name=name), self.assertRaises(ValueError) as ctx:
                oidc.config_from_env({name: value}, EXIT_IDS)
            self.assertIn(name, str(ctx.exception))

    def test_accepts_a_valid_config(self):
        config = self.cfg()
        self.assertEqual((config.issuer, config.client_id, config.public_url), (ISSUER, CLIENT_ID, PUBLIC_URL))
        self.assertEqual(config.redirect_uri, PUBLIC_URL + '/auth/callback')
        self.assertEqual(config.public_host, ('exit.example.test', None))
        self.assertEqual(config.scopes, oidc.DEFAULT_SCOPES)
        self.assertEqual(config.groups_claim, 'groups')
        self.assertEqual(config.session_ttl, oidc.DEFAULT_SESSION_TTL)
        self.assertIsNone(config.client_secret)
        self.assertEqual(config.admin_groups, frozenset({'admins'}))
        self.assertEqual(dict(config.access), {'friends-a': frozenset({'a'}), 'friends-b': frozenset({'b'})})

    def test_public_url_trailing_slash_is_dropped_and_port_kept(self):
        self.assertEqual(self.cfg(PANEL_PUBLIC_URL='https://exit.example.test/').public_url, PUBLIC_URL)
        config = self.cfg(PANEL_PUBLIC_URL='https://exit.example.test:8443')
        self.assertEqual(config.public_host, ('exit.example.test', 8443))

    def test_loopback_http_issuer_is_allowed_but_no_other_http(self):
        self.assertEqual(self.cfg(PANEL_OIDC_ISSUER='http://127.0.0.1:9000').issuer, 'http://127.0.0.1:9000')
        self.assertEqual(self.cfg(PANEL_OIDC_ISSUER='http://localhost:9000').issuer, 'http://localhost:9000')
        for bad in ('http://idp.example.test', 'http://192.0.2.10', 'ftp://idp.example.test', 'idp.example.test',
                    'https://user:pw@idp.example.test', 'https://idp.example.test#frag',
                    'https://idp.example.test?x=1'):
            with self.subTest(issuer=bad):
                self.assertRejects('PANEL_OIDC_ISSUER', PANEL_OIDC_ISSUER=bad)

    def test_client_id_is_required(self):
        for value in (None, '', '   ', 'x' * 256, 'bad\x07id'):
            with self.subTest(value=value):
                self.assertRejects('PANEL_OIDC_CLIENT_ID', PANEL_OIDC_CLIENT_ID=value)

    def test_public_url_must_be_a_bare_https_origin(self):
        for bad in (None, '', '  ', 'exit.example.test', 'http://exit.example.test',
                    'https://exit.example.test/panel', 'https://exit.example.test/?x=1',
                    'https://exit.example.test?x=1', 'https://exit.example.test#f', 'ftp://exit.example.test',
                    'https://u:p@exit.example.test'):
            with self.subTest(url=bad):
                self.assertRejects('PANEL_PUBLIC_URL', PANEL_PUBLIC_URL=bad)

    def test_scopes_must_include_openid(self):
        self.assertRejects('openid', PANEL_OIDC_SCOPES='profile email groups')
        self.assertRejects('openid', PANEL_OIDC_SCOPES='')
        self.assertEqual(self.cfg(PANEL_OIDC_SCOPES='  groups   openid ').scopes, 'groups openid')

    def test_needs_at_least_one_group(self):
        self.assertRejects('at least one group', PANEL_ADMIN_GROUPS=None, PANEL_ACCESS=None)
        self.assertRejects('at least one group', PANEL_ADMIN_GROUPS='  , ', PANEL_ACCESS='')
        self.assertEqual(self.cfg(PANEL_ADMIN_GROUPS=None).admin_groups, frozenset())
        self.assertEqual(self.cfg(PANEL_ACCESS=None).access, {})

    def test_admin_group_names_are_validated(self):
        self.assertRejects('PANEL_ADMIN_GROUPS', PANEL_ADMIN_GROUPS='two words')
        self.assertRejects('PANEL_ADMIN_GROUPS', PANEL_ADMIN_GROUPS='x' * 129)
        self.assertEqual(self.cfg(PANEL_ADMIN_GROUPS='admins, ops').admin_groups, frozenset({'admins', 'ops'}))

    def test_access_must_name_real_exits_and_be_well_formed(self):
        self.assertRejects('not an exit', PANEL_ACCESS='friends-a=zz')
        self.assertRejects('not an exit', PANEL_ACCESS='friends-a=')
        self.assertRejects('not an exit', PANEL_ACCESS='friends-a=a,friends-b=nope')
        for bad in ('friends', '=a', 'two words=a', 'g=h=a'):
            with self.subTest(entry=bad):
                self.assertRejects('PANEL_ACCESS', PANEL_ACCESS=bad)
        # Nothing to grant in a panel with no PANEL_EXITS.
        with self.assertRaises(ValueError):
            oidc.config_from_env(env_for(), [])

    def test_repeated_group_grants_several_exits(self):
        config = self.cfg(PANEL_ACCESS='family=a, family=b ,friends-a=a')
        self.assertEqual(config.access['family'], frozenset({'a', 'b'}))
        self.assertEqual(config.access['friends-a'], frozenset({'a'}))

    def test_session_ttl_bounds(self):
        self.assertEqual(self.cfg(PANEL_SESSION_TTL='300').session_ttl, 300)
        self.assertEqual(self.cfg(PANEL_SESSION_TTL=str(oidc.MAX_SESSION_TTL)).session_ttl, oidc.MAX_SESSION_TTL)
        for bad in ('299', '0', '-5', str(oidc.MAX_SESSION_TTL + 1)):
            with self.subTest(ttl=bad):
                self.assertRejects('between', PANEL_SESSION_TTL=bad)
        for bad in ('abc', '', '1.5', '1h'):
            with self.subTest(ttl=bad):
                self.assertRejects('whole number', PANEL_SESSION_TTL=bad)

    def test_client_secret_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / 'secret'
            good.write_text('  not-a-real-secret\n')
            self.assertEqual(self.cfg(PANEL_OIDC_CLIENT_SECRET_FILE=str(good)).client_secret, 'not-a-real-secret')
            empty = Path(tmp) / 'empty'
            empty.write_text(' \n')
            self.assertRejects('is empty', PANEL_OIDC_CLIENT_SECRET_FILE=str(empty))
            self.assertRejects('cannot be read', PANEL_OIDC_CLIENT_SECRET_FILE=str(Path(tmp) / 'missing'))
            self.assertRejects('cannot be read', PANEL_OIDC_CLIENT_SECRET_FILE=tmp)  # a directory
            # The message names the problem, never the file's content.
            try:
                self.cfg(PANEL_OIDC_CLIENT_SECRET_FILE=str(empty))
            except ValueError as exc:
                self.assertNotIn('secret', str(exc).replace('SECRET_FILE', ''))

    def test_exits_for(self):
        config = self.cfg(PANEL_ACCESS='family=a,family=b,friends-a=a')
        everything = frozenset(EXIT_IDS)
        self.assertEqual(config.exits_for(frozenset({'admins'}), EXIT_IDS), (True, everything))
        self.assertEqual(config.exits_for(frozenset({'admins', 'friends-a'}), EXIT_IDS), (True, everything))
        self.assertEqual(config.exits_for(frozenset({'friends-a'}), EXIT_IDS), (False, frozenset({'a'})))
        self.assertEqual(config.exits_for(frozenset({'family'}), EXIT_IDS), (False, frozenset({'a', 'b'})))
        self.assertEqual(config.exits_for(frozenset({'friends-a', 'family'}), EXIT_IDS)[1], frozenset({'a', 'b'}))
        self.assertEqual(config.exits_for(frozenset({'strangers'}), EXIT_IDS), (False, frozenset()))
        self.assertEqual(config.exits_for(frozenset(), EXIT_IDS), (False, frozenset()))
        # Group names match exactly.
        self.assertEqual(config.exits_for(frozenset({'Admins', 'FRIENDS-A'}), EXIT_IDS), (False, frozenset()))


# --------------------------------------------------------------------------
# Discovery, ID token, groups, names
# --------------------------------------------------------------------------

class DiscoveryTests(unittest.TestCase):
    def doc(self, **overrides):
        doc = {'issuer': ISSUER, 'authorization_endpoint': ISSUER + '/authorize', 'token_endpoint': ISSUER + '/token',
               'userinfo_endpoint': ISSUER + '/userinfo', 'code_challenge_methods_supported': ['S256', 'plain']}
        doc.update(overrides)
        return {k: v for k, v in doc.items() if v is not None}

    def test_good_document(self):
        endpoints = oidc.parse_discovery(self.doc(), ISSUER)
        self.assertEqual(endpoints, oidc.Endpoints(ISSUER + '/authorize', ISSUER + '/token', ISSUER + '/userinfo'))

    def test_issuer_must_match(self):
        for other in ('https://other.example.test', ISSUER + '/', None, 5):
            with self.subTest(issuer=other), self.assertRaises(oidc.AuthError):
                oidc.parse_discovery(self.doc(issuer=other), ISSUER)

    def test_endpoints_must_be_https(self):
        for key in ('authorization_endpoint', 'token_endpoint'):
            for bad in ('http://idp.example.test/x', 'javascript:alert(1)', None, 7, 'https://u:p@idp.example.test/x'):
                with self.subTest(key=key, bad=bad), self.assertRaises(oidc.AuthError):
                    oidc.parse_discovery(self.doc(**{key: bad}), ISSUER)

    def test_insecure_userinfo_is_dropped_not_trusted(self):
        for bad in ('http://idp.example.test/userinfo', 5, None):
            self.assertIsNone(oidc.parse_discovery(self.doc(userinfo_endpoint=bad), ISSUER).userinfo)

    def test_pkce_s256_is_required_when_the_list_is_given(self):
        with self.assertRaises(oidc.AuthError):
            oidc.parse_discovery(self.doc(code_challenge_methods_supported=['plain']), ISSUER)
        with self.assertRaises(oidc.AuthError):
            oidc.parse_discovery(self.doc(code_challenge_methods_supported=[]), ISSUER)
        oidc.parse_discovery(self.doc(code_challenge_methods_supported=None), ISSUER)  # not advertised: allowed


class IdTokenTests(unittest.TestCase):
    NOW = 1_700_000_000.0
    NONCE = 'nonce-123'

    def claims(self, **overrides):
        claims = {'iss': ISSUER, 'aud': CLIENT_ID, 'sub': 'user-1', 'exp': self.NOW + 300, 'iat': self.NOW,
                  'nonce': self.NONCE}
        claims.update(overrides)
        return {k: v for k, v in claims.items() if v is not ...}

    def check(self, token, nonce=None):
        return oidc.id_token_claims(token, issuer=ISSUER, client_id=CLIENT_ID,
                                    nonce=self.NONCE if nonce is None else nonce, now=self.NOW)

    def assertRefused(self, token, fragment=None, **kwargs):
        with self.assertRaises(oidc.AuthError) as ctx:
            self.check(token, **kwargs)
        if fragment:
            self.assertIn(fragment, str(ctx.exception))

    def test_accepts_a_good_token(self):
        claims = self.check(make_token(self.claims()))
        self.assertEqual((claims['sub'], claims['iss']), ('user-1', ISSUER))

    def test_wrong_issuer(self):
        self.assertRefused(make_token(self.claims(iss='https://other.example.test')), 'another issuer')
        self.assertRefused(make_token(self.claims(iss=...)), 'another issuer')
        self.assertRefused(make_token(self.claims(iss=ISSUER + '/')), 'another issuer')

    def test_wrong_audience(self):
        self.assertRefused(make_token(self.claims(aud='someone-else')), 'another client')
        self.assertRefused(make_token(self.claims(aud=...)), 'another client')
        self.assertRefused(make_token(self.claims(aud=[])), 'another client')
        self.assertRefused(make_token(self.claims(aud=12)), 'another client')
        self.assertRefused(make_token(self.claims(aud=[{'x': 1}])), 'another client')

    def test_several_audiences_need_a_matching_azp(self):
        both = [CLIENT_ID, 'other-client']
        self.assertRefused(make_token(self.claims(aud=both)), 'another client')
        self.assertRefused(make_token(self.claims(aud=both, azp='other-client')), 'another client')
        self.assertRefused(make_token(self.claims(aud=both, azp=5)), 'another client')
        self.check(make_token(self.claims(aud=both, azp=CLIENT_ID)))

    def test_azp_that_is_present_must_match(self):
        self.assertRefused(make_token(self.claims(azp='other-client')), 'another client')
        self.check(make_token(self.claims(azp=CLIENT_ID)))

    def test_expiry_with_bounded_skew(self):
        skew = oidc.CLOCK_SKEW_S
        self.assertRefused(make_token(self.claims(exp=self.NOW - skew - 1)), 'expired')
        self.check(make_token(self.claims(exp=self.NOW - skew + 1)))
        for bad in (..., '9999999999', None, True, [1]):
            with self.subTest(exp=bad):
                self.assertRefused(make_token(self.claims(exp=bad)), 'expired')

    def test_issue_time_in_the_future(self):
        skew = oidc.CLOCK_SKEW_S
        self.assertRefused(make_token(self.claims(iat=self.NOW + skew + 1)), 'future')
        self.check(make_token(self.claims(iat=self.NOW + skew - 1)))
        for bad in (..., '1', None, True):
            with self.subTest(iat=bad):
                self.assertRefused(make_token(self.claims(iat=bad)), 'future')

    def test_nonce_must_match(self):
        self.assertRefused(make_token(self.claims(nonce='other')), 'does not belong')
        self.assertRefused(make_token(self.claims(nonce=...)), 'does not belong')
        self.assertRefused(make_token(self.claims(nonce=None)), 'does not belong')
        self.assertRefused(make_token(self.claims(nonce=12345)), 'does not belong')
        self.assertRefused(make_token(self.claims(nonce='')), 'does not belong', nonce='x')

    def test_subject_is_required(self):
        for bad in (..., '', None, 5, ['u'], 'x' * 256):
            with self.subTest(sub=bad):
                self.assertRefused(make_token(self.claims(sub=bad)), 'no subject')
        self.check(make_token(self.claims(sub='x' * 255)))

    def test_unsigned_tokens_are_refused(self):
        for header in ({'alg': 'none'}, {'alg': 'None'}, {'alg': 'NONE'}, {'alg': ''}, {}, {'typ': 'JWT'}):
            with self.subTest(header=header):
                self.assertRefused(make_token(self.claims(), header=header), 'unsigned')
        self.assertRefused(make_token(self.claims(), signature=''), 'unsigned')

    def test_malformed_tokens(self):
        good = make_token(self.claims())
        head, body, sig = good.split('.')
        for bad in ('', 'abc', 'a.b', good + '.extra', f'{head}.{body}', f'.{body}.{sig}', f'{head}..{sig}'):
            with self.subTest(token=bad[:20]):
                self.assertRefused(bad)
        self.assertRefused(f'{head}.{body}+/=.{sig}', 'malformed')          # not base64url
        self.assertRefused(f'!!!.{body}.{sig}', 'malformed')
        self.assertRefused(f'{head}.{body}A.{sig}' if len(body) % 4 == 0 else f'{head}.{body}AAAA.{sig}')
        self.assertRefused(f'{head}.A.{sig}', 'malformed')                     # impossible base64 length
        self.assertRefused(f'{b64(b"not json")}.{body}.{sig}', 'malformed')
        self.assertRefused(f'{head}.{b64(b"not json")}.{sig}', 'malformed')
        not_utf8 = b64(bytes([0xff, 0xfe]))
        self.assertRefused(f'{head}.{not_utf8}.{sig}', 'malformed')
        self.assertRefused(f'{head}.{b64([1, 2])}.{sig}', 'malformed')         # claims not an object
        self.assertRefused(f'{b64([1])}.{body}.{sig}', 'malformed')            # header not an object
        self.assertRefused(f'{head}.{b64(b"null")}.{sig}', 'malformed')

    def test_duplicate_keys_are_refused(self):
        body = json.dumps(self.claims())[:-1] + ', "sub": "admin"}'
        self.assertRefused(f'{b64({"alg": "RS256"})}.{b64(body.encode())}.c2ln', 'malformed')
        head = b'{"alg": "RS256", "alg": "none"}'
        self.assertRefused(f'{b64(head)}.{b64(self.claims())}.c2ln', 'malformed')

    def test_non_string_and_oversized_input(self):
        for bad in (None, 123, b'a.b.c', {'id_token': 'x'}, ['a', 'b', 'c'], 1.5, True):
            with self.subTest(value=repr(bad)):
                self.assertRefused(bad, 'no ID token')
        self.assertRefused('a' * (64 * 1024 + 1), 'no ID token')


class GroupsAndNamesTests(unittest.TestCase):
    def test_groups_from(self):
        self.assertIsNone(oidc.groups_from({}, 'groups'))
        self.assertIsNone(oidc.groups_from({'roles': ['x']}, 'groups'))
        self.assertEqual(oidc.groups_from({'groups': 'solo'}, 'groups'), frozenset({'solo'}))
        self.assertEqual(oidc.groups_from({'groups': ['a', 'b', 'a']}, 'groups'), frozenset({'a', 'b'}))
        self.assertEqual(oidc.groups_from({'groups': []}, 'groups'), frozenset())
        self.assertEqual(oidc.groups_from({'groups': ['a', '']}, 'groups'), frozenset({'a'}))
        self.assertEqual(oidc.groups_from({'roles': ['r']}, 'roles'), frozenset({'r'}))

    def test_malformed_groups_are_refused(self):
        for bad in (None, 5, True, {'a': 1}, ['a', 1], ['a', None], [['a']], [{'name': 'a'}], 1.5,
                    ['g'] * (oidc.MAX_GROUPS + 1)):
            with self.subTest(value=repr(bad)[:30]), self.assertRaises(oidc.AuthError):
                oidc.groups_from({'groups': bad}, 'groups')

    def test_display_name_preference_and_sanitising(self):
        self.assertEqual(oidc.display_name({'preferred_username': 'jo', 'email': 'jo@example.test', 'sub': 's'}), 'jo')
        self.assertEqual(oidc.display_name({'email': 'jo@example.test', 'sub': 's'}), 'jo@example.test')
        self.assertEqual(oidc.display_name({'sub': 's-1'}), 's-1')
        self.assertEqual(oidc.display_name({}), 'unknown')
        self.assertEqual(oidc.display_name({'preferred_username': 5, 'sub': 's'}), 's')
        self.assertEqual(oidc.display_name({'preferred_username': '   ', 'sub': 's'}), 's')

    def test_display_name_removes_odd_characters(self):
        name = oidc.display_name({'preferred_username': 'jo\nFAKE admin=yes <b>&"\x1b[31m'})
        self.assertRegex(name, r'^[A-Za-z0-9._@+-]+$')
        for char in '\n\r<>&"\x1b =\'':
            self.assertNotIn(char, name)
        self.assertTrue(oidc.display_name({'preferred_username': 'Zoë Ünal'}).isascii())

    def test_display_name_is_capped_and_never_blank(self):
        self.assertEqual(len(oidc.display_name({'preferred_username': 'x' * 500})), 64)
        self.assertEqual(oidc.display_name({'preferred_username': '!!!', 'email': 'a@example.test'}), 'a@example.test')
        self.assertEqual(oidc.display_name({'preferred_username': '???', 'sub': '***'}), 'unknown')
        self.assertEqual(oidc.display_name({'preferred_username': '_'}), 'unknown')


# --------------------------------------------------------------------------
# Authenticator
# --------------------------------------------------------------------------

class AuthenticatorTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.issuer = FakeIssuer(self.clock)
        self.addCleanup(self.issuer.close)
        self.config = oidc.config_from_env(env_for(self.issuer.url), EXIT_IDS)
        self.auth = oidc.Authenticator(self.config, EXIT_IDS, clock=self.clock)

    def begin(self, next_path='/'):
        login_cookie, url = self.auth.begin(next_path)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}
        self.issuer.nonce = query['nonce']
        return login_cookie, query

    def sealed(self, **overrides):
        """A pending sign-in cookie signed by this Authenticator, for a crafted sign-in."""
        fields = {'state': 'st' * 16, 'nonce': 'no' * 16, 'verifier': 'v' * 43, 'next_path': '/',
                  'created': int(self.clock())}
        fields.update(overrides)
        return self.auth._seal(oidc.PendingLogin(**fields))

    def assertNotStarted(self, login_cookie, state='st' * 16, code='code-0001'):
        with self.assertRaises(oidc.AuthError) as ctx:
            self.auth.finish(login_cookie, state, code)
        self.assertEqual(str(ctx.exception), 'callback: this browser did not start a sign-in, or it expired')

    def sign_in(self, groups=('friends-a',), sub='user-1', **extra):
        self.issuer.groups = list(groups)
        self.issuer.sub = sub
        login_id, query = self.begin()
        return self.auth.finish(login_id, query['state'], 'code-0001')

    def test_authorization_url(self):
        login_id, query = self.begin('/?exit=a')
        self.assertRegex(login_id, oidc.LOGIN_COOKIE_RE.pattern)
        self.assertEqual(query['response_type'], 'code')
        self.assertEqual(query['client_id'], CLIENT_ID)
        self.assertEqual(query['redirect_uri'], PUBLIC_URL + '/auth/callback')
        self.assertEqual(query['scope'], oidc.DEFAULT_SCOPES)
        self.assertEqual(query['code_challenge_method'], 'S256')
        self.assertGreaterEqual(len(query['state']), 32)
        self.assertGreaterEqual(len(query['nonce']), 32)
        self.assertNotEqual(query['state'], query['nonce'])
        self.assertTrue(urllib.parse.urlsplit(self.auth.begin('/')[1]).path, '/authorize')

    def test_sign_in_sends_pkce_verifier_and_creates_a_session(self):
        login_id, query = self.begin('/embed?exit=a')
        session_id, session, next_path = self.auth.finish(login_id, query['state'], 'code-0001')
        form, headers = self.issuer.token_requests()[0]
        self.assertEqual(form['grant_type'], 'authorization_code')
        self.assertEqual(form['code'], 'code-0001')
        self.assertEqual(form['redirect_uri'], PUBLIC_URL + '/auth/callback')
        self.assertEqual(form['client_id'], CLIENT_ID)
        self.assertEqual(oidc.pkce_challenge(form['code_verifier']), query['code_challenge'])
        self.assertNotIn('Authorization', headers)            # a public client sends no secret
        self.assertEqual(next_path, '/embed?exit=a')
        self.assertEqual((session.sub, session.name, session.admin, session.exits),
                         ('user-1', 'jo', False, frozenset({'a'})))
        self.assertEqual(session.groups, frozenset({'friends-a'}))
        self.assertIs(self.auth.session(session_id), session)
        self.assertRegex(session_id, oidc.SESSION_ID_RE.pattern)
        self.assertNotEqual(session_id, login_id)
        self.assertNotIn(query['nonce'], session_id)

    def test_admin_session_gets_every_exit(self):
        _, session, _ = self.sign_in(groups=('admins',))
        self.assertTrue(session.admin)
        self.assertEqual(session.exits, frozenset(EXIT_IDS))

    def test_client_secret_is_sent_as_basic_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'secret'
            path.write_text('s3cr3t/value+x\n')
            config = oidc.config_from_env(env_for(self.issuer.url, PANEL_OIDC_CLIENT_SECRET_FILE=str(path)), EXIT_IDS)
        self.auth = oidc.Authenticator(config, EXIT_IDS, clock=self.clock)
        self.sign_in()
        _, headers = self.issuer.token_requests()[0]
        pair = (urllib.parse.quote(CLIENT_ID, safe='') + ':' + urllib.parse.quote('s3cr3t/value+x', safe=''))
        self.assertEqual(headers['Authorization'], 'Basic ' + base64.b64encode(pair.encode()).decode())

    def test_pending_sign_in_is_consumed_once(self):
        login_id, query = self.begin()
        self.auth.finish(login_id, query['state'], 'code-0001')
        self.assertNotStarted(login_id, query['state'])        # replay of the same callback
        self.assertEqual(len(self.issuer.token_requests()), 1)

    def test_wrong_state_fails_and_uses_up_the_sign_in(self):
        for bad in ('wrong', '', None):
            with self.subTest(state=bad):
                login_id, query = self.begin()
                with self.assertRaises(oidc.AuthError) as ctx:
                    self.auth.finish(login_id, bad, 'code-0001')
                self.assertEqual(str(ctx.exception), 'callback: the sign-in state does not match')
                # The correct state no longer helps: the attempt was used up.
                self.assertNotStarted(login_id, query['state'])
        self.assertEqual(self.issuer.token_requests(), [])
        self.assertEqual(self.auth._sessions, {})

    def test_state_from_another_sign_in_fails(self):
        first, first_query = self.begin()
        second, second_query = self.begin()
        with self.assertRaises(oidc.AuthError):
            self.auth.finish(first, second_query['state'], 'code-0001')

    def test_missing_or_bad_login_id_or_code(self):
        login_id, query = self.begin()
        for bad in (None, '', 'short', 'x' * 43, 'é' * 43, 'a.b', '.' + 'A' * 43, 'A' * 2049 + '.' + 'A' * 43,
                    login_id + 'A', 5, b'bytes'):
            with self.subTest(login_id=bad):
                self.assertNotStarted(bad, query['state'])
        for bad in (None, '', 'c' * 4097):
            login_id, query = self.begin()
            with self.subTest(code=bad[:5] if bad else bad), self.assertRaises(oidc.AuthError) as ctx:
                self.auth.finish(login_id, query['state'], bad)
            self.assertIn('no code', str(ctx.exception))

    def test_expired_pending_sign_in_fails(self):
        login_id, query = self.begin()
        self.clock.advance(oidc.LOGIN_TTL + 1)
        with self.assertRaises(oidc.AuthError) as ctx:
            self.auth.finish(login_id, query['state'], 'code-0001')
        self.assertTrue(str(ctx.exception).startswith('callback:'))
        self.assertEqual(self.issuer.token_requests(), [])

    def test_pending_sign_in_still_valid_just_before_expiry(self):
        login_id, query = self.begin()
        self.clock.advance(oidc.LOGIN_TTL - 5)
        self.auth.finish(login_id, query['state'], 'code-0001')

    def test_session_expires_after_session_ttl_and_groups_are_read_again(self):
        session_id, session, _ = self.sign_in(groups=('friends-a',))
        ttl = self.config.session_ttl
        self.clock.advance(ttl - 5)
        self.assertIs(self.auth.session(session_id), session)
        self.clock.advance(10)
        self.assertIsNone(self.auth.session(session_id))
        self.assertNotIn(session_id, self.auth._sessions)
        # Removed from the group at the issuer: the next sign-in is refused.
        with self.assertRaises(oidc.AuthError) as ctx:
            self.sign_in(groups=('someone-elses',))
        self.assertTrue(str(ctx.exception).startswith('access:'))

    def test_session_expires_exactly_at_the_ttl(self):
        session_id, _, _ = self.sign_in()
        self.clock.advance(self.config.session_ttl + 0.001)
        self.assertIsNone(self.auth.session(session_id))

    def test_groups_granting_nothing_get_no_session(self):
        for groups in (['strangers'], [], ['Admins'], ['friends-a ']):
            with self.subTest(groups=groups), self.assertRaises(oidc.AuthError) as ctx:
                self.sign_in(groups=groups)
            self.assertTrue(str(ctx.exception).startswith('access:'))
        self.assertEqual(self.auth._sessions, {})
        self.assertEqual(self.issuer.userinfo_requests(), [])   # an empty claim is an answer, not a gap

    def test_userinfo_fallback_when_the_id_token_has_no_groups_claim(self):
        self.issuer.include_groups = False
        self.issuer.userinfo_groups = ['friends-b']
        _, session, _ = self.sign_in(groups=())
        self.assertEqual(session.exits, frozenset({'b'}))
        self.assertEqual(self.issuer.userinfo_requests()[0]['Authorization'], 'Bearer ' + FakeIssuer.ACCESS_TOKEN)

    def test_userinfo_with_another_subject_is_refused(self):
        self.issuer.include_groups = False
        self.issuer.userinfo_sub = 'someone-else'
        self.issuer.userinfo_groups = ['admins']
        with self.assertRaises(oidc.AuthError) as ctx:
            self.sign_in()
        self.assertTrue(str(ctx.exception).startswith('userinfo:'))
        self.assertEqual(self.auth._sessions, {})

    def test_userinfo_without_groups_or_without_endpoint_is_refused(self):
        self.issuer.include_groups = False
        self.issuer.userinfo_include_groups = False
        with self.assertRaises(oidc.AuthError) as ctx:
            self.sign_in()
        self.assertIn('no groups claim', str(ctx.exception))
        # No userinfo endpoint advertised: nowhere else to look.
        self.issuer.advertise_userinfo = False
        self.auth = oidc.Authenticator(self.config, EXIT_IDS, clock=self.clock)
        with self.assertRaises(oidc.AuthError) as ctx:
            self.sign_in()
        self.assertTrue(str(ctx.exception).startswith('token:'))
        self.assertEqual(self.auth._sessions, {})

    def test_custom_groups_claim(self):
        config = oidc.config_from_env(env_for(self.issuer.url, PANEL_OIDC_GROUPS_CLAIM='roles'), EXIT_IDS)
        self.auth = oidc.Authenticator(config, EXIT_IDS, clock=self.clock)
        self.issuer.include_groups = False
        self.issuer.claims_extra = {'roles': ['friends-b']}
        _, session, _ = self.sign_in()
        self.assertEqual(session.exits, frozenset({'b'}))

    def test_malformed_groups_claim_is_refused(self):
        self.issuer.claims_extra = {'groups': {'friends-a': True}}
        with self.assertRaises(oidc.AuthError):
            self.sign_in()

    def test_id_token_problems_leave_no_session(self):
        now = self.clock()
        cases = {'iss': 'https://other.example.test', 'aud': 'other', 'exp': now - 9999,
                 'iat': now + 9999, 'nonce': 'not-mine'}
        for claim, value in cases.items():
            with self.subTest(claim=claim):
                self.issuer.claims_extra = {claim: value}
                with self.assertRaises(oidc.AuthError):
                    self.sign_in()
        self.issuer.claims_extra = {}
        self.issuer.claims_drop = {'sub'}
        with self.assertRaises(oidc.AuthError):
            self.sign_in()
        self.assertEqual(self.auth._sessions, {})

    def test_issuer_failures_give_fixed_messages_without_the_response_body(self):
        self.issuer.token_status = 500
        self.issuer.token_body = b'{"error_description": "leak-me-please", "id_token": "leak-me-too"}'
        with self.assertRaises(oidc.AuthError) as ctx:
            self.sign_in()
        self.assertEqual(str(ctx.exception), 'token: the issuer answered HTTP 500')
        self.issuer.token_status = 200
        for body, fragment in ((b'leak-me-please', 'not valid JSON'), (b'["leak-me-please"]', 'not a JSON object'),
                               (b'{"a": 1, "a": 2}', 'not valid JSON'), (b'x' * (oidc.MAX_RESPONSE_BYTES + 10), 'too large')):
            self.issuer.token_body = body
            with self.subTest(fragment=fragment), self.assertRaises(oidc.AuthError) as ctx:
                self.sign_in()
            self.assertIn(fragment, str(ctx.exception))
            self.assertNotIn('leak-me', str(ctx.exception))
        self.issuer.token_body = b'{"access_token": "x"}'
        with self.assertRaises(oidc.AuthError) as ctx:
            self.sign_in()
        self.assertIn('no ID token', str(ctx.exception))

    def test_unreachable_issuer(self):
        dead = FakeIssuer()
        dead.close()
        config = oidc.config_from_env(env_for(dead.url), EXIT_IDS)
        auth = oidc.Authenticator(config, EXIT_IDS, clock=self.clock)
        with self.assertRaises(oidc.AuthError) as ctx:
            auth.begin('/')
        self.assertEqual(str(ctx.exception), 'discovery: the issuer could not be reached')

    def test_discovery_is_cached_then_refreshed(self):
        self.begin()
        self.begin()
        self.assertEqual(self.issuer.discovery_hits, 1)
        self.clock.advance(oidc.DISCOVERY_TTL + 1)
        self.begin()
        self.assertEqual(self.issuer.discovery_hits, 2)

    def test_session_lookup_rejects_junk_and_end_removes(self):
        session_id, _, _ = self.sign_in()
        for junk in (None, '', 'short', 'x' * 43, session_id + 'x', session_id[:-1], 'é' * 43):
            self.assertIsNone(self.auth.session(junk))
        self.assertIsNotNone(self.auth.session(session_id))
        self.auth.end('unknown')
        self.auth.end(None)
        self.assertIsNotNone(self.auth.session(session_id))
        self.auth.end(session_id)
        self.assertIsNone(self.auth.session(session_id))

    def test_discard_uses_up_a_pending_sign_in(self):
        login_id, query = self.begin()
        self.auth.discard(login_id)
        self.auth.discard(None)
        self.auth.discard('junk')
        self.assertNotStarted(login_id, query['state'])
        self.assertEqual(self.issuer.token_requests(), [])

    def test_tampered_cookies_fail(self):
        login_id, query = self.begin()
        body, mac = login_id.split('.')
        other_body = self.sealed().split('.')[0]
        flipped = ('A' if mac[0] != 'A' else 'B') + mac[1:]
        for label, cookie in (('body changed', other_body + '.' + mac),
                              ('mac changed', body + '.' + flipped),
                              ('mac cut', body + '.' + mac[:-1]),
                              ('mac emptied', body + '.'),
                              ('body emptied', '.' + mac),
                              ('mac swapped with body', mac + '.' + body),
                              ('two macs', login_id + '.' + mac)):
            with self.subTest(tamper=label):
                self.assertNotStarted(cookie, query['state'])
        # The untouched cookie still works: tampering did not use it up.
        self.auth.finish(login_id, query['state'], 'code-0001')

    def test_altering_the_embedded_fields_fails(self):
        login_id, query = self.begin('/')
        body, mac = login_id.split('.')
        fields = json.loads(oidc._b64url_decode(body))
        fields['next_path'] = '/embed?exit=b'
        forged = oidc._b64url(json.dumps(fields, separators=(',', ':')).encode()) + '.' + mac
        self.assertNotStarted(forged, query['state'])

    def test_cookie_from_another_authenticator_fails(self):
        other = oidc.Authenticator(self.config, EXIT_IDS, clock=self.clock)
        login_cookie, url = other.begin('/')
        query = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}
        self.issuer.nonce = query['nonce']
        self.assertNotStarted(login_cookie, query['state'])
        self.assertEqual(self.issuer.token_requests(), [])
        other.finish(login_cookie, query['state'], 'code-0001')     # it does work where it was made

    def test_a_process_restart_invalidates_pending_sign_ins(self):
        login_id, query = self.begin()
        restarted = oidc.Authenticator(self.config, EXIT_IDS, clock=self.clock)
        with self.assertRaises(oidc.AuthError):
            restarted.finish(login_id, query['state'], 'code-0001')

    def test_signed_cookies_with_bad_contents_fail(self):
        now = int(self.clock())
        for label, overrides in (('future', {'created': now + 1000}), ('ancient', {'created': now - 10 * 86400}),
                                 ('negative', {'created': -5}), ('string time', {'created': str(now)}),
                                 ('float time', {'created': float(now) + 0.5}), ('null time', {'created': None})):
            with self.subTest(label=label):
                self.assertNotStarted(self.sealed(**overrides))
        # Correctly signed but not the right shape.
        key = self.auth._login_key
        for label, fields in (('extra field', {'state': 's', 'nonce': 'n', 'verifier': 'v', 'next_path': '/',
                                              'created': now, 'admin': True}),
                              ('missing field', {'state': 's', 'nonce': 'n'}), ('not an object', [1, 2]),
                              ('duplicate keys', None)):
            with self.subTest(label=label):
                raw = (b'{"state": "s", "state": "t"}' if fields is None
                       else json.dumps(fields, separators=(',', ':')).encode())
                body = oidc._b64url(raw)
                mac = oidc._b64url(oidc.hmac.new(key, body.encode(), oidc.hashlib.sha256).digest())
                self.assertNotStarted(f'{body}.{mac}')

    def test_expired_cookie_fails_and_is_not_accepted_late(self):
        login_id, query = self.begin()
        self.clock.advance(oidc.LOGIN_TTL + 2)
        self.assertNotStarted(login_id, query['state'])
        self.assertEqual(self.issuer.token_requests(), [])

    def test_many_sign_ins_do_not_disturb_another_browsers_pending_sign_in(self):
        victim, victim_query = self.begin()
        for _ in range(3000):
            self.auth.begin('/')
        self.assertEqual(self.auth._sessions, {})
        self.issuer.nonce = victim_query['nonce']
        _, session, _ = self.auth.finish(victim, victim_query['state'], 'code-0001')
        self.assertEqual(session.sub, 'user-1')

    def test_the_replay_memory_is_bounded(self):
        with patch.object(oidc, 'MAX_CONSUMED_LOGINS', 3):
            for _ in range(10):
                login_id, query = self.begin()
                self.auth.discard(login_id)
                self.assertLessEqual(len(self.auth._consumed), 3)

    def test_one_subjects_sign_ins_replace_their_own_oldest_session_only(self):
        with patch.object(oidc, 'MAX_SESSIONS_PER_SUBJECT', 2):
            bystander = self.sign_in(sub='bystander')[0]
            ids = []
            for _ in range(4):
                self.clock.advance(1)
                ids.append(self.sign_in(sub='busy')[0])
            self.assertIsNotNone(self.auth.session(bystander))
            self.assertEqual([self.auth.session(i) is not None for i in ids], [False, False, True, True])
            self.assertEqual(len(self.auth._sessions), 3)
            # Another subject is not affected by the first one's churn.
            other = self.sign_in(sub='other')[0]
            self.assertIsNotNone(self.auth.session(other))
            self.assertIsNotNone(self.auth.session(ids[-1]))

    def test_sessions_are_capped_by_evicting_the_oldest(self):
        with patch.object(oidc, 'MAX_SESSIONS', 2):
            ids = []
            for index in range(3):
                self.clock.advance(1)
                ids.append(self.sign_in(sub=f'user-{index}')[0])
            self.assertEqual(len(self.auth._sessions), 2)
            self.assertIsNone(self.auth.session(ids[0]))
            self.assertIsNotNone(self.auth.session(ids[1]))
            self.assertIsNotNone(self.auth.session(ids[2]))

    def test_expired_entries_are_pruned_not_kept(self):
        login_id, query = self.begin()
        self.auth.finish(login_id, query['state'], 'code-0001')
        self.assertEqual(len(self.auth._consumed), 1)
        self.clock.advance(self.config.session_ttl + oidc.LOGIN_TTL + 1)
        self.begin()
        self.auth.discard(self.begin()[0])
        self.assertEqual(len(self.auth._consumed), 1)
        # Expired sessions go at the next completed sign-in.
        login_id, query = self.begin()
        self.auth.finish(login_id, query['state'], 'code-0002')
        self.assertEqual(len(self.auth._sessions), 1)


# --------------------------------------------------------------------------
# The panel over HTTP
# --------------------------------------------------------------------------

class PanelAuthBase(unittest.TestCase):
    """The panel with sign-in on: exits mine (Mullvad), a (Mullvad) and b (PIA),
    admin group `admins`, `friends-a` granted a and `friends-b` granted b."""

    SELECT_SERVER = 'se-got-wg-002'

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        stderr = patch.object(sys, 'stderr', io.StringIO())
        self.stderr = stderr.start()
        self.addCleanup(stderr.stop)

        self.clock = FakeClock()
        self.issuer = FakeIssuer(self.clock)
        self.addCleanup(self.issuer.close)
        self.exits = app.parse_exits('mine=mullvad,a=mullvad,b=pia', self.tmpdir)
        self.mine, self.a, self.b = self.exits
        self.write_catalogues()
        self.enable_auth(env_for(self.issuer.url))
        patcher = patch.object(app, 'PANEL_HOME_URL', 'https://home.example.test')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.start_panel()

    def write_catalogues(self):
        def mullvad(host, code, ip):
            return {'hostname': host, 'country': 'Sweden', 'city': 'Stockholm', 'location_code': code,
                    'public_key': VALID_PUBKEY, 'ipv4_addr_in': ip}
        region = {'hostname': 'ex_example', 'country': 'Exampleland', 'city': 'Example City',
                  'location_code': 'ex-ex_example', 'ipv4_addr_in': '198.51.100.21',
                  'port_forward': True, 'geo': True, 'servers': [{'ip': '198.51.100.20', 'cn': 'example401'}]}
        app.write_json_atomic(self.mine.relays_path, {'fetched_at': app.now_iso(), 'relays': {
            'se-sto-wg-001': mullvad('se-sto-wg-001', 'se-sto', '198.51.100.10')}})
        app.write_json_atomic(self.a.relays_path, {'fetched_at': app.now_iso(), 'relays': {
            self.SELECT_SERVER: mullvad(self.SELECT_SERVER, 'se-got', '198.51.100.11')}})
        app.write_json_atomic(self.b.relays_path, {'fetched_at': app.now_iso(), 'provider': 'pia',
                                                   'relays': {'ex_example': region}})
        self.write_ok(self.a)
        self.write_ok(self.b, provider='pia')

    def write_ok(self, ex, provider='mullvad'):
        app.write_json_atomic(ex.result_path, {'status': 'ok', 'checked_at': app.now_iso(), 'routing_ok': True,
                                               'exit_confirmed': True, 'provider': provider,
                                               'server': 'ex_example' if provider == 'pia' else self.SELECT_SERVER})

    def enable_auth(self, env):
        config = oidc.config_from_env(env, [e.id for e in self.exits])
        self.auth = oidc.Authenticator(config, [e.id for e in self.exits], clock=self.clock)
        for target, value in (('EXITS', self.exits), ('AUTH_CONFIG', config), ('AUTH', self.auth)):
            patcher = patch.object(app, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.config = config

    def start_panel(self):
        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), app.PanelHandler)
        threading.Thread(target=self.httpd.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    # -- requests ---------------------------------------------------------

    def request(self, method, path, *, body=None, cookie=None, headers=None):
        send = dict(headers or {})
        if cookie:
            send['Cookie'] = cookie
        conn = http.client.HTTPConnection('127.0.0.1', self.httpd.server_address[1], timeout=5)
        conn.request(method, path, body=body, headers=send)
        resp = conn.getresponse()
        data = resp.read().decode()
        conn.close()
        return Reply(resp, data)

    def get(self, path, cookie=None, **kwargs):
        return self.request('GET', path, cookie=cookie, **kwargs)

    def post(self, path, fields, cookie=None, origin=None):
        body = urllib.parse.urlencode(fields).encode()
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if origin:
            headers['Origin'] = origin
        return self.request('POST', path, body=body, cookie=cookie, headers=headers)

    # -- signing in -------------------------------------------------------

    def begin_login(self, next_path='/'):
        reply = self.get('/login?' + urllib.parse.urlencode({'next': next_path}))
        query = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(reply.location).query).items()}
        self.issuer.nonce = query.get('nonce')
        return reply, query

    def callback(self, query, login_cookie, code=None, **extra):
        params = {'code': code or 'authcode-' + secrets.token_hex(8), 'state': query['state']}
        params.update(extra)
        return self.get('/auth/callback?' + urllib.parse.urlencode(params),
                        cookie=f'{oidc.LOGIN_COOKIE}={login_cookie}' if login_cookie else None)

    def sign_in(self, groups=('friends-a',), name='jo', sub='user-1', next_path='/'):
        self.issuer.groups = list(groups)
        self.issuer.username = name
        self.issuer.sub = sub
        login, query = self.begin_login(next_path)
        self.assertEqual(login.status, 303)
        done = self.callback(query, login.set_cookies[oidc.LOGIN_COOKIE][0])
        self.assertEqual(done.status, 303, done.body)
        session_id = done.set_cookies[oidc.SESSION_COOKIE][0]
        return f'{oidc.SESSION_COOKIE}={session_id}'

    def page_tokens(self, cookie, exit_id='a', path='/'):
        page = self.get(f'{path}?exit={exit_id}', cookie)
        self.assertEqual(page.status, 200, page.body)
        nonce = page.set_cookies['csrf_nonce'][0]
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.body).group(1)
        return nonce, token

    def select(self, cookie, exit_id, server=None, *, tokens=None, origin=None, **extra):
        nonce, token = tokens or self.page_tokens(cookie)
        fields = {'server': self.SELECT_SERVER if server is None else server, 'csrf_token': token, 'exit': exit_id, **extra}
        return self.post('/select', fields, cookie=f'{cookie}; csrf_nonce={nonce}', origin=origin)

    def assertNoDesired(self, *exits):
        for ex in exits or self.exits:
            self.assertFalse(ex.desired_path.exists(), f'{ex.id} was written')

    def session_count(self):
        return len(self.auth._sessions)


class SignedOutTests(PanelAuthBase):
    def test_full_page_redirects_to_the_canonical_login_url(self):
        reply = self.get('/')
        self.assertEqual(reply.status, 303)
        parts = urllib.parse.urlsplit(reply.location)
        self.assertEqual((parts.scheme, parts.netloc, parts.path), ('https', 'exit.example.test', '/login'))
        self.assertEqual(urllib.parse.parse_qs(parts.query), {'next': ['/']})
        parts = urllib.parse.urlsplit(self.get('/?exit=a').location)
        self.assertEqual(urllib.parse.parse_qs(parts.query), {'next': ['/?exit=a']})
        self.assertEqual(reply.header('Cache-Control'), 'no-store')
        self.assertNotIn('csrf_nonce', reply.set_cookies)

    def test_hostile_exit_value_does_not_reach_the_login_url(self):
        for value in ('../etc', 'A', 'a&next=https://evil.example.test', '%0d%0aX:y', 'x' * 40):
            with self.subTest(value=value):
                reply = self.get('/?exit=' + urllib.parse.quote(value, safe=''))
                self.assertEqual(reply.status, 303)
                self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(reply.location).query), {'next': ['/']})
                self.assertTrue(reply.location.startswith('https://exit.example.test/login?'))

    def test_embed_shows_a_sign_in_link_that_opens_a_new_tab(self):
        reply = self.get('/embed?exit=a')
        self.assertEqual(reply.status, 200)
        link = re.search(r'<a [^>]*href="([^"]+)"[^>]*>', reply.body)
        self.assertIsNotNone(link)
        self.assertIn('target="_blank"', link.group(0))
        self.assertIn('rel="noopener"', link.group(0))
        self.assertTrue(link.group(1).startswith('https://exit.example.test/login?next='))
        self.assertIn('Sign in', reply.body)
        # Nothing about the exits is in the page.
        for text in ('data-exit=', 'csrf_token', 'Stockholm', 'name="server"'):
            self.assertNotIn(text, reply.body)

    def test_every_api_path_is_401_json(self):
        for path in ('/api/exits', '/api/status?exit=a', '/api/status', '/api/latency?exit=a',
                     '/api/latency?exit=nope', '/api/status?exit=b'):
            with self.subTest(path=path):
                reply = self.get(path)
                self.assertEqual(reply.status, 401)
                self.assertEqual(reply.header('Content-Type'), 'application/json')
                self.assertEqual(json.loads(reply.body), {'error': 'sign in required'})

    def test_select_is_401_and_writes_nothing(self):
        # Even with a token that would verify for an anonymous caller.
        nonce = app.new_csrf_nonce()
        fields = {'server': self.SELECT_SERVER, 'csrf_token': app.csrf_token(nonce), 'exit': 'a'}
        for exit_id in ('a', 'b', 'mine', 'nope'):
            fields['exit'] = exit_id
            reply = self.post('/select', fields, cookie=f'csrf_nonce={nonce}')
            self.assertEqual(reply.status, 401)
        self.assertNoDesired()

    def test_health_and_static_need_no_login(self):
        self.assertEqual((self.get('/healthz').status, self.get('/healthz').body), (200, 'ok'))
        self.assertEqual(self.get('/static/panel.css').status, 200)
        self.assertEqual(self.get('/static/panel.js').status, 200)
        manifest = self.get('/manifest.webmanifest')
        self.assertEqual(manifest.status, 200)
        self.assertEqual(json.loads(manifest.body)['start_url'], '/')
        self.assertEqual(self.get('/static/nope.css').status, 404)

    def test_readyz_aggregate_needs_no_login(self):
        self.assertEqual(self.get('/readyz').status, 503)        # `mine` has no status yet
        self.write_ok(self.mine)
        reply = self.get('/readyz')
        self.assertEqual((reply.status, reply.body), (200, 'ready'))

    def test_readyz_does_not_reveal_which_exits_exist(self):
        nonexistent = self.get('/readyz?exit=zz-nope')
        self.assertEqual(nonexistent.status, 404)
        for exit_id in ('a', 'b', 'mine'):
            with self.subTest(exit=exit_id):
                self.assertEqual(self.get(f'/readyz?exit={exit_id}').signature(), nonexistent.signature())

    def test_login_related_pages_are_reachable_signed_out(self):
        self.assertEqual(self.get('/signed-out').status, 200)
        self.assertEqual(self.get('/login').status, 303)

    def test_logout_without_a_session_still_lands_on_signed_out(self):
        reply = self.post('/logout', {})
        self.assertEqual((reply.status, reply.location), (303, PUBLIC_URL + '/signed-out'))

    def test_unknown_session_cookies_are_signed_out(self):
        junk = (secrets.token_urlsafe(32), 'x' * 43, 'short', '', 'a;b', '"quoted"', 'é')
        for value in junk:
            cookie = f'{oidc.SESSION_COOKIE}={value}'
            with self.subTest(cookie=value):
                self.assertEqual(self.get('/api/exits', cookie).status, 401)
                self.assertEqual(self.get('/?exit=a', cookie).status, 303)
                self.assertEqual(self.select_with_forged_token(cookie).status, 401)
        self.assertNoDesired()

    def select_with_forged_token(self, cookie):
        nonce = app.new_csrf_nonce()
        return self.post('/select', {'server': self.SELECT_SERVER, 'csrf_token': app.csrf_token(nonce), 'exit': 'a'},
                         cookie=f'{cookie}; csrf_nonce={nonce}')

    def test_another_cookie_name_is_not_a_session(self):
        session = self.sign_in()
        value = session.split('=', 1)[1]
        # Without the __Host- prefix the cookie means nothing.
        self.assertEqual(self.get('/api/exits', f'molebridge_session={value}').status, 401)
        self.assertEqual(self.get('/api/exits', session).status, 200)


class SignInFlowTests(PanelAuthBase):
    def test_login_redirects_to_the_issuer_with_a_locked_down_cookie(self):
        reply, query = self.begin_login('/?exit=a')
        self.assertEqual(reply.status, 303)
        self.assertTrue(reply.location.startswith(self.issuer.url + '/authorize?'))
        self.assertEqual(query['redirect_uri'], PUBLIC_URL + '/auth/callback')
        self.assertEqual(query['code_challenge_method'], 'S256')
        value, attrs = reply.set_cookies[oidc.LOGIN_COOKIE]
        self.assertTrue(oidc.LOGIN_COOKIE.startswith('__Host-'))
        self.assertRegex(value, oidc.LOGIN_COOKIE_RE.pattern)
        self.assertLessEqual({'secure', 'httponly', 'samesite=lax', 'path=/', f'max-age={oidc.LOGIN_TTL}'}, attrs)
        self.assertFalse([a for a in attrs if a.startswith('domain')])
        self.assertNotIn(value, reply.location)        # the cookie is not sent to the issuer
        self.assertNotEqual(value.split('.')[0], query['state'])

    def test_login_over_plain_http_is_sent_to_the_canonical_https_url_without_a_cookie(self):
        for proto in ('http', 'HTTP', ' http ', 'ws', ''):
            with self.subTest(proto=proto):
                reply = self.get('/login?next=%2F%3Fexit%3Da', headers={'X-Forwarded-Proto': proto})
                self.assertEqual(reply.status, 303)
                self.assertEqual(reply.location, PUBLIC_URL + '/login?next=%2F%3Fexit%3Da&canonical=1')
                self.assertEqual(reply.set_cookies, {})
        self.assertEqual(self.get('/login', headers={'X-Forwarded-Proto': 'http'}).location,
                         PUBLIC_URL + '/login?next=%2F&canonical=1')
        # Hostile next is still reduced on the way.
        reply = self.get('/login?next=https://evil.example.test/', headers={'X-Forwarded-Proto': 'http'})
        self.assertEqual(reply.location, PUBLIC_URL + '/login?next=%2F&canonical=1')
        self.assertEqual(self.issuer.requests, [])       # the issuer was never contacted
        # A signed-in browser that arrives over http is also sent to https first.
        session = self.sign_in()
        reply = self.get('/login', session, headers={'X-Forwarded-Proto': 'http'})
        self.assertEqual(reply.location, PUBLIC_URL + '/login?next=%2F&canonical=1')

    def test_a_proxy_that_always_says_http_is_redirected_once_not_forever(self):
        reply = self.get('/login?next=%2F&canonical=1', headers={'X-Forwarded-Proto': 'http'})
        self.assertEqual(reply.status, 303)
        self.assertTrue(reply.location.startswith(self.issuer.url + '/authorize?'))

    def test_login_over_https_or_without_the_header_starts_the_sign_in(self):
        for headers in ({'X-Forwarded-Proto': 'https'}, {'X-Forwarded-Proto': 'HTTPS'},
                        {'X-Forwarded-Proto': ' https '}, {}):
            with self.subTest(headers=headers):
                reply = self.get('/login', headers=headers)
                self.assertEqual(reply.status, 303)
                self.assertTrue(reply.location.startswith(self.issuer.url + '/authorize?'))
                self.assertIn(oidc.LOGIN_COOKIE, reply.set_cookies)

    def test_login_cookie_is_signed_and_tampering_fails(self):
        login, query = self.begin_login()
        cookie = login.set_cookies[oidc.LOGIN_COOKIE][0]
        body, mac = cookie.split('.')
        for bad in (body + '.' + ('A' if mac[0] != 'A' else 'B') + mac[1:], body + '.', 'x.' + mac, body):
            with self.subTest(cookie=bad[-8:]):
                self.assertEqual(self.callback(query, bad).status, 400)
        self.assertEqual(self.session_count(), 0)
        self.assertEqual(self.issuer.token_requests(), [])
        self.assertEqual(self.callback(query, cookie).status, 303)

    def test_many_logins_do_not_break_someone_elses_sign_in(self):
        login, query = self.begin_login()
        cookie = login.set_cookies[oidc.LOGIN_COOKIE][0]
        for _ in range(30):
            self.assertEqual(self.get('/login').status, 303)
        self.issuer.nonce = query['nonce']
        self.assertEqual(self.callback(query, cookie).status, 303)

    def test_sign_in_started_before_a_restart_fails(self):
        login, query = self.begin_login()
        cookie = login.set_cookies[oidc.LOGIN_COOKIE][0]
        restarted = oidc.Authenticator(self.config, [e.id for e in self.exits], clock=self.clock)
        with patch.object(app, 'AUTH', restarted):
            self.assertEqual(self.callback(query, cookie).status, 400)

    def test_login_with_hostile_next_lands_on_the_root(self):
        for bad in ('https://evil.example.test/', '//evil.example.test', '/\\evil', '/static/x', '/?exit=A',
                    '/embed?exit=a&x=1', 'javascript:alert(1)'):
            with self.subTest(next=bad):
                self.begin_login(bad)
                login, query = self.begin_login(bad)
                done = self.callback(query, login.set_cookies[oidc.LOGIN_COOKIE][0])
                self.assertEqual(done.location, PUBLIC_URL + '/')

    def test_callback_sets_locked_down_cookies_and_redirects_to_the_canonical_url(self):
        login, query = self.begin_login('/embed?exit=a')
        done = self.callback(query, login.set_cookies[oidc.LOGIN_COOKIE][0])
        self.assertEqual((done.status, done.location), (303, PUBLIC_URL + '/embed?exit=a'))
        cleared_value, cleared_attrs = done.set_cookies[oidc.LOGIN_COOKIE]
        self.assertEqual(cleared_value, '')
        self.assertIn('max-age=0', cleared_attrs)
        value, attrs = done.set_cookies[oidc.SESSION_COOKIE]
        self.assertTrue(oidc.SESSION_COOKIE.startswith('__Host-'))
        self.assertRegex(value, oidc.SESSION_ID_RE.pattern)
        self.assertLessEqual({'secure', 'httponly', 'samesite=lax', 'path=/',
                              f'max-age={self.config.session_ttl}'}, attrs)
        self.assertFalse([a for a in attrs if a.startswith('domain')])
        self.assertEqual(done.header('Cache-Control'), 'no-store')
        self.assertEqual(self.session_count(), 1)

    def test_callback_on_the_issuers_redirect_with_a_session_lands_on_the_panel(self):
        session = self.sign_in(next_path='/?exit=a')
        reply = self.get('/login?next=%2F%3Fexit%3Da', session)
        self.assertEqual((reply.status, reply.location), (303, PUBLIC_URL + '/?exit=a'))

    def test_callback_without_the_login_cookie_fails(self):
        login, query = self.begin_login()
        done = self.callback(query, None)
        self.assertEqual(done.status, 400)
        self.assertNotIn(oidc.SESSION_COOKIE, done.set_cookies)
        self.assertEqual(self.session_count(), 0)
        self.assertEqual(self.issuer.token_requests(), [])

    def test_callback_with_a_mismatched_state_fails_and_burns_the_sign_in(self):
        login, query = self.begin_login()
        cookie = login.set_cookies[oidc.LOGIN_COOKIE][0]
        done = self.callback({'state': 'not-the-state'}, cookie)
        self.assertEqual(done.status, 400)
        self.assertNotIn(oidc.SESSION_COOKIE, done.set_cookies)
        self.assertEqual(self.session_count(), 0)
        again = self.callback(query, cookie)                 # the right state, too late
        self.assertEqual(again.status, 400)
        self.assertEqual(self.session_count(), 0)
        self.assertEqual(self.issuer.token_requests(), [])

    def test_callback_with_another_browsers_state_fails(self):
        _, mine = self.begin_login()
        login, theirs = self.begin_login()
        done = self.callback(mine, login.set_cookies[oidc.LOGIN_COOKIE][0])
        self.assertEqual(done.status, 400)
        self.assertEqual(self.session_count(), 0)

    def test_callback_with_an_issuer_error_fails_without_echoing_it(self):
        login, query = self.begin_login()
        cookie = login.set_cookies[oidc.LOGIN_COOKIE][0]
        done = self.get('/auth/callback?' + urllib.parse.urlencode(
            {'error': 'access_denied', 'error_description': 'leak<script>x</script>', 'state': query['state']}),
            cookie=f'{oidc.LOGIN_COOKIE}={cookie}')
        self.assertEqual(done.status, 403)
        self.assertNotIn('leak', done.body)
        self.assertNotIn(oidc.SESSION_COOKIE, done.set_cookies)
        self.assertEqual(done.set_cookies[oidc.LOGIN_COOKIE][0], '')
        self.assertEqual(self.session_count(), 0)
        # The attempt is burned even though the state was right.
        self.assertEqual(self.callback(query, cookie).status, 400)

    def test_callback_replay_fails(self):
        login, query = self.begin_login()
        cookie = login.set_cookies[oidc.LOGIN_COOKIE][0]
        first = self.callback(query, cookie, code='authcode-replayed')
        self.assertEqual(first.status, 303)
        second = self.callback(query, cookie, code='authcode-replayed')
        self.assertEqual(second.status, 400)
        self.assertEqual(self.session_count(), 1)

    def test_callback_without_a_code_fails(self):
        login, query = self.begin_login()
        done = self.get('/auth/callback?' + urllib.parse.urlencode({'state': query['state']}),
                        cookie=f'{oidc.LOGIN_COOKIE}={login.set_cookies[oidc.LOGIN_COOKIE][0]}')
        self.assertEqual(done.status, 400)
        self.assertEqual(self.session_count(), 0)

    def test_account_in_no_granted_group_is_refused_with_no_session(self):
        self.issuer.groups = ['strangers']
        login, query = self.begin_login()
        done = self.callback(query, login.set_cookies[oidc.LOGIN_COOKIE][0])
        self.assertEqual(done.status, 403)
        self.assertIn('not allowed', done.body.lower())
        self.assertNotIn(oidc.SESSION_COOKIE, done.set_cookies)
        self.assertEqual(self.session_count(), 0)

    def test_issuer_problem_at_login_is_a_503_page(self):
        self.issuer.close()
        self.auth._endpoints = None
        reply = self.get('/login')
        self.assertEqual(reply.status, 503)
        self.assertIn('Try again', reply.body)
        self.assertNotIn(oidc.LOGIN_COOKIE, reply.set_cookies)

    def test_issuer_problem_at_the_callback_is_a_400_page(self):
        login, query = self.begin_login()
        self.issuer.token_status = 500
        self.issuer.token_body = b'leak-me-please'
        done = self.callback(query, login.set_cookies[oidc.LOGIN_COOKIE][0])
        self.assertEqual(done.status, 400)
        self.assertNotIn('leak-me', done.body)
        self.assertNotIn('leak-me', self.stderr.getvalue())
        self.assertEqual(self.session_count(), 0)


class AccessTests(PanelAuthBase):
    """A non-admin sees only what their groups grant, and asking for anything
    else is indistinguishable from asking for something that does not exist."""

    def setUp(self):
        super().setUp()
        self.friend = self.sign_in(groups=('friends-a',), name='friend-a', sub='u-friend')
        self.admin = self.sign_in(groups=('admins',), name='boss', sub='u-admin')

    def assertSameAsNonexistent(self, path_for, cookie, status, others=('b', 'mine')):
        baseline = path_for('nope-zz')(cookie)
        self.assertEqual(baseline.status, status)
        for other in others:
            with self.subTest(exit=other):
                reply = path_for(other)(cookie)
                self.assertEqual((reply.status, reply.body), (baseline.status, baseline.body))
                self.assertEqual(reply.signature(), baseline.signature())
                self.assertNotIn('csrf_nonce', reply.set_cookies)
                self.assertNotIn('molebridge_exit', reply.set_cookies)

    def test_other_exits_are_indistinguishable_from_nonexistent_on_every_get_path(self):
        for prefix in ('/', '/embed', '/api/status', '/api/latency', '/readyz'):
            with self.subTest(path=prefix):
                self.assertSameAsNonexistent(
                    lambda exit_id, prefix=prefix: (lambda cookie: self.get(f'{prefix}?exit={exit_id}', cookie)),
                    self.friend, 404)

    def test_other_exits_are_indistinguishable_from_nonexistent_on_select(self):
        tokens = self.page_tokens(self.friend)
        self.assertSameAsNonexistent(
            lambda exit_id: (lambda cookie: self.select(cookie, exit_id, tokens=tokens)), self.friend, 400)
        self.assertNoDesired()

    def test_select_with_another_exits_server_name_is_also_refused_alike(self):
        # The friend knows a server name from a catalogue they may not use.
        tokens = self.page_tokens(self.friend)
        baseline = self.select(self.friend, 'nope-zz', 'se-sto-wg-001', tokens=tokens)
        for other in ('mine', 'b'):
            reply = self.select(self.friend, other, 'se-sto-wg-001', tokens=tokens)
            self.assertEqual((reply.status, reply.body), (baseline.status, baseline.body))
        self.assertNoDesired()

    def test_unparsable_exit_values_are_refused_alike(self):
        tokens = self.page_tokens(self.friend)
        baseline = self.select(self.friend, 'nope-zz', tokens=tokens)
        for value in ('', '../a', 'A', 'a ', ' a', 'a\x00', 'mine,b', 'a/../b'):
            with self.subTest(exit=value):
                reply = self.select(self.friend, value, tokens=tokens)
                self.assertEqual((reply.status, reply.body), (baseline.status, baseline.body))
        self.assertNoDesired()

    def test_select_without_an_exit_field_is_refused(self):
        nonce, token = self.page_tokens(self.friend)
        reply = self.post('/select', {'server': self.SELECT_SERVER, 'csrf_token': token},
                          cookie=f'{self.friend}; csrf_nonce={nonce}')
        self.assertEqual(reply.status, 400)
        self.assertNoDesired()

    def test_api_exits_lists_only_granted_exits(self):
        listed = json.loads(self.get('/api/exits', self.friend).body)['exits']
        self.assertEqual([e['id'] for e in listed], ['a'])
        everything = json.loads(self.get('/api/exits', self.admin).body)['exits']
        self.assertEqual([e['id'] for e in everything], ['mine', 'a', 'b'])

    def test_page_shows_no_other_exit(self):
        for path in ('/?exit=a', '/embed?exit=a'):
            with self.subTest(path=path):
                reply = self.get(path, self.friend)
                self.assertEqual(reply.status, 200)
                body = reply.body
                self.assertNotIn('class="exit-tab', body)
                self.assertNotIn('data-multi="1"', body)
                for text in ('exit=b', 'exit=mine', 'data-exit="b"', 'data-exit="mine"', 'ex_example',
                             'se-sto-wg-001', 'Exampleland', 'PIA'):
                    self.assertNotIn(text, body)
                self.assertIn('data-exit="a"', body)
                self.assertIn(self.SELECT_SERVER, body)

    def test_root_redirects_to_the_granted_exit_even_if_the_cookie_names_another(self):
        for other in ('b', 'mine', 'nope'):
            for path, target in (('/', '/?exit=a'), ('/embed', '/embed?exit=a')):
                with self.subTest(cookie=other, path=path):
                    reply = self.get(path, f'{self.friend}; molebridge_exit={other}')
                    self.assertEqual((reply.status, reply.location), (303, target))
        reply = self.get('/', self.friend)
        self.assertEqual(reply.location, '/?exit=a')

    def test_root_redirect_for_admin_follows_the_cookie(self):
        self.assertEqual(self.get('/', f'{self.admin}; molebridge_exit=b').location, '/?exit=b')
        self.assertEqual(self.get('/', f'{self.admin}; molebridge_exit=gone').location, '/?exit=mine')

    def test_granted_page_does_not_set_the_exit_cookie_for_other_exits(self):
        reply = self.get('/?exit=a', self.friend)
        self.assertIn('molebridge_exit', reply.set_cookies)
        self.assertEqual(reply.set_cookies['molebridge_exit'][0], 'a')

    def test_page_cookies_are_secure_with_sign_in_on(self):
        reply = self.get('/?exit=a', self.friend)
        for name in ('csrf_nonce', 'molebridge_exit'):
            with self.subTest(cookie=name):
                self.assertLessEqual({'secure', 'httponly', 'samesite=strict', 'path=/'}, reply.set_cookies[name][1])

    def test_friend_can_read_status_and_latency_of_the_granted_exit(self):
        status = json.loads(self.get('/api/status?exit=a', self.friend).body)
        self.assertEqual(status['view']['state'], 'ok')
        self.assertEqual(json.loads(self.get('/api/latency?exit=a', self.friend).body), {'latency': {}})
        self.assertEqual(self.get('/readyz?exit=a', self.friend).status, 200)

    def test_admin_reaches_every_exit_and_nonexistent_is_still_404(self):
        for exit_id in ('mine', 'a', 'b'):
            self.assertEqual(self.get(f'/?exit={exit_id}', self.admin).status, 200)
            self.assertEqual(self.get(f'/api/status?exit={exit_id}', self.admin).status, 200)
        self.assertEqual(self.get('/?exit=nope-zz', self.admin).status, 404)
        self.assertEqual(self.get('/readyz?exit=nope-zz', self.admin).status, 404)

    def test_admin_page_has_all_tabs_and_the_home_link(self):
        page = self.get('/?exit=a', self.admin).body
        self.assertEqual(page.count('class="exit-tab'), 4)   # 3 tabs, 1 is also is-selected
        for exit_id in ('mine', 'a', 'b'):
            self.assertIn(f'href="/?exit={exit_id}"', page)
        self.assertIn('href="https://home.example.test"', page)
        self.assertIn('boss', page)

    def test_non_admin_page_has_no_home_link(self):
        for path in ('/?exit=a', '/embed?exit=a'):
            self.assertNotIn('home.example.test', self.get(path, self.friend).body)

    def test_user_in_two_groups_sees_both_exits_and_no_more(self):
        both = self.sign_in(groups=('friends-a', 'friends-b'), name='both', sub='u-both')
        listed = json.loads(self.get('/api/exits', both).body)['exits']
        self.assertEqual([e['id'] for e in listed], ['a', 'b'])
        self.assertEqual(self.get('/?exit=mine', both).status, 404)
        page = self.get('/?exit=b', both).body
        self.assertEqual(page.count('class="exit-tab'), 3)
        self.assertNotIn('exit=mine', page)

    def test_repeated_group_in_panel_access_grants_several_exits_over_http(self):
        self.enable_auth(env_for(self.issuer.url, PANEL_ACCESS='family=a, family=b'))
        family = self.sign_in(groups=('family',), name='fam', sub='u-fam')
        listed = json.loads(self.get('/api/exits', family).body)['exits']
        self.assertEqual([e['id'] for e in listed], ['a', 'b'])
        # Sessions made under the old configuration are not known to the new Authenticator.
        self.assertEqual(self.get('/api/exits', self.friend).status, 401)

    def test_page_shows_the_account_and_a_sign_out_form(self):
        page = self.get('/?exit=a', self.friend).body
        self.assertIn('action="/logout"', page)
        self.assertIn('friend-a', page)
        self.assertEqual(page.count('name="csrf_token"'), 2)

    def test_account_name_is_escaped_and_reduced(self):
        weird = self.sign_in(groups=('friends-a',), name='<img src=x onerror=alert(1)>', sub='u-weird')
        page = self.get('/?exit=a', weird).body
        self.assertNotIn('<img src=x', page)
        self.assertNotIn('onerror=alert(1)>', page)


class SwitchTests(PanelAuthBase):
    def setUp(self):
        super().setUp()
        self.friend = self.sign_in(groups=('friends-a',), name='friend-a', sub='u-friend')
        self.admin = self.sign_in(groups=('admins',), name='boss', sub='u-admin')
        self.stderr.truncate(0)
        self.stderr.seek(0)

    def test_valid_select_on_the_granted_exit_writes_only_that_exit_and_logs_it(self):
        reply = self.select(self.friend, 'a')
        self.assertEqual((reply.status, reply.location), (303, '/?exit=a'))
        self.assertEqual(app.read_json(self.a.desired_path)['server'], self.SELECT_SERVER)
        self.assertNoDesired(self.mine, self.b)
        self.assertIn(f'switch: user=friend-a sub=u-friend exit=a server={self.SELECT_SERVER}\n', self.stderr.getvalue())

    def test_select_returns_to_embed(self):
        reply = self.select(self.friend, 'a', **{'return': 'embed'})
        self.assertEqual(reply.location, '/embed?exit=a')

    def test_unlisted_server_is_refused_and_not_logged_as_a_switch(self):
        for server in ('se-sto-wg-001', 'ex_example', 'nope', ''):
            with self.subTest(server=server):
                reply = self.select(self.friend, 'a', server)
                self.assertEqual(reply.status, 400)
        self.assertNoDesired()
        self.assertNotIn('switch:', self.stderr.getvalue())

    def test_admin_can_switch_any_exit(self):
        self.assertEqual(self.select(self.admin, 'b', 'ex_example', tokens=self.page_tokens(self.admin, 'b')).status, 303)
        self.assertEqual(self.select(self.admin, 'mine', 'se-sto-wg-001',
                                     tokens=self.page_tokens(self.admin, 'mine')).status, 303)
        self.assertEqual(app.read_json(self.b.desired_path)['server'], 'ex_example')
        self.assertEqual(app.read_json(self.mine.desired_path)['server'], 'se-sto-wg-001')
        self.assertFalse(self.a.desired_path.exists())
        log = self.stderr.getvalue()
        self.assertIn('switch: user=boss sub=u-admin exit=b server=ex_example\n', log)
        self.assertIn('switch: user=boss sub=u-admin exit=mine server=se-sto-wg-001\n', log)

    def test_log_carries_no_credentials(self):
        code = 'authcode-must-not-be-logged'
        self.issuer.groups = ['friends-a']
        self.issuer.username = 'logcheck'
        login, query = self.begin_login()
        login_id = login.set_cookies[oidc.LOGIN_COOKIE][0]
        done = self.callback(query, login_id, code=code)
        session_id = done.set_cookies[oidc.SESSION_COOKIE][0]
        cookie = f'{oidc.SESSION_COOKIE}={session_id}'
        nonce, token = self.page_tokens(cookie)
        self.select(cookie, 'a', tokens=(nonce, token))
        self.post('/logout', {'csrf_token': token}, cookie=f'{cookie}; csrf_nonce={nonce}')
        self.get('/auth/callback?code=' + code + '&state=x', cookie=f'{oidc.LOGIN_COOKIE}={login_id}')
        form, _ = self.issuer.token_requests()[-1]
        secrets_in_play = [code, FakeIssuer.ACCESS_TOKEN, self.issuer.last_id_token, session_id, login_id, token, nonce,
                           query['state'], query['nonce'], form['code_verifier'], query['code_challenge'],
                           self.issuer.last_id_token.split('.')[1]]
        log = self.stderr.getvalue()
        self.assertIn('user=logcheck', log)
        for value in secrets_in_play:
            self.assertNotIn(value, log)

    def test_csrf_token_of_another_session_is_refused(self):
        other = self.sign_in(groups=('friends-a',), name='other', sub='u-other')
        nonce, token = self.page_tokens(self.friend)
        reply = self.post('/select', {'server': self.SELECT_SERVER, 'csrf_token': token, 'exit': 'a'},
                          cookie=f'{other}; csrf_nonce={nonce}')
        self.assertEqual(reply.status, 403)
        self.assertNoDesired()
        # The same token with its own session works.
        reply = self.post('/select', {'server': self.SELECT_SERVER, 'csrf_token': token, 'exit': 'a'},
                          cookie=f'{self.friend}; csrf_nonce={nonce}')
        self.assertEqual(reply.status, 303)

    def test_token_not_bound_to_a_session_is_refused(self):
        nonce = app.new_csrf_nonce()
        reply = self.post('/select', {'server': self.SELECT_SERVER, 'csrf_token': app.csrf_token(nonce), 'exit': 'a'},
                          cookie=f'{self.friend}; csrf_nonce={nonce}')
        self.assertEqual(reply.status, 403)
        self.assertNoDesired()

    def test_admins_token_does_not_work_for_a_friend(self):
        nonce, token = self.page_tokens(self.admin, 'b')
        reply = self.post('/select', {'server': self.SELECT_SERVER, 'csrf_token': token, 'exit': 'a'},
                          cookie=f'{self.friend}; csrf_nonce={nonce}')
        self.assertEqual(reply.status, 403)
        self.assertNoDesired()

    def test_missing_csrf_is_refused(self):
        reply = self.post('/select', {'server': self.SELECT_SERVER, 'exit': 'a'}, cookie=self.friend)
        self.assertEqual(reply.status, 403)
        self.assertNoDesired()

    def test_origin_check_uses_the_public_host(self):
        reply = self.select(self.friend, 'a', origin='https://evil.example.test')
        self.assertEqual(reply.status, 403)
        self.assertNoDesired()
        reply = self.select(self.friend, 'a', origin='https://exit.example.test')
        self.assertEqual(reply.status, 303)

    def test_logout_needs_the_csrf_token(self):
        nonce, token = self.page_tokens(self.friend)
        reply = self.post('/logout', {}, cookie=f'{self.friend}; csrf_nonce={nonce}')
        self.assertEqual(reply.status, 403)
        reply = self.post('/logout', {'csrf_token': 'f' * 64}, cookie=f'{self.friend}; csrf_nonce={nonce}')
        self.assertEqual(reply.status, 403)
        other = self.sign_in(groups=('friends-a',), name='other', sub='u-other')
        reply = self.post('/logout', {'csrf_token': token}, cookie=f'{other}; csrf_nonce={nonce}')
        self.assertEqual(reply.status, 403)
        self.assertEqual(self.get('/api/exits', self.friend).status, 200)
        self.assertEqual(self.get('/api/exits', other).status, 200)

    def test_logout_ends_the_session_and_redirects_to_signed_out(self):
        nonce, token = self.page_tokens(self.friend)
        reply = self.post('/logout', {'csrf_token': token}, cookie=f'{self.friend}; csrf_nonce={nonce}')
        self.assertEqual((reply.status, reply.location), (303, PUBLIC_URL + '/signed-out'))
        value, attrs = reply.set_cookies[oidc.SESSION_COOKIE]
        self.assertEqual(value, '')
        self.assertIn('max-age=0', attrs)
        self.assertEqual(self.get('/api/exits', self.friend).status, 401)
        self.assertEqual(self.get('/?exit=a', self.friend).status, 303)
        self.assertEqual(self.select_after_logout(nonce, token).status, 401)
        self.assertNoDesired()
        self.assertIn('signed out: user=friend-a', self.stderr.getvalue())
        # The other session is untouched.
        self.assertEqual(self.get('/api/exits', self.admin).status, 200)

    def select_after_logout(self, nonce, token):
        return self.post('/select', {'server': self.SELECT_SERVER, 'csrf_token': token, 'exit': 'a'},
                         cookie=f'{self.friend}; csrf_nonce={nonce}')

    def test_signed_out_page_offers_sign_in_on_the_canonical_address(self):
        reply = self.get('/signed-out')
        self.assertEqual(reply.status, 200)
        self.assertIn(f'href="{PUBLIC_URL}/login?next=%2F"', reply.body)

    def test_expired_session_is_signed_out(self):
        self.clock.advance(self.config.session_ttl - 5)
        self.assertEqual(self.get('/api/exits', self.friend).status, 200)
        self.clock.advance(10)
        self.assertEqual(self.get('/api/exits', self.friend).status, 401)
        reply = self.get('/?exit=a', self.friend)
        self.assertEqual(reply.status, 303)
        self.assertTrue(reply.location.startswith(PUBLIC_URL + '/login?'))
        self.assertEqual(self.get('/embed?exit=a', self.friend).status, 200)    # the sign-in link page
        self.assertNotIn('csrf_token', self.get('/embed?exit=a', self.friend).body)
        self.assertEqual(self.select_after_logout(app.new_csrf_nonce(), 'f' * 64).status, 401)
        self.assertEqual(self.get('/api/exits', self.admin).status, 401)
        self.assertNoDesired()

    def test_token_from_before_expiry_does_not_switch_after_it(self):
        nonce, token = self.page_tokens(self.friend)
        self.clock.advance(self.config.session_ttl + 1)
        reply = self.post('/select', {'server': self.SELECT_SERVER, 'csrf_token': token, 'exit': 'a'},
                          cookie=f'{self.friend}; csrf_nonce={nonce}')
        self.assertEqual(reply.status, 401)
        self.assertNoDesired()


class ConfidentialClientPanelTests(PanelAuthBase):
    def test_secret_file_is_used_for_the_token_request_only(self):
        path = self.tmpdir / 'client-secret'
        path.write_text('panel-test-secret-value\n')
        path.chmod(0o600)
        self.enable_auth(env_for(self.issuer.url, PANEL_OIDC_CLIENT_SECRET_FILE=str(path)))
        session = self.sign_in()
        _, headers = self.issuer.token_requests()[-1]
        self.assertTrue(headers['Authorization'].startswith('Basic '))
        self.assertNotIn('panel-test-secret-value', self.stderr.getvalue())
        self.assertNotIn('panel-test-secret-value', self.get('/?exit=a', session).body)


class NoSignInConfiguredTests(PanelAuthBase):
    """Without PANEL_OIDC_ISSUER the panel behaves exactly as before."""

    def setUp(self):
        super().setUp()
        for target in ('AUTH_CONFIG', 'AUTH'):
            patcher = patch.object(app, target, None)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_sign_in_routes_do_not_exist(self):
        for path in ('/login', '/login?next=%2F', '/auth/callback', '/auth/callback?code=x&state=y', '/signed-out'):
            with self.subTest(path=path):
                reply = self.get(path)
                self.assertEqual((reply.status, reply.body), (404, 'not found'))
        reply = self.post('/logout', {})
        self.assertEqual((reply.status, reply.body), (404, 'not found'))
        reply = self.post('/logout', {'csrf_token': 'f' * 64}, cookie='csrf_nonce=x')
        self.assertEqual(reply.status, 404)

    def test_everything_is_open_to_anyone_who_reaches_the_panel(self):
        self.assertEqual(self.get('/?exit=b').status, 200)
        self.assertEqual(self.get('/embed?exit=mine').status, 200)
        self.assertEqual(self.get('/api/status?exit=a').status, 200)
        self.assertEqual([e['id'] for e in json.loads(self.get('/api/exits').body)['exits']], ['mine', 'a', 'b'])
        self.assertEqual(self.get('/readyz?exit=b').status, 200)
        self.assertEqual(self.get('/readyz?exit=nope-zz').status, 404)
        self.assertEqual(self.get('/', headers={'Cookie': 'molebridge_exit=b'}).location, '/?exit=b')

    def test_page_has_no_account_form_and_keeps_the_home_link(self):
        page = self.get('/?exit=a').body
        self.assertNotIn('/logout', page)
        self.assertNotIn('class="account"', page)
        self.assertIn('href="https://home.example.test"', page)
        self.assertEqual(page.count('class="exit-tab'), 4)

    def test_select_works_with_an_unbound_token_and_logs_no_user(self):
        resp = self.get('/?exit=a')
        nonce = resp.set_cookies['csrf_nonce'][0]
        token = re.search(r'name="csrf_token" value="([^"]+)"', resp.body).group(1)
        reply = self.post('/select', {'server': self.SELECT_SERVER, 'csrf_token': token, 'exit': 'a'},
                          cookie=f'csrf_nonce={nonce}')
        self.assertEqual((reply.status, reply.location), (303, '/?exit=a'))
        self.assertEqual(app.read_json(self.a.desired_path)['server'], self.SELECT_SERVER)
        self.assertNotIn('switch:', self.stderr.getvalue())

    def test_page_cookies_are_not_marked_secure(self):
        reply = self.get('/?exit=a')
        for name in ('csrf_nonce', 'molebridge_exit'):
            with self.subTest(cookie=name):
                attrs = reply.set_cookies[name][1]
                self.assertNotIn('secure', attrs)
                self.assertLessEqual({'httponly', 'samesite=strict', 'path=/'}, attrs)

    def test_forwarded_proto_means_nothing(self):
        self.assertEqual(self.get('/login', headers={'X-Forwarded-Proto': 'http'}).status, 404)

    def test_a_session_cookie_means_nothing(self):
        self.assertEqual(self.get('/api/exits', f'{oidc.SESSION_COOKIE}={secrets.token_urlsafe(32)}').status, 200)


if __name__ == '__main__':
    unittest.main()


# --------------------------------------------------------------------------
# Second review (fresh-context) findings
# --------------------------------------------------------------------------

class ReviewFindingTests(AuthenticatorTests):
    def test_login_cookie_carries_no_nonce_or_verifier(self):
        login_cookie, query = self.begin()
        body = json.loads(oidc._b64url_decode(login_cookie.split('.')[0]))
        self.assertEqual(set(body), {'state', 'next_path', 'created'})
        self.assertNotIn(query['nonce'], login_cookie)

    def test_non_ascii_state_is_refused_not_crashed(self):
        login_cookie, _ = self.begin()
        with self.assertRaises(oidc.AuthError):
            self.auth.finish(login_cookie, 'é' * 43, 'code-0001')

    def test_https_issuer_never_accepts_http_endpoints(self):
        doc = {'issuer': ISSUER, 'authorization_endpoint': ISSUER + '/authorize',
               'token_endpoint': 'http://127.0.0.1:9/token'}
        with self.assertRaises(oidc.AuthError):
            oidc.parse_discovery(doc, ISSUER)
        doc['token_endpoint'] = ISSUER + '/token'
        doc['userinfo_endpoint'] = 'http://127.0.0.1:9/userinfo'
        self.assertIsNone(oidc.parse_discovery(doc, ISSUER).userinfo)

    def test_a_discovery_failure_is_not_retried_for_every_request(self):
        auth = oidc.Authenticator(oidc.config_from_env(env_for('https://unreachable.invalid'), EXIT_IDS),
                                  EXIT_IDS, clock=self.clock)
        calls = []
        real = oidc.http_json

        def failing(*args, **kwargs):
            calls.append(1)
            raise oidc.AuthError('discovery: the issuer could not be reached')
        oidc.http_json = failing
        try:
            for _ in range(3):
                with self.assertRaises(oidc.AuthError):
                    auth.endpoints()
            self.assertEqual(len(calls), 1)
            self.clock.advance(oidc.DISCOVERY_RETRY_S + 1)
            with self.assertRaises(oidc.AuthError):
                auth.endpoints()
            self.assertEqual(len(calls), 2)
        finally:
            oidc.http_json = real

    def test_consumed_states_expire_from_the_oldest_end(self):
        for _ in range(3):
            self.auth.discard(self.begin()[0])
        self.assertEqual(len(self.auth._consumed), 3)
        self.clock.advance(oidc.LOGIN_TTL + 1)
        self.auth.discard(self.begin()[0])
        self.assertEqual(len(self.auth._consumed), 1)


class StrictCookieTests(unittest.TestCase):
    def test_a_planted_cookie_cannot_stand_in_for_a_host_cookie(self):
        name = oidc.SESSION_COOKIE
        self.assertEqual(app.get_cookie_strict(f'{name}=REAL', name), 'REAL')
        self.assertEqual(app.get_cookie_strict(f'a=b; {name}=REAL; c=d', name), 'REAL')
        # SimpleCookie would read these as a session cookie named `name`.
        self.assertIsNone(app.get_cookie_strict(f'a=x {name}=EVIL', name))
        self.assertIsNone(app.get_cookie_strict(f'{name}=REAL; {name}=EVIL', name))
        self.assertIsNone(app.get_cookie_strict(f'{name}', name))
        self.assertEqual(app.get_cookie_strict(f'{name}=REAL; a=x {name}=EVIL', name), 'REAL')

    def test_a_reserved_word_or_stray_quote_does_not_sign_anyone_out(self):
        name = oidc.SESSION_COOKIE
        for header in (f'Path=/; {name}=REAL', f'version=1; {name}=REAL', f'a=b"c; {name}=REAL'):
            with self.subTest(header=header):
                self.assertEqual(app.get_cookie_strict(header, name), 'REAL')


class PlantedCookieOverHttpTests(PanelAuthBase):
    def test_a_session_id_smuggled_inside_another_cookie_is_ignored(self):
        cookie = self.sign_in()
        self.assertEqual(self.get('/api/exits', cookie).status, 200)
        self.assertEqual(self.get('/api/exits', f'planted=x {cookie}').status, 401)
