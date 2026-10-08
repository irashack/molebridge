import html
import http.client
import http.server
import io
import json
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest.mock import patch
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
import app  # noqa: E402


VALID_PUBKEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='


class RenderEscapingTests(unittest.TestCase):
    def test_page_escapes_malicious_city_name(self):
        relays_data = {
            'fetched_at': app.now_iso(),
            'relays': {
                'se-sto-wg-001': {
                    'hostname': 'se-sto-wg-001',
                    'country': 'Sweden',
                    'city': '<script>alert(1)</script>',
                    'location_code': 'se-sto',
                    'public_key': VALID_PUBKEY,
                    'ipv4_addr_in': '198.51.100.10',
                },
            },
        }
        page = app.render_index_html(None, None, relays_data, None, None, 'tok')
        self.assertNotIn('<script>alert(1)</script>', page)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', page)


class CsrfAndOriginUnitTests(unittest.TestCase):
    def test_csrf_round_trip(self):
        nonce = app.new_csrf_nonce()
        token = app.csrf_token(nonce)
        self.assertTrue(app.verify_csrf(nonce, token))
        self.assertFalse(app.verify_csrf(nonce, 'wrong-token'))
        self.assertFalse(app.verify_csrf(None, token))
        self.assertFalse(app.verify_csrf(nonce, None))
        self.assertFalse(app.verify_csrf(nonce, 'é' * 64))

    def test_origin_allowlist(self):
        with patch.dict('os.environ', {'PANEL_PUBLIC_HOSTS': 'exit.example.test, other.example.test:8443'}):
            self.assertTrue(app.origin_allowed(None))
            self.assertTrue(app.origin_allowed('https://exit.example.test'))
            self.assertTrue(app.origin_allowed('https://exit.example.test:443'))
            self.assertFalse(app.origin_allowed('https://exit.example.test:8443'))
            self.assertTrue(app.origin_allowed('https://other.example.test:8443'))
            self.assertFalse(app.origin_allowed('https://other.example.test'))
            self.assertFalse(app.origin_allowed('https://evil.example.com'))
            self.assertFalse(app.origin_allowed('https://exit.example.test/path'))
            self.assertFalse(app.origin_allowed('ftp://exit.example.test'))
            self.assertFalse(app.origin_allowed('http://['))
            self.assertFalse(app.origin_allowed('null'))
        # Loopback is always acceptable, on any port: SSH forwards vary.
        self.assertTrue(app.origin_allowed('http://[::1]:8095'))
        self.assertTrue(app.origin_allowed('http://127.0.0.1:9000'))
        self.assertTrue(app.origin_allowed('http://localhost:8095'))
        self.assertFalse(app.origin_allowed('https://exit.example.test'))

    def test_host_allowlist(self):
        with patch.dict('os.environ', {'PANEL_PUBLIC_HOSTS': 'exit.example.test,host.docker.internal:8095'}):
            self.assertTrue(app.host_allowed('exit.example.test'))
            self.assertTrue(app.host_allowed('exit.example.test:443'))
            self.assertTrue(app.host_allowed('EXIT.example.test'))
            self.assertFalse(app.host_allowed('exit.example.test:8095'))
            self.assertTrue(app.host_allowed('host.docker.internal:8095'))
            self.assertFalse(app.host_allowed('host.docker.internal'))
            self.assertFalse(app.host_allowed('evil.example.com:8095'))
            self.assertFalse(app.host_allowed('exit.example.test@evil.example.com'))
            self.assertFalse(app.host_allowed(None))
            self.assertFalse(app.host_allowed(''))
        self.assertTrue(app.host_allowed('127.0.0.1:8095'))
        self.assertTrue(app.host_allowed('[::1]:8095'))
        self.assertTrue(app.host_allowed('localhost'))
        self.assertFalse(app.host_allowed('exit.example.test'))


class ServerIntegrationTests(unittest.TestCase):
    """End-to-end tests against a real ThreadingHTTPServer bound to loopback
    (no external network calls are made)."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        (self.tmpdir / 'panel').mkdir()
        (self.tmpdir / 'applier').mkdir()

        self._orig_paths = (app.RELAYS_PATH, app.DESIRED_PATH, app.APPLIER_RESULT_PATH)
        app.RELAYS_PATH = self.tmpdir / 'applier' / 'relays.json'
        app.DESIRED_PATH = self.tmpdir / 'panel' / 'desired.json'
        app.APPLIER_RESULT_PATH = self.tmpdir / 'applier' / 'result.json'

        app.write_json_atomic(app.RELAYS_PATH, {
            'fetched_at': app.now_iso(),
            'relays': {'se-sto-wg-001': {
                'hostname': 'se-sto-wg-001', 'country': 'Sweden', 'city': 'Stockholm',
                'location_code': 'se-sto', 'public_key': VALID_PUBKEY,
                'ipv4_addr_in': '198.51.100.10',
            }},
        })

        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), app.PanelHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        app.RELAYS_PATH, app.DESIRED_PATH, app.APPLIER_RESULT_PATH = self._orig_paths
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _get_index(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('GET', '/')
        resp = conn.getresponse()
        body = resp.read().decode()
        cookie_header = resp.getheader('Set-Cookie')
        conn.close()
        nonce_match = re.search(r'csrf_nonce=([^;]+)', cookie_header)
        token_match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        return resp.status, nonce_match.group(1), token_match.group(1)

    def test_healthz(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('GET', '/healthz')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.read(), b'ok')
        conn.close()

    def test_post_without_csrf_is_rejected(self):
        status, _nonce, _token = self._get_index()
        self.assertEqual(status, 200)

        body = 'server=se-sto-wg-001'.encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('POST', '/select', body=body, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(len(body)),
        })
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)
        conn.close()
        self.assertIsNone(app.read_json(app.DESIRED_PATH))

    def test_post_bad_origin_is_rejected(self):
        _status, nonce, token = self._get_index()
        body = f'server=se-sto-wg-001&csrf_token={token}'.encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('POST', '/select', body=body, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(len(body)),
            'Cookie': f'csrf_nonce={nonce}',
            'Origin': 'https://evil.example.com',
        })
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)
        conn.close()
        self.assertIsNone(app.read_json(app.DESIRED_PATH))

    def test_post_unlisted_server_is_rejected(self):
        _status, nonce, token = self._get_index()
        body = f'server=not-in-allowlist-wg-999&csrf_token={token}'.encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('POST', '/select', body=body, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(len(body)),
            'Cookie': f'csrf_nonce={nonce}',
        })
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        conn.close()
        self.assertIsNone(app.read_json(app.DESIRED_PATH))

    def test_malformed_origin_is_rejected_without_logging_input(self):
        for origin in ('http://[', 'https://private.example.test'):
            with self.subTest(origin=origin), patch('sys.stderr', new_callable=io.StringIO) as log:
                conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
                conn.request('POST', '/select', body=b'', headers={'Origin': origin})
                response = conn.getresponse()
                response.read()
                conn.close()
                self.assertEqual(response.status, 403)
                self.assertNotIn(origin, log.getvalue())
                self.assertNotIn('127.0.0.1', log.getvalue())

    def _request(self, method, path, headers, body=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def test_unpublished_host_is_misdirected_and_not_logged(self):
        # DNS rebinding: the browser reaches loopback under an attacker's name.
        for path in ('/', '/embed', '/api/status', '/readyz', '/static/panel.js'):
            with self.subTest(path=path), patch('sys.stderr', new_callable=io.StringIO) as log:
                resp, data = self._request('GET', path, {'Host': f'rebind.example.com:{self.port}'})
                self.assertEqual(resp.status, 421)
                self.assertNotIn(b'csrf_token', data)
                self.assertNotIn('rebind.example.com', log.getvalue())
        resp, _ = self._request('GET', '/healthz', {'Host': f'rebind.example.com:{self.port}'})
        self.assertEqual(resp.status, 200)
        _status, nonce, token = self._get_index()
        body = f'server=se-sto-wg-001&csrf_token={token}'.encode()
        resp, _ = self._request('POST', '/select', {
            'Host': f'rebind.example.com:{self.port}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(len(body)),
            'Cookie': f'csrf_nonce={nonce}',
            'Origin': f'http://rebind.example.com:{self.port}',
            'X-Forwarded-Host': '127.0.0.1',
        }, body)
        self.assertEqual(resp.status, 421)
        self.assertIsNone(app.read_json(app.DESIRED_PATH))

    def test_published_hosts_include_a_proxy_upstream_name(self):
        with patch.dict('os.environ', {'PANEL_PUBLIC_HOSTS': 'exit.example.test,host.docker.internal:8095'}):
            for host, expected in (('host.docker.internal:8095', 200), ('host.docker.internal:8096', 421),
                                   ('exit.example.test', 200), ('127.0.0.1:%d' % self.port, 200)):
                with self.subTest(host=host):
                    resp, _ = self._request('GET', '/api/status', {'Host': host})
                    self.assertEqual(resp.status, expected)

    def test_unknown_path_is_not_logged(self):
        with patch('sys.stderr', new_callable=io.StringIO) as log:
            conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
            conn.request('GET', '/private.example.test?token=example')
            response = conn.getresponse()
            response.read()
            conn.close()
            self.assertEqual(response.status, 404)
            self.assertNotIn('private.example.test', log.getvalue())
            self.assertNotIn('token=', log.getvalue())
            self.assertIn('(unknown route)', log.getvalue())

    def test_post_oversized_body_is_rejected(self):
        _status, nonce, token = self._get_index()
        padding = 'x' * 5000
        body = f'server=se-sto-wg-001&csrf_token={token}&pad={padding}'.encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('POST', '/select', body=body, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(len(body)),
            'Cookie': f'csrf_nonce={nonce}',
        })
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        conn.close()
        self.assertIsNone(app.read_json(app.DESIRED_PATH))

    def test_valid_post_writes_desired_json_atomically(self):
        _status, nonce, token = self._get_index()
        body = f'server=se-sto-wg-001&csrf_token={token}'.encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('POST', '/select', body=body, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(len(body)),
            'Cookie': f'csrf_nonce={nonce}',
            'Origin': 'http://127.0.0.1:%d' % self.port,
        })
        resp = conn.getresponse()
        self.assertEqual(resp.status, 303)
        self.assertEqual(resp.getheader('Location'), '/')
        resp.read()
        conn.close()

        desired = app.read_json(app.DESIRED_PATH)
        self.assertEqual(desired['server'], 'se-sto-wg-001')
        self.assertIn('requested_at', desired)


if __name__ == '__main__':
    unittest.main()


def test_forwarded_host_header_is_not_trusted(monkeypatch):
    # A rebinding page can set X-Forwarded-Host on a same-origin fetch, so the
    # panel never derives its allowlist from request headers.
    monkeypatch.setenv("PANEL_PUBLIC_HOSTS", "exit.example.test")
    assert app.origin_allowed("https://exit.example.test")
    assert not app.origin_allowed("https://evil.example")
    assert not app.host_allowed("evil.example:8095")
    monkeypatch.delenv("PANEL_PUBLIC_HOSTS")
    assert not app.origin_allowed("https://exit.example.test")
    assert not app.host_allowed("exit.example.test")


def test_referrer_policy_keeps_origin_for_same_site_posts():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("panel_app_rp", Path(__file__).parent / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.SECURITY_HEADERS["Referrer-Policy"] == "same-origin"


class LatencyTests(unittest.TestCase):
    RELAYS = {
        'se-sto-wg-001': {'hostname': 'se-sto-wg-001', 'country': 'Sweden', 'city': 'Stockholm',
                          'location_code': 'se-sto', 'ipv4_addr_in': '198.51.100.10'},
        'se-sto-wg-002': {'hostname': 'se-sto-wg-002', 'country': 'Sweden', 'city': 'Stockholm',
                          'location_code': 'se-sto', 'ipv4_addr_in': '198.51.100.11'},
        'us-nyc-wg-301': {'hostname': 'us-nyc-wg-301', 'country': 'USA', 'city': 'New York',
                          'location_code': 'us-nyc', 'ipv4_addr_in': '198.51.100.12'},
    }

    def setUp(self):
        app._latency_cache.clear()
        self.probed = []
        self._orig_probe = app.probe_tcp_rtt_ms

        def fake_probe(ip, *_a, **_kw):
            self.probed.append(ip)
            return None if ip.endswith('.12') else 20.0
        app.probe_tcp_rtt_ms = fake_probe

    def tearDown(self):
        app.probe_tcp_rtt_ms = self._orig_probe
        app._latency_cache.clear()

    def test_city_sweep_probes_one_relay_per_city(self):
        targets = app.latency_targets({'scope': ['cities']}, self.RELAYS)
        self.assertEqual(sorted(targets), ['se-sto-wg-001', 'us-nyc-wg-301'])

    def test_country_and_host_targets_ignore_unlisted_names(self):
        targets = app.latency_targets({'country': ['Sweden'], 'hosts': ['evil-wg-001,us-nyc-wg-301']}, self.RELAYS)
        result = app.measure_latency(self.RELAYS, targets)
        self.assertEqual(result, {'se-sto-wg-001': 20.0, 'se-sto-wg-002': 20.0, 'us-nyc-wg-301': None})

    def test_cached_results_are_not_reprobed_unless_fresh(self):
        app.measure_latency(self.RELAYS, ['se-sto-wg-001'])
        app.measure_latency(self.RELAYS, ['se-sto-wg-001'])
        self.assertEqual(len(self.probed), 1)
        app.measure_latency(self.RELAYS, ['se-sto-wg-001'], fresh=True)
        self.assertEqual(len(self.probed), 2)

    def test_host_list_is_capped(self):
        many = ','.join(f'x{i}-wg-001' for i in range(200))
        self.assertEqual(len(app.latency_targets({'hosts': [many]}, self.RELAYS)), app.MAX_PROBE_HOSTS)

    def test_probe_counts_refused_connection_as_round_trip(self):
        from unittest.mock import patch
        with patch('app.socket.create_connection', side_effect=ConnectionRefusedError):
            self.assertIsNotNone(self._orig_probe('198.51.100.10', attempts=1))
        with patch('app.socket.create_connection', side_effect=TimeoutError):
            self.assertIsNone(self._orig_probe('198.51.100.10', attempts=1))


class FramingAndRenderTests(unittest.TestCase):
    def test_framing_denied_by_default(self):
        headers = app.security_headers()
        self.assertEqual(headers['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])

    def test_framing_allows_only_configured_https_origins(self):
        import os
        os.environ['PANEL_FRAME_ANCESTORS'] = 'https://dashboard.example.test http://insecure.example *'
        try:
            headers = app.security_headers()
        finally:
            del os.environ['PANEL_FRAME_ANCESTORS']
        self.assertNotIn('X-Frame-Options', headers)
        self.assertTrue(headers['Content-Security-Policy'].endswith(
            'frame-ancestors https://dashboard.example.test'))

    def test_flag_emoji(self):
        self.assertEqual(app.flag_emoji('se-sto'), '\U0001F1F8\U0001F1EA')
        self.assertEqual(app.flag_emoji(None), '')

    def test_embed_page_posts_back_to_embed(self):
        page = app.render_index_html({'server': 'x'}, None, None, None, None, 'tok', embed=True)
        self.assertIn('name="return" value="embed"', page)
        self.assertNotIn('<h1>', page)


def _relay(hostname='se-sto-wg-001', **extra):
    return {'hostname': hostname, 'country': 'Sweden', 'city': 'Stockholm', 'location_code': 'se-sto',
            'public_key': VALID_PUBKEY, 'ipv4_addr_in': '198.51.100.10', **extra}


def _catalogue(*entries):
    return {'fetched_at': app.now_iso(), 'relays': {e['hostname']: e for e in entries}}


class SwitcherRenderTests(unittest.TestCase):
    def _failed(self, server='se-sto-wg-001'):
        desired = {'server': server, 'requested_at': app.now_iso(), 'request_id': 'a' * 32}
        result = {'status': 'failed', 'message': 'Switch verification timed out.', 'checked_at': app.now_iso(),
                  'request_id': 'a' * 32, 'server': None}
        return desired, result

    def test_status_pill_is_live_from_first_render(self):
        page = app.render_index_html(None, None, None, None, None, 'tok')
        self.assertRegex(page, r'data-state-pill role="status" aria-live="polite"')
        self.assertIn('data-announce', page)

    def test_request_time_is_exposed_for_progress(self):
        desired = {'server': 'se-sto-wg-001', 'requested_at': '2026-01-01T00:00:00Z', 'request_id': 'a' * 32}
        page = app.render_index_html(desired, None, _catalogue(_relay()), None, None, 'tok')
        self.assertIn('data-requested="2026-01-01T00:00:00Z"', page)

    def test_retry_offered_for_failed_catalogued_server(self):
        desired, result = self._failed()
        page = app.render_index_html(desired, result, _catalogue(_relay()), None, None, 'tok')
        self.assertIn('form="select-form" name="server" value="se-sto-wg-001"', page)
        self.assertIn('data-retry>Retry</button>', page)

    def test_no_retry_when_not_failed_or_not_catalogued(self):
        desired, result = self._failed(server='no-where-wg-001')
        page = app.render_index_html(desired, result, _catalogue(_relay()), None, None, 'tok')
        self.assertNotIn('data-retry', page)
        ok = {'status': 'ok', 'routing_ok': True, 'mullvad_exit_ip': True, 'checked_at': app.now_iso(),
              'request_id': 'a' * 32, 'server': 'se-sto-wg-001'}
        page = app.render_index_html(self._failed()[0], ok, _catalogue(_relay()), None, None, 'tok')
        self.assertNotIn('data-retry', page)

    def test_failure_message_is_escaped_beside_retry(self):
        desired, result = self._failed()
        result['message'] = '<img src=x onerror=alert(1)>'
        page = app.render_index_html(desired, result, _catalogue(_relay()), None, None, 'tok')
        self.assertNotIn('<img src=x', page)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', page)

    def test_relay_attributes_only_when_known(self):
        page = app.render_index_html(None, None, _catalogue(_relay()), None, None, 'tok')
        self.assertNotIn('data-owned', page)
        self.assertNotIn('data-attr-filter', page)
        self.assertNotIn('data-filters-toggle', page)

        relays = _catalogue(_relay(owned=True, stboot=False, provider='<b>Example Hosting</b>'),
                            _relay('se-sto-wg-002', owned='yes'))
        page = app.render_index_html(None, None, relays, None, None, 'tok')
        self.assertIn('data-owned="1" data-stboot="0"', page)
        self.assertEqual(page.count('data-owned='), 1)
        self.assertIn('data-attr-filter="owned"', page)
        # No relay is RAM-only here, so that filter would hide everything.
        self.assertNotIn('data-attr-filter="stboot"', page)
        self.assertIn('data-filters-toggle', page)
        self.assertNotIn('<b>Example Hosting</b>', page)
        self.assertIn('&lt;b&gt;Example Hosting&lt;/b&gt; · Mullvad-owned', page)

    def test_filters_offered_only_when_they_narrow_the_list(self):
        every = _catalogue(_relay(stboot=True), _relay('se-sto-wg-002', stboot=True))
        page = app.render_index_html(None, None, every, None, None, 'tok')
        self.assertIn('data-stboot="1"', page)
        self.assertNotIn('data-attr-filter', page)
        self.assertNotIn('data-filters-toggle', page)

        mixed = _catalogue(_relay(stboot=True), _relay('se-sto-wg-002', stboot=False))
        page = app.render_index_html(None, None, mixed, None, None, 'tok')
        self.assertIn('data-attr-filter="stboot"', page)
        self.assertNotIn('data-attr-filter="owned"', page)

        partly_known = _catalogue(_relay(owned=True), _relay('se-sto-wg-002'))
        page = app.render_index_html(None, None, partly_known, None, None, 'tok')
        self.assertIn('data-attr-filter="owned"', page)

    def test_favicon_and_unbroken_address(self):
        page = app.render_index_html(None, None, None, None, None, 'tok')
        self.assertRegex(page, r'<link rel="icon" href="/static/icon-192\.png\?v=\w+" type="image/png">')
        self.assertIn('<span class="nowrap">· <span data-current-ip>', page)

    def test_theme_setting(self):
        for value, expected in (('light', 'light'), ('dark', 'dark'), ('auto', 'auto'), ('neon', 'auto'), ('', 'auto')):
            self.assertEqual(app.theme_setting(value), expected)
        for theme in ('light', 'dark'):
            with patch.object(app, 'PANEL_THEME', theme):
                page = app.render_index_html(None, None, None, None, None, 'tok')
                self.assertIn(f'<html lang="en" data-theme="{theme}" ', page)
                self.assertIn(f'<meta name="color-scheme" content="{theme}">', page)
        with patch.object(app, 'PANEL_THEME', 'auto'):
            page = app.render_index_html(None, None, None, None, None, 'tok')
        self.assertIn('<meta name="color-scheme" content="dark light">', page)
        self.assertIn('media="(prefers-color-scheme: light)"', page)


class EmbedAndApiIntegrationTests(ServerIntegrationTests):
    def _get(self, path):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('GET', path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp, body

    def test_embed_select_redirects_to_embed(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('GET', '/embed')
        resp = conn.getresponse()
        page = resp.read().decode()
        nonce = re.search(r'csrf_nonce=([^;]+)', resp.getheader('Set-Cookie')).group(1)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        conn.close()

        body = f'server=se-sto-wg-001&csrf_token={token}&return=embed'.encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('POST', '/select', body=body, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(len(body)),
            'Cookie': f'csrf_nonce={nonce}',
        })
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 303)
        self.assertEqual(resp.getheader('Location'), '/embed')

    def test_status_api(self):
        app.write_json_atomic(app.DESIRED_PATH, {'server': 'se-sto-wg-001', 'requested_at': 'now'})
        resp, body = self._get('/api/status')
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(body)['desired']['server'], 'se-sto-wg-001')

    def test_stale_success_is_unknown_in_api_html_and_readiness(self):
        app.write_json_atomic(app.APPLIER_RESULT_PATH, {
            'server': 'se-sto-wg-001', 'status': 'ok', 'checked_at': '2000-01-01T00:00:00Z',
            'routing_ok': True, 'mullvad_exit_ip': True,
        })
        _, body = self._get('/api/status')
        self.assertEqual(json.loads(body)['view']['state'], 'unknown')
        _, page = self._get('/')
        self.assertIn(b'status stale', page)
        ready, _ = self._get('/readyz')
        self.assertEqual(ready.status, 503)
        live, _ = self._get('/healthz')
        self.assertEqual(live.status, 200)

    def test_fresh_success_ready_without_desired_file(self):
        app.write_json_atomic(app.APPLIER_RESULT_PATH, {
            'server': 'se-sto-wg-001', 'status': 'ok', 'checked_at': app.now_iso(),
            'routing_ok': True, 'mullvad_exit_ip': True,
        })
        ready, _ = self._get('/readyz')
        self.assertEqual(ready.status, 200)
        _, page = self._get('/')
        self.assertIn(b'se-sto-wg-001', page)
        self.assertNotIn(b'Awaiting verified server', page)

    def test_panel_ignores_old_writable_catalogue(self):
        # Production RELAYS_PATH is under the read-only applier mount.
        self.assertEqual(app.STATE_DIR / 'applier' / 'relays.json',
                         self._orig_paths[0])

    def test_static_files_are_allowlisted(self):
        resp, _ = self._get('/static/panel.js')
        self.assertEqual(resp.status, 200)
        resp, _ = self._get('/static/app.py')
        self.assertEqual(resp.status, 404)
        resp, _ = self._get('/static/../app.py')
        self.assertEqual(resp.status, 404)


class PwaTests(ServerIntegrationTests.__base__):
    def test_manifest_and_icons_are_declared(self):
        page = app.render_index_html(None, None, None, None, None, 'tok')
        self.assertIn('rel="manifest" href="/manifest.webmanifest" crossorigin="use-credentials"', page)
        self.assertIn('rel="apple-touch-icon"', page)
        self.assertIn('viewport-fit=cover', page)
        for icon in app.WEB_MANIFEST['icons']:
            name = icon['src'].rsplit('/', 1)[1]
            self.assertIn(name, app.STATIC_FILES)
            self.assertTrue((app.STATIC_DIR / name).read_bytes().startswith(b'\x89PNG'))
        self.assertIn("manifest-src 'self'", app.security_headers()['Content-Security-Policy'])


class SigtermTests(unittest.TestCase):
    """The panel runs as a container's PID 1, which ignores SIGTERM without a
    handler; main() must turn SIGTERM into a clean exit."""

    def test_sigterm_exits_cleanly(self):
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state)
        script = (
            'import sys, http.server\n'
            f'sys.path.insert(0, {str(Path(__file__).parent)!r})\n'
            'import app\n'
            "app.LISTEN_HOST, app.LISTEN_PORT = '127.0.0.1', 0\n"
            'activate = http.server.ThreadingHTTPServer.server_activate\n'
            'def ready(self):\n'
            '    activate(self)\n'
            "    print('ready', flush=True)\n"
            'http.server.ThreadingHTTPServer.server_activate = ready\n'
            'app.main()\n'
        )
        proc = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE,
                                text=True, env={'STATE_DIR': state, 'PATH': '/usr/bin:/bin'})
        self.addCleanup(proc.kill)
        self.assertEqual(proc.stdout.readline().strip(), 'ready')
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=5), 0)


class PiaPanelTests(unittest.TestCase):
    """The panel in PIA mode: region ids, provider-scoped catalogue, labels."""

    REGION = {'hostname': 'ex_example', 'country': 'Exampleland', 'city': 'Example City',
              'location_code': 'ex-ex_example', 'ipv4_addr_in': '198.51.100.21',
              'port_forward': True, 'geo': True, 'servers': [{'ip': '198.51.100.20', 'cn': 'example401'}]}

    def setUp(self):
        patcher = patch.multiple(app, PROVIDER='pia')
        patcher.start()
        self.addCleanup(patcher.stop)

    def catalogue(self, provider='pia'):
        return {'fetched_at': app.now_iso(), 'provider': provider, 'relays': {'ex_example': self.REGION}}

    def test_region_id_is_selectable_only_when_listed(self):
        with tempfile.TemporaryDirectory() as tmp:
            desired = Path(tmp) / 'desired.json'
            self.assertEqual(app.process_select(server='ex_example', allowlist={'ex_example'}, desired_path=desired)[0], 303)
            self.assertEqual(json.loads(desired.read_text())['server'], 'ex_example')
            for bad in ('ex_other', 'se-sto-wg-001', '../x', 'Ex'):
                self.assertEqual(app.process_select(server=bad, allowlist={'ex_example'}, desired_path=desired)[0], 400)

    def test_page_shows_regions_and_provider_labels(self):
        result = {'checked_at': app.now_iso(), 'status': 'ok', 'server': 'ex_example', 'routing_ok': True,
                  'exit_confirmed': True, 'provider': 'pia', 'port_forward': True, 'forwarded_port': 43210}
        page = app.render_index_html(None, result, self.catalogue(), None, None, 'tok')
        self.assertIn('data-provider="pia"', page)
        self.assertIn('value="ex_example"', page)
        self.assertIn('<dt>PIA IP</dt><dd data-f="exit_confirmed">True</dd>', page)
        self.assertIn('data-f="forwarded_port">43210<', page)
        self.assertIn('port forwarding · virtual location', page)
        self.assertNotIn('Mullvad', page)

    def test_catalogue_of_another_provider_is_not_offered(self):
        page = app.render_index_html(None, None, self.catalogue('mullvad'), None, None, 'tok')
        self.assertNotIn('value="ex_example"', page)
        self.assertIn('No relays available.', page)


class MultiExitTests(unittest.TestCase):
    """One panel serving several exits (PANEL_EXITS): each exit's requests,
    catalogue and state stay its own."""

    MULLVAD = {'hostname': 'se-sto-wg-001', 'country': 'Sweden', 'city': 'Stockholm',
               'location_code': 'se-sto', 'public_key': VALID_PUBKEY, 'ipv4_addr_in': '198.51.100.10'}
    PIA = PiaPanelTests.REGION

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        exits = app.parse_exits('home=mullvad, away=pia:PIA Chicago', self.tmpdir)
        patcher = patch.object(app, 'EXITS', exits)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.home, self.away = exits
        app.write_json_atomic(self.home.relays_path, {'fetched_at': app.now_iso(),
                                                      'relays': {'se-sto-wg-001': self.MULLVAD}})
        app.write_json_atomic(self.away.relays_path, {'fetched_at': app.now_iso(), 'provider': 'pia',
                                                      'relays': {'ex_example': self.PIA}})
        app.write_json_atomic(self.away.result_path, {
            'server': 'ex_example', 'status': 'ok', 'checked_at': app.now_iso(), 'routing_ok': True,
            'exit_confirmed': True, 'provider': 'pia'})
        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), app.PanelHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.httpd.server_address[1], timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data.decode()

    def select(self, exit_id, server, page_exit=None):
        resp, page = self.request('GET', f'/?exit={page_exit or exit_id}')
        nonce = re.search(r'csrf_nonce=([^;]+)', resp.getheader('Set-Cookie')).group(1)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        body = urllib.parse.urlencode({'server': server, 'csrf_token': token, 'exit': exit_id}).encode()
        return self.request('POST', '/select', body, {
            'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': str(len(body)),
            'Cookie': f'csrf_nonce={nonce}'})

    def test_parse_exits(self):
        self.assertEqual([(e.id, e.provider, e.label) for e in (self.home, self.away)],
                         [('home', 'mullvad', 'Mullvad'), ('away', 'pia', 'PIA Chicago')])
        self.assertEqual(self.away.desired_path, self.tmpdir / 'away' / 'panel' / 'desired.json')
        self.assertEqual(app.parse_exits('', self.tmpdir), [])
        for bad in ('home', 'Home=mullvad', '../x=pia', 'a=examplevpn', 'a=pia,a=mullvad', 'a=pia:' + 'x' * 41,
                    'a=pia:bad\x07label'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                app.parse_exits(bad, self.tmpdir)

    def test_each_exit_renders_in_its_own_layout_with_tabs(self):
        _, home = self.request('GET', '/?exit=home')
        self.assertIn('data-layout="tree"', home)
        self.assertIn('value="se-sto-wg-001"', home)
        self.assertNotIn('value="ex_example"', home)
        _, away = self.request('GET', '/?exit=away')
        self.assertIn('data-layout="regions"', away)
        self.assertIn('data-provider="pia"', away)
        self.assertIn('value="ex_example"', away)
        self.assertIn('<input type="hidden" name="exit" value="away">', away)
        for page in (home, away):
            self.assertIn('href="/?exit=home"', page)
            self.assertIn('href="/?exit=away"', page)
        self.assertIn('class="exit-tab is-selected" href="/?exit=away"', away)
        self.assertIn('<span class="exit-place" data-exit-place>Example City</span>', away)

    def test_unknown_exit_is_404_everywhere(self):
        for path in ('/?exit=nope', '/embed?exit=nope', '/api/status?exit=nope', '/api/latency?exit=nope',
                     '/readyz?exit=nope', '/api/status', '/?exit=..%2Fhome'):
            with self.subTest(path=path):
                self.assertEqual(self.request('GET', path)[0].status, 404)

    def test_select_writes_only_the_named_exits_request(self):
        resp, _ = self.select('away', 'ex_example')
        self.assertEqual((resp.status, resp.getheader('Location')), (303, '/?exit=away'))
        self.assertEqual(app.read_json(self.away.desired_path)['server'], 'ex_example')
        self.assertIsNone(app.read_json(self.home.desired_path))
        # A name from another exit's catalogue is refused.
        resp, _ = self.select('home', 'ex_example')
        self.assertEqual(resp.status, 400)
        self.assertIsNone(app.read_json(self.home.desired_path))
        resp, _ = self.select('elsewhere', 'ex_example', page_exit='away')
        self.assertEqual(resp.status, 400)

    def test_remembered_exit_is_the_default(self):
        resp, _ = self.request('GET', '/?exit=away')
        self.assertIn('molebridge_exit=away; Path=/', ' '.join(resp.headers.get_all('Set-Cookie')))
        # An address without ?exit= is redirected to one that names the exit,
        # so the page's own reloads cannot follow another tab's choice.
        resp, _ = self.request('GET', '/', headers={'Cookie': 'molebridge_exit=away'})
        self.assertEqual((resp.status, resp.getheader('Location')), (303, '/?exit=away'))
        resp, _ = self.request('GET', '/embed', headers={'Cookie': 'molebridge_exit=gone'})
        self.assertEqual((resp.status, resp.getheader('Location')), (303, '/embed?exit=home'))
        _, page = self.request('GET', '/?exit=home', headers={'Cookie': 'molebridge_exit=away'})
        self.assertIn('data-exit="home"', page)

    def test_status_readiness_and_summaries(self):
        resp, body = self.request('GET', '/api/status?exit=away')
        self.assertEqual(json.loads(body)['view']['state'], 'ok')
        self.assertEqual(self.request('GET', '/readyz?exit=away')[0].status, 200)
        self.assertEqual(self.request('GET', '/readyz')[0].status, 503)
        _, body = self.request('GET', '/api/exits')
        summaries = {s['id']: s for s in json.loads(body)['exits']}
        self.assertEqual(summaries['away'], {'id': 'away', 'label': 'PIA Chicago', 'provider': 'pia',
                                             'state': 'ok', 'status': 'connected', 'place': 'Example City'})
        self.assertEqual(summaries['home']['state'], 'unknown')

    def test_latency_cache_is_per_exit(self):
        app._latency_cache.clear()
        self.addCleanup(app._latency_cache.clear)
        with patch.object(app, 'probe_tcp_rtt_ms', return_value=12.0) as probe:
            app.measure_latency({'x': {'ipv4_addr_in': '198.51.100.1'}}, ['x'], scope='home')
            app.measure_latency({'x': {'ipv4_addr_in': '198.51.100.2'}}, ['x'], scope='away')
        self.assertEqual(probe.call_count, 2)


class RegistryPanelTests(unittest.TestCase):
    """The panel takes provider names, patterns and presentation from the registry."""

    def test_server_pattern_reaches_the_browser_for_every_provider(self):
        for provider in app.providers.PROVIDERS:
            with self.subTest(provider=provider), patch.multiple(app, PROVIDER=provider):
                page = app.render_index_html(None, None, None, None, None, 'tok')
                pattern = re.search(r'data-server-pattern="([^"]*)"', page).group(1)
                self.assertEqual(html.unescape(pattern), app.providers.get(provider).server_name_re.pattern)
                self.assertIn(f'data-layout="{app.providers.get(provider).layout}"', page)

    def test_panel_exits_accept_only_registered_providers(self):
        exits = app.parse_exits(','.join(f'{p}={p}' for p in app.providers.PROVIDERS), Path('/state'))
        self.assertEqual([(e.provider, e.label) for e in exits],
                         [(p.id, p.label) for p in app.providers.REGISTRY.values()])
        with self.assertRaisesRegex(ValueError, 'provider must be one of'):
            app.parse_exits('a=examplevpn', Path('/state'))


class EgressTierPanelTests(ServerIntegrationTests):
    """A connected exit shows how its egress was confirmed; /readyz passes for
    both tiers, and the tunnel tier only for a provider without its own check."""

    def _get(self, path):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('GET', path)
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        return resp, body

    def _result(self, **changes):
        app.write_json_atomic(app.APPLIER_RESULT_PATH, {
            'server': 'se-sto-wg-001', 'status': 'ok', 'checked_at': app.now_iso(), 'routing_ok': True,
            'netbird_native': True, **changes})

    def _tunnel_provider(self):
        import dataclasses
        spec = dataclasses.replace(app.providers.get('mullvad'), id='tunnelvpn', label='Tunnel Example',
                                   egress_tier='tunnel')
        for patcher in (patch.dict(app.providers.REGISTRY, {'tunnelvpn': spec}),
                        patch.multiple(app, PROVIDER='tunnelvpn')):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_provider_confirmed_exit_has_no_tunnel_label(self):
        self._result(exit_confirmed=True, egress_tier='provider')
        _, body = self._get('/api/status')
        self.assertEqual(json.loads(body)['view'], {'state': 'ok', 'label': 'connected', 'tier': 'provider'})
        _, page = self._get('/')
        self.assertIn('data-tier-note title="No check by the provider itself; see Diagnostics" hidden>', page)
        self.assertIn('<dd data-f="egress_tier">provider-confirmed</dd>', page)
        self.assertEqual(self._get('/readyz')[0].status, 200)

    def test_tunnel_verified_exit_is_connected_with_a_label(self):
        self._tunnel_provider()
        self._result(exit_confirmed=False, egress_tier='tunnel')
        _, body = self._get('/api/status')
        self.assertEqual(json.loads(body)['view'], {'state': 'ok', 'label': 'connected', 'tier': 'tunnel'})
        _, page = self._get('/')
        self.assertIn('data-tier-note title="No check by the provider itself; see Diagnostics">tunnel checks only<',
                      page)
        self.assertIn('<dd data-f="egress_tier">tunnel checks only</dd>', page)
        self.assertEqual(self._get('/readyz')[0].status, 200)

    def test_tunnel_tier_is_refused_for_a_provider_with_its_own_check(self):
        self._result(exit_confirmed=False, egress_tier='tunnel')
        _, body = self._get('/api/status')
        self.assertEqual(json.loads(body)['view'], {'state': 'failed', 'label': 'verification failed', 'tier': None})
        _, page = self._get('/')
        self.assertIn('<dd data-f="egress_tier">not confirmed</dd>', page)
        self.assertIn('Diagnostics" hidden>', page)
        self.assertEqual(self._get('/readyz')[0].status, 503)

    def test_unconfirmed_tunnel_tier_is_not_ready(self):
        self._tunnel_provider()
        self._result(exit_confirmed=False, egress_tier=None)
        self.assertEqual(self._get('/readyz')[0].status, 503)


class NordPanelTests(unittest.TestCase):
    """The panel in NordVPN mode: hostnames, country and city tree, labels."""

    KEY = VALID_PUBKEY
    US = {'hostname': 'us9001.nordvpn.com', 'public_key': KEY, 'ipv4_addr_in': '198.51.100.11',
          'city': 'Dallas', 'country': 'United States', 'country_code': 'US', 'location_code': 'us-dallas',
          'load': 12, 'virtual': False}
    US2 = {**US, 'hostname': 'us9004.nordvpn.com', 'ipv4_addr_in': '198.51.100.14'}
    VIRTUAL = {**US, 'hostname': 'bs9005.nordvpn.com', 'ipv4_addr_in': '198.51.100.15', 'city': 'Nassau',
               'country': 'Bahamas', 'country_code': 'BS', 'location_code': 'bs-nassau', 'virtual': True}

    def setUp(self):
        patcher = patch.multiple(app, PROVIDER='nordvpn')
        patcher.start()
        self.addCleanup(patcher.stop)

    def catalogue(self, provider='nordvpn'):
        return {'fetched_at': app.now_iso(), 'provider': provider,
                'relays': {r['hostname']: r for r in (self.US, self.US2, self.VIRTUAL)}}

    def test_hostnames_are_selectable_only_when_listed(self):
        with tempfile.TemporaryDirectory() as tmp:
            desired = Path(tmp) / 'desired.json'
            listed = {'us9001.nordvpn.com'}
            self.assertEqual(app.process_select(server='us9001.nordvpn.com', allowlist=listed,
                                                desired_path=desired)[0], 303)
            self.assertEqual(app.process_select(server='us9002.nordvpn.com', allowlist=listed,
                                                desired_path=desired)[0], 400)
            # Not a NordVPN name, even if a catalogue somehow listed it.
            for bad in ('se-sto-wg-001', 'ex_example', 'US9001.nordvpn.com', 'us9001.nordvpn.com.example.net', '../x'):
                self.assertEqual(app.process_select(server=bad, allowlist=listed | {bad}, desired_path=desired)[0], 400)

    def test_allowlist_reads_only_a_fresh_nordvpn_catalogue(self):
        with tempfile.TemporaryDirectory() as tmp:
            ex = app.Exit.under('', 'nordvpn', 'NordVPN', Path(tmp))
            app.write_json_atomic(ex.relays_path, self.catalogue())
            self.assertEqual(app.load_allowlist(ex), {'us9001.nordvpn.com', 'us9004.nordvpn.com', 'bs9005.nordvpn.com'})
            app.write_json_atomic(ex.relays_path, self.catalogue('mullvad'))
            self.assertEqual(app.load_allowlist(ex), set())

    def test_page_groups_servers_by_country_and_city_and_labels_virtual_locations(self):
        result = {'checked_at': app.now_iso(), 'status': 'ok', 'server': 'us9001.nordvpn.com', 'routing_ok': True,
                  'netbird_native': True, 'exit_confirmed': True, 'egress_tier': 'provider', 'provider': 'nordvpn',
                  'egress_ip': '198.51.100.11', 'egress_city': 'Dallas', 'egress_country': 'United States'}
        page = app.render_index_html(None, result, self.catalogue(), None, None, 'tok')
        self.assertIn('data-provider="nordvpn" data-layout="tree"', page)
        self.assertIn('<dt>NordVPN IP</dt><dd data-f="exit_confirmed">True</dd>', page)
        self.assertIn('<span class="country-name">United States</span>', page)
        self.assertIn('2 countries', page)
        self.assertIn('<div class="city-name">Dallas', page)
        self.assertIn('<span class="relay-name" data-arm-text>us9001</span><span class="ms"', page)
        self.assertIn('<span class="relay-name" data-arm-text>bs9005</span>'
                      '<span class="badge" title="Virtual location">virtual</span>', page)
        self.assertIn('title="bs9005.nordvpn.com · virtual location · load 12%"', page)
        self.assertIn('title="us9001.nordvpn.com · load 12%"', page)
        self.assertIn('Filter country, city or relay', page)
        self.assertNotIn('data-attr-filter', page)
        self.assertNotIn('Mullvad', page)
        self.assertNotIn('Forwarded port', page)
        self.assertIn('<dd data-f="egress_tier">provider-confirmed</dd>', page)

    def test_catalogue_of_another_provider_is_not_offered(self):
        page = app.render_index_html(None, None, self.catalogue('mullvad'), None, None, 'tok')
        self.assertNotIn('us9001', page)
        self.assertIn('No relays available.', page)

    def test_provider_style_colours(self):
        with patch.multiple(app, PANEL_STYLE='provider', PANEL_THEME='auto'):
            meta = app.theme_color_meta('nordvpn')
        self.assertIn('content="#161b26" media="(prefers-color-scheme: dark)"', meta)
        self.assertIn('content="#eef2f8" media="(prefers-color-scheme: light)"', meta)
        css = (app.STATIC_DIR / 'panel.css').read_text()
        self.assertIn(':root[data-style="provider"][data-provider="nordvpn"] {', css)
        self.assertIn('.exit-tab[data-provider="nordvpn"] { --exit-accent: var(--exit-nordvpn); }', css)

    def test_status_view_and_readiness_use_nordvpn_names(self):
        desired = {'server': 'us9001.nordvpn.com', 'requested_at': app.now_iso(), 'request_id': 'a' * 32}
        result = {'checked_at': app.now_iso(), 'status': 'ok', 'server': 'us9001.nordvpn.com', 'routing_ok': True,
                  'netbird_native': True, 'exit_confirmed': True, 'request_id': 'a' * 32}
        self.assertEqual(app.status_view(desired, result, 'nordvpn'), ('ok', 'connected'))
        self.assertEqual(app.status_view(desired, result, 'mullvad'), ('ok', 'connected'))
        self.assertEqual(app.status_view(desired, {**result, 'exit_confirmed': False}, 'nordvpn'),
                         ('failed', 'verification failed'))


def _country(n, cities=3, country='Bigland'):
    """n servers spread over `cities` cities, with loads that repeat."""
    relays = {}
    for i in range(n):
        host = f'bg{i:04d}.nordvpn.com'
        relays[host] = {'hostname': host, 'country': country, 'city': f'City {i % cities}',
                        'ipv4_addr_in': f'198.51.100.{i % 250}', 'load': (i * 7) % 100 if i % 5 else None}
    return relays


class LatencyBoundsTests(unittest.TestCase):
    """Latency probing stays bounded for large providers and never lets one
    exit's request hold up another's."""

    def setUp(self):
        app._latency_cache.clear()
        self.addCleanup(app._latency_cache.clear)

    def test_normal_size_country_is_timed_whole_as_before(self):
        relays = _country(app.MAX_COUNTRY_PROBES)
        probed, total = app.country_sample(relays, 'Bigland')
        self.assertEqual((probed, total), (sorted(relays), app.MAX_COUNTRY_PROBES))
        self.assertEqual(app.country_sample(relays, 'Elsewhere'), ([], 0))

    def test_large_country_is_sampled_the_same_way_every_time(self):
        relays = _country(1900)
        probed, total = app.country_sample(relays, 'Bigland')
        self.assertEqual((len(probed), total), (app.MAX_COUNTRY_PROBES, 1900))
        self.assertEqual(len(set(probed)), len(probed))
        self.assertEqual(probed, app.country_sample(dict(reversed(list(relays.items()))), 'Bigland')[0])
        # Each city in turn, lowest load first; servers with no load last.
        self.assertEqual([relays[h]['city'] for h in probed[:3]], ['City 0', 'City 1', 'City 2'])
        for city in ('City 0', 'City 1', 'City 2'):
            loads = [relays[h]['load'] for h in probed if relays[h]['city'] == city]
            known = [x for x in loads if x is not None]
            self.assertEqual(known, sorted(known))
            self.assertEqual(loads[:len(known)], known)

    def test_targets_are_capped_deduplicated_and_keep_named_hosts(self):
        relays = _country(1900, cities=400)
        named = ['bg1899.nordvpn.com', 'bg1898.nordvpn.com']
        targets = app.latency_targets({'hosts': [','.join(named + named)], 'scope': ['cities'],
                                       'country': ['Bigland']}, relays)
        self.assertEqual(len(targets), app.MAX_PROBE_TARGETS)
        self.assertEqual(len(set(targets)), len(targets))
        self.assertEqual(targets[:2], named)

    def test_one_exits_slow_probes_do_not_block_another_exit(self):
        started, release = threading.Event(), threading.Event()

        def probe(ip, *_a, **_kw):
            if ip == '198.51.100.1':
                started.set()
                release.wait(5)
            return 10.0
        with patch.object(app, 'probe_tcp_rtt_ms', side_effect=probe):
            slow = threading.Thread(target=app.measure_latency,
                                    args=({'a': {'ipv4_addr_in': '198.51.100.1'}}, ['a']), kwargs={'scope': 'home'})
            slow.start()
            self.assertTrue(started.wait(5))
            began = time.monotonic()
            result = app.measure_latency({'b': {'ipv4_addr_in': '198.51.100.2'}}, ['b'], scope='away')
            self.assertEqual(result, {'b': 10.0})
            self.assertLess(time.monotonic() - began, 2)
            release.set()
            slow.join(5)

    def test_a_host_already_being_probed_is_waited_for_not_probed_again(self):
        started, release = threading.Event(), threading.Event()
        calls = []

        def probe(ip, *_a, **_kw):
            calls.append(ip)
            started.set()
            release.wait(5)
            return 12.0
        relays = {'a': {'ipv4_addr_in': '198.51.100.1'}}
        with patch.object(app, 'probe_tcp_rtt_ms', side_effect=probe):
            first = threading.Thread(target=app.measure_latency, args=(relays, ['a']), kwargs={'scope': 'home'})
            first.start()
            self.assertTrue(started.wait(5))
            results = []
            second = threading.Thread(target=lambda: results.append(
                app.measure_latency(relays, ['a'], fresh=True, scope='home')))
            second.start()
            time.sleep(0.1)
            release.set()
            first.join(5)
            second.join(5)
        self.assertEqual(calls, ['198.51.100.1'])
        self.assertEqual(results, [{'a': 12.0}])
        self.assertEqual(app._probes_in_flight, {})

    def test_admission_is_one_request_per_exit_and_bounded_panel_wide(self):
        self.assertTrue(app.latency_admit('home'))
        self.assertFalse(app.latency_admit('home'))
        others = [f'x{i}' for i in range(app.LATENCY_SLOTS - 1)]
        self.assertTrue(all(app.latency_admit(e) for e in others))
        self.assertFalse(app.latency_admit('away'))
        app.latency_release('home')
        self.assertTrue(app.latency_admit('away'))
        for exit_id in others + ['away']:
            app.latency_release(exit_id)
        self.assertTrue(app.latency_admit('home'))
        app.latency_release('home')


class LatencyEndpointTests(ServerIntegrationTests):
    def _get(self, path):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('GET', path)
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        return resp, body

    def test_busy_exit_gets_429_before_anything_is_loaded(self):
        self.assertTrue(app.latency_admit(''))
        self.addCleanup(app.latency_release, '')
        with patch.object(app, 'load_relays', side_effect=AssertionError('loaded while busy')):
            resp, body = self._get('/api/latency?scope=cities')
        self.assertEqual((resp.status, resp.getheader('Retry-After')), (429, '3'))
        self.assertEqual(json.loads(body), {'error': 'latency busy'})

    def test_country_answer_says_how_many_were_timed(self):
        relays = _country(300)
        with patch.object(app, 'load_relays', return_value=relays), \
                patch.object(app, 'probe_tcp_rtt_ms', return_value=5.0):
            resp, body = self._get('/api/latency?country=Bigland')
        data = json.loads(body)
        self.assertEqual(resp.status, 200)
        self.assertEqual(data['country'], {'probed': app.MAX_COUNTRY_PROBES, 'total': 300})
        self.assertEqual(len(data['latency']), app.MAX_COUNTRY_PROBES)
        # The slot was given back.
        self.assertTrue(app.latency_admit(''))
        app.latency_release('')
