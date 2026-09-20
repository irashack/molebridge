import http.client
import http.server
import io
import json
import re
import shutil
import tempfile
import threading
import unittest
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

    def test_origin_host_matching(self):
        self.assertTrue(app.origin_matches_host(None, 'exit.example.test'))
        self.assertTrue(app.origin_matches_host(
            'https://exit.example.test', 'exit.example.test'))
        self.assertFalse(app.origin_matches_host(
            'https://evil.example.com', 'exit.example.test'))
        self.assertFalse(app.origin_matches_host('https://evil.example.com', None))
        self.assertFalse(app.origin_matches_host('http://exit.example.test:8096', 'exit.example.test:8095'))
        self.assertTrue(app.origin_matches_host('http://[::1]:8095', '[::1]:8095'))
        self.assertFalse(app.origin_matches_host('http://[', 'exit.example.test'))


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


def test_origin_accepts_forwarded_host_behind_proxy():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("panel_app_fwd", Path(__file__).parent / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    origin = "https://exit.example.test"
    assert mod.origin_matches_host(origin, "host.docker.internal:8095", "exit.example.test")
    assert not mod.origin_matches_host("https://evil.example", "host.docker.internal:8095", "exit.example.test")


def test_origin_accepts_configured_public_host_behind_proxy(monkeypatch):
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("panel_app_public", Path(__file__).parent / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setenv("PANEL_PUBLIC_HOSTS", "exit.example.test")
    assert mod.origin_matches_host("https://exit.example.test", "127.0.0.1:8095", None)
    assert not mod.origin_matches_host("https://evil.example", "127.0.0.1:8095", None)
    monkeypatch.delenv("PANEL_PUBLIC_HOSTS")
    assert not mod.origin_matches_host("https://exit.example.test", "127.0.0.1:8095", None)


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
