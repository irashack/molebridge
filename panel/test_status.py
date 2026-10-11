"""The panel's status consumers, all from one verdict (molebridge/verdict.py,
whose own judgments tools/test_verdict.py covers): the page, /api/status
with its deprecated `view` and diagnostic fields, /api/exits, /readyz, and
the switch gate (D8). Also the exit kind in PANEL_EXITS and EXIT_KIND."""
import html
import http.client
import http.server
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'fixtures'))
import app  # noqa: E402
import records  # noqa: E402
from records import request, schema2  # noqa: E402

PROJECTION = ('routing_ok', 'netbird_native', 'exit_confirmed', 'egress_tier', 'handshake_age_s',
              'unreachable_fallback')


def setup_exit(tmp_path, provider, kind, result, desired, exit_id='x'):
    (ex,) = app.parse_exits(f'{exit_id}={provider}/{kind}:Example', tmp_path)
    if result is not None:
        app.write_json_atomic(ex.result_path, result)
    if desired is not None:
        app.write_json_atomic(ex.desired_path, desired)
    return ex


@pytest.fixture
def server(monkeypatch):
    """A panel on loopback; returns a GET helper once EXITS is set."""
    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), app.PanelHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def get(path):
        conn = http.client.HTTPConnection('127.0.0.1', httpd.server_address[1], timeout=5)
        conn.request('GET', path)
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        return resp.status, body
    yield get
    httpd.shutdown()
    httpd.server_close()


# -- the consumer matrix ------------------------------------------------------

@pytest.mark.parametrize('case', list(records.CASES))
def test_every_consumer_shows_the_one_verdict(case, tmp_path, monkeypatch, server):
    provider, kind, record, desired, state, label, tier = records.CASES[case]
    result = record()
    ex = setup_exit(tmp_path, provider, kind, result, desired())
    monkeypatch.setattr(app, 'EXITS', [ex])
    configured = (result or {}).get('configured_server')

    # /api/status: the verdict, and the old view kept whole.
    code, body = server('/api/status?exit=x')
    payload = json.loads(body)
    assert code == 200
    verdict = payload['verdict']
    assert (verdict['state'], verdict['label'], verdict['tier'], verdict['kind']) == (state, label, tier, kind)
    assert set(verdict['checks']) == set(app.CHECKS)
    assert payload['view'] == {'state': state, 'label': label, 'tier': tier,
                               'selection_mode': 'configuration' if configured else 'panel',
                               'configured_server': configured}

    # The deprecated diagnostic fields: derived for schema 2 only, and a
    # record's own fields are never overwritten.
    if result is not None and result.get('schema') == 2:
        assert set(PROJECTION) <= set(payload['result'])
    elif result is not None:
        assert {key: payload['result'].get(key) for key in PROJECTION} == \
            {key: result.get(key) for key in PROJECTION}

    # The page, from the same verdict.
    code, page = server('/?exit=x')
    assert code == 200
    assert f'data-state="{state}"' in page
    assert f'data-state-pill role="status" aria-live="polite">{html.escape(label)}</span>' in page
    assert (f'data-tier-note title="No check by the provider itself; see Diagnostics">' in page) == (tier == 'tunnel')
    assert (f'<dd data-f="egress_tier">{app.TEXT["tier"][tier or "none"]}</dd>') in page
    # Only a connected exit shows an egress address.
    shown = '203.0.113.7' if state == 'ok' else '—'
    assert f'<span data-current-ip>{shown}</span>' in page
    for name, check in verdict['checks'].items():
        assert f'data-check="{name}" data-check-state="{html.escape(check)}">' in page

    # The exit tabs and readiness.
    code, body = server('/api/exits')
    (summary,) = json.loads(body)['exits']
    assert (summary['state'], summary['status']) == (state, label)
    assert server('/readyz?exit=x')[0] == (200 if state == 'ok' else 503)
    assert server('/readyz')[0] == (200 if state == 'ok' else 503)


def test_the_page_and_its_own_tab_share_one_read(tmp_path, monkeypatch):
    ex = setup_exit(tmp_path, 'mullvad', 'overlay', schema2(), request('se-sto-wg-001'))
    monkeypatch.setattr(app, 'EXITS', [ex])
    reads = []
    original = app.read_status
    monkeypatch.setattr(app, 'read_status', lambda e=None: reads.append(e) or original(e))
    h = app.PanelHandler.__new__(app.PanelHandler)
    h.headers = {}
    h._cookie = Mock(return_value=None)
    h._send_body = Mock()
    h._handle_index({'exit': ['x']}, None, embed=False)
    assert reads == [ex]
    assert h._send_body.call_args.args[0] == 200


def test_the_page_carries_the_wording_and_kind_for_its_script():
    page = app.render_index_html(None, None, None, None, None, 'tok')
    attribute = page.split(' data-text="', 1)[1].split('"', 1)[0]
    assert json.loads(html.unescape(attribute)) == app.TEXT
    assert ' data-kind="overlay" ' in page
    # The browser has no wording or tier logic of its own.
    script = (app.STATIC_DIR / 'panel.js').read_text()
    for gone in ('egressTier', 'exit_confirmed', 'Secure connection', 'provider-confirmed', 'data.view'):
        assert gone not in script


def test_a_failed_exit_shows_no_tier_and_no_address():
    result = records.legacy('ok', egress_tier='tunnel', exit_confirmed=False)
    page = app.render_index_html(request('se-sto-wg-001'), result, None, None, None, 'tok')
    # Mullvad has its own check: a tunnel tier isn't enough.
    assert 'data-state="failed"' in page
    assert '<dd data-f="egress_tier">not confirmed</dd>' in page
    assert '<span data-current-ip>—</span>' in page


# -- sidecar wording ------------------------------------------------------------

def sidecar_page(tmp_path, result, desired, exit_id='x'):
    ex = setup_exit(tmp_path, 'gluetun-surfshark', 'sidecar', result, desired, exit_id)
    status = app.read_status(ex)
    return app.render_index_html(status.desired, status.result, None, None, None, 'tok', exit=ex, status=status)


def test_a_sidecar_is_a_tunnel_and_says_what_it_couldnt_check(tmp_path):
    page = sidecar_page(tmp_path, records.unmeasurable_sidecar(), request(records.SERVER['gluetun-surfshark']))
    assert '<span class="brand-kicker">Molebridge / tunnel control</span>' in page
    assert '<h2>Example tunnel <span class="provider-note">via gluetun</span></h2>' in page
    assert 'switched, egress unverified</span>' in page
    assert ('<p class="note note-negative">Switched; the egress couldn&#x27;t be compared with this host&#x27;s '
            'address.<br><span class="subdue small" data-next>Re-checking at 18:01:00 UTC.</span></p>') in page
    assert ('<dd data-check="traffic_protection" data-check-state="not-checked">not checked by Molebridge '
            '(gluetun&#x27;s firewall)</dd>') in page
    assert '<dd data-check="routing" data-check-state="n/a">not applicable</dd>' in page
    assert ('<dd data-check="egress" data-check-state="fail">failed: this host&#x27;s address '
            'can&#x27;t be measured</dd>') in page
    assert 'Connection unverified' in page and 'data-retry' not in page


def test_a_sidecar_switch_drops_tunnel_connections(tmp_path):
    page = sidecar_page(tmp_path, records.schema2('gluetun-surfshark', 'sidecar', status='applying'),
                        request('us-nyc.prod.surfshark.com', 'b' * 32))
    assert '<span data-connection-label>Switching server</span>' in page
    assert ('Leaving us-chi.prod.surfshark.com. Open connections through the tunnel will drop.') in page


def test_an_overlay_keeps_its_exit_wording(tmp_path):
    ex = setup_exit(tmp_path, 'mullvad', 'overlay', schema2(status='applying'), request('se-got-wg-001', 'b' * 32))
    page = app.render_index_html(None, app.read_json(ex.result_path), None, None, None, 'tok', exit=ex,
                                 status=app.read_status(ex))
    assert 'Molebridge / exit control' in page and '<h2>Example exit' in page
    assert 'Switching route' in page and 'Open connections through the exit will drop.' in page
    single = app.render_index_html(None, None, None, None, None, 'tok')
    assert '<h2>Current exit</h2>' in single


# -- the exit kind ----------------------------------------------------------------

def test_panel_exits_take_an_optional_kind(tmp_path):
    exits = app.parse_exits('a=mullvad, b=gluetun-mullvad/sidecar:Side car, c=gluetun-ivpn/overlay, '
                            'd=gluetun-surfshark/sidecar', tmp_path)
    assert [(e.id, e.provider, e.kind, e.label) for e in exits] == [
        ('a', 'mullvad', 'overlay', 'Mullvad'), ('b', 'gluetun-mullvad', 'sidecar', 'Side car'),
        ('c', 'gluetun-ivpn', 'overlay', providers_label('gluetun-ivpn')),
        ('d', 'gluetun-surfshark', 'sidecar', providers_label('gluetun-surfshark'))]
    with pytest.raises(ValueError, match=r"^PANEL_EXITS: a sidecar exit needs a gluetun provider "
                                         r"\(gluetun-<name>/sidecar\), in 'a=mullvad/sidecar'$"):
        app.parse_exits('a=mullvad/sidecar', tmp_path)
    for bad in ('a=gluetun-mullvad/tunnel', 'a=gluetun-mullvad/', 'a=gluetun-mullvad/Sidecar'):
        with pytest.raises(ValueError, match='^PANEL_EXITS: the kind after / is overlay or sidecar'):
            app.parse_exits(bad, tmp_path)


def providers_label(provider):
    return app.providers.get(provider).label


@pytest.mark.parametrize('env,error', [
    ({'EXIT_KIND': 'sidecar', 'PROVIDER': 'gluetun-mullvad'}, None),
    ({'EXIT_KIND': '', 'PROVIDER': 'mullvad'}, None),
    ({'EXIT_KIND': 'sidecar', 'PROVIDER': 'mullvad'},
     'a sidecar exit needs a gluetun provider (PROVIDER=gluetun-<name>)'),
    ({'EXIT_KIND': 'tunnel'}, 'EXIT_KIND must be overlay or sidecar'),
    # PANEL_EXITS names each exit's kind; EXIT_KIND is then unused.
    ({'EXIT_KIND': 'tunnel', 'PANEL_EXITS': 'a=mullvad'}, None),
])
def test_a_single_exit_reads_exit_kind_at_start(env, error):
    script = 'import app; print(app.single_exit().kind if not app.EXITS else "-")'
    run = subprocess.run([sys.executable, '-c', script], cwd=HERE, capture_output=True, text=True, timeout=30,
                         env={'PATH': os.environ.get('PATH', ''), 'PYTHONDONTWRITEBYTECODE': '1', **env})
    if error is None:
        assert run.returncode == 0, run.stderr
    else:
        assert run.returncode != 0
        assert run.stderr.strip().endswith(f'ValueError: {error}')


# -- the switch gate (D8) ------------------------------------------------------

def post_handler(ex, monkeypatch, server='se-got-wg-001', csrf=True):
    h = app.PanelHandler.__new__(app.PanelHandler)
    h.path = '/select'
    h._misdirected = Mock(return_value=False)
    h._session = Mock(return_value=None)
    h._cookie = Mock(return_value='nonce')
    h._read_form = Mock(return_value={'server': server, 'csrf_token': 'token', 'exit': ex.id})
    h._send_plain = Mock()
    h._send_body = Mock()
    monkeypatch.setattr(app, 'AUTH', None)
    monkeypatch.setattr(app, 'EXITS', [ex])
    monkeypatch.setattr(app, 'verify_csrf', lambda *_args: csrf)
    monkeypatch.setattr(app, 'load_allowlist', lambda _ex: {'se-sto-wg-001', 'se-got-wg-001'})
    return h


def answer(h):
    if h._send_plain.called:
        return h._send_plain.call_args.args
    return (h._send_body.call_args.args[0],)


BUSY = (409, 'A switch is in progress; wait for it to finish.')


@pytest.mark.parametrize('result,desired', [
    (schema2(status='applying'), request('se-sto-wg-001')),
    # The panel's own request, not yet acknowledged.
    (schema2(), request('se-got-wg-001', 'b' * 32)),
    (records.legacy('applying'), request('se-sto-wg-001')),
])
def test_a_switch_in_progress_refuses_another(tmp_path, monkeypatch, result, desired):
    ex = setup_exit(tmp_path, 'mullvad', 'overlay', result, desired)
    before = ex.desired_path.read_bytes()
    h = post_handler(ex, monkeypatch)
    h.do_POST()
    assert answer(h) == BUSY
    assert ex.desired_path.read_bytes() == before


def test_gate_order_csrf_then_configuration_then_switching(tmp_path, monkeypatch):
    configured = schema2(status='applying', configured='se-sto-wg-001', source='configured')
    ex = setup_exit(tmp_path, 'mullvad', 'overlay', configured, None)
    h = post_handler(ex, monkeypatch, csrf=False)
    h.do_POST()
    assert answer(h) == (403, 'invalid or missing csrf token')
    h = post_handler(ex, monkeypatch)
    h.do_POST()
    assert answer(h) == (403, 'Exit is set in configuration; change SERVER to choose another server.')
    assert not ex.desired_path.exists()


@pytest.mark.parametrize('result', [schema2(at='2000-01-01T00:00:00Z', status='applying'), None,
                                    schema2(), schema2(status='failed', checks={'egress': 'fail'})])
def test_only_a_visible_switch_blocks(tmp_path, monkeypatch, result):
    # Stale or missing status (unknown) doesn't block: the applier decides.
    ex = setup_exit(tmp_path, 'mullvad', 'overlay', result, request('se-sto-wg-001'))
    h = post_handler(ex, monkeypatch)
    h.do_POST()
    assert answer(h) == (303,)
    assert app.read_json(ex.desired_path)['server'] == 'se-got-wg-001'


def test_concurrent_requests_write_once(tmp_path, monkeypatch):
    """Two requests read the same connected snapshot; the lock lets only the
    first write, and the second then sees the switch it started."""
    ex = setup_exit(tmp_path, 'mullvad', 'overlay', schema2(), request('se-sto-wg-001'))
    writes = []
    original = app.process_select

    def slow_select(**kwargs):
        # Widen the window between assessing and writing.
        time.sleep(0.2)
        writes.append(kwargs['server'])
        return original(**kwargs)
    monkeypatch.setattr(app, 'process_select', slow_select)
    handlers = [post_handler(ex, monkeypatch, server) for server in ('se-got-wg-001', 'se-sto-wg-001') * 3]
    barrier = threading.Barrier(len(handlers))

    def run(h):
        barrier.wait()
        h.do_POST()
    threads = [threading.Thread(target=run, args=(h,)) for h in handlers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    answers = sorted(answer(h)[0] for h in handlers)
    assert answers == [303, 409, 409, 409, 409, 409]
    assert len(writes) == 1
    assert app.read_json(ex.desired_path)['server'] == writes[0]


def test_each_exit_has_its_own_lock(tmp_path):
    a = app.Exit.under('a', 'mullvad', 'A', tmp_path / 'a')
    b = app.Exit.under('b', 'mullvad', 'B', tmp_path / 'b')
    assert app.select_lock(a) is app.select_lock(a)
    assert app.select_lock(a) is not app.select_lock(b)
