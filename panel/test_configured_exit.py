"""Read-only exits through rendering and handlers, without opening sockets."""
import html
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import app
from molebridge.state import now_iso, status_view, write_json_atomic

PROVIDERS = app.providers.PROVIDERS
CONFIGURED = 'configured.example.test'


def result(**changes):
    return {'status': 'ok', 'checked_at': now_iso(), 'configured_server': CONFIGURED,
            'server': CONFIGURED, 'routing_ok': True, 'netbird_native': True,
            'exit_confirmed': True, **changes}


def desire():
    return {'server': 'se-sto-wg-001', 'request_id': '0' * 32, 'requested_at': now_iso()}


@pytest.mark.parametrize('provider', PROVIDERS)
@pytest.mark.parametrize('embed', [False, True])
@pytest.mark.parametrize('state', ['ok', 'failed', 'unknown', 'applying'])
def test_configuration_page_has_no_switch_form_or_controls(provider, embed, state, tmp_path):
    ex = app.Exit.under('', provider, 'Example', tmp_path)
    snapshot = {'provider': provider, 'fetched_at': now_iso(), 'relays': {
        CONFIGURED: {'hostname': CONFIGURED, 'country': 'Example', 'city': 'Example City',
                     'location_code': 'ex-one', 'ipv4_addr_in': '198.51.100.10'}}}
    page = app.render_index_html(desire(), result(status=state, message='Example failure.'),
                                 snapshot, None, None, 'token', exit=ex, embed=embed)
    assert 'Set in configuration:' in page and CONFIGURED in page
    for control in ['action="/select"', 'id="select-form"', 'name="server"', 'data-retry',
                    'id="fastest"', 'id="saved"', 'data-pin', 'locations-widget']:
        assert control not in page
    assert 'Diagnostics' in page and 'data-state-pill' in page
    assert 'data-request=""' in page


@pytest.mark.parametrize('checked', [now_iso(), '2000-01-01T00:00:00Z'])
def test_configuration_status_ignores_panel_and_keeps_stale_lock(tmp_path, monkeypatch, checked):
    ex = app.Exit.under('', 'mullvad', 'Example', tmp_path)
    write_json_atomic(ex.desired_path, desire())
    write_json_atomic(ex.result_path, result(checked_at=checked))
    original = app.read_json
    def read(path, *args):
        assert path != ex.desired_path
        return original(path, *args)
    monkeypatch.setattr(app, 'read_json', read)
    payload = app.status_payload(ex)
    assert payload['desired'] is None
    assert payload['view']['selection_mode'] == 'configuration'
    assert payload['view']['configured_server'] == CONFIGURED
    assert payload['view']['state'] == ('unknown' if checked == '2000-01-01T00:00:00Z' else 'ok')
    page = app.render_index_html(desire(), result(checked_at=checked), None, None, None, 'token')
    assert 'Set in configuration:' in page and 'action="/select"' not in page


def handler(path, ex, monkeypatch):
    h = app.PanelHandler.__new__(app.PanelHandler)
    h.path = path
    h._misdirected = Mock(return_value=False)
    h._session = Mock(return_value=None)
    h._cookie = Mock(return_value='nonce')
    h._read_form = Mock(return_value={'server': 'se-sto-wg-001', 'csrf_token': 'token', 'exit': ex.id})
    h._send_plain = Mock()
    h._send_body = Mock()
    h._send_json = Mock()
    monkeypatch.setattr(app, 'AUTH', None)
    monkeypatch.setattr(app, 'authorized_exit', lambda _id, _session: ex)
    monkeypatch.setattr(app, 'verify_csrf', lambda *_args: True)
    return h


@pytest.mark.parametrize('checked', [now_iso(), '2000-01-01T00:00:00Z'])
def test_post_refused_without_writing_for_configured_exit(tmp_path, monkeypatch, checked):
    ex = app.Exit.under('example', 'mullvad', 'Example', tmp_path)
    write_json_atomic(ex.desired_path, desire())
    before = ex.desired_path.read_bytes()
    write_json_atomic(ex.result_path, result(checked_at=checked))
    h = handler('/select', ex, monkeypatch)
    h.do_POST()
    h._send_plain.assert_called_once_with(403, 'Exit is set in configuration; change SERVER to choose another server.')
    assert ex.desired_path.read_bytes() == before


def test_api_status_handler_exposes_configuration(tmp_path, monkeypatch):
    ex = app.Exit.under('example', 'mullvad', 'Example', tmp_path)
    write_json_atomic(ex.desired_path, desire())
    write_json_atomic(ex.result_path, result())
    h = handler('/api/status?exit=example', ex, monkeypatch)
    h.do_GET()
    payload = h._send_json.call_args.args[0]
    assert payload['desired'] is None
    assert payload['view']['configured_server'] == CONFIGURED
    assert payload['view']['selection_mode'] == 'configuration'
    assert payload['view']['state'] == 'ok'


@pytest.mark.parametrize('configured', [None, ''])
def test_without_setting_selection_and_status_keep_old_behavior(tmp_path, monkeypatch, configured):
    ex = app.Exit.under('', 'mullvad', 'Example', tmp_path)
    write_json_atomic(ex.result_path, result(configured_server=configured))
    h = handler('/select', ex, monkeypatch)
    monkeypatch.setattr(app, 'load_allowlist', lambda _ex: {'se-sto-wg-001'})
    h.do_POST()
    assert app.read_json(ex.desired_path)['server'] == 'se-sto-wg-001'
    assert h._send_body.call_args.args[0] == 303
    payload = app.status_payload(ex)
    assert payload['view']['selection_mode'] == 'panel'
    assert payload['desired']['server'] == 'se-sto-wg-001'
    assert payload['view']['state'] == 'applying'


def test_invalid_configured_text_escaped_and_not_reported_connected():
    configured = '<script>bad</script>"\n'
    res = result(configured_server=configured, status='failed')
    page = app.render_index_html(desire(), res, None, None, None, 'token')
    assert '<script>bad</script>' not in page
    assert html.escape(configured) in page
    assert 'action="/select"' not in page
    assert status_view(desire(), res) == ('failed', 'failed')


def test_configured_status_cannot_mark_a_different_server_connected():
    assert status_view(desire(), result(server='other.example.test')) == ('failed', 'verification failed')


def test_configuration_lock_is_per_exit(tmp_path, monkeypatch):
    configured = app.Exit.under('configured', 'mullvad', 'Configured', tmp_path / 'configured')
    writable = app.Exit.under('writable', 'mullvad', 'Writable', tmp_path / 'writable')
    write_json_atomic(configured.result_path, result())
    write_json_atomic(writable.result_path, result(configured_server=None))
    authorize = app.authorized_exit
    h = handler('/select', configured, monkeypatch)
    monkeypatch.setattr(app, 'EXITS', (configured, writable))
    monkeypatch.setattr(app, 'authorized_exit', authorize)
    monkeypatch.setattr(app, 'load_allowlist', lambda _ex: {'se-sto-wg-001'})
    h.do_POST()
    assert h._send_plain.call_args.args[0] == 403
    assert not configured.desired_path.exists()
    h._read_form.return_value['exit'] = 'writable'
    h.do_POST()
    assert h._send_body.call_args.args[0] == 303
    assert app.read_json(writable.desired_path)['server'] == 'se-sto-wg-001'
    assert not configured.desired_path.exists()
