"""Status records for the panel's tests and the JS tests, with fictitious
values only: schema 2 as the appliers publish it (applier/apply.py publish),
and the 0.6 shape the panel still reads."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from molebridge import providers  # noqa: E402
from molebridge.state import now_iso  # noqa: E402
from molebridge.verdict import NOT_CHECKED_BY, SERVER_BOUND, backend_of, fixed_checks, required_checks  # noqa: E402

SERVER = {'mullvad': 'se-sto-wg-001', 'pia': 'ex_example', 'nordvpn': 'us9001.nordvpn.com',
          'gluetun-mullvad': 'se-sto-wg-001', 'gluetun-nordvpn': 'us9001.nordvpn.com',
          'gluetun-surfshark': 'us-chi.prod.surfshark.com'}
EGRESS_IP = '203.0.113.7'
REQUEST_ID = 'a' * 32


def request(server: str, request_id: str = REQUEST_ID, at: Optional[str] = None) -> Dict[str, Any]:
    """A panel request, as desired.json holds it."""
    return {'server': server, 'requested_at': at or now_iso(), 'request_id': request_id}


def schema2(provider: str = 'mullvad', kind: str = 'overlay', *, status: str = 'ok', server: Any = '',
            checks: Optional[Dict[str, Any]] = None, at: Optional[str] = None, request_id: Any = REQUEST_ID,
            requested_server: Any = '', configured: Optional[str] = None, source: str = 'panel',
            outcome: str = 'verified', **fields) -> Dict[str, Any]:
    """A schema-2 record: every required check passing unless `checks`
    overrides it, by name, with a state (its other fields kept) or a whole
    check. Other keyword arguments replace top-level fields."""
    at = at or now_iso()
    backend = backend_of(provider)
    server = SERVER.get(provider, 'se-sto-wg-001') if server == '' else server
    requested = server if requested_server == '' else requested_server
    tier = providers.get(provider).egress_tier
    record_checks: Dict[str, Any] = {}
    for name in required_checks(kind, backend):
        check: Dict[str, Any] = {'state': 'pass', 'at': at}
        if name in SERVER_BOUND:
            check['server'] = server
        if name == 'routing':
            check['fallback'] = True
        if name == 'traffic_protection':
            check['from'] = 'routing'
        if name == 'handshake':
            check['age_s'] = 12
        if name == 'egress':
            check.update(tier=tier, expected_families=['4'], families={'4': 'pass'})
        record_checks[name] = check
    for name, state in fixed_checks(kind, backend).items():
        record_checks[name] = {'state': state, **({'by': NOT_CHECKED_BY[name]} if state == 'not-checked' else {})}
    for name, change in (checks or {}).items():
        if isinstance(change, str):
            record_checks[name] = {**record_checks.get(name, {}), 'state': change}
            if name == 'egress' and change != 'pass':
                record_checks[name].update(tier=None, families={'4': change if change == 'fail' else 'unknown'})
        else:
            record_checks[name] = change
    egress = record_checks.get('egress', {})
    passing = egress.get('state') == 'pass'
    record = {'schema': 2, 'kind': kind, 'backend': backend, 'provider': provider, 'status': status,
              'message': 'Healthy.' if status == 'ok' else 'Tunnel egress is not confirmed.',
              'checked_at': at, 'server': server, 'requested_server': requested,
              'configured_server': configured, 'request_id': request_id,
              'selection': {'source': source, 'outcome': outcome, 'attempt': 1, 'target': server,
                            'next_action': None, 'next_action_at': None},
              'checks': record_checks,
              # egress_ips covers exactly the passing families.
              'egress_ip': EGRESS_IP, 'egress_ips': {'4': EGRESS_IP} if passing else {},
              'egress_city': 'Stockholm', 'egress_country': 'Sweden'}
    record.update(fields)
    return record


def unmeasurable_sidecar(provider: str = 'gluetun-surfshark', **fields) -> Dict[str, Any]:
    """A tunnel-tier sidecar after a switch: switched, its egress never
    comparable with the host's address (applier/gluetun_applier.py)."""
    record = schema2(provider, 'sidecar', status='failed', outcome='applied-unverified', **fields)
    record['checks']['egress'] = {'state': 'fail', 'at': record['checked_at'], 'server': record['server'],
                                  'tier': None, 'expected_families': ['4'], 'families': {'4': 'unknown'},
                                  'reason': 'host-address-not-measurable'}
    record['message'] = "Switched; the egress couldn't be compared with this host's address."
    record['egress_ips'] = {'4': EGRESS_IP}
    record['selection'].update(next_action='recheck', next_action_at='2026-10-10T18:01:00Z')
    return record


def legacy(status: str = 'ok', server: str = 'se-sto-wg-001', **fields) -> Dict[str, Any]:
    """A 0.6 overlay record (no schema)."""
    record = {'server': server, 'requested_server': server, 'request_id': REQUEST_ID, 'status': status,
              'message': 'Healthy.' if status == 'ok' else 'Switch verification timed out.',
              'checked_at': now_iso(), 'routing_ok': True, 'netbird_native': True, 'exit_confirmed': True,
              'egress_tier': 'provider', 'handshake_age_s': 12, 'unreachable_fallback': True,
              'egress_ip': EGRESS_IP, 'egress_city': 'Stockholm', 'egress_country': 'Sweden'}
    if status != 'ok':
        record.update(exit_confirmed=False, egress_tier=None)
    record.update(fields)
    return record


def _without(record: Dict[str, Any], check: str) -> Dict[str, Any]:
    del record['checks'][check]
    return record


# The consumer matrix: one exit's record (and the panel's request), and the
# state and label every consumer must show for it. Each value is
# (provider, kind, record, request, state, label, tier); records and requests
# are built when called, so their times are fresh.
CASES = {
    'legacy-ok': ('mullvad', 'overlay', lambda: legacy(), lambda: request(SERVER['mullvad']),
                  'ok', 'connected', 'provider'),
    'legacy-failed': ('mullvad', 'overlay', lambda: legacy('failed'), lambda: request(SERVER['mullvad']),
                      'failed', 'failed', None),
    'overlay-ok': ('mullvad', 'overlay', lambda: schema2(), lambda: request(SERVER['mullvad']),
                   'ok', 'connected', 'provider'),
    'overlay-routing-failed': (
        'mullvad', 'overlay',
        lambda: schema2(status='failed', checks={'routing': 'fail', 'traffic_protection': 'fail', 'egress': 'unknown'}),
        lambda: request(SERVER['mullvad']), 'failed', 'failed', None),
    'overlay-retrying': (
        'mullvad', 'overlay',
        lambda: schema2(status='failed', checks={'egress': 'fail'}, outcome='applied-unverified',
                        selection={'source': 'panel', 'outcome': 'applied-unverified', 'attempt': 2,
                                   'target': SERVER['mullvad'], 'next_action': 'reapply',
                                   'next_action_at': '2026-10-10T18:02:30Z'}),
        lambda: request(SERVER['mullvad']), 'failed', 'failed', None),
    'pia-forwarding': ('pia', 'overlay', lambda: schema2('pia', port_forward=True, forwarded_port=43210),
                       lambda: request(SERVER['pia']), 'ok', 'connected', 'provider'),
    'overlay-gluetun-tunnel-tier': ('gluetun-surfshark', 'overlay', lambda: schema2('gluetun-surfshark'),
                                    lambda: request(SERVER['gluetun-surfshark']), 'ok', 'connected', 'tunnel'),
    'sidecar-provider-tier': ('gluetun-mullvad', 'sidecar', lambda: schema2('gluetun-mullvad', 'sidecar'),
                              lambda: request(SERVER['gluetun-mullvad']), 'ok', 'connected', 'provider'),
    'sidecar-tunnel-tier': ('gluetun-surfshark', 'sidecar', lambda: unmeasurable_sidecar(),
                            lambda: request(SERVER['gluetun-surfshark']), 'unknown', 'switched, egress unverified',
                            None),
    'unsupported-schema': ('mullvad', 'overlay', lambda: schema2(schema=3), lambda: request(SERVER['mullvad']),
                           'unknown', 'unsupported status version', None),
    'kind-mismatch': ('gluetun-mullvad', 'overlay', lambda: schema2('gluetun-mullvad', 'sidecar'),
                      lambda: request(SERVER['gluetun-mullvad']), 'unknown', 'kind mismatch', None),
    'provider-mismatch': ('mullvad', 'overlay', lambda: schema2(provider='nordvpn'),
                          lambda: request(SERVER['mullvad']), 'unknown', 'provider mismatch', None),
    'missing-check': ('mullvad', 'overlay', lambda: _without(schema2(), 'peer'), lambda: request(SERVER['mullvad']),
                      'unknown', 'invalid status record', None),
    'stale': ('mullvad', 'overlay', lambda: schema2(at='2000-01-01T00:00:00Z'), lambda: request(SERVER['mullvad']),
              'unknown', 'status stale', None),
    'request-pending': ('mullvad', 'overlay', lambda: schema2(), lambda: request('se-got-wg-001', 'b' * 32),
                        'applying', 'switching', None),
    'request-not-acknowledged': ('mullvad', 'overlay', lambda: schema2(),
                                 lambda: request('se-got-wg-001', 'b' * 32, '2000-01-01T00:00:00Z'),
                                 'unknown', 'request not acknowledged', None),
    'target-disagreement': ('mullvad', 'overlay', lambda: schema2(requested_server='se-got-wg-001'),
                            lambda: request('se-got-wg-001'), 'failed', 'verification failed', None),
    'configured': ('mullvad', 'overlay', lambda: schema2(configured=SERVER['mullvad'], source='configured',
                                                         request_id=None, requested_server=None),
                   lambda: request('se-got-wg-001', 'b' * 32), 'ok', 'connected', 'provider'),
    'no-status': ('mullvad', 'overlay', lambda: None, lambda: None, 'unknown', 'awaiting status', None),
}
