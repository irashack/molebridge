"""molebridge/verdict.py: the one judgment every reader shares. Records are
built here; nothing touches an applier, a panel or a tunnel."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from molebridge.state import request_token
from molebridge.verdict import ExitConfig, Target, assess, legacy_projection

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
HOST, OTHER = 'se-sto-wg-001', 'se-sto-wg-002'
GLUETUN_HOST = 'two.example.test'
REQUEST = {'server': HOST, 'requested_at': '2026-10-11T11:59:50Z', 'request_id': 'a' * 32}


def at(seconds_ago=5):
    return (NOW - timedelta(seconds=seconds_ago)).strftime('%Y-%m-%dT%H:%M:%SZ')


def record(kind='overlay', provider='mullvad', server=HOST, *, tier='provider', families=('4', '6'), **changes):
    """A healthy schema-2 record as the applier writes it."""
    backend = 'gluetun' if provider.startswith('gluetun-') else 'native'
    checks = {'peer': {'state': 'pass', 'at': at(), 'server': server},
              'handshake': {'state': 'pass', 'at': at(), 'server': server, 'age_s': 12},
              'egress': {'state': 'pass', 'at': at(), 'server': server, 'tier': tier,
                         'expected_families': list(families), 'families': {f: 'pass' for f in families}}}
    if kind == 'overlay':
        checks.update(routing={'state': 'pass', 'at': at(), 'fallback': True},
                      netbird={'state': 'pass', 'at': at()},
                      traffic_protection={'state': 'pass', 'at': at(), 'from': 'routing'},
                      app_attachment={'state': 'n/a'})
        checks['owner_record'] = {'state': 'pass', 'at': at()} if backend == 'native' else {'state': 'n/a'}
    else:
        checks.update(routing={'state': 'n/a'}, netbird={'state': 'n/a'}, owner_record={'state': 'n/a'},
                      traffic_protection={'state': 'not-checked', 'by': "gluetun's firewall"},
                      app_attachment={'state': 'not-checked', 'by': 'the host doctor'})
    result = {'schema': 2, 'kind': kind, 'backend': backend, 'provider': provider, 'status': 'ok',
              'message': 'Healthy.', 'checked_at': at(), 'server': server, 'requested_server': server,
              'configured_server': None, 'request_id': REQUEST['request_id'],
              'selection': {'source': 'panel', 'outcome': 'verified', 'attempt': 1, 'target': server,
                            'next_action': None, 'next_action_at': None},
              'checks': checks, 'egress_ip': '203.0.113.7',
              'egress_ips': {f: '203.0.113.7' if f == '4' else '2001:db8::7' for f in families}}
    for key, value in changes.items():
        result[key] = value
    return result


def panel(result, desired=None, provider='mullvad', kind='overlay'):
    desired = REQUEST if desired is None else desired
    return assess(ExitConfig(provider, kind), result, Target.for_panel(result, desired, provider), NOW)


def with_check(result, name, **fields):
    result['checks'][name] = {**result['checks'][name], **fields}
    return result


# -- schema 2 ------------------------------------------------------------------

def test_a_healthy_record_is_connected_for_every_kind():
    verdict = panel(record())
    assert (verdict.state, verdict.label, verdict.tier, verdict.schema) == ('ok', 'connected', 'provider', 2)
    assert verdict.checks['owner_record'] == 'pass' and verdict.checks['app_attachment'] == 'n/a'
    sidecar = record('sidecar', 'gluetun-nordvpn', GLUETUN_HOST, families=('4',))
    verdict = panel(sidecar, dict(REQUEST, server=GLUETUN_HOST), 'gluetun-nordvpn', 'sidecar')
    assert verdict.state == 'ok'
    assert verdict.checks['traffic_protection'] == 'not-checked' and verdict.checks['routing'] == 'n/a'


@pytest.mark.parametrize('schema', [1, 3, '2', None, 2.0])
def test_unknown_or_newer_versions_are_never_connected(schema):
    assert panel(record(schema=schema)).label == 'unsupported status version'


@pytest.mark.parametrize('change,label', [
    ({'kind': 'sidecar'}, 'kind mismatch'), ({'kind': None}, 'kind mismatch'),
    ({'provider': 'pia'}, 'provider mismatch'), ({'provider': None}, 'provider mismatch'),
    ({'backend': 'gluetun'}, 'provider mismatch'), ({'backend': None}, 'provider mismatch'),
])
def test_kind_provider_and_backend_are_never_defaulted(change, label):
    result = record()
    result.update(change)
    verdict = panel(result)
    assert verdict.state == 'unknown' and verdict.label == label


def test_a_sidecar_reader_refuses_an_overlay_record_and_a_native_provider():
    assert panel(record(), provider='mullvad', kind='overlay').state == 'ok'
    with pytest.raises(ValueError):
        ExitConfig('mullvad', 'sidecar')
    overlay = record(provider='gluetun-nordvpn', server=GLUETUN_HOST)
    assert panel(overlay, dict(REQUEST, server=GLUETUN_HOST), 'gluetun-nordvpn', 'sidecar').label == 'kind mismatch'


@pytest.mark.parametrize('checked', [at(151), at(-10), 'broken', None, '2026-10-11T12:00:00'])
def test_a_stale_future_or_malformed_envelope_is_unknown(checked):
    verdict = panel(record(checked_at=checked))
    assert (verdict.state, verdict.label) == ('unknown', 'status stale')


def test_request_acknowledgement():
    newer = dict(REQUEST, request_id='b' * 32)
    assert panel(record(), newer).state == 'applying'
    assert panel(record(), dict(newer, requested_at=at(151))).label == 'request not acknowledged'


def test_applying_is_switching():
    assert panel(record(status='applying')).state == 'applying'


@pytest.mark.parametrize('name', ['routing', 'netbird', 'owner_record', 'peer', 'handshake', 'egress',
                                  'traffic_protection'])
def test_a_missing_or_waived_required_check_is_an_invalid_record(name):
    broken = record()
    del broken['checks'][name]
    assert panel(broken).label == 'invalid status record'
    waived = record()
    waived['checks'][name] = {'state': 'n/a'}
    assert panel(waived).label == 'invalid status record'


def test_traffic_protection_is_the_routing_contract_itself():
    assert panel(with_check(record(), 'traffic_protection', **{'from': 'gluetun'})).label == 'invalid status record'


# Evidence rules ---------------------------------------------------------------

@pytest.mark.parametrize('name', ['routing', 'peer', 'handshake', 'egress'])
@pytest.mark.parametrize('when', [at(151), at(-30), None, 'yesterday'])
def test_expired_future_or_missing_evidence_is_unknown_not_failed(name, when):
    verdict = panel(with_check(record(), name, at=when))
    assert (verdict.state, verdict.label) == ('unknown', 'evidence expired')
    assert verdict.checks[name] == 'unknown'


def test_a_slow_inspection_yields_expired_evidence_not_extended_evidence():
    """A fresh envelope whose early measurements aged out while egress probes
    ran (routing measured first) is unknown, never ok and never failed."""
    slow = record()
    for name in ('routing', 'netbird', 'owner_record', 'traffic_protection', 'peer', 'handshake'):
        slow['checks'][name]['at'] = at(160)
    verdict = panel(slow)
    assert (verdict.state, verdict.label) == ('unknown', 'evidence expired')


@pytest.mark.parametrize('name', ['peer', 'handshake', 'egress'])
def test_a_pass_for_a_previous_selection_never_counts(name):
    verdict = panel(with_check(record(), name, server=OTHER))
    assert verdict.state == 'unknown' and verdict.checks[name] == 'unknown'


@pytest.mark.parametrize('age', [180, 500, None, -1, '12', 12.5, True])
def test_handshake_types_are_strict(age):
    assert panel(with_check(record(), 'handshake', age_s=age)).label == 'invalid status record'


def test_a_failed_handshake_may_be_stale_or_never_completed():
    for age in (180, 10_000, None):
        verdict = panel(with_check(record(status='failed'), 'handshake', state='fail', age_s=age))
        assert verdict.state == 'failed' and 'handshake-failed' in verdict.reasons


@pytest.mark.parametrize('egress', [
    {'families': {'4': 'pass'}},  # an expected family missing
    {'families': {'4': 'pass', '6': 'fail'}},
    {'families': {'4': 'pass', '5': 'pass'}},
    {'expected_families': []},
    {'expected_families': ['4', '4']},
    {'families': {'4': 'yes', '6': 'pass'}},
    {'tier': 'gold'},
    {'tier': None},
])
def test_egress_families_and_tier_are_strict(egress):
    assert panel(with_check(record(), 'egress', **egress)).label == 'invalid status record'


def test_egress_ips_must_cover_exactly_the_passing_families():
    assert panel(record(egress_ips={'4': '203.0.113.7'})).label == 'invalid status record'
    assert panel(record(egress_ips={'4': '203.0.113.7', '6': '2001:db8::7', '5': 'x'})).label == 'invalid status record'


def test_the_tunnel_tier_counts_only_where_the_provider_has_no_stronger_check():
    assert panel(record(tier='tunnel')).label == 'invalid status record'
    ivpn = record(provider='gluetun-ivpn', server=GLUETUN_HOST, tier='tunnel', families=('4',))
    assert panel(ivpn, dict(REQUEST, server=GLUETUN_HOST), 'gluetun-ivpn').tier == 'tunnel'
    sidecar = record('sidecar', 'gluetun-ivpn', GLUETUN_HOST, tier='tunnel', families=('4',))
    assert panel(sidecar, dict(REQUEST, server=GLUETUN_HOST), 'gluetun-ivpn', 'sidecar').label == \
        'invalid status record'


# Verdict order ------------------------------------------------------------------

def test_a_fresh_failure_wins_over_what_wasnt_measured():
    """Inspection stops at a routing failure without measuring egress."""
    stopped = record(status='failed', message='Routing protection is incomplete; run the recovery helper.')
    stopped['checks']['routing'] = {'state': 'fail', 'at': at(), 'fallback': True}
    stopped['checks']['traffic_protection'] = {'state': 'fail', 'at': at(), 'from': 'routing'}
    stopped['checks']['egress'] = {'state': 'unknown'}
    verdict = panel(stopped)
    assert verdict.state == 'failed' and 'routing-failed' in verdict.reasons
    assert verdict.message.startswith('Routing protection') and verdict.checks['egress'] == 'unknown'


def test_a_fresh_failure_wins_over_expired_evidence():
    mixed = with_check(record(status='failed'), 'peer', at=at(400))
    mixed['checks']['egress'] = {**mixed['checks']['egress'], 'state': 'fail', 'reason': 'not-confirmed'}
    assert panel(mixed).state == 'failed'


def test_a_rejection_is_failed_whatever_was_measured():
    rejected = record(status='failed', message='Requested server is not in a fresh trusted relay catalogue.')
    rejected['selection'] = {**rejected['selection'], 'outcome': 'rejected'}
    for name in ('peer', 'handshake', 'egress'):
        rejected['checks'][name] = {'state': 'unknown'}
    verdict = panel(rejected)
    assert verdict.state == 'failed' and 'rejected' in verdict.reasons


def test_not_yet_measured_only_when_nothing_failed():
    starting = record(status='unknown')
    for name in ('peer', 'handshake', 'egress'):
        starting['checks'][name] = {'state': 'unknown'}
    assert panel(starting).label == 'not yet measured'
    pending = record(status='failed', message='Waiting for a fresh trusted relay catalogue.')
    for name in ('peer', 'handshake', 'egress'):
        pending['checks'][name] = {'state': 'unknown'}
    assert panel(pending).state == 'failed'


def test_next_action_passes_through():
    unverified = record(status='failed')
    unverified['checks']['egress'] = {**unverified['checks']['egress'], 'state': 'fail', 'tier': None,
                                      'reason': 'unanswered', 'families': {}}
    unverified['egress_ips'] = {}
    unverified['selection'] = {**unverified['selection'], 'outcome': 'applied-unverified',
                               'next_action': 'recheck', 'next_action_at': at(-60)}
    verdict = panel(unverified)
    assert verdict.state == 'failed' and verdict.next_action == 'recheck' and verdict.next_action_at == at(-60)


def test_a_tunnel_tier_sidecar_is_switched_never_connected():
    sidecar = record('sidecar', 'gluetun-ivpn', GLUETUN_HOST, families=('4',), status='failed',
                     message="Switched; the egress couldn't be compared with this host's address.")
    sidecar['checks']['egress'] = {'state': 'fail', 'at': at(), 'server': GLUETUN_HOST, 'tier': None,
                                   'reason': 'host-address-not-measurable', 'expected_families': ['4'],
                                   'families': {'4': 'unknown'}}
    sidecar['egress_ips'] = {}
    sidecar['selection'] = {**sidecar['selection'], 'outcome': 'applied-unverified'}
    verdict = panel(sidecar, dict(REQUEST, server=GLUETUN_HOST), 'gluetun-ivpn', 'sidecar')
    assert verdict.state == 'unknown' and verdict.label == 'switched, egress unverified'
    assert verdict.message.startswith('Switched')
    assert verdict.checks['traffic_protection'] == 'not-checked'


# Target agreement, for every source --------------------------------------------

def test_target_agreement_for_a_panel_request():
    assert panel(record(server=OTHER, requested_server=HOST)).reasons == ('not-requested-server',)
    assert panel(record(requested_server=OTHER)).reasons == ('not-requested-server',)


def test_target_agreement_for_the_configured_server():
    configured = record(configured_server=HOST, request_id=None)
    assert panel(configured).state == 'ok'
    verdict = panel(record(configured_server=HOST, server=OTHER, request_id=None))
    assert verdict.state == 'failed' and verdict.reasons == ('not-configured-server',)


def test_the_local_server_setting_is_authoritative():
    """The applier and the doctor judge against their own SERVER, whatever
    the record says."""
    omitted = record(configured_server=None)
    assert assess(ExitConfig('mullvad'), omitted, Target(HOST, 'configured'), NOW).state == 'ok'
    misreported = record(configured_server=OTHER)
    assert assess(ExitConfig('mullvad'), misreported, Target(HOST, 'configured'), NOW).state == 'ok'
    assert assess(ExitConfig('mullvad'), record(server=OTHER, requested_server=OTHER,
                                                selection={'source': 'configured', 'target': OTHER}),
                  Target(HOST, 'configured'), NOW).state == 'failed'


@pytest.mark.parametrize('source', ['restore', 'reconverge', 'retry', 'operator-retry'])
def test_target_agreement_for_the_resolved_target(source):
    selection = {'source': source, 'outcome': 'verified', 'target': HOST}
    assert assess(ExitConfig('mullvad'), record(selection=selection), Target(HOST, 'restore'), NOW).state == 'ok'
    assert assess(ExitConfig('mullvad'), record(selection=selection), Target(OTHER, 'restore'), NOW).state == 'failed'
    # A reader without a target of its own holds the record to itself.
    assert panel(record(selection=selection), {}).state == 'ok'
    assert panel(record(selection={**selection, 'target': OTHER}), {}).state == 'failed'


def test_a_seed_without_any_selection_may_be_connected():
    verdict = panel(record(selection={'source': 'seed', 'outcome': None}, request_id=None,
                           requested_server=None), {})
    assert verdict.state == 'ok' and verdict.reasons == ('no-selection',)


# Legacy (0.6) records ------------------------------------------------------------

def legacy(**changes):
    return {'status': 'ok', 'checked_at': at(), 'server': HOST, 'requested_server': HOST,
            'request_id': REQUEST['request_id'], 'routing_ok': True, 'netbird_native': True,
            'exit_confirmed': True, 'egress_tier': 'provider', 'provider': 'mullvad', **changes}


@pytest.mark.parametrize('changes,state', [
    ({}, 'ok'),
    ({'status': 'failed'}, 'failed'),
    ({'status': 'applying'}, 'applying'),
    ({'status': 'weird'}, 'unknown'),
    ({'routing_ok': False}, 'failed'),
    ({'routing_ok': None}, 'failed'),
    ({'netbird_native': False}, 'failed'),
    ({'netbird_native': None}, 'failed'),
    ({'exit_confirmed': False}, 'failed'),
    # Results written before the NetBird check and before exit_confirmed.
    ({'netbird_native': '__absent__'}, 'ok'),
    ({'exit_confirmed': '__absent__', 'mullvad_exit_ip': True}, 'ok'),
    # An explicit false confirmation overrides a historical true field.
    ({'exit_confirmed': False, 'mullvad_exit_ip': True}, 'failed'),
    ({'provider': '__absent__'}, 'ok'),
    ({'provider': 'pia'}, 'unknown'),
    ({'server': OTHER}, 'failed'),
    ({'checked_at': at(151)}, 'unknown'),
])
def test_the_legacy_truth_table(changes, state):
    result = legacy(**changes)
    for key, value in changes.items():
        if value == '__absent__':
            del result[key]
    verdict = panel(result)
    assert verdict.state == state
    assert verdict.schema == 1 or state == 'unknown'
    if verdict.checks:
        # Never shown as passed: not reported individually.
        assert verdict.checks['routing'] == 'legacy'


def test_a_legacy_tunnel_tier_counts_only_for_a_tunnel_tier_provider():
    result = legacy(exit_confirmed=False, egress_tier='tunnel', provider='gluetun-ivpn', server=GLUETUN_HOST,
                    requested_server=GLUETUN_HOST)
    assert panel(result, dict(REQUEST, server=GLUETUN_HOST), 'gluetun-ivpn').state == 'ok'
    assert panel(legacy(exit_confirmed=False, egress_tier='tunnel')).state == 'failed'


def test_a_legacy_record_under_a_sidecar_is_a_mismatch():
    result = legacy(provider='gluetun-nordvpn', server=GLUETUN_HOST, requested_server=GLUETUN_HOST)
    assert panel(result, dict(REQUEST, server=GLUETUN_HOST), 'gluetun-nordvpn', 'sidecar').label == 'kind mismatch'


def test_a_configured_lock_holds_when_the_record_is_stale():
    verdict = panel(record(configured_server=HOST, checked_at=at(3600)))
    assert verdict.state == 'unknown' and verdict.configured_server == HOST


def test_nothing_readable_is_awaiting_status():
    for result in (None, [], 'ok', 3):
        assert panel(result).label == 'awaiting status'


# The deprecated 0.6 projection ---------------------------------------------------

def test_the_projection_derives_the_old_fields_from_the_verdict():
    result = record()
    projection = legacy_projection(result, panel(result))
    assert projection == {'routing_ok': True, 'netbird_native': True, 'exit_confirmed': True, 'egress_tier': None,
                          'handshake_age_s': 12, 'unreachable_fallback': True}
    sidecar = record('sidecar', 'gluetun-nordvpn', GLUETUN_HOST, families=('4',))
    verdict = panel(sidecar, dict(REQUEST, server=GLUETUN_HOST), 'gluetun-nordvpn', 'sidecar')
    projection = legacy_projection(sidecar, verdict)
    assert projection['routing_ok'] is None and projection['netbird_native'] is None
    assert projection['unreachable_fallback'] is None and projection['exit_confirmed'] is True
    assert legacy_projection(legacy(), panel(legacy())) == {}


def test_the_request_token_is_the_acknowledgement():
    assert record()['request_id'] == request_token(REQUEST)
