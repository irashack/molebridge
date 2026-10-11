"""The admission pipeline and its persisted attempt (applier/apply.py,
applier/attempt.py), against the fake kernel of test_runtime.py. Nothing
touches a live tunnel."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from applier.apply import Applier
from applier.attempt import BACKOFF_SEC, REAPPLY_GUARD_SEC, UNIDENTIFIED_SEC, Attempt
from molebridge.state import now_iso, read_json, write_json_atomic
from test_runtime import CONFIG, ENTRY, HOST, KEY, Kernel, live_owner, request

OTHER_HOST, OTHER_KEY = 'se-sto-wg-002', 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
OTHER = {**ENTRY, 'hostname': OTHER_HOST, 'public_key': OTHER_KEY}
BOOT = '00000000-0000-4000-8000-0000000000aa'


def build(tmp_path, kernel, *, boot=BOOT, server=''):
    write_json_atomic(tmp_path / 'applier' / 'relays.json',
                      {'fetched_at': now_iso(), 'relays': {HOST: ENTRY, OTHER_HOST: OTHER}})
    app = Applier(tmp_path, CONFIG, run=kernel.run, clock=lambda: kernel.now, sleep=kernel.sleep,
                  boot_id=boot, server=server)
    app.next_catalog = float('inf')
    return app


@pytest.fixture
def setup(tmp_path):
    kernel = Kernel()
    kernel.keys = [OTHER_KEY]  # live on the other server: a switch is needed
    return build(tmp_path, kernel), kernel, tmp_path


def adds(kernel):
    return [c for c in kernel.mutations if c[-1] != 'remove']


def saved(tmp_path):
    return read_json(tmp_path / 'applier' / 'attempt.json')


# The attempt record ------------------------------------------------------------

def test_the_attempt_is_written_before_any_mutation_io(setup):
    app, kernel, tmp_path = setup
    seen = []
    real = app.apply_relay

    def apply(relay, keys):
        seen.append(saved(tmp_path))
        return real(relay, keys)
    app.apply_relay = apply
    write_json_atomic(app.desired_path, request())
    assert app.tick()['status'] == 'ok'
    assert seen[0]['state'] == 'attempting' and seen[0]['target'] == HOST and seen[0]['attempts'] == 1
    assert seen[0]['mutation_certainty'] == 'uncertain' and seen[0]['boot_id'] == BOOT
    after = saved(tmp_path)
    assert after['state'] == 'idle' and after['outcome'] == 'verified' and after['backoff_step'] == 0


def test_the_published_selection_says_why_and_how(setup):
    app, kernel, _ = setup
    write_json_atomic(app.desired_path, request())
    result = app.tick()
    assert result['schema'] == 2 and result['kind'] == 'overlay' and result['backend'] == 'native'
    assert result['selection'] == {'source': 'panel', 'outcome': 'verified', 'attempt': 1, 'target': HOST,
                                   'next_action': None, 'next_action_at': None}


# Crash at every boundary ------------------------------------------------------------

def restart(tmp_path, kernel, *, boot=BOOT):
    app = build(tmp_path, kernel, boot=boot)
    return app


def interrupted(tmp_path, kernel, *, live_after):
    """An attempt persisted as `attempting`, as a crash leaves it."""
    attempt = Attempt.new(source='panel', target=HOST, target_key='0' * 32, boot_id=BOOT)
    attempt.state, attempt.attempts, attempt.last_mutation_at = 'attempting', 1, kernel.now
    attempt.mutation_certainty = 'uncertain'
    attempt.save(tmp_path / 'applier' / 'attempt.json')
    kernel.keys = [KEY] if live_after else [OTHER_KEY]


def test_a_crash_before_the_record_starts_afresh(setup):
    app, kernel, tmp_path = setup
    write_json_atomic(app.desired_path, request())
    app = restart(tmp_path, kernel)
    assert app.tick()['status'] == 'ok' and len(adds(kernel)) == 1


def test_a_crash_after_the_record_before_the_io_is_inspected_not_replayed(setup):
    app, kernel, tmp_path = setup
    write_json_atomic(app.desired_path, request())
    interrupted(tmp_path, kernel, live_after=False)
    app = restart(tmp_path, kernel)
    result = app.tick()
    assert not adds(kernel)
    assert result['status'] == 'failed' and app.attempt.state == 'failed'
    assert app.attempt.mutation_certainty == 'uncertain' and app.attempt.next_action == 'reapply'
    kernel.now += BACKOFF_SEC[0] - 1
    app.tick()
    assert not adds(kernel)
    kernel.now += 1
    assert app.tick()['status'] == 'ok' and len(adds(kernel)) == 1


@pytest.mark.parametrize('boundary', ['after the io', 'after the response'])
def test_a_crash_after_the_mutation_took_effect_verifies_without_a_second(setup, boundary):
    app, kernel, tmp_path = setup
    write_json_atomic(app.desired_path, request())
    interrupted(tmp_path, kernel, live_after=True)
    app = restart(tmp_path, kernel)
    result = app.tick()
    assert result['status'] == 'ok' and app.attempt.state == 'idle' and not adds(kernel)


def test_a_crash_with_the_target_live_but_unverified_rechecks(setup):
    app, kernel, tmp_path = setup
    write_json_atomic(app.desired_path, request())
    interrupted(tmp_path, kernel, live_after=True)
    kernel.egress_ok = False
    app = restart(tmp_path, kernel)
    result = app.tick()
    assert app.attempt.state == 'unverified' and result['selection']['next_action'] == 'recheck'
    for _ in range(10):
        kernel.now += 60
        app.tick()
    assert not adds(kernel)


@pytest.mark.parametrize('state', ['unverified', 'failed', 'pending', 'rejected'])
def test_resting_states_survive_a_restart(setup, state):
    app, kernel, tmp_path = setup
    write_json_atomic(app.desired_path, request())
    attempt = Attempt.new(source='panel', target=HOST, target_key='0' * 32, boot_id=BOOT)
    attempt.state = state
    attempt.message = 'Example.'
    if state == 'failed':
        attempt.next_action, attempt.next_action_at, attempt.backoff_step = 'reapply', 500, 2
    if state == 'rejected':
        attempt.extra = {'why': 'invalid', 'release': 'invalid'}
    attempt.save(tmp_path / 'applier' / 'attempt.json')
    app = restart(tmp_path, kernel)
    assert app.attempt.state == state
    app.tick()
    assert app.attempt.target == HOST
    if state == 'failed':
        # Nothing before its deadline, which survived the restart.
        assert not adds(kernel) and app.attempt.next_action_at == 500
    if state == 'rejected':
        assert not adds(kernel)


def test_deadlines_from_another_boot_are_rebased(tmp_path):
    kernel = Kernel()
    path = tmp_path / 'applier' / 'attempt.json'
    attempt = Attempt.new(source='panel', target=HOST, target_key='0' * 32, boot_id='old-boot')
    attempt.state, attempt.next_action, attempt.next_action_at, attempt.backoff_step = 'failed', 'reapply', 9e9, 3
    attempt.last_mutation_at = 9e9
    attempt.save(path)
    kernel.now = 100
    loaded = Attempt.load(path, boot_id=BOOT, now=kernel.now)
    assert loaded.next_action_at == 100 + BACKOFF_SEC[3] and loaded.last_mutation_at is None
    attempt.next_action, attempt.next_action_at = 'recheck', 9e9
    attempt.save(path)
    assert Attempt.load(path, boot_id=BOOT, now=kernel.now).next_action_at == 100


@pytest.mark.parametrize('content', ['{broken', '[]', json.dumps({'state': 'exploded'}),
                                     json.dumps({'state': 'failed', 'backoff_step': -1})])
def test_an_unreadable_attempt_starts_idle(tmp_path, content):
    path = tmp_path / 'applier' / 'attempt.json'
    path.parent.mkdir(parents=True)
    path.write_text(content)
    assert Attempt.load(path, boot_id=BOOT, now=0).state == 'idle'


# Lost responses ---------------------------------------------------------------------

def test_a_lost_response_recovers_without_a_second_mutation(setup):
    app, kernel, tmp_path = setup
    real = app.apply_relay

    def applied_then_lost(relay, keys):
        real(relay, keys)
        raise RuntimeError('response lost')
    app.apply_relay = applied_then_lost
    write_json_atomic(app.desired_path, request())
    result = app.tick()
    # The check right after finds the target live and verified.
    assert result['status'] == 'ok' and app.attempt.state == 'idle' and len(adds(kernel)) == 1


def test_a_lost_response_after_failed_was_persisted(setup):
    app, kernel, tmp_path = setup
    real = app.apply_relay
    egress = []

    def applied_then_lost(relay, keys):
        real(relay, keys)
        kernel.egress_ok = False  # not verifiable at once
        egress.append(1)
        raise RuntimeError('response lost')
    app.apply_relay = applied_then_lost
    write_json_atomic(app.desired_path, request())
    app.tick()
    assert app.attempt.state == 'failed' and saved(tmp_path)['state'] == 'failed'
    # A restart, then the egress answers: verified, nothing applied again.
    app = restart(tmp_path, kernel)
    app.apply_relay = applied_then_lost
    kernel.egress_ok = True
    kernel.now += BACKOFF_SEC[0]
    assert app.tick()['status'] == 'ok' and len(egress) == 1 and app.attempt.state == 'idle'


# Triggers ---------------------------------------------------------------------------

def test_drift_within_the_guard_waits(setup):
    app, kernel, _ = setup
    write_json_atomic(app.desired_path, request())
    app.tick()
    kernel.keys = [OTHER_KEY]  # something put the other server back
    kernel.now += REAPPLY_GUARD_SEC - 10
    app.tick()
    assert len(adds(kernel)) == 1
    kernel.now += 10
    result = app.tick()
    assert len(adds(kernel)) == 2 and result['selection']['source'] == 'reconverge'


def test_a_mullvad_request_reconverges_after_tunnel_recreation(setup):
    """A recreated tunnel starts with its config's peer."""
    app, kernel, _ = setup
    write_json_atomic(app.desired_path, request())
    app.tick()
    kernel.now += 600
    kernel.keys = [OTHER_KEY]
    result = app.tick()
    assert result['status'] == 'ok' and kernel.keys == [KEY] and len(adds(kernel)) == 2


def test_an_unidentifiable_peer_is_waited_out(setup):
    app, kernel, _ = setup
    write_json_atomic(app.desired_path, request())
    app.tick()
    kernel.now += 600
    kernel.keys = ['AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=']
    app.tick()
    kernel.now += UNIDENTIFIED_SEC - 1
    app.tick()
    assert len(adds(kernel)) == 1
    # Identifiable again (the right one): the timer resets.
    kernel.keys = [KEY]
    app.tick()
    kernel.keys = ['AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=']
    kernel.now += 1
    app.tick()
    assert len(adds(kernel)) == 1
    kernel.now += UNIDENTIFIED_SEC
    app.tick()
    assert len(adds(kernel)) == 2 and kernel.keys == [KEY]


def test_a_new_owner_generation_reapplies_once_at_once(tmp_path, monkeypatch):
    kernel = Kernel()
    kernel.keys = []
    app = build(tmp_path, kernel)
    live_owner(tmp_path, monkeypatch, generation='0a0a')
    app.owner_path = tmp_path / 'owner'
    write_json_atomic(app.desired_path, request())
    assert app.tick()['status'] == 'ok' and len(adds(kernel)) == 1
    # The wireguard container started again: no peer, new generation.
    kernel.now += REAPPLY_GUARD_SEC
    kernel.keys = []
    live_owner(tmp_path, monkeypatch, generation='0b0b')
    app.owner_seen = None
    assert app.tick()['status'] == 'ok' and len(adds(kernel)) == 2
    # A failure backing off: no peer in the same generation waits for the
    # backoff; a new generation is re-applied once at once.
    kernel.now += REAPPLY_GUARD_SEC
    kernel.fail_set = True
    kernel.keys = [OTHER_KEY]
    write_json_atomic(app.desired_path, request(request_id='9' * 32))
    app.tick()
    assert app.attempt.state == 'failed'
    kernel.fail_set = False
    kernel.keys = []
    app.attempt.next_action_at = kernel.now + 900  # a late backoff step
    kernel.now += REAPPLY_GUARD_SEC
    app.tick()
    assert app.attempt.state == 'failed'
    live_owner(tmp_path, monkeypatch, generation='0c0c')
    app.owner_seen = None
    assert app.tick()['status'] == 'ok' and app.attempt.state == 'idle'


def test_a_new_owner_generation_still_respects_the_guard(tmp_path, monkeypatch):
    kernel = Kernel()
    kernel.keys = []
    app = build(tmp_path, kernel)
    live_owner(tmp_path, monkeypatch, generation='0a0a')
    app.owner_path = tmp_path / 'owner'
    write_json_atomic(app.desired_path, request())
    app.tick()
    kernel.keys = []
    live_owner(tmp_path, monkeypatch, generation='0b0b')
    app.owner_seen = None
    kernel.now += 10
    app.tick()
    assert len(adds(kernel)) == 1


def test_no_native_peer_while_idle_is_applied_at_once(setup):
    """The exit's routing loop recreated a lost tunnel from its config,
    which (NordVPN, PIA) has no peer."""
    app, kernel, _ = setup
    write_json_atomic(app.desired_path, request())
    app.tick()
    kernel.now += REAPPLY_GUARD_SEC
    kernel.keys = []
    assert app.tick()['status'] == 'ok' and kernel.keys == [KEY] and len(adds(kernel)) == 2


def test_no_peer_after_a_failed_mutation_waits_for_the_backoff(setup):
    """A NordVPN-style replacement interrupted after the old peer went."""
    app, kernel, _ = setup
    kernel.fail_set = True
    write_json_atomic(app.desired_path, request())
    app.tick()
    kernel.keys = []
    kernel.fail_set = False
    for _ in range(5):
        kernel.now += 10
        app.tick()
    assert not adds(kernel)
    kernel.now += BACKOFF_SEC[0]
    app.tick()
    assert len(adds(kernel)) == 1 and app.attempt.state == 'idle'


def test_the_backoff_steps(setup):
    app, kernel, _ = setup
    kernel.fail_set = True
    write_json_atomic(app.desired_path, request())
    app.tick()
    times = []
    start = kernel.now
    while len(times) < 6:
        kernel.now += 5
        before = app.attempt.attempts
        app.tick()
        if app.attempt.attempts > before:
            times.append(kernel.now - start)
            start = kernel.now
    assert times == [60, 120, 240, 480, 900, 900]


def test_a_new_target_cancels_the_backoff(setup):
    app, kernel, _ = setup
    kernel.fail_set = True
    write_json_atomic(app.desired_path, request())
    app.tick()
    assert app.attempt.next_action == 'reapply'
    kernel.fail_set = False
    write_json_atomic(app.desired_path, request(server=OTHER_HOST, request_id='1' * 32))
    kernel.keys = [KEY]
    result = app.tick()
    assert result['status'] == 'ok' and result['server'] == OTHER_HOST
    assert app.attempt.backoff_step == 0 and app.attempt.source == 'panel'


def test_retry_now_is_a_new_request_id(setup):
    app, kernel, _ = setup
    kernel.fail_set = True
    write_json_atomic(app.desired_path, request())
    app.tick()
    kernel.fail_set = False
    write_json_atomic(app.desired_path, request(request_id='2' * 32))
    result = app.tick()
    assert result['status'] == 'ok' and result['selection']['source'] == 'operator-retry'


def test_an_old_request_is_inspected_first_a_fresh_one_applied(setup):
    """An upgrade from 0.6 finds desired.json without an attempt: the server
    already live isn't touched. A request made now is applied."""
    app, kernel, _ = setup
    kernel.keys = [KEY]
    write_json_atomic(app.desired_path, request(requested_at='2026-01-01T00:00:00Z'))
    assert app.tick()['status'] == 'ok' and not adds(kernel)
    write_json_atomic(app.desired_path, request(request_id='3' * 32))
    assert app.tick()['status'] == 'ok' and len(adds(kernel)) == 1


def test_native_aborts_when_netbird_is_lost_during_a_switch(setup):
    app, kernel, _ = setup
    run = kernel.run

    def lose_netbird(args, **kwargs):
        result = run(args, **kwargs)
        if args[:2] == ['wg', 'set']:
            kernel.overlay_kind = 'tun'
        return result
    app.run = lose_netbird
    write_json_atomic(app.desired_path, request())
    result = app.tick()
    assert result['status'] == 'failed' and app.attempt.state == 'failed'
    assert result['selection']['outcome'] == 'mutation-failed' and kernel.now < 10


def test_native_aborts_when_the_owner_record_is_lost_during_a_switch(tmp_path, monkeypatch):
    kernel = Kernel()
    kernel.keys = [OTHER_KEY]
    app = build(tmp_path, kernel)
    live_owner(tmp_path, monkeypatch)
    app.owner_path = tmp_path / 'owner'
    run = kernel.run

    def lose_owner(args, **kwargs):
        result = run(args, **kwargs)
        if args[:2] == ['wg', 'set'] and args[-1] != 'remove':
            (tmp_path / 'owner').write_text('')
        return result
    app.run = lose_owner
    write_json_atomic(app.desired_path, request())
    result = app.tick()
    assert result['status'] == 'failed' and result['checks']['owner_record']['state'] == 'fail'
    assert app.attempt.state == 'failed'


# Gatus ---------------------------------------------------------------------------------

def gatus(app, monkeypatch):
    pushed = []
    monkeypatch.setenv('GATUS_URL', 'https://gatus.example.test')
    monkeypatch.setenv('GATUS_TOKEN', 'token')
    real = app.run

    def run(args, **kwargs):
        if args[0] == 'curl' and '/external?' in args[-1]:
            pushed.append(args[-1].split('?', 1)[1])
            return ''
        return real(args, **kwargs)
    app.run = run
    return pushed


def test_gatus_gets_the_verdict_and_never_applying(setup, monkeypatch):
    app, kernel, _ = setup
    pushed = gatus(app, monkeypatch)
    write_json_atomic(app.desired_path, request())
    app.tick()
    assert pushed == ['success=true&error=']
    kernel.egress_ok = False
    kernel.now += 60
    app.tick()
    assert pushed[-1].startswith('success=false&error=')


def test_a_request_arriving_during_verification_is_not_judged_by_the_old_one(setup, monkeypatch):
    app, kernel, _ = setup
    pushed = gatus(app, monkeypatch)
    real = app.apply_relay

    def apply(relay, keys):
        real(relay, keys)
        write_json_atomic(app.desired_path, request(server=OTHER_HOST, request_id='4' * 32))
    app.apply_relay = apply
    write_json_atomic(app.desired_path, request())
    app.tick()
    # Verified, but the operator has already asked for another server.
    assert pushed == []


def test_the_overlay_health_check_leaves_a_missing_peer_to_the_pipeline(setup):
    """A lost tunnel comes back without its peer; killing the applier for
    that (HealthOnFailure=kill on the homelab) would only delay the repair."""
    app, kernel, _ = setup
    write_json_atomic(app.desired_path, request())
    app.tick()
    kernel.keys = []
    assert app.healthy()
    kernel.tunnel_present = False
    with pytest.raises(RuntimeError):
        app.healthy()
