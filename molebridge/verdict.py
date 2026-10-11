"""One judgment of an exit's status record, for every reader.

The applier writes state/applier/result.json (schema 2, below). The panel's
page, its API, the exit tabs, the browser, /readyz, the Gatus push and the
doctor all judge it here, with `assess`, so they agree. The container health
check is operational and stays separate (applier/apply.py, --healthcheck).

Schema 2 states every check explicitly (CHECK_STATES) and says which exit kind
wrote it: `overlay` (a NetBird exit, native or gluetun backend) or `sidecar`
(an ordinary gluetun other containers share). Records written before schema 2
(0.6 and earlier) are read as overlay records (`_legacy`). Any other schema
is never connected.

Only a fresh `pass` counts as passed. Every measured check carries its own
`at`, and `peer`, `handshake` and `egress` carry the `server` they measured,
which must be the record's server: evidence never carries across a change of
server, and a slow inspection's early measurements can age out even when the
record itself is fresh.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple

from molebridge import providers

SCHEMA = 2
KINDS = ('overlay', 'sidecar')
CHECK_STATES = ('pass', 'fail', 'unknown', 'n/a', 'not-checked')
CHECKS = ('routing', 'netbird', 'owner_record', 'peer', 'handshake', 'egress', 'traffic_protection',
          'app_attachment')
SOURCES = ('configured', 'panel', 'restore', 'reconverge', 'retry', 'operator-retry', 'seed', 'failover')
OUTCOMES = ('verified', 'applied-unverified', 'pending', 'rejected', 'mutation-failed')
NEXT_ACTIONS = ('recheck', 'reapply')
# A record, and each measured check in it, counts for this long (seconds).
EVIDENCE_MAX_AGE = 150
# A handshake this old or older is stale (applier/apply.py).
HANDSHAKE_FRESH_SEC = 180
# Checks bound to the selection they measured.
SERVER_BOUND = ('peer', 'handshake', 'egress')
FAMILIES = ('4', '6')

# Who performs a check Molebridge doesn't, by kind.
NOT_CHECKED_BY = {'traffic_protection': "gluetun's firewall", 'app_attachment': 'the host doctor'}


def backend_of(provider: str) -> str:
    """'gluetun' or 'native', from the provider registry."""
    spec = providers.REGISTRY.get(provider)
    return 'gluetun' if spec is not None and spec.backend == 'gluetun' else 'native'


def required_checks(kind: str, backend: str) -> Tuple[str, ...]:
    """The checks that must pass for this kind and backend."""
    if kind == 'sidecar':
        return ('peer', 'handshake', 'egress')
    checks = ('routing', 'netbird', 'peer', 'handshake', 'egress', 'traffic_protection')
    if backend == 'native':
        checks = ('routing', 'netbird', 'owner_record') + checks[2:]
    return checks


def fixed_checks(kind: str, backend: str) -> Dict[str, str]:
    """The checks that are `n/a` or `not-checked` for this kind and backend."""
    if kind == 'sidecar':
        return {'routing': 'n/a', 'netbird': 'n/a', 'owner_record': 'n/a',
                'traffic_protection': 'not-checked', 'app_attachment': 'not-checked'}
    fixed = {'app_attachment': 'n/a'}
    if backend == 'gluetun':
        fixed['owner_record'] = 'n/a'
    return fixed


@dataclass(frozen=True)
class ExitConfig:
    """The reader's own configuration of one exit."""
    provider: str
    kind: str = 'overlay'
    id: str = ''

    def __post_init__(self):
        if self.provider not in providers.REGISTRY:
            raise ValueError('unknown provider')
        if self.kind not in KINDS:
            raise ValueError('EXIT_KIND must be overlay or sidecar')
        if self.kind == 'sidecar' and self.backend != 'gluetun':
            raise ValueError('a sidecar exit needs a gluetun provider (PROVIDER=gluetun-<name>)')

    @property
    def backend(self) -> str:
        return backend_of(self.provider)

    @property
    def spec(self):
        return providers.get(self.provider)


@dataclass(frozen=True)
class Target:
    """The server the reader expects, and why.

    - In the applier and the doctor: the applier's own resolution (its local
      SERVER first, then its pipeline state).
    - In the panel (`for_panel`): the configured lock read from the record,
      or else the panel's own request, which the record must acknowledge."""
    server: Optional[str] = None
    source: Optional[str] = None
    # The panel's desired.json request, when the target is one.
    request: Optional[Mapping[str, Any]] = None

    @classmethod
    def for_panel(cls, result, desired, provider) -> 'Target':
        from molebridge.state import configured_server, desired_request
        configured = configured_server(result)
        if configured is not None:
            return cls(configured, 'configured')
        request = desired_request(desired, provider)
        if request is not None:
            return cls(request['server'], 'panel', request)
        return cls()


@dataclass(frozen=True)
class Verdict:
    state: str
    label: str
    reasons: Tuple[str, ...] = ()
    # The applier's own message, shown with a failure.
    message: Optional[str] = None
    tier: Optional[str] = None
    checks: Mapping[str, str] = field(default_factory=dict)
    schema: Optional[int] = None
    kind: Optional[str] = None
    configured_server: Optional[str] = None
    next_action: Optional[str] = None
    next_action_at: Optional[str] = None

    def as_json(self) -> Dict[str, Any]:
        return {'state': self.state, 'label': self.label, 'reasons': list(self.reasons),
                'message': self.message, 'tier': self.tier, 'checks': dict(self.checks),
                'schema': self.schema, 'kind': self.kind, 'configured_server': self.configured_server,
                'next_action': self.next_action, 'next_action_at': self.next_action_at}


# -- time --------------------------------------------------------------------

def _parse_time(value) -> Optional[datetime]:
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value):
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _fresh(value, now: datetime, max_age=EVIDENCE_MAX_AGE) -> bool:
    """Valid, not in the future, and at most `max_age` seconds old."""
    when = _parse_time(value)
    if when is None:
        return False
    age = (now - when).total_seconds()
    return 0 <= age <= max_age


# -- the verdict -------------------------------------------------------------

def assess(exit_config: ExitConfig, result, target: Optional[Target], now: Optional[datetime] = None) -> Verdict:
    """The one judgment of `result` (the parsed result.json) for this exit,
    against `target`. See the module docstring and the order below."""
    from molebridge.state import configured_server
    now = now or datetime.now(timezone.utc)
    target = target or Target()
    # 1. The configured lock, independently: it holds when the record is stale.
    configured = configured_server(result)
    base = {'configured_server': configured, 'kind': exit_config.kind}
    # 2. Nothing readable yet.
    if not isinstance(result, dict):
        return Verdict('unknown', 'awaiting status', ('no-status',), **base)
    # 3. The schema.
    if 'schema' not in result:
        return _legacy(exit_config, result, target, now, base)
    if result.get('schema') != SCHEMA or type(result.get('schema')) is not int:
        return Verdict('unknown', 'unsupported status version', ('unsupported-schema',), **base)
    base['schema'] = SCHEMA
    selection = result.get('selection') if isinstance(result.get('selection'), dict) else {}
    next_action = selection.get('next_action') if selection.get('next_action') in NEXT_ACTIONS else None
    next_at = selection.get('next_action_at') if next_action and _parse_time(selection.get('next_action_at')) else None
    base.update(next_action=next_action, next_action_at=next_at)
    # 4. Kind, provider and backend: never defaulted.
    if result.get('kind') != exit_config.kind:
        return Verdict('unknown', 'kind mismatch', ('kind-mismatch',), **base)
    if result.get('provider') != exit_config.provider or result.get('backend') != exit_config.backend:
        return Verdict('unknown', 'provider mismatch', ('provider-mismatch',), **base)
    # 5. A stale or future record.
    if not _fresh(result.get('checked_at'), now):
        return Verdict('unknown', 'status stale', ('status-stale',), **base)
    # 6. The panel's request, acknowledged.
    pending = _unacknowledged(result, target, now)
    if pending is not None:
        return Verdict(pending[0], pending[1], (pending[2],), **base)
    status = result.get('status')
    # 7. A switch in progress.
    if status == 'applying':
        return Verdict('applying', 'switching', ('applying',), **base)
    message = result.get('message') if isinstance(result.get('message'), str) else None
    checks, problems = _read_checks(exit_config, result, now)
    if problems is None:
        return Verdict('unknown', 'invalid status record', ('invalid-record',), checks=checks, **base)
    failed, expired, unmeasured = problems
    rejected = selection.get('outcome') in ('rejected', 'mutation-failed')
    # A tunnel-tier sidecar can't compare its egress with the host's own
    # address: switched, never verified, and not a measured failure.
    unmeasurable = (exit_config.kind == 'sidecar' and not rejected and failed == ['egress']
                    and isinstance(result['checks'].get('egress'), dict)
                    and result['checks']['egress'].get('reason') == 'host-address-not-measurable')
    if unmeasurable:
        return Verdict('unknown', 'switched, egress unverified', ('host-address-not-measurable',),
                       message="Switched; the egress couldn't be compared with this host's address.",
                       checks=checks, **base)
    # 8. A fresh measured failure, or a rejection, first; then expired
    # evidence; then what was never measured.
    if failed or rejected:
        reasons = tuple(f'{name}-failed' for name in failed) + (('rejected',) if rejected else ())
        return Verdict('failed', 'failed', reasons, message=message, checks=checks, **base)
    if expired:
        return Verdict('unknown', 'evidence expired', tuple(f'{name}-expired' for name in expired),
                       checks=checks, **base)
    if status == 'failed':
        return Verdict('failed', 'failed', ('status-failed',), message=message, checks=checks, **base)
    if unmeasured:
        return Verdict('unknown', 'not yet measured', tuple(f'{name}-unmeasured' for name in unmeasured),
                       checks=checks, **base)
    # 9. A healthy record: every required check passes and the target agrees.
    if status == 'ok':
        tier = result['checks']['egress'].get('tier')
        disagreement = _target_disagreement(result, target, selection, configured)
        if disagreement:
            return Verdict('failed', 'verification failed', (disagreement,), message=message, checks=checks, **base)
        note = ('no-selection',) if target.server is None and selection.get('source') in (None, 'seed') else ()
        return Verdict('ok', 'connected', note, tier=tier, checks=checks, **base)
    # 10. Anything else.
    return Verdict('unknown', 'unknown', ('status-unknown',), message=message, checks=checks, **base)


def _unacknowledged(result, target: Target, now) -> Optional[Tuple[str, str, str]]:
    """While the panel's request isn't acknowledged: switching while it is
    fresh, then unknown."""
    from molebridge.state import request_token
    if target.source != 'panel' or target.request is None:
        return None
    if result.get('request_id') == request_token(target.request):
        return None
    if _fresh(target.request.get('requested_at'), now):
        return 'applying', 'switching', 'request-pending'
    return 'unknown', 'request not acknowledged', 'request-not-acknowledged'


def _target_disagreement(result, target: Target, selection, configured) -> Optional[str]:
    """Why the record's server isn't the reader's target, or None."""
    server = result.get('server')
    if target.source == 'configured' or configured is not None:
        expected = target.server if target.source == 'configured' else configured
        return None if server == expected else 'not-configured-server'
    if target.source == 'panel':
        if server == target.server and result.get('requested_server') == target.server:
            return None
        return 'not-requested-server'
    if target.server is not None:
        return None if server == target.server else 'not-target-server'
    # The reader has no target of its own: the record's selection must agree
    # with itself, except an observed seed.
    if selection.get('source') in ('restore', 'reconverge', 'retry', 'operator-retry', 'failover'):
        return None if server == selection.get('target') else 'not-target-server'
    return None


def _read_checks(exit_config: ExitConfig, result, now):
    """(display states by check, (failed, expired, unmeasured)) for the
    required checks, or (display, None) when the record is malformed."""
    kind, backend = exit_config.kind, exit_config.backend
    raw = result.get('checks')
    display: Dict[str, str] = dict(fixed_checks(kind, backend))
    if not isinstance(raw, dict):
        return display, None
    failed, expired, unmeasured = [], [], []
    server = result.get('server')
    for name in required_checks(kind, backend):
        check = raw.get(name)
        if not isinstance(check, dict) or check.get('state') not in CHECK_STATES:
            return display, None
        state = check['state']
        if state in ('n/a', 'not-checked'):
            # A required check can't be waived by the record.
            return display, None
        if state in ('pass', 'fail'):
            if not _valid_shape(name, check, kind, exit_config.spec):
                return display, None
            if not _fresh(check.get('at'), now):
                expired.append(name)
                display[name] = 'unknown'
                continue
            if name in SERVER_BOUND and (check.get('server') != server or server is None) and state == 'pass':
                # A pass for another selection never counts.
                expired.append(name)
                display[name] = 'unknown'
                continue
            if state == 'fail':
                failed.append(name)
        else:
            unmeasured.append(name)
        display[name] = state
    if 'traffic_protection' in required_checks(kind, backend) and display.get('traffic_protection') == 'pass':
        # Overlay traffic protection is the routing contract itself.
        if raw['traffic_protection'].get('from') != 'routing' or display.get('routing') == 'fail':
            return display, None
    if display.get('egress') == 'pass' and not egress_ips_consistent(result):
        return display, None
    return display, (failed, expired, unmeasured)


def _valid_shape(name, check, kind, spec) -> bool:
    """Strict types for the checks that carry measurements."""
    state = check['state']
    if name == 'handshake':
        age = check.get('age_s')
        if age is not None and (type(age) is not int or age < 0):
            return False
        if state == 'pass' and (age is None or age >= HANDSHAKE_FRESH_SEC):
            return False
    if name == 'egress':
        families = check.get('families')
        expected = check.get('expected_families')
        if not isinstance(families, dict) or not isinstance(expected, list) or not expected:
            return False
        if set(families) - set(FAMILIES) or set(expected) - set(FAMILIES) or len(set(expected)) != len(expected):
            return False
        if any(value not in CHECK_STATES for value in families.values()):
            return False
        if state == 'pass':
            if any(families.get(f) != 'pass' for f in expected):
                return False
            tier = check.get('tier')
            if tier not in providers.TIERS:
                return False
            # The tunnel tier counts only where the provider has no stronger
            # check, and never for a sidecar.
            if tier == 'tunnel' and (kind == 'sidecar' or spec.egress_tier != 'tunnel'):
                return False
    return True


def egress_ips_consistent(result) -> bool:
    """`egress_ips` covers exactly the passing families."""
    check = (result.get('checks') or {}).get('egress') if isinstance(result, dict) else None
    ips = result.get('egress_ips') if isinstance(result, dict) else None
    if not isinstance(check, dict) or not isinstance(ips, dict):
        return False
    passing = {f for f, state in (check.get('families') or {}).items() if state == 'pass'}
    return set(ips) == passing


# -- legacy records (schema absent: 0.6 and earlier) --------------------------

LEGACY_CHECKS = {name: 'legacy' for name in ('routing', 'netbird', 'owner_record', 'peer', 'handshake', 'egress',
                                              'traffic_protection')}


def _legacy(exit_config: ExitConfig, result, target: Target, now, base) -> Verdict:
    """A 0.6 overlay record, judged as 0.6's status_view judged it, plus the
    target and provider. Its checks aren't reported individually."""
    from molebridge.state import egress_tier
    base = dict(base, schema=1)
    checks = dict(LEGACY_CHECKS, app_attachment='n/a')
    if exit_config.kind != 'overlay':
        return Verdict('unknown', 'kind mismatch', ('kind-mismatch',), **base)
    if not _fresh(result.get('checked_at'), now):
        return Verdict('unknown', 'status stale', ('status-stale',), **base)
    pending = _unacknowledged(result, target, now)
    if pending is not None:
        return Verdict(pending[0], pending[1], (pending[2],), **base)
    status = result.get('status')
    message = result.get('message') if isinstance(result.get('message'), str) else None
    if status == 'applying':
        return Verdict('applying', 'switching', ('applying',), **base)
    if status == 'failed':
        return Verdict('failed', 'failed', ('status-failed',), message=message, checks=checks, **base)
    if status != 'ok':
        return Verdict('unknown', 'unknown', ('status-unknown',), checks=checks, **base)
    provider = result.get('provider')
    tier = egress_tier(result, exit_config.provider)
    reasons = []
    if provider is not None and provider != exit_config.provider:
        return Verdict('unknown', 'provider mismatch', ('provider-mismatch',), **base)
    if result.get('routing_ok') is not True:
        reasons.append('routing-failed')
    # Results written before the NetBird mode check have no such field.
    if result.get('netbird_native', True) is not True:
        reasons.append('netbird-failed')
    if tier is None:
        reasons.append('egress-failed')
    disagreement = _target_disagreement(result, target, {}, base['configured_server'])
    if disagreement:
        reasons.append(disagreement)
    if reasons:
        return Verdict('failed', 'verification failed', tuple(reasons), message=message, checks=checks, **base)
    return Verdict('ok', 'connected', (), tier=tier, checks=checks, **base)


# -- the deprecated 0.6 projection ------------------------------------------

def legacy_projection(result, verdict: Verdict) -> Dict[str, Any]:
    """The fields a cached 0.6 browser script reads from /api/status's
    `result`, derived from a schema-2 record (deprecated; one release). None
    where the check is unknown or doesn't apply."""
    if not isinstance(result, dict) or verdict.schema != SCHEMA:
        return {}
    checks = result.get('checks') if isinstance(result.get('checks'), dict) else {}

    def state(name):
        value = verdict.checks.get(name)
        return True if value == 'pass' else False if value == 'fail' else None
    routing = checks.get('routing') if isinstance(checks.get('routing'), dict) else {}
    egress = checks.get('egress') if isinstance(checks.get('egress'), dict) else {}
    handshake = checks.get('handshake') if isinstance(checks.get('handshake'), dict) else {}
    egress_state = verdict.checks.get('egress')
    confirmed = None
    tier = None
    if egress_state == 'pass':
        confirmed = egress.get('tier') == 'provider'
        tier = egress.get('tier') if egress.get('tier') == 'tunnel' else None
    elif egress_state == 'fail':
        confirmed = False
    fallback = routing.get('fallback') if verdict.checks.get('routing') in ('pass', 'fail') else None
    return {'routing_ok': state('routing'), 'netbird_native': state('netbird'), 'exit_confirmed': confirmed,
            'egress_tier': tier,
            'handshake_age_s': handshake.get('age_s') if verdict.checks.get('handshake') in ('pass', 'fail') else None,
            'unreachable_fallback': fallback if isinstance(fallback, bool) else None}
