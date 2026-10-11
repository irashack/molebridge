"""The per-exit attempt record (state/applier/attempt.json).

Every change to the live selection goes through one admission pipeline
(applier/apply.py, `Applier.admit`). Its state lives here, so a restart
resumes it: written atomically before every mutation's I/O, because a lost
response can hide success, and after every outcome.

Deadlines and the time of the last mutation are kept on the boot clock
(`clock`, CLOCK_MONOTONIC on Linux) together with the boot's id: a value from
another boot means nothing on this one (`Attempt.load`).
"""
from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from molebridge.state import now_iso, read_json, write_json_atomic

STATES = ('idle', 'pending', 'rejected', 'attempting', 'unverified', 'failed')
# Automatic retries wait 1, 2, 4 and 8 minutes, then every 15.
BACKOFF_SEC = (60, 120, 240, 480, 900)
# No automatic re-apply within this long of the last mutation.
REAPPLY_GUARD_SEC = 90
# A live peer the catalogue can't name is waited out this long before it
# counts as drift.
UNIDENTIFIED_SEC = 90
BOOT_ID_FILE = '/proc/sys/kernel/random/boot_id'


def backoff(step: int) -> int:
    return BACKOFF_SEC[min(max(step, 0), len(BACKOFF_SEC) - 1)]


def read_boot_id(path=BOOT_ID_FILE) -> str:
    try:
        value = Path(path).read_text(encoding='ascii').strip()
    except (OSError, UnicodeError):
        return 'unknown'
    return value if value and len(value) <= 64 and value.replace('-', '').isalnum() else 'unknown'


@dataclass
class Attempt:
    """One exit's admission state for its current effective target."""
    attempt_id: str = ''
    # Why the target is what it is (molebridge/verdict.py SOURCES), its server,
    # and its identity: a panel request's token, 'configured:<server>' or
    # 'restore:<server>'. A new identity is a new target.
    source: Optional[str] = None
    target: Optional[str] = None
    target_key: Optional[str] = None
    state: str = 'idle'
    # The last outcome published for this target (verdict.py OUTCOMES).
    outcome: Optional[str] = None
    message: Optional[str] = None
    boot_id: str = ''
    started_at: Optional[str] = None
    # Mutations made for this target, and the backoff step the next retry uses.
    attempts: int = 0
    backoff_step: int = 0
    next_action: Optional[str] = None
    next_action_at: Optional[float] = None
    last_mutation_at: Optional[float] = None
    # 'definite' when the change was refused before taking effect, 'uncertain'
    # when its outcome is unknown.
    mutation_certainty: Optional[str] = None
    # The native exit's owner generation already given its one re-apply.
    generation: Optional[str] = None
    # The last rejected panel request, kept apart from the target so its
    # acknowledgement survives a restart without blocking restore:
    # {'key', 'reason', 'release'} where `release` is what lifts it (the
    # catalogue's or the credentials' signature at the time).
    rejected: Optional[Dict[str, Any]] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def new(cls, *, source, target, target_key, boot_id, rejected=None, generation=None):
        return cls(attempt_id=secrets.token_hex(8), source=source, target=target, target_key=target_key,
                   boot_id=boot_id, started_at=now_iso(), rejected=rejected, generation=generation)

    @classmethod
    def load(cls, path: Path, *, boot_id: str, now: float) -> 'Attempt':
        """The persisted attempt, adjusted for this boot. Anything unreadable
        starts idle."""
        raw = read_json(path, 16384)
        if not isinstance(raw, dict):
            return cls(boot_id=boot_id)
        try:
            known = {k: raw[k] for k in cls.__dataclass_fields__ if k in raw}
            attempt = cls(**known)
        except TypeError:
            return cls(boot_id=boot_id)
        if attempt.state not in STATES or not isinstance(attempt.backoff_step, int) or attempt.backoff_step < 0:
            return cls(boot_id=boot_id)
        for name in ('next_action_at', 'last_mutation_at'):
            value = getattr(attempt, name)
            if value is not None and type(value) not in (int, float):
                setattr(attempt, name, None)
        if attempt.next_action not in (None, 'recheck', 'reapply'):
            attempt.next_action = None
        if attempt.boot_id != boot_id:
            # Clock values from another boot: a recheck is due now, a reapply
            # waits the current step, and the last mutation is long past.
            attempt.last_mutation_at = None
            if attempt.next_action == 'recheck':
                attempt.next_action_at = now
            elif attempt.next_action == 'reapply':
                attempt.next_action_at = now + backoff(attempt.backoff_step)
            attempt.boot_id = boot_id
        return attempt

    def save(self, path: Path):
        write_json_atomic(path, asdict(self))

    def guard_passed(self, now: float) -> bool:
        """True when no mutation happened within REAPPLY_GUARD_SEC."""
        return self.last_mutation_at is None or now - self.last_mutation_at >= REAPPLY_GUARD_SEC

    def schedule(self, action: str, now: float):
        """Set the next automatic action on the backoff, and advance it."""
        self.next_action = action
        self.next_action_at = now + backoff(self.backoff_step)
        self.backoff_step += 1

    def settle(self):
        """A verified selection: no further action, the backoff starts over."""
        self.state, self.outcome = 'idle', 'verified'
        self.message = None
        self.next_action = self.next_action_at = None
        self.backoff_step = 0
        self.mutation_certainty = None
