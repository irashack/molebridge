"""The native exit's owner record (routing/molebridge-exit writes it,
routing/contract-rules and molebridge/routing.py read it): its exact shape and
the validity rule at each boundary."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from molebridge.routing import OWNER_EXPIRY, owner_record_valid, parse_owner_record  # noqa: E402

BOOT = '00000000-0000-4000-8000-0000000000aa'
LINE = f'molebridge-exit 1 {BOOT} 1000 5:4026531992 0a0a 203.0.113.1 2001:db8:3::1 conf 2 990\n'


def test_the_written_shape_parses():
    record = parse_owner_record(LINE)
    assert record == {'boot': BOOT, 'stamp': 1000, 'netns': '5:4026531992', 'generation': '0a0a',
                      'addresses': {4: '203.0.113.1', 6: '2001:db8:3::1'}, 'rule94': 'conf', 'repairs': 2,
                      'last_repair': 990}
    assert parse_owner_record(f'molebridge-exit 1 {BOOT} 1000 5:1 0a0a - - applier 0 -\n')['addresses'] == {}


@pytest.mark.parametrize('line', [
    LINE.rstrip('\n'), LINE + LINE, LINE.replace('molebridge-exit 1', 'molebridge-exit 2'),
    LINE.replace(' conf ', ' other '), LINE.replace('203.0.113.1', '203.0.113.01'),
    LINE.replace('2001:db8:3::1', '2001:DB8:3::1'), LINE.replace('2001:db8:3::1', '2001:db8:3:0::1'),
    LINE.replace('203.0.113.1 2001', '2001:db8::1 2001'), LINE.replace(' conf ', ' applier '),
    LINE.replace('5:4026531992', '5'), LINE.replace(' 1000 ', ' -1 '), LINE.replace(' 0a0a ', ' 0A0A '),
    LINE.replace(' 990', ' x'), LINE.replace(BOOT, 'boot id'), '', 'x' * 600 + '\n',
])
def test_anything_else_is_refused(line):
    assert parse_owner_record(line) is None


def valid(age=0, *, boot=BOOT, netns='5:4026531992', seen=None, line=LINE):
    return owner_record_valid(parse_owner_record(line), boot=boot, now=1000 + age, netns=netns, seen=seen)


def test_validity_boundaries():
    assert OWNER_EXPIRY == 6
    assert valid(6) and not valid(7)
    assert valid(-1) and not valid(-2)
    assert not valid(boot='00000000-0000-4000-8000-0000000000bb')
    assert not valid(netns='5:1')
    assert valid(seen=('0a0a', 1000)) and not valid(seen=('0a0a', 1001))
    assert valid(seen=('0b0b', 1001))


def shell_valid(tmp_path, line, now):
    """The shell side's verdict (routing/contract-rules, owner_valid) on the
    same record, with the same clock."""
    (tmp_path / 'owner').write_text(line)
    (tmp_path / 'boot').write_text(BOOT + '\n')
    (tmp_path / 'uptime').write_text(f'{now}.42 1.00\n')
    (tmp_path / 'stat').write_text('#!/bin/sh\necho 5:4026531992\n')
    (tmp_path / 'stat').chmod(0o755)
    env = dict(os.environ, PATH=f'{tmp_path}:{os.environ["PATH"]}', MOLEBRIDGE_BOOT_ID_FILE=str(tmp_path / 'boot'),
               MOLEBRIDGE_UPTIME_FILE=str(tmp_path / 'uptime'), OWNER=str(tmp_path / 'owner'),
               RULES=str(ROOT / 'routing' / 'contract-rules'))
    result = subprocess.run(['sh', '-c', 'set -f; fail() { exit 9; }; . "$RULES"; owner_valid "$OWNER"'],
                            env=env, capture_output=True, text=True, timeout=10)
    return result.returncode == 0


@pytest.mark.parametrize('now,expected', [(1000, True), (1006, True), (1007, False), (999, True), (998, False)])
def test_the_shell_and_python_agree(tmp_path, now, expected):
    assert shell_valid(tmp_path, LINE, now) is expected
    assert valid(now - 1000) is expected


@pytest.mark.parametrize('line', [LINE.replace(' conf ', ' other '), LINE.replace('203.0.113.1', '203.0.113.01'),
                                  LINE.replace('2001:db8:3::1', '2001:db8:3:0::1'),
                                  LINE.replace('2001:db8:3::1', '2001:DB8:3::1'),
                                  LINE.replace(' 0a0a ', ' 0A0A '), 'molebridge-exit 1 x\n'])
def test_the_shell_refuses_what_python_refuses(tmp_path, line):
    assert parse_owner_record(line) is None
    assert not shell_valid(tmp_path, line, 1000)
