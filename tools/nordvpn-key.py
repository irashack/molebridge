#!/usr/bin/env python3
"""Fetch your NordLynx private key with a NordVPN access token and write
Molebridge's tunnel config for NordVPN.

Usage: tools/nordvpn-key.py TOKEN_FILE OUTPUT
       printf %s "$TOKEN" | tools/nordvpn-key.py - OUTPUT

TOKEN_FILE holds the access token (Nord Account -> NordVPN -> Advanced
settings -> Get access token) and must be mode 0600 or stricter. With `-` the
token is read from standard input. It is never read from the command line or
the environment, and it reaches curl only through a mode-0600 temporary file.

OUTPUT is created with mode 0600 and is never overwritten. It carries the
private key and the NordLynx tunnel address (10.5.0.2/32) but no peer: the
applier sets the peer when you pick a server.

Prints one fixed line and no token, key or response. Delete the token file, or
revoke the token in your Nord Account, once this succeeds: only the key is
needed afterwards.
"""
from __future__ import annotations

import importlib.util
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from molebridge.nordvpn import NORD_ADDRESS
from molebridge.validate import decode_json, valid_key

_spec = importlib.util.spec_from_file_location('prepare_tunnel_config', Path(__file__).with_name('prepare-tunnel-config.py'))
prepare = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prepare)

CREDENTIALS_URL = 'https://api.nordvpn.com/v1/users/services/credentials'
TOKEN_MAX_BYTES = 512
RESPONSE_MAX_BYTES = 65536
TIMEOUT_S = 20
# Printable ASCII without quote or backslash, which the curl config would need escaped.
TOKEN_RE = re.compile(r'[\x21\x23-\x5b\x5d-\x7e]{1,256}')

OK_LINE = 'wrote the NordVPN tunnel config (mode 0600)'


class NordKeyError(Exception):
    """A failure with a fixed, value-free message."""


def read_token(source: str) -> str:
    """The access token from a mode-0600 file, or from stdin for `-`."""
    try:
        if source == '-':
            raw = sys.stdin.buffer.read(TOKEN_MAX_BYTES + 1)
        else:
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
            with os.fdopen(os.open(source, flags), 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise NordKeyError('the token file is not a regular file')
                if info.st_mode & 0o077:
                    raise NordKeyError('the token file must be mode 0600 or stricter')
                raw = stream.read(TOKEN_MAX_BYTES + 1)
    except OSError:
        raise NordKeyError('the token could not be read') from None
    if len(raw) > TOKEN_MAX_BYTES:
        raise NordKeyError('the token is too long')
    try:
        token = raw.decode('ascii')
    except UnicodeError:
        raise NordKeyError('the token is not valid') from None
    token = token[:-1] if token.endswith('\n') else token
    token = token[:-1] if token.endswith('\r') else token
    if not TOKEN_RE.fullmatch(token):
        raise NordKeyError('the token is not valid')
    return token


def fetch_credentials(token: str) -> bytes:
    """GET the credentials document. Tests replace this function.

    The credential reaches curl only through a mode-0600 config file."""
    fd, name = tempfile.mkstemp(prefix='.nordvpn-')
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(f'user = "token:{token}"\n')
        try:
            done = subprocess.run(
                ['curl', '-q', '--noproxy', '*', '--proto', '=https', '-fsS',
                 '--max-time', str(TIMEOUT_S), '--max-filesize', str(RESPONSE_MAX_BYTES),
                 '--config', name, CREDENTIALS_URL],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT_S + 5, check=False)
        except (OSError, subprocess.SubprocessError):
            raise NordKeyError('the request to NordVPN failed') from None
        if done.returncode != 0 or len(done.stdout) > RESPONSE_MAX_BYTES:
            raise NordKeyError('the request to NordVPN failed')
        return done.stdout
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


def parse_private_key(raw) -> str:
    """Only `nordlynx_private_key`; nothing else in the response is used."""
    try:
        data = decode_json(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise NordKeyError('the NordVPN response is not valid') from None
    key = data.get('nordlynx_private_key') if isinstance(data, dict) else None
    if not valid_key(key):
        raise NordKeyError('the NordVPN response has no usable key')
    return key


def build_nord_conf(private_key: str, table: str = prepare.EXIT_TABLE) -> str:
    prepare.require_key(private_key, 'PrivateKey')
    prepare.check_table(table)
    # IPv4 only: NordLynx carries no IPv6, so IPv6 stays on the unreachable fallback.
    return '\n'.join([
        '# Generated by tools/nordvpn-key.py. Keep mode 0600; never commit.',
        '# No peer: the applier sets it when a server is chosen.',
        '[Interface]',
        f'PrivateKey = {private_key}',
        f'Address = {NORD_ADDRESS}',
        'MTU = 1420',
        'Table = off',
        f'PostUp = ip route replace default dev %i table {table}',
        f'PreDown = ip route del default dev %i table {table}',
        '',
    ])


def write_new(path: Path, content: str) -> None:
    """Create `path` with mode 0600; never replace an existing file."""
    if not hasattr(os, 'fchmod'):
        raise NordKeyError('create the tunnel config on a POSIX host that supports mode 0600')
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError:
        raise NordKeyError('the output file exists; keep it, or remove it deliberately') from None
    except OSError:
        raise NordKeyError('the output file could not be created') from None
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def main(argv: list) -> int:
    if len(argv) != 3:
        print('usage: nordvpn-key.py TOKEN_FILE|- OUTPUT', file=sys.stderr)
        return 2
    output = Path(argv[2])
    try:
        if os.path.lexists(output):
            raise NordKeyError('the output file exists; keep it, or remove it deliberately')
        token = read_token(argv[1])
        key = parse_private_key(fetch_credentials(token))
        write_new(output, build_nord_conf(key))
    except NordKeyError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    except (OSError, ValueError, prepare.ConfigError):
        print('error: the tunnel config could not be written', file=sys.stderr)
        return 1
    print(OK_LINE)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
