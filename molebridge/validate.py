"""Strict decoding and value checks shared by every provider's parser.

Standard library only, and imports nothing else from Molebridge, so each
provider module and the registry can use it without import cycles.
"""
from __future__ import annotations

import base64
import ipaddress
import json


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate JSON field')
        obj[key] = value
    return obj


def decode_json(raw):
    def invalid_constant(_value):
        raise ValueError('non-finite JSON number')
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=invalid_constant)


def valid_key(value):
    if not isinstance(value, str):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32 and base64.b64encode(raw).decode() == value
    except ValueError:
        return False


def valid_ipv4(value):
    try:
        return isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def valid_text(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and all(ord(c) >= 32 for c in value)
