#!/usr/bin/env python3
"""Draw the control panel's home-screen icons into panel/static/.

Standard library only: a globe in the panel theme's primary colour with a
green "connected" dot, rendered from signed distances with 1px antialiasing.
Full-bleed background so iOS and maskable Android icons can crop freely.
Re-run after changing the design; commit the PNGs it writes.
"""
from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / 'panel' / 'static'
SIZES = {'apple-touch-icon.png': 180, 'icon-192.png': 192, 'icon-512.png': 512}

BACKGROUND = (0x23, 0x26, 0x38)  # panel theme-color
PRIMARY = (0x8A, 0xAD, 0xF4)     # hsl(220 83% 75%)
POSITIVE = (0xA6, 0xDA, 0x95)    # hsl(105 48% 72%)


def cover(distance: float, px: float) -> float:
    """Coverage of a shape at signed distance (design units, negative inside)."""
    return min(1.0, max(0.0, 0.5 - distance / px))


def ring(d_center: float, radius: float, width: float) -> float:
    return abs(d_center - radius) - width / 2


def ellipse_ring(x: float, y: float, rx: float, ry: float, width: float) -> float:
    f = (x / rx) ** 2 + (y / ry) ** 2 - 1
    grad = 2 * math.hypot(x / rx ** 2, y / ry ** 2) or 1e-9
    return abs(f / grad) - width / 2


def mix(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def render(size: int) -> bytes:
    px = 512 / size  # design units per pixel
    rows = []
    for j in range(size):
        row = bytearray(b'\x00')
        for i in range(size):
            x = (i + 0.5) * px - 256
            y = (j + 0.5) * px - 256
            r = math.hypot(x, y)
            inside_globe = r - 150
            globe = min(
                ring(r, 150, 24),
                max(abs(y) - 9, inside_globe),                    # equator
                max(abs(abs(y) - 80) - 8, inside_globe),          # latitudes
                max(ellipse_ring(x, y, 66, 150, 18), inside_globe),  # longitudes
            )
            colour = mix(BACKGROUND, PRIMARY, cover(globe, px))
            dot_r = math.hypot(x - 128, y - 128)
            colour = mix(colour, BACKGROUND, cover(dot_r - 62, px))  # cut-out
            colour = mix(colour, POSITIVE, cover(dot_r - 44, px))
            row += bytes(colour)
        rows.append(bytes(row))
    raw = zlib.compress(b''.join(rows), 9)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))

    header = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'IDAT', raw) + chunk(b'IEND', b'')


def main() -> None:
    for name, size in SIZES.items():
        (STATIC / name).write_bytes(render(size))
        print(f'wrote {name} ({size}px)')


if __name__ == '__main__':
    main()
