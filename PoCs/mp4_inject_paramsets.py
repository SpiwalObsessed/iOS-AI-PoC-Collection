#!/usr/bin/env python3
"""
mp4_inject_paramsets.py — put the malformed parameter-set flood into a real MP4.

Problem it solves:
  AVAssetReader needs a container. Raw Annex-B has no video track, so the
  harness reported "no video track". ffmpeg's muxer refuses to build an MP4
  from our flood because it re-parses the parameter sets to build the hvcC
  box and errors out ("No start code is found").

Solution:
  Start from a VALID MP4 produced by ffmpeg from a real stream, then rewrite
  the single sample's payload in `mdat` with our flood, and patch the sample
  size (`stsz`) and chunk offset (`stco`) tables. The `hvcC` extradata stays
  the valid original, so the decoder initialises normally and only then
  parses the (excessive) parameter sets in the sample data.

Usage:
  python3 mp4_inject_paramsets.py <base.mp4> <flood.h265> <out.mp4>

Note on hvcC length-prefix:
  MP4 samples are length-prefixed (4-byte big-endian NAL length) by default,
  NOT Annex-B start codes. ffmpeg writes the `mdat` with 4-byte length
  prefixes. This script converts the Annex-B flood to length-prefixed form.
"""

import sys
import struct


def split_annexb(data: bytes):
    """Return NAL units (payload only, no start codes)."""
    # Record (start_code_begin, payload_begin) for every NAL.
    marks = []
    i = 0
    n = len(data)
    while i < n - 3:
        if data[i] == 0 and data[i+1] == 0 and data[i+2] == 0 and data[i+3] == 1:
            marks.append((i, i + 4))
            i += 4
        elif data[i] == 0 and data[i+1] == 0 and data[i+2] == 1:
            marks.append((i, i + 3))
            i += 3
        else:
            i += 1
    nals = []
    for k, (sc_begin, pay_begin) in enumerate(marks):
        pay_end = marks[k+1][0] if k + 1 < len(marks) else n
        if pay_end > pay_begin:
            nals.append(data[pay_begin:pay_end])
    return nals


def to_length_prefixed(nals):
    out = bytearray()
    for nal in nals:
        out += struct.pack(">I", len(nal))
        out += nal
    return bytes(out)


def _children(d, start, end):
    """Yield (type, box_offset, box_size, payload_offset) for boxes in a range."""
    off = start
    while off + 8 <= end:
        sz = int.from_bytes(d[off:off+4], "big")
        typ = d[off+4:off+8].decode("latin1", "replace")
        if sz == 1:
            # 64-bit size follows the type
            if off + 16 > end:
                return
            sz = int.from_bytes(d[off+8:off+16], "big")
            payload = off + 16
        elif sz == 0:
            sz = end - off
            payload = off + 8
        else:
            payload = off + 8
        if sz < 8 or off + sz > end:
            return
        yield typ, off, sz, payload
        off += sz


def find_box(d: bytes, path, start=0, end=None):
    """Walk a box path like ['moov','trak',...] and return (offset, size, payload_offset)."""
    if end is None:
        end = len(d)
    cur_start, cur_end = start, end
    result = None
    for depth, want in enumerate(path):
        found = None
        for typ, off, sz, payload in _children(d, cur_start, cur_end):
            if typ == want:
                found = (off, sz, payload)
                break
        if found is None:
            return None
        result = found
        cur_start, cur_end = found[2], found[0] + found[1]
        # Skip fixed headers inside specific containers to reach their children.
        if want == "stsd":
            # version/flags (4) + entry_count (4)
            cur_start += 8
        elif want in ("hvc1", "avc1", "hev1", "avc3"):
            # visual sample entry: 78 bytes before child boxes
            cur_start += 78
    return result


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(__doc__)
        return 2
    base_path, flood_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

    base = bytearray(open(base_path, "rb").read())
    flood = open(flood_path, "rb").read()

    nals = split_annexb(flood)
    if not nals:
        sys.stderr.write("no NALs in flood\n")
        return 1
    sample = to_length_prefixed(nals)
    sys.stderr.write("flood NALs=%d  sample size=%d\n" % (len(nals), len(sample)))

    mdat = find_box(base, ["mdat"])
    if mdat is None:
        sys.stderr.write("no mdat\n"); return 1
    m_off, m_sz, m_pay = mdat
    old_payload_len = m_sz - (m_pay - m_off)
    delta = len(sample) - old_payload_len
    sys.stderr.write("mdat payload %d -> %d (delta %+d)\n"
                     % (old_payload_len, len(sample), delta))

    nb = bytearray()
    nb += base[:m_off]
    nb += struct.pack(">I", 8 + len(sample)) + b"mdat" + sample
    nb += base[m_off+m_sz:]
    d = bytes(nb)

    # --- stsz: sample sizes ---
    stsz = find_box(d, ["moov","trak","mdia","minf","stbl","stsz"])
    if stsz:
        off, sz, pay = stsz
        # pay = version/flags(4) + sample_size(4) + sample_count(4) + entries
        shared = int.from_bytes(d[pay+4:pay+8], "big")
        count  = int.from_bytes(d[pay+8:pay+12], "big")
        sys.stderr.write("stsz shared=%d count=%d\n" % (shared, count))
        if shared != 0:
            nb[pay+4:pay+8] = struct.pack(">I", len(sample))
            sys.stderr.write("stsz: shared sample_size=%d\n" % len(sample))
        else:
            for i in range(count):
                e = pay + 12 + i*4
                if e + 4 <= len(nb):
                    nb[e:e+4] = struct.pack(">I", len(sample))
            sys.stderr.write("stsz: set %d entries to %d\n" % (count, len(sample)))
    else:
        sys.stderr.write("WARN: no stsz\n")

    # --- stco / co64: chunk offsets ---
    #
    # Chunk offsets are absolute file offsets into mdat. Whether they need
    # adjusting depends on WHERE moov sits relative to mdat:
    #   * moov AFTER mdat (ffmpeg's usual layout): growing mdat moves moov,
    #     but every offset still points at the same place inside mdat, so the
    #     stored values are unchanged.
    #   * moov BEFORE mdat (faststart): mdat shifted, so every offset must
    #     move by +delta.
    moov = find_box(bytes(nb), ["moov"])
    mdat_now = find_box(bytes(nb), ["mdat"])
    moov_before_mdat = (moov is not None and mdat_now is not None
                        and moov[0] < mdat_now[0])
    shift = delta if moov_before_mdat else 0
    sys.stderr.write("layout: moov %s mdat -> shift %+d\n"
                     % ("before" if moov_before_mdat else "after", shift))

    stco = find_box(bytes(nb), ["moov","trak","mdia","minf","stbl","stco"])
    if stco:
        off, sz, pay = stco
        cnt = int.from_bytes(nb[pay+4:pay+8], "big")
        if shift:
            for i in range(cnt):
                e = pay + 8 + i*4
                v = int.from_bytes(nb[e:e+4], "big")
                nb[e:e+4] = struct.pack(">I", v + shift)
        sys.stderr.write("stco: %d offsets, shift %+d\n" % (cnt, shift))
    else:
        co64 = find_box(bytes(nb), ["moov","trak","mdia","minf","stbl","co64"])
        if co64:
            off, sz, pay = co64
            cnt = int.from_bytes(nb[pay+4:pay+8], "big")
            if shift:
                for i in range(cnt):
                    e = pay + 8 + i*8
                    v = int.from_bytes(nb[e:e+8], "big")
                    nb[e:e+8] = struct.pack(">Q", v + shift)
            sys.stderr.write("co64: %d offsets, shift %+d\n" % (cnt, shift))
        else:
            sys.stderr.write("WARN: no stco/co64\n")

    open(out_path, "wb").write(bytes(nb))
    sys.stderr.write("wrote %s (%d bytes)\n" % (out_path, len(nb)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
