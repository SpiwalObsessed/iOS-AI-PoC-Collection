#!/bin/sh
# log_redaction_check.sh — SCAFFOLD, not an exploit.
#
# Target : CVE-2026-113898 (Accounts) and CVE-2026-112432 (FontParser)
#          "A logging issue was addressed with improved data redaction."
# Theory : a log line printed sensitive data (email, phone, path) without
#          the <private> annotation. The fix changes the format string only,
#          which is the single most confirmable fix in the corpus: the
#          changed __os_log/__cstring delta names the subsystem, and the
#          redaction is visible by diffing the two builds' log output.
#
# Usage  : sudo ./log_redaction_check.sh <subsystem> <seconds>
# Example: sudo ./log_redaction_check.sh com.apple.accounts 60
#
# Run the same script on a 27.0.1 device and a 27.2 device. If 27.0.1
# prints unredacted emails/phones/paths and 27.2 prints <private>, the
# CVE is confirmed for that subsystem.

set -eu

SUBSYSTEM="${1:-com.apple.accounts}"
DURATION="${2:-60}"

echo "[*] streaming logs for subsystem '$SUBSYSTEM' for ${DURATION}s"
echo "[*] trigger activity now (open Settings > Accounts, sign in, etc.)"

OUT="$(mktemp /tmp/logredact.XXXXXX)"

# Stream logs; the predicate filters to the subsystem and to messages that
# are NOT already marked <private>.
log stream --style compact \
    --predicate "subsystem == \"$SUBSYSTEM\"" \
    > "$OUT" 2>&1 &
LOGPID=$!

sleep "$DURATION"
kill "$LOGPID" 2>/dev/null || true
wait "$LOGPID" 2>/dev/null || true

echo "[*] captured $(wc -l < "$OUT") lines"

# Heuristics for unredacted PII.
echo
echo "=== candidate unredacted emails ==="
grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$OUT" | sort -u | head -20

echo
echo "=== candidate unredacted phone numbers ==="
grep -Eo '\+?[0-9][0-9 ()-]{7,}[0-9]' "$OUT" | sort -u | head -20

echo
echo "=== candidate unredacted absolute paths ==="
grep -Eo '/(private|var|Users)/[^ "]+' "$OUT" | sort -u | head -20

echo
echo "[*] full capture: $OUT"
echo "[*] Compare this output between 27.0.1 and 27.2."
