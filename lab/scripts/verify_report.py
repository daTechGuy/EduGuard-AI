#!/usr/bin/env python3
"""
Verify a student's exported Canvas lab report (.md).

Usage (instructor only, with the same secret the gateway was started with):
    REPORT_SECRET=... python lab/scripts/verify_report.py report.md [more.md ...]

PowerShell:
    $env:REPORT_SECRET = "..."; python lab/scripts/verify_report.py report.md

Exit code is 0 only if every report verifies.
"""

import sys

from report_signing import get_secret, verify_report


def main(paths):
    secret = get_secret()
    if not secret:
        print("ERROR: set REPORT_SECRET to the secret the gateway server used.")
        return 2
    if not paths:
        print(__doc__)
        return 2

    all_ok = True
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            print(f"[ERROR] {path}: {e}")
            all_ok = False
            continue
        ok, msg = verify_report(text, secret)
        print(f"[{'VALID' if ok else 'FAIL'}] {path}: {msg}")
        all_ok = all_ok and ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
