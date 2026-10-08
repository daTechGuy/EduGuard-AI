"""
Canvas Lab Report Signing (HMAC-SHA256)
=======================================
Shared by secure_gateway.py (signs reports on export) and
verify_report.py (instructor checks a submitted .md file).

The signature is an HMAC over the whole report text above the signature
line, keyed with the REPORT_SECRET environment variable. Only someone who
knows the secret can produce a valid signature, so this is meaningful
only when the INSTRUCTOR runs the gateway (shared classroom server) and
students never see the secret. A student running the lab on their own
laptop gets an "UNSIGNED - practice copy" report.
"""

import hashlib
import hmac
import os
import re

SIGNATURE_PREFIX = "**Report Signature (HMAC-SHA256)**:"
UNSIGNED_TEXT = "UNSIGNED - practice copy (no REPORT_SECRET on this server)"


def get_secret():
    return os.environ.get("REPORT_SECRET", "").strip()


def canonicalize(text):
    """Normalize line endings and trailing whitespace so a report still
    verifies after a round-trip through Windows/Mac editors."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip("\n")


def compute_signature(body, secret):
    return hmac.new(
        secret.encode("utf-8"),
        canonicalize(body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def sign_report(body, secret=None):
    """Append the signature line to `body`. Returns (text, signature or None)."""
    if secret is None:
        secret = get_secret()
    if not secret:
        return f"{body}\n{SIGNATURE_PREFIX} `{UNSIGNED_TEXT}`\n", None
    signature = compute_signature(body, secret)
    return f"{body}\n{SIGNATURE_PREFIX} `{signature}`\n", signature


def verify_report(text, secret):
    """Returns (ok, message)."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    sig_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith(SIGNATURE_PREFIX):
            sig_idx = i  # last one wins; earlier copies are just body text
    if sig_idx is None:
        return False, "No signature line found."

    match = re.search(r"`([0-9a-f]{64})`", lines[sig_idx])
    if not match:
        return False, "Report is UNSIGNED (exported from a server without REPORT_SECRET)."

    expected = compute_signature("\n".join(lines[:sig_idx]), secret)
    if hmac.compare_digest(expected, match.group(1)):
        return True, "Signature valid: report is unmodified since export."
    return False, "Signature INVALID: report was edited after export, or signed with a different secret."
