#!/usr/bin/env python3
"""
Regenerate the booth "scan me" QR code (lab/assets/butler_cyber_qr.svg).

The SVG is committed so the gateway needs no QR library at runtime (works
in the Docker `web` container and offline at event venues). Run this only
when the target URL changes; it needs `pip install qrcode`.

Usage:
    python lab/scripts/make_qr.py                 # default Butler cyber URL
    python lab/scripts/make_qr.py https://...     # custom URL

If you change the URL, also update BOOTH_QR_URL in secure_gateway.py so the
printed link under the code matches.
"""

import os
import re
import sys

DEFAULT_URL = "https://www.butlercc.edu/academics/degrees-certificates/cyber-security"
OUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "butler_cyber_qr.svg"))


def main(url):
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        print("Needs the qrcode package: pip install qrcode")
        return 1

    img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=1)
    svg = img.to_string(encoding="unicode")
    svg = re.sub(r"^<\?xml[^>]*\?>\s*", "", svg)  # inlined into HTML, no XML prolog

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(svg + "\n")
    print(f"Wrote {OUT_PATH} -> {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL))
