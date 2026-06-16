#!/usr/bin/env python3
"""
NETH - download the WeChat QR detector model files.

The WeChat detector reads logo / stylized QR codes (e.g. ABA Pay) that zbar
often misses. It needs four model files from the OpenCV 3rdparty repo, saved to
data/wechat_models/. Run once:

    python scripts/fetch_wechat_models.py

Also requires the contrib build:  pip install opencv-contrib-python-headless
"""
from __future__ import annotations

from pathlib import Path
from urllib.request import Request, urlopen

BASE = "https://raw.githubusercontent.com/WeChatCV/opencv_3rdparty/wechat_qrcode/"
FILES = ["detect.prototxt", "detect.caffemodel", "sr.prototxt", "sr.caffemodel"]
OUT = Path(__file__).resolve().parent.parent / "data" / "wechat_models"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        dest = OUT / name
        if dest.exists() and dest.stat().st_size > 0:
            print(f"✓ {name} (already present)")
            continue
        print(f"↓ {name} …")
        req = Request(BASE + name, headers={"User-Agent": "neth/0.1"})
        with urlopen(req, timeout=60) as resp:  # noqa: S310 - trusted source
            dest.write_bytes(resp.read())
        print(f"✓ {name} ({dest.stat().st_size // 1024} KB)")
    print(f"\nDone -> {OUT}\nThe WeChat detector will now activate automatically.")


if __name__ == "__main__":
    main()
