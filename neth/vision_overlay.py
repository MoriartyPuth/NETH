#!/usr/bin/env python3
"""
NETH - Physical overlay / sticker detection from an uploaded photo.

Reframed from "detect shadows/edges" (unreliable) to two signals that actually
generalise:

  1. MULTI-QR  : more than one QR code in frame is a strong overlay tell — a
                 sticker pasted over a placard usually leaves the original
                 partially visible, or the fraudster's print sits beside it.
  2. EXTRACT   : decode every QR so the KHQR + identity engines can run on the
                 actual payload(s).

Uses pyzbar if available (best multi-decode), else OpenCV's QRCodeDetector.
A trained YOLOv8 sticker-boundary model can later augment this via detect().
"""
from __future__ import annotations

from dataclasses import dataclass, field

try:
    import numpy as np
    import cv2
except ImportError:
    np = None
    cv2 = None

try:
    from pyzbar.pyzbar import decode as zbar_decode
except ImportError:
    zbar_decode = None

from pathlib import Path

# WeChat QR detector (handles logo / stylized QR like ABA Pay) — optional.
# Requires opencv-contrib-python(-headless) + the 4 model files in this dir.
WECHAT_MODEL_DIR = Path(__file__).resolve().parent.parent / "data" / "wechat_models"


# Reject absurdly large images (decompression-bomb / memory-exhaustion guard).
MAX_PIXELS = 40_000_000   # ~40 MP (e.g. 7000x5700); generous for phone photos


@dataclass
class OverlaySignal:
    status: str            # SAFE | SUSPICIOUS | BLOCKED | INVALID
    score: int
    reason: str
    qr_count: int = 0
    payloads: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return self.__dict__.copy()


class OverlayDetector:
    def __init__(self) -> None:
        self._wechat = self._init_wechat()

    @staticmethod
    def _init_wechat():
        """Build the WeChat QR detector if opencv-contrib + models are present."""
        if cv2 is None or not hasattr(cv2, "wechat_qrcode"):
            return None
        files = ["detect.prototxt", "detect.caffemodel", "sr.prototxt", "sr.caffemodel"]
        paths = [str(WECHAT_MODEL_DIR / f) for f in files]
        try:
            if all((WECHAT_MODEL_DIR / f).exists() for f in files):
                return cv2.wechat_qrcode.WeChatQRCode(*paths)
            return cv2.wechat_qrcode.WeChatQRCode()  # no SR models (still works)
        except Exception as exc:  # noqa: BLE001
            print(f"[vision] WeChat detector unavailable ({exc}); using zbar/cv2.")
            return None

    def _decode_wechat(self, img) -> list[str]:
        if self._wechat is None:
            return []
        try:
            texts, _points = self._wechat.detectAndDecode(img)
            return [t for t in texts if t]
        except Exception:  # noqa: BLE001
            return []

    def _decode_pyzbar(self, img) -> list[str]:
        out = []
        for sym in zbar_decode(img):
            try:
                out.append(sym.data.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                pass
        return out

    def _decode_cv2(self, img) -> list[str]:
        detector = cv2.QRCodeDetector()
        try:
            ok, decoded, points, _ = detector.detectAndDecodeMulti(img)
            if ok:
                return [d for d in decoded if d]
        except Exception:  # noqa: BLE001
            pass
        try:
            data, _, _ = detector.detectAndDecode(img)
            return [data] if data else []
        except Exception:  # noqa: BLE001
            return []

    def _image_variants(self, img):
        """Yield preprocessing variants — stylized / logo / screenshot QR codes
        (e.g. ABA Pay's rounded modules + center coin) often need help."""
        variants = [img]
        try:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            variants.append(gray)
            variants.append(cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC))
            _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            variants.append(otsu)
            # adaptive threshold helps uneven lighting / phone photos of placards
            variants.append(cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                                   cv2.THRESH_BINARY, 31, 5))
        except Exception:  # noqa: BLE001
            pass
        return variants

    def _decode_robust(self, img) -> list[str]:
        """Try WeChat (best for logo QRs), then preprocessing variants + zbar/cv2."""
        wx = self._decode_wechat(img)
        if wx:
            return wx
        for variant in self._image_variants(img):
            found = []
            if zbar_decode:
                found += self._decode_pyzbar(variant)
            found += self._decode_cv2(variant)
            found = [p for p in found if p]
            if found:
                return found
        return []

    def analyze_path(self, image_path: str) -> OverlaySignal:
        if cv2 is None:
            return OverlaySignal("INVALID", -1, "OpenCV not installed: pip install opencv-python-headless")
        img = cv2.imread(image_path)
        if img is None:
            return OverlaySignal("INVALID", -1, f"Could not read image: {image_path}")
        return self._analyze_img(img)

    def analyze_bytes(self, data: bytes) -> OverlaySignal:
        if cv2 is None or np is None:
            return OverlaySignal("INVALID", -1, "OpenCV not installed: pip install opencv-python-headless")
        arr = np.frombuffer(data, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return OverlaySignal("INVALID", -1, "Could not decode uploaded image bytes.")
        return self._analyze_img(img)

    def _analyze_img(self, img) -> OverlaySignal:
        h, w = img.shape[:2]
        if h * w > MAX_PIXELS:
            return OverlaySignal("INVALID", -1,
                                 f"Image too large ({w}x{h}); exceeds {MAX_PIXELS // 1_000_000} MP limit.")
        payloads = self._decode_robust(img)
        payloads = list(dict.fromkeys(p for p in payloads if p))  # dedupe, keep order
        n = len(payloads)

        if n == 0:
            return OverlaySignal("INVALID", -1,
                                 "No QR code detected in image. Try a sharper photo, "
                                 "more light, or crop to just the QR.", 0, [])
        if n >= 2:
            return OverlaySignal(
                "SUSPICIOUS", 1,
                f"{n} QR codes detected in one frame — possible sticker overlaid on a placard. "
                "Confirm which code the merchant points to.",
                n, payloads,
            )
        return OverlaySignal("SAFE", 0, "Single QR detected; extracted for payload analysis.", 1, payloads)


if __name__ == "__main__":
    import sys
    det = OverlayDetector()
    if len(sys.argv) > 1:
        print(det.analyze_path(sys.argv[1]).as_dict())
    else:
        print("usage: python -m neth.vision_overlay <image>")
