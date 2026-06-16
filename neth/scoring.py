#!/usr/bin/env python3
"""
NETH - signal aggregation.

Each engine emits a partial signal (status/score/reason). The gateway combines
them into one verdict. Policy:

  * Final score = max severity across engines (a single BLOCKED wins).
  * Scores of -1 (not-checked / not-applicable) never lower the verdict and are
    surfaced as "unverified" notes so users aren't given false assurance.
  * The full breakdown is always returned for transparency.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .bakong_verify import BakongVerifier
from .i18n import localize_signal, localize_summary
from .identity_match import IdentityMatcher
from .khqr_core import NethKHQREngine
from .nlp_khmer import KhmerPhishingDetector
from .vision_overlay import OverlayDetector

LABELS = {0: "SAFE", 1: "SUSPICIOUS", 2: "BLOCKED"}


@dataclass
class GatewayVerdict:
    score: int
    label: str
    summary: str
    summary_km: str = ""
    signals: list[dict] = field(default_factory=list)
    extracted_payloads: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return self.__dict__.copy()


class NethGateway:
    def __init__(self) -> None:
        self.khqr = NethKHQREngine()
        self.nlp = KhmerPhishingDetector()
        self.vision = OverlayDetector()
        self.identity = IdentityMatcher()
        self.bakong = BakongVerifier()

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _push(signals: list[dict], engine: str, status: str, score: int, reason: str, extra=None):
        sig = {"engine": engine, "status": status, "score": score, "reason": reason}
        if extra:
            sig.update(extra)
        signals.append(sig)

    def _finalize(self, signals: list[dict], payloads: list[str]) -> GatewayVerdict:
        effective = [s["score"] for s in signals if s["score"] >= 0]
        score = max(effective) if effective else 0
        unverified = [s["engine"] for s in signals if s["score"] == -1]
        summary = LABELS[score]
        if score == 0 and unverified:
            summary = "SAFE (some checks unverified: " + ", ".join(unverified) + ")"
        # Attach Khmer localization to each signal and the summary.
        for s in signals:
            s["reason_km"] = localize_signal(s)
        summary_km = localize_summary(score, bool(unverified))
        return GatewayVerdict(score, LABELS[score], summary, summary_km, signals, payloads)

    # -- entry points --------------------------------------------------------
    def analyze_text(self, text: str) -> GatewayVerdict:
        signals: list[dict] = []
        s = self.nlp.analyze(text)
        self._push(signals, "nlp_khmer", s.status, s.score, s.reason,
                   {"matches": s.matches, "urls": s.urls})
        return self._finalize(signals, [])

    def _analyze_payload(self, signals: list[dict], raw: str) -> None:
        """Run KHQR validity, offline identity/routing, and (if a token is set)
        Bakong account-existence on a single payload string."""
        v = self.khqr.inspect(raw)
        self._push(signals, "khqr_core", v.status, v.score, v.reason, {"fields": v.fields})
        if not v.fields:
            return

        # Offline cross-field identity/routing check — the real overlay defense.
        ident = self.identity.check(
            v.fields.get("display_name", ""), v.fields.get("account_id"),
            v.fields.get("account_type", "unknown"), v.fields.get("acquiring_bank"))
        self._push(signals, "identity_match", ident.status, ident.score, ident.reason,
                   {"claimed_brand": ident.claimed_brand, "routing_brand": ident.routing_brand})

        # Optional: Bakong account-existence verification (only if a token is
        # configured — the public API cannot resolve account -> holder name).
        if self.bakong.token:
            bk = self.bakong.verify(v.fields.get("account_id"), v.fields.get("display_name"))
            self._push(signals, "bakong_verify", bk.status, bk.score, bk.reason,
                       {"registered_name": bk.registered_name})

    def analyze_khqr(self, raw: str) -> GatewayVerdict:
        signals: list[dict] = []
        self._analyze_payload(signals, raw)
        return self._finalize(signals, [raw])

    def analyze_image_bytes(self, data: bytes) -> GatewayVerdict:
        signals: list[dict] = []
        ov = self.vision.analyze_bytes(data)
        self._push(signals, "vision_overlay", ov.status, ov.score, ov.reason,
                   {"qr_count": ov.qr_count})

        # No QR decoded -> we analysed NOTHING. Never imply "safe": return a
        # neutral "couldn't read" caution so the user doesn't assume it's fine.
        if not ov.payloads:
            return GatewayVerdict(
                1, "UNREADABLE",
                "Could not read a QR in this image — not analysed. "
                "Send a clearer photo or crop to just the QR.",
                "⚠️ មិនអាចអាន QR បានទេ — មិនទាន់បានពិនិត្យ។ "
                "សូមថតរូបឱ្យច្បាស់ ឬកាត់យកតែ QR រួចផ្ញើម្ដងទៀត។",
                signals, [])

        for p in ov.payloads:
            self._analyze_payload(signals, p)
        return self._finalize(signals, ov.payloads)


if __name__ == "__main__":
    g = NethGateway()
    print(g.analyze_text("អ្នកបានឈ្នះរង្វាន់! ចុចលីង bit.ly/x បន្ទាន់").as_dict())
