#!/usr/bin/env python3
"""
NETH - Khmer phishing / social-engineering text detector.

Strategy
--------
Ships with a working *offline heuristic* baseline (weighted Khmer + English
lexicon, URL extraction, lookalike-domain checks) so the gateway is useful on
day one with no model download. A fine-tuned transformer (XLM-RoBERTa +
khmer-nltk segmentation) can be dropped in behind the same `analyze()` API by
setting NETH_NLP_MODEL; the heuristic then becomes a fallback / ensemble member.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .url_reputation import URLReputation

# Weighted signal lexicon. Khmer script + romanised + English, because real
# scam messages mix all three. Weights are additive toward a risk score.
LEXICON: dict[str, int] = {
    # urgency / panic
    "បន្ទាន់": 2, "ឥឡូវនេះ": 1, "ផុតកំណត់": 2, "urgent": 2, "immediately": 2,
    # account threats
    "បិទគណនី": 3, "ផ្អាកគណនី": 3, "គណនីរបស់អ្នក": 1, "suspend": 3, "blocked": 2,
    "verify": 2, "ផ្ទៀងផ្ទាត់": 2, "confirm your": 2,
    # credential / OTP harvesting
    "otp": 3, "លេខកូដ": 2, "ពាក្យសម្ងាត់": 3, "password": 3, "pin": 2,
    # money lures
    "ឈ្នះ": 3, "រង្វាន់": 3, "win": 2, "prize": 3, "reward": 2, "lucky": 2,
    "ឥណទាន": 2, "ប្រាក់កម្ចី": 2, "loan": 2, "វិនិយោគ": 2, "investment": 2,
    "ប្រាក់ឥតគិតថ្លៃ": 3, "free money": 3, "ទទួលបាន": 1,
    # action triggers
    "ចុចលីង": 2, "ចុចទីនេះ": 2, "click here": 2, "click the link": 2,
    "ផ្ទេរប្រាក់": 2, "transfer": 1,
}

@dataclass
class TextSignal:
    status: str            # SAFE | SUSPICIOUS | BLOCKED
    score: int             # 0 | 1 | 2
    reason: str
    matches: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    raw_weight: int = 0

    def as_dict(self) -> dict:
        return {
            "status": self.status, "score": self.score, "reason": self.reason,
            "matches": self.matches, "urls": self.urls, "raw_weight": self.raw_weight,
        }


class KhmerPhishingDetector:
    def __init__(self, url_rep: URLReputation | None = None) -> None:
        self.model = None
        self.url_rep = url_rep or URLReputation()
        model_path = os.environ.get("NETH_NLP_MODEL")
        if model_path:
            self._try_load_transformer(model_path)

    def _try_load_transformer(self, path: str) -> None:
        try:
            from transformers import (AutoModelForSequenceClassification,
                                      AutoTokenizer, pipeline)
            tok = AutoTokenizer.from_pretrained(path)
            mdl = AutoModelForSequenceClassification.from_pretrained(path)
            self.model = pipeline("text-classification", model=mdl, tokenizer=tok)
        except Exception as exc:  # noqa: BLE001 - degrade gracefully to heuristic
            print(f"[nlp_khmer] transformer load failed ({exc}); using heuristic.")
            self.model = None

    # -- helpers -------------------------------------------------------------
    def extract_urls(self, text: str) -> list[str]:
        return self.url_rep.find_urls(text)

    def _url_risk(self, urls: list[str]) -> tuple[int, list[str]]:
        """Delegate per-URL scoring to the reputation engine."""
        weight, notes = 0, []
        for u in urls:
            verdict = self.url_rep.analyze(u)
            weight += verdict.weight
            notes += [f"{u}: {r}" for r in verdict.reasons]
        return weight, notes

    # -- main API ------------------------------------------------------------
    def analyze(self, text: str) -> TextSignal:
        text = (text or "").strip()
        if not text:
            return TextSignal("SAFE", 0, "Empty input.")

        low = text.lower()
        matches = [kw for kw in LEXICON if kw.lower() in low]
        weight = sum(LEXICON[kw] for kw in matches)

        urls = self.extract_urls(text)
        url_weight, url_notes = self._url_risk(urls)
        weight += url_weight
        matches += url_notes

        # Optional transformer as an ensemble booster.
        if self.model is not None:
            try:
                pred = self.model(text[:512])[0]
                if pred["label"].lower() not in ("legit", "label_0", "safe"):
                    weight += int(3 * float(pred.get("score", 0)))
                    matches.append(f"model:{pred['label']}({pred['score']:.2f})")
            except Exception:  # noqa: BLE001
                pass

        if weight >= 5:
            status, score = "BLOCKED", 2
            reason = "High-confidence Khmer phishing pattern (urgency + credential/money + link)."
        elif weight >= 2:
            status, score = "SUSPICIOUS", 1
            reason = "Some social-engineering markers present; verify the sender independently."
        else:
            status, score = "SAFE", 0
            reason = "No notable phishing markers."

        return TextSignal(status, score, reason, matches, urls, weight)


if __name__ == "__main__":
    d = KhmerPhishingDetector()
    tests = [
        "សួស្តី ពេលណាជួបគ្នា?",
        "អ្នកបានឈ្នះរង្វាន់ពី ABA! ចុចលីងនេះដើម្បីទទួលប្រាក់ bit.ly/xx បន្ទាន់!",
        "Your ABA account will be suspended. Verify now: http://aba-secure.xyz/login",
    ]
    for t in tests:
        s = d.analyze(t)
        print(f"[{s.status:10}] w={s.raw_weight:<2} {s.reason}  {s.matches}")
