#!/usr/bin/env python3
"""
NETH - whole-gateway benchmark (text + KHQR), not just URLs.

Runs labeled inputs through the full NethGateway and reports precision / recall /
F1 / accuracy per modality. Ships a small bundled labeled set so it runs offline;
point --phish-text / --benign-text at your own files for a real number.

    python bench_gateway.py
    python bench_gateway.py --phish-text scams.txt --benign-text normal.txt
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass

from neth.khqr_core import NethKHQREngine
from neth.scoring import NethGateway

# --- bundled labeled TEXT (1 = phishing, 0 = benign) ------------------------
PHISH_TEXT = [
    "អ្នកបានឈ្នះរង្វាន់ពី ABA! ចុចលីង bit.ly/x បន្ទាន់!",
    "គណនី Wing របស់អ្នកនឹងត្រូវបិទ។ ផ្ទៀងផ្ទាត់ឥឡូវនេះ៖ http://wing-verify.xyz",
    "Your ACLEDA account is suspended, verify: http://acleda-secure.top/login",
    "ផ្ញើលេខកូដ OTP មកយើងដើម្បីទទួលប្រាក់រង្វាន់ឥតគិតថ្លៃ",
    "លោកអ្នកបានឈ្នះ iPhone! ចុចទីនេះ http://prize.click បន្ទាន់",
    "Congratulations! Claim your loan now at http://aba-loan.tk",
]
BENIGN_TEXT = [
    "សួស្តី ពេលណាជួបគ្នា?",
    "ប្អូនអាចផ្ញើរូបភាពម្ហូបបានទេ?",
    "Meeting at 3pm tomorrow, see you there",
    "ថ្ងៃនេះម៉ោងប៉ុន្មានយើងជួបគ្នា?",
    "សូមអរគុណសម្រាប់ការទិញទំនិញ",
    "Can you send me the report when you get a chance",
]


def _tlv(tag: str, val: str) -> str:
    return f"{tag}{len(val):02d}{val}"


def _khqr(name: str, account: str, merchant: bool = True) -> str:
    eng = NethKHQREngine()
    acct_tag = "30" if merchant else "29"
    acct_val = _tlv("00", "kh.gov.nbc.bakong") + _tlv("01", account)
    body = (_tlv("00", "01") + _tlv("01", "11") + _tlv(acct_tag, acct_val)
            + _tlv("53", "116") + _tlv("58", "KH") + _tlv("59", name)
            + _tlv("60", "Phnom Penh") + "6304")
    return body + eng.calculate_crc16(body)


# --- bundled labeled KHQR (1 = scam, 0 = legit) -----------------------------
def khqr_samples() -> tuple[list[str], list[str]]:
    scam = [
        _khqr("ABA Merchant", "sokha@aclb"),     # claims ABA, routes ACLEDA
        _khqr("Wing Pay", "x@aclb"),             # claims Wing, routes ACLEDA
        _khqr("ACLEDA Bank", "y@aba"),           # claims ACLEDA, routes ABA
    ]
    legit = [
        _khqr("ABA Bank", "shop@aba"),
        _khqr("Canadia", "z@cadi"),
        _khqr("Borey Coffee", "borey@wing"),     # no institutional claim
    ]
    return scam, legit


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, is_pos: bool, pred_pos: bool) -> None:
        if is_pos and pred_pos: self.tp += 1
        elif is_pos: self.fn += 1
        elif pred_pos: self.fp += 1
        else: self.tn += 1

    def line(self, name: str) -> str:
        p = self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
        r = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        acc = (self.tp + self.tn) / max(self.tp + self.fp + self.fn + self.tn, 1)
        return (f"{name:10} prec={p:.2f} recall={r:.2f} F1={f1:.2f} acc={acc:.2f} "
                f"(TP/FP/FN/TN {self.tp}/{self.fp}/{self.fn}/{self.tn})")


def load_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def main() -> None:
    ap = argparse.ArgumentParser(description="Whole-gateway benchmark.")
    ap.add_argument("--phish-text")
    ap.add_argument("--benign-text")
    ap.add_argument("--threshold", type=int, default=1,
                    help="min score to count as flagged (default 1 = not-safe)")
    args = ap.parse_args()

    g = NethGateway()
    t = args.threshold

    phish_text = load_lines(args.phish_text) if args.phish_text else PHISH_TEXT
    benign_text = load_lines(args.benign_text) if args.benign_text else BENIGN_TEXT

    text_m = Metrics()
    for msg in phish_text:
        text_m.add(True, g.analyze_text(msg).score >= t)
    for msg in benign_text:
        text_m.add(False, g.analyze_text(msg).score >= t)

    scam_qr, legit_qr = khqr_samples()
    qr_m = Metrics()
    for qr in scam_qr:
        qr_m.add(True, g.analyze_khqr(qr).score >= t)
    for qr in legit_qr:
        qr_m.add(False, g.analyze_khqr(qr).score >= t)

    print(f"NETH gateway benchmark · threshold={t} (flagged = score >= {t})\n")
    print(text_m.line("TEXT"))
    print(qr_m.line("KHQR"))


if __name__ == "__main__":
    main()
