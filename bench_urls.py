#!/usr/bin/env python3
"""
NETH - URL reputation benchmark.

Turns "the link check feels accurate" into measured precision/recall/F1.

Quick offline demo (bundled labeled sample):
    python bench_urls.py

Real evaluation against your own data:
    python bench_urls.py --phish phish.txt --benign tranco.csv --benign-format domain
    python bench_urls.py --online --phish phish.txt --benign benign.txt

File formats: one entry per line; '#' comments ignored. With
--benign-format domain, bare domains (e.g. Tranco rank,domain CSV) are accepted
and the last comma-field is treated as the domain.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass

from neth.url_reputation import URLReputation

# --- bundled labeled sample (offline; no network needed) --------------------
SAMPLE_PHISH = [
    "http://aba-secure.xyz/login",
    "http://ababank.com@evil.tk/",
    "https://acleda-verify.top/account",
    "http://wing-reward.click/claim",
    "https://bakong-update.buzz/otp",
    "http://192.168.10.5/aba",
    "https://aba.com.kh-login.tk/",
    "http://canadia-bank.ml/verify",
    "https://truemoney-bonus.ga/win",
    "http://аbabank.com/login",      # Cyrillic 'а' homoglyph
]
SAMPLE_BENIGN = [
    "https://www.ababank.com/",
    "https://www.acledabank.com.kh/personal",
    "https://wingmoney.com/",
    "https://bakong.nbc.gov.kh/",
    "https://www.nbc.gov.kh/",
    "https://canadiabank.com.kh/",
    "https://www.google.com/",
    "https://web.facebook.com/",
    "https://www.wikipedia.org/",
    "https://github.com/features",
]


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        d = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / d if d else 0.0


def load(path: str, domain_fmt: bool) -> list[str]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if domain_fmt:
                dom = line.split(",")[-1].strip()
                line = dom if "://" in dom else "https://" + dom
            out.append(line)
    return out


def score(rep: URLReputation, urls: list[str], is_phish: bool, threshold: int,
          metrics: Metrics, misses: list) -> None:
    for u in urls:
        weight = rep.analyze(u).weight
        predicted_phish = weight >= threshold
        if is_phish and predicted_phish:
            metrics.tp += 1
        elif is_phish and not predicted_phish:
            metrics.fn += 1
            misses.append(("FN miss", u, weight))
        elif not is_phish and predicted_phish:
            metrics.fp += 1
            misses.append(("FP false-alarm", u, weight))
        else:
            metrics.tn += 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Benchmark NETH URL reputation.")
    ap.add_argument("--phish", help="file of known phishing URLs (label=1)")
    ap.add_argument("--benign", help="file of known-good URLs/domains (label=0)")
    ap.add_argument("--benign-format", choices=["url", "domain"], default="url")
    ap.add_argument("--threshold", type=int, default=2,
                    help="min weight to predict phishing (default 2 = 'not SAFE')")
    ap.add_argument("--sweep", action="store_true", help="show metrics across thresholds 2..6")
    ap.add_argument("--online", action="store_true", help="enable shortener expansion + feeds")
    args = ap.parse_args()

    rep = URLReputation(online=args.online)

    if args.phish or args.benign:
        phish = load(args.phish, False) if args.phish else []
        benign = load(args.benign, args.benign_format == "domain") if args.benign else []
        source = f"{args.phish or '-'} / {args.benign or '-'}"
    else:
        phish, benign = SAMPLE_PHISH, SAMPLE_BENIGN
        source = "bundled sample"

    print(f"NETH URL benchmark  ·  source: {source}  ·  online={args.online}")
    print(f"phishing={len(phish)}  benign={len(benign)}\n")

    thresholds = range(2, 7) if args.sweep else [args.threshold]
    print(f"{'thresh':>6} {'prec':>7} {'recall':>7} {'F1':>7} {'acc':>7}   (TP/FP/FN/TN)")
    detail_misses: list = []
    for t in thresholds:
        m = Metrics()
        misses: list = []
        score(rep, phish, True, t, m, misses)
        score(rep, benign, False, t, m, misses)
        print(f"{t:>6} {m.precision:>7.2f} {m.recall:>7.2f} {m.f1:>7.2f} {m.accuracy:>7.2f}"
              f"   ({m.tp}/{m.fp}/{m.fn}/{m.tn})")
        if t == args.threshold:
            detail_misses = misses

    if detail_misses:
        print(f"\nMisclassified at threshold={args.threshold}:")
        for kind, u, w in detail_misses:
            print(f"  [{kind:15}] w={w}  {u}")
    else:
        print(f"\nNo misclassifications at threshold={args.threshold}.")


if __name__ == "__main__":
    main()
