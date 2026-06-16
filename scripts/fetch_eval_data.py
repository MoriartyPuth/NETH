#!/usr/bin/env python3
"""
NETH - fetch real evaluation data for measuring URL accuracy.

Pulls malicious URLs from URLhaus (abuse.ch, free, no key) and benign sites from
the Tranco top-list, samples N of each, and writes eval_data/phish.txt and
eval_data/benign.txt — ready for `python bench_urls.py --phish ... --benign ...`.

Usage:
    python scripts/fetch_eval_data.py --n 500
"""
from __future__ import annotations

import argparse
import csv
import io
import random
import sys
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
TRANCO_ZIP = "https://tranco-list.eu/top-1m.csv.zip"
OUT_DIR = Path("eval_data")


def _get(url: str, timeout: int = 60) -> bytes:
    req = Request(url, headers={"User-Agent": "neth-eval/0.1"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - trusted feeds
        return resp.read()


def fetch_phish(n: int) -> list[str]:
    print(f"↓ URLhaus recent feed …")
    text = _get(URLHAUS_CSV).decode("utf-8", errors="replace")
    urls = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        # CSV: id,dateadded,url,url_status,...
        parts = next(csv.reader([line]), [])
        if len(parts) >= 3 and parts[2].startswith("http"):
            urls.append(parts[2])
    random.shuffle(urls)
    return urls[:n]


def fetch_benign(n: int) -> list[str]:
    print(f"↓ Tranco top-list …")
    blob = _get(TRANCO_ZIP)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        name = zf.namelist()[0]
        rows = zf.read(name).decode("utf-8", errors="replace").splitlines()
    domains = [r.split(",")[-1].strip() for r in rows if r.strip()]
    return ["https://" + d for d in domains[: n * 2]][:n]


def main() -> None:
    ap = argparse.ArgumentParser(description="Fetch URL eval data (URLhaus + Tranco).")
    ap.add_argument("--n", type=int, default=500, help="samples per class")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    random.seed(args.seed)
    OUT_DIR.mkdir(exist_ok=True)

    try:
        phish = fetch_phish(args.n)
        benign = fetch_benign(args.n)
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"download failed ({exc}). Check your connection / feed availability.")

    (OUT_DIR / "phish.txt").write_text("\n".join(phish), encoding="utf-8")
    (OUT_DIR / "benign.txt").write_text("\n".join(benign), encoding="utf-8")
    print(f"✓ wrote {len(phish)} phishing -> {OUT_DIR/'phish.txt'}")
    print(f"✓ wrote {len(benign)} benign   -> {OUT_DIR/'benign.txt'}")
    print(f"\nNext: python bench_urls.py --phish {OUT_DIR/'phish.txt'} "
          f"--benign {OUT_DIR/'benign.txt'} --sweep")


if __name__ == "__main__":
    main()
