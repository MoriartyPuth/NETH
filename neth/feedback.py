#!/usr/bin/env python3
"""
NETH - user feedback capture.

A safety tool with no feedback loop can never improve and has no ground truth.
This stores user corrections ("you said safe but it was a scam") in a local
SQLite DB. Two payoffs:

  1. Ground truth to MEASURE real-world accuracy over time.
  2. A growing labeled corpus to TRAIN the Khmer NLP model (the dataset NETH
     is currently missing).

Privacy: we store a short EXCERPT (truncated) of the input, never full financial
payloads or message bodies, plus a hash for dedup. Keep the DB out of git.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "feedback.db"
EXCERPT_LEN = 280
VALID_LABELS = {"safe", "suspicious", "scam"}


class FeedbackStore:
    def __init__(self, db_path: Path = DEFAULT_DB) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    input_type TEXT NOT NULL,
                    input_excerpt TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    predicted_score INTEGER NOT NULL,
                    correct_label TEXT NOT NULL,
                    note TEXT
                )"""
            )

    def record(self, input_type: str, input_excerpt: str, predicted_score: int,
               correct_label: str, note: str = "") -> int:
        label = (correct_label or "").strip().lower()
        if label not in VALID_LABELS:
            raise ValueError(f"correct_label must be one of {sorted(VALID_LABELS)}")
        excerpt = (input_excerpt or "")[:EXCERPT_LEN]
        digest = hashlib.sha256((input_excerpt or "").encode("utf-8")).hexdigest()[:16]
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO feedback (ts, input_type, input_excerpt, input_hash, "
                "predicted_score, correct_label, note) VALUES (?,?,?,?,?,?,?)",
                (time.time(), input_type[:16], excerpt, digest,
                 int(predicted_score), label, (note or "")[:EXCERPT_LEN]),
            )
            return int(cur.lastrowid)

    def stats(self) -> dict:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
            by_label = {r["correct_label"]: r["n"] for r in c.execute(
                "SELECT correct_label, COUNT(*) n FROM feedback GROUP BY correct_label")}
            # a "miss" = user says scam but we predicted safe (score 0)
            misses = c.execute(
                "SELECT COUNT(*) FROM feedback WHERE correct_label='scam' AND predicted_score=0"
            ).fetchone()[0]
        return {"total": total, "by_label": by_label, "scam_missed_as_safe": misses}

    def export_jsonl(self, out_path: str | Path) -> int:
        """Dump labeled rows as JSONL for model training."""
        out = Path(out_path)
        n = 0
        with self._conn() as c, out.open("w", encoding="utf-8") as fh:
            for r in c.execute("SELECT * FROM feedback ORDER BY id"):
                fh.write(json.dumps({
                    "input_type": r["input_type"], "text": r["input_excerpt"],
                    "label": r["correct_label"], "predicted_score": r["predicted_score"],
                }, ensure_ascii=False) + "\n")
                n += 1
        return n


if __name__ == "__main__":
    store = FeedbackStore(Path("data") / "feedback_demo.db")
    store.record("text", "អ្នកបានឈ្នះរង្វាន់...", 0, "scam", "missed obvious phishing")
    print(store.stats())
