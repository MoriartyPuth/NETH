#!/usr/bin/env python3
"""
NETH - KHQR & Phishing Scam Detection Gateway
khqr_core.py : EMVCo/KHQR parser + validity and identity checks.

This is the corrected core. Two important design notes:

  1. CRC/TLV validation is a *validity pre-filter*, not a fraud detector.
     A real overlay scam uses a perfectly valid KHQR pointing at the
     attacker's own account. The fraud signal lives in the *identity*
     (Tag 29/30 account id -> registered holder name), not the checksum.

  2. TLV is positional. Tags are found by walking the string tag-by-tag
     from offset 0, never by str.index("59").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

try:
    import crccheck
except ImportError:  # keep the parser usable without the dep installed
    crccheck = None


# ---- EMVCo / KHQR tag reference -------------------------------------------
TAG_PAYLOAD_FORMAT = "00"   # "01"
TAG_POINT_OF_INIT = "01"    # "11" static, "12" dynamic
TAG_MERCHANT_INDIV = "29"   # Bakong individual account template (nested)
TAG_MERCHANT_MERCH = "30"   # Bakong merchant account template (nested)
TAG_MCC = "52"
TAG_CURRENCY = "53"         # 116 = KHR, 840 = USD
TAG_AMOUNT = "54"
TAG_COUNTRY = "58"          # "KH"
TAG_MERCHANT_NAME = "59"
TAG_CITY = "60"
TAG_ADDITIONAL = "62"       # nested
TAG_CRC = "63"

# Nested subtags inside 29 / 30
SUB_GUID = "00"             # "kh.gov.nbc.bakong"
SUB_ACCOUNT = "01"          # the bakong account id, e.g. name@aclb
SUB_ACQ_BANK = "02"         # acquiring bank (merchant template)

KNOWN_BANK_KEYWORDS = ["aba", "acleda", "bakong", "wing", "canadia", "aclb"]


# ---- Parse results ---------------------------------------------------------
@dataclass
class TLVNode:
    tag: str
    value: str
    children: dict[str, "TLVNode"] = field(default_factory=dict)


@dataclass
class Verdict:
    status: str          # SAFE | SUSPICIOUS | BLOCKED | INVALID
    score: int           # 0 safe, 1 suspicious, 2 blocked, -1 not-a-khqr
    reason: str
    fields: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "score": self.score,
            "reason": self.reason,
            "fields": self.fields,
        }


# ---- Core engine -----------------------------------------------------------
class NethKHQREngine:
    def __init__(self) -> None:
        self.known_bank_keywords = KNOWN_BANK_KEYWORDS

    # -- TLV walker ----------------------------------------------------------
    def parse_tlv(self, data: str) -> dict[str, TLVNode]:
        """Walk an EMVCo TLV string positionally. Raises ValueError on malformed input."""
        nodes: dict[str, TLVNode] = {}
        i = 0
        n = len(data)
        while i < n:
            if i + 4 > n:
                raise ValueError(f"Truncated tag/length header at offset {i}")
            tag = data[i:i + 2]
            length_str = data[i + 2:i + 4]
            if not length_str.isdigit():
                raise ValueError(f"Non-numeric length '{length_str}' for tag {tag} at offset {i}")
            length = int(length_str)
            start = i + 4
            end = start + length
            if end > n:
                raise ValueError(f"Tag {tag} length {length} overruns payload (offset {start})")
            value = data[start:end]
            nodes[tag] = TLVNode(tag=tag, value=value)
            i = end
        return nodes

    def calculate_crc16(self, payload: str) -> str:
        """CRC-16/CCITT-FALSE over the payload *including* the '6304' header, zero-padded to 4 hex."""
        if crccheck is None:
            raise RuntimeError("crccheck not installed: pip install crccheck")
        crc = crccheck.crc.Crc16CcittFalse()
        crc.process(payload.encode("ascii"))
        return crc.finalhex().upper().zfill(4)

    # -- Account / identity helpers -----------------------------------------
    def extract_account(self, nodes: dict[str, TLVNode]) -> tuple[Optional[str], Optional[str], str]:
        """Return (account_id, acquiring_bank, account_type) from Tag 29/30."""
        for tag, kind in ((TAG_MERCHANT_MERCH, "merchant"), (TAG_MERCHANT_INDIV, "individual")):
            node = nodes.get(tag)
            if node is None:
                continue
            sub = self.parse_tlv(node.value)
            account_id = sub.get(SUB_ACCOUNT).value if SUB_ACCOUNT in sub else None
            acq_bank = sub.get(SUB_ACQ_BANK).value if SUB_ACQ_BANK in sub else None
            return account_id, acq_bank, kind
        return None, None, "unknown"

    # -- Top-level inspection -----------------------------------------------
    def inspect(self, raw: str) -> Verdict:
        raw = raw.strip()

        # 0) Is this even a KHQR? (validity pre-filter, NOT a malicious verdict)
        if not raw.startswith("000201"):
            return Verdict("INVALID", -1, "Not an EMVCo/KHQR payload (missing format indicator).")

        if len(raw) < 8 or raw[-8:-4] != TAG_CRC + "04":
            return Verdict("INVALID", -1, "Malformed: CRC tag '6304' not found in final position.")

        # 1) CRC integrity (cheap corruption/garbage filter)
        body = raw[:-4]                 # everything up to and including '6304'
        provided_crc = raw[-4:].upper()
        try:
            expected_crc = self.calculate_crc16(body)
        except RuntimeError as exc:
            return Verdict("INVALID", -1, str(exc))
        if expected_crc != provided_crc:
            return Verdict(
                "SUSPICIOUS", 1,
                f"CRC mismatch (expected {expected_crc}, got {provided_crc}); payload corrupted or hand-edited.",
            )

        # 2) Structural parse over the FULL payload (incl. the 6304 CRC tag,
        #    which is a valid TLV node). CRC above was computed over `body` only.
        try:
            nodes = self.parse_tlv(raw)
        except ValueError as exc:
            return Verdict("SUSPICIOUS", 1, f"TLV structure error: {exc}")

        display_name = nodes.get(TAG_MERCHANT_NAME).value if TAG_MERCHANT_NAME in nodes else ""
        account_id, acq_bank, acct_type = self.extract_account(nodes)
        fields = {
            "display_name": display_name,
            "account_id": account_id,
            "acquiring_bank": acq_bank,
            "account_type": acct_type,
            "amount": nodes.get(TAG_AMOUNT).value if TAG_AMOUNT in nodes else None,
            "currency": nodes.get(TAG_CURRENCY).value if TAG_CURRENCY in nodes else None,
        }

        # 3) Structural + CRC checks pass. Identity/routing analysis is delegated
        #    to identity_match (offline Tag 59 vs Tag 29/30 cross-field check).
        #    NOTE: the Bakong public API does NOT resolve account id -> holder
        #    name, so the cross-field routing check — not a name lookup — is the
        #    real overlay defense.
        return Verdict("SAFE", 0, "Structure and CRC valid.", fields)


if __name__ == "__main__":
    engine = NethKHQREngine()
    samples = [
        # malformed / not a KHQR
        "hello world",
        # structurally fine but CRC will not match (so SUSPICIOUS, not 'SAFE')
        "00020101021129180014aba@abakhppxxx5912ABA Merchant6304ABCD",
    ]
    for s in samples:
        v = engine.inspect(s)
        print(f"[{v.status:10}] score={v.score}  {v.reason}")
