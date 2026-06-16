#!/usr/bin/env python3
"""
NETH - offline identity / routing cross-field check (blueprint ANOMALY_02).

The strongest anti-overlay signal that needs NO API: a KHQR's displayed name
(Tag 59) should be consistent with where the money actually routes
(Tag 29 individual / Tag 30 merchant account + bank code). A scammer who pastes
their personal wallet QR under a trusted label trips one of:

  * NAME/ROUTING MISMATCH - name claims bank X, account routes to bank Y.
  * PERSONAL-ACCOUNT-AS-MERCHANT - name claims an institution/merchant but the
    payment uses an individual (Tag 29) account, not a registered merchant one.

Design is CONSERVATIVE: it only declares a hard mismatch when BOTH the claimed
brand and the routing brand are known. An unknown routing code never produces a
false alarm — it downgrades to "could not verify routing".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .url_reputation import CANONICAL_BANK_DOMAINS  # brand slugs are the keys

try:
    import yaml
except ImportError:
    yaml = None

_CODES_FILE = Path(__file__).resolve().parent.parent / "data" / "bank_codes.yaml"

# Built-in fallback if the YAML is missing.
DEFAULT_CODE_PREFIXES: dict[str, str] = {
    "aba": "aba", "aclb": "acleda", "cadi": "canadia", "wing": "wing",
}

# Extra name aliases beyond the brand slug itself (slug is always included).
NAME_ALIASES: dict[str, list[str]] = {
    "truemoney": ["true money", "truemoney"],
    "campu": ["public bank", "campu"],
    "jtrust": ["j trust", "jtrust", "royal"],
}


def load_code_prefixes(path: Path = _CODES_FILE) -> dict[str, str]:
    if yaml is None or not path.exists():
        return dict(DEFAULT_CODE_PREFIXES)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        codes = data.get("code_prefixes", {}) or {}
        result = {str(k).lower(): str(v).lower() for k, v in codes.items()}
        return result or dict(DEFAULT_CODE_PREFIXES)
    except Exception as exc:  # noqa: BLE001
        print(f"[identity_match] failed to load {path} ({exc}); using built-ins.")
        return dict(DEFAULT_CODE_PREFIXES)


@dataclass
class IdentitySignal:
    status: str           # OK | SUSPICIOUS | MISMATCH | UNVERIFIED
    score: int            # 0 ok, 1 caution, 2 block, -1 nothing to check
    reason: str
    claimed_brand: str | None = None
    routing_brand: str | None = None
    details: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return self.__dict__.copy()


class IdentityMatcher:
    def __init__(self) -> None:
        self.code_prefixes = load_code_prefixes()
        self.brands = list(CANONICAL_BANK_DOMAINS.keys())

    # -- brand from the displayed name (Tag 59) ------------------------------
    def brand_in_name(self, name: str) -> str | None:
        low = (name or "").lower()
        tokens = [t for t in re.split(r"[^a-z0-9]+", low) if t]
        for brand in self.brands:
            aliases = [brand] + NAME_ALIASES.get(brand, [])
            for alias in aliases:
                if " " in alias:
                    if alias in low:
                        return brand
                elif any(tok.startswith(alias) for tok in tokens):
                    return brand
        return None

    # -- brand from the routing (account suffix / acquiring BIC) --------------
    def brand_from_routing(self, account_id: str | None, acquiring_bank: str | None) -> str | None:
        candidates = []
        if account_id and "@" in account_id:
            candidates.append(account_id.split("@")[-1].lower())
        if acquiring_bank:
            candidates.append(acquiring_bank.lower())
        for routing in candidates:
            for prefix, brand in self.code_prefixes.items():
                if routing.startswith(prefix):
                    return brand
        return None

    # -- main ----------------------------------------------------------------
    def check(self, display_name: str, account_id: str | None,
              account_type: str, acquiring_bank: str | None = None) -> IdentitySignal:
        claimed = self.brand_in_name(display_name)
        routing = self.brand_from_routing(account_id, acquiring_bank)
        details = {"account_id": account_id, "account_type": account_type,
                   "acquiring_bank": acquiring_bank}

        if not claimed:
            return IdentitySignal("OK", 0, "Name makes no bank/institution claim to cross-check.",
                                  None, routing, details)

        # Hard mismatch: name says one bank, money routes to another.
        if routing and routing != claimed:
            return IdentitySignal(
                "MISMATCH", 2,
                f"Routing mismatch: name claims '{claimed.upper()}' but the account routes to "
                f"'{routing.upper()}'. Classic overlay-scam pattern — do not pay.",
                claimed, routing, details)

        # Name claims an institution but it's a personal/individual account.
        if account_type == "individual":
            return IdentitySignal(
                "SUSPICIOUS", 1,
                f"Name claims '{claimed.upper()}' but payment uses an individual (personal) "
                f"account, not a registered merchant account. Verify the recipient.",
                claimed, routing, details)

        # Routing confirms the claimed brand.
        if routing and routing == claimed:
            return IdentitySignal("OK", 0, f"Name and account routing both indicate '{claimed.upper()}'.",
                                  claimed, routing, details)

        # Merchant account but routing code unknown — can't confirm or deny.
        return IdentitySignal(
            "UNVERIFIED", -1,
            f"Name claims '{claimed.upper()}'; routing bank code unknown, could not confirm. "
            f"Match the name against your banking app before paying.",
            claimed, routing, details)


if __name__ == "__main__":
    m = IdentityMatcher()
    cases = [
        ("ABA Merchant", "sokha@aclb", "individual", None),   # claims ABA, routes ACLEDA
        ("ABA Bank", "shop@aba", "merchant", "ABAAKHPP"),      # consistent
        ("ABA Merchant", "sokha@aba", "individual", None),     # personal acct as merchant
        ("Borey Coffee", "borey@wing", "individual", None),    # no bank claim
    ]
    for name, acc, typ, bic in cases:
        s = m.check(name, acc, typ, bic)
        print(f"[{s.status:10}] score={s.score:>2}  {s.reason}")
