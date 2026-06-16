#!/usr/bin/env python3
"""
NETH - Bakong account-name resolution.

THE single most important fraud signal for QR-overlay scams: an attacker's
pasted QR is structurally perfect, so the only way to catch it is to resolve
the embedded account id to the *registered holder name* and compare it against
who the user believes they are paying.

The NBC Bakong Open API exposes account lookups. Provide a token via
NETH_BAKONG_TOKEN (and optionally NETH_BAKONG_BASE) to enable live checks.
Without a token the module returns UNVERIFIED so the gateway degrades safely
instead of giving false assurance.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

try:
    import requests
except ImportError:
    requests = None

DEFAULT_BASE = os.environ.get("NETH_BAKONG_BASE", "https://api-bakong.nbc.gov.kh")


@dataclass
class AccountIdentity:
    status: str            # VERIFIED | MISMATCH | UNKNOWN_ACCOUNT | UNVERIFIED | ERROR
    score: int             # 0 ok, 1 caution, 2 mismatch/block, -1 not-checked
    account_id: str | None
    registered_name: str | None
    claimed_name: str | None
    reason: str

    def as_dict(self) -> dict:
        return self.__dict__.copy()


class BakongVerifier:
    def __init__(self, token: str | None = None, base: str = DEFAULT_BASE) -> None:
        self.token = token or os.environ.get("NETH_BAKONG_TOKEN")
        self.base = base.rstrip("/")

    @staticmethod
    def _norm(name: str) -> str:
        return "".join(ch for ch in (name or "").lower() if ch.isalnum())

    def lookup(self, account_id: str) -> tuple[str | None, str | None]:
        """Return (registered_name, error). Hits the Bakong account endpoint."""
        if not self.token:
            return None, "no-token"
        if requests is None:
            return None, "requests-not-installed"
        try:
            resp = requests.post(
                f"{self.base}/v1/check_account_by_account_id",
                json={"account_id": account_id},
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=8,
            )
            if resp.status_code != 200:
                return None, f"http-{resp.status_code}"
            data = resp.json()
            # API shape: {"responseCode":0,"data":{"accountName":"..."}}
            if data.get("responseCode") not in (0, None):
                return None, "account-not-found"
            name = (data.get("data") or {}).get("accountName")
            return name, None
        except Exception as exc:  # noqa: BLE001
            return None, f"request-error:{exc}"

    def verify(self, account_id: str | None, claimed_name: str | None) -> AccountIdentity:
        if not account_id:
            return AccountIdentity("UNVERIFIED", -1, account_id, None, claimed_name,
                                   "No account id present in payload.")
        registered, err = self.lookup(account_id)
        if err == "no-token":
            return AccountIdentity("UNVERIFIED", -1, account_id, None, claimed_name,
                                   "Bakong token not configured; identity not verified.")
        if err == "account-not-found":
            return AccountIdentity("UNKNOWN_ACCOUNT", 2, account_id, None, claimed_name,
                                   f"Account '{account_id}' is not a registered Bakong account.")
        if err:
            return AccountIdentity("ERROR", -1, account_id, None, claimed_name,
                                   f"Verification unavailable ({err}).")

        if claimed_name and self._norm(registered) != self._norm(claimed_name):
            return AccountIdentity("MISMATCH", 2, account_id, registered, claimed_name,
                                   f"Name mismatch: QR shows '{claimed_name}' but account "
                                   f"is registered to '{registered}'. Likely overlay scam.")
        return AccountIdentity("VERIFIED", 0, account_id, registered, claimed_name,
                               f"Account verified as '{registered}'.")


if __name__ == "__main__":
    v = BakongVerifier()
    print(v.verify("aba@abakhppxxx", "ABA Merchant").as_dict())
