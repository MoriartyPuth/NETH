#!/usr/bin/env python3
"""
NETH - URL reputation.

Replaces the old naive "brand-in-string + suspicious-TLD" guess with layered
checks, ordered cheapest-first:

  OFFLINE (always on, no key, no network)
    * registrable-domain extraction (handles .com.kh style multi-part TLDs)
    * brand-off-domain: bank name in host but registrable domain not canonical
    * punycode / non-ASCII homoglyph hosts
    * IP-literal hosts, userinfo '@' tricks, shortener detection
    * cheap/abused TLDs (weak signal)

  ONLINE (opt-in)
    * shortener expansion (follow redirects to the real destination)
    * threat feeds: URLhaus (NETH_URLHAUS_KEY) and Google Safe Browsing
      (NETH_GSB_KEY). A feed hit is decisive (BLOCKED on its own).

Offline checks give a usable prior; the feeds are what make it *measurable*.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

try:
    import yaml
except ImportError:
    yaml = None

# Built-in fallback if data/bank_domains.yaml is missing or PyYAML isn't
# installed. The full, extensible list lives in that YAML file.
DEFAULT_BANK_DOMAINS: dict[str, set[str]] = {
    "aba": {"ababank.com", "abamobile.com"},
    "acleda": {"acledabank.com", "acledabank.com.kh"},
    "wing": {"wingmoney.com", "wingbank.com.kh"},
    "bakong": {"bakong.nbc.gov.kh", "nbc.gov.kh"},
    "nbc": {"nbc.gov.kh", "nbc.org.kh"},
    "canadia": {"canadiabank.com.kh"},
    "truemoney": {"truemoney.com.kh", "truemoney.com"},
}

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "bank_domains.yaml"


def load_bank_domains(path: Path = _DATA_FILE) -> dict[str, set[str]]:
    """Load brand -> {official domains} from YAML; fall back to built-ins."""
    if yaml is None or not path.exists():
        return {k: set(v) for k, v in DEFAULT_BANK_DOMAINS.items()}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        banks = data.get("banks", {})
        result: dict[str, set[str]] = {}
        for brand, info in banks.items():
            domains = info.get("domains", []) if isinstance(info, dict) else info
            if domains:
                result[str(brand).lower()] = {str(d).lower() for d in domains}
        return result or {k: set(v) for k, v in DEFAULT_BANK_DOMAINS.items()}
    except Exception as exc:  # noqa: BLE001 - never let bad data break parsing
        print(f"[url_reputation] failed to load {path} ({exc}); using built-ins.")
        return {k: set(v) for k, v in DEFAULT_BANK_DOMAINS.items()}


# Canonical brand domains and the union of every official domain (a host on any
# of these is legit regardless of which brand token it contains — fixes 'aba'
# matching inside 'acledabank').
CANONICAL_BANK_DOMAINS: dict[str, set[str]] = load_bank_domains()
ALL_CANONICAL_DOMAINS: set[str] = {d for s in CANONICAL_BANK_DOMAINS.values() for d in s}

SHORTENERS = {
    "bit.ly", "t.me", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly", "t.co", "lnkd.in", "s.id",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "live", "tk", "ml", "ga", "cf", "buzz", "rest",
    "monster", "quest", "country", "kim", "work", "fit", "gq",
}

# Second-level labels that act like TLDs (so example.com.kh -> example.com.kh).
MULTIPART_SLDS = {"com", "net", "org", "gov", "edu", "mil", "per", "co", "biz"}

URL_RE = re.compile(r"https?://[^\s<>\"']+|(?:www\.)[^\s<>\"']+", re.IGNORECASE)


@dataclass
class URLVerdict:
    url: str
    weight: int
    status: str                      # SAFE | SUSPICIOUS | BLOCKED
    reasons: list[str] = field(default_factory=list)
    final_url: str | None = None     # after shortener expansion
    registrable: str | None = None


class URLReputation:
    def __init__(self, online: bool | None = None) -> None:
        env = os.environ.get("NETH_URL_ONLINE", "").lower() in ("1", "true", "yes")
        self.online = env if online is None else online
        self.urlhaus_key = os.environ.get("NETH_URLHAUS_KEY")
        self.gsb_key = os.environ.get("NETH_GSB_KEY")

    # -- parsing helpers -----------------------------------------------------
    @staticmethod
    def find_urls(text: str) -> list[str]:
        return URL_RE.findall(text or "")

    @staticmethod
    def _host(url: str) -> str:
        if "://" not in url:
            url = "//" + url
        netloc = urlparse(url).netloc
        # strip userinfo and port
        host = netloc.split("@")[-1].split(":")[0]
        return host.lower().strip(".")

    @classmethod
    def registrable_domain(cls, host: str) -> str:
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        # handle multi-part TLDs like com.kh, gov.kh
        if len(parts) >= 3 and parts[-2] in MULTIPART_SLDS and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _has_homoglyph(host: str) -> bool:
        # any non-ASCII char in a hostname = punycode/IDN; common in spoofing
        return any(ord(c) > 127 for c in host) or host.startswith("xn--") or ".xn--" in host

    # -- SSRF guard ----------------------------------------------------------
    @staticmethod
    def _ip_is_blocked(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # unparseable -> refuse
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified)

    def _url_is_fetch_safe(self, url: str) -> bool:
        """Reject non-HTTP schemes and any host resolving to a private/internal
        IP — blocks SSRF to localhost, LAN, and cloud metadata (169.254.169.254)."""
        parsed = urlparse(url if "://" in url else "http://" + url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = (parsed.hostname or "").strip(".")
        if not host:
            return False
        # If host is a literal IP, check it directly; else resolve ALL A/AAAA.
        try:
            infos = socket.getaddrinfo(host, parsed.port or 80, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError, OSError):
            return False
        ips = {info[4][0] for info in infos}
        return bool(ips) and not any(self._ip_is_blocked(ip) for ip in ips)

    # -- online: shortener expansion (SSRF-guarded, manual redirects) --------
    def _expand(self, url: str, max_hops: int = 5) -> str | None:
        if not (self.online and requests):
            return None
        current = url if "://" in url else "http://" + url
        start = current
        try:
            for _ in range(max_hops):
                if not self._url_is_fetch_safe(current):
                    return None  # refuse to fetch internal/unsafe targets
                resp = requests.head(current, allow_redirects=False, timeout=6)
                if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                    nxt = resp.headers.get("Location")
                    if not nxt:
                        break
                    current = requests.compat.urljoin(current, nxt)
                    continue
                break
        except Exception:  # noqa: BLE001
            return None
        return current if current != start else None

    # -- online: threat feeds ------------------------------------------------
    def _urlhaus(self, url: str) -> str | None:
        if not (self.online and requests and self.urlhaus_key):
            return None
        try:
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Auth-Key": self.urlhaus_key},
                timeout=6,
            )
            data = r.json()
            if data.get("query_status") == "ok":
                threat = data.get("threat") or "listed"
                return f"URLhaus: known malicious ({threat})"
        except Exception:  # noqa: BLE001
            pass
        return None

    def _gsb(self, url: str) -> str | None:
        if not (self.online and requests and self.gsb_key):
            return None
        try:
            body = {
                "client": {"clientId": "neth", "clientVersion": "0.1"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            r = requests.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": self.gsb_key}, json=body, timeout=6,
            )
            if r.json().get("matches"):
                return "Google Safe Browsing: flagged (social engineering / malware)"
        except Exception:  # noqa: BLE001
            pass
        return None

    # -- main ----------------------------------------------------------------
    def analyze(self, url: str) -> URLVerdict:
        v = URLVerdict(url=url, weight=0, status="SAFE")

        expanded = self._expand(url)
        scan_url = expanded or url
        if expanded:
            v.final_url = expanded
            v.reasons.append(f"shortener expands to {expanded}")
        elif self._host(url) in SHORTENERS:
            v.weight += 1
            v.reasons.append("link shortener hides the real destination")

        host = self._host(scan_url)
        reg = self.registrable_domain(host)
        v.registrable = reg

        # Decisive: known-bad in a threat feed.
        for feed in (self._urlhaus(scan_url), self._gsb(scan_url)):
            if feed:
                v.weight += 5
                v.reasons.append(feed)

        # Homoglyph / punycode host.
        if self._has_homoglyph(host):
            v.weight += 3
            v.reasons.append("non-ASCII / punycode host (possible homoglyph spoof)")

        # IP-literal host.
        if self._is_ip(host):
            v.weight += 2
            v.reasons.append("raw IP address instead of a domain")

        # userinfo '@' trick (e.g. ababank.com@evil.xyz).
        if "@" in urlparse(scan_url if "://" in scan_url else "//" + scan_url).netloc:
            v.weight += 2
            v.reasons.append("'@' in URL hides the true host")

        # Brand-off-domain: a bank name appears as a host *token* but the
        # registrable domain is not an official one. Skip entirely if the
        # domain is canonical for ANY brand (so legit acledabank.com.kh, whose
        # label contains the substring "aba", is never flagged).
        if reg not in ALL_CANONICAL_DOMAINS:
            tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
            for brand in CANONICAL_BANK_DOMAINS:
                if any(tok.startswith(brand) for tok in tokens):
                    v.weight += 3
                    v.reasons.append(f"'{brand}' appears but domain '{reg}' is not official")
                    break

        # Cheap/abused TLD (weak).
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            v.weight += 2
            v.reasons.append(f".{tld} is a frequently-abused TLD")

        if v.weight >= 5:
            v.status = "BLOCKED"
        elif v.weight >= 2:
            v.status = "SUSPICIOUS"
        return v


if __name__ == "__main__":
    rep = URLReputation()
    for u in [
        "http://aba-secure.xyz/login",
        "https://www.ababank.com/promo",
        "http://ababank.com@evil.tk/",
        "bit.ly/win-now",
        "http://192.168.0.5/aba",
    ]:
        r = rep.analyze(u)
        print(f"[{r.status:10}] w={r.weight} {u}\n   -> {r.reasons}")
