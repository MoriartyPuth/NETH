"""Smoke tests for the NETH engines (offline, no model/API needed)."""
import pytest

from neth.feedback import FeedbackStore
from neth.identity_match import IdentityMatcher
from neth.khqr_core import NethKHQREngine
from neth.nlp_khmer import KhmerPhishingDetector
from neth.scoring import NethGateway
from neth.url_reputation import URLReputation


def _tlv(tag: str, val: str) -> str:
    return f"{tag}{len(val):02d}{val}"


def _build_khqr(name: str, account: str, merchant: bool = True) -> str:
    """Construct a CRC-valid KHQR with a given Tag 59 name and Tag 29/30 account."""
    eng = NethKHQREngine()
    acct_tag = "30" if merchant else "29"
    acct_val = _tlv("00", "kh.gov.nbc.bakong") + _tlv("01", account)
    body = (_tlv("00", "01") + _tlv("01", "11") + _tlv(acct_tag, acct_val)
            + _tlv("53", "116") + _tlv("58", "KH") + _tlv("59", name)
            + _tlv("60", "Phnom Penh") + "6304")
    return body + eng.calculate_crc16(body)


def _valid_khqr() -> str:
    """Build a KHQR with a correct CRC so we test the SAFE path, not corruption."""
    eng = NethKHQREngine()
    body = "00020101021129180014aba@abakhppxxx5912ABA Merchant6304"
    return body + eng.calculate_crc16(body)


def test_tlv_walker_is_positional():
    eng = NethKHQREngine()
    # tag 00 len 02 = "01"; tag 59 len 04 = "ABCD"
    nodes = eng.parse_tlv("0002015904ABCD")
    assert nodes["00"].value == "01"
    assert nodes["59"].value == "ABCD"


def test_not_a_khqr_is_invalid_not_malicious():
    v = NethKHQREngine().inspect("just some text")
    assert v.status == "INVALID"
    assert v.score == -1  # not scored as a threat


def test_bad_crc_is_suspicious_not_blocked():
    v = NethKHQREngine().inspect("00020101021129180014aba@abakhppxxx5912ABA Merchant6304ABCD")
    assert v.status == "SUSPICIOUS"


def test_valid_crc_parses_fields():
    v = NethKHQREngine().inspect(_valid_khqr())
    assert v.score in (0, 1)
    assert v.fields.get("display_name") == "ABA Merchant"


def test_khmer_phishing_flagged():
    s = KhmerPhishingDetector().analyze(
        "អ្នកបានឈ្នះរង្វាន់ពី ABA! ចុចលីង bit.ly/xx បន្ទាន់!")
    assert s.score >= 1


def test_benign_text_safe():
    s = KhmerPhishingDetector().analyze("សួស្តី ពេលណាជួបគ្នា?")
    assert s.score == 0


def test_url_legit_bank_domain_is_safe():
    # the old code wrongly checked aba.com; ABA is ababank.com
    r = URLReputation(online=False).analyze("https://www.ababank.com/promo")
    assert r.status == "SAFE"


def test_url_lookalike_blocked():
    r = URLReputation(online=False).analyze("http://aba-secure.xyz/login")
    assert r.status == "BLOCKED"
    assert any("not official" in x for x in r.reasons)


def test_url_brand_substring_no_false_positive():
    # 'aba' is a substring of 'acledabank'/'canadiabank' — must NOT flag legit .com.kh
    rep = URLReputation(online=False)
    for u in ("https://www.acledabank.com.kh/personal", "https://canadiabank.com.kh/"):
        assert rep.analyze(u).status == "SAFE", u


def test_url_at_trick_and_registrable_domain():
    rep = URLReputation(online=False)
    assert rep.registrable_domain("www.acledabank.com.kh") == "acledabank.com.kh"
    r = rep.analyze("http://ababank.com@evil.tk/")
    assert r.weight >= 2
    assert any("@" in x for x in r.reasons)


def test_bank_domains_loaded_from_yaml():
    rep = URLReputation(online=False)
    # YAML adds many more banks beyond the 7 built-in defaults
    from neth.url_reputation import CANONICAL_BANK_DOMAINS
    assert len(CANONICAL_BANK_DOMAINS) >= 20
    # a non-default KH bank works both ways
    assert rep.analyze("https://www.vattanacbank.com/").status == "SAFE"
    assert rep.analyze("http://vattanac-secure.xyz/login").status == "BLOCKED"


def test_identity_routing_mismatch_unit():
    m = IdentityMatcher()
    s = m.check("ABA Merchant", "sokha@aclb", "individual")  # claims ABA, routes ACLEDA
    assert s.status == "MISMATCH" and s.score == 2


def test_identity_personal_account_as_merchant():
    m = IdentityMatcher()
    s = m.check("ABA Merchant", "sokha@aba", "individual")   # right bank, but personal acct
    assert s.score == 1


def test_identity_consistent_ok():
    m = IdentityMatcher()
    s = m.check("ABA Bank", "shop@aba", "merchant")
    assert s.score == 0


def test_identity_no_brand_claim():
    m = IdentityMatcher()
    s = m.check("Borey Coffee", "borey@wing", "individual")
    assert s.score == 0


def test_gateway_blocks_routing_mismatch_end_to_end():
    # CRC-valid QR that looks like ABA but routes to an ACLEDA account
    qr = _build_khqr("ABA Merchant", "sokha@aclb", merchant=True)
    v = NethGateway().analyze_khqr(qr)
    assert v.score == 2
    assert any(s["engine"] == "identity_match" and s["score"] == 2 for s in v.signals)


def test_khmer_output_attached():
    qr = _build_khqr("ABA Merchant", "sokha@aclb", merchant=True)
    v = NethGateway().analyze_khqr(qr)
    assert v.summary_km  # Khmer headline present
    assert any(s.get("reason_km") for s in v.signals)


def test_url_ssrf_guard_blocks_internal():
    r = URLReputation(online=True)
    for u in ("http://169.254.169.254/", "http://127.0.0.1/", "http://10.0.0.1/", "ftp://x/"):
        assert r._url_is_fetch_safe(u) is False, u


def test_feedback_store(tmp_path):
    store = FeedbackStore(tmp_path / "fb.db")
    fid = store.record("text", "អ្នកបានឈ្នះរង្វាន់...", 0, "scam", "missed")
    assert fid == 1
    s = store.stats()
    assert s["total"] == 1 and s["scam_missed_as_safe"] == 1
    with pytest.raises(ValueError):
        store.record("text", "x", 0, "not_a_label")


def test_gateway_aggregates():
    v = NethGateway().analyze_text("Your ABA account suspended, verify: http://aba-secure.xyz")
    assert v.score >= 1
    assert any(s["engine"] == "nlp_khmer" for s in v.signals)
