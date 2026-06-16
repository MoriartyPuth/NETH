"""
NETH - KHQR & Phishing Scam Detection Gateway.

Engines
-------
khqr_core      : EMVCo/KHQR TLV parser + validity + identity heuristic
bakong_verify  : resolve a Bakong account id -> registered holder name
nlp_khmer      : Khmer-language phishing / social-engineering detector
vision_overlay : QR extraction + physical-overlay (multi-QR) detection
scoring        : combine all signals into one Safe/Suspicious/Blocked verdict
"""
__version__ = "0.1.0"
