#!/usr/bin/env python3
"""
NETH - Khmer localization of verdicts.

Users are Khmer speakers on phones; verdicts must be readable in Khmer. Rather
than translate freeform English reasons, we map each signal's structured
(engine, status) to a Khmer template and interpolate the values we already have
(brand names, QR counts). English is kept alongside for developers/logs.
"""
from __future__ import annotations

from collections import defaultdict

# Verdict headline by final score.
SUMMARY_KM = {
    0: "✅ មានសុវត្ថិភាព",
    1: "⚠️ គួរប្រយ័ត្ន — ពិនិត្យឱ្យបានច្បាស់",
    2: "⛔ បានរារាំង — កុំបង់ប្រាក់",
}
SUMMARY_KM_UNVERIFIED = "✅ ទំនងជាមានសុវត្ថិភាព (មានការត្រួតពិនិត្យខ្លះមិនទាន់បានផ្ទៀងផ្ទាត់)"

# (engine, status) -> Khmer template. {claimed} {routing} {qr} are interpolated.
TEMPLATES: dict[tuple[str, str], str] = {
    ("identity_match", "MISMATCH"):
        "ឈ្មោះបង្ហាញថា '{claimed}' ប៉ុន្តែគណនីផ្ទេរប្រាក់ទៅ '{routing}' — "
        "ករណីបោកប្រាស់ដោយបិទ QR ក្លែងក្លាយ។ កុំបង់ប្រាក់។",
    ("identity_match", "SUSPICIOUS"):
        "ឈ្មោះអះអាងថាជា '{claimed}' ប៉ុន្តែប្រើគណនីផ្ទាល់ខ្លួន មិនមែនគណនីពាណិជ្ជករទេ។ "
        "សូមផ្ទៀងផ្ទាត់អ្នកទទួលប្រាក់។",
    ("identity_match", "OK"):
        "ឈ្មោះ និងគណនីធនាគារត្រូវគ្នា។",
    ("identity_match", "UNVERIFIED"):
        "មិនអាចផ្ទៀងផ្ទាត់ធនាគារបានទេ។ សូមប្រៀបធៀបឈ្មោះក្នុងកម្មវិធីធនាគាររបស់អ្នកមុនបង់ប្រាក់។",
    ("khqr_core", "INVALID"):
        "នេះមិនមែនជា KHQR ត្រឹមត្រូវទេ។",
    ("khqr_core", "SUSPICIOUS"):
        "ផលបូកត្រួតពិនិត្យ (CRC) មិនត្រូវគ្នា — ទិន្នន័យ QR អាចខូច ឬត្រូវបានកែប្រែ។",
    ("khqr_core", "SAFE"):
        "រចនាសម្ព័ន្ធ និង CRC ត្រឹមត្រូវ។",
    ("nlp_khmer", "BLOCKED"):
        "សារនេះមានលក្ខណៈបោកប្រាស់ខ្ពស់ (ភាពបន្ទាន់ + តំណ ឬប្រាក់)។ កុំចុចតំណ។",
    ("nlp_khmer", "SUSPICIOUS"):
        "មានសញ្ញាបោកប្រាស់មួយចំនួន។ សូមផ្ទៀងផ្ទាត់ប្រភពដោយខ្លួនឯង។",
    ("nlp_khmer", "SAFE"):
        "មិនមានសញ្ញាបោកប្រាស់គួរឱ្យកត់សម្គាល់ទេ។",
    ("vision_overlay", "SUSPICIOUS"):
        "រកឃើញ QR ច្រើនជាងមួយក្នុងរូបភាព — អាចមានស្ទីកគ័របិទពីលើ។ សូមផ្ទៀងផ្ទាត់ QR ត្រឹមត្រូវ។",
    ("vision_overlay", "INVALID"):
        "រកមិនឃើញ QR ក្នុងរូបភាពទេ។",
    ("vision_overlay", "SAFE"):
        "រកឃើញ QR មួយ។ កំពុងពិនិត្យមាតិកា។",
}

# Fallback by severity when no specific template matches.
SCORE_FALLBACK_KM = {
    0: "មិនមានបញ្ហាគួរឱ្យកត់សម្គាល់ទេ។",
    1: "គួរប្រយ័ត្ន — សូមផ្ទៀងផ្ទាត់បន្ថែម។",
    2: "ប្រកបដោយហានិភ័យ — កុំបន្ត។",
}


def localize_signal(sig: dict) -> str:
    """Return a Khmer string for one signal dict."""
    key = (sig.get("engine", ""), sig.get("status", ""))
    template = TEMPLATES.get(key)
    if template is None:
        score = sig.get("score", 0)
        return SCORE_FALLBACK_KM.get(max(score, 0) if score is not None else 0, "")
    values = defaultdict(str, {
        "claimed": (sig.get("claimed_brand") or "").upper(),
        "routing": (sig.get("routing_brand") or "").upper(),
        "qr": sig.get("qr_count", ""),
    })
    return template.format_map(values)


def localize_summary(score: int, has_unverified: bool) -> str:
    if score == 0 and has_unverified:
        return SUMMARY_KM_UNVERIFIED
    return SUMMARY_KM.get(score, SUMMARY_KM[1])


if __name__ == "__main__":
    demo = {"engine": "identity_match", "status": "MISMATCH",
            "claimed_brand": "aba", "routing_brand": "acleda", "score": 2}
    print(localize_summary(2, False))
    print(localize_signal(demo))
