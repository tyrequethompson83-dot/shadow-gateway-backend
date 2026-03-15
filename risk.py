from collections import Counter
from typing import Any, Dict, List


WEIGHTS = {
    "API_KEY": 40,
    "SECRET_TOKEN": 35,
    "US_SSN": 40,
    "GOVERNMENT_ID": 30,
    "CREDIT_CARD": 35,
    "PHONE_NUMBER": 12,
    "EMAIL_ADDRESS": 10,
    "PERSON": 8,
    "IP_ADDRESS": 10,
    "LOCATION": 0,
    "PHI_TERM": 16,
}

ENTITY_CATEGORY_MAP = {
    "EMAIL_ADDRESS": "PII",
    "PHONE_NUMBER": "PII",
    "PERSON": "PII",
    "LOCATION": "PUBLIC",
    "US_SSN": "PII",
    "GOVERNMENT_ID": "PII",
    "CREDIT_CARD": "FIN",
    "API_KEY": "SECRETS",
    "SECRET_TOKEN": "SECRETS",
    "PHI_TERM": "HEALTH",
    "IP_ADDRESS": "IP",
}


def count_entities(detections: List[Dict[str, Any]]) -> Dict[str, int]:
    c = Counter()
    for d in detections or []:
        t = str(d.get("entity_type", "UNKNOWN")).strip().upper() or "UNKNOWN"
        c[t] += 1
    return dict(c)


def _severity(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 25:
        return "Med"
    return "Low"


def compute_risk_score(
    entity_counts: Dict[str, int],
    *,
    injection_detected: bool = False,
) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    categories: Dict[str, int] = {"PII": 0, "FIN": 0, "SECRETS": 0, "HEALTH": 0, "IP": 0, "PUBLIC": 0}

    for ent, cnt in (entity_counts or {}).items():
        count = max(0, int(cnt))
        if count <= 0:
            continue
        w = int(WEIGHTS.get(ent, 3))
        part = w * count
        score += part
        reasons.append(f"{ent} x{count} (+{part})")
        category = ENTITY_CATEGORY_MAP.get(ent, "PII")
        categories[category] = categories.get(category, 0) + count

    if injection_detected:
        score += 35
        reasons.append("PROMPT_INJECTION (+35)")

    score = min(100, score)
    severity = _severity(score)
    if severity == "Critical":
        decision = "BLOCK_OR_STRICT_REDACT"
    elif severity in {"High", "Med"}:
        decision = "REDACT"
    else:
        decision = "ALLOW"

    return {
        "risk_score": int(score),
        "risk_level": severity.upper(),
        "severity": severity,
        "decision_suggested": decision,
        "reasons": reasons,
        "risk_categories": categories,
    }
