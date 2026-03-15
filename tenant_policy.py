from typing import Any, Dict, List


CATEGORY_TO_POLICY_FIELD = {
    "PII": "pii_action",
    "FIN": "financial_action",
    "SECRETS": "secrets_action",
    "HEALTH": "health_action",
    "IP": "ip_action",
}

SEVERITY_RANK = {
    "LOW": 1,
    "MED": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

CATEGORY_BLOCK_RANK_OVERRIDE = {
    "SECRETS": 4,
}


def _severity_rank(value: str) -> int:
    return int(SEVERITY_RANK.get(str(value or "").strip().upper(), 1))


def _threshold_allows_block(risk_level: str, block_threshold: str, *, category: str) -> bool:
    threshold = str(block_threshold or "critical").strip().lower()
    required_rank = 4 if threshold == "critical" else 3
    category_rank = int(CATEGORY_BLOCK_RANK_OVERRIDE.get(str(category or "").strip().upper(), 0))
    return max(_severity_rank(risk_level), category_rank) >= required_rank


def evaluate_tenant_policy(
    *,
    tenant_policy: Dict[str, Any],
    risk_level: str,
    risk_score: float,
    entity_counts: Dict[str, int],
    category_counts: Dict[str, int],
    cleaned_prompt: str,
    redactions_applied: int,
    injection_detected: bool,
) -> Dict[str, Any]:
    reasons: List[str] = []
    decision = "ALLOW"

    if injection_detected:
        reasons.append("prompt injection detected")
        decision = "BLOCK"
    else:
        block_threshold = str(tenant_policy.get("block_threshold") or "critical").strip().lower()
        should_block = False
        should_redact = False
        for category, count in sorted((category_counts or {}).items()):
            if int(count or 0) <= 0:
                continue
            field = CATEGORY_TO_POLICY_FIELD.get(str(category).upper())
            if not field:
                continue
            action = str(tenant_policy.get(field) or "redact").strip().lower()
            if action == "block":
                if _threshold_allows_block(
                    risk_level=risk_level,
                    block_threshold=block_threshold,
                    category=str(category),
                ):
                    should_block = True
                    reasons.append(f"{category} configured as block")
                else:
                    should_redact = True
                    reasons.append(
                        f"{category} block threshold not met ({risk_level} < {block_threshold}), downgraded to redact"
                    )
            elif action == "redact":
                should_redact = True
                reasons.append(f"{category} configured as redact")

        if should_block:
            decision = "BLOCK"
        elif should_redact:
            decision = "REDACT"
        else:
            decision = "ALLOW"
            reasons.append("no policy-triggered category action")

    return {
        "decision": str(decision).upper(),
        "risk_level": str(risk_level).upper(),
        "risk_score": float(risk_score),
        "redactions_applied": int(redactions_applied),
        "entity_counts": dict(entity_counts or {}),
        "cleaned_prompt": str(cleaned_prompt or ""),
        "reasons": reasons,
    }
