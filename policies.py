from typing import Dict, List, Optional, Tuple

from injection_detector import InjectionResult
from policy_engine import evaluate_policy


DEFAULT_BLOCK = {"US_SSN", "API_KEY", "SECRET_TOKEN", "PROMPT_INJECTION"}
DEFAULT_ALWAYS_REDACT = {"CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER", "PHI_TERM"}


def apply_policies(
    entity_counts: Dict[str, int],
    *,
    tenant_id: Optional[int] = None,
    injection: Optional[InjectionResult] = None,
    risk_severity: str = "Low",
    risk_categories: Optional[Dict[str, int]] = None,
) -> Tuple[str, List[str]]:
    """
    Backward-compatible entry point.
    If tenant_id is provided, DB-backed policy rules are used.
    """
    if tenant_id is not None:
        decision = evaluate_policy(
            tenant_id=int(tenant_id),
            injection=injection or InjectionResult(False, "PROMPT_INJECTION", "Low", [], 0),
            category_counts=risk_categories or {},
            severity=risk_severity,
        )
        return decision.decision, decision.reasons

    reasons: List[str] = []

    if injection and injection.detected:
        reasons.append("Prompt injection detected")
        return "BLOCK", reasons

    for ent in DEFAULT_BLOCK:
        if entity_counts.get(ent, 0) > 0:
            reasons.append(f"Blocked entity detected: {ent}")
            return "BLOCK", reasons

    for ent in DEFAULT_ALWAYS_REDACT:
        if entity_counts.get(ent, 0) > 0:
            reasons.append(f"Sensitive entity detected: {ent}")
            return "REDACT", reasons

    return "ALLOW", reasons
