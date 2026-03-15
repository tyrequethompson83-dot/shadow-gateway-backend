import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from injection_detector import InjectionResult


_POLICY_CACHE: dict[int, tuple[float, list[dict]]] = {}
POLICY_CACHE_TTL_SECONDS = 5.0


@dataclass
class PolicyDecision:
    decision: str
    reasons: List[str]
    matched_rule_id: Optional[int] = None


def _default_decision_for_severity(severity: str) -> str:
    sev = (severity or "").strip().lower()
    if sev in {"critical"}:
        return "BLOCK"
    if sev in {"high", "med", "medium"}:
        return "REDACT"
    return "ALLOW"


def _load_rules(tenant_id: int) -> List[Dict]:
    now = time.time()
    cached = _POLICY_CACHE.get(int(tenant_id))
    if cached and (now - cached[0]) < POLICY_CACHE_TTL_SECONDS:
        return cached[1]
    try:
        from enterprise.db_enterprise import list_policy_rules

        rows = list_policy_rules(tenant_id=int(tenant_id))
    except Exception:
        rows = []
    _POLICY_CACHE[int(tenant_id)] = (now, rows)
    return rows


def invalidate_policy_cache(tenant_id: Optional[int] = None) -> None:
    if tenant_id is None:
        _POLICY_CACHE.clear()
        return
    _POLICY_CACHE.pop(int(tenant_id), None)


def _first_enabled_rule(rules: List[Dict], rule_type: str, match_value: str) -> Optional[Dict]:
    wanted = (match_value or "").strip().upper()
    for row in rules:
        if not bool(int(row.get("enabled", 1))):
            continue
        if str(row.get("rule_type", "")).strip().lower() != rule_type:
            continue
        candidate = str(row.get("match", "")).strip().upper()
        if candidate in {"*", "ANY", wanted}:
            return row
    return None


def evaluate_policy(
    *,
    tenant_id: int,
    injection: InjectionResult,
    category_counts: Dict[str, int],
    severity: str,
) -> PolicyDecision:
    rules = _load_rules(tenant_id)

    # 1) Injection rules
    if injection.detected:
        rule = _first_enabled_rule(rules, "injection", "PROMPT_INJECTION")
        if rule:
            action = str(rule.get("action", "BLOCK")).upper()
            return PolicyDecision(
                decision=action,
                reasons=[f"injection rule matched ({rule.get('match')})"],
                matched_rule_id=int(rule["id"]),
            )
        return PolicyDecision(
            decision="BLOCK",
            reasons=["prompt injection detected (default block)"],
        )

    # 2) Sensitive category rules
    for category, count in sorted((category_counts or {}).items()):
        if int(count) <= 0:
            continue
        rule = _first_enabled_rule(rules, "category", category)
        if rule:
            action = str(rule.get("action", "REDACT")).upper()
            return PolicyDecision(
                decision=action,
                reasons=[f"category rule matched ({category})"],
                matched_rule_id=int(rule["id"]),
            )

    # 3) Severity fallback (rules then default)
    rule = _first_enabled_rule(rules, "severity", severity)
    if rule:
        action = str(rule.get("action", "ALLOW")).upper()
        return PolicyDecision(
            decision=action,
            reasons=[f"severity rule matched ({severity})"],
            matched_rule_id=int(rule["id"]),
        )

    return PolicyDecision(
        decision=_default_decision_for_severity(severity),
        reasons=[f"default severity policy ({severity})"],
    )
