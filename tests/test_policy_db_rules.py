from injection_detector import InjectionResult
from policy_engine import evaluate_policy, invalidate_policy_cache


def test_policy_rule_order_category_before_severity(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]

    db_enterprise.create_policy_rule(
        tenant_id=1,
        rule_type="category",
        match="FIN",
        action="ALLOW",
        enabled=True,
    )
    db_enterprise.create_policy_rule(
        tenant_id=1,
        rule_type="severity",
        match="HIGH",
        action="BLOCK",
        enabled=True,
    )
    invalidate_policy_cache(1)

    result = evaluate_policy(
        tenant_id=1,
        injection=InjectionResult(False, "PROMPT_INJECTION", "Low", [], 0),
        category_counts={"FIN": 1},
        severity="High",
    )
    assert result.decision == "ALLOW"


def test_policy_injection_default_block(app_ctx):
    invalidate_policy_cache(1)
    result = evaluate_policy(
        tenant_id=1,
        injection=InjectionResult(True, "PROMPT_INJECTION", "High", ["ignore_instructions"], 80),
        category_counts={},
        severity="Low",
    )
    assert result.decision == "BLOCK"
