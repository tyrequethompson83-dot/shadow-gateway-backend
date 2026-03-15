from datetime import datetime
import json
import uuid


def _insert_sample(db, tenant_id: int, tag: str):
    db.insert_request(
        {
            "id": str(uuid.uuid4()),
            "ts": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "user": f"user-{tag}",
            "purpose": f"purpose-{tag}",
            "model": "local-model",
            "cleaned_prompt_preview": f"preview-{tag}",
            "detections_count": 1,
            "entity_counts_json": json.dumps({"EMAIL_ADDRESS": 1}),
            "risk_score": 10,
            "risk_level": "LOW",
            "decision": "ALLOW",
        },
        tenant_id=tenant_id,
    )


def test_summary_is_tenant_scoped(app_ctx):
    client = app_ctx["client"]
    db = app_ctx["db"]
    db_enterprise = app_ctx["db_enterprise"]

    tenant_2 = db_enterprise.create_tenant("Tenant Two")
    user_1 = db_enterprise.ensure_user("u1")
    user_2 = db_enterprise.ensure_user("u2")
    db_enterprise.upsert_membership(tenant_id=1, user_id=user_1, role="user")
    db_enterprise.upsert_membership(tenant_id=tenant_2, user_id=user_2, role="user")

    _insert_sample(db, tenant_id=1, tag="t1-a")
    _insert_sample(db, tenant_id=1, tag="t1-b")
    _insert_sample(db, tenant_id=tenant_2, tag="t2-a")

    r1 = client.get("/summary", headers={"X-User": "u1", "X-Tenant-Id": "1"})
    r2 = client.get("/summary", headers={"X-User": "u2", "X-Tenant-Id": str(tenant_2)})
    assert r1.status_code == 200
    assert r2.status_code == 200

    s1 = r1.json()
    s2 = r2.json()
    assert s1["total_requests"] == 2
    assert s2["total_requests"] == 1
    assert s1["total_requests"] != s2["total_requests"]
