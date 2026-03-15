import product_app


def test_provider_429_warning_formats_retry_seconds():
    detail = {
        "provider": "gemini",
        "status_code": 429,
        "retry_info": {"retry_after_seconds": 7.0},
    }
    retry_after = product_app._extract_retry_after_seconds(detail)
    text = product_app._provider_429_warning_text(retry_after)

    assert retry_after == 7
    assert "AI provider quota/rate limit reached for this tenant." in text
    assert "retry in ~7 seconds" in text


def test_personal_tenant_gets_simplified_navigation_and_default_view():
    pages = product_app._nav_options_for_user(role="tenant_admin", is_personal=True)
    default_view = product_app._default_view_for_user(role="tenant_admin", is_personal=True)

    assert pages == ["Chat", "Settings"]
    assert default_view == "chat"


def test_company_tenant_admin_keeps_full_navigation():
    pages = product_app._nav_options_for_user(role="tenant_admin", is_personal=False)
    default_view = product_app._default_view_for_user(role="tenant_admin", is_personal=False)

    assert pages == ["Tenant Admin", "Chat", "Settings"]
    assert default_view == "tenant_admin"


def test_resolve_is_personal_prefers_me_payload_top_level_flag():
    payload = {
        "tenant_id": 42,
        "role": "tenant_admin",
        "is_personal": True,
        "memberships": [
            {"tenant_id": 42, "role": "tenant_admin", "is_personal": False},
        ],
    }
    assert product_app._resolve_is_personal_from_payload(payload, tenant_id=42, fallback=False) is True


def test_resolve_is_personal_uses_membership_flag_for_auth_payloads():
    payload = {
        "tenant_id": 7,
        "role": "tenant_admin",
        "memberships": [
            {"tenant_id": 7, "role": "tenant_admin", "is_personal": 1},
        ],
    }
    assert product_app._resolve_is_personal_from_payload(payload, tenant_id=7, fallback=False) is True
