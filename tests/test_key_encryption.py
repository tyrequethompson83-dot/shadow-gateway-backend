import sqlite3


def test_provider_key_encryption_roundtrip_and_migration(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]
    db_path = app_ctx["db_path"]

    plain_key = "sk-test-openai-abcdef1234567890"
    db_enterprise.upsert_tenant_provider_config(
        tenant_id=1,
        provider="openai",
        model="gpt-4.1-mini",
        api_key=plain_key,
    )

    with sqlite3.connect(str(db_path)) as con:
        row = con.execute(
            """
            SELECT api_key_enc, api_key_tail
            FROM tenant_provider_keys
            WHERE tenant_id = 1 AND provider = 'openai'
            """
        ).fetchone()
    assert row is not None
    assert row[0].startswith("enc:v2:")
    assert row[1] == plain_key[-4:]
    assert plain_key not in row[0]

    safe = db_enterprise.get_tenant_provider_config(1)
    runtime = db_enterprise.get_tenant_provider_runtime_config(1)
    assert safe["api_key_tail"] == plain_key[-4:]
    assert safe["has_api_key"] is True
    assert runtime["api_key"] == plain_key

    legacy = "legacy_plain_text_key_1234567890"
    with sqlite3.connect(str(db_path)) as con:
        con.execute(
            """
            UPDATE tenant_provider_keys
            SET api_key_enc = ?, api_key_tail = NULL
            WHERE tenant_id = 1 AND provider = 'openai'
            """,
            (legacy,),
        )
        con.commit()

    runtime_after = db_enterprise.get_tenant_provider_runtime_config(1)
    assert runtime_after["api_key"] == legacy

    with sqlite3.connect(str(db_path)) as con:
        row2 = con.execute(
            """
            SELECT api_key_enc, api_key_tail
            FROM tenant_provider_keys
            WHERE tenant_id = 1 AND provider = 'openai'
            """
        ).fetchone()
    assert row2[0].startswith("enc:v2:")
    assert row2[1] == legacy[-4:]
