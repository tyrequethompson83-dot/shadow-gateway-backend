def _auth_headers(token: str, tenant_id: int) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-Id": str(int(tenant_id)),
    }


def _create_simple_pdf_bytes(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET".encode("latin-1")

    objects = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objects.append(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
    )
    objects.append(
        b"4 0 obj\n<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream\nendobj\n"
    )
    objects.append(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)
    xref_offset = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)


def _signup_company_admin(client, company_name: str, admin_email: str) -> tuple[int, str]:
    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": company_name,
            "admin_email": admin_email,
            "password": "StrongPass123!",
        },
    )
    assert signup.status_code == 200
    body = signup.json()
    return int(body["tenant_id"]), str(body["access_token"])


def test_file_scan_valid_txt_upload(app_ctx):
    client = app_ctx["client"]
    tenant_id, token = _signup_company_admin(client, "File Scan TXT Org", "owner@filescan-txt.test")

    response = client.post(
        "/files/scan",
        headers=_auth_headers(token, tenant_id),
        files={"file": ("sample.txt", b"Contact: user@example.com", "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "sample.txt"
    assert body["file_type"] == ".txt"
    assert body["decision"] in {"ALLOW", "REDACT", "BLOCK"}
    assert body["findings_count"] >= 1
    assert int(body["entity_counts"].get("EMAIL_ADDRESS", 0)) >= 1
    assert "[EMAIL_ADDRESS_" in body["redacted_text"]


def test_file_scan_valid_pdf_upload(app_ctx):
    client = app_ctx["client"]
    tenant_id, token = _signup_company_admin(client, "File Scan PDF Org", "owner@filescan-pdf.test")
    pdf_bytes = _create_simple_pdf_bytes("PDF email: person@example.com")

    response = client.post(
        "/files/scan",
        headers=_auth_headers(token, tenant_id),
        files={"file": ("sample.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "sample.pdf"
    assert body["file_type"] == ".pdf"
    assert "PDF" in str(body["extracted_text"])
    assert int(body["findings_count"]) >= 1


def test_file_scan_rejects_unsupported_file_type(app_ctx):
    client = app_ctx["client"]
    tenant_id, token = _signup_company_admin(client, "File Scan Unsupported Org", "owner@filescan-unsupported.test")

    response = client.post(
        "/files/scan",
        headers=_auth_headers(token, tenant_id),
        files={"file": ("malware.exe", b"MZ", "application/octet-stream")},
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "Unsupported file extension" in str(detail.get("message") or detail)


def test_file_scan_rejects_oversized_upload(app_ctx):
    client = app_ctx["client"]
    tenant_id, token = _signup_company_admin(client, "File Scan Oversize Org", "owner@filescan-oversize.test")
    too_large = b"A" * ((5 * 1024 * 1024) + 8)

    response = client.post(
        "/files/scan",
        headers=_auth_headers(token, tenant_id),
        files={"file": ("big.txt", too_large, "text/plain")},
    )
    assert response.status_code == 413
    assert "Upload too large" in str(response.json().get("detail", ""))


def test_file_scan_returns_extraction_failure(app_ctx):
    client = app_ctx["client"]
    tenant_id, token = _signup_company_admin(client, "File Scan Bad PDF Org", "owner@filescan-badpdf.test")

    response = client.post(
        "/files/scan",
        headers=_auth_headers(token, tenant_id),
        files={"file": ("broken.pdf", b"%PDF-1.4\nnot-a-real-pdf", "application/pdf")},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "message" in detail


def test_file_scan_requires_authentication(app_ctx):
    client = app_ctx["client"]
    response = client.post(
        "/files/scan",
        files={"file": ("sample.txt", b"hello", "text/plain")},
    )
    assert response.status_code == 401
