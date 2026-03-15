import io
from email.parser import BytesParser
from email.policy import default
from typing import Any, Dict, Optional, Tuple

from starlette.datastructures import Headers, UploadFile
from starlette.requests import Request

from file_extraction import (
    FileInfo,
    FileValidationError,
    TextExtractionError,
    extract_text_from_bytes,
    validate_file_info,
)
from injection_detector import detect_prompt_injection
from risk import count_entities, compute_risk_score
from scrubber import scrub_prompt
from tenant_policy import evaluate_tenant_policy


class UploadRequestError(ValueError):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = int(status_code)
        self.message = str(message)


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _validate_content_type(content_type: str) -> str:
    normalized = str(content_type or "").strip().lower()
    if "multipart/form-data" not in normalized:
        raise UploadRequestError(400, "Content-Type must be multipart/form-data")
    return normalized


async def _read_request_body_limited(request: Request, max_bytes: int) -> bytes:
    total = 0
    chunks = []
    async for chunk in request.stream():
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise UploadRequestError(413, f"Upload too large. Max allowed is {max_bytes} bytes.")
        chunks.append(chunk)
    return b"".join(chunks)


def _form_field_value(part: Any) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_content()
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw or "")
    return payload.decode("utf-8", errors="replace")


def _parse_upload_from_multipart_body(
    *,
    body: bytes,
    content_type: str,
    max_file_bytes: int,
) -> Tuple[UploadFile, Dict[str, str], bytes]:
    parser_payload = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("latin-1")
        + body
    )
    try:
        message = BytesParser(policy=default).parsebytes(parser_payload)
    except Exception as exc:
        raise UploadRequestError(400, "Invalid multipart form payload.") from exc
    if not message.is_multipart():
        raise UploadRequestError(400, "Invalid multipart form payload.")

    fields: Dict[str, str] = {}
    file_upload: Optional[UploadFile] = None
    file_bytes: bytes = b""
    for part in message.iter_parts():
        field_name = str(part.get_param("name", header="Content-Disposition") or "").strip()
        filename = part.get_param("filename", header="Content-Disposition")

        if filename is not None:
            if file_upload is not None:
                raise UploadRequestError(400, "Only one file is supported per request.")
            payload = part.get_payload(decode=True) or b""
            if len(payload) > max_file_bytes:
                raise UploadRequestError(413, f"Upload too large. Max allowed is {max_file_bytes} bytes.")
            content_type_header = str(part.get_content_type() or "application/octet-stream")
            file_upload = UploadFile(
                file=io.BytesIO(payload),
                size=len(payload),
                filename=str(filename),
                headers=Headers({"content-type": content_type_header}),
            )
            file_bytes = payload
            continue

        if field_name:
            fields[field_name] = _form_field_value(part)

    if file_upload is None:
        raise UploadRequestError(400, "Form field 'file' is required.")
    return file_upload, fields, file_bytes


async def _upload_from_form_parser(request: Request, max_file_bytes: int) -> Tuple[UploadFile, Dict[str, str], bytes]:
    try:
        form = await request.form()
    except AssertionError:
        raise
    except Exception as exc:
        raise UploadRequestError(400, f"Invalid multipart form payload: {exc}") from exc

    file_field = form.get("file")
    if not isinstance(file_field, UploadFile):
        raise UploadRequestError(400, "Form field 'file' is required.")

    total = 0
    chunks = []
    while True:
        chunk = await file_field.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_file_bytes:
            raise UploadRequestError(413, f"Upload too large. Max allowed is {max_file_bytes} bytes.")
        chunks.append(chunk)
    payload = b"".join(chunks)
    await file_field.close()

    fields: Dict[str, str] = {}
    for key, value in form.multi_items():
        if key == "file":
            continue
        fields[str(key)] = str(value)

    upload = UploadFile(
        file=io.BytesIO(payload),
        size=len(payload),
        filename=str(file_field.filename or ""),
        headers=file_field.headers,
    )
    return upload, fields, payload


async def read_upload_from_request(
    request: Request,
    *,
    max_file_bytes: int,
    max_form_bytes: Optional[int] = None,
) -> Tuple[UploadFile, Dict[str, str], bytes]:
    content_type = _validate_content_type(request.headers.get("content-type", ""))
    max_form_payload = _safe_int(max_form_bytes, max_file_bytes + 256 * 1024)
    try:
        return await _upload_from_form_parser(request, max_file_bytes=max_file_bytes)
    except AssertionError:
        body = await _read_request_body_limited(request, max_bytes=max_form_payload)
        return _parse_upload_from_multipart_body(
            body=body,
            content_type=content_type,
            max_file_bytes=max_file_bytes,
        )


def validate_and_extract_text(
    *,
    filename: str,
    content_type: str,
    file_bytes: bytes,
) -> Tuple[FileInfo, str]:
    info = validate_file_info(filename, content_type)
    if not file_bytes:
        raise TextExtractionError("Uploaded file is empty.")
    text = extract_text_from_bytes(file_bytes, info)
    if not text.strip():
        raise TextExtractionError("No text content extracted from file.")
    return info, text


def scan_text_with_policy(
    *,
    text: str,
    tenant_policy: Dict[str, Any],
) -> Dict[str, Any]:
    scrubbed = scrub_prompt(text)
    cleaned_text = str(scrubbed.get("cleaned_prompt") or "")
    detections = list(scrubbed.get("detections") or [])
    placeholders = dict(scrubbed.get("placeholders") or {})

    injection = detect_prompt_injection(text)
    entity_counts = count_entities(detections)
    risk_pack = compute_risk_score(entity_counts, injection_detected=bool(injection.detected))
    policy_eval = evaluate_tenant_policy(
        tenant_policy=tenant_policy,
        risk_level=str(risk_pack.get("risk_level", "LOW")),
        risk_score=float(risk_pack.get("risk_score", 0.0)),
        entity_counts=entity_counts,
        category_counts=risk_pack.get("risk_categories") or {},
        cleaned_prompt=cleaned_text,
        redactions_applied=len(placeholders),
        injection_detected=bool(injection.detected),
    )

    decision = str(policy_eval.get("decision") or "ALLOW").upper()
    decision_reasons = [str(item) for item in policy_eval.get("reasons") or []]
    if injection.detected and injection.matches:
        decision_reasons.append(f"injection_signals={','.join(sorted(set(injection.matches)))}")

    return {
        "extracted_text": text,
        "redacted_text": str(policy_eval.get("cleaned_prompt") or cleaned_text),
        "entities": detections,
        "entity_counts": entity_counts,
        "risk_categories": risk_pack.get("risk_categories") or {},
        "risk_score": float(risk_pack.get("risk_score", 0.0)),
        "risk_level": str(risk_pack.get("risk_level", "LOW")),
        "severity": str(risk_pack.get("severity", "Low")),
        "decision": decision,
        "blocked": decision == "BLOCK",
        "allowed": decision != "BLOCK",
        "decision_reasons": decision_reasons,
        "findings_count": int(len(detections)),
        "injection_detected": bool(injection.detected),
    }
