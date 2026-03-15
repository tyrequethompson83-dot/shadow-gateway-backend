import base64
import json
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

try:
    import jwt as pyjwt
except Exception:  # pragma: no cover - fallback used when PyJWT unavailable
    pyjwt = None
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app_config import is_prod


ENC_PREFIX_V1 = "enc:v1:"
ENC_PREFIX_V2 = "enc:v2:"
ENC_PREFIX = ENC_PREFIX_V2
PASSWORD_ITERATIONS = int(os.getenv("PASSWORD_HASH_ITERATIONS", "210000"))
JWT_ALGORITHM = "HS256"
DEV_JWT_SECRET = "dev-only-jwt-secret-not-for-prod-0123456789"
MASTER_KEY_MIN_LEN_PROD = 32
SENSITIVE_KEY_MARKERS = (
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
)
COMMON_WEAK_PASSWORDS = {
    "password",
    "password123",
    "1234567890",
    "123456789",
    "qwertyuiop",
    "qwerty123",
    "letmein123",
    "welcome123",
    "admin123456",
    "iloveyou123",
}


def _derive_fernet_key(master_key: str) -> bytes:
    digest = hashlib.sha256(master_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _resolve_master_key() -> str:
    return (os.getenv("MASTER_KEY", "").strip() or os.getenv("SHADOW_MASTER_KEY", "").strip())


def validate_master_key_config() -> None:
    master_key = _resolve_master_key()
    if is_prod():
        if not master_key:
            raise ValueError("MASTER_KEY must be set when APP_ENV=prod")
        if len(master_key) < MASTER_KEY_MIN_LEN_PROD:
            raise ValueError("MASTER_KEY must be at least 32 characters when APP_ENV=prod")


def _get_fernet() -> Fernet | None:
    master_key = _resolve_master_key()
    if not master_key:
        return None
    return Fernet(_derive_fernet_key(master_key))


def _get_aesgcm() -> AESGCM | None:
    master_key = _resolve_master_key()
    if not master_key:
        return None
    digest = hashlib.sha256(master_key.encode("utf-8")).digest()
    return AESGCM(digest)


def is_encrypted_secret(value: str | None) -> bool:
    text = (value or "").strip()
    return text.startswith(ENC_PREFIX_V2) or text.startswith(ENC_PREFIX_V1)


def encrypt_secret(value: str | None) -> str:
    plain = (value or "").strip()
    if not plain:
        return ""
    aesgcm = _get_aesgcm()
    if aesgcm is None:
        if is_prod():
            raise ValueError("MASTER_KEY must be set when APP_ENV=prod")
        return plain
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plain.encode("utf-8"), None)
    packed = base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")
    return f"{ENC_PREFIX_V2}{packed}"


def decrypt_secret(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if raw.startswith(ENC_PREFIX_V2):
        aesgcm = _get_aesgcm()
        if aesgcm is None:
            raise ValueError("Encrypted secret present but MASTER_KEY is not set")
        token = raw[len(ENC_PREFIX_V2) :]
        try:
            blob = base64.urlsafe_b64decode(token.encode("utf-8"))
            nonce = blob[:12]
            ciphertext = blob[12:]
            plain = aesgcm.decrypt(nonce, ciphertext, None)
            return plain.decode("utf-8")
        except Exception as exc:
            raise ValueError("Unable to decrypt secret with current MASTER_KEY") from exc
    if raw.startswith(ENC_PREFIX_V1):
        fernet = _get_fernet()
        if fernet is None:
            raise ValueError("Encrypted secret present but MASTER_KEY is not set")
        token = raw[len(ENC_PREFIX_V1) :]
        try:
            return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Unable to decrypt secret with current MASTER_KEY") from exc
    if not is_encrypted_secret(raw):
        return raw
    return raw


def mask_key_tail(value: str | None, visible: int = 4) -> str | None:
    text = (value or "").strip()
    if not text:
        return None
    return text[-max(1, int(visible)) :]


def _validate_password_policy(password: str) -> str:
    pw = (password or "").strip()
    if len(pw) < 10:
        raise ValueError("password must be at least 10 characters")
    if pw.lower() in COMMON_WEAK_PASSWORDS:
        raise ValueError("password is too common")
    return pw


def make_password_hash(password: str, salt_hex: str | None = None) -> Dict[str, str]:
    pw = _validate_password_policy(password)
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        pw.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return {
        "password_hash": digest.hex(),
        "password_salt": salt.hex(),
    }


def verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    if not password_hash or not password_salt:
        return False
    pw = (password or "").strip()
    try:
        salt = bytes.fromhex(password_salt)
    except Exception:
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        pw.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return hmac.compare_digest(digest.hex(), password_hash)


def _jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET", "").strip()
    if not secret:
        if is_prod():
            raise ValueError("JWT_SECRET must be set when APP_ENV=prod")
        secret = DEV_JWT_SECRET
    if is_prod() and len(secret) < 32:
        raise ValueError("JWT_SECRET must be at least 32 characters when APP_ENV=prod")
    return secret


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("utf-8"))


def _fallback_issue_jwt(payload: Dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("utf-8")
    signature = hmac.new(_jwt_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_part = _b64url_encode(signature)
    return f"{header_part}.{payload_part}.{sig_part}"


def _fallback_decode_jwt(token: str) -> Dict[str, Any]:
    parts = (token or "").split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    header_part, payload_part, sig_part = parts
    signing_input = f"{header_part}.{payload_part}".encode("utf-8")
    expected = hmac.new(_jwt_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    actual = _b64url_decode(sig_part)
    if not hmac.compare_digest(expected, actual):
        raise ValueError("Invalid token signature")
    payload = json.loads(_b64url_decode(payload_part).decode("utf-8"))
    exp = int(payload.get("exp", 0) or 0)
    if exp and int(datetime.now(timezone.utc).timestamp()) > exp:
        raise ValueError("Token expired")
    return payload


def _jwt_exp_minutes_default() -> int:
    return 30 if is_prod() else 60


def issue_jwt(payload: Dict[str, Any], expires_minutes: int | None = None) -> str:
    exp_minutes = int(expires_minutes) if expires_minutes is not None else _jwt_exp_minutes_default()
    now = datetime.now(timezone.utc)
    data = dict(payload)
    data["iat"] = int(now.timestamp())
    data["exp"] = int((now + timedelta(minutes=max(1, exp_minutes))).timestamp())
    data["jti"] = str(data.get("jti") or uuid.uuid4().hex)
    if pyjwt is not None:
        return pyjwt.encode(data, _jwt_secret(), algorithm=JWT_ALGORITHM)
    return _fallback_issue_jwt(data)


def decode_jwt(token: str) -> Dict[str, Any]:
    if pyjwt is not None:
        return pyjwt.decode(token, _jwt_secret(), algorithms=[JWT_ALGORITHM])
    return _fallback_decode_jwt(token)


def _looks_sensitive_key(key: str) -> bool:
    lowered = (key or "").strip().lower()
    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, item in value.items():
            if _looks_sensitive_key(str(key)):
                out[str(key)] = "[REDACTED]"
            else:
                out[str(key)] = redact_secrets(item)
        return out
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    if isinstance(value, str):
        text = value.strip()
        if text.lower().startswith("bearer "):
            return "Bearer [REDACTED]"
        return value
    return value


def validate_runtime_security() -> None:
    _jwt_secret()
    validate_master_key_config()
