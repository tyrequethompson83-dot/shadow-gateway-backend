import os
from typing import List


APP_ENV_DEV = "dev"
APP_ENV_PROD = "prod"
DEFAULT_DEV_STREAMLIT_ORIGIN = "http://127.0.0.1:8501"
DEFAULT_DEV_NEXT_ORIGIN = "http://127.0.0.1:3000"
DEFAULT_PROD_FRONTEND_ORIGIN = "https://app.shadowaigateway.com"
ALT_PROD_FRONTEND_ORIGIN = "https://shadowaigateway.com"
REQUIRED_CORS_ORIGINS = [
    DEFAULT_PROD_FRONTEND_ORIGIN,
    ALT_PROD_FRONTEND_ORIGIN,
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


def app_env() -> str:
    raw = (os.getenv("APP_ENV", APP_ENV_DEV) or APP_ENV_DEV).strip().lower()
    if raw == APP_ENV_PROD:
        return APP_ENV_PROD
    return APP_ENV_DEV


def is_dev() -> bool:
    return app_env() == APP_ENV_DEV


def is_prod() -> bool:
    return app_env() == APP_ENV_PROD


def dev_streamlit_origin() -> str:
    origin = (os.getenv("STREAMLIT_ORIGIN", DEFAULT_DEV_STREAMLIT_ORIGIN) or DEFAULT_DEV_STREAMLIT_ORIGIN).strip()
    return origin or DEFAULT_DEV_STREAMLIT_ORIGIN


def dev_next_origin() -> str:
    origin = (os.getenv("NEXT_ORIGIN", DEFAULT_DEV_NEXT_ORIGIN) or DEFAULT_DEV_NEXT_ORIGIN).strip()
    return origin or DEFAULT_DEV_NEXT_ORIGIN


def _parse_origins_csv(raw: str) -> List[str]:
    out: List[str] = []
    for item in (raw or "").split(","):
        origin = item.strip()
        if origin and origin not in out:
            out.append(origin)
    return out


def _normalize_dev_origins(origins: List[str]) -> List[str]:
    out: List[str] = []
    for origin in origins:
        value = (origin or "").strip()
        if value and value not in out:
            out.append(value)
    return out


def cors_allowed_origins() -> List[str]:
    if is_dev():
        extras = _parse_origins_csv((os.getenv("DEV_ALLOWED_ORIGINS", "") or "").strip())
        return _normalize_dev_origins(
            [
                dev_streamlit_origin(),
                "http://localhost:8501",
                dev_next_origin(),
                "http://localhost:3000",
                *REQUIRED_CORS_ORIGINS,
                *extras,
            ]
        )
    raw = (os.getenv("ALLOWED_ORIGINS", "") or "").strip()
    origins = _parse_origins_csv(raw)
    configured_prod_origin = (
        os.getenv("PROD_FRONTEND_ORIGIN", DEFAULT_PROD_FRONTEND_ORIGIN) or DEFAULT_PROD_FRONTEND_ORIGIN
    ).strip()
    required_origins = [
        configured_prod_origin,
        ALT_PROD_FRONTEND_ORIGIN,
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    origins = _normalize_dev_origins([*origins, *required_origins])
    if not origins:
        raise ValueError("ALLOWED_ORIGINS or PROD_FRONTEND_ORIGIN must be set when APP_ENV=prod")
    return origins
