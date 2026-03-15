# Shadow AI Gateway

FastAPI gateway with tenant-aware policy controls, sensitive-data redaction, prompt-injection defenses, multi-provider LLM routing, audit chain, quotas, metrics, and Streamlit UIs.

## Core Features

- Multi-provider runtime: `gemini`, `openai`, `anthropic` (per tenant).
- Prompt injection detection (`PROMPT_INJECTION`) with DB-backed policy actions.
- Advanced classification buckets: `PII`, `FIN`, `SECRETS`, `HEALTH`, `IP`.
- DB-backed policy editor (injection/category/severity ordered evaluation).
- Compliance export jobs (CSV + JSON packaged as ZIP).
- Prometheus `/metrics` endpoint + live monitoring tab.
- API key encryption at rest (`MASTER_KEY`) with legacy plaintext auto-migration.
- Tenant provider key management (`GET/PUT/DELETE /tenant/keys`) with masked tails only.
- Reversible redaction for user responses (`RESTORE_REDACTED_VALUES=true` by default) while upstream/provider prompts remain sanitized.
- Auth modes:
  - `AUTH_MODE=header` (default): `X-User` / `X-Tenant-Id`.
  - `AUTH_MODE=jwt`: bearer token signup/login + role checks.
- Product onboarding endpoints:
  - `POST /auth/signup/company`
  - `POST /auth/signup/individual`
  - `POST /auth/signup/invite`
  - `POST /auth/login`
  - `GET /me`
  - `POST /tenant/admin/invite`
  - `GET /tenant/keys`
  - `PUT /tenant/keys`
  - `DELETE /tenant/keys/{provider}`

## Provider API Choices

- OpenAI provider uses the **Responses API** (`POST /v1/responses`) with deterministic request settings (`temperature=0`, `top_p=1`).
- Anthropic provider uses the **Messages API** (`POST /v1/messages`) and sends required headers:
  - `x-api-key`
  - `anthropic-version` (default `2023-06-01`)

## Run Locally

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

Set required environment variables before starting the API:

```powershell
$env:JWT_SECRET="replace-with-a-strong-random-secret-at-least-32-chars"
$env:AUTH_MODE="jwt"
```

Start backend (FastAPI on `8080`):

```powershell
python -m uvicorn main:app --reload --port 8080
```

Start product app (Streamlit on `8501`):

```powershell
.\.venv\Scripts\activate
python -m streamlit run product_app.py
```

## Client Run Instructions (Docker)

1. Copy the environment template:

```powershell
Copy-Item .env.example .env
```

2. Edit `.env` and set at minimum:
   - `APP_ENV` (`dev` or `prod`)
   - `JWT_SECRET` (32+ chars)
   - `MASTER_KEY` (32+ chars)
   - `ALLOWED_ORIGINS` (comma-separated origins)

3. Start the full stack (API + product app + persisted SQLite + startup migrations):

```powershell
docker compose up --build
```

4. Open the product app at `http://localhost:8501`.

## Run Other UIs

In separate terminals:

```powershell
.\.venv\Scripts\activate
python -m streamlit run onboarding_wizard.py
```

```powershell
.\.venv\Scripts\activate
python -m streamlit run employee_chat.py
```

```powershell
.\.venv\Scripts\activate
python -m streamlit run dashboard_admin.py
```

## URLs

- API: `http://127.0.0.1:8080`
- API docs (dev): `http://127.0.0.1:8080/docs`
- Product app: `http://127.0.0.1:8501` (`product_app.py`)
- Employee chat UI: `http://127.0.0.1:8501` (employee_chat)
- Admin UI: `http://127.0.0.1:8501` (dashboard_admin; run in its own process)
- Onboarding wizard: `http://127.0.0.1:8501` (onboarding_wizard; run in its own process)
- Metrics: `http://127.0.0.1:8080/metrics`

## Required / Important Env Vars

- `DB_PATH` (default `app.db`)
- `LOG_DIR` (default `logs`)
- `AUDIT_SIGNING_KEY`
- `ENABLE_TENANT_LIMITS` (`true`/`false`)
- `ENABLE_JOB_WORKER` (`true`/`false`)
- `RESTORE_REDACTED_VALUES` (`true`/`false`, default `true`)
- `MASTER_KEY` (required in prod for encryption at rest)
- `SHADOW_MASTER_KEY` (legacy alias)
- `APP_ENV` (`dev` default, `prod` for strict mode)
- `ALLOWED_ORIGINS` (required in prod; comma-separated)

### Auth

- `AUTH_MODE=header|jwt`
- `JWT_SECRET`
- `JWT_ALGORITHM` is fixed to `HS256`
- Token lifetime is 60 minutes in `dev`, 30 minutes in `prod`

### Gemini

- `GEMINI_API_KEY`
- `GEMINI_MODEL`
- `GEMINI_TIMEOUT_SECONDS`
- `GEMINI_MAX_RETRIES`
- `GEMINI_RETRY_BASE_SECONDS`

### OpenAI

- `OPENAI_API_KEY`
- `OPENAI_MODEL` (default `gpt-4.1-mini`)
- `OPENAI_TIMEOUT_SECONDS`
- `OPENAI_MAX_RETRIES`
- `OPENAI_RETRY_BASE_SECONDS`

### Anthropic

- `ANTHROPIC_API_KEY`
- `ANTHROPIC_MODEL` (default `claude-3-5-haiku-latest`)
- `ANTHROPIC_VERSION` (default `2023-06-01`)
- `ANTHROPIC_MAX_TOKENS` (default `512`)
- `ANTHROPIC_TIMEOUT_SECONDS`
- `ANTHROPIC_MAX_RETRIES`
- `ANTHROPIC_RETRY_BASE_SECONDS`

### Injection / Policy

- `INJECTION_ALLOWLIST` (comma-separated allowlist terms)

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

Current status: **27 passed**.

## Production Safety Checklist

- Set `APP_ENV=prod` in all production deployments.
- Set a strong `JWT_SECRET` (at least 32 characters).
- Set a strong `MASTER_KEY` (at least 32 characters).
- Set `ALLOWED_ORIGINS` explicitly (comma-separated frontend origins).
- Do not use `X-User` auth outside `dev`; prod rejects it.
- Keep `AUTH_MODE=jwt` in production.
- Ensure provider keys are managed through tenant admin access only.
- Provider keys are encrypted at rest in SQLite; UI/API responses only expose key tail.
- Provider keys can be deleted immediately via `DELETE /tenant/keys/{provider}`.

### Quick Verification Checklist

- brute-force triggers `429` on repeated login attempts.
- lockout triggers after repeated credential failures.
- `X-User` is rejected when `APP_ENV=prod`.
- cross-tenant access attempts are blocked.
- employee role is blocked from `/admin/*` and `/tenant/admin/*`.
