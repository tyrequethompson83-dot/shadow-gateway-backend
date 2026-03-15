import os
import json
import httpx
from fastapi import HTTPException
from gemini_client import normalize_gemini_model

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash").strip()


async def send_to_gemini(clean_prompt: str) -> str:
    if not GEMINI_API_KEY:
        return "GEMINI_API_KEY not set. (local test response)"

    normalized_model = normalize_gemini_model(GEMINI_MODEL)
    model_id = normalized_model[len("models/") :]
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent"
    params = {"key": GEMINI_API_KEY}

    payload = {
        "contents": [
            {"role": "user", "parts": [{"text": clean_prompt}]}
        ]
    }

    async with httpx.AsyncClient(timeout=30, http2=False) as client:
        r = await client.post(url, params=params, json=payload)

    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Gemini error: {r.text}")

    data = r.json()

    try:
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(p.get("text", "") for p in parts).strip()
        return text or "(empty response)"
    except Exception:
        return json.dumps(data)[:2000]
