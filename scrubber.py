import re
from typing import Dict, List, Tuple, Any

from presidio_analyzer import AnalyzerEngine, RecognizerResult


# ---- Hard-coded regex "safety net" patterns ----
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Examples (tune these later)
OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")
GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b")
GENERIC_SECRET_RE = re.compile(r"\b(?:api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{16,}\b", re.I)
GOVERNMENT_ID_RE = re.compile(
    r"\b(?:passport|driver(?:'s)?\s*license|national\s*id|government\s*id|tax\s*id)\s*[:#]?\s*[A-Za-z0-9\-]{5,20}\b",
    re.I,
)
PHI_KEYWORD_RE = re.compile(
    r"\b(patient|diagnosis|prescription|treatment|medical\s+record|lab\s+result|blood\s+pressure|hiv|oncology)\b",
    re.I,
)

CREDIT_CARD_FALLBACK_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
EMAIL_FALLBACK_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
TECHNICAL_INDICATOR_RE = re.compile(r"\b(import|def|class|async|from|return|httpx|asyncio)\b", re.I)
PERSON_LOCATION_CONFIDENCE_THRESHOLD = 0.80
ANALYTICS_ONLY_ENTITIES = {"LOCATION"}
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CLASS_NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9]*$")


def _is_luhn_valid(candidate: str) -> bool:
    digits = [int(ch) for ch in candidate if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        value = digit
        if idx % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        checksum += value
    return checksum % 10 == 0


def _is_technical_prompt(text: str) -> bool:
    return bool(TECHNICAL_INDICATOR_RE.search(str(text or "")))


def _is_python_syntax_token(text: str, start: int, end: int) -> bool:
    if start < 0 or end <= start or end > len(text):
        return False
    token = text[start:end]
    if not IDENTIFIER_RE.fullmatch(token):
        return False

    prev_char = text[start - 1] if start > 0 else ""
    next_char = text[end] if end < len(text) else ""

    # module.function or dotted attribute access.
    if prev_char == "." or next_char == ".":
        return True
    # function() style call.
    if next_char == "(":
        return True
    # snake_case variable names.
    if "_" in token:
        return True
    # ClassName / CamelCase identifier.
    if CLASS_NAME_RE.fullmatch(token) and any(ch.isupper() for ch in token[1:]):
        return True
    return False


def _apply_regex_safety_net(text: str) -> Tuple[str, Dict[str, str], List[Dict[str, Any]]]:
    """
    Replace high-risk patterns first with placeholders.
    Returns (updated_text, placeholder_map).
    """
    placeholder_map: Dict[str, str] = {}
    counters: Dict[str, int] = {}
    detections: List[Dict[str, Any]] = []

    def repl(pattern: re.Pattern, label: str, s: str, validator=None) -> str:
        def _r(m: re.Match) -> str:
            value = m.group(0)
            if validator and not validator(value):
                return value
            counters[label] = counters.get(label, 0) + 1
            ph = f"[{label}_{counters[label]}]"
            placeholder_map[ph] = value
            detections.append(
                {
                    "entity_type": label,
                    "start": m.start(),
                    "end": m.end(),
                    "score": 1.0,
                    "placeholder": ph,
                }
            )
            return ph
        return pattern.sub(_r, s)

    # Order matters: most sensitive first
    text = repl(SSN_RE, "US_SSN", text)
    text = repl(GOVERNMENT_ID_RE, "GOVERNMENT_ID", text)
    text = repl(OPENAI_KEY_RE, "API_KEY", text)
    text = repl(ANTHROPIC_KEY_RE, "API_KEY", text)
    text = repl(GOOGLE_API_KEY_RE, "API_KEY", text)
    text = repl(GENERIC_SECRET_RE, "SECRET_TOKEN", text)
    text = repl(PHI_KEYWORD_RE, "PHI_TERM", text)

    # Fallbacks (optional)
    text = repl(EMAIL_FALLBACK_RE, "EMAIL_ADDRESS", text)
    text = repl(CREDIT_CARD_FALLBACK_RE, "CREDIT_CARD", text, validator=_is_luhn_valid)

    return text, placeholder_map, detections


def _presidio_engine() -> AnalyzerEngine:
    """
    Presidio AnalyzerEngine uses spaCy under the hood.
    Make sure you've installed a model:
      python -m spacy download en_core_web_sm
    """
    return AnalyzerEngine()


def _presidio_detect(text: str, engine: AnalyzerEngine, *, technical_mode: bool = False) -> List[RecognizerResult]:
    entities = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "US_SSN",
        "IP_ADDRESS",
    ]
    if not technical_mode:
        entities.extend(["PERSON", "LOCATION"])
    results = engine.analyze(text=text, entities=entities, language="en")
    # Replace from back to front to avoid index shifting
    return sorted(results, key=lambda r: r.start, reverse=True)


def _tokenize_with_placeholders(
    text: str, results: List[RecognizerResult]
) -> Tuple[str, Dict[str, str], List[Dict[str, Any]]]:
    """
    Replace detected entity spans with placeholders.
    Returns: cleaned_text, placeholder_map, detections
    """
    placeholder_map: Dict[str, str] = {}
    counters: Dict[str, int] = {}

    detections: List[Dict[str, Any]] = []

    for r in results:
        original = text[r.start:r.end]
        ent = r.entity_type
        score = float(r.score)

        # Preserve code identifiers (module.function(), variable_name, ClassName).
        if _is_python_syntax_token(text, r.start, r.end):
            continue

        if ent in {"PERSON", "LOCATION"} and score <= PERSON_LOCATION_CONFIDENCE_THRESHOLD:
            continue

        if ent in ANALYTICS_ONLY_ENTITIES:
            detections.append(
                {
                    "entity_type": ent,
                    "start": r.start,
                    "end": r.end,
                    "score": score,
                    "redacted": False,
                }
            )
            continue

        counters[ent] = counters.get(ent, 0) + 1
        ph = f"[{ent}_{counters[ent]}]"

        # Save mapping (first occurrence)
        if ph not in placeholder_map:
            placeholder_map[ph] = original

        # Replace span
        text = text[: r.start] + ph + text[r.end :]

        detections.append(
            {
                "entity_type": ent,
                "start": r.start,
                "end": r.end,
                "score": score,
                "placeholder": ph,
            }
        )

    return text, placeholder_map, detections


def scrub_prompt(prompt: str) -> Dict[str, Any]:
    """
    Main entry point.
    Returns dict with:
      cleaned_prompt, placeholders, detections
    """
    technical_mode = _is_technical_prompt(prompt)

    # 1) Regex safety net
    stage1_text, regex_map, regex_detections = _apply_regex_safety_net(prompt)

    # 2) Presidio detect + tokenize
    engine = _presidio_engine()
    results = _presidio_detect(stage1_text, engine, technical_mode=technical_mode)
    cleaned, presidio_map, detections = _tokenize_with_placeholders(stage1_text, results)

    # 3) Merge maps
    placeholders = dict(regex_map)
    placeholders.update(presidio_map)

    return {
        "cleaned_prompt": cleaned,
        "placeholders": placeholders,
        "detections": regex_detections + detections,
        "technical_mode": technical_mode,
    }


def rehydrate(text: str, placeholders: Dict[str, str]) -> str:
    """
    Replace placeholders back with originals.
    Only do this for the INTERNAL user view, never before sending to the LLM.
    """
    for ph in sorted(placeholders.keys(), key=len, reverse=True):
        text = text.replace(ph, placeholders[ph])
    return text
