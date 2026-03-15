import os
import re
from dataclasses import dataclass
from typing import List


DEFAULT_ALLOWLIST = [
    "prompt injection training",
    "example of prompt injection",
    "security awareness",
]

HEURISTIC_PATTERNS = [
    (re.compile(r"\bignore\s+(all|any|the|previous|prior)\s+(instructions|rules|prompts?)\b", re.I), "ignore_instructions"),
    (re.compile(r"\b(system prompt|developer message|hidden instructions?)\b", re.I), "prompt_exfiltration"),
    (re.compile(r"\b(bypass|disable|override)\s+(safety|policy|guardrail|filters?)\b", re.I), "safety_bypass"),
    (re.compile(r"\b(jailbreak|do anything now|dan)\b", re.I), "jailbreak"),
    (re.compile(r"\breveal\s+.*\b(api key|secret|password|token)\b", re.I), "secret_exfiltration"),
    (re.compile(r"\brole[- ]?play\s+as\s+(system|developer)\b", re.I), "role_escalation"),
]


@dataclass
class InjectionResult:
    detected: bool
    category: str
    severity: str
    matches: List[str]
    score: int


def _load_allowlist() -> List[str]:
    raw = os.getenv("INJECTION_ALLOWLIST", "").strip()
    values = [v.strip().lower() for v in raw.split(",") if v.strip()]
    return DEFAULT_ALLOWLIST + values


def detect_prompt_injection(text: str) -> InjectionResult:
    prompt = (text or "").strip()
    if not prompt:
        return InjectionResult(False, "PROMPT_INJECTION", "Low", [], 0)

    lowered = prompt.lower()
    for allowed in _load_allowlist():
        if allowed and allowed in lowered:
            return InjectionResult(False, "PROMPT_INJECTION", "Low", [], 0)

    matches: List[str] = []
    for pattern, tag in HEURISTIC_PATTERNS:
        if pattern.search(prompt):
            matches.append(tag)

    if not matches:
        return InjectionResult(False, "PROMPT_INJECTION", "Low", [], 0)

    score = min(100, 30 + (len(matches) * 20))
    if score >= 80:
        severity = "Critical"
    elif score >= 60:
        severity = "High"
    elif score >= 35:
        severity = "Med"
    else:
        severity = "Low"

    return InjectionResult(True, "PROMPT_INJECTION", severity, sorted(set(matches)), score)
