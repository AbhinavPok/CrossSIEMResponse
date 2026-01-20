from __future__ import annotations

import time
from collections import deque
import json
import os
from typing import Any, Dict

import requests

from core.ai.validator import load_schema, validate_against_schema, AIOutputValidationError


class AIReasonerError(Exception):
    pass


# -----------------------------
# Cost / Safety Controls (env)
# -----------------------------
_MAX_CALLS_PER_MIN = int(os.getenv("LLM_MAX_CALLS_PER_MIN", "10"))
_MAX_PROMPT_CHARS = int(os.getenv("LLM_MAX_PROMPT_CHARS", "12000"))
_AUDIT_ENABLED = os.getenv("LLM_AUDIT", "1").strip() == "1"

# in-memory per-process call window (good enough for local/dev; for multi-worker use Redis later)
_call_times = deque()  # timestamps (float epoch seconds)


def _audit_log(event: str, details: Dict[str, Any]) -> None:
    """
    Minimal audit log (stdout). Safe to ship; can later redirect to file/SIEM.
    """
    if not _AUDIT_ENABLED:
        return
    record = {
        "ts": time.time(),
        "event": event,
        "details": details,
    }
    print(f"[AI_AUDIT] {json.dumps(record, ensure_ascii=False)}")


def _enforce_rate_limit() -> None:
    """
    Hard rate limit to prevent runaway cost.
    """
    now = time.time()
    window_start = now - 60

    while _call_times and _call_times[0] < window_start:
        _call_times.popleft()

    if len(_call_times) >= _MAX_CALLS_PER_MIN:
        raise AIReasonerError(f"AI rate limit exceeded ({_MAX_CALLS_PER_MIN}/minute).")

    _call_times.append(now)


def _offline_fallback(deterministic: Dict[str, Any]) -> Dict[str, Any]:
    """
    Schema-valid fallback output when LLM_OFFLINE=1 or no key configured.
    Keeps your pipeline testable and demoable without paid calls.
    """
    scoring = deterministic.get("scoring", {})
    mitre = deterministic.get("mitre", [])

    obs = [
        f"Deterministic score={scoring.get('score')} level={scoring.get('level')}.",
        "MITRE hypotheses were generated from bounded rules (not AI).",
    ]

    if scoring.get("reasons"):
        obs.append("Top scoring reasons: " + "; ".join(scoring["reasons"][:3]))

    mitre_lines = []
    for m in mitre[:3]:
        mitre_lines.append(f"{m.get('technique')} ({m.get('confidence')})")
    if mitre_lines:
        obs.append("Top MITRE candidates: " + ", ".join(mitre_lines))

    out = {
        "observations": obs,
        "assessment": (
            "Offline mode: advisory summary generated without an LLM. "
            "Enable live mode to generate richer narrative and recommended queries."
        ),
        "mitre_mapping": [
            {
                "tactic": m.get("tactic", ""),
                "technique": m.get("technique", ""),
                "confidence": float(m.get("confidence", 0.0) or 0.0),
                "evidence": m.get("evidence", []) or []
            }
            for m in mitre[:5]
        ],
        "recommendations": [
            {"type": "verification", "description": "Confirm the entities (IP/user/domain) exist in logs and match the incident timeline."},
            {"type": "monitoring", "description": "Monitor for repeated authentication failures, impossible travel, and new device sign-ins."},
            {"type": "containment", "description": "If confidence remains high after verification: reset credentials and enforce MFA for impacted accounts."}
        ],
        "confidence": int(scoring.get("score", 0) or 0),
        "assumptions": ["Live LLM reasoning is disabled (LLM_OFFLINE=1 or missing API key)."],
        "missing_data": ["Raw authentication event details (source IP, user agent, device ID, geo), and correlated alerts across hosts/users."]
    }
    return out


def _build_prompt(deterministic: Dict[str, Any]) -> str:
    """
    Instruct the model to return STRICT JSON matching our ai_response.schema.json.
    """
    incident = deterministic.get("incident", {})
    scoring = deterministic.get("scoring", {})
    mitre = deterministic.get("mitre", [])

    context = {
        "incident": {
            "title": incident.get("title"),
            "severity": incident.get("severity"),
            "timestamp": incident.get("timestamp"),
            "source": incident.get("source"),
            "entities": incident.get("entities", []),
            "tags": incident.get("tags", []),
        },
        "scoring": {
            "score": scoring.get("score"),
            "level": scoring.get("level"),
            "reasons": scoring.get("reasons", []),
            "signals_used": scoring.get("signals_used", {}),
        },
        "mitre_candidates": mitre,
    }

    prompt = (
        "You are a SOC triage assistant. Produce an ADVISORY triage response.\n"
        "Rules:\n"
        "1) Output MUST be valid JSON only. No markdown. No extra keys.\n"
        "2) Do not claim actions were executed.\n"
        "3) If evidence is missing, state assumptions and missing_data.\n"
        "4) Keep recommendations actionable and safe.\n"
        "5) Confidence is 0-100 (integer).\n\n"
        "Return JSON matching this exact shape:\n"
        "{\n"
        '  "observations": ["..."],\n'
        '  "assessment": "...",\n'
        '  "mitre_mapping": [{"tactic":"...","technique":"Txxxx - ...","confidence":0.0,"evidence":["..."]}],\n'
        '  "recommendations": [{"type":"query|verification|containment|monitoring","description":"..."}],\n'
        '  "confidence": 0,\n'
        '  "assumptions": ["..."],\n'
        '  "missing_data": ["..."]\n'
        "}\n\n"
        "Here is the deterministic context (JSON):\n"
        + json.dumps(context, ensure_ascii=False)
    )

    # Prompt size guard (cost/safety)
    if len(prompt) > _MAX_PROMPT_CHARS:
        raise AIReasonerError(
            f"Prompt exceeds limit ({len(prompt)} chars > {_MAX_PROMPT_CHARS}). Refusing AI call."
        )

    return prompt


def reason_with_llm(
    deterministic: Dict[str, Any],
    schema_path: str = "schemas/ai_response.schema.json",
    timeout_s: int = 45
) -> Dict[str, Any]:
    """
    Produces schema-validated AI advisory output.

    Env vars:
      LLM_OFFLINE=1                     -> use offline fallback (no network)
      LLM_BASE_URL=https://api.openai.com/v1
      LLM_API_KEY=...
      LLM_MODEL=gpt-4o-mini (example)
      LLM_TEMPERATURE=0.2
      LLM_MAX_CALLS_PER_MIN=10          -> hard rate limit (per process)
      LLM_MAX_PROMPT_CHARS=12000        -> hard prompt size guard
      LLM_AUDIT=1                       -> audit logs to stdout
    """
    schema = load_schema(schema_path)

    # Kill switch
    if os.getenv("LLM_OFFLINE", "").strip() == "1":
        _audit_log("ai_fallback_used", {"reason": "LLM_OFFLINE=1"})
        out = _offline_fallback(deterministic)
        validate_against_schema(out, schema)
        return out

    base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    api_key = os.getenv("LLM_API_KEY", "").strip()
    model = os.getenv("LLM_MODEL", "").strip()
    temperature = float(os.getenv("LLM_TEMPERATURE", "0.2"))

    # Conservative guardrail
    if temperature > 0.3:
        raise AIReasonerError("LLM_TEMPERATURE too high for SOC-safe mode. Use <= 0.3.")

    # Missing config -> safe fallback
    if not api_key or not model:
        _audit_log("ai_fallback_used", {"reason": "missing_api_key_or_model"})
        out = _offline_fallback(deterministic)
        validate_against_schema(out, schema)
        return out

    # Hard rate limit before any network call
    _enforce_rate_limit()

    prompt = _build_prompt(deterministic)

    url = f"{base_url}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": "You are a careful SOC analyst. Follow the schema exactly."},
            {"role": "user", "content": prompt}
        ],
        "response_format": {"type": "json_object"}
    }

    _audit_log("ai_call_attempt", {"model": model, "base_url": base_url})

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
        r.raise_for_status()
        data = r.json()

        content = data["choices"][0]["message"]["content"]
        out = json.loads(content)

        validate_against_schema(out, schema)

        _audit_log("ai_call_success", {"model": model})
        return out

    except (requests.RequestException, KeyError, ValueError, AIOutputValidationError) as e:
        _audit_log("ai_call_failed", {"error": str(e)})
        raise AIReasonerError(str(e)) from e
