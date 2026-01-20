import os
import json
from pathlib import Path

import pytest

from core.pipeline import run_pipeline
from core.ai.reasoner import reason_with_llm


@pytest.fixture(autouse=True)
def force_offline_mode(monkeypatch):
    """
    Force offline mode for all tests in this module.
    Ensures ZERO network calls and ZERO cost.
    """
    monkeypatch.setenv("LLM_OFFLINE", "1")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)


def _sample_incident():
    return {
        "incident_id": "test-001",
        "source": "unit-test",
        "title": "Suspicious login",
        "severity": "high",
        "timestamp": "2026-01-20T12:00:00Z",
        "entities": [
            {"type": "user", "value": "user@corp.com"},
            {"type": "ip", "value": "8.8.8.8"},
        ],
    }


def _sample_signals():
    return {
        "virustotal": {"malicious": 5, "total": 70},
        "abuseipdb": {"confidence": 60},
        "whois": {"domain_age_days": 10},
        "asn": {"type": "hosting", "is_bulletproof": False},
        "context": {
            "login_anomaly": True,
            "impossible_travel": True,
            "mfa_enabled": False,
            "prior_incidents": 1,
        },
    }


def test_ai_reasoner_offline_schema_valid():
    """
    GIVEN deterministic pipeline output
    WHEN AI reasoning runs in offline mode
    THEN output is schema-valid and contains required fields
    """

    deterministic = run_pipeline(
        incident=_sample_incident(),
        signals=_sample_signals(),
    )

    ai_output = reason_with_llm(deterministic)

    # Basic structural assertions
    assert isinstance(ai_output, dict)
    assert "observations" in ai_output
    assert "assessment" in ai_output
    assert "mitre_mapping" in ai_output
    assert "recommendations" in ai_output
    assert "confidence" in ai_output
    assert "assumptions" in ai_output
    assert "missing_data" in ai_output

    # Offline mode must be explicit
    assert any(
        "offline" in a.lower() or "disabled" in a.lower()
        for a in ai_output.get("assumptions", [])
    )

    # Confidence must be bounded
    assert isinstance(ai_output["confidence"], int)
    assert 0 <= ai_output["confidence"] <= 100

    # MITRE mapping must be structured
    for m in ai_output["mitre_mapping"]:
        assert "tactic" in m
        assert "technique" in m
        assert "confidence" in m
        assert isinstance(m["confidence"], float)


def test_ai_offline_no_network_calls(monkeypatch):
    """
    Ensures that requests.post is NEVER called in offline mode.
    """

    called = {"count": 0}

    def fake_post(*args, **kwargs):
        called["count"] += 1
        raise AssertionError("Network call attempted in offline mode")

    monkeypatch.setattr("requests.post", fake_post)

    deterministic = run_pipeline(
        incident=_sample_incident(),
        signals=_sample_signals(),
    )

    _ = reason_with_llm(deterministic)

    assert called["count"] == 0
