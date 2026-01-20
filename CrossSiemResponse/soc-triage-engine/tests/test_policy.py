import os
import pytest

from core.pipeline import run_pipeline


def _base_incident():
    return {
        "incident_id": "test-incident",
        "source": "local",
        "title": "Test incident",
        "severity": "high",
        "timestamp": "2026-01-20T12:00:00Z",
        "entities": [
            {"type": "user", "value": "exec@corp.com"}
        ],
    }


def test_policy_triggers_for_high_risk_exec(monkeypatch):
    """
    GIVEN a high-risk executive incident
    WHEN policy file is loaded
    THEN containment is denied and approval is required
    """
    monkeypatch.setenv("POLICY_FILE", "policies/default.yaml")

    result = run_pipeline(
        incident=_base_incident(),
        signals={
            "context": {
                "login_anomaly": True,
                "impossible_travel": True,
                "mfa_enabled": False,
                "prior_incidents": 3,
            },
            "abuseipdb": {"confidence": 90},
            "virustotal": {"malicious": 10, "total": 20},
        },
    )

    policy = result["policy"]

    assert "contain" in policy["denied_actions"]
    assert policy["requires_approval"] is True
    assert len(policy["reasons"]) > 0


def test_policy_does_not_trigger_for_low_risk(monkeypatch):
    """
    GIVEN a low-risk incident
    WHEN policy is evaluated
    THEN no actions are denied
    """
    monkeypatch.setenv("POLICY_FILE", "policies/default.yaml")

    result = run_pipeline(
        incident=_base_incident(),
        signals={
            "context": {
                "login_anomaly": True,
                "mfa_enabled": False,
                "prior_incidents": 1,
            }
        },
    )

    policy = result["policy"]

    assert policy["denied_actions"] == []
    assert policy["requires_approval"] is False


def test_missing_policy_file_fails_closed(monkeypatch):
    """
    GIVEN POLICY_FILE is set to a missing file
    WHEN pipeline runs
    THEN an error is raised (fail closed)
    """
    monkeypatch.setenv("POLICY_FILE", "policies/does_not_exist.yaml")

    with pytest.raises(FileNotFoundError):
        run_pipeline(
            incident=_base_incident(),
            signals={}
        )
