from core.pipeline import run_pipeline

def test_pipeline_runs_end_to_end():
    incident = {
        "incident_id": "inc-001",
        "source": "local",
        "title": "Suspicious sign-in",
        "severity": "high",
        "timestamp": "2026-01-20T12:00:00Z",
        "entities": [
            {"type": "user", "value": "user@corp.com"},
            {"type": "ip", "value": "1.2.3.4"}
        ]
    }

    signals = {
        "virustotal": {"malicious": 12, "total": 94},
        "abuseipdb": {"confidence": 85, "reports": 412},
        "whois": {"domain_age_days": 3},
        "asn": {"type": "hosting", "is_bulletproof": False},
        "context": {"login_anomaly": True, "impossible_travel": True, "mfa_enabled": False, "prior_incidents": 2}
    }

    out = run_pipeline(incident, signals)

    assert out["incident"]["incident_id"] == "inc-001"
    assert "scoring" in out and "mitre" in out
    assert out["scoring"]["score"] >= 0
    assert isinstance(out["mitre"], list)

def test_pipeline_requires_minimal_fields():
    bad_incident = {"incident_id": "inc-002"}  # missing required fields
    try:
        run_pipeline(bad_incident, signals={})
        assert False, "Expected PipelineError"
    except Exception as e:
        assert "missing required field" in str(e).lower()
