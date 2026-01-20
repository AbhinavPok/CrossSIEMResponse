from core.scoring import score_confidence

def test_scoring_high_confidence():
    signals = {
        "virustotal": {"malicious": 12, "total": 94},
        "abuseipdb": {"confidence": 85, "reports": 412},
        "whois": {"domain_age_days": 3},
        "asn": {"type": "hosting", "is_bulletproof": False},
        "context": {"login_anomaly": True, "mfa_enabled": False, "prior_incidents": 2}
    }

    result = score_confidence(signals)
    assert result.score >= 70
    assert result.level == "high"
    assert len(result.reasons) > 0

def test_scoring_low_confidence_when_empty():
    result = score_confidence({})
    assert result.level == "low"
    assert result.score >= 0
