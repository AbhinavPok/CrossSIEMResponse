from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class MitreHypothesis:
    tactic: str
    technique: str  # "Txxxx - Name"
    confidence: float  # 0.0 - 1.0
    evidence: List[str] = field(default_factory=list)


def _safe_get(d: Dict[str, Any], path: Tuple[str, ...], default: Any = None) -> Any:
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _add_hypothesis(
    out: List[MitreHypothesis],
    tactic: str,
    technique: str,
    confidence: float,
    evidence: List[str],
    min_conf: float
) -> None:
    conf = _clamp01(confidence)
    if conf < min_conf:
        return
    out.append(MitreHypothesis(tactic=tactic, technique=technique, confidence=conf, evidence=evidence))


def infer_mitre(
    signals: Dict[str, Any],
    min_confidence: float = 0.35,
    max_results: int = 10
) -> List[MitreHypothesis]:
    """
    Returns a ranked list of MITRE hypotheses (highest confidence first).
    """
    out: List[MitreHypothesis] = []

    # --- Pull signals we care about ---
    login_anomaly = _safe_get(signals, ("context", "login_anomaly"))
    impossible_travel = _safe_get(signals, ("context", "impossible_travel"))
    mfa_enabled = _safe_get(signals, ("context", "mfa_enabled"))
    prior_incidents = _safe_get(signals, ("context", "prior_incidents"))

    vt_mal = _safe_get(signals, ("virustotal", "malicious"))
    vt_total = _safe_get(signals, ("virustotal", "total"))
    abuse_conf = _safe_get(signals, ("abuseipdb", "confidence"))

    domain_age_days = _safe_get(signals, ("whois", "domain_age_days"))
    asn_type = _safe_get(signals, ("asn", "type"))
    is_bulletproof = _safe_get(signals, ("asn", "is_bulletproof"))

    # Helper booleans
    prior_linked = isinstance(prior_incidents, int) and prior_incidents >= 2
    hosting_asn = isinstance(asn_type, str) and asn_type.lower() == "hosting"
    new_domain = isinstance(domain_age_days, int) and domain_age_days <= 30

    # --- Rule cluster 1: Valid Accounts (T1078) / Account compromise ---
    # Common when you see login anomaly / impossible travel + weak auth posture (no MFA)
    if isinstance(login_anomaly, bool) and login_anomaly:
        evidence = ["Login anomaly detected (context.login_anomaly=true)"]
        conf = 0.55

        if isinstance(impossible_travel, bool) and impossible_travel:
            evidence.append("Impossible travel signal present (context.impossible_travel=true)")
            conf += 0.10

        if isinstance(mfa_enabled, bool) and not mfa_enabled:
            evidence.append("MFA not enabled (context.mfa_enabled=false)")
            conf += 0.10

        if hosting_asn:
            evidence.append("Source IP appears to be from hosting ASN (asn.type=hosting)")
            conf += 0.05

        if prior_linked:
            evidence.append(f"Entity linked to prior incidents (context.prior_incidents={prior_incidents})")
            conf += 0.05

        _add_hypothesis(
            out,
            tactic="Credential Access",
            technique="T1078 - Valid Accounts",
            confidence=conf,
            evidence=evidence,
            min_conf=min_confidence
        )

    # --- Rule cluster 2: External Remote Services (T1133) ---
    # This is a reasonable companion hypothesis for anomalous logins where access path is external.
    if isinstance(login_anomaly, bool) and login_anomaly:
        evidence = ["Anomalous authentication pattern suggests external access path"]
        conf = 0.45

        if hosting_asn:
            evidence.append("Login source is hosting/provider ASN (asn.type=hosting)")
            conf += 0.10

        if isinstance(impossible_travel, bool) and impossible_travel:
            evidence.append("Impossible travel increases likelihood of remote access misuse")
            conf += 0.05

        _add_hypothesis(
            out,
            tactic="Initial Access",
            technique="T1133 - External Remote Services",
            confidence=conf,
            evidence=evidence,
            min_conf=min_confidence
        )

    # --- Rule cluster 3: Command and Control via Application Layer Protocol (T1071) ---
    # Triggered by strong IP reputation indicators + hosting/bulletproof infra.
    # Note: Without traffic telemetry, keep confidence moderate.
    rep_strong = False
    rep_evidence: List[str] = []

    if isinstance(abuse_conf, int) and abuse_conf >= 80:
        rep_strong = True
        rep_evidence.append(f"AbuseIPDB confidence high (abuseipdb.confidence={abuse_conf})")

    if isinstance(vt_mal, int) and isinstance(vt_total, int) and vt_total > 0:
        ratio = vt_mal / vt_total
        if ratio >= 0.10:
            rep_strong = True
            rep_evidence.append(f"VirusTotal malicious ratio high ({vt_mal}/{vt_total}={ratio:.2%})")

    if rep_strong:
        evidence = rep_evidence.copy()
        conf = 0.50

        if hosting_asn:
            evidence.append("Infrastructure characteristic: hosting ASN")
            conf += 0.05

        if isinstance(is_bulletproof, bool) and is_bulletproof:
            evidence.append("Infrastructure characteristic: bulletproof hosting (asn.is_bulletproof=true)")
            conf += 0.10

        _add_hypothesis(
            out,
            tactic="Command and Control",
            technique="T1071 - Application Layer Protocol",
            confidence=conf,
            evidence=evidence,
            min_conf=min_confidence
        )

    # --- Rule cluster 4: Phishing (T1566) / Suspicious newly-registered domains ---
    # If you have domain age (new) + reputation indicators, suggest phishing-related initial access.
    if new_domain:
        evidence = [f"Domain is newly registered (whois.domain_age_days={domain_age_days})"]
        conf = 0.40

        if isinstance(vt_mal, int) and isinstance(vt_total, int) and vt_total > 0:
            ratio = vt_mal / vt_total
            if ratio >= 0.03:
                evidence.append(f"VirusTotal indicates suspicious/malicious signals ({vt_mal}/{vt_total}={ratio:.2%})")
                conf += 0.10

        _add_hypothesis(
            out,
            tactic="Initial Access",
            technique="T1566 - Phishing",
            confidence=conf,
            evidence=evidence,
            min_conf=min_confidence
        )

    # --- Sort + cap results ---
    out.sort(key=lambda x: x.confidence, reverse=True)
    return out[:max_results]