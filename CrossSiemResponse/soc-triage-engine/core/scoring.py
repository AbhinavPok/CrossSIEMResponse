from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# -----------------------------
# Config (tunable)
# -----------------------------

@dataclass(frozen=True)
class ScoringConfig:
    # VirusTotal
    vt_malicious_ratio_high: float = 0.10   # malicious/total >= 10%
    vt_malicious_ratio_med: float = 0.03    # malicious/total >= 3%
    wt_vt_high: int = 30
    wt_vt_med: int = 15

    # AbuseIPDB
    abuse_conf_high: int = 80
    abuse_conf_med: int = 50
    wt_abuse_high: int = 25
    wt_abuse_med: int = 12

    # Domain age (days)
    domain_new_days: int = 30
    domain_very_new_days: int = 7
    wt_domain_very_new: int = 15
    wt_domain_new: int = 8

    # ASN / hosting context
    wt_asn_hosting: int = 10
    wt_asn_bulletproof: int = 15

    # Incident context signals
    wt_login_anomaly: int = 20
    wt_mfa_disabled: int = 10
    wt_prior_incidents: int = 8  # if >= prior_incidents_threshold
    prior_incidents_threshold: int = 2

    # Safety caps
    min_score: int = 0
    max_score: int = 100

    # Convert numeric score to levels
    level_low_max: int = 39
    level_medium_max: int = 69
    # 70+ => high


@dataclass
class ScoreResult:
    score: int
    level: str  # low|medium|high
    reasons: List[str] = field(default_factory=list)
    signals_used: Dict[str, Any] = field(default_factory=dict)


# -----------------------------
# Helpers
# -----------------------------

def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def _score_level(score: int, cfg: ScoringConfig) -> str:
    if score <= cfg.level_low_max:
        return "low"
    if score <= cfg.level_medium_max:
        return "medium"
    return "high"


def _safe_get(d: Dict[str, Any], path: Tuple[str, ...], default: Any = None) -> Any:
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _parse_vt_ratio(vt: Dict[str, Any]) -> Optional[float]:
    """
    Accepts either:
      vt = {"malicious": 12, "total": 94}
    or
      vt = {"malicious_ratio": 0.127}
    Returns ratio in [0,1] or None.
    """
    if not isinstance(vt, dict):
        return None

    ratio = vt.get("malicious_ratio")
    if isinstance(ratio, (int, float)):
        if ratio < 0:
            return 0.0
        return min(float(ratio), 1.0)

    mal = vt.get("malicious")
    total = vt.get("total")
    if isinstance(mal, (int, float)) and isinstance(total, (int, float)) and total > 0:
        r = float(mal) / float(total)
        return max(0.0, min(r, 1.0))

    return None


# -----------------------------
# Main scoring function
# -----------------------------

def score_confidence(
    signals: Dict[str, Any],
    cfg: Optional[ScoringConfig] = None
) -> ScoreResult:
    """
    signals: normalized dict produced by your enrichment/normalization layer, e.g.:

    {
      "virustotal": {"malicious": 12, "total": 94, "last_analysis_days": 1},
      "abuseipdb": {"confidence": 85, "reports": 412},
      "whois": {"domain_age_days": 3},
      "asn": {"type": "hosting", "is_bulletproof": false},
      "context": {"login_anomaly": true, "mfa_enabled": false, "prior_incidents": 2}
    }
    """
    cfg = cfg or ScoringConfig()
    score = 0
    reasons: List[str] = []

    # Track which signals we actually used for transparency/debugging
    used: Dict[str, Any] = {}

    # --- VirusTotal ---
    vt = signals.get("virustotal", {})
    vt_ratio = _parse_vt_ratio(vt)
    if vt_ratio is not None:
        used["virustotal"] = {"malicious_ratio": vt_ratio}
        if vt_ratio >= cfg.vt_malicious_ratio_high:
            score += cfg.wt_vt_high
            reasons.append(f"VirusTotal malicious ratio high ({vt_ratio:.2%}) +{cfg.wt_vt_high}")
        elif vt_ratio >= cfg.vt_malicious_ratio_med:
            score += cfg.wt_vt_med
            reasons.append(f"VirusTotal malicious ratio moderate ({vt_ratio:.2%}) +{cfg.wt_vt_med}")

    # --- AbuseIPDB ---
    abuse = signals.get("abuseipdb", {})
    abuse_conf = abuse.get("confidence")
    if isinstance(abuse_conf, int):
        used["abuseipdb"] = {"confidence": abuse_conf}
        if abuse_conf >= cfg.abuse_conf_high:
            score += cfg.wt_abuse_high
            reasons.append(f"AbuseIPDB confidence high ({abuse_conf}) +{cfg.wt_abuse_high}")
        elif abuse_conf >= cfg.abuse_conf_med:
            score += cfg.wt_abuse_med
            reasons.append(f"AbuseIPDB confidence moderate ({abuse_conf}) +{cfg.wt_abuse_med}")

    # --- Domain age (if present) ---
    domain_age_days = _safe_get(signals, ("whois", "domain_age_days"))
    if isinstance(domain_age_days, int):
        used.setdefault("whois", {})["domain_age_days"] = domain_age_days
        if domain_age_days <= cfg.domain_very_new_days:
            score += cfg.wt_domain_very_new
            reasons.append(f"Domain very new ({domain_age_days}d) +{cfg.wt_domain_very_new}")
        elif domain_age_days <= cfg.domain_new_days:
            score += cfg.wt_domain_new
            reasons.append(f"Domain newly registered ({domain_age_days}d) +{cfg.wt_domain_new}")

    # --- ASN context ---
    asn_type = _safe_get(signals, ("asn", "type"))
    is_bulletproof = _safe_get(signals, ("asn", "is_bulletproof"))
    if isinstance(asn_type, str):
        used.setdefault("asn", {})["type"] = asn_type
        if asn_type.lower() == "hosting":
            score += cfg.wt_asn_hosting
            reasons.append(f"ASN appears to be hosting provider +{cfg.wt_asn_hosting}")

    if isinstance(is_bulletproof, bool):
        used.setdefault("asn", {})["is_bulletproof"] = is_bulletproof
        if is_bulletproof:
            score += cfg.wt_asn_bulletproof
            reasons.append(f"ASN flagged as bulletproof hosting +{cfg.wt_asn_bulletproof}")

    # --- Incident context ---
    login_anomaly = _safe_get(signals, ("context", "login_anomaly"))
    mfa_enabled = _safe_get(signals, ("context", "mfa_enabled"))
    prior_incidents = _safe_get(signals, ("context", "prior_incidents"))

    if isinstance(login_anomaly, bool):
        used.setdefault("context", {})["login_anomaly"] = login_anomaly
        if login_anomaly:
            score += cfg.wt_login_anomaly
            reasons.append(f"Login anomaly detected +{cfg.wt_login_anomaly}")

    if isinstance(mfa_enabled, bool):
        used.setdefault("context", {})["mfa_enabled"] = mfa_enabled
        if not mfa_enabled:
            score += cfg.wt_mfa_disabled
            reasons.append(f"MFA not enabled for account +{cfg.wt_mfa_disabled}")

    if isinstance(prior_incidents, int):
        used.setdefault("context", {})["prior_incidents"] = prior_incidents
        if prior_incidents >= cfg.prior_incidents_threshold:
            score += cfg.wt_prior_incidents
            reasons.append(f"Entity linked to prior incidents ({prior_incidents}) +{cfg.wt_prior_incidents}")

    # Finalize
    score = _clamp(score, cfg.min_score, cfg.max_score)
    level = _score_level(score, cfg)

    if not reasons:
        reasons.append("No strong deterministic signals found; defaulting to low confidence")

    return ScoreResult(score=score, level=level, reasons=reasons, signals_used=used)