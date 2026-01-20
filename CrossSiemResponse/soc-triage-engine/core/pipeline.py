from __future__ import annotations
from pathlib import Path

import os
from typing import Any, Dict, Optional

from core.policy import evaluate_policy
from core.policy_loader import load_policies
from core.scoring import ScoringConfig, ScoreResult, score_confidence
from core.mitre import MitreHypothesis, infer_mitre


class PipelineError(Exception):
    """Raised when pipeline input is missing required minimal fields."""


def _require(incident: Dict[str, Any], key: str) -> Any:
    if key not in incident:
        raise PipelineError(f"Incident missing required field: '{key}'")
    return incident[key]


def run_pipeline(
    incident: Dict[str, Any],
    signals: Dict[str, Any],
    scoring_cfg: Optional[ScoringConfig] = None,
    mitre_min_confidence: float = 0.35,
    mitre_max_results: int = 10
) -> Dict[str, Any]:
    """
    Run deterministic triage pipeline.
    """

    # ---- Minimal incident sanity checks ----
    incident_id = _require(incident, "incident_id")
    title = _require(incident, "title")
    severity = _require(incident, "severity")
    timestamp = _require(incident, "timestamp")
    source = _require(incident, "source")

    # ---- Deterministic scoring ----
    score_res: ScoreResult = score_confidence(signals, cfg=scoring_cfg)

    # ---- Deterministic MITRE inference ----
    mitre_res = infer_mitre(
        signals,
        min_confidence=mitre_min_confidence,
        max_results=mitre_max_results
    )

    mitre_out = [
        {
            "tactic": h.tactic,
            "technique": h.technique,
            "confidence": h.confidence,
            "evidence": h.evidence
        }
        for h in mitre_res
    ]

    output: Dict[str, Any] = {
        "meta": {
            "engine_version": "v1",
            "mode": "deterministic",
        },
        "incident": {
            "incident_id": incident_id,
            "source": source,
            "title": title,
            "severity": severity,
            "timestamp": timestamp,
            "entities": incident.get("entities", []),
            "tags": incident.get("tags", []),
            "environment": incident.get("environment"),
            "notes": incident.get("notes"),
        },
        "scoring": {
            "score": score_res.score,
            "level": score_res.level,
            "reasons": score_res.reasons,
            "signals_used": score_res.signals_used
        },
        "mitre": mitre_out,
    }

   
    # Policy evaluation (optional)
    # -----------------------------
    policy_file = os.getenv("POLICY_FILE")
    policies = None

    if policy_file:
        base_dir = Path(__file__).resolve().parents[1]  # soc-triage-engine/
        policy_path = base_dir / policy_file
        policies = load_policies(str(policy_path))

    policy_decision = evaluate_policy(output, policies)
    output["policy"] = policy_decision.to_dict()

    return output

