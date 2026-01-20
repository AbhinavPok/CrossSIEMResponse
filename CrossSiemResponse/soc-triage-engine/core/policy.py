from __future__ import annotations

from typing import Any, Dict, List


class PolicyDecision:
    """
    Output of policy evaluation.
    This does NOT execute actions.
    """
    def __init__(
        self,
        allowed_actions: List[str],
        denied_actions: List[str],
        requires_approval: bool,
        reasons: List[str],
    ):
        self.allowed_actions = allowed_actions
        self.denied_actions = denied_actions
        self.requires_approval = requires_approval
        self.reasons = reasons

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed_actions": self.allowed_actions,
            "denied_actions": self.denied_actions,
            "requires_approval": self.requires_approval,
            "reasons": self.reasons,
        }


# -----------------------------
# Policy evaluation
# -----------------------------

def evaluate_policy(
    pipeline_output: Dict[str, Any],
    policies: List[Dict[str, Any]] | None = None,
) -> PolicyDecision:
    """
    Evaluate organizational policies against pipeline output.

    This function:
    - never executes actions
    - never modifies scores
    - only returns constraints / guidance
    """

    scoring = pipeline_output.get("scoring", {})
    incident = pipeline_output.get("incident", {})
    entities = incident.get("entities", [])

    risk_score = scoring.get("score", 0)
    risk_level = scoring.get("level", "low")

    allowed_actions = ["monitor", "investigate"]
    denied_actions: List[str] = []
    reasons: List[str] = []
    requires_approval = False

    # Default baseline policy
    if risk_level == "high":
        allowed_actions.extend(["contain", "reset_credentials"])
        reasons.append("High-risk incident allows containment actions.")

    # Apply custom policies (if any)
    if policies:
        for rule in policies:
            when = rule.get("when", {})
            effect = rule.get("effect", {})
            reason = rule.get("reason", "Policy rule applied.")

            # ---- Conditions ----
            min_risk = when.get("min_risk")
            entity_type = when.get("entity_type")

            if min_risk is not None and risk_score < min_risk:
                continue

            if entity_type:
                if not any(e.get("type") == entity_type for e in entities):
                    continue

            # ---- Effects ----
            deny = effect.get("deny_actions", [])
            allow = effect.get("allow_actions", [])
            approval = effect.get("require_approval", False)

            for a in deny:
                if a not in denied_actions:
                    denied_actions.append(a)

            for a in allow:
                if a not in allowed_actions:
                    allowed_actions.append(a)

            if approval:
                requires_approval = True

            reasons.append(reason)

    # Final cleanup
    allowed_actions = [a for a in allowed_actions if a not in denied_actions]

    return PolicyDecision(
        allowed_actions=allowed_actions,
        denied_actions=denied_actions,
        requires_approval=requires_approval,
        reasons=reasons,
    )
