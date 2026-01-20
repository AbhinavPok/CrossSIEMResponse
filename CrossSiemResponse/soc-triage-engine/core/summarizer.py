from typing import Any, Dict


def summarize(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic SOC summary.
    Converts pipeline output into a human-readable brief.
    """

    incident = result.get("incident", {})
    scoring = result.get("scoring", {})
    policy = result.get("policy", {})

    summary_lines = []

    summary_lines.append(
        f"Incident '{incident.get('title')}' reported with severity "
        f"{incident.get('severity')}."
    )

    summary_lines.append(
        f"Risk score assessed at {scoring.get('score')} "
        f"({scoring.get('level')})."
    )

    if scoring.get("reasons"):
        summary_lines.append(
            "Primary risk drivers: "
            + "; ".join(scoring["reasons"][:3])
        )

    if policy:
        if policy.get("denied_actions"):
            summary_lines.append(
                "Policy restrictions applied: "
                + ", ".join(policy["denied_actions"])
            )

        if policy.get("requires_approval"):
            summary_lines.append(
                "Human approval required before containment actions."
            )

    return {
        "headline": incident.get("title"),
        "summary": summary_lines,
        "recommended_next_step": _next_step(policy),
    }


def _next_step(policy: Dict[str, Any]) -> str:
    if policy.get("requires_approval"):
        return "Escalate to SOC lead for approval."
    if policy.get("allowed_actions"):
        return f"Proceed with: {', '.join(policy['allowed_actions'])}."
    return "Continue monitoring."
