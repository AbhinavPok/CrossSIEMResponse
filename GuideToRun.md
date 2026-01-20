# How to Use This Engine

This project is meant to be run locally and explored the same way a human analyst would reason through an incident.  
No cloud account, no SIEM, and no automation magic required.

Everything is explicit, explainable, and safe to experiment with.

---

## What This Engine Expects

Each request contains **two parts**:

### 1. Incident
Describes *what happened*.

Required fields:
- incident_id
- source
- title
- severity
- timestamp

Optional:
- entities (users, IPs, domains)
- tags, environment, notes

---

### 2. Signals
Describes *context and enrichment*.

Examples:
- behavioral anomalies
- reputation data
- historical indicators
- environment context

Signals are vendor-neutral and intentionally simple.

---

## Starting the Engine

From the project root:

```bash
python -m uvicorn adapters.local.api:app --reload
Then open:

http://127.0.0.1:8000/docs
This launches an interactive interface where you can send requests and inspect responses without writing any code.

Sending a Request
Example request body:

{
  "incident": {
    "incident_id": "example-001",
    "source": "local",
    "title": "Suspicious account activity",
    "severity": "high",
    "timestamp": "2026-01-20T12:00:00Z",
    "entities": [
      { "type": "user", "value": "user@corp.com" }
    ]
  },
  "signals": {
    "context": {
      "login_anomaly": true,
      "mfa_enabled": false,
      "prior_incidents": 2
    }
  }
}
Submit this to the /triage endpoint.

Understanding the Output
Each response includes:

Risk Evaluation
numeric score

confidence level

exact reasons explaining how the score was calculated

Nothing is inferred silently.

Behavior Mapping
Patterns are mapped to known adversary behaviors with:

technique names

confidence levels

evidence tied directly to input signals

Policy Decisions
If policies are enabled, the response clearly states:

what actions are allowed

what actions are restricted

whether human approval is required

why those decisions were made

Enabling Policy Controls
Policies are defined in YAML.

Enable them with:

export POLICY_FILE=policies/default.yaml
Policies control decision boundaries such as:

automated account actions

approval requirements

restricted response paths

Human-Readable Summary
Each response includes a summary section that:

explains the situation in plain language

highlights primary risk drivers

recommends a reasonable next step

This is designed for handoffs, escalation notes, and clarity.

Advisory Layer (Optional)
The /triage-ai endpoint adds an advisory-only layer.

Key points:

scores and decisions never change

output is schema validated

safe to disable at any time

By default, it runs in offline mode.

Enabling Live Advisory Reasoning (Optional)
export LLM_API_KEY=your_key
export LLM_MODEL=gpt-4o-mini
export LLM_OFFLINE=0
Disable again with:

export LLM_OFFLINE=1
The core engine works the same either way.

Running Tests
Run all tests with:

pytest
Tests cover:

scoring logic

policy enforcement

summaries

advisory fallback behavior

schema validation

How This Is Intended to Be Used
This engine is meant for:

learning

experimentation

portfolio demonstration

reasoning about security decisions

It is not automated response software.

Every decision is visible and explainable.

Final Note
If you can explain:

why the score is high,

what behaviors are suspected,

what actions are allowed,

and what should happen next,

then the engine is doing exactly what it was designed to do.
