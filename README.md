# CrossSIEMResponse

#Please read all the files
# SOC Triage Engine (Local)

A deterministic SOC triage engine that converts raw security alerts into
clear, explainable, and actionable decisions.

This project combines:
- Rule-based risk scoring
- MITRE ATT&CK technique inference
- Policy-based action gating
- Optional AI advisory (strictly non-authoritative)

The core principle is **explainability first** — AI can assist analysts,
but never replaces deterministic security logic.

---

## Key Features

- Deterministic confidence scoring with transparent reasons
- MITRE ATT&CK tactic & technique inference
- Policy engine to allow / deny response actions
- Human-readable incident summaries
- Optional AI advisory layer (safe to disable)
- SIEM-agnostic and vendor-neutral design
- Local-first, API-driven architecture

---

## Architecture Overview

# SOC Triage Engine (Local)

A deterministic SOC triage engine that converts raw security alerts into
clear, explainable, and actionable decisions.

This project combines:
- Rule-based risk scoring
- MITRE ATT&CK technique inference
- Policy-based action gating
- Optional AI advisory (strictly non-authoritative)

The core principle is **explainability first** — AI can assist analysts,
but never replaces deterministic security logic.

---

## Key Features

- Deterministic confidence scoring with transparent reasons
- MITRE ATT&CK tactic & technique inference
- Policy engine to allow / deny response actions
- Human-readable incident summaries
- Optional AI advisory layer (safe to disable)
- SIEM-agnostic and vendor-neutral design
- Local-first, API-driven architecture

---

## Architecture Overview

Client / SIEM / User <br>
|<br>
v<br>
+---------------------+<br>
| FastAPI Adapter |<br>
| (HTTP Interface) |<br>
+---------------------+<br>
|<br>
v<br>
+---------------------+<br>
| Deterministic |<br>
| Triage Pipeline |<br>
+---------------------+<br>
|<br>
+-----------------------------+<br>
| |<br>
v v<br>
+------------------+ +------------------+<br>
| Policy Engine | | Summary Builder |<br>
+------------------+ +------------------+<br>
|<br>
v<br>
+---------------------+<br>
| Optional AI Layer |<br>
| (Advisory Only) |<br>
+---------------------+<br>
|<br>
v<br>
Structured JSON Response<br>
## API Endpoints

| Endpoint        | Description |
|-----------------|-------------|
| `GET /health`   | Health check |
| `POST /triage`  | Deterministic SOC triage |
| `POST /triage-ai` | Triage + AI advisory |

## Design Philosophy

- **Deterministic first**: scoring, MITRE mapping, and policy decisions are rule-based
- **AI is advisory only**: AI never changes scores or policy outcomes
- **Auditable output**: every decision includes reasoning
- **Safe by default**: AI can be disabled entirely via environment variables

## Example Output (High-Level)

```json
{
  "score": 93,
  "level": "high",
  "mitre": ["T1078", "T1133"],
  "policy": {
    "requires_approval": true
  },
  "summary": {
    "headline": "Executive account compromise",
    "recommended_next_step": "Escalate to SOC lead"
  }
}

Then open your browser and navigate to:

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


Submit this payload to the /triage endpoint.

Enabling Policy Controls

Policies are defined using YAML.

Enable them by setting:

export POLICY_FILE=policies/default.yaml


Policies control boundaries such as:

automated account actions

approval requirements

restricted response paths

Enabling Live Advisory Reasoning (Optional)
export LLM_API_KEY=your_key
export LLM_MODEL=gpt-4o-mini
export LLM_OFFLINE=0


Disable again with:

export LLM_OFFLINE=1


The core engine behaves the same either way.

Running Tests

Run all tests with:

pytest


Tests cover:

scoring logic

policy enforcement

summaries

advisory fallback behavior

schema validation

Intended Use

This engine is meant for:

learning

experimentation

portfolio demonstration

reasoning about security decisions

It is not automated response software.

Every decision is visible and explainable.
