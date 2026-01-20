# CrossSIEMResponse
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

Client / SIEM / User
|
v
+---------------------+
| FastAPI Adapter |
| (HTTP Interface) |
+---------------------+
|
v
+---------------------+
| Deterministic |
| Triage Pipeline |
+---------------------+
|
+-----------------------------+
| |
v v
+------------------+ +------------------+
| Policy Engine | | Summary Builder |
+------------------+ +------------------+
|
v
+---------------------+
| Optional AI Layer |
| (Advisory Only) |
+---------------------+
|
v
Structured JSON Response
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


