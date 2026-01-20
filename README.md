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

This engine is meant for:
learning experimentation and reasoning about security decisions


