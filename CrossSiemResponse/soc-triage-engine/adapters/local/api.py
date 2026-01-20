"""
Local FastAPI adapter (v1)

Purpose:
- Expose the SOC triage engine over HTTP
- Accept incident + signals as JSON
- Run deterministic pipeline
- Optionally run AI advisory layer
- Return structured output

This adapter is SIEM-agnostic and intended for:
- local testing
- demos
- integration with any SIEM/SOAR
"""
from core.summarizer import summarize

from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from core.pipeline import run_pipeline, PipelineError
from core.ai.reasoner import reason_with_llm, AIReasonerError


# -----------------------------
# App
# -----------------------------

app = FastAPI(
    title="SOC Triage Engine (Local)",
    version="v1",
    description="Deterministic SOC triage engine with scoring, MITRE inference, and policy gating",
)


# -----------------------------
# Request / Response models
# -----------------------------

class PipelineRequest(BaseModel):
    incident: Dict[str, Any]
    signals: Dict[str, Any]


class PipelineResponse(BaseModel):
    result: Dict[str, Any]


# -----------------------------
# Routes
# -----------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


# --------------------------------
# Deterministic triage (DEBUG SAFE)
# --------------------------------
@app.post("/triage-ai", response_model=PipelineResponse)
def triage_ai(req: PipelineRequest):
    """
    Deterministic triage + AI advisory (policy-guarded).
    """

    # Run deterministic pipeline
    output = run_pipeline(
        incident=req.incident,
        signals=req.signals,
    )

    # Always include deterministic summary
    output["summary"] = summarize(output)

    # AI advisory (never modifies core results)
    ai = reason_with_llm(output)
    output["ai"] = ai

    # Mark mode
    output["meta"]["mode"] = "deterministic+ai"

    return {"result": output}



# --------------------------------
# Deterministic + AI advisory
# --------------------------------
@app.post("/triage-ai", response_model=PipelineResponse)
def triage_ai(req: PipelineRequest):
    """
    Deterministic triage + optional AI advisory layer.

    AI is:
    - schema validated
    - advisory only
    - safe to disable via env vars
    """

    try:
        deterministic = run_pipeline(
            incident=req.incident,
            signals=req.signals,
        )

        ai = reason_with_llm(deterministic)

        # Attach AI output
        deterministic["ai"] = ai
        deterministic["meta"]["mode"] = "deterministic+ai"

        return {"result": deterministic}

    except PipelineError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except AIReasonerError as e:
        raise HTTPException(
            status_code=502,
            detail=f"AI reasoner error: {str(e)}"
        )

    except Exception as e:
        # Safe fallback for AI path
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )
