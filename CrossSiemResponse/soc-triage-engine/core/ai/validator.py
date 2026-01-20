from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from jsonschema import Draft7Validator


class AIOutputValidationError(Exception):
    pass


def load_schema(schema_path: str) -> Dict[str, Any]:
    p = Path(schema_path)
    if not p.exists():
        raise FileNotFoundError(f"Schema not found: {schema_path}")
    return json.loads(p.read_text(encoding="utf-8"))


def validate_against_schema(payload: Dict[str, Any], schema: Dict[str, Any]) -> None:
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)

    if errors:
        msgs: List[str] = []
        for e in errors[:10]:
            path = ".".join([str(x) for x in e.path]) if e.path else "(root)"
            msgs.append(f"{path}: {e.message}")
        raise AIOutputValidationError("AI output failed schema validation: " + " | ".join(msgs))
