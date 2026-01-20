import json
from pathlib import Path
from typing import List, Dict, Any

try:
    import yaml
except ImportError:
    yaml = None


def load_policies(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    if p.suffix in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError("PyYAML not installed")
        return yaml.safe_load(p.read_text())

    if p.suffix == ".json":
        return json.loads(p.read_text())

    raise ValueError("Policy file must be .json or .yaml")
