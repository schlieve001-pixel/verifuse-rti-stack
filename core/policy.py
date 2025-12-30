import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set


@dataclass
class Policy:
    policy_id: str
    required: Set[str]
    optional: Set[str]
    forbidden: Set[str]
    time_window_seconds: Optional[int]


def load_policy(path: Optional[Path]) -> Optional[Policy]:
    if not path:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    roles = data.get("roles", {})
    return Policy(
        policy_id=data.get("policy_id", ""),
        required=set(roles.get("required", [])),
        optional=set(roles.get("optional", [])),
        forbidden=set(roles.get("forbidden", [])),
        time_window_seconds=(data.get("time") or {}).get("max_skew_seconds"),
    )
