from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATE_DIR = Path.home() / ".nexis"
EVENTS_FILE = STATE_DIR / "events.jsonl"
BASELINE_FILE = STATE_DIR / "network_baseline.json"


def _ensure_state() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def record(event_type: str, data: dict[str, Any]) -> None:
    _ensure_state()
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "data": data,
    }
    with EVENTS_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")


def recent(limit: int = 20) -> list[dict[str, Any]]:
    if not EVENTS_FILE.exists():
        return []
    lines = EVENTS_FILE.read_text(encoding="utf-8").splitlines()
    output: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            output.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return output


def save_baseline(snapshot: dict[str, Any]) -> None:
    _ensure_state()
    BASELINE_FILE.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")


def load_baseline() -> dict[str, Any] | None:
    if not BASELINE_FILE.exists():
        return None
    try:
        return json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def compare_devices(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    old = {item["ip"]: item for item in (previous or {}).get("devices", [])}
    new = {item["ip"]: item for item in current.get("devices", [])}
    added = sorted(set(new) - set(old), key=lambda x: tuple(int(v) for v in x.split(".")))
    removed = sorted(set(old) - set(new), key=lambda x: tuple(int(v) for v in x.split(".")))
    return {
        "added": [new[ip] for ip in added],
        "removed": [old[ip] for ip in removed],
        "counts": {"previous": len(old), "current": len(new)},
    }
