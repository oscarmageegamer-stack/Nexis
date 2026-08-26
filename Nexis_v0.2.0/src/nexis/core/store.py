from __future__ import annotations

import json
import time
from pathlib import Path

APP_DIR = Path.home() / ".nexis"
EVENTS_FILE = APP_DIR / "events.jsonl"
BASELINE_FILE = APP_DIR / "baseline.json"


def _ensure_dir() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


def record_event(kind: str, data: dict) -> None:
    _ensure_dir()
    event = {"ts": time.time(), "kind": kind, "data": data}
    with EVENTS_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")


def load_baseline() -> dict | None:
    if not BASELINE_FILE.exists():
        return None
    try:
        return json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_baseline(snapshot: dict) -> None:
    _ensure_dir()
    BASELINE_FILE.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")


def recent_events(limit: int = 50) -> list[dict]:
    if not EVENTS_FILE.exists():
        return []
    try:
        lines = EVENTS_FILE.read_text(encoding="utf-8").splitlines()[-limit:]
        return [json.loads(line) for line in lines]
    except (OSError, json.JSONDecodeError):
        return []
