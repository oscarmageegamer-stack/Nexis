from __future__ import annotations

from datetime import datetime
from pathlib import Path
import json
import time

from .store import APP_DIR, EVENTS_FILE

RETENTION_STATE = APP_DIR / "retention_state.json"


def _today() -> str:
    return datetime.now().date().isoformat()


def rotate_daily_app_log() -> bool:
    """Apply Nexis's own daily privacy-retention policy.

    This only removes Nexis-owned event history. It does not attempt to
    alter operating-system, router, firewall, DNS, or third-party logs.
    """
    APP_DIR.mkdir(parents=True, exist_ok=True)
    today = _today()
    previous = None
    if RETENTION_STATE.exists():
        try:
            previous = json.loads(RETENTION_STATE.read_text(encoding="utf-8")).get("last_date")
        except (OSError, json.JSONDecodeError):
            previous = None

    if previous == today:
        return False

    if EVENTS_FILE.exists():
        EVENTS_FILE.unlink()

    RETENTION_STATE.write_text(json.dumps({"last_date": today, "rotated_at": time.time()}, indent=2), encoding="utf-8")
    return True


def retention_status() -> dict:
    return {
        "policy": "daily Nexis-owned event-log rotation",
        "today": _today(),
        "events_file_exists": EVENTS_FILE.exists(),
        "events_file": str(EVENTS_FILE),
        "scope": "Nexis application data only",
        "external_logs_touched": False,
    }
