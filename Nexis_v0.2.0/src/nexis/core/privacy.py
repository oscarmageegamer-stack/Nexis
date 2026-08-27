from __future__ import annotations

import json
import shutil
from pathlib import Path

from .store import APP_DIR, BASELINE_FILE, EVENTS_FILE
from .retention import RETENTION_STATE

SESSION_DIR = APP_DIR / "session"
GENERATED_REPORTS = Path("reports")


def privacy_status() -> dict:
    return {
        "app_dir": str(APP_DIR),
        "events_present": EVENTS_FILE.exists(),
        "baseline_present": BASELINE_FILE.exists(),
        "retention_state_present": RETENTION_STATE.exists(),
        "session_dir_present": SESSION_DIR.exists(),
        "generated_reports_dir": str(GENERATED_REPORTS.resolve()),
        "note": "Status covers Nexis-owned application data only.",
    }


def _remove(path: Path) -> bool:
    if not path.exists():
        return False
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    return True


def privacy_reset() -> dict:
    """Reset Nexis-owned local state to a first-run condition.

    This intentionally does not touch OS, browser, network, cloud, or
    third-party logs. The caller should terminate the application after
    a successful reset so the next launch is a fresh Nexis session.
    """
    removed = []
    for path in (EVENTS_FILE, BASELINE_FILE, RETENTION_STATE, SESSION_DIR):
        if _remove(path):
            removed.append(str(path))

    return {
        "reset": True,
        "removed": removed,
        "remaining_nexis_state": privacy_status(),
        "external_logs_touched": False,
        "requires_restart": True,
    }
