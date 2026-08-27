from __future__ import annotations

from datetime import datetime, timezone
import os
import platform
import threading
import time


class Heartbeat:
    """Lightweight local runtime health monitor for Nexis."""

    def __init__(self, interval: float = 10.0) -> None:
        self.interval = max(2.0, float(interval))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.ticks = 0
        self.last_tick: str | None = None

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.ticks += 1
            self.last_tick = datetime.now(timezone.utc).isoformat()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="nexis-heartbeat", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> dict[str, object]:
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "started_at": self.started_at,
            "ticks": self.ticks,
            "last_tick": self.last_tick,
            "pid": os.getpid(),
            "platform": platform.system(),
            "python": platform.python_version(),
        }
