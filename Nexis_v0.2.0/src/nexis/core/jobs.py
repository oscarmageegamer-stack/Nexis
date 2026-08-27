from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import threading
import uuid


@dataclass(frozen=True)
class Job:
    id: str
    name: str
    description: str
    runner: object


class JobManager:
    def __init__(self, max_workers: int = 8) -> None:
        self.max_workers = max(1, min(max_workers, 32))
        self._lock = threading.Lock()
        self.jobs: dict[str, dict] = {}

    def submit(self, name: str, description: str, runner) -> str:
        job_id = uuid.uuid4().hex[:10]
        with self._lock:
            self.jobs[job_id] = {
                "id": job_id,
                "name": name,
                "description": description,
                "status": "queued",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        thread = threading.Thread(target=self._run, args=(job_id, runner), daemon=True)
        thread.start()
        return job_id

    def _run(self, job_id: str, runner) -> None:
        with self._lock:
            self.jobs[job_id]["status"] = "running"
            self.jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()
        try:
            result = runner()
            with self._lock:
                self.jobs[job_id].update({"status": "complete", "result": result, "finished_at": datetime.now(timezone.utc).isoformat()})
        except Exception as exc:
            with self._lock:
                self.jobs[job_id].update({"status": "error", "error": str(exc), "finished_at": datetime.now(timezone.utc).isoformat()})

    def status(self) -> list[dict]:
        with self._lock:
            return list(self.jobs.values())
