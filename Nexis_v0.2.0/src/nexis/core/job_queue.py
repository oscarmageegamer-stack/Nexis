from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Any
import time
import uuid


@dataclass(frozen=True)
class Job:
    id: str
    name: str
    category: str
    runner: Callable[[], Any]


class JobQueue:
    def __init__(self, max_workers: int = 8):
        self.max_workers = max(1, min(max_workers, 32))
        self.jobs: dict[str, dict] = {}

    def submit(self, name: str, category: str, runner: Callable[[], Any]) -> str:
        job_id = uuid.uuid4().hex[:10]
        self.jobs[job_id] = {
            "id": job_id,
            "name": name,
            "category": category,
            "status": "queued",
            "created_at": time.time(),
            "runner": Job(job_id, name, category, runner),
        }
        return job_id

    def run_all(self) -> list[dict]:
        if not self.jobs:
            return []
        pending = list(self.jobs.values())
        for item in pending:
            item["status"] = "running"
        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="nexis-worker") as pool:
            futures = {pool.submit(item["runner"].runner): item for item in pending}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    result = future.result()
                    item["status"] = "complete"
                    results.append({"id": item["id"], "name": item["name"], "category": item["category"], "status": "complete", "result": result})
                except Exception as exc:
                    item["status"] = "error"
                    results.append({"id": item["id"], "name": item["name"], "category": item["category"], "status": "error", "error": str(exc)})
        return results

    def status(self) -> list[dict]:
        return [
            {k: v for k, v in item.items() if k != "runner"}
            for item in self.jobs.values()
        ]
