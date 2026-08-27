from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import json
import threading
import uuid


WORKSPACE_DIR = Path.home() / ".nexis" / "workspaces"


@dataclass
class Workspace:
    id: str
    name: str
    created_at: str
    targets: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)


class WorkspaceStore:
    """Small persistent workspace registry for authorised assessments."""

    def __init__(self, root: Path = WORKSPACE_DIR) -> None:
        self.root = root
        self._lock = threading.Lock()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, workspace_id: str) -> Path:
        return self.root / f"{workspace_id}.json"

    def create(self, name: str, targets: list[str] | None = None, tags: list[str] | None = None) -> Workspace:
        cleaned = name.strip()
        if not cleaned:
            raise ValueError("Workspace name cannot be empty.")
        workspace = Workspace(
            id=uuid.uuid4().hex[:10],
            name=cleaned,
            created_at=datetime.now(timezone.utc).isoformat(),
            targets=list(targets or []),
            tags=list(tags or []),
        )
        with self._lock:
            self._path(workspace.id).write_text(json.dumps(workspace.__dict__, indent=2), encoding="utf-8")
        return workspace

    def list(self) -> list[Workspace]:
        result: list[Workspace] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                result.append(Workspace(**data))
            except (OSError, json.JSONDecodeError, TypeError):
                continue
        return result

    def get(self, workspace_id: str) -> Workspace | None:
        try:
            data = json.loads(self._path(workspace_id).read_text(encoding="utf-8"))
            return Workspace(**data)
        except (OSError, json.JSONDecodeError, TypeError):
            return None

    def add_job(self, workspace_id: str, job_id: str) -> bool:
        with self._lock:
            workspace = self.get(workspace_id)
            if not workspace:
                return False
            if job_id not in workspace.jobs:
                workspace.jobs.append(job_id)
            self._path(workspace_id).write_text(json.dumps(workspace.__dict__, indent=2), encoding="utf-8")
            return True
