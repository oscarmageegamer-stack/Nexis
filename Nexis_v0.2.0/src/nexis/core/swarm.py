from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable
import subprocess
import shutil


@dataclass(frozen=True)
class SwarmTask:
    name: str
    description: str
    runner: Callable[[], object]


def run_parallel(tasks: list[SwarmTask], max_workers: int = 4) -> list[dict]:
    """Run registered, non-destructive Nexis tasks concurrently."""
    if not tasks:
        return []
    workers = max(1, min(max_workers, len(tasks), 8))
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nexis-agent") as pool:
        futures = {pool.submit(task.runner): task for task in tasks}
        for future in as_completed(futures):
            task = futures[future]
            try:
                results.append({"task": task.name, "description": task.description, "status": "ok", "result": future.result()})
            except Exception as exc:
                results.append({"task": task.name, "description": task.description, "status": "error", "error": str(exc)})
    return sorted(results, key=lambda item: item["task"])


def open_power_shell_terminal(command: str, title: str = "Nexis Agent") -> bool:
    """Open a visible PowerShell window for a Nexis-safe command."""
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if not powershell:
        return False
    subprocess.Popen([
        powershell,
        "-NoExit",
        "-Command",
        f"$Host.UI.RawUI.WindowTitle='{title}'; {command}",
    ])
    return True
