from __future__ import annotations

import shutil
import subprocess


def status() -> dict[str, object]:
    """Report whether Ruflo is available locally without launching it."""
    exe = shutil.which("ruflo")
    npx = shutil.which("npx")
    return {
        "ruflo_installed": bool(exe),
        "ruflo_path": exe or "",
        "npx_available": bool(npx),
        "integration": "Nexis safe-task orchestration adapter",
        "autonomous_exploit_execution": False,
    }


def version() -> str:
    exe = shutil.which("ruflo")
    if not exe:
        return "Ruflo is not installed or not on PATH."
    try:
        proc = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=8)
        return (proc.stdout or proc.stderr).strip()[:200] or "Ruflo detected; version unavailable."
    except Exception as exc:
        return f"Ruflo version check failed: {exc}"
