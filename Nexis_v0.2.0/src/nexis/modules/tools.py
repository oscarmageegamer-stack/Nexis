from __future__ import annotations

import shutil
import subprocess

TOOL_COMMANDS = {
    "nmap": ["nmap", "--version"],
    "tshark": ["tshark", "--version"],
    "msfconsole": ["msfconsole", "--version"],
    "amass": ["amass", "-version"],
    "spiderfoot": ["sf.py", "--version"],
    "whatweb": ["whatweb", "--version"],
}


def status() -> dict[str, dict[str, str | bool]]:
    result = {}
    for name, command in TOOL_COMMANDS.items():
        path = shutil.which(command[0])
        entry: dict[str, str | bool] = {"installed": bool(path), "path": path or ""}
        if path:
            try:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=7)
                output = (proc.stdout + "\n" + proc.stderr).strip().splitlines()
                if output:
                    entry["version"] = output[0][:160]
            except Exception as exc:
                entry["version_check_error"] = str(exc)
        result[name] = entry
    return result


def tshark_interfaces() -> str:
    path = shutil.which("tshark")
    if not path:
        raise RuntimeError("TShark is not installed or is not in PATH.")
    proc = subprocess.run([path, "-D"], capture_output=True, text=True, timeout=15)
    return (proc.stdout + "\n" + proc.stderr).strip()
