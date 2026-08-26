from __future__ import annotations

import shutil
import subprocess

TOOLS = {
    "nmap": (["nmap", "--version"], "network discovery and service enumeration"),
    "tshark": (["tshark", "--version"], "packet analysis"),
    "amass": (["amass", "-version"], "attack-surface and asset discovery"),
    "subfinder": (["subfinder", "-version"], "passive subdomain discovery"),
    "httpx": (["httpx", "-version"], "HTTP asset probing"),
    "nuclei": (["nuclei", "-version"], "authorised vulnerability-template checks"),
    "whatweb": (["whatweb", "--version"], "web technology identification"),
    "msfconsole": (["msfconsole", "--version"], "Metasploit installation detection"),
    "nikto": (["nikto", "-Version"], "web server auditing"),
    "ffuf": (["ffuf", "-V"], "authorised content discovery"),
    "masscan": (["masscan", "--version"], "high-speed network scanning tool detection"),
    "curl": (["curl", "--version"], "HTTP diagnostics"),
    "git": (["git", "--version"], "repository metadata"),
    "openssl": (["openssl", "version"], "TLS/cryptography diagnostics"),
}


def status() -> dict:
    output = {}
    for name, (command, purpose) in TOOLS.items():
        path = shutil.which(command[0])
        entry = {"installed": bool(path), "path": path, "purpose": purpose}
        if path:
            try:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=8)
                lines = (proc.stdout + "\n" + proc.stderr).strip().splitlines()
                entry["version"] = lines[0][:160] if lines else None
            except Exception as exc:
                entry["version_error"] = str(exc)
        output[name] = entry
    return output


def tshark_interfaces() -> str:
    path = shutil.which("tshark")
    if not path:
        raise RuntimeError("TShark is not installed or is not in PATH.")
    proc = subprocess.run([path, "-D"], capture_output=True, text=True, timeout=15)
    return (proc.stdout + "\n" + proc.stderr).strip()
