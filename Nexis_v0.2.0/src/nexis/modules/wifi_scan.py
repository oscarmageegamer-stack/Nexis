from __future__ import annotations

import platform
import re
import subprocess


def scan() -> dict:
    system = platform.system()
    if system == "Windows":
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, timeout=20)
        raw = (result.stdout + "\n" + result.stderr).strip()
        networks = []
        current = None
        for line in raw.splitlines():
            text = line.strip()
            if text.lower().startswith("ssid ") and ":" in text:
                if current: networks.append(current)
                current = {"ssid": text.split(":", 1)[1].strip(), "bssids": []}
            elif current and text.lower().startswith("bssid ") and ":" in text:
                current["bssids"].append({"bssid": text.split(":", 1)[1].strip()})
            elif current and text.lower().startswith("signal"):
                match = re.search(r"(\d+)%", text)
                if match and current["bssids"]: current["bssids"][-1]["signal_percent"] = int(match.group(1))
            elif current and text.lower().startswith("channel"):
                match = re.search(r"(\d+)", text)
                if match and current["bssids"]: current["bssids"][-1]["channel"] = int(match.group(1))
        if current: networks.append(current)
        return {"platform": system, "networks": networks, "raw": raw}
    if system == "Linux":
        result = subprocess.run(["bash", "-lc", "iw dev"], capture_output=True, text=True, timeout=15)
        return {"platform": system, "networks": [], "adapter_info": (result.stdout + "\n" + result.stderr).strip(), "note": "Use a platform Wi-Fi survey utility for nearby AP scanning."}
    return {"platform": system, "networks": [], "note": "Nearby Wi-Fi scanning is not implemented for this platform yet."}
