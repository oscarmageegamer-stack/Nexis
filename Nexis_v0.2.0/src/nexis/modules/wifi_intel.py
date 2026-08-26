from __future__ import annotations

import platform
import re
import subprocess


def snapshot() -> dict:
    system = platform.system()
    if system == "Windows":
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=15)
        raw = (result.stdout + "\n" + result.stderr).strip()
        parsed = {"platform": system, "raw": raw, "ssid": None, "bssid": None, "signal_percent": None, "channel": None, "radio": None}
        for line in raw.splitlines():
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "ssid": parsed["ssid"] = value or None
            elif key == "bssid": parsed["bssid"] = value or None
            elif key == "signal":
                match = re.search(r"(\d+)%", value)
                parsed["signal_percent"] = int(match.group(1)) if match else None
            elif key == "channel":
                match = re.search(r"(\d+)", value)
                parsed["channel"] = int(match.group(1)) if match else None
            elif key == "radio type": parsed["radio"] = value or None
        return parsed

    if system == "Linux":
        result = subprocess.run(["bash", "-lc", "iw dev"], capture_output=True, text=True, timeout=15)
        return {"platform": system, "raw": (result.stdout + "\n" + result.stderr).strip()}

    return {"platform": system, "raw": "", "note": "Platform-specific Wi-Fi telemetry is not implemented yet."}


def quality(signal_percent: int | None, latency_ms: float | None = None, packet_loss: float | None = None) -> dict:
    score = 50
    if signal_percent is not None:
        score = max(0, min(100, signal_percent))
    if latency_ms is not None:
        if latency_ms > 100: score -= 20
        elif latency_ms > 60: score -= 10
        elif latency_ms < 20: score += 5
    if packet_loss is not None:
        score -= min(40, int(packet_loss * 2))
    score = max(0, min(100, score))
    label = "excellent" if score >= 85 else "good" if score >= 70 else "fair" if score >= 50 else "poor"
    return {"score": score, "label": label}
