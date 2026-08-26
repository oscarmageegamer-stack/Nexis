from __future__ import annotations

from .store import record_event, save_baseline


def _device_key(device: dict) -> str:
    return device.get("mac") or device.get("hostname") or device.get("ip", "unknown")


def compare_devices(previous: dict | None, current: dict) -> dict:
    previous = previous or {"devices": []}
    old = {_device_key(d): d for d in previous.get("devices", [])}
    new = {_device_key(d): d for d in current.get("devices", [])}

    added = [new[key] for key in sorted(set(new) - set(old))]
    removed = [old[key] for key in sorted(set(old) - set(new))]

    changed = []
    for key in sorted(set(old) & set(new)):
        before, after = old[key], new[key]
        fields = ["ip", "hostname", "mac", "status"]
        delta = {field: {"before": before.get(field), "after": after.get(field)}
                 for field in fields if before.get(field) != after.get(field)}
        if delta:
            changed.append({"identity": key, "changes": delta})

    result = {"added": added, "removed": removed, "changed": changed}
    if added or removed or changed:
        record_event("network_baseline_change", result)
    return result


def establish(snapshot: dict) -> None:
    save_baseline(snapshot)
    record_event("network_baseline_created", {"device_count": len(snapshot.get("devices", []))})
