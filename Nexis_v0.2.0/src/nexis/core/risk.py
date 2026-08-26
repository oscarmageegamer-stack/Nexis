from __future__ import annotations

SEVERITY_WEIGHTS = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}


def score_finding(severity: str, confidence: str = "medium") -> int:
    base = SEVERITY_WEIGHTS.get(severity.lower(), 5)
    multiplier = {"high": 1.0, "medium": 0.8, "low": 0.6}.get(confidence.lower(), 0.8)
    return round(base * multiplier)


def assess_network_change(delta: dict) -> dict:
    added = len(delta.get("added", []))
    removed = len(delta.get("removed", []))
    changed = len(delta.get("changed", []))

    if added == 0 and removed == 0 and changed == 0:
        return {"risk": "INFO", "score": 0, "summary": "No baseline changes detected."}

    # Discovery changes are observations, not proof of compromise.
    if added >= 5 or removed >= 5:
        risk, score = "MEDIUM", 35
    elif added or removed:
        risk, score = "LOW", 20
    else:
        risk, score = "INFO", 5

    return {
        "risk": risk,
        "score": score,
        "summary": (
            f"Detected {added} new, {removed} missing and {changed} changed device record(s)."
        ),
    }
