from __future__ import annotations

from collections import defaultdict


def correlate(observations: list[dict]) -> dict:
    """Correlate structured observations without inferring hidden facts."""
    by_key: dict[str, list[dict]] = defaultdict(list)
    for item in observations:
        key = str(item.get("asset") or item.get("target") or item.get("label") or "unknown")
        by_key[key].append(item)

    groups = []
    for key, items in sorted(by_key.items()):
        severities = [str(i.get("severity", "info")).lower() for i in items]
        score = 0
        score += severities.count("low") * 10
        score += severities.count("medium") * 25
        score += severities.count("high") * 45
        score += severities.count("critical") * 70
        confidence = sum(float(i.get("confidence", 1.0)) for i in items) / len(items)
        groups.append({
            "asset": key,
            "observation_count": len(items),
            "risk_score": min(100, score),
            "confidence": round(max(0.0, min(1.0, confidence)), 3),
            "observations": items,
        })

    return {"groups": groups, "observation_count": len(observations)}
