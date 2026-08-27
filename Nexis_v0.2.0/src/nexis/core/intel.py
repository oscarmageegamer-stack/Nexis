from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import json
import uuid

from .store import APP_DIR

INTEL_FILE = APP_DIR / "intel.json"


@dataclass
class IntelNode:
    id: str
    kind: str
    label: str
    value: str = ""
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


@dataclass
class IntelEdge:
    source: str
    target: str
    relation: str
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


def _load() -> dict:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    if not INTEL_FILE.exists():
        return {"nodes": [], "edges": [], "updated_at": None}
    try:
        return json.loads(INTEL_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"nodes": [], "edges": [], "updated_at": None}


def _save(data: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    INTEL_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def add_node(kind: str, label: str, value: str = "", confidence: float = 1.0, metadata: dict | None = None) -> str:
    data = _load()
    for node in data["nodes"]:
        if node["kind"] == kind and node["label"] == label and node.get("value", "") == value:
            return node["id"]
    node_id = str(uuid.uuid4())
    data["nodes"].append({"id": node_id, "kind": kind, "label": label, "value": value, "confidence": max(0.0, min(1.0, confidence)), "metadata": metadata or {}})
    _save(data)
    return node_id


def add_edge(source: str, target: str, relation: str, confidence: float = 1.0, metadata: dict | None = None) -> None:
    data = _load()
    edge = {"source": source, "target": target, "relation": relation, "confidence": max(0.0, min(1.0, confidence)), "metadata": metadata or {}}
    if not any(e["source"] == source and e["target"] == target and e["relation"] == relation for e in data["edges"]):
        data["edges"].append(edge)
        _save(data)


def summary() -> dict:
    data = _load()
    return {"nodes": len(data["nodes"]), "edges": len(data["edges"]), "updated_at": data.get("updated_at"), "storage": str(INTEL_FILE)}


def related(label: str) -> dict:
    data = _load()
    ids = {n["id"] for n in data["nodes"] if n["label"].lower() == label.lower() or n.get("value", "").lower() == label.lower()}
    node_map = {n["id"]: n for n in data["nodes"]}
    related_nodes = set(ids)
    matching_edges = []
    for edge in data["edges"]:
        if edge["source"] in ids or edge["target"] in ids:
            matching_edges.append(edge)
            related_nodes.add(edge["source"])
            related_nodes.add(edge["target"])
    return {"query": label, "nodes": [node_map[i] for i in related_nodes if i in node_map], "edges": matching_edges}
