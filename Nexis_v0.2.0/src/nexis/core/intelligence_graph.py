from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import time

from .store import APP_DIR

GRAPH_FILE = APP_DIR / "intelligence_graph.json"

@dataclass
class Node:
    id: str
    kind: str
    label: str
    confidence: float = 0.5
    metadata: dict | None = None
    updated_at: float = 0.0

@dataclass
class Edge:
    source: str
    target: str
    relation: str
    confidence: float = 0.5
    metadata: dict | None = None


def _load() -> dict:
    if not GRAPH_FILE.exists():
        return {"nodes": {}, "edges": []}
    try:
        return json.loads(GRAPH_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"nodes": {}, "edges": []}


def _save(data: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    GRAPH_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def upsert_node(node_id: str, kind: str, label: str, confidence: float = 0.5, metadata: dict | None = None) -> dict:
    data = _load()
    data["nodes"][node_id] = asdict(Node(node_id, kind, label, max(0.0, min(1.0, confidence)), metadata or {}, time.time()))
    _save(data)
    return data["nodes"][node_id]


def connect(source: str, target: str, relation: str, confidence: float = 0.5, metadata: dict | None = None) -> dict:
    data = _load()
    edge = asdict(Edge(source, target, relation, max(0.0, min(1.0, confidence)), metadata or {}))
    if edge not in data["edges"]:
        data["edges"].append(edge)
        _save(data)
    return edge


def snapshot() -> dict:
    return _load()


def related(node_id: str) -> dict:
    data = _load()
    node = data["nodes"].get(node_id)
    edges = [e for e in data["edges"] if e["source"] == node_id or e["target"] == node_id]
    return {"node": node, "edges": edges}
