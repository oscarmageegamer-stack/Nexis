from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json
import threading


GRAPH_FILE = Path.home() / ".nexis" / "intelligence_graph.json"


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    value: str
    confidence: float = 1.0
    first_seen: str = ""
    last_seen: str = ""


@dataclass(frozen=True)
class Edge:
    source: str
    relation: str
    target: str
    confidence: float = 1.0


class IntelligenceGraph:
    """Persistent asset/relationship graph for authorised investigations."""

    def __init__(self, path: Path = GRAPH_FILE) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.nodes = {item["id"]: Node(**item) for item in data.get("nodes", [])}
            self.edges = [Edge(**item) for item in data.get("edges", [])]
        except (OSError, json.JSONDecodeError, TypeError):
            self.nodes, self.edges = {}, []

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "nodes": [asdict(node) for node in self.nodes.values()],
            "edges": [asdict(edge) for edge in self.edges],
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def upsert_node(self, node_id: str, kind: str, value: str, confidence: float = 1.0) -> Node:
        now = datetime.now(timezone.utc).isoformat()
        confidence = max(0.0, min(1.0, confidence))
        with self._lock:
            current = self.nodes.get(node_id)
            node = Node(
                id=node_id,
                kind=kind,
                value=value,
                confidence=confidence if current is None else max(current.confidence, confidence),
                first_seen=current.first_seen if current else now,
                last_seen=now,
            )
            self.nodes[node_id] = node
            self._save()
            return node

    def relate(self, source: str, relation: str, target: str, confidence: float = 1.0) -> Edge:
        edge = Edge(source, relation, target, max(0.0, min(1.0, confidence)))
        with self._lock:
            if edge not in self.edges:
                self.edges.append(edge)
                self._save()
        return edge

    def neighbours(self, node_id: str) -> list[dict]:
        related: list[dict] = []
        for edge in self.edges:
            if edge.source == node_id and edge.target in self.nodes:
                related.append({"relation": edge.relation, "target": asdict(self.nodes[edge.target]), "confidence": edge.confidence})
            elif edge.target == node_id and edge.source in self.nodes:
                related.append({"relation": edge.relation, "target": asdict(self.nodes[edge.source]), "confidence": edge.confidence})
        return related

    def summary(self) -> dict:
        return {"nodes": len(self.nodes), "edges": len(self.edges), "kinds": sorted({n.kind for n in self.nodes.values()})}
