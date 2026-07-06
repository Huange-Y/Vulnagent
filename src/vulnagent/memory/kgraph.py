"""Knowledge Graph — semantic memory as a structured entity-relation network.

Innovation: security-specific entity types and relation predicates that form
an "attack path topology" rather than a generic concept graph.

Entity types: tool, vulnerability, technique, service, target, flag_type, payload, defense
Relation predicates: exposes, exploits, bypasses, requires, contradicts, is_variant_of, patched_in

This enables path-based reasoning: seeing "apache/2.4.29" traverses directly
to exploitable vulnerabilities and their payloads.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import networkx as nx


@dataclass
class Entity:
    """A node in the knowledge graph."""

    id: str
    type: str  # tool | vulnerability | technique | service | target | flag_type | payload | defense
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class Relation:
    """A directed edge in the knowledge graph."""

    subject: str
    predicate: str  # exposes | exploits | bypasses | requires | contradicts | is_variant_of | patched_in
    object: str
    weight: float = 1.0
    timestamp: float = 0.0
    ttl: float | None = None  # temporal validity — relations can expire


class KnowledgeGraph:
    """NetworkX-backed knowledge graph for semantic security memory.

    Usage:
        kg = KnowledgeGraph()
        kg.add_entity(Entity("tool:nmap", "tool"))
        kg.add_entity(Entity("cve-2021-41773", "vulnerability", {"cvss": 7.5}))
        kg.add_relation("tool:nmap", "exposes", "service:apache/2.4.29")
        paths = kg.traverse("service:apache/2.4.29", max_depth=3)
    """

    # Security-specific predicate vocabulary
    PREDICATES = {
        "exposes": "A tool or scan reveals a service or vulnerability",
        "exploits": "A technique exploits a vulnerability",
        "bypasses": "A technique bypasses a defense",
        "requires": "A technique requires a payload or condition",
        "contradicts": "Two techniques or findings are incompatible",
        "is_variant_of": "One vulnerability is a variant of another",
        "patched_in": "A vulnerability is patched in a specific version (temporal)",
    }

    def __init__(self, backend: str = "networkx") -> None:
        self._graph = nx.DiGraph()
        self._entities: dict[str, Entity] = {}

    # ── Entity operations ──────────────────────────────────────────

    def add_entity(self, entity: Entity) -> str:
        """Add or update an entity. Returns the entity ID."""
        self._entities[entity.id] = entity
        self._graph.add_node(entity.id, type=entity.type, **entity.properties)
        return entity.id

    def get_entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def search_entities(
        self,
        query: str,
        entity_type: str | None = None,
        top_k: int = 10,
    ) -> list[Entity]:
        """Search entities by query string, optionally filtering by type."""
        results: list[tuple[float, Entity]] = []
        query_lower = query.lower()
        query_words = set(query_lower.split())

        for entity in self._entities.values():
            if entity_type and entity.type != entity_type:
                continue

            score = 0.0
            entity_text = f"{entity.id} {json.dumps(entity.properties)}".lower()

            # Direct ID match
            if query_lower in entity.id.lower():
                score += 5.0

            # Property match
            for word in query_words:
                if word in entity_text:
                    score += 2.0

            if score > 0:
                results.append((score, entity))

        results.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in results[:top_k]]

    def list_entities_by_type(self, entity_type: str) -> list[Entity]:
        """Get all entities of a specific type."""
        return [e for e in self._entities.values() if e.type == entity_type]

    # ── Relation operations ────────────────────────────────────────

    def add_relation(
        self,
        subject: str,
        predicate: str,
        object_: str,
        weight: float = 1.0,
        ttl: float | None = None,
        **attrs: Any,
    ) -> None:
        """Add a directed relation between two entities.

        Args:
            subject: Source entity ID
            predicate: Relation type (must be in PREDICATES)
            object_: Target entity ID
            weight: Relation strength
            ttl: Time-to-live in seconds (None = permanent)
        """
        # Auto-create entities if they don't exist
        if subject not in self._entities:
            self.add_entity(Entity(subject, "unknown"))
        if object_ not in self._entities:
            self.add_entity(Entity(object_, "unknown"))

        self._graph.add_edge(
            subject, object_,
            predicate=predicate,
            weight=weight,
            timestamp=time.time(),
            ttl=ttl,
            **attrs,
        )

    def has_relation(self, subject: str, predicate: str, object_: str) -> bool:
        """Check if a specific relation exists."""
        if not self._graph.has_edge(subject, object_):
            return False
        edge_data = self._graph.get_edge_data(subject, object_)
        return edge_data.get("predicate") == predicate

    # ── Graph traversal ────────────────────────────────────────────

    def traverse(
        self,
        start_entity: str,
        max_depth: int = 3,
        predicates: list[str] | None = None,
    ) -> dict[str, Any]:
        """BFS traversal from start entity, following specified predicates.

        Returns:
            {"entities": [...], "relations": [...], "paths": [[...]]}
        """
        if start_entity not in self._graph:
            return {"entities": [], "relations": [], "paths": []}

        entities_found: set[str] = {start_entity}
        relations_found: list[dict[str, Any]] = []
        paths: dict[str, list[str]] = {start_entity: [start_entity]}

        frontier = [start_entity]
        for _ in range(max_depth):
            next_frontier: list[str] = []
            for node in frontier:
                for _, neighbor, edge_data in self._graph.out_edges(node, data=True):
                    pred = edge_data.get("predicate", "")
                    if predicates and pred not in predicates:
                        continue
                    if neighbor not in entities_found:
                        entities_found.add(neighbor)
                        paths[neighbor] = paths[node] + [neighbor]
                        next_frontier.append(neighbor)
                    relations_found.append({
                        "subject": node,
                        "predicate": pred,
                        "object": neighbor,
                        "weight": edge_data.get("weight", 1.0),
                        "timestamp": edge_data.get("timestamp", 0.0),
                    })
            frontier = next_frontier

        return {
            "entities": [
                {"id": eid, **self._entities[eid].__dict__}
                for eid in entities_found
                if eid in self._entities
            ],
            "relations": relations_found,
            "paths": [
                {"target": target, "path": path}
                for target, path in paths.items()
            ][:10],
        }

    def query_paths(
        self,
        source: str,
        target: str,
        max_length: int = 5,
        predicates: list[str] | None = None,
    ) -> list[list[str]]:
        """Find all paths between source and target within max_length."""
        if source not in self._graph or target not in self._graph:
            return []

        try:
            paths: list[list[str]] = []
            for path in nx.all_simple_paths(self._graph, source, target, cutoff=max_length):
                # Filter by predicates if specified
                if predicates:
                    valid = True
                    for i in range(len(path) - 1):
                        edge_data = self._graph.get_edge_data(path[i], path[i + 1])
                        if edge_data and edge_data.get("predicate") not in predicates:
                            valid = False
                            break
                    if not valid:
                        continue
                paths.append(path)

            paths.sort(key=len)
            return paths[:20]
        except nx.NetworkXNoPath:
            return []

    def get_neighbors(self, entity_id: str, radius: int = 1) -> list[Entity]:
        """Get neighboring entities within the specified radius."""
        if entity_id not in self._graph:
            return []

        neighbors: set[str] = set()
        frontier = {entity_id}
        for _ in range(radius):
            next_frontier: set[str] = set()
            for node in frontier:
                next_frontier.update(self._graph.neighbors(node))
                next_frontier.update(self._graph.predecessors(node))
            neighbors.update(next_frontier)
            frontier = next_frontier

        return [self._entities[n] for n in neighbors if n in self._entities]

    # ── Attack path reasoning (innovation) ─────────────────────────

    def find_attack_paths(
        self,
        entity_id: str,
        target_type: str = "payload",
    ) -> list[dict[str, Any]]:
        """Find all attack paths from an entity to any payload-type entity.

        This is the core "attack path topology" traversal — given a
        service or vulnerability, find the chain to exploitable payloads.

        Returns paths sorted by relevance (shortest first, highest weight).
        """
        payloads = self.list_entities_by_type(target_type)
        all_paths: list[dict[str, Any]] = []

        for payload in payloads:
            paths = self.query_paths(entity_id, payload.id, max_length=5)
            for path in paths:
                # Calculate total path weight
                total_weight = 0.0
                edges: list[str] = []
                for i in range(len(path) - 1):
                    edge_data = self._graph.get_edge_data(path[i], path[i + 1])
                    if edge_data:
                        total_weight += edge_data.get("weight", 1.0)
                        edges.append(edge_data.get("predicate", ""))

                all_paths.append({
                    "path": path,
                    "edges": edges,
                    "length": len(path),
                    "weight": total_weight,
                    "target_payload": payload.id,
                })

        all_paths.sort(key=lambda x: (x["length"], -x["weight"]))
        return all_paths[:20]

    # ── Maintenance ────────────────────────────────────────────────

    def remove_expired_relations(self) -> int:
        """Remove relations where timestamp + ttl < now. Returns count removed."""
        now = time.time()
        removed = 0
        edges_to_remove: list[tuple[str, str]] = []

        for u, v, data in self._graph.edges(data=True):
            ttl = data.get("ttl")
            if ttl is not None:
                ts = data.get("timestamp", 0)
                if ts + ttl < now:
                    edges_to_remove.append((u, v))

        for u, v in edges_to_remove:
            self._graph.remove_edge(u, v)
            removed += 1

        return removed

    def remove_orphan_entities(self) -> int:
        """Remove entities with no incoming or outgoing relations."""
        orphans = [n for n in self._graph.nodes() if self._graph.degree(n) == 0]
        for node in orphans:
            self._graph.remove_node(node)
            self._entities.pop(node, None)
        return len(orphans)

    # ── Serialization ──────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph to a dict for persistence."""
        return {
            "entities": {
                eid: {"type": e.type, "properties": e.properties}
                for eid, e in self._entities.items()
            },
            "relations": [
                {
                    "subject": u, "predicate": data.get("predicate", ""),
                    "object": v, "weight": data.get("weight", 1.0),
                    "timestamp": data.get("timestamp", 0.0),
                    "ttl": data.get("ttl"),
                }
                for u, v, data in self._graph.edges(data=True)
            ],
        }

    def from_dict(self, data: dict[str, Any]) -> None:
        """Restore a graph from a serialized dict."""
        self._graph.clear()
        self._entities.clear()

        for eid, edata in data.get("entities", {}).items():
            self.add_entity(Entity(
                id=eid,
                type=edata.get("type", "unknown"),
                properties=edata.get("properties", {}),
            ))

        for rdata in data.get("relations", []):
            self.add_relation(
                subject=rdata["subject"],
                predicate=rdata["predicate"],
                object_=rdata["object"],
                weight=rdata.get("weight", 1.0),
                ttl=rdata.get("ttl"),
            )

    def save(self, filepath: str) -> None:
        """Persist knowledge graph to a JSON file."""
        import os
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @classmethod
    def load(cls, filepath: str) -> "KnowledgeGraph":
        """Load knowledge graph from a JSON file."""
        kg = cls()
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            kg.from_dict(data)
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # fresh graph
        return kg

    @property
    def stats(self) -> dict[str, int]:
        return {
            "entities": len(self._entities),
            "relations": self._graph.number_of_edges(),
            "entity_types": {
                t: len(self.list_entities_by_type(t))
                for t in {"tool", "vulnerability", "technique", "service", "payload", "defense", "unknown"}
            },
        }
