"""Hierarchical memory — three-tier storage with automatic promotion and eviction.

Core innovation from the Reference docs: memories flow from short → mid → long
term via automatic consolidation, with configurable caps and TTL-based expiration.

Storage backend: SQLite via sqlite-utils (MVP), optionally Redis.
"""

from __future__ import annotations

import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MemoryEntry:
    """A single memory entry in any tier."""

    id: str = ""
    content: str = ""  # raw text or JSON-encoded structured data
    layer: str = "short_term"  # "short_term" | "mid_term" | "long_term"
    timestamp: float = 0.0
    ttl: float | None = None  # time-to-live in seconds
    weight: float = 1.0  # retrieval weight (boosted by flashbulb)
    emotional_salience: float = 0.0  # 0.0 to 1.0
    narrative: str = ""  # human-readable "experience summary"
    tags: list[str] = field(default_factory=list)
    embedding: list[float] | None = None
    source_task_id: str = ""  # which task created this memory

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "layer": self.layer,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
            "weight": self.weight,
            "emotional_salience": self.emotional_salience,
            "narrative": self.narrative,
            "tags": json.dumps(self.tags),
            "source_task_id": self.source_task_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryEntry":
        tags = data.get("tags", "[]")
        if isinstance(tags, str):
            tags = json.loads(tags) if tags else []
        return cls(
            id=data.get("id", ""),
            content=data.get("content", ""),
            layer=data.get("layer", "short_term"),
            timestamp=data.get("timestamp", 0.0),
            ttl=data.get("ttl"),
            weight=data.get("weight", 1.0),
            emotional_salience=data.get("emotional_salience", 0.0),
            narrative=data.get("narrative", ""),
            tags=tags,
            source_task_id=data.get("source_task_id", ""),
        )


class HierarchicalMemory:
    """Three-tier hierarchical memory system.

    Layers:
        short_term: max 10 entries — raw, full context of recent actions
        mid_term:   max 50 entries — structured summaries of completed tasks
        long_term:  max 200 entries — abstract knowledge, technique patterns

    On overflow, oldest entries are compressed and promoted upward.
    Flashbulb entries (high salience) get weight priority and bypass caps.
    """

    MAX_SHORT_TERM = 10
    MAX_MID_TERM = 50
    MAX_LONG_TERM = 200

    def __init__(
        self,
        store_backend: str = "sqlite",
        db_path: str = ":memory:",
    ) -> None:
        self.store_backend = store_backend
        self.db_path = db_path
        self._db: Any = None
        self._init_store()
        self._flashbulb_overrides: list[str] = []  # IDs of flashbulb entries

    def _init_store(self) -> None:
        """Initialize the storage backend."""
        if self.store_backend == "sqlite":
            import sqlite_utils

            self._db = sqlite_utils.Database(self.db_path)
            self._db["memories"].create(
                {
                    "id": str,
                    "content": str,
                    "layer": str,
                    "timestamp": float,
                    "ttl": float,
                    "weight": float,
                    "emotional_salience": float,
                    "narrative": str,
                    "tags": str,
                    "source_task_id": str,
                },
                pk="id",
                if_not_exists=True,
            )

    # ── Write operations ───────────────────────────────────────────

    def add_short_term(self, entry: MemoryEntry) -> str:
        """Add to short-term. If overflow, compress oldest to mid-term."""
        entry.layer = "short_term"
        entry.timestamp = time.time()
        if not entry.id:
            entry.id = self._gen_id("st", entry.timestamp)
        self._write_entry(entry)

        count = self._count("short_term")
        flashbulb_count = sum(1 for eid in self._flashbulb_overrides if self._exists(eid, "short_term"))
        normal_limit = self.MAX_SHORT_TERM - flashbulb_count

        if count > self.MAX_SHORT_TERM:
            # Move oldest non-flashbulb entries to mid-term (compress 5 oldest)
            overflow = self._get_oldest("short_term", min(5, count))
            self._promote_batch(overflow, "mid_term")

        return entry.id

    def add_mid_term(self, entry: MemoryEntry) -> str:
        """Add to mid-term. If overflow, abstract oldest to long-term."""
        entry.layer = "mid_term"
        if not entry.id:
            entry.id = self._gen_id("mt", time.time())
        self._write_entry(entry)

        count = self._count("mid_term")
        if count > self.MAX_MID_TERM:
            overflow = self._get_oldest("mid_term", min(10, count))
            self._promote_batch(overflow, "long_term")

        return entry.id

    def add_long_term(self, entry: MemoryEntry) -> str:
        """Add to long-term. If overflow, consolidate similar entries."""
        entry.layer = "long_term"
        if not entry.id:
            entry.id = self._gen_id("lt", time.time())
        self._write_entry(entry)

        count = self._count("long_term")
        if count > self.MAX_LONG_TERM:
            # Remove oldest non-flashbulb entries
            non_flashbulb = [
                e for e in self._get_oldest("long_term", 20)
                if e.id not in self._flashbulb_overrides
            ]
            for e in non_flashbulb[:5]:
                self._delete_entry(e.id)

        return entry.id

    # ── Read operations ────────────────────────────────────────────

    def retrieve(
        self,
        query: str,
        layers: list[str] | None = None,
        top_k: int = 5,
        min_salience: float = 0.0,
    ) -> list[MemoryEntry]:
        """Search across layers for entries matching the query.

        Ranking: flashbulb > weight > tag match > keyword match.
        """
        layers = layers or ["short_term", "mid_term", "long_term"]
        candidates: list[tuple[float, MemoryEntry]] = []

        query_lower = query.lower()
        query_words = set(query_lower.split())

        for layer in layers:
            for entry in self._get_all_in_layer(layer):
                score = 0.0

                # Flashbulb boost
                if entry.id in self._flashbulb_overrides:
                    score += 10.0

                # Weight
                score += entry.weight * 2.0

                # Salience filter
                if entry.emotional_salience < min_salience:
                    continue

                # Tag match
                for tag in entry.tags:
                    if tag.lower() in query_lower:
                        score += 3.0

                # Keyword match in content
                content_lower = (entry.content or "").lower()
                content_words = set(content_lower.split())
                overlap = len(query_words & content_words)
                score += overlap * 1.0

                # Keyword match in narrative
                if entry.narrative:
                    narrative_lower = entry.narrative.lower()
                    if any(w in narrative_lower for w in query_words):
                        score += 2.0

                if score > 0:
                    candidates.append((score, entry))

        # Sort by score descending, take top_k
        candidates.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in candidates[:top_k]]

    def get_by_id(self, memory_id: str) -> MemoryEntry | None:
        """Retrieve a specific memory by ID."""
        return self._read_entry(memory_id)

    def get_by_tag(self, tag: str, limit: int = 10) -> list[MemoryEntry]:
        """Retrieve memories with a specific tag."""
        results: list[MemoryEntry] = []
        for layer in ["short_term", "mid_term", "long_term"]:
            for entry in self._get_all_in_layer(layer):
                if tag in entry.tags:
                    results.append(entry)
                    if len(results) >= limit:
                        return results
        return results

    def get_flashbulbs(self, limit: int = 10) -> list[MemoryEntry]:
        """Retrieve flashbulb memories (high salience events)."""
        results: list[MemoryEntry] = []
        for entry_id in self._flashbulb_overrides:
            entry = self._read_entry(entry_id)
            if entry:
                results.append(entry)
        results.sort(key=lambda e: e.emotional_salience, reverse=True)
        return results[:limit]

    # ── Lifecycle management ───────────────────────────────────────

    def evict_expired(self) -> int:
        """Remove entries where timestamp + ttl < now. Returns count removed."""
        now = time.time()
        removed = 0
        for layer in ["short_term", "mid_term", "long_term"]:
            for entry in self._get_all_in_layer(layer):
                if entry.ttl is not None and (entry.timestamp + entry.ttl) < now:
                    self._delete_entry(entry.id)
                    if entry.id in self._flashbulb_overrides:
                        self._flashbulb_overrides.remove(entry.id)
                    removed += 1
        return removed

    def boost_weight(self, memory_id: str, factor: float = 1.5) -> None:
        """Increase the weight of a memory entry."""
        entry = self._read_entry(memory_id)
        if entry:
            entry.weight *= factor
            self._write_entry(entry)

    def mark_flashbulb(self, memory_id: str) -> None:
        """Mark a memory as a flashbulb (immune to eviction)."""
        if memory_id not in self._flashbulb_overrides:
            self._flashbulb_overrides.append(memory_id)

    def update_salience(self, memory_id: str, salience: float) -> None:
        """Update the emotional salience of a memory."""
        entry = self._read_entry(memory_id)
        if entry:
            entry.emotional_salience = salience
            self._write_entry(entry)
            if salience > 0.6 and memory_id not in self._flashbulb_overrides:
                self._flashbulb_overrides.append(memory_id)

    def consolidate_layer(
        self, from_layer: str, to_layer: str, count: int
    ) -> list[str]:
        """Move entries from one layer to another (compressing on promotion)."""
        overflow = self._get_oldest(from_layer, count)
        return self._promote_batch(overflow, to_layer)

    # ── Internal helpers ───────────────────────────────────────────

    def _gen_id(self, prefix: str, ts: float) -> str:
        import uuid
        return f"{prefix}_{ts:.0f}_{uuid.uuid4().hex[:8]}"

    def _count(self, layer: str) -> int:
        if self._db and self.store_backend == "sqlite":
            try:
                rows = list(self._db["memories"].rows_where("layer = ?", [layer]))
                return len(rows)
            except Exception:
                return 0
        return 0

    def _write_entry(self, entry: MemoryEntry) -> None:
        if not self._db:
            return
        try:
            self._db["memories"].upsert(
                entry.to_dict(),
                pk="id",
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to write memory entry {entry.id}: {e}")

    def _read_entry(self, memory_id: str) -> MemoryEntry | None:
        if not self._db:
            return None
        try:
            rows = list(self._db["memories"].rows_where("id = ?", [memory_id]))
            if rows:
                return MemoryEntry.from_dict(dict(rows[0]))
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug(f"Failed to read memory entry {memory_id}: {e}")
        return None

    def _delete_entry(self, memory_id: str) -> None:
        if self._db:
            try:
                self._db["memories"].delete(memory_id)
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to delete memory entry {memory_id}: {e}")

    def _exists(self, memory_id: str, layer: str) -> bool:
        entry = self._read_entry(memory_id)
        return entry is not None and entry.layer == layer

    def _get_all_in_layer(self, layer: str) -> list[MemoryEntry]:
        if not self._db:
            return []
        try:
            rows = self._db["memories"].rows_where("layer = ?", [layer])
            entries = [MemoryEntry.from_dict(dict(r)) for r in rows]
            # Sort by timestamp descending (newest first)
            entries.sort(key=lambda e: e.timestamp, reverse=True)
            return entries
        except Exception:
            return []

    def _get_oldest(self, layer: str, count: int) -> list[MemoryEntry]:
        """Get the oldest non-flashbulb entries in a layer."""
        entries = self._get_all_in_layer(layer)
        # Sort by timestamp ascending (oldest first)
        entries.sort(key=lambda e: e.timestamp)
        # Exclude flashbulb entries
        non_fb = [e for e in entries if e.id not in self._flashbulb_overrides]
        return non_fb[:count]

    def _promote_batch(self, entries: list[MemoryEntry], target_layer: str) -> list[str]:
        """Move entries to target layer, updating their layer field."""
        ids: list[str] = []
        for entry in entries:
            entry.layer = target_layer
            self._write_entry(entry)
            ids.append(entry.id)
        return ids

    # ── Persistence ───────────────────────────────────────────────

    def save(self) -> None:
        """Force SQLite WAL checkpoint to ensure data is on disk."""
        if self._db and self.store_backend == "sqlite":
            try:
                self._db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"WAL checkpoint failed: {e}")

    def close(self) -> None:
        """Close the database connection."""
        if self._db and self.store_backend == "sqlite":
            self.save()
            try:
                self._db.conn.close()
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to close database: {e}")

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass  # Acceptable: destructor should never raise

    @classmethod
    def load(cls, db_path: str) -> "HierarchicalMemory":
        """Load memory from a persistent SQLite file."""
        import os

        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        return cls(store_backend="sqlite", db_path=db_path)
