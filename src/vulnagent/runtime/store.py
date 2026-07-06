from __future__ import annotations

import json
import mimetypes
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from vulnagent.runtime.models import RunRecord


_TEXT_FILE_SUFFIXES = {".txt", ".log", ".json", ".md", ".html", ".htm", ".csv", ".xml", ".yaml", ".yml"}
_IMAGE_MIME_PREFIX = "image/"


class RuntimeStore:
    def __init__(self, root: Path, *, runs_root: Path | None = None) -> None:
        self.root = Path(root)
        self.db_path = self.root / "index.db"
        self.assets_root = self.root / "assets"
        self.runs_root = Path(runs_root) if runs_root is not None else self.root / "runs"
        self.root.mkdir(parents=True, exist_ok=True)
        self.assets_root.mkdir(parents=True, exist_ok=True)
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                create table if not exists assets (
                    asset_id text primary key,
                    name text not null,
                    kind text not null,
                    source_path text not null,
                    fingerprint text default '',
                    created_at real default (strftime('%s','now'))
                );

                create table if not exists runs (
                    run_id text primary key,
                    asset_id text not null,
                    entry_target text not null,
                    scope text not null,
                    status text not null,
                    run_root text not null,
                    started_at real default (strftime('%s','now')),
                    ended_at real,
                    summary text default '',
                    foreign key(asset_id) references assets(asset_id)
                );

                create table if not exists findings (
                    finding_id text primary key,
                    run_id text not null,
                    title text not null,
                    category text not null,
                    severity text not null,
                    state text not null,
                    why_suspicious text not null,
                    impact_statement text not null,
                    current_hypothesis text default '',
                    next_best_action text default '',
                    confidence real default 0.0,
                    created_at real default (strftime('%s','now')),
                    updated_at real default (strftime('%s','now'))
                );

                create table if not exists events (
                    event_id integer primary key autoincrement,
                    run_id text not null,
                    type text not null,
                    agent_name text default '',
                    payload text not null,
                    created_at real default (strftime('%s','now'))
                );

                create table if not exists agents (
                    agent_id text primary key,
                    run_id text not null,
                    agent_name text not null,
                    status text not null,
                    current_target text default '',
                    current_hypothesis text default '',
                    current_blocker text default '',
                    next_step text default '',
                    updated_at real default (strftime('%s','now'))
                );

                create table if not exists evidence (
                    evidence_id text primary key,
                    run_id text not null,
                    finding_id text not null,
                    kind text not null,
                    title text not null,
                    source_type text not null,
                    source_ref text not null,
                    collector text not null,
                    snippet text not null,
                    artifact_path text not null,
                    created_at real default (strftime('%s','now'))
                );

                create table if not exists interventions (
                    intervention_id text primary key,
                    run_id text not null,
                    scope_type text not null,
                    scope_id text not null,
                    instruction text not null,
                    status text not null,
                    response_summary text default '',
                    created_at real default (strftime('%s','now')),
                    updated_at real default (strftime('%s','now'))
                );
                create index if not exists idx_events_run_id on events(run_id);
                create index if not exists idx_events_type on events(type);
                create index if not exists idx_findings_run_id on findings(run_id);
                create index if not exists idx_findings_severity on findings(severity);
                create index if not exists idx_evidence_run_id on evidence(run_id);
                create index if not exists idx_evidence_finding_id on evidence(finding_id);
                create index if not exists idx_agents_run_id on agents(run_id);
                """
            )

    def create_run(
        self,
        *,
        asset_name: str,
        asset_kind: str,
        source_path: str,
        entry_target: str,
        scope: str,
    ) -> RunRecord:
        asset_id = uuid.uuid5(uuid.NAMESPACE_URL, f"{asset_kind}:{source_path}").hex
        run_id = uuid.uuid4().hex[:12]
        run_root = self.runs_root / run_id
        for child in (run_root, run_root / "artifacts", run_root / "reports", run_root / "exports"):
            child.mkdir(parents=True, exist_ok=True)
        (run_root / "events.jsonl").touch()
        with self._connect() as conn:
            conn.execute(
                "insert or ignore into assets(asset_id, name, kind, source_path) values (?, ?, ?, ?)",
                (asset_id, asset_name, asset_kind, source_path),
            )
            conn.execute(
                "insert into runs(run_id, asset_id, entry_target, scope, status, run_root) values (?, ?, ?, ?, ?, ?)",
                (run_id, asset_id, entry_target, scope, "running", str(run_root)),
            )
        return RunRecord(
            run_id=run_id,
            asset_id=asset_id,
            asset_name=asset_name,
            asset_kind=asset_kind,
            source_path=source_path,
            entry_target=entry_target,
            scope=scope,
            status="running",
            run_root=run_root,
        )

    def upsert_finding(self, **payload: object) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                insert into findings (
                    finding_id, run_id, title, category, severity, state,
                    why_suspicious, impact_statement, current_hypothesis,
                    next_best_action, confidence
                ) values (
                    :finding_id, :run_id, :title, :category, :severity, :state,
                    :why_suspicious, :impact_statement, :current_hypothesis,
                    :next_best_action, :confidence
                )
                on conflict(finding_id) do update set
                    state=excluded.state,
                    why_suspicious=excluded.why_suspicious,
                    impact_statement=excluded.impact_statement,
                    current_hypothesis=excluded.current_hypothesis,
                    next_best_action=excluded.next_best_action,
                    confidence=excluded.confidence,
                    updated_at=strftime('%s','now')
                """,
                {
                    "current_hypothesis": "",
                    "next_best_action": "",
                    "confidence": 0.0,
                    **payload,
                },
            )

    def append_event(self, run_id: str, payload: dict[str, object]) -> None:
        event_path = self.runs_root / run_id / "events.jsonl"
        event_path.parent.mkdir(parents=True, exist_ok=True)
        with event_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")

        with self._connect() as conn:
            conn.execute(
                "insert into events(run_id, type, agent_name, payload) values (?, ?, ?, ?)",
                (
                    run_id,
                    str(payload.get("type", "")),
                    str(payload.get("agent_name", "")),
                    json.dumps(payload, ensure_ascii=False, default=str),
                ),
            )

    def list_events(self, run_id: str) -> list[dict[str, object]]:
        with self._connect() as conn:
            rows = conn.execute(
                "select type, agent_name, payload, created_at from events where run_id = ? order by event_id asc",
                (run_id,),
            )
            events: list[dict[str, object]] = []
            for row in rows:
                payload = json.loads(str(row["payload"]))
                payload["created_at"] = row["created_at"]
                events.append(payload)
            return events

    def upsert_agent(
        self,
        *,
        run_id: str,
        agent_name: str,
        current_target: str,
        status: str,
        current_hypothesis: str = "",
        current_blocker: str = "",
        next_step: str = "",
    ) -> None:
        agent_id = f"{run_id}:{agent_name}"
        with self._connect() as conn:
            conn.execute(
                """
                insert into agents (
                    agent_id, run_id, agent_name, status, current_target,
                    current_hypothesis, current_blocker, next_step
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(agent_id) do update set
                    status=excluded.status,
                    current_target=excluded.current_target,
                    current_hypothesis=excluded.current_hypothesis,
                    current_blocker=excluded.current_blocker,
                    next_step=excluded.next_step,
                    updated_at=strftime('%s','now')
                """,
                (
                    agent_id,
                    run_id,
                    agent_name,
                    status,
                    current_target,
                    current_hypothesis,
                    current_blocker,
                    next_step,
                ),
            )

    def list_agents(self, run_id: str) -> list[dict[str, object]]:
        with self._connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "select * from agents where run_id = ? order by updated_at desc, agent_name asc",
                    (run_id,),
                )
            ]

    def add_evidence(
        self,
        *,
        evidence_id: str,
        run_id: str,
        finding_id: str,
        kind: str,
        title: str,
        source_type: str,
        source_ref: str,
        collector: str,
        snippet: str,
        artifact_path: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                insert or replace into evidence (
                    evidence_id, run_id, finding_id, kind, title, source_type,
                    source_ref, collector, snippet, artifact_path
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    run_id,
                    finding_id,
                    kind,
                    title,
                    source_type,
                    source_ref,
                    collector,
                    snippet,
                    artifact_path,
                ),
            )

    def list_evidence_for_finding(self, finding_id: str) -> list[dict[str, object]]:
        with self._connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "select * from evidence where finding_id = ? order by created_at asc",
                    (finding_id,),
                )
            ]

    def list_run_evidence(self, run_id: str) -> list[dict[str, object]]:
        with self._connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "select * from evidence where run_id = ? order by created_at asc",
                    (run_id,),
                )
            ]

    def create_intervention(
        self,
        *,
        run_id: str,
        scope_type: str,
        scope_id: str,
        instruction: str,
    ) -> dict[str, object]:
        intervention_id = uuid.uuid4().hex[:12]
        payload: dict[str, object] = {
            "intervention_id": intervention_id,
            "run_id": run_id,
            "scope_type": scope_type,
            "scope_id": scope_id,
            "instruction": instruction,
            "status": "received",
            "response_summary": "",
        }
        with self._connect() as conn:
            conn.execute(
                """
                insert into interventions(
                    intervention_id, run_id, scope_type, scope_id,
                    instruction, status, response_summary
                ) values (
                    :intervention_id, :run_id, :scope_type, :scope_id,
                    :instruction, :status, :response_summary
                )
                """,
                payload,
            )
            row = conn.execute(
                "select * from interventions where intervention_id = ?",
                (intervention_id,),
            ).fetchone()
        return dict(row) if row else payload

    def list_run_interventions(self, run_id: str) -> list[dict[str, object]]:
        with self._connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "select * from interventions where run_id = ? order by created_at desc, intervention_id desc",
                    (run_id,),
                )
            ]

    def update_intervention(
        self,
        intervention_id: str,
        *,
        status: str,
        response_summary: str = "",
    ) -> dict[str, object] | None:
        with self._connect() as conn:
            conn.execute(
                """
                update interventions
                set status = ?, response_summary = ?, updated_at = strftime('%s','now')
                where intervention_id = ?
                """,
                (status, response_summary, intervention_id),
            )
            row = conn.execute(
                "select * from interventions where intervention_id = ?",
                (intervention_id,),
            ).fetchone()
            return dict(row) if row else None

    def update_run_status(self, run_id: str, *, status: str, summary: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                """
                update runs
                set status = ?, summary = ?, ended_at = strftime('%s','now')
                where run_id = ?
                """,
                (status, summary, run_id),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "select * from runs where run_id = ?",
                (run_id,),
            ).fetchone()
            return dict(row) if row else None

    def get_run_root(self, run_id: str) -> Path:
        run = self.get_run(run_id)
        if not run:
            raise FileNotFoundError(f"run not found: {run_id}")
        run_root = Path(str(run.get("run_root", ""))).resolve()
        if not run_root.exists() or not run_root.is_dir():
            raise FileNotFoundError(f"run root not found: {run_root}")
        return run_root

    def resolve_run_relative_path(self, run_id: str, relative_path: str) -> Path:
        normalized = str(relative_path or "").strip().replace("\\", "/")
        if not normalized:
            raise ValueError("path is required")
        candidate = Path(normalized)
        if candidate.is_absolute() or any(part == ".." for part in candidate.parts):
            raise ValueError("invalid path")

        run_root = self.get_run_root(run_id)
        resolved = (run_root / candidate).resolve()
        try:
            resolved.relative_to(run_root)
        except ValueError as exc:
            raise ValueError("invalid path") from exc
        return resolved

    def build_run_file_tree(self, run_id: str) -> dict[str, Any]:
        run_root = self.get_run_root(run_id)

        def build_node(path: Path) -> dict[str, Any]:
            stat = path.stat()
            relative_path = "" if path == run_root else path.relative_to(run_root).as_posix()
            node: dict[str, Any] = {
                "relative_path": relative_path,
                "name": path.name or run_root.name,
                "kind": "directory" if path.is_dir() else "file",
                "size": int(stat.st_size),
                "mtime": float(stat.st_mtime),
            }
            if path.is_dir():
                node["children"] = [
                    build_node(child)
                    for child in sorted(path.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
                ]
            return node

        return build_node(run_root)

    def get_run_file_content(self, run_id: str, relative_path: str) -> dict[str, Any]:
        resolved = self.resolve_run_relative_path(run_id, relative_path)
        if not resolved.exists() or not resolved.is_file():
            raise FileNotFoundError(relative_path)

        stat = resolved.stat()
        mime_type, _ = mimetypes.guess_type(resolved.name)
        normalized_path = Path(relative_path).as_posix()
        base = {
            "relative_path": normalized_path,
            "name": resolved.name,
            "size": int(stat.st_size),
            "mtime": float(stat.st_mtime),
            "mime_type": mime_type or "application/octet-stream",
        }
        suffix = resolved.suffix.lower()
        if suffix in _TEXT_FILE_SUFFIXES or (mime_type or "").startswith("text/"):
            return {
                **base,
                "kind": "text",
                "content": resolved.read_text(encoding="utf-8", errors="replace"),
            }
        if (mime_type or "").startswith(_IMAGE_MIME_PREFIX):
            return {
                **base,
                "kind": "image",
            }
        return {
            **base,
            "kind": "binary",
            "message": "暂不支持预览",
        }

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "select * from findings where finding_id = ?",
                (finding_id,),
            ).fetchone()
            return dict(row) if row else None

    def list_assets(self) -> list[dict[str, object]]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute("select * from assets order by created_at desc")]

    def list_runs_for_asset(self, asset_id: str) -> list[dict[str, object]]:
        with self._connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "select * from runs where asset_id = ? order by started_at desc",
                    (asset_id,),
                )
            ]

    def list_findings(self, run_id: str) -> list[dict[str, object]]:
        with self._connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "select * from findings where run_id = ? order by updated_at desc",
                    (run_id,),
                )
            ]

    def list_run_agents(self, run_id: str) -> list[dict[str, Any]]:
        return self.list_agents(run_id)

    def list_run_timeline(
        self,
        run_id: str,
        limit: int = 50,
        *,
        finding_id: str = "",
        artifact_path: str = "",
        phase: str = "",
        agent_name: str = "",
        event_type: str = "",
        intervention_id: str = "",
    ) -> list[dict[str, Any]]:
        events = self.list_events(run_id)
        filters = {
            "finding_id": str(finding_id or "").strip(),
            "artifact_path": str(artifact_path or "").strip(),
            "phase": str(phase or "").strip(),
            "agent_name": str(agent_name or "").strip(),
            "event_type": str(event_type or "").strip(),
            "intervention_id": str(intervention_id or "").strip(),
        }
        filtered = [event for event in events if _timeline_event_matches(event, filters)]
        if limit <= 0:
            return filtered
        return filtered[-limit:]


def _timeline_event_matches(event: dict[str, Any], filters: dict[str, str]) -> bool:
    if not any(filters.values()):
        return True

    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    haystack_parts = [
        str(event.get("type", "")),
        str(event.get("agent_name", "")),
        str(event.get("message", "")),
        str(event.get("title", "")),
        json.dumps(data, ensure_ascii=False, sort_keys=True),
    ]
    haystack = "\n".join(haystack_parts).lower()

    checks = [
        (filters["finding_id"], [data.get("finding_id"), event.get("finding_id")]),
        (filters["artifact_path"], [data.get("artifact_path"), data.get("path"), event.get("artifact_path")]),
        (filters["phase"], [data.get("phase"), event.get("phase")]),
        (filters["agent_name"], [event.get("agent_name"), data.get("agent_name")]),
        (filters["event_type"], [event.get("type")]),
        (filters["intervention_id"], [data.get("intervention_id"), event.get("intervention_id")]),
    ]
    for needle, candidates in checks:
        if not needle:
            continue
        normalized = needle.lower()
        structured = {str(value).strip().lower() for value in candidates if str(value or "").strip()}
        if normalized in structured:
            continue
        if normalized not in haystack:
            return False
    return True
