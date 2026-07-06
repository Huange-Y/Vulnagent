from __future__ import annotations

import hashlib


class ProjectionProjector:
    """Project agent events into RuntimeStore for observability.

    Handles node.enter, tool.called, tool.result, verify.completed,
    flashbulb.detected, and agent.phase events.
    """

    def __init__(self, store, run_id: str) -> None:
        self.store = store
        self.run_id = run_id
        self._phase: str = ""

    def handle(self, event) -> None:
        payload = event.to_dict()
        event_type = str(payload.get("type", ""))
        agent_name = str(payload.get("agent_name", ""))

        # Write every event to store (JSONL + SQLite)
        self.store.append_event(self.run_id, payload)

        # Phase tracking
        if event_type == "agent.phase":
            self._phase = str(payload.get("message", "")) or str(
                (payload.get("data") or {}).get("phase", "")
            )
            self.store.upsert_agent(
                run_id=self.run_id, agent_name=agent_name or "orchestrator",
                status=self._phase,
            )

        # Node transitions
        if event_type == "node.enter":
            node = str(payload.get("data", {}).get("node", "")) or str(
                payload.get("message", "")
            )
            self.store.upsert_agent(
                run_id=self.run_id,
                agent_name=agent_name or "unknown",
                current_target=node,
                status="running",
            )

        # Tool calls — record agent activity
        if event_type == "tool.called":
            tool_name = str(payload.get("message", ""))
            tool_args = payload.get("data", {}).get("args", {})
            self.store.upsert_agent(
                run_id=self.run_id,
                agent_name=agent_name or "unknown",
                current_target=tool_name,
                next_step=str(tool_args)[:200],
                status="running",
            )

        # Verification completion — capture findings
        if event_type == "verify.completed":
            data = payload.get("data", {})
            findings = data.get("findings", data.get("confirmed", []))
            if isinstance(findings, list):
                for f in findings:
                    if isinstance(f, dict) and f.get("title"):
                        self.record_observation(
                            agent_name=agent_name,
                            title=str(f.get("title", "")),
                            category=str(f.get("vuln_type", f.get("cwe_id", ""))),
                            severity=str(f.get("severity", "medium")),
                            why_suspicious=str(f.get("evidence", "")),
                            impact_statement=str(f.get("impact", "")),
                            source_ref=str(f.get("component_path", "")),
                            snippet=str(f.get("evidence", ""))[:500],
                        )

        # Flashbulb moments
        if event_type == "flashbulb.detected":
            data = payload.get("data", {})
            self.store.upsert_agent(
                run_id=self.run_id,
                agent_name=agent_name or "unknown",
                current_hypothesis=str(data.get("trigger", "")),
                next_step="Investigate flashbulb trigger",
                current_blocker="",
                status="flashbulb",
            )

    def record_observation(
        self,
        *,
        agent_name: str,
        title: str,
        category: str,
        severity: str,
        why_suspicious: str,
        impact_statement: str,
        source_ref: str,
        snippet: str,
    ) -> str:
        finding_id = hashlib.sha1(f"{self.run_id}:{title}:{source_ref}".encode("utf-8")).hexdigest()[:16]
        evidence_id = hashlib.sha1(f"{finding_id}:{snippet}".encode("utf-8")).hexdigest()[:16]
        self.store.upsert_finding(
            run_id=self.run_id,
            finding_id=finding_id,
            title=title,
            category=category,
            severity=severity,
            state="suspect",
            why_suspicious=why_suspicious,
            impact_statement=impact_statement,
            current_hypothesis="",
            next_best_action="Validate the exposed service or code path.",
            confidence=0.4,
        )
        self.store.add_evidence(
            evidence_id=evidence_id,
            run_id=self.run_id,
            finding_id=finding_id,
            kind="file_hit",
            title=title,
            source_type="artifact_path",
            source_ref=source_ref,
            collector=agent_name,
            snippet=snippet,
            artifact_path=source_ref,
        )
        self.store.upsert_agent(
            run_id=self.run_id,
            agent_name=agent_name,
            current_target=source_ref,
            status="running",
            current_hypothesis=title,
            next_step="Validate the exposed service or code path.",
        )
        return finding_id
