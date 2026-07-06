from pathlib import Path

from vulnagent.events.types import AgentEvent
from vulnagent.runtime.projector import ProjectionProjector
from vulnagent.runtime.store import RuntimeStore


def test_projector_records_raw_event_and_agent_summary(tmp_path: Path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="local-test",
    )
    projector = ProjectionProjector(store=store, run_id=run.run_id)

    projector.handle(AgentEvent.node_enter("DiscoveryAgent", "execute_tools"))

    events = store.list_events(run.run_id)
    agents = store.list_agents(run.run_id)
    assert events[0]["type"] == "node.enter"
    assert agents[0]["current_target"] == "execute_tools"


def test_projector_promotes_finding_and_evidence_from_tool_output(tmp_path: Path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="local-test",
    )
    projector = ProjectionProjector(store=store, run_id=run.run_id)

    projector.record_observation(
        agent_name="DiscoveryAgent",
        title="BusyBox telnetd exposed in init scripts",
        category="service-exposure",
        severity="medium",
        why_suspicious="rcS contains telnetd -l /bin/sh",
        impact_statement="Potential unauthenticated management plane",
        source_ref="/etc_ro/rcS",
        snippet="telnetd -l /bin/sh",
    )

    findings = store.list_findings(run.run_id)
    evidence = store.list_evidence_for_finding(findings[0]["finding_id"])
    assert findings[0]["state"] == "suspect"
    assert evidence[0]["source_ref"] == "/etc_ro/rcS"
