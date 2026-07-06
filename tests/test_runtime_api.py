import sys
import types
from pathlib import Path

from fastapi.testclient import TestClient

from vulnagent.runtime.store import RuntimeStore


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnagent.server.app import create_app
from vulnagent.server.app import start_server


def test_assets_runs_and_findings_endpoints(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    store.upsert_finding(
        finding_id="finding-1",
        run_id=run.run_id,
        title="BusyBox telnetd exposed in init scripts",
        category="service-exposure",
        severity="medium",
        state="suspect",
        why_suspicious="rcS contains telnetd -l /bin/sh",
        impact_statement="Potential unauthenticated management plane",
        current_hypothesis="",
        next_best_action="Validate the service runtime.",
        confidence=0.4,
    )
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    assets = client.get("/api/assets").json()["data"]
    runs = client.get(f"/api/assets/{assets[0]['asset_id']}/runs").json()["data"]
    findings = client.get(f"/api/runs/{run.run_id}/findings").json()["data"]

    assert runs[0]["run_id"] == run.run_id
    assert findings[0]["title"].startswith("BusyBox telnetd")


def test_intervention_endpoint_persists_instruction(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    response = client.post(
        "/api/interventions",
        json={
            "run_id": run.run_id,
            "scope_type": "run",
            "scope_id": run.run_id,
            "instruction": "Prioritize telnetd verification before broad rescans.",
        },
    ).json()

    assert response["status"] == "ok"
    assert response["data"]["status"] == "received"


def test_vuln_run_endpoint_starts_background_analysis(monkeypatch, tmp_path) -> None:
    class FakeThread:
        def __init__(self, *, target, daemon):
            self._target = target
            self.daemon = daemon

        def start(self) -> None:
            self._target()

    class FakeOrchestrator:
        def __init__(self, store) -> None:
            self.runtime_store = store
            self.event_emitter = None
            self.calls = []

        def run(self, *, target, scope, max_iterations, token_limit):
            self.calls.append(
                {
                    "target": target,
                    "scope": scope,
                    "max_iterations": max_iterations,
                    "token_limit": token_limit,
                }
            )
            return {
                "success": True,
                "target": target,
                "scope": scope,
                "run_id": "demo-run",
                "report": "ok",
            }

    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    orch = FakeOrchestrator(store)
    app = create_app(orch)
    client = TestClient(app)

    import vulnagent.server.vuln_routes as vuln_routes_module

    monkeypatch.setattr(vuln_routes_module.threading, "Thread", FakeThread)

    response = client.post(
        "/api/vuln/run",
        json={
            "target": "https://example.test",
            "scope": "authorized test",
            "max_iterations": 2,
            "token_limit": 999,
        },
    ).json()
    state = client.get("/api/vuln/run-state").json()["data"]

    assert response["status"] == "ok"
    assert orch.calls[0]["target"] == "https://example.test"
    assert orch.calls[0]["scope"] == "authorized test"
    assert orch.calls[0]["max_iterations"] == 2
    assert orch.calls[0]["token_limit"] == 999
    assert state["running"] is False
    assert state["last_result"]["run_id"] == "demo-run"


def test_vuln_run_endpoint_requires_orchestrator(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    response = client.post("/api/vuln/run", json={"target": "https://example.test"})

    assert response.status_code == 503


def test_vuln_run_state_exposes_active_run_id(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    run_row = store.get_run(run.run_id)
    app = create_app()
    app.state.vuln_runtime_store = store
    app.state.vuln_run_state = {
        "running": True,
        "target": "firmware/DIR816_A1_FW101CNB04.img",
        "scope": "api-test",
        "started_at": float((run_row or {}).get("started_at", 0) or 0),
        "last_result": None,
        "last_error": "",
    }
    client = TestClient(app)

    state = client.get("/api/vuln/run-state").json()["data"]

    assert state["run_id"] == run.run_id


def test_intervention_history_endpoint_and_timeline_event(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    response = client.post(
        "/api/interventions",
        json={
            "run_id": run.run_id,
            "scope_type": "agent",
            "scope_id": f"{run.run_id}:DiscoveryAgent",
            "instruction": "Focus on the telnetd path before starting another broad scan.",
        },
    ).json()
    intervention_id = response["data"]["intervention_id"]

    interventions = client.get(f"/api/runs/{run.run_id}/interventions").json()["data"]
    timeline = client.get(f"/api/runs/{run.run_id}/timeline").json()["data"]

    assert interventions[0]["intervention_id"] == intervention_id
    assert interventions[0]["instruction"].startswith("Focus on the telnetd path")
    assert timeline[-1]["type"] == "intervention.received"
    assert timeline[-1]["data"]["intervention_id"] == intervention_id


def test_finding_detail_and_evidence_endpoints(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    store.upsert_finding(
        finding_id="finding-1",
        run_id=run.run_id,
        title="BusyBox telnetd exposed in init scripts",
        category="service-exposure",
        severity="medium",
        state="suspect",
        why_suspicious="rcS contains telnetd -l /bin/sh",
        impact_statement="Potential unauthenticated management plane",
        current_hypothesis="Telnet service may be reachable after boot.",
        next_best_action="Validate emulated telnet reachability.",
        confidence=0.4,
    )
    store.add_evidence(
        evidence_id="evidence-1",
        run_id=run.run_id,
        finding_id="finding-1",
        kind="file_hit",
        title="telnetd marker",
        source_type="artifact_path",
        source_ref="/etc_ro/rcS",
        collector="DiscoveryAgent",
        snippet="telnetd -l /bin/sh",
        artifact_path="/etc_ro/rcS",
    )
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    detail = client.get("/api/findings/finding-1").json()["data"]
    evidence = client.get("/api/findings/finding-1/evidence").json()["data"]

    assert detail["finding_id"] == "finding-1"
    assert detail["current_hypothesis"].startswith("Telnet service")
    assert evidence[0]["source_ref"] == "/etc_ro/rcS"


def test_run_agents_and_timeline_endpoints(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    store.upsert_agent(
        run_id=run.run_id,
        agent_name="DiscoveryAgent",
        current_target="/etc_ro/rcS",
        status="running",
        current_hypothesis="telnet bootstrap path",
        current_blocker="",
        next_step="Read follow-up paths.",
    )
    store.append_event(
        run.run_id,
        {
            "type": "node.enter",
            "agent_name": "DiscoveryAgent",
            "message": "execute_tools",
            "data": {"node": "execute_tools"},
        },
    )
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    agents = client.get(f"/api/runs/{run.run_id}/agents").json()["data"]
    timeline = client.get(f"/api/runs/{run.run_id}/timeline").json()["data"]

    assert agents[0]["agent_name"] == "DiscoveryAgent"
    assert timeline[0]["type"] == "node.enter"


def test_run_timeline_supports_finding_and_artifact_filters(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    store.append_event(
        run.run_id,
        {
            "type": "tool.result",
            "agent_name": "DiscoveryAgent",
            "message": "rcS hit for finding-1",
            "data": {
                "finding_id": "finding-1",
                "artifact_path": "/etc_ro/rcS",
                "tool_name": "firmware_read_path",
            },
        },
    )
    store.append_event(
        run.run_id,
        {
            "type": "tool.result",
            "agent_name": "ExploitAgent",
            "message": "unrelated artifact",
            "data": {
                "finding_id": "finding-2",
                "artifact_path": "/etc/passwd",
                "tool_name": "firmware_read_path",
            },
        },
    )
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    by_finding = client.get(f"/api/runs/{run.run_id}/timeline?finding_id=finding-1").json()["data"]
    by_artifact = client.get(
        f"/api/runs/{run.run_id}/timeline?artifact_path=%2Fetc_ro%2FrcS"
    ).json()["data"]

    assert len(by_finding) == 1
    assert by_finding[0]["data"]["finding_id"] == "finding-1"
    assert len(by_artifact) == 1
    assert by_artifact[0]["data"]["artifact_path"] == "/etc_ro/rcS"


def test_run_file_tree_and_content_endpoints(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    notes_path = run.run_root / "artifacts" / "notes.txt"
    notes_path.write_text("telnetd marker", encoding="utf-8")
    image_path = run.run_root / "artifacts" / "preview.png"
    image_path.write_bytes(bytes.fromhex("89504E470D0A1A0A"))
    binary_path = run.run_root / "artifacts" / "blob.bin"
    binary_path.write_bytes(bytes.fromhex("00010203"))

    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    tree_payload = client.get(f"/api/runs/{run.run_id}/file-tree").json()
    content_payload = client.get(
        f"/api/runs/{run.run_id}/files/content",
        params={"path": "artifacts/notes.txt"},
    ).json()
    image_payload = client.get(
        f"/api/runs/{run.run_id}/files/content",
        params={"path": "artifacts/preview.png"},
    ).json()
    binary_payload = client.get(
        f"/api/runs/{run.run_id}/files/content",
        params={"path": "artifacts/blob.bin"},
    ).json()

    assert tree_payload["status"] == "ok"
    assert tree_payload["run_id"] == run.run_id
    artifacts_node = next(child for child in tree_payload["tree"]["children"] if child["relative_path"] == "artifacts")
    assert any(child["relative_path"] == "artifacts/notes.txt" for child in artifacts_node["children"])
    assert content_payload["data"]["kind"] == "text"
    assert content_payload["data"]["content"] == "telnetd marker"
    assert image_payload["data"]["kind"] == "image"
    assert image_payload["data"]["preview_url"].endswith("path=artifacts%2Fpreview.png")
    assert binary_payload["data"]["kind"] == "binary"
    assert "暂不支持预览" in binary_payload["data"]["message"]


def test_run_raw_file_endpoint_serves_bytes(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    image_path = run.run_root / "artifacts" / "preview.png"
    image_bytes = bytes.fromhex("89504E470D0A1A0A") + b"raw"
    image_path.write_bytes(image_bytes)
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    response = client.get(f"/api/runs/{run.run_id}/files/raw", params={"path": "artifacts/preview.png"})

    assert response.status_code == 200
    assert response.content == image_bytes
    assert response.headers["content-type"].startswith("image/png")


def test_run_file_endpoints_reject_path_traversal(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="api-test",
    )
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    content_response = client.get(f"/api/runs/{run.run_id}/files/content", params={"path": "../secret.txt"})
    raw_response = client.get(f"/api/runs/{run.run_id}/files/raw", params={"path": "../secret.txt"})

    assert content_response.status_code == 400
    assert raw_response.status_code == 400


def test_frontend_shell_mentions_findings_and_supervision(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    response = client.get("/")
    html = response.text

    assert "漏洞 / 可疑点" in html
    assert "监督 / 审计" in html
    assert "相关证据" in html
    assert "运行态" in html


def test_start_server_does_not_depend_on_common_events(monkeypatch) -> None:
    class FakeEmitter:
        event_count = 0

        def on(self, *_args, **_kwargs) -> None:
            return None

    class FakeOrchestrator:
        event_emitter = FakeEmitter()

    uvicorn_calls = {}

    def fake_run(app, host, port, log_level) -> None:
        uvicorn_calls["host"] = host
        uvicorn_calls["port"] = port
        uvicorn_calls["log_level"] = log_level

    fake_uvicorn = types.SimpleNamespace(run=fake_run)
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)

    start_server(FakeOrchestrator(), host="127.0.0.1", port=8091, open_browser=False)

    assert uvicorn_calls["host"] == "127.0.0.1"
    assert uvicorn_calls["port"] == 8091
