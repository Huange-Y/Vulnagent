import sys
from pathlib import Path

from fastapi.testclient import TestClient

from vulnagent.runtime.store import RuntimeStore


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnagent.server.app import create_app


def test_frontend_shell_mentions_finding_detail_sections(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    html = client.get("/").text

    assert 'id="findingWhy"' in html
    assert 'id="findingHypothesis"' in html
    assert 'id="findingNextStep"' in html
    assert 'id="findingEvidence"' in html
    assert 'id="findingTimeline"' in html


def test_frontend_shell_mentions_intervention_and_related_timeline_sections(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    html = client.get("/").text

    assert 'id="interventionForm"' in html
    assert 'id="interventionList"' in html
    assert 'id="agentTimeline"' in html


def test_frontend_shell_mentions_file_tree_preview_and_related_timeline_sections(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    html = client.get("/").text

    assert "???" in html
    assert "????" in html
    assert "?????" in html
    assert 'id="fileTree"' in html
    assert 'id="artifactPreview"' in html
    assert 'id="artifactTimeline"' in html


def test_frontend_shell_mentions_launch_controls(tmp_path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    app = create_app()
    app.state.vuln_runtime_store = store
    client = TestClient(app)

    html = client.get("/").text

    assert 'id="launchForm"' in html
    assert 'id="launchTarget"' in html
    assert 'id="launchScope"' in html
    assert 'id="launchButton"' in html
    assert "URL" in html


def test_frontend_script_tracks_active_run_from_launch_state() -> None:
    script = (ROOT / "frontend" / "vulnapp.js").read_text(encoding="utf-8")

    assert "state.launchState.run_id" in script
    assert "state.selectedRunId = state.launchState.run_id" in script


def test_frontend_script_mentions_file_tree_and_related_timeline_apis() -> None:
    script = (ROOT / "frontend" / "vulnapp.js").read_text(encoding="utf-8")

    assert "/file-tree" in script
    assert "/files/content" in script
    assert "finding_id" in script
    assert "artifact_path" in script
