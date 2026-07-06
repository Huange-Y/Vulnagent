from pathlib import Path

from vulnagent.runtime.store import RuntimeStore


def test_runtime_store_bootstraps_sqlite_and_run_dirs(tmp_path: Path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")

    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="local-test",
    )

    assert store.db_path.exists()
    assert run.run_root.exists()
    assert (run.run_root / "events.jsonl").exists()
    assert (run.run_root / "artifacts").exists()
    assert (run.run_root / "reports").exists()


def test_runtime_store_lists_assets_runs_and_findings(tmp_path: Path) -> None:
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent")
    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="local-test",
    )

    store.upsert_finding(
        run_id=run.run_id,
        finding_id="finding-1",
        title="BusyBox telnetd exposed in init scripts",
        category="service-exposure",
        severity="medium",
        state="suspect",
        why_suspicious="rcS enables telnetd when nvram flag is set",
        impact_statement="Possible unauthenticated management surface",
    )

    assets = store.list_assets()
    runs = store.list_runs_for_asset(assets[0]["asset_id"])
    findings = store.list_findings(run.run_id)

    assert len(assets) == 1
    assert len(runs) == 1
    assert findings[0]["state"] == "suspect"


def test_runtime_store_supports_external_runs_root(tmp_path: Path) -> None:
    runs_root = tmp_path / "external-runs" / "runs"
    store = RuntimeStore(root=tmp_path / "runtime" / "vulnagent", runs_root=runs_root)

    run = store.create_run(
        asset_name="DIR-816",
        asset_kind="firmware",
        source_path="firmware/DIR816_A1_FW101CNB04.img",
        entry_target="firmware/DIR816_A1_FW101CNB04.img",
        scope="local-test",
    )

    assert run.run_root == runs_root / run.run_id
    assert (run.run_root / "events.jsonl").exists()
    assert (run.run_root / "artifacts").exists()
