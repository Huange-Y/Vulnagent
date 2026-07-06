"""Structured read APIs for vulnagent runtime data."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from urllib.parse import quote
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse


router = APIRouter()


def _get_store(request: Request) -> Any:
    store = getattr(request.app.state, "vuln_runtime_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="vulnagent runtime store is unavailable")
    return store


def _get_orchestrator(request: Request) -> Any:
    orch = getattr(request.app.state, "vuln_orchestrator", None)
    if orch is None:
        raise HTTPException(status_code=503, detail="vulnagent orchestrator is unavailable")
    return orch


def _get_run_state(request: Request) -> dict[str, Any]:
    state = getattr(request.app.state, "vuln_run_state", None)
    if state is None:
        state = {
            "running": False,
            "target": "",
            "scope": "",
            "started_at": 0.0,
            "last_result": None,
            "last_error": "",
            "run_id": "",
        }
        request.app.state.vuln_run_state = state
    return state


def _get_run_lock(request: Request) -> Any:
    lock = getattr(request.app.state, "vuln_run_lock", None)
    if lock is None:
        lock = threading.Lock()
        request.app.state.vuln_run_lock = lock
    return lock


def _normalize_target(value: Any) -> str:
    return str(value or "").strip().replace("/", "\\").lower()


def _resolve_run_state_run_id(request: Request, state: dict[str, Any]) -> str:
    last_result = state.get("last_result")
    if isinstance(last_result, dict):
        run_id = str(last_result.get("run_id", "")).strip()
        if run_id:
            return run_id

    if not state.get("running"):
        return ""

    store = getattr(request.app.state, "vuln_runtime_store", None)
    if store is None:
        return ""

    target = _normalize_target(state.get("target", ""))
    started_at = float(state.get("started_at") or 0)
    if not target:
        return ""

    candidates: list[dict[str, Any]] = []
    for asset in store.list_assets():
        asset_id = str(asset.get("asset_id", "")).strip()
        if not asset_id:
            continue
        asset_target = _normalize_target(asset.get("source_path", ""))
        for run in store.list_runs_for_asset(asset_id):
            entry_target = _normalize_target(run.get("entry_target", ""))
            if target not in {asset_target, entry_target}:
                continue
            run_started = float(run.get("started_at") or 0)
            status = str(run.get("status", "")).strip().lower()
            if status == "running" or run_started >= started_at - 1:
                candidates.append(run)

    if not candidates:
        return ""

    candidates.sort(key=lambda item: float(item.get("started_at") or 0), reverse=True)
    return str(candidates[0].get("run_id", "")).strip()


def _get_safe_run_path(store: Any, run_id: str, relative_path: str) -> Path:
    try:
        return store.resolve_run_relative_path(run_id, relative_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/assets")
async def api_assets(request: Request) -> dict[str, Any]:
    return {"status": "ok", "data": _get_store(request).list_assets()}


@router.get("/api/assets/{asset_id}/runs")
async def api_asset_runs(asset_id: str, request: Request) -> dict[str, Any]:
    return {"status": "ok", "data": _get_store(request).list_runs_for_asset(asset_id)}


@router.get("/api/runs/{run_id}")
async def api_run_detail(run_id: str, request: Request) -> dict[str, Any]:
    return {"status": "ok", "data": _get_store(request).get_run(run_id)}


@router.get("/api/vuln/run-state")
async def api_vuln_run_state(request: Request) -> dict[str, Any]:
    state = dict(_get_run_state(request))
    state["run_id"] = _resolve_run_state_run_id(request, state)
    return {"status": "ok", "data": state}


@router.post("/api/vuln/run")
async def api_vuln_run(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    orch = _get_orchestrator(request)
    target = str(payload.get("target", "")).strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")

    scope = str(payload.get("scope", "")).strip()
    max_iterations = int(payload.get("max_iterations") or 5)
    token_limit = int(payload.get("token_limit") or 100000)
    lock = _get_run_lock(request)
    state = _get_run_state(request)

    with lock:
        if state.get("running"):
            raise HTTPException(status_code=409, detail="a vulnagent analysis is already running")
        started_at = time.time()
        state.update(
            {
                "running": True,
                "target": target,
                "scope": scope,
                "started_at": started_at,
                "last_error": "",
                "run_id": "",
            }
        )

    def _execute() -> None:
        result: dict[str, Any] | None = None
        error_message = ""
        try:
            result = orch.run(
                target=target,
                scope=scope,
                max_iterations=max_iterations,
                token_limit=token_limit,
            )
        except Exception as exc:  # pragma: no cover - defensive runtime bridge
            error_message = str(exc)
            result = {
                "success": False,
                "target": target,
                "scope": scope,
                "report": "",
                "error": error_message,
                "run_id": "",
            }
        finally:
            with lock:
                state.update(
                    {
                        "running": False,
                        "last_result": result,
                        "last_error": error_message,
                        "run_id": str((result or {}).get("run_id", "")).strip(),
                    }
                )

    thread = threading.Thread(target=_execute, daemon=True)
    thread.start()

    return {
        "status": "ok",
        "data": {
            "running": True,
            "target": target,
            "scope": scope,
            "started_at": started_at,
            "run_id": "",
        },
    }


@router.get("/api/runs/{run_id}/findings")
async def api_run_findings(run_id: str, request: Request) -> dict[str, Any]:
    return {"status": "ok", "data": _get_store(request).list_findings(run_id)}


@router.get("/api/runs/{run_id}/agents")
async def api_run_agents(run_id: str, request: Request) -> dict[str, Any]:
    return {"status": "ok", "data": _get_store(request).list_run_agents(run_id)}


@router.get("/api/runs/{run_id}/timeline")
async def api_run_timeline(
    run_id: str,
    request: Request,
    limit: int = 50,
    finding_id: str = "",
    artifact_path: str = "",
    phase: str = "",
    agent_name: str = "",
    event_type: str = "",
    intervention_id: str = "",
) -> dict[str, Any]:
    return {
        "status": "ok",
        "data": _get_store(request).list_run_timeline(
            run_id,
            limit=limit,
            finding_id=finding_id,
            artifact_path=artifact_path,
            phase=phase,
            agent_name=agent_name,
            event_type=event_type,
            intervention_id=intervention_id,
        ),
    }


@router.get("/api/runs/{run_id}/file-tree")
async def api_run_file_tree(run_id: str, request: Request) -> dict[str, Any]:
    store = _get_store(request)
    try:
        tree = store.build_run_file_tree(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "ok", "run_id": run_id, "tree": tree}


@router.get("/api/runs/{run_id}/files/content")
async def api_run_file_content(run_id: str, request: Request, path: str) -> dict[str, Any]:
    store = _get_store(request)
    try:
        data = store.get_run_file_content(run_id, path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if data.get("kind") == "image":
        data = {
            **data,
            "preview_url": f"/api/runs/{run_id}/files/raw?path={quote(Path(path).as_posix(), safe='')}",
        }
    return {"status": "ok", "run_id": run_id, "data": data}


@router.get("/api/runs/{run_id}/files/raw")
async def api_run_file_raw(run_id: str, request: Request, path: str) -> FileResponse:
    store = _get_store(request)
    resolved = _get_safe_run_path(store, run_id, path)
    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(status_code=404, detail=path)
    return FileResponse(resolved)


@router.get("/api/runs/{run_id}/interventions")
async def api_run_interventions(run_id: str, request: Request) -> dict[str, Any]:
    return {"status": "ok", "data": _get_store(request).list_run_interventions(run_id)}


@router.get("/api/findings/{finding_id}")
async def api_finding_detail(finding_id: str, request: Request) -> dict[str, Any]:
    return {"status": "ok", "data": _get_store(request).get_finding(finding_id)}


@router.get("/api/findings/{finding_id}/evidence")
async def api_finding_evidence(finding_id: str, request: Request) -> dict[str, Any]:
    return {"status": "ok", "data": _get_store(request).list_evidence_for_finding(finding_id)}


@router.post("/api/interventions")
async def api_interventions(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    store = _get_store(request)
    record = store.create_intervention(
        run_id=str(payload["run_id"]),
        scope_type=str(payload["scope_type"]),
        scope_id=str(payload["scope_id"]),
        instruction=str(payload["instruction"]),
    )
    scope_type = str(record.get("scope_type", ""))
    scope_id = str(record.get("scope_id", ""))
    agent_name = ""
    if scope_type == "agent" and ":" in scope_id:
        agent_name = scope_id.split(":", 1)[1]
    store.append_event(
        str(record["run_id"]),
        {
            "type": "intervention.received",
            "agent_name": agent_name,
            "message": str(record["instruction"])[:200],
            "data": {
                "intervention_id": str(record["intervention_id"]),
                "scope_type": scope_type,
                "scope_id": scope_id,
                "instruction": str(record["instruction"]),
                "status": str(record.get("status", "received")),
            },
        },
    )
    return {"status": "ok", "data": record}
