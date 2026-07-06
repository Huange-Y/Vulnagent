"""REST API routes for agent state inspection and control."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .websocket_manager import manager

router = APIRouter()

# Global reference to orchestrator — set by app startup
_orchestrator: Any = None

# Run state tracking
_run_state: dict[str, Any] = {
    "running": False,
    "task": "",
    "result": None,
}

# Task history
import json as _json
from pathlib import Path as _Path
_HISTORY_FILE = _Path(__file__).resolve().parent.parent.parent.parent / ".myagents" / "task_history.json"
_task_history: list[dict[str, Any]] = []


def _load_history() -> list[dict[str, Any]]:
    global _task_history
    try:
        if _HISTORY_FILE.exists():
            _task_history = _json.loads(_HISTORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        _task_history = []
    return _task_history


def _save_history() -> None:
    try:
        _HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Keep last 50 entries
        if len(_task_history) > 50:
            _task_history[:] = _task_history[-50:]
        _HISTORY_FILE.write_text(_json.dumps(_task_history, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    except Exception:
        pass


_load_history()


def set_orchestrator(orch: Any) -> None:
    global _orchestrator
    _orchestrator = orch


def get_orchestrator() -> Any:
    return _orchestrator


# ── WebSocket ───────────────────────────────────────────────────

@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """WebSocket endpoint for real-time event streaming.

    Clients connect here to receive AgentEvent broadcasts during agent execution.
    Also accepts text messages for commands: /state, /tools, /memory <query>.
    """
    await manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            orch = get_orchestrator()
            if not orch:
                await ws.send_json({"error": "No orchestrator available"})
                continue

            cmd = data.strip()
            if cmd == "/state":
                await ws.send_json({"type": "state", "data": _get_state()})
            elif cmd == "/tools":
                await ws.send_json({"type": "tools", "data": _get_tools(orch)})
            elif cmd == "/kg":
                await ws.send_json({"type": "kg", "data": _get_kg(orch)})
            elif cmd.startswith("/memory"):
                query = cmd[8:] if len(cmd) > 7 else ""
                await ws.send_json({"type": "memory", "data": _get_memory(orch, query)})
            elif cmd == "/budget":
                await ws.send_json({"type": "budget", "data": _get_budget()})
            elif cmd == "/checkpoints":
                await ws.send_json({"type": "checkpoints", "data": _get_checkpoints()})
            elif cmd == "/models":
                await ws.send_json({"type": "models", "data": orch.get_model_config()})
            elif cmd == "/categories":
                from fastapi import Response
                cats = [
                    {"id": "auto", "name": "Auto Detect", "description": "Automatically classify the problem"},
                    {"id": "web", "name": "Web Exploitation", "description": "SQL injection, XSS, LFI, etc."},
                    {"id": "crypto", "name": "Cryptography", "description": "Ciphers, hashing, RSA, etc."},
                    {"id": "pwn", "name": "Binary Exploitation", "description": "Buffer overflow, ROP, etc."},
                    {"id": "rev", "name": "Reverse Engineering", "description": "Disassembly, decompilation"},
                    {"id": "vuln", "name": "Vulnerability Discovery", "description": "Firmware analysis, 0day hunting, PoC generation"},
                ]
                await ws.send_json({"type": "categories", "data": cats})
            elif cmd == "/history":
                await ws.send_json({"type": "history", "data": _task_history})
            elif cmd == "/result":
                await ws.send_json({
                    "type": "result",
                    "running": _run_state.get("running", False),
                    "result": _run_state.get("result"),
                })
            elif cmd.startswith("/run "):
                # Parse: /run {"task": "...", "category": "auto"}
                try:
                    import json
                    run_args = json.loads(cmd[5:])
                    await ws.send_json({"type": "info", "message": "Use POST /api/run to start tasks"})
                except Exception:
                    await ws.send_json({"type": "error", "message": "Invalid /run format"})
            elif cmd.startswith("/models "):
                # Parse: /models {"overrides": {"reasoning": {"provider":"x","model":"y"}}}
                try:
                    import json
                    model_args = json.loads(cmd[8:])
                    overrides = model_args.get("overrides", {})
                    if overrides and orch:
                        orch.apply_model_overrides(overrides)
                    await ws.send_json({"type": "models", "data": orch.get_model_config() if orch else {}})
                except Exception as e:
                    await ws.send_json({"type": "error", "message": f"Model update failed: {e}"})
            else:
                await ws.send_json({"type": "echo", "message": f"Unknown: {cmd}"})
    except WebSocketDisconnect:
        await manager.disconnect(ws)


# ── REST endpoints ──────────────────────────────────────────────

@router.get("/api/state")
async def api_state() -> dict[str, Any]:
    orch = get_orchestrator()
    if not orch:
        return {"error": "No orchestrator"}
    return {"status": "ok", "data": _get_state()}


@router.get("/api/tools")
async def api_tools(category: str = "") -> dict[str, Any]:
    orch = get_orchestrator()
    if not orch:
        return {"error": "No orchestrator"}
    return {"status": "ok", "data": _get_tools(orch, category)}


@router.get("/api/kg")
async def api_kg() -> dict[str, Any]:
    orch = get_orchestrator()
    if not orch:
        return {"error": "No orchestrator"}
    return {"status": "ok", "data": _get_kg(orch)}


@router.get("/api/memory")
async def api_memory(query: str = "") -> dict[str, Any]:
    orch = get_orchestrator()
    if not orch:
        return {"error": "No orchestrator"}
    return {"status": "ok", "data": _get_memory(orch, query)}


@router.get("/api/budget")
async def api_budget() -> dict[str, Any]:
    return {"status": "ok", "data": _get_budget()}


@router.post("/api/run")
async def api_run(request: dict[str, Any]) -> dict[str, Any]:
    """Submit a task for execution. Events stream via WebSocket.

    Body: {
        "task": "description or target URL",
        "category": "auto|web|crypto|pwn|rev",
        "max_iterations": 5,
        "token_limit": 100000,
        "model_overrides": {"reasoning": {"provider": "deepseek", "model": "deepseek-chat"}}
    }
    """
    orch = get_orchestrator()
    if not orch:
        return {"status": "error", "message": "No orchestrator available"}

    task = request.get("task", "").strip()
    if not task:
        return {"status": "error", "message": "Task is required"}

    category = request.get("category", "auto")
    max_iterations = request.get("max_iterations", 5)
    token_limit = request.get("token_limit", 100000)
    model_overrides = request.get("model_overrides", {})

    # Check if already running
    if _run_state.get("running"):
        return {"status": "error", "message": "A task is already running. Wait for it to complete."}

    _run_state["running"] = True
    _run_state["task"] = task
    _run_state["result"] = None

    import threading

    def _execute() -> None:
        try:
            # Apply model overrides if any
            if model_overrides and orch.router:
                orch.apply_model_overrides(model_overrides)

            result = orch.run(
                task=task,
                category=category,
                max_iterations=max_iterations,
                token_limit=token_limit,
                verbose=True,  # enables console_subscriber → emits events
            )
            _run_state["result"] = result
            _run_state["task"] = task

            # Save to history
            import time
            _task_history.append({
                "timestamp": time.time(),
                "task": task[:200],
                "category": category,
                "success": result.get("success", False),
                "flag": result.get("flag", ""),
                "iterations": result.get("iterations", 0),
                "tokens_used": result.get("tokens_used", 0),
                "tools_called": result.get("tools_called", []),
                "failure_analysis": result.get("failure_analysis"),
            })
            _save_history()
        except Exception as e:
            _run_state["result"] = {
                "success": False,
                "flag": None,
                "category": category,
                "iterations": 0,
                "tokens_used": 0,
                "tools_called": [],
                "failure_analysis": {"error": str(e)},
            }
        finally:
            _run_state["running"] = False

    thread = threading.Thread(target=_execute, daemon=True)
    thread.start()

    return {
        "status": "ok",
        "message": f"Task started: {task[:100]}",
        "category": category,
    }


@router.get("/api/models")
async def api_models() -> dict[str, Any]:
    """Get current model configuration."""
    orch = get_orchestrator()
    if not orch:
        return {"status": "error", "message": "No orchestrator"}
    if hasattr(orch, "get_model_config"):
        config = orch.get_model_config()
    elif hasattr(orch, "router") and orch.router:
        config = {"providers": [], "purposes": {}, "ready": False}
    else:
        config = {"providers": [], "purposes": {}, "ready": False}
    return {"status": "ok", "data": config}


@router.post("/api/models")
async def api_update_models(request: dict[str, Any]) -> dict[str, Any]:
    """Update model routing at runtime.

    Body: {
        "overrides": {
            "reasoning": {"provider": "deepseek", "model": "deepseek-chat"},
            "routing": {"provider": "deepseek", "model": "deepseek-chat"}
        }
    }
    """
    orch = get_orchestrator()
    if not orch:
        return {"status": "error", "message": "No orchestrator"}

    overrides = request.get("overrides", {})
    if overrides and hasattr(orch, "apply_model_overrides"):
        orch.apply_model_overrides(overrides)

    if hasattr(orch, "get_model_config"):
        config = orch.get_model_config()
    else:
        config = {"providers": [], "purposes": {}, "ready": False}
    return {"status": "ok", "message": "Models updated" if overrides else "No changes", "data": config}


@router.get("/api/categories")
async def api_categories() -> dict[str, Any]:
    """List available agent categories with recommendations."""
    return {
        "status": "ok",
        "categories": [
            {"id": "auto", "name": "Auto Detect", "description": "Automatically classify the problem", "recommended_model": "routing"},
            {"id": "web", "name": "Web Exploitation", "description": "SQL injection, XSS, LFI, etc.", "recommended_model": "reasoning"},
            {"id": "crypto", "name": "Cryptography", "description": "Ciphers, hashing, RSA, etc.", "recommended_model": "reasoning"},
            {"id": "pwn", "name": "Binary Exploitation", "description": "Buffer overflow, ROP, etc.", "recommended_model": "reasoning"},
            {"id": "rev", "name": "Reverse Engineering", "description": "Disassembly, decompilation", "recommended_model": "reasoning"},
            {"id": "vuln", "name": "Vulnerability Discovery", "description": "Firmware analysis, 0day hunting, PoC generation", "recommended_model": "reasoning"},
        ],
    }


@router.get("/api/result")
async def api_result() -> dict[str, Any]:
    """Get the result of the last task execution."""
    result = _run_state.get("result")
    return {
        "status": "ok",
        "running": _run_state.get("running", False),
        "task": _run_state.get("task", ""),
        "result": result,
    }


@router.get("/api/history")
async def api_history() -> dict[str, Any]:
    """Get task execution history."""
    return {"status": "ok", "data": _task_history}


@router.get("/api/health")
async def api_health() -> dict[str, Any]:
    return {"status": "ok", "connections": manager.active_count}


# ── Internal helpers ────────────────────────────────────────────

_last_state: dict[str, Any] = {}
_last_checkpoints: list[dict[str, Any]] = []


def update_last_state(state: dict[str, Any]) -> None:
    global _last_state
    _last_state = dict(state)


def add_checkpoint(info: dict[str, Any]) -> None:
    _last_checkpoints.append(info)


def _get_state() -> dict[str, Any]:
    return dict(_last_state)


def _get_tools(orch: Any, category: str = "") -> list[dict[str, Any]]:
    tools = orch.tool_registry.list_all()
    if category:
        if category == "dangerous":
            tools = [t for t in tools if t.risk_level == "dangerous"]
        else:
            tools = [t for t in tools if t.category == category]
    return [
        {
            "name": t.name,
            "description": t.description,
            "category": t.category,
            "risk_level": t.risk_level,
            "requires_network": t.requires_network,
        }
        for t in sorted(tools, key=lambda x: (x.risk_level, x.name))
    ]


def _get_kg(orch: Any) -> dict[str, Any]:
    if orch.kg:
        return orch.kg.stats
    return {"entities": 0, "relations": 0}


def _get_memory(orch: Any, query: str = "") -> list[dict[str, Any]]:
    query = query or "security"
    entries = orch.memory.retrieve(query, top_k=10)
    return [
        {
            "id": e.id,
            "content": e.content[:500],
            "layer": e.layer,
            "tags": e.tags,
            "salience": e.emotional_salience,
            "timestamp": e.timestamp,
        }
        for e in entries
    ]


def _get_budget() -> dict[str, Any]:
    return dict(_last_state.get("token_budget", {}))


def _get_checkpoints() -> list[dict[str, Any]]:
    return _last_checkpoints[-20:]
