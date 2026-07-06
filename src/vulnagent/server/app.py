"""FastAPI application for MYAGENTS WebUI."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .routes import router, set_orchestrator, update_last_state, add_checkpoint
from .vuln_routes import router as vuln_router
from .websocket_manager import manager

_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "frontend"


def create_app(orch: Any = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        orch: Optional CTFOrchestrator instance. Can be set later via set_orchestrator().
    """
    app = FastAPI(
        title="MYAGENTS WebUI",
        description="Multi-Agent CTF & Vulnerability Discovery System",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    app.include_router(vuln_router)
    app.state.vuln_runtime_store = getattr(orch, "runtime_store", None)
    app.state.vuln_orchestrator = orch
    app.state.vuln_run_lock = threading.Lock()
    app.state.vuln_run_state = {
        "running": False,
        "target": "",
        "scope": "",
        "started_at": 0.0,
        "last_result": None,
        "last_error": "",
        "run_id": "",
    }

    if orch:
        set_orchestrator(orch)

    # Bridge EventEmitter → WebSocket
    if orch and orch.event_emitter:
        orch.event_emitter.on("*", _make_ws_broadcaster())

    # Serve frontend
    if _FRONTEND_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR)), name="frontend-static")

        @app.get("/")
        async def serve_frontend() -> FileResponse:
            return FileResponse(str(_FRONTEND_DIR / "index.html"))

    return app


def _make_ws_broadcaster() -> Any:
    """Create a callback that bridges AgentEvent → WebSocket broadcast."""
    def broadcast(event: Any) -> None:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(manager.broadcast_event(event))
            else:
                loop.run_until_complete(manager.broadcast_event(event))
        except RuntimeError:
            pass  # no event loop available yet

    return broadcast


def start_server(
    orch: Any,
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = True,
) -> None:
    """Start the FastAPI server with uvicorn.

    Args:
        orch: CTFOrchestrator instance with EventEmitter
        host: Bind address
        port: Bind port
        open_browser: Whether to open the browser automatically
    """
    import threading
    import webbrowser

    app = create_app(orch)
    set_orchestrator(orch)

    # Bridge EventEmitter → WebSocket
    if orch.event_emitter:
        orch.event_emitter.on("*", _make_ws_broadcaster())

    # State tracking bridge — update REST state before and after each node
    if orch.event_emitter:
        def track_state(event: Any) -> None:
            event_type = getattr(getattr(event, "type", None), "value", getattr(event, "type", ""))
            if event_type == "node.enter":
                add_checkpoint({
                    "step": orch.event_emitter.event_count,
                    "node": event.data.get("node", ""),
                    "timestamp": event.timestamp,
                })
        orch.event_emitter.on("*", track_state)

    if open_browser:
        def _open():
            import time
            time.sleep(0.5)
            webbrowser.open(f"http://{host}:{port}")
        threading.Thread(target=_open, daemon=True).start()

    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
