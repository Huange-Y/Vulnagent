from __future__ import annotations


class RuntimeSession:
    def __init__(self, *, store, projector, run_record) -> None:
        self.store = store
        self.projector = projector
        self.run_record = run_record

    def attach(self, emitter) -> None:
        emitter.on("*", self._handle_event)

    def _handle_event(self, event) -> None:
        self.projector.handle(event)
