from __future__ import annotations

import builtins

from common.utils.logging import StructuredLogger


def test_structured_logger_flushes_each_record(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_print(*args, **kwargs) -> None:
        calls.append({"args": args, "kwargs": kwargs})

    monkeypatch.setattr(builtins, "print", fake_print)

    StructuredLogger("TestComponent").info("hello")

    assert calls
    assert calls[0]["kwargs"].get("flush") is True
