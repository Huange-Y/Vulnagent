"""Source-to-Sink data flow tracing for firmware vulnerability analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TraceNode:
    name: str
    node_type: str = ""
    location: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class TracePath:
    source: TraceNode | None = None
    sink: TraceNode | None = None
    nodes: list[TraceNode] = field(default_factory=list)
    risk_level: str = "unknown"
    description: str = ""


class SourceToSinkTracer:
    """Trace data flow from user input (source) to vulnerability trigger (sink)."""

    SOURCE_PATTERNS: dict[str, list[str]] = {
        "http_param": ["getenv(", "QUERY_STRING", "POST_DATA", "websGetVar("],
        "file_upload": ["upload", "websUpload", "multipart/form-data", "tempnam("],
        "network_input": ["recv(", "read(sock", "accept("],
        "firmware_update": ["upgrade", "flash_write", "mtd_write"],
        "nvram_input": ["nvram_get(", "config_get("],
    }

    SINK_PATTERNS: dict[str, list[str]] = {
        "command_execution": ["system(", "popen(", "execve(", "doSystem("],
        "buffer_overflow": ["strcpy(", "sprintf(", "strcat(", "gets(", "memcpy("],
        "format_string": ["printf(", "fprintf(", "syslog("],
        "file_write": ["fwrite(", "write(", "websWrite("],
        "nvram_write": ["nvram_set(", "nvram_commit("],
    }

    @classmethod
    def trace_from_tool_outputs(cls, tool_outputs: dict[str, str]) -> list[TracePath]:
        combined = "\n".join(str(v) for v in tool_outputs.values()).lower()
        sources = []
        for st, patterns in cls.SOURCE_PATTERNS.items():
            for p in patterns:
                if p.lower() in combined:
                    sources.append(TraceNode(name=p, node_type="source", metadata={"source_type": st}))
                    break
        sinks = []
        for st, patterns in cls.SINK_PATTERNS.items():
            for p in patterns:
                if p.lower() in combined:
                    sinks.append(TraceNode(name=p, node_type="sink", metadata={"sink_type": st}))
                    break
        paths = []
        for s in sources:
            for k in sinks:
                risk = cls._assess(s, k)
                paths.append(TracePath(source=s, sink=k, nodes=[s, k], risk_level=risk,
                                        description=f"{s.name} → {k.name}"))
        return paths

    @classmethod
    def _assess(cls, source: TraceNode, sink: TraceNode) -> str:
        st = sink.metadata.get("sink_type", "")
        if st in ("command_execution", "buffer_overflow"): return "critical"
        if st in ("format_string", "file_write"): return "high"
        if st == "nvram_write": return "medium"
        return "low"
