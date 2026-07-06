"""Custom exception hierarchy for the agent system."""

from __future__ import annotations


class AgentError(Exception):
    """Base exception for all agent-related errors."""
    pass


class ToolExecutionError(AgentError):
    """Raised when a security tool execution fails."""

    def __init__(self, tool_name: str, return_code: int, stderr: str) -> None:
        self.tool_name = tool_name
        self.return_code = return_code
        self.stderr = stderr
        super().__init__(
            f"Tool '{tool_name}' failed with code {return_code}: {stderr[:200]}"
        )


class TokenBudgetExceeded(AgentError):
    """Raised when the token budget for an agent run is exceeded."""

    def __init__(self, used: int, limit: int) -> None:
        self.used = used
        self.limit = limit
        super().__init__(
            f"Token budget exceeded: {used}/{limit} tokens used"
        )


class MemoryError(AgentError):
    """Raised when a memory operation fails."""

    def __init__(self, operation: str, detail: str = "") -> None:
        self.operation = operation
        self.detail = detail
        super().__init__(f"Memory operation '{operation}' failed: {detail}")


class ConfigurationError(AgentError):
    """Raised when required configuration is missing."""

    def __init__(self, missing_key: str) -> None:
        self.missing_key = missing_key
        super().__init__(f"Missing required configuration: {missing_key}")


class CompactionError(AgentError):
    """Raised when context compaction fails."""

    def __init__(self, level: str, detail: str = "") -> None:
        self.level = level
        self.detail = detail
        super().__init__(f"Compaction at level '{level}' failed: {detail}")
