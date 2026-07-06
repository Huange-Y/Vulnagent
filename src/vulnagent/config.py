"""Vulnerability discovery agent default configuration."""

DEFAULT_VULN_CONFIG = {
    "max_iterations": 8,  # Vuln discovery can take longer
    "token_limit": 150000,
    "model": "gpt-4o",
    "temperature": 0.0,
    "tool_timeout": 300,
    "micro_compact_threshold": 0.6,
    "mid_compact_threshold": 0.8,
    "deep_compact_threshold": 0.95,
    "flashbulb_threshold": 0.6,
    "max_retries": 2,
    "scope_restriction": True,  # Enforce target scope
}
