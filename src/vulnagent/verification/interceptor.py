"""L3: Keyword interceptor — garbage list filter.

From article: "关键词拦截器：标题命中垃圾洞 → 拒绝"
"""

from __future__ import annotations


class KeywordInterceptor:
    """Intercept findings matching known garbage patterns (L3 hard gate)."""

    GARBAGE_PATTERNS: list[tuple[str, str]] = [
        ("CORS", "cors_configuration"),
        ("安全头", "security_header_missing"),
        ("security header", "security_header_missing"),
        ("版本号", "version_disclosure"),
        ("version disclosure", "version_disclosure"),
        ("banner", "banner_information"),
        ("self-xss", "self_xss"),
        ("Self-XSS", "self_xss"),
        ("sourcemap", "source_map_leak"),
        ("SSL", "ssl_tls_warning"),
        ("TLS", "ssl_tls_warning"),
        ("rate limit", "rate_limiting_missing"),
        ("开放重定向", "open_redirect_without_chain"),
        ("open redirect", "open_redirect_without_chain"),
        ("物理", "physical_access_required"),
        ("physical", "physical_access_required"),
        ("JTAG", "jtag_swd_exposure"),
        ("SWD", "jtag_swd_exposure"),
        ("UART", "uart_no_auth"),
    ]

    def __init__(self, extra_patterns: list[tuple[str, str]] | None = None) -> None:
        self._patterns = list(self.GARBAGE_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def check(self, title: str, description: str = "", evidence: str = "") -> str:
        """Check if finding matches any garbage pattern. Returns category or ''."""
        combined = f"{title} {description} {evidence}"
        for pattern, category in self._patterns:
            if pattern.lower() in combined.lower():
                return category
        return ""

    def add_pattern(self, pattern: str, category: str) -> None:
        self._patterns.append((pattern, category))
