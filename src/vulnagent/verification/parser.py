"""L2: Output parser — structured PoC enforcement.

From article: "输出解析器：无结构化 PoC → 拒绝"
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class StructuredPoC:
    executable_command: str = ""
    expected_output: str = ""
    actual_output: str = ""
    impact_statement: str = ""
    raw_text: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "executable_command": self.executable_command,
            "expected_output": self.expected_output,
            "actual_output": self.actual_output,
            "impact_statement": self.impact_statement,
        }


class PocParser:
    """Parse and validate structured PoC from finding text.

    From article: "报告必须有 curl 或可执行命令"
    """

    def parse(self, text: str) -> StructuredPoC | None:
        if not text:
            return None

        # Strategy 1: XML tagged format
        cmd = self._extract_tag(text, "executable_command")
        if not cmd:
            cmd = self._extract_tag(text, "poc_command")
        expected = self._extract_tag(text, "expected_output") or self._extract_tag(text, "expected")
        actual = self._extract_tag(text, "actual_output") or self._extract_tag(text, "actual")
        impact = self._extract_tag(text, "impact_statement") or self._extract_tag(text, "impact")

        # Strategy 2: Fallback — find first shell command
        if not cmd:
            cmd = self._extract_first_command(text)

        if not cmd:
            return None

        return StructuredPoC(
            executable_command=cmd.strip(),
            expected_output=(expected or "").strip(),
            actual_output=(actual or "").strip(),
            impact_statement=(impact or "").strip(),
            raw_text=text,
        )

    @staticmethod
    def _extract_tag(text: str, tag: str) -> str:
        m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else ""

    @staticmethod
    def _extract_first_command(text: str) -> str:
        patterns = [
            r"(curl\s+[^\n]{10,})",
            r"(wget\s+[^\n]{10,})",
            r"(python3?\s+[^\n]{10,})",
            r"(qemu-\w+\s+[^\n]{10,})",
            r"```(?:bash|sh|python)?\s*\n(.+?)\n```",
            r"`([^`]{20,})`",
            r"(echo\s+[^\n]{10,}\|[^\n]+)",
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.MULTILINE | re.DOTALL)
            if m:
                return m.group(1).strip()
        return ""
