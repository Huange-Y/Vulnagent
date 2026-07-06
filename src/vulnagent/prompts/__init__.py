"""Vulnerability discovery agent prompt templates."""

from vulnagent.prompts.discovery_prompts import (
    DISCOVERY_AGENT_SYSTEM_PROMPT,
    DISCOVERY_AGENT_SYSTEM_PROMPT_FIRMWARE,
    KNOWN_BUGS_SECTION_TEMPLATE,
    build_known_bugs_section,
)
from vulnagent.prompts.exploit_prompts import EXPLOIT_AGENT_SYSTEM_PROMPT
from vulnagent.prompts.remediation_prompts import (
    REMEDIATION_TEMPLATES,
    cwe_for_finding,
    cvss_score_for_finding,
    format_remediation_for_prompt,
    match_remediation_template,
    remediation_context_for_findings,
)
from vulnagent.prompts.report_prompts import REPORT_AGENT_SYSTEM_PROMPT
from vulnagent.prompts.untrusted import make_nonce, sanitize_untrusted, untrusted_block
from vulnagent.prompts.verification_prompts import (
    BRAINSTORM_AGENT_SYSTEM_PROMPT,
    VERIFICATION_AGENT_SYSTEM_PROMPT,
)

__all__ = [
    "BRAINSTORM_AGENT_SYSTEM_PROMPT",
    "DISCOVERY_AGENT_SYSTEM_PROMPT",
    "DISCOVERY_AGENT_SYSTEM_PROMPT_FIRMWARE",
    "EXPLOIT_AGENT_SYSTEM_PROMPT",
    "KNOWN_BUGS_SECTION_TEMPLATE",
    "REMEDIATION_TEMPLATES",
    "REPORT_AGENT_SYSTEM_PROMPT",
    "VERIFICATION_AGENT_SYSTEM_PROMPT",
    "build_known_bugs_section",
    "cwe_for_finding",
    "cvss_score_for_finding",
    "format_remediation_for_prompt",
    "make_nonce",
    "match_remediation_template",
    "remediation_context_for_findings",
    "sanitize_untrusted",
    "untrusted_block",
]
