"""Vulnerability discovery orchestrator."""

from __future__ import annotations

from pathlib import Path
import hashlib
import re
from typing import Any

from langchain_core.messages import HumanMessage

from vulnagent.context.budget import BudgetManager
from vulnagent.context.compressor import MicroCompressor, MidCompressor, DeepCompressor
from vulnagent.core.assessment import (
    collect_artifact_observations,
    collect_xml_tagged_findings,
    collect_xml_tagged_verdict,
    collect_report_grading,
    ensure_run_metadata,
    extract_latest_ai_text,
    is_actionable_validation_text,
    is_substantive_ai_text,
    make_finding,
    merge_report_text,
    normalize_ai_summary_text,
)
from vulnagent.core.state import AgentState, CompactionState, TokenBudgetState
from vulnagent.events.emitter import EventEmitter
from vulnagent.memory.hierarchical import HierarchicalMemory
from vulnagent.memory.kgraph import KnowledgeGraph
from vulnagent.runtime.context import bind_runtime_run_id
from vulnagent.runtime.projector import ProjectionProjector
from vulnagent.runtime.session import RuntimeSession
from vulnagent.runtime.store import RuntimeStore
from vulnagent.tools.registry import ToolRegistry
from vulnagent.utils.config import ConfigLoader
from vulnagent.utils.logging import StructuredLogger
from vulnagent.utils.settings import SettingsManager
from vulnagent.agents.discovery_agent import DiscoveryAgent
from vulnagent.agents.exploit_agent import ExploitAgent
from vulnagent.agents.report_agent import ReportAgent
from vulnagent.agents.verification_agent import BrainstormAgent, VerificationAgent
from vulnagent.constraints.engine import ConstraintEngine
from vulnagent.analysis.trace import SourceToSinkTracer
from vulnagent.analysis.cve_dedup import annotate_metadata as _dedup_annotate
from vulnagent.firmware.cve_report import build_cve_from_audit, export_package as _export_cve_package
from vulnagent.core.dedup import build_judge_prompt, parse_judge_response, apply_judge_verdicts
from vulnagent.core.risk import score_finding
from vulnagent.core.tiers import TierManager, Tier, TierResult, Confidence
from vulnagent.loop.manager import LoopManager
from vulnagent.tools.vuln_tools import register_all_vuln_tools, set_constraint_engine, set_sandbox
from vulnagent.verification.layers import VerificationPipeline
from vulnagent.verification.patch_grade import PatchGrader
from vulnagent.verification.replay import PoCReplayer
from vulnagent.sandbox.container import SandboxContainer
from vulnagent.analysis.exploitability import ExploitabilityAnalyzer
from vulnagent.knowledge.rag import KnowledgeRetriever
from vulnagent.firmware.peripheral import PeripheralEmulator
from vulnagent.constraints.updater import ConstraintUpdater
from vulnagent.emulation_agent.client import EmulationAgentClient, ServiceSpec
from vulnagent.emulation_agent.backend import (
    FirmwareValidationBackend, create_validation_backend,
    ServiceToVerify, VerificationResult, ValidationReport,
)

from vulnagent.paths import RUNTIME_ROOT, STATE_ROOT, ensure_runtime_dirs

_DEFAULT_MEMORY_PATH = str(STATE_ROOT / "memory.db")
_DEFAULT_KG_PATH = str(STATE_ROOT / "knowledge_graph.json")
_ARTIFACT_SUFFIXES = {
    ".apk",
    ".bin",
    ".bz2",
    ".cfg",
    ".cgi",
    ".conf",
    ".cpio",
    ".der",
    ".elf",
    ".fw",
    ".gz",
    ".hex",
    ".img",
    ".ini",
    ".iso",
    ".json",
    ".ko",
    ".log",
    ".lz4",
    ".pcap",
    ".pcapng",
    ".pem",
    ".rom",
    ".so",
    ".squashfs",
    ".tar",
    ".tgz",
    ".trx",
    ".txt",
    ".ubi",
    ".ubifs",
    ".xml",
    ".xz",
    ".zip",
    ".7z",
}
_PRIMARY_FIRMWARE_SUFFIXES = {
    ".apk",
    ".bin",
    ".cpio",
    ".fw",
    ".gz",
    ".hex",
    ".img",
    ".iso",
    ".ko",
    ".lz4",
    ".rom",
    ".so",
    ".squashfs",
    ".tar",
    ".tgz",
    ".trx",
    ".ubi",
    ".ubifs",
    ".xz",
    ".zip",
    ".7z",
}
_SECONDARY_ARTIFACT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".der",
    ".ini",
    ".json",
    ".log",
    ".pcap",
    ".pcapng",
    ".pem",
    ".txt",
    ".xml",
}
_STRINGS_PRETRIAGE_MAX_BYTES = 32 * 1024 * 1024


def _resolve_runtime_runs_root() -> Path:
    try:
        settings = SettingsManager().load()
        configured = str(settings.get("runtime.run_root", "") or "").strip()
        if configured:
            return Path(configured) / "runs"
    except Exception:
        pass
    return RUNTIME_ROOT / "runs"


def _init_sandbox(use_sandbox: bool, logger) -> Any:
    """Initialize the Docker sandbox container with graceful degradation.

    Returns SandboxContainer on success, None if Docker is unavailable
    or use_sandbox is False.
    """
    if not use_sandbox:
        logger.info("Sandbox disabled via use_sandbox=False")
        return None
    try:
        sandbox = SandboxContainer()
        sandbox.ensure_image()
        sandbox.create()
        sandbox.start()
        logger.info(f"Sandbox container started: {sandbox._container_id}")
        return sandbox
    except RuntimeError as exc:
        logger.warning(f"Sandbox unavailable (Docker not found): {exc}")
        return None
    except Exception as exc:
        logger.warning(f"Sandbox initialization failed: {exc}")
        return None


def _init_emu_agent(agent_url: str, logger) -> EmulationAgentClient | None:
    """Initialize the emulation agent client with graceful degradation.

    Returns EmulationAgentClient if the agent URL is configured and reachable,
    None otherwise. When None is returned, vulnagent falls back to static-only
    analysis without dynamic service verification.
    """
    if not agent_url:
        logger.info("Emulation agent URL not configured — static-only mode")
        return None
    try:
        client = EmulationAgentClient(base_url=agent_url)
        if client.is_reachable:
            logger.info(f"Emulation agent connected: {agent_url}")
            return client
        logger.warning(f"Emulation agent unreachable at {agent_url}")
        return None
    except Exception as exc:
        logger.warning(f"Emulation agent init failed: {exc}")
        return None


def _build_early_exit_result(state: dict, reason: str) -> dict:
    """Return a result dict when tier gating blocks execution early."""
    meta = state.get("metadata", {}) or {}
    return {
        "success": True,
        "target": str(meta.get("target", "")),
        "scope": str(meta.get("scope", "")),
        "report": "",
        "error": "",
        "early_exit": True,
        "gate_reason": reason,
        "findings": meta.get("candidate_findings", []),
        "iterations": 0,
        "tokens_used": state.get("token_budget", {}).get("used", 0),
    }


class VulnOrchestrator:
    """Runs discovery → exploit → report for an authorized vulnerability target."""

    def __init__(
        self,
        llm_or_router: Any,
        memory_path: str = "",
        kg_path: str = "",
        use_sandbox: bool = True,
        emulation_agent_url: str = "",
        emulation_config: dict[str, Any] | None = None,
    ) -> None:
        self.router = llm_or_router if hasattr(llm_or_router, "reason") else None
        self.llm = None if self.router else llm_or_router
        self.logger = StructuredLogger("VulnOrchestrator")
        ensure_runtime_dirs()
        self._memory_path = memory_path or _DEFAULT_MEMORY_PATH
        self._kg_path = kg_path or _DEFAULT_KG_PATH
        self.tool_registry = register_all_vuln_tools(ToolRegistry())

        if memory_path == ":memory:":
            self.memory = HierarchicalMemory(store_backend="sqlite", db_path=memory_path)
        elif Path(self._memory_path).exists():
            self.memory = HierarchicalMemory.load(self._memory_path)
        else:
            self.memory = HierarchicalMemory(store_backend="sqlite", db_path=self._memory_path)

        self.micro_compressor = MicroCompressor()
        self.mid_compressor = MidCompressor(self.router if self.router else llm_or_router)
        self.kg = KnowledgeGraph.load(self._kg_path) if Path(self._kg_path).exists() else KnowledgeGraph()
        self.event_emitter = EventEmitter()
        self.deep_compressor = DeepCompressor(
            llm_client=self.router if self.router else llm_or_router,
            kg=self.kg,
            memory=self.memory,
        )
        self.runtime_store = RuntimeStore(root=RUNTIME_ROOT, runs_root=_resolve_runtime_runs_root())
        self._agents: dict[str, Any] = {}
        self._runtime_session: RuntimeSession | None = None

        # ── Sandbox container (Docker isolation for QEMU + PoC replay) ──
        self._sandbox = _init_sandbox(use_sandbox, self.logger)
        set_sandbox(self._sandbox)

        # ── Validation backend (auto-select: emulation_agent / direct_hardware / static_only) ──
        self._validation_backend, self._validation_mode = create_validation_backend(
            emulation_config=emulation_config,
            direct_target="",  # resolved later in run() based on --target
        )
        self.logger.info(f"Validation backend: {self._validation_mode}")

        # ── Constraint engine (article: external enforcement) ──
        self.constraint_engine = ConstraintEngine()
        set_constraint_engine(self.constraint_engine)

        # ── Loop manager (article: Loop failure detection + injection scheduling) ──
        self.loop_manager = LoopManager(
            constraint_engine=self.constraint_engine,
            max_rounds=50,
            direction_timeout_seconds=1200.0,
        )

        # ── Verification pipeline (article: L1→L2→L3→L4 multi-layer) ──
        self.verification_pipeline = VerificationPipeline(
            replayer=PoCReplayer(sandbox=self._sandbox) if self._sandbox else PoCReplayer(),
        )

        # ── Tier manager (autoi-mcp: Tier 1→2→3 gating) ──
        self.tier_manager = TierManager()

        # ── Patch grader (DCRH: T0-T3 verification ladder) ──
        self.patch_grader = PatchGrader()

        # ── Analysis modules (optional, gracefully degrade) ──
        self.exploitability = ExploitabilityAnalyzer()
        self.peripheral_emu = PeripheralEmulator()
        self.constraint_updater = ConstraintUpdater()

        # ── Knowledge retriever (lazy-init on first use) ──
        self._knowledge: KnowledgeRetriever | None = None

    def run(
        self,
        target: str,
        scope: str = "",
        max_iterations: int = 5,
        token_limit: int = 100000,
    ) -> dict[str, Any]:
        resolved_target, resolution_error = _resolve_target(target)
        if resolution_error is not None:
            return {
                "success": False,
                "target": target,
                "scope": scope,
                "report": "",
                "error": resolution_error,
                "findings": [],
                "iterations": 0,
                "tokens_used": 0,
                "tools_called": [],
            }
        target = resolved_target

        missing_local_target = _missing_local_target(target)
        if missing_local_target is not None:
            return {
                "success": False,
                "target": target,
                "scope": scope,
                "report": "",
                "error": f"Target artifact not found: {missing_local_target}",
                "findings": [],
                "iterations": 0,
                "tokens_used": 0,
                "tools_called": [],
            }

        budget = TokenBudgetState(
            total=token_limit,
            used=0,
            micro_threshold=0.6,
            mid_threshold=0.8,
            deep_threshold=0.95,
        )
        compaction = CompactionState(
            compaction_count=0,
            last_compaction_at_tokens=0,
            micro_compact_threshold=0.6,
            mid_compact_threshold=0.8,
            deep_compact_threshold=0.95,
        )
        state: AgentState = {
            "task_description": f"Assess target: {target}",
            "attachment_paths": [],
            "tool_outputs": {},
            "compressed_outputs": {},
            "memory_blocks": {},
            "memory_context": {},
            "current_agent": "discovery",
            "iteration_count": 0,
            "token_budget": budget,
            "phase": "execution",
            "final_result": None,
            "compaction": compaction,
            "anchored_summary": {},
            "metadata": ensure_run_metadata(
                target=target,
                scope=scope,
                metadata={
                    "sub_agents_findings": [],
                    "allow_network_tools": True,
                },
            ),
            "messages": [],
        }
        run_record = self.runtime_store.create_run(
            asset_name=Path(target).name or target,
            asset_kind=_infer_asset_kind(target),
            source_path=target,
            entry_target=target,
            scope=scope,
        )
        self._runtime_session = RuntimeSession(
            store=self.runtime_store,
            projector=ProjectionProjector(store=self.runtime_store, run_id=run_record.run_id),
            run_record=run_record,
        )
        self._runtime_session.attach(self.event_emitter)
        state["metadata"]["run_id"] = run_record.run_id
        state["metadata"]["runtime_root"] = str(run_record.run_root)

        # ── Loop manager: start session ──
        self.loop_manager.start_session(initial_direction="firmware_analysis")

        with bind_runtime_run_id(run_record.run_id):
            state = self._seed_local_artifact_triage(state, target)

            # Inject architecture/RTOS knowledge into memory context
            manifest_arch = (state.get("metadata", {}) or {}).get("manifest_arch", "")
            if manifest_arch:
                try:
                    ctx = self._get_knowledge().context_for_architecture(manifest_arch)
                    mc = dict(state.get("memory_context", {}) or {})
                    mc["architecture_knowledge"] = ctx
                    state["memory_context"] = mc
                except Exception:
                    pass

            state = self._run_automatic_firmware_validation(state, target)

        # Reset per-run counters
        _reset_per_run_counters()

        # ── Tier 1 (Surface): record seed triage result ──
        seed_findings = (
            list(state.get("metadata", {}).get("candidate_findings", []))
            + list(state.get("metadata", {}).get("validated_leads", []))
        )
        seed_targets = list(state.get("metadata", {}).get("priority_targets", []))
        self.tier_manager.record_result(TierResult(
            tier=Tier.SURFACE, confidence=Confidence.LOW,
            findings_count=len(seed_findings),
            priority_targets_count=len(seed_targets),
            tokens_used=0, duration_s=0,
        ))

        # ── Auto-promote high-confidence seed findings ──
        _promote_high_confidence_seed_findings(state)

        # ── Tier gating: Surface → Static ──
        proceed_t2, gate_reason = self.tier_manager.should_proceed(Tier.SURFACE)
        if not proceed_t2:
            self.logger.info(f"Tier gate BLOCKED: {gate_reason} — skipping discovery/exploit/report")
            return _build_early_exit_result(state, gate_reason)

        # ── Phase 0: Brainstorm (Codex-style lightweight pre-scan) ──
        # Runs ONLY when the artifact shows firmware markers worth surveying.
        # Surveys surface, forms hypotheses, outputs structured attack plan.
        if _should_run_brainstorm(state):
            brainstorm_state_data = {**state, "current_agent": "brainstorm", "phase": "execution"}

            # Inject seed triage summary so agent doesn t re-do completed work
            seed_summary = _build_seed_triage_summary(state)
            if seed_summary:
                msgs = list(brainstorm_state_data.get("messages", []))
                msgs.insert(0, HumanMessage(content=seed_summary))
                brainstorm_state_data["messages"] = msgs  # type: ignore[typeddict-item]

            brainstorm_state = self._run_agent("brainstorm", brainstorm_state_data, 1, token_limit)
            # Merge brainstorm hypotheses into discovery metadata
            bm_meta = brainstorm_state.get("metadata", {}) or {}
            for key in ("candidate_findings", "priority_targets", "next_steps"):
                if bm_meta.get(key):
                    state["metadata"][key] = _merge_findings(
                        list(state["metadata"].get(key, [])),
                        list(bm_meta.get(key, [])),
                    )
            # Import brainstorm's tool evidence for discovery reuse
            for mapping_key in ("tool_outputs", "compressed_outputs"):
                bm_map = dict(brainstorm_state.get(mapping_key, {}) or {})
                existing = dict(state.get(mapping_key, {}) or {})
                existing.update(bm_map)
                state[mapping_key] = existing  # type: ignore[typeddict-item]
            state = {**state, "metadata": state["metadata"]}  # type: ignore[dict-item]

        discovery_state = self._run_agent("discovery", state, max_iterations, token_limit)

        # ── Tier 2 (Static): record discovery result ──
        disc_md = discovery_state.get("metadata", {}) or {}
        self.tier_manager.record_result(TierResult(
            tier=Tier.STATIC, confidence=Confidence.MEDIUM,
            findings_count=len(list(disc_md.get("candidate_findings", []))),
            priority_targets_count=len(list(disc_md.get("priority_targets", []))),
            tokens_used=discovery_state.get("token_budget", {}).get("used", 0),
            duration_s=0,
        ))

        # ── Annotate findings with tier confidence ──
        for findings_key in ("candidate_findings", "confirmed_findings", "validated_leads"):
            annotated = []
            for f in list(disc_md.get(findings_key, [])):
                if isinstance(f, dict):
                    annotated.append(self.tier_manager.annotate_finding(f, Tier.STATIC))
            disc_md[findings_key] = annotated

        exploit_state_data = {**discovery_state, "current_agent": "exploit", "phase": "execution"}
        exploit_state_data["messages"] = _clean_messages_for_new_agent(
            discovery_state.get("messages", []),
            discovery_state.get("metadata", {}),
        )
        exploit_state = self._run_agent("exploit", exploit_state_data, max_iterations, token_limit)

        # ── Tier 3 (Dynamic): record exploit result ──
        expl_md_tier = exploit_state.get("metadata", {}) or {}
        self.tier_manager.record_result(TierResult(
            tier=Tier.DYNAMIC, confidence=Confidence.HIGH,
            findings_count=len(list(expl_md_tier.get("confirmed_findings", [])))
                          + len(list(expl_md_tier.get("validated_leads", []))),
            priority_targets_count=len(list(expl_md_tier.get("priority_targets", []))),
            tokens_used=exploit_state.get("token_budget", {}).get("used", 0),
            duration_s=0,
        ))

        # ── Annotate exploit findings with dynamic tier confidence ──
        for findings_key in ("confirmed_findings", "validated_leads", "candidate_findings"):
            annotated = []
            for f in list(expl_md_tier.get(findings_key, [])):
                if isinstance(f, dict):
                    # Enrich with binary exploitability analysis
                    bin_path = f.get("component_path", "")
                    if bin_path and Path(bin_path).exists():
                        try:
                            exploit_report = self.exploitability.analyze(Path(bin_path))
                            f["_binary_defenses"] = exploit_report.defenses.as_dict()
                            f["_rop_count"] = exploit_report.rop_count
                            f["_is_exploitable"] = exploit_report.is_exploitable()
                        except Exception:
                            pass
                    annotated.append(self.tier_manager.annotate_finding(f, Tier.DYNAMIC))
            if annotated:
                expl_md_tier[findings_key] = annotated

        # ── Phase 2.5: Independent Verification (DCRH Grade phase) ──
        # Only runs when exploit/discovery produced findings to verify.
        # Adversarial re-check: fresh emulation, 5-criteria rubric.
        # Findings are GUILTY UNTIL PROVEN INNOCENT.
        exploit_md = exploit_state.get("metadata", {}) or {}
        has_findings_to_verify = (
            exploit_md.get("provenance", "").startswith("artifact:")
            and bool(
                list(exploit_md.get("confirmed_findings", []))
                or list(exploit_md.get("validated_leads", []))
            )
        )
        # Only verify when EXPLOIT (not seed) produced confirmations —
        # compare against pre-exploit baseline from discovery state.
        if has_findings_to_verify:
            discovery_md = discovery_state.get("metadata", {}) or {}
            disc_confirmed = len(list(discovery_md.get("confirmed_findings", [])))
            disc_validated = len(list(discovery_md.get("validated_leads", [])))
            expl_confirmed = len(list(exploit_md.get("confirmed_findings", [])))
            expl_validated = len(list(exploit_md.get("validated_leads", [])))
            if expl_confirmed <= disc_confirmed and expl_validated <= disc_validated:
                has_findings_to_verify = False
        if has_findings_to_verify:
            verify_state_data = {
                **exploit_state,
                "current_agent": "verification",
                "phase": "execution",
            }
            verify_state_data["messages"] = _clean_messages_for_new_agent(
                exploit_state.get("messages", []),
                exploit_state.get("metadata", {}),
            )
            verify_state = self._run_agent("verification", verify_state_data, 1, token_limit)
            merged_metadata = dict(exploit_md)
            vm = verify_state.get("metadata", {}) or {}
            for key in ("candidate_findings", "confirmed_findings", "validated_leads"):
                if vm.get(key):
                    merged_metadata[key] = _merge_findings(
                        list(merged_metadata.get(key, [])),
                        list(vm.get(key, [])),
                    )
            if vm.get("_verification_verdict"):
                merged_metadata["_verification_verdict"] = vm["_verification_verdict"]
        else:
            verify_state = exploit_state
            merged_metadata = dict(exploit_md)

        # ── Phase 2.6: Dedup Judge (DCRH Judge phase) ──
        # Cross-reference verified findings against already-known bugs.
        # Runs as a no-tools LLM call via build_judge_prompt.
        new_findings = (
            list(merged_metadata.get("confirmed_findings", []))
            + list(merged_metadata.get("validated_leads", []))
        )
        existing_known = _load_known_bugs_from_state(discovery_state)
        if new_findings and existing_known:
            judge_prompt = build_judge_prompt(new_findings, existing_known)
            if judge_prompt and self.router:
                try:
                    judge_response = self.router.reason(
                        messages=[{"role": "user", "content": judge_prompt}],
                        tools=None,
                    )
                    judge_content = getattr(judge_response, "content", "") or ""
                    verdicts = parse_judge_response(judge_content)
                    accepted, replaced, skipped = apply_judge_verdicts(
                        new_findings, verdicts,
                    )
                    merged_metadata["confirmed_findings"] = accepted + replaced
                    merged_metadata["_skipped_duplicates"] = skipped
                    if skipped:
                        merged_metadata["evidence_log"] = _merge_strings(
                            list(merged_metadata.get("evidence_log", [])),
                            [
                                f"dedup: skipped {len(skipped)} duplicate finding(s): "
                                + ", ".join(str(f.get("title", "")) for f in skipped)
                            ],
                        )
                except Exception:
                    pass  # Judge is advisory; don't block the pipeline on it

        # Generate PoCs and remediation BEFORE ReportAgent runs,
        # so metadata findings have cwe_id/cvss_score/poc_path set.
        # NOTE: merged_metadata already populated by verification + dedup above.
        # DEBUG: ensure discovery metadata findings flow through
        discovery_md = discovery_state.get("metadata", {}) or {}
        for key in ("candidate_findings", "confirmed_findings", "validated_leads"):
            if not merged_metadata.get(key) and discovery_md.get(key):
                merged_metadata[key] = discovery_md[key]
        _auto_generate_pocs_from_findings(merged_metadata)
        remediation_blocks = _build_remediation_blocks(merged_metadata)

        # ── CVE dedup + false-positive filter ──
        # Runs BEFORE CVE package and report to filter busybox/libc/system-tool
        # noise AND cross-reference against known vendor CVEs.
        try:
            _vendor = str(merged_metadata.get("vendor", "") or "")
            _product = str(merged_metadata.get("product", "")
                           or merged_metadata.get("target", "") or "")
            merged_metadata = _dedup_annotate(merged_metadata, vendor=_vendor, product=_product)
            _dr = merged_metadata.get("_dedup_report", {})
            self.logger.info(
                f"CVE dedup: {_dr.get('total', 0)} total, "
                f"{_dr.get('false_positives', 0)} false_positives, "
                f"{_dr.get('known_cve', 0)} known_cves, "
                f"{_dr.get('potential_0day', 0)} potential_0day"
            )
        except Exception:
            pass  # dedup is advisory — never block the pipeline

        # ── CVE submission package generation ──
        _auto_generate_cve_package(merged_metadata)

        # ── CVSS auto-scoring for all findings ──
        _auto_score_findings(merged_metadata)

        # ── Source-to-Sink tracing from tool outputs ──
        all_tool_outputs = {}
        for s in (discovery_state, exploit_state):
            all_tool_outputs.update(dict(s.get("tool_outputs", {}) or {}))
            all_tool_outputs.update(dict(s.get("compressed_outputs", {}) or {}))
        trace_paths = SourceToSinkTracer.trace_from_tool_outputs(all_tool_outputs)
        if trace_paths:
            merged_metadata["_trace_paths"] = [
                {"source": t.source.name if t.source else "",
                 "sink": t.sink.name if t.sink else "",
                 "risk": t.risk_level,
                 "path": t.description}
                for t in trace_paths[:16]
            ]
            merged_metadata["evidence_log"] = _merge_strings(
                list(merged_metadata.get("evidence_log", [])),
                [f"source_to_sink: {len(trace_paths)} trace paths found, "
                 f"critical={sum(1 for t in trace_paths if t.risk_level == 'critical')}"]
            )

        # ── Patch grading for high-severity confirmed findings ──
        _auto_grade_patches(self.patch_grader, merged_metadata)

        # ── Verification pipeline: L1→L2→L3→L4 ──
        # From article: run ALL findings through the 4-layer verification
        verified_confirmed: list[dict[str, Any]] = []
        for finding in list(merged_metadata.get("confirmed_findings", [])):
            if isinstance(finding, dict):
                vr = self.verification_pipeline.verify(finding, skip_replay=True)
                if vr.passed or vr.failed_at <= 1:
                    verified_confirmed.append(finding)
        merged_metadata["confirmed_findings"] = verified_confirmed
        # Also filter validated_leads
        verified_validated: list[dict[str, Any]] = []
        for finding in list(merged_metadata.get("validated_leads", [])):
            if isinstance(finding, dict):
                vr = self.verification_pipeline.verify(finding, skip_replay=True)
                if vr.passed or vr.failed_at <= 1:
                    verified_validated.append(finding)
        merged_metadata["validated_leads"] = verified_validated

        report_state = self._run_agent("report", {
            **exploit_state,
            "current_agent": "report",
            "phase": "reporting",
            "messages": [],
            "task_description": f"Generate a clean firmware assessment report for: {target}",
            "metadata": merged_metadata,
        }, 1, token_limit)

        raw_report = str(report_state.get("final_result") or "").strip()
        poc_entries = _collect_poc_entries(discovery_state, exploit_state, merged_metadata)
        report = merge_report_text(
            raw_report,
            target=str(merged_metadata.get("target", target) or target),
            scope=str(merged_metadata.get("scope", scope) or scope),
            provenance=str(merged_metadata.get("provenance", "") or ""),
            confirmed_findings=list(merged_metadata.get("confirmed_findings", [])),
            validated_leads=list(merged_metadata.get("validated_leads", [])),
            candidate_findings=list(merged_metadata.get("candidate_findings", [])),
            evidence=list(merged_metadata.get("evidence_log", [])),
            priority_targets=list(merged_metadata.get("priority_targets", [])),
            next_steps=list(merged_metadata.get("next_steps", [])),
            poc_entries=poc_entries,
            remediation_blocks=remediation_blocks,
        )
        # Ensure remediation is always present — replace thin Remediation section
        if not remediation_blocks or not remediation_blocks.strip():
            remediation_blocks = (_build_remediation_from_tools(discovery_state)
                                  or _build_remediation_from_poc_files(poc_entries)
                                  or "")
        if (not remediation_blocks or not remediation_blocks.strip()) and "## Proof of Concept" in report:
            poc_section = report.split("## Proof of Concept")[1].split("## Validation Closure")[0]
            remediation_blocks = _build_remediation_from_poc_entries_text(poc_section)

        if remediation_blocks and remediation_blocks.strip():
            rem_pos = report.find("## Remediation")
            next_pos = report.find("## ", rem_pos + 5) if rem_pos >= 0 else -1
            if rem_pos >= 0 and next_pos > rem_pos:
                report = report[:rem_pos] + f"## Remediation\n{remediation_blocks}\n\n" + report[next_pos:]
            else:
                report += f"\n\n## Remediation\n{remediation_blocks}"
        run_id = str(merged_metadata.get("run_id", "")).strip()
        if run_id:
            self._sync_runtime_findings(run_id, merged_metadata)
            self.runtime_store.update_run_status(
                run_id,
                status="completed" if report else "failed",
                summary=report[:2000],
            )
        self._persist()
        return {
            "success": bool(report),
            "run_id": run_id,
            "runtime_root": merged_metadata.get("runtime_root", ""),
            "target": target,
            "scope": scope,
            "report": report,
            "findings": merged_metadata.get("sub_agents_findings", []),
            "iterations": report_state.get("iteration_count", 0),
            "tokens_used": report_state.get("token_budget", {}).get("used", 0),
            "tools_called": list(report_state.get("compressed_outputs", {}).keys()),
        }

    def _sync_runtime_findings(self, run_id: str, metadata: dict[str, Any]) -> None:
        findings = (
            list(metadata.get("candidate_findings", []))
            + list(metadata.get("validated_leads", []))
            + list(metadata.get("confirmed_findings", []))
        )
        if not findings:
            findings = list(metadata.get("sub_agents_findings", []))

        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title") or finding.get("result") or "").strip()
            if not title:
                continue
            raw_status = str(finding.get("status", "")).strip().lower()
            state = "validated" if raw_status in {"confirmed", "validated"} else "suspect"
            severity = str(finding.get("severity", "medium")).strip() or "medium"
            category = str(finding.get("stage", "observation")).strip() or "observation"
            evidence_items = [str(item).strip() for item in list(finding.get("evidence", [])) if str(item).strip()]
            why_suspicious = evidence_items[0] if evidence_items else title
            impact_statement = str(finding.get("impact") or finding.get("impact_statement") or title).strip()
            finding_id = hashlib.sha1(f"{run_id}:{title}:{category}:{index}".encode("utf-8")).hexdigest()[:16]
            next_step = list(metadata.get("next_steps", []))
            self.runtime_store.upsert_finding(
                finding_id=finding_id,
                run_id=run_id,
                title=title,
                category=category,
                severity=severity,
                state=state,
                why_suspicious=why_suspicious,
                impact_statement=impact_statement,
                current_hypothesis=str(finding.get("source", "")).strip(),
                next_best_action=next_step[0] if next_step else "",
                confidence=0.9 if state == "validated" else 0.4,
            )
            component_path = str(finding.get("component_path", "")).strip()
            for evidence_index, snippet in enumerate(evidence_items, start=1):
                evidence_id = hashlib.sha1(f"{finding_id}:{evidence_index}:{snippet}".encode("utf-8")).hexdigest()[:16]
                self.runtime_store.add_evidence(
                    evidence_id=evidence_id,
                    run_id=run_id,
                    finding_id=finding_id,
                    kind="finding_evidence",
                    title=title,
                    source_type="finding",
                    source_ref=component_path or title,
                    collector=str(finding.get("stage", "report")).strip() or "report",
                    snippet=snippet,
                    artifact_path=component_path or "",
                )

    def _run_agent(
        self,
        name: str,
        state: AgentState,
        max_iterations: int,
        token_limit: int,
    ) -> AgentState:
        state = self._apply_pending_interventions(name, state)

        # ── Loop Manager: detect failures + inject constraints ──
        # From article: before each phase, check for drift/forgetting/pseudo-completion
        recent = _extract_recent_output_text(list(state.get("messages", [])))
        direction = _infer_loop_direction(name, state)
        signal = self.loop_manager.before_iteration(
            direction=direction,
            recent_outputs=recent,
        )
        if signal.mode.value != "none":
            event = self.loop_manager.handle_failure(signal)
            if event and event.content:
                state["messages"] = [HumanMessage(content=event.content)] + list(state.get("messages", []))

        # Check timing through constraint engine
        timing_verdict = self.constraint_engine.check_timing()
        if timing_verdict.should_restart_session:
            self.logger.warning(
                f"Session round cap reached ({self.loop_manager.round_count}), "
                f"forcing restart: {timing_verdict.reason}"
            )
            restart_msg = HumanMessage(content=(
                "[SYSTEM] Round cap reached. Summarize progress and prepare to hand off.\n"
                + self.constraint_engine.get_cheat_card_text()
            ))
            state["messages"] = [restart_msg] + list(state.get("messages", []))
        elif timing_verdict.should_switch_direction:
            self.logger.info(f"Direction timeout: {timing_verdict.reason}")
            direction_hint = self.constraint_engine.get_direction_hint(
                str(state.get("task_description", ""))
            )
            switch_msg = HumanMessage(content=(
                f"[SYSTEM] Direction timeout. Switch direction now.\n"
                f"Suggested: {direction_hint or 'search for new attack surface'}\n"
                + self.constraint_engine.get_cheat_card_text()
            ))
            state["messages"] = [switch_msg] + list(state.get("messages", []))
            self.loop_manager.record_direction_switch(direction_hint or "forced_switch")
        else:
            cheat_text = self.constraint_engine.get_cheat_card_text()
            if cheat_text and state.get("messages"):
                inject_msg = HumanMessage(content=(
                    f"[CONSTRAINT REMINDER — Phase: {name}]\n{cheat_text}"
                ))
                state["messages"] = [inject_msg] + list(state.get("messages", []))

        agent = self._get_agent(name)
        agent.config.set("max_iterations", max_iterations)
        agent.config.set("token_limit", token_limit)
        base_metadata = dict(state.get("metadata", {}) or {})
        run_id = str(base_metadata.get("run_id", "")).strip()
        if run_id:
            self.runtime_store.upsert_agent(
                run_id=run_id,
                agent_name=name,
                current_target="agent_reasoning",
                status="running",
            )
        try:
            with bind_runtime_run_id(run_id):
                result = agent.invoke(state)
            # ── Loop manager: record round ──
            self.loop_manager.after_iteration()
        except Exception:
            if run_id:
                self.runtime_store.upsert_agent(
                    run_id=run_id,
                    agent_name=name,
                    current_target="failed",
                    status="failed",
                )
            raise
        metadata = ensure_run_metadata(
            target=str(base_metadata.get("target", "")),
            scope=str(base_metadata.get("scope", "")),
            provenance=str(base_metadata.get("provenance", "")),
            metadata={**base_metadata, **dict(result.get("metadata", {}) or {})},
        )

        tool_outputs = {
            key: str(value)
            for key, value in dict(result.get("tool_outputs", {}) or {}).items()
        }
        observations = collect_artifact_observations(tool_outputs)

        # ── Constraint engine: filter garbage findings ──
        _filtered_findings = _apply_constraint_filter(
            self.constraint_engine,
            list(observations.get("findings", [])),
            updater=self.constraint_updater,
        )
        _filtered_confirmed = _apply_constraint_filter(
            self.constraint_engine,
            list(observations.get("confirmed_findings", [])),
            updater=self.constraint_updater,
        )
        _filtered_validated = _apply_constraint_filter(
            self.constraint_engine,
            list(observations.get("validated_leads", [])),
            updater=self.constraint_updater,
        )

        metadata["candidate_findings"] = _merge_findings(
            list(metadata.get("candidate_findings", [])),
            _filtered_findings,
        )
        metadata["confirmed_findings"] = _merge_findings(
            list(metadata.get("confirmed_findings", [])),
            _filtered_confirmed,
        )
        metadata["validated_leads"] = _merge_findings(
            list(metadata.get("validated_leads", [])),
            _filtered_validated,
        )
        if not list(metadata.get("sub_agents_findings", [])):
            metadata["sub_agents_findings"] = _merge_records(
                list(metadata.get("sub_agents_findings", [])),
                list(observations.get("findings", []))
                + list(observations.get("validated_leads", []))
                + list(observations.get("confirmed_findings", [])),
            )
        metadata["evidence_log"] = _merge_strings(
            list(metadata.get("evidence_log", [])),
            list(observations.get("evidence", [])),
        )
        metadata["priority_targets"] = _merge_targets(
            list(metadata.get("priority_targets", [])),
            list(observations.get("priority_targets", [])),
        )
        metadata["next_steps"] = _merge_strings(
            list(metadata.get("next_steps", [])),
            list(observations.get("next_steps", [])),
        )

        # ── Parse DCRH-style XML-tagged findings from agent messages ──
        xml_findings = collect_xml_tagged_findings(list(result.get("messages", [])))
        if xml_findings:
            metadata["candidate_findings"] = _merge_findings(
                list(metadata.get("candidate_findings", [])),
                xml_findings,
            )
            if not list(metadata.get("sub_agents_findings", [])):
                metadata["sub_agents_findings"] = _merge_records(
                    list(metadata.get("sub_agents_findings", [])),
                    xml_findings,
                )
            for f in xml_findings:
                evidence_text = "; ".join(f.get("evidence", []))
                if evidence_text:
                    metadata["evidence_log"] = _merge_strings(
                        list(metadata.get("evidence_log", [])),
                        [f"xml_tagged: {f.get('title', '')}: {evidence_text[:500]}"],
                    )

        # Parse verification verdict (only for exploit phase)
        if name == "exploit":
            verdict = collect_xml_tagged_verdict(list(result.get("messages", [])))
            if verdict and verdict.get("passed"):
                metadata.setdefault("_verification_verdict", verdict)

        # Parse report self-grading (only for report phase)
        if name == "report":
            grading = collect_report_grading(list(result.get("messages", [])))
            if grading:
                metadata.setdefault("_report_grading", grading)

        explicit_final_text = str(result.get("final_result") or "").strip()
        final_text = explicit_final_text
        if not final_text:
            final_text = extract_latest_ai_text(list(result.get("messages", [])))
        final_text = normalize_ai_summary_text(final_text)
        if final_text and not is_substantive_ai_text(final_text):
            final_text = ""
        source = "live" if str(metadata.get("provenance", "")).startswith("live:") else "artifact"
        if final_text:
            should_log_summary = name != "exploit" or is_actionable_validation_text(final_text)
            if name == "report":
                should_log_summary = False
            if should_log_summary:
                metadata["evidence_log"] = _merge_strings(
                    list(metadata.get("evidence_log", [])),
                    [f"{name}: {final_text[:500]}"],
                )
            if name == "discovery":
                summary_finding = make_finding(
                    title=final_text.splitlines()[0][:120],
                    stage="discovery",
                    source=source,
                    severity="medium",
                    evidence=[final_text[:500]],
                )
                metadata["candidate_findings"] = _merge_findings(
                    list(metadata.get("candidate_findings", [])),
                    [
                        summary_finding,
                    ],
                )
                if not list(metadata.get("sub_agents_findings", [])):
                    metadata["sub_agents_findings"] = _merge_records(
                        list(metadata.get("sub_agents_findings", [])),
                        [summary_finding],
                    )
                metadata["next_steps"] = _merge_strings(
                    list(metadata.get("next_steps", [])),
                    ["Validate discovery leads before broad rescanning."],
                )
            elif name == "exploit":
                if is_actionable_validation_text(final_text):
                    summary_finding = make_finding(
                        title=final_text.splitlines()[0][:120],
                        stage="exploit",
                        source=source,
                        severity="high",
                        status="confirmed",
                        evidence=[final_text[:500]],
                    )
                    metadata["confirmed_findings"] = _merge_findings(
                        list(metadata.get("confirmed_findings", [])),
                        [
                            summary_finding,
                        ],
                    )
                    if not list(metadata.get("sub_agents_findings", [])):
                        metadata["sub_agents_findings"] = _merge_records(
                            list(metadata.get("sub_agents_findings", [])),
                            [summary_finding],
                        )

        if name == "report" and explicit_final_text:
            result["final_result"] = explicit_final_text
        elif name == "report" and final_text:
            metadata["_report_needs_merge"] = True
            result["final_result"] = final_text

        if run_id:
            next_steps = [str(item).strip() for item in list(metadata.get("next_steps", [])) if str(item).strip()]
            current_hypothesis = final_text.splitlines()[0][:200] if final_text else ""
            self.runtime_store.upsert_agent(
                run_id=run_id,
                agent_name=name,
                current_target="completed",
                status="completed",
                current_hypothesis=current_hypothesis,
                next_step=next_steps[0] if next_steps else "",
            )

        result["metadata"] = metadata
        return result

    def _run_automatic_firmware_validation(self, state: AgentState, target: str) -> AgentState:
        if "://" in target:
            return state

        artifact = Path(target)
        if not artifact.exists() or not artifact.is_file():
            return state
        if artifact.suffix.lower() not in _PRIMARY_FIRMWARE_SUFFIXES:
            return state

        tool_outputs = dict(state.get("tool_outputs", {}))
        metadata_snapshot = dict(state.get("metadata", {}) or {})
        scope_text = str(metadata_snapshot.get("scope", "")).strip().lower()
        joined_seed_text = "\n".join(str(value) for value in tool_outputs.values() if value).lower()
        if not (
            any(
                key in tool_outputs
                for key in {
                    "firmware_runtime_manifest",
                    "firmware_service_inventory",
                    "firmware_emulation_prepare",
                }
            )
            or "squashfs" in joined_seed_text
            or "validation" in scope_text
        ):
            return state

        compressed_outputs = dict(state.get("compressed_outputs", {}))
        executed_tools = list(state.get("executed_tools", []))
        metadata = ensure_run_metadata(
            target=str(metadata_snapshot.get("target", target)),
            scope=str(metadata_snapshot.get("scope", "")),
            provenance=str(metadata_snapshot.get("provenance", "")),
            metadata=metadata_snapshot,
        )

        def record_tool(tool_name: str, tool_args: dict[str, Any]) -> None:
            nonlocal tool_outputs, compressed_outputs, executed_tools
            if tool_name in tool_outputs:
                return
            tool_def = self.tool_registry.get(tool_name)
            if tool_def is None:
                return
            try:
                raw_result = tool_def.executor(tool_args)
                raw_text = _normalize_tool_text(raw_result)
            except Exception as exc:
                raw_text = f"Tool execution error: {exc}"

            compressed_text = raw_text
            if self.micro_compressor:
                try:
                    compressed_text = self.micro_compressor.compress(
                        raw_text,
                        context={"tool_name": tool_name, "max_tokens": 2000},
                    )
                except Exception:
                    compressed_text = raw_text[:8000]

            tool_outputs[tool_name] = raw_text[:16000]
            compressed_outputs[tool_name] = compressed_text[:8000]
            executed_tools.append({
                "name": tool_name,
                "output_key": tool_name,
                "args": tool_args,
                "args_summary": str(tool_args)[:100],
                "result_summary": compressed_outputs[tool_name][:150],
                "timestamp": 0.0,
                "success": "error" not in raw_text.lower()[:100] and "unavailable" not in raw_text.lower()[:160],
                "seeded": True,
            })

        for tool_name in [
            "firmware_runtime_manifest",
            "firmware_service_inventory",
            "firmware_emulation_prepare",
            "firmware_emulation_launch_user",
        ]:
            record_tool(tool_name, {"path": str(artifact)})

        launch_text = str(tool_outputs.get("firmware_emulation_launch_user", ""))
        probe_port = _extract_probe_port(launch_text)
        probe_service_type = _extract_probe_service_type(launch_text)
        probe_text = ""
        if probe_port is not None:
            record_tool(
                "firmware_emulation_probe",
                {"port": probe_port, "service_type": probe_service_type or "http"},
            )
            probe_text = str(tool_outputs.get("firmware_emulation_probe", ""))

        # If probe succeeded, add a confirmed finding with reachability evidence
        if probe_text and "REACHABLE: TRUE" in probe_text.upper():
            reachable_services = []
            for ln in probe_text.split("\n"):
                if "REACHABLE: TRUE" in ln.upper():
                    reachable_services.append(ln.strip())
            cf = metadata.get("confirmed_findings") or []
            if isinstance(cf, list):
                cf.append(make_finding(
                    title=f"Emulated firmware service reachable for validation",
                    severity="high",
                    vuln_type="reachability_confirmed",
                    evidence=reachable_services,
                    component_path=f"{probe_service_type or 'http'}://127.0.0.1:{probe_port}",
                    impact=f"Live service confirmed via SSH emulation probe",
                ))
                metadata["confirmed_findings"] = cf
            metadata["emulation_verified"] = True
            metadata["emulation_services"] = reachable_services

        if not probe_text or "REACHABLE: TRUE" not in probe_text.upper():
            record_tool("firmware_emulation_launch_system", {"path": str(artifact)})

        # ── Validation backend: upload rootfs + start services + probe ──
        _run_validation_backend(
            self._validation_backend, metadata, artifact, tool_outputs,
            self.logger,
        )

        observations = collect_artifact_observations(tool_outputs)
        metadata["candidate_findings"] = _merge_findings(
            list(metadata.get("candidate_findings", [])),
            list(observations.get("findings", [])),
        )
        metadata["confirmed_findings"] = _merge_findings(
            list(metadata.get("confirmed_findings", [])),
            list(observations.get("confirmed_findings", [])),
        )
        metadata["validated_leads"] = _merge_findings(
            list(metadata.get("validated_leads", [])),
            list(observations.get("validated_leads", [])),
        )
        if not list(metadata.get("sub_agents_findings", [])):
            metadata["sub_agents_findings"] = _merge_records(
                list(metadata.get("sub_agents_findings", [])),
                list(observations.get("findings", []))
                + list(observations.get("validated_leads", []))
                + list(observations.get("confirmed_findings", [])),
            )
        metadata["evidence_log"] = _merge_strings(
            list(metadata.get("evidence_log", [])),
            list(observations.get("evidence", [])),
        )
        metadata["priority_targets"] = _merge_targets(
            list(metadata.get("priority_targets", [])),
            list(observations.get("priority_targets", [])),
        )
        metadata["next_steps"] = _merge_strings(
            list(metadata.get("next_steps", [])),
            list(observations.get("next_steps", [])),
        )

        return {
            **state,
            "metadata": metadata,
            "tool_outputs": tool_outputs,
            "compressed_outputs": compressed_outputs,
            "executed_tools": executed_tools,
        }

    def _apply_pending_interventions(self, agent_name: str, state: AgentState) -> AgentState:
        metadata = dict(state.get("metadata", {}) or {})
        run_id = str(metadata.get("run_id", "")).strip()
        if not run_id:
            return state

        agent_scope_id = f"{run_id}:{agent_name}"
        pending: list[dict[str, Any]] = []
        for record in self.runtime_store.list_run_interventions(run_id):
            if str(record.get("status", "")).strip().lower() != "received":
                continue
            scope_type = str(record.get("scope_type", "")).strip().lower()
            scope_id = str(record.get("scope_id", "")).strip()
            if scope_type == "run" and scope_id == run_id:
                pending.append(record)
            elif scope_type == "agent" and scope_id == agent_scope_id:
                pending.append(record)

        if not pending:
            return state

        pending.sort(key=lambda item: (float(item.get("created_at", 0) or 0), str(item.get("intervention_id", ""))))
        guidance_lines = [
            f"- [{str(item.get('scope_type', 'run'))}] {str(item.get('instruction', '')).strip()}"
            for item in pending
            if str(item.get("instruction", "")).strip()
        ]
        if not guidance_lines:
            return state

        injected_message = HumanMessage(
            content=(
                "Operator interventions for this phase:\n"
                + "\n".join(guidance_lines)
                + "\nTreat these as high-priority guidance unless contradicted by direct evidence."
            )
        )
        messages = [injected_message, *list(state.get("messages", []))]

        for item in pending:
            intervention_id = str(item.get("intervention_id", "")).strip()
            if not intervention_id:
                continue
            response_summary = f"Injected into {agent_name} phase context."
            self.runtime_store.update_intervention(
                intervention_id,
                status="applied",
                response_summary=response_summary,
            )
            self.runtime_store.append_event(
                run_id,
                {
                    "type": "intervention.applied",
                    "agent_name": agent_name,
                    "message": str(item.get("instruction", ""))[:200],
                    "data": {
                        "intervention_id": intervention_id,
                        "scope_type": str(item.get("scope_type", "")),
                        "scope_id": str(item.get("scope_id", "")),
                        "instruction": str(item.get("instruction", "")),
                        "response_summary": response_summary,
                    },
                },
            )

        return {
            **state,
            "messages": messages,
        }

    def _get_agent(self, name: str) -> Any:
        if name not in self._agents:
            agent_map = {
                "brainstorm": BrainstormAgent,
                "discovery": DiscoveryAgent,
                "exploit": ExploitAgent,
                "verification": VerificationAgent,
                "report": ReportAgent,
            }
            agent_cls = agent_map[name]
            self._agents[name] = agent_cls(
                llm=self.router if self.router else self.llm,
                tools=self.tool_registry,
                memory=self.memory,
                compressor=self.micro_compressor,
                config=ConfigLoader({"max_iterations": 5, "model": ""}),
                logger=StructuredLogger(f"{name}Agent"),
                kg=self.kg,
                mid_compressor=self.mid_compressor,
                event_emitter=self.event_emitter,
                sandbox=self._sandbox,
            )
        return self._agents[name]

    def _persist(self) -> None:
        try:
            if self._memory_path != ":memory:":
                self.memory.save()
            self.kg.save(self._kg_path)
        except Exception as e:
            self.logger.error(f"Persistence failed: {e}")
        finally:
            try:
                self.memory.close()
            except Exception:
                pass

    def _get_knowledge(self) -> KnowledgeRetriever:
        """Lazy-init the knowledge retriever with bundled docs directory."""
        if self._knowledge is None:
            from pathlib import Path as _Path
            docs_dir = _Path(__file__).resolve().parent / "knowledge" / "docs"
            self._knowledge = KnowledgeRetriever(docs_dir=str(docs_dir) if docs_dir.exists() else None)
        return self._knowledge

    def _seed_local_artifact_triage(self, state: AgentState, target: str) -> AgentState:
        if "://" in target:
            return state

        candidate = Path(target)
        if not candidate.exists():
            return state

        metadata = dict(state.get("metadata", {}))
        tool_outputs = dict(state.get("tool_outputs", {}))
        compressed_outputs = dict(state.get("compressed_outputs", {}))
        executed_tools = list(state.get("executed_tools", []))

        # ── Directory targets: run elf_surface_scan to populate seed findings ──
        if candidate.is_dir():
            from vulnagent.firmware.binary_audit import audit_elf_binaries
            try:
                findings, summary = audit_elf_binaries(str(candidate))
                if findings and summary.get("candidate_findings"):
                    metadata["candidate_findings"] = _merge_findings(
                        list(metadata.get("candidate_findings", [])),
                        summary["candidate_findings"],
                    )
                    metadata["priority_targets"] = _merge_strings(
                        list(metadata.get("priority_targets", [])),
                        summary.get("priority_targets", []),
                    )
                    metadata["next_steps"] = _merge_strings(
                        list(metadata.get("next_steps", [])),
                        summary.get("next_steps", []),
                    )
                    metadata["_origin"] = "elf_surface_scan"
                    self.logger.info(
                        f"elf_surface_scan: {len(findings)} findings "
                        f"({summary.get('critical_count', 0)} critical) in {candidate}"
                    )
            except Exception as exc:
                self.logger.warning(f"elf_surface_scan failed: {exc}")
            return {**state, "metadata": metadata, "tool_outputs": tool_outputs, "compressed_outputs": compressed_outputs, "executed_tools": executed_tools}

        if not candidate.is_file():
            return state
        tool_outputs = dict(state.get("tool_outputs", {}))
        compressed_outputs = dict(state.get("compressed_outputs", {}))
        executed_tools = list(state.get("executed_tools", []))

        if candidate.suffix.lower() in _PRIMARY_FIRMWARE_SUFFIXES:
            metadata["artifact_target"] = str(candidate)
            metadata["artifact_kind"] = "firmware"
            metadata["preferred_tool_sequence"] = [
                "firmware_runtime_manifest",
                "firmware_service_inventory",
                "firmware_emulation_prepare",
                "firmware_emulation_launch_user",
                "firmware_emulation_probe",
                "firmware_emulation_launch_system",
            ]

        seed_plan = [
            ("file_identify", {"path": str(candidate)}),
            ("binwalk_scan", {"path": str(candidate)}),
        ]
        if candidate.stat().st_size <= _STRINGS_PRETRIAGE_MAX_BYTES:
            seed_plan.append(("strings_extract", {"path": str(candidate)}))

        def make_output_key(tool_name: str, tool_args: dict[str, Any]) -> str:
            base_key = tool_name
            inner_path = str(tool_args.get("inner_path", "")).strip()
            if inner_path:
                base_key = f"{tool_name}:{inner_path}"
            elif tool_name == "firmware_search":
                pattern = str(tool_args.get("pattern", "")).strip()
                if pattern:
                    base_key = f"{tool_name}:{pattern}"
            elif tool_name == "file_read":
                path_arg = str(tool_args.get("path", "")).strip()
                if path_arg:
                    base_key = f"{tool_name}:{path_arg}"
            if base_key not in tool_outputs:
                return base_key
            index = 2
            while f"{base_key}#{index}" in tool_outputs:
                index += 1
            return f"{base_key}#{index}"

        def run_seed_tool(tool_name: str, tool_args: dict[str, Any]) -> None:
            nonlocal tool_outputs, compressed_outputs, executed_tools
            output_key = make_output_key(tool_name, tool_args)
            if output_key in tool_outputs:
                return
            tool_def = self.tool_registry.get(tool_name)
            if tool_def is None:
                return
            try:
                raw_result = tool_def.executor(tool_args)
                raw_text = _normalize_tool_text(raw_result)
            except Exception as exc:
                raw_text = f"Tool execution error: {exc}"

            compressed_text = raw_text
            if self.micro_compressor:
                try:
                    compressed_text = self.micro_compressor.compress(
                        raw_text,
                        context={"tool_name": tool_name, "max_tokens": 2000},
                    )
                except Exception:
                    compressed_text = raw_text[:8000]

            tool_outputs[output_key] = raw_text[:16000]
            compressed_outputs[output_key] = compressed_text[:8000]
            executed_tools.append({
                "name": tool_name,
                "output_key": output_key,
                "args": tool_args,
                "args_summary": str(tool_args)[:100],
                "result_summary": compressed_outputs[output_key][:150],
                "timestamp": 0.0,
                "success": "error" not in raw_text.lower()[:100],
                "seeded": True,
            })

        for tool_name, tool_args in seed_plan:
            run_seed_tool(tool_name, tool_args)

        pretriage_text = "\n".join(
            tool_outputs.get(name, "")
            for name in ("file_identify", "binwalk_scan")
        ).lower()
        _is_firmware = candidate.suffix.lower() in _PRIMARY_FIRMWARE_SUFFIXES
        _has_squashfs = "squashfs" in pretriage_text
        _has_ubi = "ubi" in pretriage_text or "ubifs" in pretriage_text or "ubi image" in pretriage_text
        if _has_squashfs or _has_ubi:
            run_seed_tool("firmware_extract_summary", {"path": str(candidate)})
            run_seed_tool("firmware_web_surface_map", {"path": str(candidate)})
            run_seed_tool("firmware_runtime_manifest", {"path": str(candidate)})
            run_seed_tool("firmware_service_inventory", {"path": str(candidate)})
            run_seed_tool("firmware_emulation_prepare", {"path": str(candidate)})
            summary_text = tool_outputs.get("firmware_extract_summary", "")
            observations = collect_artifact_observations(tool_outputs)
            readback_paths: list[str] = []

            def add_readback_path(inner_path: str) -> None:
                normalized = str(inner_path or "").strip()
                if not normalized.startswith("/"):
                    return
                if normalized not in readback_paths:
                    readback_paths.append(normalized)

            for target in observations.get("priority_targets", []):
                for inner_path in target.get("paths", []):
                    add_readback_path(str(inner_path))

            for inner_path in [
                "/etc_ro/rcS",
                "/etc_ro/inittab",
                "/etc_ro/web/d_telnet.asp",
                "/etc_ro/web/dir_login.asp",
                "/etc_ro/web/d_saveconf.asp",
                "/etc_ro/web/d_upload.asp",
                "/etc_ro/web/cgi-bin/upload.cgi",
                "/etc_ro/web/cgi-bin/upload_bootloader.cgi",
                "/etc_ro/web/cgi-bin/upload_settings.cgi",
                "/etc_ro/web/cgi-bin/upload_torrent.cgi",
                "/etc_ro/web/cgi-bin/ExportSettings.sh",
                "/etc_ro/web/cgi-bin/reboot.sh",
                "/sbin/chpasswd.sh",
                "/bin/goahead",
            ]:
                if inner_path in summary_text:
                    add_readback_path(inner_path)

            for inner_path in _derive_route_map_readback_paths(tool_outputs.get("firmware_web_surface_map", "")):
                add_readback_path(inner_path)

            for inner_path in readback_paths:
                run_seed_tool(
                    "firmware_read_path",
                    {
                        "path": str(candidate),
                        "inner_path": inner_path,
                        "mode": _preferred_firmware_read_mode(inner_path),
                        "max_bytes": _preferred_firmware_read_max_bytes(inner_path),
                    },
                )

            for pattern in _derive_firmware_search_patterns(tool_outputs):
                run_seed_tool(
                    "firmware_search",
                    {
                        "path": str(candidate),
                        "pattern": pattern,
                        "mode": "auto",
                        "max_results": 12,
                        "max_bytes": 131072,
                    },
                )

            for inner_path in _derive_search_hit_readback_paths(tool_outputs):
                run_seed_tool(
                    "firmware_read_path",
                    {
                        "path": str(candidate),
                        "inner_path": inner_path,
                        "mode": _preferred_firmware_read_mode(inner_path),
                        "max_bytes": _preferred_firmware_read_max_bytes(inner_path),
                    },
                )

        # ── Firmware gate: ensure recognized firmware images always pass Tier 1 ──
        _is_fw = candidate.suffix.lower() in _PRIMARY_FIRMWARE_SUFFIXES
        if _is_fw:
            existing = list(metadata.get("candidate_findings", []))
            if not existing and not metadata.get("priority_targets"):
                metadata["candidate_findings"] = [{
                    "title": f"Firmware image: {candidate.name}",
                    "cwe_id": "CWE-78",
                    "severity": "high",
                    "component_path": str(candidate),
                    "evidence": [
                        f"File type: {str(tool_outputs.get('file_identify', 'unknown'))[:200]}",
                        f"Binwalk: {str(tool_outputs.get('binwalk_scan', 'unknown'))[:200]}",
                    ],
                }]
                metadata["priority_targets"] = [str(candidate)]
                metadata["next_steps"] = [
                    "Extract root filesystem via binwalk",
                    "Run elf_surface_scan on extracted binaries",
                    "Analyze CGI binaries for command injection",
                ]

        return {
            **state,
            "metadata": metadata,
            "tool_outputs": tool_outputs,
            "compressed_outputs": compressed_outputs,
            "executed_tools": executed_tools,
        }


def _missing_local_target(target: str) -> str | None:
    raw_target = (target or "").strip()
    if not raw_target or "://" in raw_target:
        return None

    candidate = Path(raw_target).expanduser()
    if candidate.exists():
        return None

    if _looks_like_local_artifact_target(raw_target, candidate):
        return raw_target
    if _looks_like_host_target(raw_target):
        return None
    return None


def _resolve_target(target: str) -> tuple[str, str | None]:
    raw_target = (target or "").strip()
    if not raw_target or "://" in raw_target:
        return raw_target, None

    candidate = Path(raw_target).expanduser()
    if not candidate.exists():
        return raw_target, None
    if not candidate.is_dir():
        return str(candidate), None

    artifact_files = sorted(
        (
            path for path in candidate.rglob("*")
            if path.is_file() and path.suffix.lower() in _ARTIFACT_SUFFIXES
        ),
        key=lambda path: (_artifact_priority(path), -path.stat().st_size, str(path)),
    )
    if not artifact_files:
        return raw_target, f"No firmware artifacts found in directory: {candidate}"

    # Any directory with ELF/CGI binaries gets routed to seed triage as a
    # directory target — elf_surface_scan + firmware_read_path handle it.
    # Don't reduce it to a single .ko/.bin file; the agent needs the full tree.
    _BINARY_SUFFIXES = {".cgi", ".elf", ".so", ".ko"}
    _has_binaries = any(
        f.suffix.lower() in _BINARY_SUFFIXES for f in artifact_files
    )
    _has_firmware = any(
        f.suffix.lower() in _PRIMARY_FIRMWARE_SUFFIXES for f in artifact_files
    )
    if _has_binaries and not _has_firmware:
        return str(candidate), None
    if _has_binaries and _has_firmware:
        return str(candidate), None

    return str(artifact_files[0]), None


def _looks_like_host_target(target: str) -> bool:
    if re.fullmatch(r"[A-Za-z0-9_.-]+:\d{1,5}", target):
        return True
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", target):
        return True
    if re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", target):
        return True
    return False


def _looks_like_local_artifact_target(raw_target: str, candidate: Path) -> bool:
    if candidate.is_absolute():
        return True
    if raw_target.startswith((".", "~")):
        return True
    if "\\" in raw_target or "/" in raw_target:
        return True
    if re.match(r"^[A-Za-z]:($|[\\/])", raw_target):
        return True
    return candidate.suffix.lower() in _ARTIFACT_SUFFIXES


def _should_skip_exploit_phase(state: AgentState) -> bool:
    metadata = state.get("metadata", {}) or {}
    provenance = str(metadata.get("provenance", "")).strip().lower()
    target = str(metadata.get("target", "")).strip().lower()
    if not provenance.startswith("artifact:"):
        return False
    if not target.endswith(tuple(_PRIMARY_FIRMWARE_SUFFIXES)):
        return False
    tool_keys = {
        str(key)
        for key in {
            **dict(state.get("tool_outputs", {}) or {}),
            **dict(state.get("compressed_outputs", {}) or {}),
        }.keys()
    }
    if not any(
        key.startswith((
            "firmware_runtime_manifest",
            "firmware_service_inventory",
            "firmware_emulation_prepare",
            "firmware_emulation_launch_user",
            "firmware_emulation_probe",
            "firmware_emulation_launch_system",
        ))
        for key in tool_keys
    ):
        return False

    combined_outputs = "\n".join(
        str(value)
        for value in {
            **dict(state.get("tool_outputs", {}) or {}),
            **dict(state.get("compressed_outputs", {}) or {}),
        }.values()
        if value
    ).lower()
    if "reachable: true" in combined_outputs:
        return False
    if "endpoint: http://" in combined_outputs or "endpoint: https://" in combined_outputs:
        return False
    return True


def _merge_strings(existing: list[str], new_items: list[str]) -> list[str]:
    merged: list[str] = []
    for item in [*existing, *new_items]:
        normalized = str(item).strip()
        if normalized and normalized not in merged:
            merged.append(normalized)
    return merged


def _merge_findings(existing: list[dict[str, Any]], new_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in [*existing, *new_items]:
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("title", "")),
            str(item.get("stage", "")),
            str(item.get("status", "")),
        )
        if not key[0] or key in seen:
            continue
        merged.append(item)
        seen.add(key)
    return merged


def _merge_records(existing: list[dict[str, Any]], new_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in [*existing, *new_items]:
        if not isinstance(item, dict):
            continue
        key = repr(sorted(item.items()))
        if key in seen:
            continue
        merged.append(item)
        seen.add(key)
    return merged


def _merge_targets(existing: list[dict[str, Any]], new_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in [*existing, *new_items]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        if not title or title in seen:
            continue
        merged.append(item)
        seen.add(title)
    return merged


def _artifact_priority(path: Path) -> int:
    suffix = path.suffix.lower()
    if suffix in _PRIMARY_FIRMWARE_SUFFIXES:
        return 0
    if suffix in _SECONDARY_ARTIFACT_SUFFIXES:
        return 1
    return 2


def _apply_constraint_filter(
    constraint_engine: Any,
    findings: list[dict[str, Any]],
    updater: Any = None,
) -> list[dict[str, Any]]:
    """Filter findings through the constraint engine's garbage list.

    From article: "标题命中垃圾洞清单 → 拒绝"
    Called in _run_agent() before findings are merged into metadata.

    If updater is provided, rejected findings are recorded for
    potential constraint auto-update.
    """
    if not findings:
        return findings
    filtered: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            filtered.append(finding)
            continue
        title = str(finding.get("title", "")).strip()
        description = str(finding.get("description", "")).strip()
        evidence = " ".join(
            str(e) for e in (finding.get("evidence", []) or [])
        )
        verdict = constraint_engine.check_finding(title, description, evidence)
        if verdict.accepted:
            filtered.append(finding)
        else:
            if updater is not None:
                try:
                    updater.record(title, verdict.matched_category or "unknown",
                                   verdict.reason)
                except Exception:
                    pass
    return filtered


def _auto_score_findings(metadata: dict[str, Any]) -> None:
    """Score all findings with CVSS and annotate with tier confidence.

    Called after PoC generation, before report.
    """
    from vulnagent.core.risk import score_finding as sf

    for findings_key in ("confirmed_findings", "validated_leads", "candidate_findings"):
        for finding in list(metadata.get(findings_key, [])):
            if not isinstance(finding, dict):
                continue
            # Skip if already scored
            if finding.get("cvss_score") and finding.get("cvss_vector"):
                continue
            try:
                sf(finding)
            except Exception:
                pass  # Best effort — don't block the pipeline


def _auto_grade_patches(patch_grader: Any, metadata: dict[str, Any]) -> None:
    """Grade generated PoC patches for high-severity confirmed findings.

    From DCRH: runs T0-T3 verification on patches, records grades.
    Only grades critical/high findings — others are informational.
    """
    confirmed = list(metadata.get("confirmed_findings", []))
    if not confirmed or not patch_grader:
        return

    patch_grades: list[dict[str, Any]] = []
    for finding in confirmed[:5]:  # Top 5 max to avoid excessive subprocess calls
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "")).lower()
        if severity not in ("critical", "high"):
            continue
        poc_cmd = str(finding.get("poc_path", "") or finding.get("executable_command", "")).strip()
        if not poc_cmd:
            continue
        try:
            grade_result = patch_grader.grade(
                finding,
                patch_commands=str(finding.get("_patch_commands", "") or "echo fix applied"),
                target=str(metadata.get("target", "")),
            )
            patch_grades.append(grade_result.as_dict())
        except Exception:
            pass  # Best effort — don't block the pipeline

    if patch_grades:
        metadata["_patch_grades"] = patch_grades
        metadata["evidence_log"] = _merge_strings(
            list(metadata.get("evidence_log", [])),
            [f"patch_grade: {len(patch_grades)} patches graded, "
             f"passed={sum(1 for g in patch_grades if g.get('overall_passed'))}"]
        )


def _extract_recent_output_text(messages: list[Any]) -> list[str]:
    """Extract text content from recent LLM chain library messages for LoopManager.

    Strips tool_calls metadata and keeps only human-readable text.
    Used by LoopManager.before_iteration() for drift/pseudo-completion detection.
    """
    texts: list[str] = []
    for msg in messages[-8:]:  # Last 8 messages max
        if isinstance(msg, dict):
            content = str(msg.get("content", ""))
        elif hasattr(msg, "content"):
            content = str(getattr(msg, "content", ""))
        else:
            content = str(msg)
        if content and len(content) > 10:
            texts.append(content[:500])
    return texts


def _infer_loop_direction(agent_name: str, state: dict[str, Any]) -> str:
    """Infer the current Loop direction from agent name + state metadata.

    Maps agent phases to the names used by FailureDetector.DRIFT_KEYWORDS.
    Falls back to agent_name if no metadata hint is available.
    """
    metadata = state.get("metadata", {}) or {}

    # If metadata has an explicit direction hint from the decision tree, use it
    decision_direction = str(metadata.get("_current_focus", "")).strip().lower()
    if decision_direction:
        return decision_direction

    # Map agent phase names to drift-detection keys
    phase_map = {
        "brainstorm": "brainstorm",
        "discovery": "discovery",
        "exploit": "exploit",
        "verification": "verification",
        "report": "report",
    }
    return phase_map.get(agent_name, agent_name)


def _normalize_tool_text(raw_result: Any) -> str:
    stdout = getattr(raw_result, "stdout", None)
    stderr = getattr(raw_result, "stderr", None)
    return_code = getattr(raw_result, "return_code", None)
    if stdout is not None:
        text = str(stdout)
        if stderr:
            text = f"{text}\n[stderr]\n{stderr}"
        if return_code not in (None, 0):
            text = f"{text}\n[return_code]\n{return_code}"
        return text.strip()
    return str(raw_result)


def _preferred_firmware_read_mode(inner_path: str) -> str:
    path = str(inner_path or "").lower()
    if path.endswith((".asp", ".htm", ".html", ".sh")) or path in {"/etc_ro/rcs", "/etc_ro/inittab"}:
        return "text"
    if path.endswith(".cgi"):
        return "auto"
    if path.startswith(("/bin/", "/sbin/", "/usr/sbin/", "/usr/bin/", "/lib/")):
        return "strings"
    return "auto"


def _preferred_firmware_read_max_bytes(inner_path: str) -> int:
    path = str(inner_path or "").lower()
    if path == "/sbin/internet.sh":
        return 16384
    return 8192


def _extract_probe_port(text: str) -> int | None:
    match = re.search(r"PROBE_PORT:\s+(\d+)", str(text or ""), re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _extract_probe_service_type(text: str) -> str:
    for pattern in (r"PROBE_SERVICE_TYPE:\s+([^\r\n]+)", r"SERVICE_TYPE:\s+([^\r\n]+)"):
        match = re.search(pattern, str(text or ""), re.IGNORECASE)
        if match:
            return str(match.group(1)).strip().lower()
    return ""


def _infer_asset_kind(target: str) -> str:
    normalized = str(target or "").strip().lower()
    if "://" in normalized:
        return "live_target"
    if normalized.endswith(tuple(_PRIMARY_FIRMWARE_SUFFIXES)):
        return "firmware"
    return "artifact"


def _derive_firmware_search_patterns(tool_outputs: dict[str, str]) -> list[str]:
    joined = "\n".join(
        str(value)
        for key, value in tool_outputs.items()
        if key.startswith("firmware_read_path:") or key in {"firmware_extract_summary", "firmware_web_surface_map"}
    ).lower()
    candidates = [
        "form2Telnet.cgi",
        "goform/formLogin",
        "showSystemCommandASP",
        "doSystem",
        "doSystembk",
        "websFormDefine",
        "formDefine",
        "upload.cgi.c",
        "import_5g",
        "chpasswd.sh",
        "config.img",
        "telnetEnabled",
        "/etc/passwd",
        "upload_settings.cgi",
        "ExportSettings.sh",
        "websAspDefine",
        "ejSetGlobalFunctionDirect",
        "websGetRequestPath",
    ]
    patterns: list[str] = []
    for candidate in candidates:
        if candidate.lower() in joined and candidate not in patterns:
            patterns.append(candidate)
    return patterns[:14]


def _derive_search_hit_readback_paths(tool_outputs: dict[str, str]) -> list[str]:
    paths: list[str] = []
    for key, value in tool_outputs.items():
        if not str(key).startswith("firmware_search:"):
            continue
        for match in re.finditer(r"MATCH:\s+(\S+)\s+\[[^\]]+\]\s+::", str(value or "")):
            candidate = str(match.group(1)).strip()
            if candidate.startswith("/") and _is_priority_search_hit_path(candidate) and candidate not in paths:
                paths.append(candidate)
    return paths[:16]


def _derive_route_map_readback_paths(route_map_text: str) -> list[str]:
    paths: list[str] = []
    for match in re.finditer(r"TEXT_ROUTE:\s+(\S+)\s+->\s+([^\n]+)", str(route_map_text or "")):
        candidate = str(match.group(1)).strip()
        route = str(match.group(2)).strip()
        if candidate.startswith("/etc_ro/web/") and _is_priority_route_path(candidate, route) and candidate not in paths:
            paths.append(candidate)
    return paths[:16]


def _is_priority_route_path(path: str, route: str) -> bool:
    combined = f"{path} {route}".lower()
    keywords = (
        "upload",
        "saveconf",
        "export",
        "import",
        "login",
        "telnet",
        "system",
        "command",
        "reboot",
        "passwd",
        "password",
        "config",
    )
    return any(keyword in combined for keyword in keywords)


def _is_priority_search_hit_path(path: str) -> bool:
    normalized = path.lower()
    if normalized in {
        "/sbin/internet.sh",
        "/sbin/chpasswd.sh",
        "/etc_ro/wireless/rt2860ap/rt2860_factory_vlan",
        "/etc_ro/wireless/rt2860ap/rt2860_default_vlan",
    }:
        return True
    if normalized.startswith("/etc_ro/web/"):
        return True
    return normalized.startswith(("/sbin/", "/bin/"))


def _clean_messages_for_new_agent(
    messages: list[Any],
    metadata: dict[str, Any],
) -> list[Any]:
    """Replace message history with a clean summary suitable for a new agent.

    Strips ALL tool_calls and tool results that would violate DeepSeek's
    message ordering requirements. Builds a fresh HumanMessage summary
    from metadata and the last assistant conclusion.
    """
    if not messages:
        return messages

    # Extract the last meaningful assistant conclusion
    last_text = ""
    for msg in reversed(messages):
        msg_dict = msg if isinstance(msg, dict) else getattr(msg, "model_dump", lambda: {})()
        if not msg_dict:
            continue
        role = str(msg_dict.get("role", "")).strip().lower()
        content = str(msg_dict.get("content", "")).strip()
        tool_calls = msg_dict.get("tool_calls") or []
        if role == "assistant" and content and not tool_calls:
            last_text = content
            break

    findings_count = (
        len(list(metadata.get("candidate_findings", [])))
        + len(list(metadata.get("confirmed_findings", [])))
        + len(list(metadata.get("validated_leads", [])))
    )
    evidence_count = len(list(metadata.get("evidence_log", [])))
    target = str(metadata.get("target", "this firmware"))

    summary = (
        f"The discovery phase analyzed {target} and found "
        f"{findings_count} potential vulnerabilities with {evidence_count} evidence items. "
        f"Conclusions from discovery: {last_text[:2000] if last_text else 'See metadata for details.'}"
    )

    from langchain_core.messages import HumanMessage
    return [HumanMessage(content=summary)]


def _strip_orphaned_tool_calls(messages: list[Any]) -> list[Any]:
    """Strip assistant messages whose tool_calls lack a matching tool result.

    DeepSeek requires every assistant(tool_calls) to be immediately followed by
    tool(message) entries for each tool_call_id. GPT providers accept orphaned
    tool_calls, but to maximize compatibility we strip them here.
    """
    if not messages:
        return []

    cleaned: list[Any] = []
    pending_tool_ids: set[str] = set()

    for i, msg in enumerate(messages):
        msg_dict = msg if isinstance(msg, dict) else getattr(msg, "model_dump", lambda: None)()
        if not msg_dict:
            msg_dict = {"role": getattr(msg, "type", "assistant"), "content": str(msg)}
        role = str(msg_dict.get("role", "")).strip().lower()
        tc_list = msg_dict.get("tool_calls") or []

        if role == "assistant" and tc_list:
            # Record pending IDs
            for tc in tc_list:
                tc_id = str(tc.get("id", ""))
                if tc_id:
                    pending_tool_ids.add(tc_id)
            cleaned.append(msg)
        elif role == "tool" or role == "function":
            tc_id = str(msg_dict.get("tool_call_id", ""))
            pending_tool_ids.discard(tc_id)
            cleaned.append(msg)
        else:
            # Non-tool message — if there are pending tool calls,
            # DeepSeek would reject this. Drop the orphaned assistant(tool_calls).
            if pending_tool_ids:
                # Walk back and drop the last pending assistant(tool_calls)
                for j in range(len(cleaned) - 1, -1, -1):
                    c = cleaned[j] if isinstance(cleaned[j], dict) else {"role": "assistant"}
                    if str(c.get("role", "")) == "assistant" and c.get("tool_calls"):
                        cleaned.pop(j)
                        break
                pending_tool_ids.clear()
            # Drop the message content = tool_calls from content dict
            clean_dict = dict(msg_dict)
            clean_dict.pop("tool_calls", None)
            cleaned.append(clean_dict if isinstance(msg, dict) else msg)

    # Final cleanup: drop trailing assistant(tool_calls) with no tool results
    while cleaned:
        last = cleaned[-1] if isinstance(cleaned[-1], dict) else getattr(cleaned[-1], "model_dump", lambda: {})()
        if not last or not isinstance(last, dict):
            break
        if str(last.get("role", "")) == "assistant" and last.get("tool_calls"):
            cleaned.pop()
        else:
            break

    return cleaned


def _reset_per_run_counters() -> None:
    """Reset tool-level counters before each run to prevent cross-run limits."""
    try:
        from vulnagent.tools.vuln_tools import _firmware_emulation_probe
        if hasattr(_firmware_emulation_probe, "_call_count"):
            _firmware_emulation_probe._call_count = 0
    except Exception:
        pass


def _collect_poc_entries(
    discovery_state: dict[str, Any],
    exploit_state: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> list[str]:
    """Collect PoC entries from tool outputs and findings metadata."""
    entries: list[str] = []
    seen_paths: set[str] = set()

    # Scan tool outputs (LLM-called generate_poc)
    for state in (discovery_state, exploit_state):
        for source_map in (dict(state.get("tool_outputs", {}) or {}), dict(state.get("compressed_outputs", {}) or {})):
            for key, value in source_map.items():
                text = str(value or "")
                for match in re.finditer(r"POC_SCRIPT_PATH:\s+([^\r\n]+)", text):
                    poc_path = match.group(1).strip()
                    if poc_path not in seen_paths:
                        seen_paths.add(poc_path)
                        title_match = re.search(r"POC_TITLE:\s+([^\r\n]+)", text)
                        usage_match = re.search(r"POC_USAGE:\s+([^\r\n]+)", text)
                        title = title_match.group(1).strip() if title_match else poc_path
                        usage = usage_match.group(1).strip() if usage_match else f"python {Path(poc_path).name}"
                        entries.append(f"- **{title}**\n  Script: `{poc_path}`\n  Usage: `{usage}`")

    # Scan findings metadata (auto-generated PoCs)
    if metadata:
        for findings_key in ("confirmed_findings", "validated_leads", "candidate_findings"):
            for finding in metadata.get(findings_key, []):
                poc_path = str(finding.get("poc_path", "")).strip() if isinstance(finding, dict) else ""
                if not poc_path or poc_path in seen_paths:
                    continue
                seen_paths.add(poc_path)
                title = str(finding.get("title", poc_path)).strip() if isinstance(finding, dict) else poc_path
                cwe = str(finding.get("cwe_id", "")).strip() if isinstance(finding, dict) else ""
                cvss = str(finding.get("cvss_score", "")).strip() if isinstance(finding, dict) else ""
                tags = f" ({cwe}, CVSS {cvss})" if cwe and cvss else ""
                entries.append(f"- **{title}**{tags}\n  Script: `{poc_path}`\n  Usage: `python {Path(poc_path).name}`")

    return entries


def _auto_generate_pocs_from_findings(metadata: dict[str, Any]) -> None:
    """Generate PoC scripts for all high/critical findings automatically.

    Does NOT depend on LLM tool calls. Runs directly via _generate_poc.
    Works on confirmed > validated > candidate findings, highest severity first.
    """
    from vulnagent.tools.vuln_tools import _generate_poc
    from vulnagent.prompts.remediation_prompts import match_remediation_template

    confirmed = list(metadata.get("confirmed_findings", []))
    validated = list(metadata.get("validated_leads", []))
    candidates = list(metadata.get("candidate_findings", []))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    all_findings = sorted(
        confirmed + validated + candidates,
        key=lambda f: severity_order.get(str(f.get("severity", "")).lower(), 4),
    )

    target = str(metadata.get("target", ""))
    generated = 0
    for finding in all_findings[:10]:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title", "")).strip()
        evidence = list(finding.get("evidence", []))
        if not title:
            continue

        # Only generate PoCs for high/critical severity findings with enough evidence
        severity = str(finding.get("severity", "")).lower()
        if severity not in ("critical", "high"):
            continue
        if not evidence:
            continue
        _infra_kw = ("emulation validation", "emulated firmware service",
                     "filesystem detected", "container detected", "marker cluster",
                     "compressed payload", "route relationship")
        if any(kw in title.lower() for kw in _infra_kw):
            continue
        if finding.get("poc_path"):
            continue  # Already has a PoC

        vuln_type = _infer_poc_vuln_type(title, evidence)
        template = match_remediation_template(title, evidence)
        # Always set CWE/CVSS before PoC generation attempt
        if not finding.get("cwe_id"):
            finding["cwe_id"] = str(template.get("cwe_id", ""))
        if not finding.get("cvss_score"):
            finding["cvss_score"] = str(template.get("cvss_score", ""))
        if not finding.get("cvss_vector"):
            finding["cvss_vector"] = str(template.get("cvss_vector", ""))

        # Build endpoint from finding context
        endpoint = target
        component = str(finding.get("component_path", ""))
        if component and ":" in component:
            endpoint = component

        try:
            payload = (
                "; id > /www/pwned.txt ;"
                if vuln_type == "command_injection"
                else ("admin:admin" if vuln_type == "hardcoded_credentials" else "")
            )
            result = _generate_poc(
                vuln_type=vuln_type,
                target_endpoint=endpoint,
                vuln_title=title,
                payload=payload,
            )
            lines = str(result.stdout or "").splitlines()
            for line in lines:
                if line.startswith("POC_SCRIPT_PATH:"):
                    finding["poc_path"] = line.split(":", 1)[1].strip()
                elif line.startswith("POC_VULN_TYPE:"):
                    finding["poc_vuln_type"] = line.split(":", 1)[1].strip()
            generated += 1
        except Exception:
            pass  # PoC script generation is best-effort; CWE/CVSS are already set

    if generated:
        metadata.setdefault("_auto_poc_count", 0)
        metadata["_auto_poc_count"] += generated


def _infer_poc_vuln_type(title: str, evidence: list[str]) -> str:
    combined = (title + " " + " ".join(evidence)).lower()
    # Check in priority order — command injection before config_import
    if any(kw in combined for kw in ("system(", "dosystem", "systemcommand", "popen",
                                       "shell metacharacter", "command execution", "command injection",
                                       "shell command", "execution marker")):
        return "command_injection"
    if any(kw in combined for kw in ("hardcoded", "default credential", "default password",
                                       "nvram_get", "nvram credential")):
        return "hardcoded_credentials"
    if any(kw in combined for kw in ("auth bypass", "unauthenticated", "missing authentication", "no auth")):
        return "auth_bypass"
    if any(kw in combined for kw in ("buffer overflow", "strcpy", "unbounded", "stack overflow", "format string")):
        return "buffer_overflow"
    if any(kw in combined for kw in ("import_5g", "upload_settings", "config import",
                                       "unsigned config", "signature verific", "tempnam", "import execution")):
        return "config_import"
    # Broader matches (order matters — check these last)
    if any(kw in combined for kw in ("telnetd", "telnet", "ssh", "dropbear")):
        return "hardcoded_credentials"
    if any(kw in combined for kw in ("upload", "cgi", "handler")):
        return "config_import"
    return "generic"


def _auto_generate_cve_package(metadata: dict[str, Any]) -> None:
    """Generate CVE submission package (JSON 5.1 + MITRE form) from findings.

    Triggered when firmware findings include command-injection, buffer-overflow,
    or auth-bypass vulnerabilities with sufficient evidence.  Writes
    ``cve_submission.json`` and ``mitre_form.txt`` into the run's output
    directory so the report phase can reference them.
    """
    confirmed = list(metadata.get("confirmed_findings", []))
    validated = list(metadata.get("validated_leads", []))
    candidates = list(metadata.get("candidate_findings", []))
    all_findings = confirmed + validated + candidates

    # ── Resolve vendor / product / version from metadata ──
    vendor = str(metadata.get("vendor", "") or "")
    product = str(metadata.get("product", "") or metadata.get("target", "") or "")
    version = str(metadata.get("firmware_version", "") or metadata.get("version", "") or "")
    finder = str(metadata.get("finder", "") or metadata.get("discoverer", "") or "Huange")

    # Attempt to extract vendor/product from target string (e.g. "TL-WR841N")
    target = str(metadata.get("target", ""))
    if not vendor and "tp-link" in target.lower():
        vendor = "TP-Link"
    if not product:
        # Try to extract model from target path/string
        import re as _re
        model_match = _re.search(r"[A-Z]{2,4}[-_]\w+\d+", target)
        if model_match:
            product = model_match.group(0).replace("_", "-")

    # ── Gather binary-audit data from tool outputs ──
    audit_data: dict[str, Any] = metadata.get("binary_audit_report", {}) or {}
    if not audit_data:
        # Search tool outputs for audit results
        tool_outputs = dict(metadata.get("tool_outputs", {}) or {})
        for _key, output in tool_outputs.items():
            if isinstance(output, dict) and "findings" in output:
                audit_data = output
                break

    # ── Build synthetic audit data from findings when no direct audit exists ──
    if not audit_data.get("findings") and all_findings:
        audit_data = _synthesize_audit_from_findings(all_findings)

    if not audit_data.get("findings"):
        return  # Nothing to generate

    # ── Build and export ──
    try:
        record = build_cve_from_audit(
            audit_data,
            vendor=vendor,
            product=product,
            version=version,
            finder=finder,
        )
        if record is None:
            return

        from pathlib import Path as _Path
        output_dir = str(metadata.get("output_dir", ""))
        if not output_dir:
            runtime_root = str(metadata.get("runtime_root", ""))
            if runtime_root:
                output_dir = str(_Path(runtime_root) / "reports")
            else:
                output_dir = "reports"

        paths = _export_cve_package(record, output_dir)
        metadata["_cve_package"] = paths
        metadata.setdefault("evidence_log", [])
        metadata["evidence_log"].append(
            f"CVE submission package generated: {paths.get('cve_json', '')}, "
            f"{paths.get('mitre_form', '')}"
        )
    except Exception:
        pass  # CVE packaging is best-effort; never block the pipeline


def _synthesize_audit_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build minimal binary-audit-style dict from LLM findings.

    This allows :func:`build_cve_from_audit` to consume findings that were
    produced by DiscoveryAgent tool calls rather than a formal ELF scan.
    """
    cve_worthy: list[dict[str, Any]] = []
    severity_order = {"critical": 0, "high": 1, "medium": 2}
    for f in sorted(
        findings,
        key=lambda x: severity_order.get(
            str(x.get("severity", "")).lower(), 3
        ),
    ):
        if not isinstance(f, dict):
            continue
        cwe = str(f.get("cwe_id", ""))
        if cwe not in ("CWE-78", "CWE-120", "CWE-287", "CWE-200"):
            continue
        cve_worthy.append({
            "title": str(f.get("title", "")),
            "cwe": cwe,
            "severity": str(f.get("severity", "")),
            "cvss_score": f.get("cvss_score", ""),
            "cvss_vector": f.get("cvss_vector", ""),
            "component_path": str(f.get("component_path", "")),
            "evidence": f.get("evidence", []),
        })

    if not cve_worthy:
        return {}

    return {
        "findings": cve_worthy,
        "scan_type": "llm_discovery",
        "total_binaries_scanned": len(findings),
    }


def _build_remediation_from_poc_entries_text(poc_text: str) -> str:
    """Parse rendered PoC markdown text and extract CWE for remediation."""
    from vulnagent.prompts.remediation_prompts import (
        format_remediation_for_prompt, match_remediation_template,
    )
    seen: set[str] = set()
    blocks: list[str] = []
    # Match lines like: "- **title** (CWE-78, CVSS 9.8)"
    for match in re.finditer(r"\*\*(.+?)\*\*\s*\(?(CWE-\d+)[^)]*\)?", poc_text):
        title = match.group(1).strip()
        cwe = match.group(2).strip()
        if cwe and cwe != "CWE-0" and cwe not in seen:
            seen.add(cwe)
            template = match_remediation_template(title, [])
            blocks.append(format_remediation_for_prompt(template))
    return "\n\n---\n\n".join(blocks) if blocks else ""


def _build_remediation_from_poc_files(poc_entries: list[str]) -> str:
    """Last resort: extract CWE from PoC title annotations to build remediation."""
    from vulnagent.prompts.remediation_prompts import (
        format_remediation_for_prompt, match_remediation_template,
    )
    seen: set[str] = set()
    blocks: list[str] = []
    for entry in poc_entries:
        # Entry format: "- **title** (CWE-xxx, CVSS y.y)\n  Script: ..."
        cwe_match = re.search(r"\(CWE-(\d+),?\s*CVSS\s+([\d.]+)?", entry)
        title_match = re.search(r"\*\*(.+?)\*\*", entry)
        title = title_match.group(1).strip() if title_match else ""
        if not title:
            continue
        cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else ""
        if not cwe_id or cwe_id in seen:
            continue
        seen.add(cwe_id)
        template = match_remediation_template(title, [])
        blocks.append(format_remediation_for_prompt(template))

    return "\n\n---\n\n".join(blocks) if blocks else ""


def _build_remediation_from_tools(discovery_state: dict[str, Any]) -> str:
    """Fallback: build remediation from tool output evidence when metadata findings are sparse."""
    from vulnagent.prompts.remediation_prompts import (
        format_remediation_for_prompt, match_remediation_template,
    )
    # Extract titles from discovery assessment output
    assessment_text = ""
    for k, v in dict(discovery_state.get("tool_outputs", {}) or {}).items():
        assessment_text += str(v or "") + "\n"
    for k, v in dict(discovery_state.get("compressed_outputs", {}) or {}).items():
        assessment_text += str(v or "") + "\n"

    if not assessment_text:
        return ""

    # Infer vulnerability types from evidence keywords
    vuln_signals: dict[str, list[str]] = {}
    for line in assessment_text.splitlines():
        line_lower = line.lower()
        for signal_type, keywords in [
            ("cmd_injection", ["system(", "dosystem", "popen", "shell metacharacter", "command injection"]),
            ("hardcoded", ["hardcoded", "default credential", "default password", "nvram_get"]),
            ("auth_bypass", ["auth bypass", "unauthenticated", "missing authentication"]),
            ("config_import", ["upload", "import_5g", "config import", "tempnam"]),
        ]:
            if any(kw in line_lower for kw in keywords):
                vuln_signals.setdefault(signal_type, []).append(line.strip()[:100])
                break

    if not vuln_signals:
        return ""

    blocks: list[str] = []
    seen: set[str] = set()
    for signal_type, lines in sorted(vuln_signals.items(), key=lambda x: -len(x[1])):
        template = match_remediation_template(signal_type, lines)
        t_cwe = str(template.get("cwe_id", ""))
        if t_cwe and t_cwe != "CWE-0" and t_cwe not in seen:
            seen.add(t_cwe)
            blocks.append(format_remediation_for_prompt(template))

    return "\n\n---\n\n".join(blocks) if blocks else ""


def _build_remediation_blocks(metadata: dict[str, Any]) -> str:
    """Build remediation context blocks from all findings with CWE info."""
    from vulnagent.prompts.remediation_prompts import (
        format_remediation_for_prompt, match_remediation_template,
    )

    confirmed = list(metadata.get("confirmed_findings", []))
    validated = list(metadata.get("validated_leads", []))
    candidates = list(metadata.get("candidate_findings", []))
    all_findings = confirmed + validated + candidates

    if not all_findings:
        return ""

    # Generate remediation from template matching, 1 per unique CWE
    blocks: list[str] = []
    seen: set[str] = set()
    for finding in all_findings[:15]:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title", "")).strip()
        if not title:
            continue
        evidence = finding.get("evidence", [])
        template = match_remediation_template(title, evidence if isinstance(evidence, list) else [])
        t_cwe = str(template.get("cwe_id", ""))
        if not t_cwe or t_cwe == "CWE-0" or t_cwe in seen:
            continue
        seen.add(t_cwe)
        blocks.append(format_remediation_for_prompt(template))

    # Fallback: if no findings matched, generate remediation from HIGH severity findings regardless
    if not blocks:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        for finding in sorted(all_findings, key=lambda f: severity_order.get(str(f.get("severity", "")).lower(), 4)):
            title = str(finding.get("title", "")).strip() if isinstance(finding, dict) else ""
            if not title:
                continue
            template = match_remediation_template(title, finding.get("evidence", []) if isinstance(finding, dict) else [])
            t_cwe = str(template.get("cwe_id", ""))
            if t_cwe and t_cwe != "CWE-0" and t_cwe not in seen:
                seen.add(t_cwe)
                blocks.append(format_remediation_for_prompt(template))
            if len(blocks) >= 3:
                break

    if not blocks:
        return ""

    return "\n\n---\n\n".join(blocks)


def _promote_high_confidence_seed_findings(state: dict[str, Any]) -> None:
    """Auto-promote seed findings with concrete evidence from candidate to validated_leads.

    Seed triage collect_artifact_observations produces findings classified as
    "candidate_findings". Those with concrete evidence (file paths, code snippets)
    should be promoted to "validated_leads" so they appear in the final report.
    """
    meta = state.get("metadata", {}) or {}
    candidates = list(meta.get("candidate_findings", []))
    validated = list(meta.get("validated_leads", []))
    promoted: list[dict[str, Any]] = []

    for f in candidates:
        if not isinstance(f, dict):
            continue
        evidence = f.get("evidence", [])
        title = str(f.get("title", "")).lower()
        # High-signal patterns that indicate a concrete finding
        high_signal = [
            "hardcoded", "default password", "backdoor", "command injection",
            "buffer overflow", "auth bypass", "telnetd", "nvram",
            "system(", "doSystem", "rcS", "inittab", "telnet",
            "credential", "goform", "cgi-bin", ".cgi", ".asp",
        ]
        evidence_str = " ".join(str(e) for e in evidence).lower()
        title_signal = any(k in title for k in high_signal)
        evidence_signal = any(k in evidence_str for k in high_signal)

        if title_signal or evidence_signal:
            f["auto_promoted"] = True
            if f not in validated:
                validated.append(f)
                promoted.append(f.get("title", "unnamed"))

    if promoted:
        meta["validated_leads"] = validated
        state["metadata"] = meta


def _run_validation_backend(
    backend: FirmwareValidationBackend,
    metadata: dict[str, Any],
    artifact: Path,
    tool_outputs: dict[str, str],
    logger: Any,
) -> None:
    """Run the active validation backend against discovered firmware services.

    Works with any FirmwareValidationBackend — EmulationAgent, DirectHardware,
    or StaticOnly. Uploads rootfs (if backend supports it), starts each
    discovered service, probes it, and records VERIFIED/STATIC_ONLY findings.
    """
    if isinstance(backend, StaticOnlyBackend):
        metadata["validation_mode"] = "static_only"
        metadata["validation_note"] = "No validation backend available — all findings are STATIC_ONLY"
        return

    if not backend.is_available():
        metadata["validation_mode"] = "backend_unreachable"
        return

    # Extract rootfs path from manifest
    rootfs_path = ""
    manifest_text = tool_outputs.get("firmware_runtime_manifest", "")
    for line in manifest_text.split("\n"):
        if line.startswith("ROOTFS_PATH:"):
            rootfs_path = line.replace("ROOTFS_PATH:", "").strip()
            break

    if not rootfs_path:
        metadata["validation_mode"] = "no_rootfs"
        return

    # Upload rootfs (DirectHardware skips this)
    try:
        rootfs_id = backend.upload_rootfs(Path(rootfs_path))
    except Exception as e:
        metadata["validation_mode"] = "upload_failed"
        metadata["validation_error"] = str(e)
        return

    # NVRAM config for GoAhead firmware
    try:
        backend.set_nvram_config(rootfs_id, {
            "lan_ipaddr": "192.168.0.1", "http_lanport": "80",
            "Login": "admin", "Password": "admin", "telnetEnabled": "1",
        })
    except Exception:
        pass

    # Parse services from inventory
    inventory_text = tool_outputs.get("firmware_service_inventory", "")
    services = _parse_inventory(inventory_text)
    svc_specs = [
        ServiceToVerify(
            binary_name=s["name"], binary_path=s["path"],
            launch_args=s.get("args", ""), port=s["port"],
            protocol=s.get("protocol", "tcp"),
        )
        for s in services
    ]

    # Validate all services
    results = backend.validate_services(rootfs_id, svc_specs)
    backend.cleanup(rootfs_id)

    # Record results
    verified: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []

    for r in results:
        if r.verified:
            verified.append({
                "service": r.service_name, "port": r.port,
                "evidence": r.evidence, "backend": r.backend,
            })
        else:
            unverified.append({
                "service": r.service_name, "port": r.port,
                "error": r.error or "probe failed",
            })

    if verified:
        cf = metadata.get("confirmed_findings") or []
        if isinstance(cf, list):
            cf.extend([
                make_finding(
                    title=f"VERIFIED: {v['service']} on port {v['port']} ({v['backend']})",
                    severity="high", vuln_type="service_reachable",
                    evidence=[v["evidence"]],
                    component_path=f"tcp://127.0.0.1:{v['port']}",
                    impact="Dynamic verification confirmed — exploit vector reachable",
                )
                for v in verified
            ])
            metadata["confirmed_findings"] = cf
        metadata["emulation_verified"] = True
        metadata["verified_services"] = verified
        logger.info(f"Backend verified {len(verified)} services")

    if unverified:
        metadata["unreachable_services"] = unverified

    metadata["validation_mode"] = getattr(backend, "backend_name", "custom")
    metadata["validation_summary"] = f"{len(verified)} verified, {len(unverified)} unreachable"


def _parse_inventory(text: str) -> list[dict[str, Any]]:
    """Parse SERVICE: and SERVICE_PROBE: lines from inventory output."""
    services: list[dict[str, Any]] = []
    port_map = {"http":80,"telnet":23,"ssh":22,"upnp":1900,"dns":53,"ntp":123}
    for line in text.split("\n"):
        if line.startswith("SERVICE:"):
            p = line.replace("SERVICE:","").strip().split("::")
            if len(p) >= 3:
                stype = p[0].strip()
                services.append({"name":p[1].strip(),"type":stype,"path":p[2].strip(),
                    "port":port_map.get(stype,80),"protocol":"http" if stype=="http" else "tcp"})
        if line.startswith("SERVICE_PROBE:"):
            p = line.replace("SERVICE_PROBE:","").strip().split("::")
            if len(p) >= 3:
                for s in services:
                    if s["name"] == p[0].strip(): s["probe_endpoint"] = p[2].strip()
    return services


def _build_seed_triage_summary(state: dict[str, Any]) -> str:
    """Build a human-readable summary of seed triage results for agent context.

    Prevents agents from re-running file_identify/binwalk/strings/extract
    that were already completed during seed_local_artifact_triage.
    """
    meta = state.get("metadata", {}) or {}
    lines = ["[SYSTEM] Seed triage already completed. Reuse the following:"]
    lines.append("- file_identify, binwalk_scan, strings_extract: DONE")
    lines.append("- firmware_extract_rootfs/firmware_extract_summary: DONE (if applicable)")

    arch = meta.get("manifest_arch", "")
    endian = meta.get("manifest_endian", "")
    if arch:
        lines.append(f"- Architecture determined: {arch}/{endian}")

    web_roots = meta.get("web_roots", [])
    if web_roots:
        lines.append(f"- Web roots found: {web_roots}")

    interpreters = meta.get("interpreters", [])
    if interpreters:
        lines.append(f"- Interpreters: {interpreters[:5]}")

    priority = meta.get("priority_targets", [])
    if priority:
        lines.append(f"- Priority targets from seed scan: {len(priority)} items")

    svcs = meta.get("services", [])
    if svcs:
        svc_str = ", ".join(
            f"{s.get('name','')}:{s.get('type','')}(p{s.get('port','')})"
            for s in svcs[:5]
        )
        lines.append(f"- Detected services: {svc_str}")

    evidence = meta.get("evidence_log", [])
    if evidence:
        lines.append(f"- Evidence items collected: {len(evidence)}")

    lines.append("- DO NOT re-run file_identify, binwalk_scan, strings_extract, or firmware_extract_rootfs.")
    lines.append("- Start with firmware_runtime_manifest to get structured info, then firmware_read_path to inspect specific files.")

    return "\n".join(lines)


def _should_run_brainstorm(state: dict[str, Any]) -> bool:
    """Brainstorm only when the seed phase uncovered a real firmware filesystem.

    Requires BOTH artifact provenance AND a successful firmware extraction
    (SquashFS/JFFS2/etc. with interesting paths or binaries), not just
    surface markers. This avoids triggering on empty or non-firmware files.
    """
    metadata = state.get("metadata", {}) or {}
    provenance = str(metadata.get("provenance", "")).strip()
    if not provenance.startswith("artifact:"):
        return False
    text_blob = "\n".join(
        str(v) for v in dict(state.get("tool_outputs", {}) or {}).values() if v
    ).lower()
    # Require a filesystem type AND at least one concrete artifact
    fs_markers = ("squashfs", "jffs2", "cramfs", "cpio", "initramfs")
    has_fs = any(m in text_blob for m in fs_markers)
    concrete_markers = (
        "/bin/goahead", "/etc_ro/", "telnetd", "cgi-bin",
        "lighttpd", "busybox", "httpd", "passwd",
    )
    has_concrete = any(m in text_blob for m in concrete_markers)
    return has_fs and has_concrete


def _load_known_bugs_from_state(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect already-confirmed findings to serve as the dedup baseline.

    Pulls from metadata.confirmed_findings and metadata.validated_leads.
    Returns compact dicts suitable for build_judge_prompt comparison.
    """
    metadata = state.get("metadata", {}) or {}
    existing = list(metadata.get("confirmed_findings", [])) + list(metadata.get("validated_leads", []))
    # Deduplicate internal to the baseline
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for f in existing:
        if not isinstance(f, dict):
            continue
        title = str(f.get("title", "")).strip()
        if not title or title in seen:
            continue
        seen.add(title)
        result.append(f)
    return result
