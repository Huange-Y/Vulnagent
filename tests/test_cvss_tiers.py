"""Tests for B.8 CVSS calculator + tier manager + source-to-sink tracer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vulnagent.core.risk import CVSSCalculator, score_finding
from vulnagent.core.tiers import TierManager, Tier, TierResult, Confidence
from vulnagent.analysis.trace import SourceToSinkTracer


class TestCVSSCalculator:
    def test_cwe78_command_injection(self):
        score = CVSSCalculator.calculate({"cwe_id": "CWE-78", "title": "cmd injection"})
        assert score.base_score == 9.8
        assert score.severity == "critical"

    def test_cwe200_info_leak(self):
        score = CVSSCalculator.calculate({"cwe_id": "CWE-200", "title": "info leak"})
        assert score.base_score == 5.3
        assert score.severity == "medium"

    def test_cwe287_auth_bypass(self):
        score = CVSSCalculator.calculate({"cwe_id": "CWE-287", "title": "auth bypass"})
        assert score.severity == "critical"

    def test_network_adjustment(self):
        remote = CVSSCalculator.calculate({"cwe_id": "CWE-78", "title": "x"}, network_exposed=True)
        local = CVSSCalculator.calculate({"cwe_id": "CWE-78", "title": "x"}, network_exposed=False)
        assert local.base_score < remote.base_score

    def test_infer_from_title(self):
        score = CVSSCalculator.calculate({"title": "remote code execution in httpd"})
        assert score.severity == "critical"

    def test_score_finding_modifies_in_place(self):
        finding = {"title": "buffer overflow", "cwe_id": "CWE-120"}
        score_finding(finding)
        assert finding["cvss_score"] == "9.8"
        assert finding["severity"] == "critical"
        assert "cvss_vector" in finding


class TestTierManager:
    def test_configs_exist(self):
        tm = TierManager()
        assert tm.get_config(Tier.SURFACE).confidence == Confidence.LOW
        assert tm.get_config(Tier.STATIC).confidence == Confidence.MEDIUM
        assert tm.get_config(Tier.DYNAMIC).confidence == Confidence.HIGH

    def test_gate_blocks_no_targets(self):
        tm = TierManager()
        tm.record_result(TierResult(
            tier=Tier.SURFACE, confidence=Confidence.LOW,
            findings_count=0, priority_targets_count=0, tokens_used=100,
        ))
        proceed, reason = tm.should_proceed(Tier.SURFACE)
        assert not proceed
        assert "skip" in reason.lower()

    def test_gate_allows_with_targets(self):
        tm = TierManager()
        tm.record_result(TierResult(
            tier=Tier.SURFACE, confidence=Confidence.LOW,
            findings_count=0, priority_targets_count=3, tokens_used=100,
        ))
        proceed, _ = tm.should_proceed(Tier.SURFACE)
        assert proceed

    def test_annotate_finding_adds_tier(self):
        tm = TierManager()
        finding = {"title": "test"}
        tm.annotate_finding(finding, Tier.STATIC)
        assert finding["confidence"] == "medium"
        assert finding["tier"] == 2

    def test_static_to_dynamic_gating(self):
        tm = TierManager()
        tm.record_result(TierResult(
            tier=Tier.STATIC, confidence=Confidence.MEDIUM,
            findings_count=0, priority_targets_count=0, tokens_used=500,
        ))
        proceed, _ = tm.should_proceed(Tier.STATIC)
        assert not proceed


class TestSourceToSinkTracer:
    def test_traces_sources_and_sinks(self):
        paths = SourceToSinkTracer.trace_from_tool_outputs({
            "strings": "system( nvram_get( strcpy( websGetVar(",
        })
        assert len(paths) > 0
        sources = {p.source.name for p in paths if p.source}
        sinks = {p.sink.name for p in paths if p.sink}
        assert len(sources) >= 2  # websGetVar + nvram_get
        assert len(sinks) >= 2    # system + strcpy

    def test_critical_paths_identified(self):
        paths = SourceToSinkTracer.trace_from_tool_outputs({
            "strings": "system( websGetVar(",
        })
        critical = [p for p in paths if p.risk_level == "critical"]
        assert len(critical) > 0

    def test_empty_output_no_paths(self):
        paths = SourceToSinkTracer.trace_from_tool_outputs({"empty": ""})
        assert len(paths) == 0
