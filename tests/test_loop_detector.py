"""Tests for B.2 loop failure detection — drift, forgetting, pseudo-completion."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vulnagent.loop.detector import FailureDetector, FailureMode, FailureSignal
from vulnagent.loop.manager import LoopManager


class TestFailureDetector:
    def test_direction_drift_detected(self):
        detector = FailureDetector()
        sig = None
        for i in range(1, 6):
            sig = detector.detect(
                "discovery",
                ["generate_poc exploit shellcode payload rop reverse_shell"],
                round_count=i, direction_elapsed=100, session_elapsed=i * 30,
            )
        assert sig.mode == FailureMode.DIRECTION_DRIFT
        assert sig.confidence > 0.3

    def test_exploit_drift_detected(self):
        detector = FailureDetector()
        sig = None
        for i in range(1, 6):
            sig = detector.detect(
                "exploit",
                ["nmap scan ports 22 80 443", "gobuster dir /admin", "whatweb Apache"],
                round_count=i, direction_elapsed=100, session_elapsed=i * 30,
            )
        assert sig.mode == FailureMode.DIRECTION_DRIFT

    def test_rule_forgetting_after_25_rounds(self):
        detector = FailureDetector()
        sig = None
        for i in range(1, 30):
            sig = detector.detect(
                "discovery", ["normal analysis output"],
                round_count=i, direction_elapsed=100, session_elapsed=i * 60,
            )
        assert sig.mode == FailureMode.RULE_FORGETTING

    def test_normal_output_no_failure(self):
        detector = FailureDetector()
        sig = detector.detect(
            "brainstorm",
            ["analyzing SquashFS filesystem", "found CGI endpoints at /cgi-bin/"],
            round_count=2, direction_elapsed=30, session_elapsed=60,
        )
        assert sig.mode == FailureMode.NONE

    def test_detector_reset(self):
        detector = FailureDetector()
        detector._empty_rounds = 5
        detector._recent_output_hashes = [1, 2, 3]
        detector.reset()
        assert detector._empty_rounds == 0
        assert len(detector._recent_output_hashes) == 0


class TestLoopManager:
    def test_session_lifecycle(self):
        mgr = LoopManager()
        assert mgr.state.value == "terminated"
        mgr.start_session("discovery")
        assert mgr.state.value == "running"
        assert mgr.round_count == 0

    def test_handle_drift_failure(self):
        mgr = LoopManager()
        mgr.start_session("discovery")
        drift = FailureSignal(mode=FailureMode.DIRECTION_DRIFT, confidence=0.8, evidence="drift")
        event = mgr.handle_failure(drift)
        assert event is not None
        assert event.trigger == "direction_drift"
        assert mgr._injector.injection_counts.get("direction_drift", 0) == 1

    def test_handle_pseudo_completion(self):
        mgr = LoopManager()
        mgr.start_session("exploit")
        pseudo = FailureSignal(mode=FailureMode.PSEUDO_COMPLETION, confidence=0.7)
        event = mgr.handle_failure(pseudo)
        assert event is not None
        assert event.trigger == "pseudo_completion"

    def test_should_restart_at_50(self):
        mgr = LoopManager()
        mgr.start_session("discovery")
        for _ in range(50): mgr.after_iteration()
        assert mgr.should_restart()

    def test_should_not_restart_early(self):
        mgr = LoopManager()
        mgr.start_session("discovery")
        for _ in range(10): mgr.after_iteration()
        assert not mgr.should_restart()

    def test_round_count_tracking(self):
        mgr = LoopManager()
        mgr.start_session("discovery")
        for _ in range(7): mgr.after_iteration()
        assert mgr.round_count == 7

    def test_snapshot_preserves_state(self):
        mgr = LoopManager()
        mgr.start_session("exploit")
        for _ in range(3): mgr.after_iteration()
        snap = mgr.take_snapshot()
        assert snap.round_count == 3
        assert snap.direction == "exploit"
