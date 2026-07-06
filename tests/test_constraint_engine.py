"""Tests for B.1 constraint engine — command gate, finding gate, timing gate."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vulnagent.constraints.engine import ConstraintEngine


class TestCommandGate:
    def test_allows_safe_commands(self):
        engine = ConstraintEngine()
        assert engine.check_command("nmap -sV 192.168.1.1").allowed
        assert engine.check_command("curl http://target").allowed
        assert engine.check_command("qemu-mipsel-static ./busybox").allowed

    def test_blocks_dangerous_commands(self):
        engine = ConstraintEngine()
        r = engine.check_command("rm -rf / --no-preserve-root")
        assert not r.allowed

    def test_blocks_fork_bomb(self):
        engine = ConstraintEngine()
        r = engine.check_command(":(){ :|:& };:")
        assert not r.allowed

    def test_empty_command_allowed(self):
        engine = ConstraintEngine()
        assert engine.check_command("").allowed


class TestFindingGate:
    def test_rejects_info_leak(self):
        engine = ConstraintEngine()
        v = engine.check_finding("version disclosure", "found busybox 1.22.1 via banner info leak")
        assert not v.accepted
        assert v.matched_category == "garbage_list"

    def test_rejects_no_poc(self):
        engine = ConstraintEngine()
        v = engine.check_finding("possible buffer overflow", "no concrete exploit yet")
        assert not v.accepted
        assert v.matched_category == "no_poc"

    def test_accepts_valid_finding_with_poc(self):
        engine = ConstraintEngine()
        v = engine.check_finding(
            "Command injection in upload.cgi",
            "sends malicious input via POST",
            "curl http://target/cgi-bin/upload.cgi -d ';id;'"
        )
        assert v.accepted

    def test_accepts_qemu_poc(self):
        engine = ConstraintEngine()
        v = engine.check_finding(
            "Buffer overflow in httpd",
            "qemu-mipsel -L . ./httpd -p 8080",
        )
        assert v.accepted


class TestTimingGate:
    def test_session_starts_clean(self):
        engine = ConstraintEngine()
        engine.start_session()
        t = engine.check_timing()
        assert t.should_continue
        assert not t.should_switch_direction

    def test_records_rounds(self):
        engine = ConstraintEngine()
        engine.start_session()
        for _ in range(5):
            engine.record_round()
        assert engine.round_count == 5


class TestCheatCard:
    def test_cheat_card_non_empty(self):
        engine = ConstraintEngine()
        card = engine.get_cheat_card_text()
        assert len(card) > 0

    def test_decision_tree_match(self):
        engine = ConstraintEngine()
        hint = engine.get_direction_hint("SquashFS + Web CGI endpoints found in firmware")
        assert len(hint) > 0

    def test_hard_rules_loaded(self):
        engine = ConstraintEngine()
        assert len(engine.hard_rules) > 0
