"""Tests for B.3 verification pipeline + B.7 patch grader."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vulnagent.verification.layers import VerificationPipeline
from vulnagent.verification.parser import PocParser
from vulnagent.verification.interceptor import KeywordInterceptor
from vulnagent.verification.patch_grade import PatchGrader


class TestVerificationPipeline:
    def test_rejects_no_poc(self):
        p = VerificationPipeline()
        r = p.verify({"title": "version disclosure", "description": "found via banner"})
        assert not r.passed
        assert r.failed_at == 2

    def test_rejects_cors_garbage(self):
        p = VerificationPipeline()
        r = p.verify({
            "title": "CORS misconfiguration",
            "executable_command": "curl -H 'Origin: x' http://t",
        })
        assert not r.passed
        assert r.failed_at == 3

    def test_accepts_valid_cmd_injection(self):
        p = VerificationPipeline()
        r = p.verify({
            "title": "Command injection in upload.cgi",
            "description": "sends shell commands via POST",
            "executable_command": "curl http://t/cgi-bin/upload.cgi -d '$(id)'",
        })
        assert r.passed
        assert r.failed_at == 0

    def test_l1_advisory_not_blocking(self):
        p = VerificationPipeline()
        r = p.verify(
            {"title": "cmd injection", "executable_command": "curl http://t -d test"},
            ai_self_check_passed=False,
        )
        assert r.l1_self_check is not None
        assert not r.l1_self_check.passed
        assert r.l2_parse is not None
        assert r.l2_parse.passed


class TestPocParser:
    def test_extracts_xml_tagged_command(self):
        parser = PocParser()
        text = "<executable_command>curl http://t -d test</executable_command>"
        poc = parser.parse(text)
        assert poc is not None
        assert poc.executable_command == "curl http://t -d test"

    def test_extracts_fallback_curl(self):
        parser = PocParser()
        text = "Run: curl http://target/admin -H 'Cookie: admin=true'"
        poc = parser.parse(text)
        assert poc is not None
        assert "curl" in poc.executable_command

    def test_returns_none_for_empty(self):
        parser = PocParser()
        assert parser.parse("") is None
        assert parser.parse("no command here") is None


class TestKeywordInterceptor:
    def test_matches_cors(self):
        i = KeywordInterceptor()
        assert i.check("CORS misconfiguration", "Access-Control") == "cors_configuration"

    def test_matches_self_xss(self):
        i = KeywordInterceptor()
        assert i.check("Self-XSS in profile", "stored self-xss") == "self_xss"

    def test_clean_finding_passes(self):
        i = KeywordInterceptor()
        assert i.check("Command injection in upload.cgi", "") == ""


class TestPatchGrader:
    def test_t0_rejects_empty_commands(self):
        grader = PatchGrader()
        result = grader.grade({"title": "test"}, "")
        assert not result.overall_passed
        assert result.t0 is not None
        assert not result.t0.passed

    def test_t0_rejects_dangerous(self):
        grader = PatchGrader()
        result = grader.grade({"title": "test"}, "rm -rf /")
        assert not result.overall_passed

    def test_t0_accepts_safe(self):
        grader = PatchGrader()
        result = grader.grade({"title": "test"}, "echo patch applied")
        assert result.t0.passed

    def test_full_ladder_ok(self):
        grader = PatchGrader()
        result = grader.grade(
            {"title": "cmd injection fix"},
            "echo patched",
            target="firmware.bin",
        )
        assert result.overall_passed
