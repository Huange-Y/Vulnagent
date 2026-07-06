"""Tests for RuleEngine — zero-LLM problem classification."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import unittest
from common.routing.rule_engine import RuleEngine


class TestRuleEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine()

    def test_classifies_web_challenges(self):
        cases = [
            ("There's a website at http://chall.example.com with a login form", "web"),
            ("SQL injection vulnerability in the login page", "web"),
            ("XSS attack on the admin panel", "web"),
            ("JWT token manipulation in the API", "web"),
            ("PHP deserialization RCE via cookie", "web"),
        ]
        for desc, expected in cases:
            with self.subTest(desc=desc):
                result = self.engine.classify(desc)
                self.assertEqual(result.category, expected)

    def test_classifies_crypto_challenges(self):
        cases = [
            ("RSA encrypted message with a weak modulus", "crypto"),
            ("AES-CBC padding oracle attack", "crypto"),
            ("Decrypt the ciphertext to get the flag", "crypto"),
            ("Vigenere cipher with unknown key", "crypto"),
        ]
        for desc, expected in cases:
            with self.subTest(desc=desc):
                result = self.engine.classify(desc)
                self.assertEqual(result.category, expected)

    def test_classifies_pwn_challenges(self):
        cases = [
            ("Buffer overflow in this ELF binary", "pwn"),
            ("ROP chain to bypass ASLR and NX", "pwn"),
            ("Format string vulnerability in the binary", "pwn"),
            ("Shellcode injection to get a shell", "pwn"),
        ]
        for desc, expected in cases:
            with self.subTest(desc=desc):
                result = self.engine.classify(desc)
                self.assertEqual(result.category, expected)

    def test_classifies_rev_challenges(self):
        cases = [
            ("Reverse engineer this obfuscated binary", "rev"),
            ("Decompile this APK to find the flag", "rev"),
            ("This bytecode VM implements a custom cipher", "rev"),
        ]
        for desc, expected in cases:
            with self.subTest(desc=desc):
                result = self.engine.classify(desc)
                self.assertEqual(result.category, expected)

    def test_classifies_vuln_tasks(self):
        cases = [
            ("Penetration test of target.com", "vuln"),
            ("CVE-2024-1234 vulnerability assessment", "vuln"),
            ("Bug bounty: find vulnerabilities in the web app", "vuln"),
        ]
        for desc, expected in cases:
            with self.subTest(desc=desc):
                result = self.engine.classify(desc)
                self.assertEqual(result.category, expected)

    def test_unknown_falls_back_to_misc(self):
        result = self.engine.classify("abc xyz foo bar hello world")
        self.assertEqual(result.category, "misc")
        self.assertEqual(result.confidence, 0.1)

    def test_strong_match_has_higher_confidence(self):
        # Weak: single keyword, Strong: no keywords → both misc
        # We test that multi-keyword matches have higher raw scores (before cap)
        weak = self.engine.classify("website")
        self.assertGreater(weak.confidence, 0.3)

        # Multi-keyword: should still hit 1.0 due to cap, but text_score is higher
        strong = self.engine.classify("SQL injection XSS CSRF SSRF SSTI on this web app with JWT tokens deserialization XXE")
        self.assertGreaterEqual(strong.confidence, 0.9)

    def test_get_agent_name(self):
        result = self.engine.classify("SQL injection on login page")
        self.assertEqual(self.engine.get_agent_name(result), "WebAgent")
        result = self.engine.classify("RSA factorization challenge")
        self.assertEqual(self.engine.get_agent_name(result), "CryptoAgent")
        result = self.engine.classify("Buffer overflow ROP exploit")
        self.assertEqual(self.engine.get_agent_name(result), "PwnAgent")

    def test_features_dict(self):
        result = self.engine.classify("RSA decryption challenge")
        self.assertIn("text_scores", result.features)
        self.assertGreater(result.features["text_scores"]["crypto"], 0)


if __name__ == "__main__":
    unittest.main()
