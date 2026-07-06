"""Tests for CTF flag extraction."""

from __future__ import annotations

import unittest

from common.verification.flag_checker import FlagExtractor


class TestFlagExtractor(unittest.TestCase):
    def test_extracts_standard_flag(self) -> None:
        extractor = FlagExtractor()
        self.assertEqual(extractor.extract("done: flag{real_demo}"), ["flag{real_demo}"])

    def test_extracts_flag_after_flag_is_prefix(self) -> None:
        extractor = FlagExtractor()
        self.assertEqual(extractor.extract("The flag is: flag{real_demo}"), ["flag{real_demo}"])

    def test_extracts_custom_ctf_prefix(self) -> None:
        extractor = FlagExtractor()
        self.assertEqual(extractor.extract("answer: TeamCTF{custom_demo}"), ["TeamCTF{custom_demo}"])

    def test_extracts_lowercase_custom_ctf_prefix(self) -> None:
        extractor = FlagExtractor()
        self.assertEqual(extractor.extract("answer: uiuctf{custom_demo}"), ["uiuctf{custom_demo}"])

    def test_extracts_cube_prefix(self) -> None:
        extractor = FlagExtractor()
        self.assertEqual(extractor.extract("answer: cube{demo_flag}"), ["cube{demo_flag}"])

    def test_rejects_gzctf_md5_submission_placeholder(self) -> None:
        extractor = FlagExtractor()
        text = "Flag content should be md5-wrapped before submit, for example cube{md5(flag_inner)}."
        self.assertEqual(extractor.extract(text), [])

    def test_rejects_ctf_prefix_ellipsis_placeholder(self) -> None:
        extractor = FlagExtractor()
        self.assertEqual(extractor.extract("Expected format: ISCTF{...}"), [])

    def test_rejects_handoff_only_ellipsis_placeholder_after_tools(self) -> None:
        extractor = FlagExtractor()
        result = extractor.extract_from_state({
            "messages": [],
            "executed_tools": [{"name": "submit_handoff"}],
            "tool_outputs": {
                "submit_handoff": (
                    "worker_handoff: recover and submit the real flag in format ISCTF{...}"
                )
            },
            "compressed_outputs": {},
            "anchored_summary": {},
            "final_result": None,
        })

        self.assertFalse(result.found)
        self.assertEqual(result.candidates, [])

    def test_rejects_css_pseudo_selector_false_positive(self) -> None:
        extractor = FlagExtractor()
        text = "CSS contains ::-webkit-outer-spin-button{height:auto}"
        self.assertEqual(extractor.extract(text), [])

    def test_rejects_plain_word_after_flag_is(self) -> None:
        extractor = FlagExtractor()
        self.assertEqual(extractor.extract("The flag is found."), [])

    def test_extracts_from_raw_tool_outputs_when_compressed_output_loses_flag(self) -> None:
        extractor = FlagExtractor()
        result = extractor.extract_from_state({
            "messages": [],
            "tool_outputs": {"browser_request": "raw response ISCTF{raw_tool_flag}"},
            "compressed_outputs": {"browser_request": "summary without candidate"},
            "anchored_summary": {},
            "final_result": None,
        })

        self.assertTrue(result.found)
        self.assertEqual(result.flag, "ISCTF{raw_tool_flag}")

    def test_prefers_specific_ctf_prefix_over_model_reformatted_flag(self) -> None:
        extractor = FlagExtractor()
        result = extractor.extract_from_state({
            "messages": [
                type("Msg", (), {
                    "content": (
                        "Candidate from response: ISCTF{ab2916f9-e3ed-44c2-9962-7c226ba6162c}\n"
                        "I think final submit should be flag{ab2916f9-e3ed-44c2-9962-7c226ba6162c}"
                    )
                })()
            ],
            "tool_outputs": {
                "browser_probe_paths": "raw response ISCTF{ab2916f9-e3ed-44c2-9962-7c226ba6162c}"
            },
            "compressed_outputs": {},
            "anchored_summary": {},
            "final_result": None,
        })

        self.assertTrue(result.found)
        self.assertEqual(result.flag, "ISCTF{ab2916f9-e3ed-44c2-9962-7c226ba6162c}")

    def test_rejects_message_only_stale_flag_after_tool_execution(self) -> None:
        extractor = FlagExtractor()
        result = extractor.extract_from_state({
            "messages": [
                type("Msg", (), {"content": "I think the flag is ISCTF{old_challenge_flag}"})()
            ],
            "executed_tools": [{"name": "browser_gzctf_start_web_challenge"}],
            "tool_outputs": {
                "browser_gzctf_start_web_challenge": (
                    '{"challenge":{"id":1124,"title":"Who am I"},'
                    '"flag_candidates":[],"initial_http":{"snippet":"login page"}}'
                )
            },
            "compressed_outputs": {},
            "anchored_summary": {},
            "final_result": None,
        })

        self.assertFalse(result.found)
        self.assertEqual(result.candidates, [])

    def test_rejects_partial_flag_markers_inside_structured_tool_json(self) -> None:
        extractor = FlagExtractor()
        result = extractor.extract_from_state({
            "messages": [],
            "tool_outputs": {
                "browser_attack_php_unserialize": (
                    '{"success_indicators":["isctf{","ctf{"],'
                    '"snippet":"object(FLAG)#1 { string(34) \\";}var_dump(...);/*\\" } '
                    'ISCTF{af60453b-fc1e-4063-93fc-103d4d2a520f}\\n"}'
                )
            },
            "compressed_outputs": {},
            "anchored_summary": {},
            "final_result": None,
        })

        self.assertTrue(result.found)
        self.assertEqual(result.flag, "ISCTF{af60453b-fc1e-4063-93fc-103d4d2a520f}")
        self.assertNotIn('isctf{","ctf{"', result.candidates)

    def test_extracts_flag_after_json_escaped_tab_without_escape_prefix(self) -> None:
        extractor = FlagExtractor()
        result = extractor.extract_from_state({
            "messages": [],
            "tool_outputs": {
                "browser_attack_php_unserialize": (
                    'string(51) "     1\\tISCTF{af60453b-fc1e-4063-93fc-103d4d2a520f}\\n"'
                )
            },
            "compressed_outputs": {},
            "anchored_summary": {},
            "final_result": None,
        })

        self.assertTrue(result.found)
        self.assertEqual(result.flag, "ISCTF{af60453b-fc1e-4063-93fc-103d4d2a520f}")
        self.assertNotIn("tISCTF{af60453b-fc1e-4063-93fc-103d4d2a520f}", result.candidates)


if __name__ == "__main__":
    unittest.main()
