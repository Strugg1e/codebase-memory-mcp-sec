"""End-to-end tests against the real vendored Java parser; no recorded responses."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else ""
SOURCE = b'''import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.security.access.prepost.PreAuthorize;
class Example {
  @GetMapping("/orders") @PreAuthorize("isAuthenticated()")
  void run(String input) { save(input); save("constant"); many(1,2,3,4,5,6,7,8,9); }
  void save(String value) {} void save(int value) {}
  void many(int... values) {}
}
'''

class EvidenceCLI(unittest.TestCase):
    def run_tool(self, source: bytes = SOURCE, *args: str, ok: bool = True, path: str = "src/Example.java") -> dict:
        result = subprocess.run([BINARY, "--path", path, *args], input=source, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0 if ok else 2, result.stderr.decode("utf-8", "replace"))
        return json.loads(result.stdout)

    @staticmethod
    def calls(data: dict, name: str) -> list[dict]:
        return [f for f in data["facts"] if f["kind"] == "call_site" and f.get("name", {}).get("text_prefix") == name]

    def test_independent_calls_on_one_line(self):
        data = self.run_tool()
        calls = self.calls(data, "save")
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0]["id"], calls[1]["id"])
        self.assertEqual(calls[0]["location"]["start_line"], calls[1]["location"]["start_line"])
        self.assertEqual([f["arguments"][0]["location"]["text_prefix"] for f in calls], ["input", '"constant"'])
        self.assertTrue(all(f["target_resolution"] == "not_attempted" for f in calls))

    def test_more_than_eight_arguments(self):
        call = self.calls(self.run_tool(), "many")[0]
        self.assertEqual(call["argument_total"], 9)
        self.assertEqual(len(call["arguments"]), 9)
        self.assertFalse(call["arguments_truncated"])
        self.assertEqual(call["arguments"][-1]["location"]["text_prefix"], "9")

    def test_argument_limit_is_visible(self):
        source = b"class X { void f(){ many(" + b",".join([b"1"] * 257) + b"); }}"
        call = self.calls(self.run_tool(source), "many")[0]
        self.assertEqual(call["argument_total"], 257)
        self.assertEqual(len(call["arguments"]), 256)
        self.assertTrue(call["arguments_truncated"])

    def test_overloaded_declarations_do_not_merge(self):
        data = self.run_tool()
        methods = [f for f in data["facts"] if f["kind"] == "method_declaration" and f["name"]["text_prefix"] == "save"]
        self.assertEqual(len(methods), 2)
        self.assertNotEqual(methods[0]["id"], methods[1]["id"])

    def test_annotation_is_not_protection_proof(self):
        data = self.run_tool()
        annotations = [f for f in data["facts"] if f["kind"] == "annotation"]
        self.assertEqual(len(annotations), 2)
        self.assertTrue(all(f["security_effect"] == "not_evaluated" for f in annotations))
        self.assertTrue(all(f["basis"] == "syntax_observation" for f in annotations))
        ids = {f["id"] for f in data["facts"]}
        self.assertTrue(all(f["enclosing_id"] in ids for f in annotations))

    def test_custom_annotation_is_not_claimed_as_spring(self):
        data = self.run_tool(b"@interface GetMapping {} class X { @GetMapping void f() {} }")
        annotations = [f for f in data["facts"] if f["kind"] == "annotation"]
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]["security_effect"], "not_evaluated")
        self.assertNotIn("protected", json.dumps(data))

    def test_exact_source_and_locations(self):
        data = self.run_tool()
        self.assertEqual(data["source"]["sha256"], hashlib.sha256(SOURCE).hexdigest())
        for fact in data["facts"]:
            locations = [fact["location"], *(a["location"] for a in fact.get("arguments", []))]
            for loc in locations:
                raw = SOURCE[loc["start_byte"]:loc["end_byte"]]
                preview = loc["text_prefix"].encode("utf-8")
                self.assertTrue(raw.startswith(preview))
                self.assertEqual(len(preview), loc["text_bytes_returned"])
                if not loc["text_truncated"]:
                    self.assertEqual(raw, preview)

    def test_repeatability(self):
        self.assertEqual(self.run_tool(), self.run_tool())

    def test_paging_is_complete_without_duplicates(self):
        expected = self.run_tool()
        page = self.run_tool(SOURCE, "--limit", "2")
        ids = []
        for _ in range(100):
            ids.extend(f["id"] for f in page["facts"])
            if not page["page"]["has_more"]:
                break
            page = self.run_tool(SOURCE, "--limit", "2", "--offset", str(page["page"]["next_offset"]),
                                 "--expect-analysis", page["analysis_id"])
        else:
            self.fail("pagination did not terminate")
        self.assertEqual(ids, [f["id"] for f in expected["facts"]])
        self.assertEqual(len(ids), len(set(ids)))

    def test_continuation_requires_identity(self):
        data = self.run_tool(SOURCE, "--offset", "1", ok=False)
        self.assertEqual(data["error"]["code"], "analysis_id_required")

    def test_changed_source_and_path_reject_old_identity(self):
        old = self.run_tool()["analysis_id"]
        for source, path in ((SOURCE + b"\n", "src/Example.java"), (SOURCE, "Other.java")):
            with self.subTest(path=path):
                data = self.run_tool(source, "--expect-analysis", old, ok=False, path=path)
                self.assertEqual(data["error"]["code"], "analysis_mismatch")

    def test_get_one_fact(self):
        data = self.run_tool()
        wanted = self.calls(data, "many")[0]
        result = self.run_tool(SOURCE, "--fact-id", wanted["id"], "--expect-analysis", data["analysis_id"])
        self.assertEqual(result["facts"], [wanted])
        self.assertFalse(result["page"]["has_more"])

    def test_unknown_fact_is_not_an_empty_success(self):
        data = self.run_tool()
        result = self.run_tool(SOURCE, "--fact-id", "a" * 64, "--expect-analysis", data["analysis_id"], ok=False)
        self.assertEqual(result["error"]["code"], "fact_not_found_in_extracted_scope")

    def test_comments_and_string_contents_are_not_calls(self):
        source = b'class X { void f() { /* fake(1); */ String x = "fake(2)"; real(3); } }'
        data = self.run_tool(source)
        self.assertEqual(self.calls(data, "fake"), [])
        self.assertEqual(len(self.calls(data, "real")), 1)

    def test_nested_calls_and_constructor(self):
        data = self.run_tool(b"class X { void f() { outer(inner(1)); new X(); } }")
        self.assertEqual(len(self.calls(data, "outer")), 1)
        self.assertEqual(len(self.calls(data, "inner")), 1)
        self.assertTrue(any(f["syntax_kind"] == "object_creation_expression" for f in data["facts"]))

    def test_comments_are_not_arguments(self):
        data = self.run_tool(b"class X { void f() { go(1, /* note */ 2); } }")
        self.assertEqual(self.calls(data, "go")[0]["argument_total"], 2)

    def test_unicode_positions_and_preview(self):
        source = ('class 示例 { void f() { save("' + '中' * 200 + '"); } }').encode()
        call = self.calls(self.run_tool(source, path="src/示例.java"), "save")[0]
        loc = call["arguments"][0]["location"]
        preview = loc["text_prefix"].encode()
        self.assertTrue(source[loc["start_byte"]:loc["end_byte"]].startswith(preview))
        self.assertTrue(loc["text_truncated"])
        self.assertLessEqual(len(preview), 256)

    def test_parse_gaps_are_visible(self):
        data = self.run_tool(b"class X { void f( { broken( ; }")
        self.assertTrue(data["coverage"]["parse_has_error"])
        self.assertTrue(any(f["kind"] == "parse_gap" for f in data["facts"]))
        self.assertTrue(data["page"]["total_is_lower_bound"])

    def test_empty_source_is_not_a_clean_security_verdict(self):
        data = self.run_tool(b"")
        self.assertEqual(data["facts"], [])
        self.assertEqual(data["coverage"]["status"], "syntax_only")
        self.assertIn("absence_is_not_a_security_verdict", data["coverage"]["unknowns"])

    def test_invalid_source_and_limit(self):
        for raw in (b"\xff", b"a\0b", b"x" * (1024 * 1024 + 1)):
            with self.subTest(size=len(raw)):
                self.assertIn("error", self.run_tool(raw, ok=False))

    def test_invalid_options(self):
        for args in (("--limit", "0"), ("--limit", "201"), ("--offset", "-1"),
                     ("--limit", "2", "--limit", "3"), ("--unexpected", "x")):
            with self.subTest(args=args):
                self.assertIn("error", self.run_tool(SOURCE, *args, ok=False))
        for path in ("A.py", "../A.java", "/A.java", "a//A.java", "C:\\A.java"):
            with self.subTest(path=path):
                self.assertIn("error", self.run_tool(SOURCE, ok=False, path=path))

    def test_fact_budget_is_reported(self):
        source = b"class X { void f() {" + b"go();" * 21000 + b"} }"
        data = self.run_tool(source, "--limit", "1")
        self.assertFalse(data["coverage"]["traversal_complete"])
        self.assertTrue(data["page"]["total_is_lower_bound"])

if __name__ == "__main__":
    unittest.main()
