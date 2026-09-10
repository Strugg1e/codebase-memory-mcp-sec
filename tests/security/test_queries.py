"""Query identity, bounded paging, and enclosing-context tests with real parsers."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
SOURCE = b'''import express from "express";
const app = express();
function setup() {
    app.use(auth);
    app.get("/a", first);
    app.post("/b", second);
    app.put("/c", third);
    helper(1); helper(2);
}
function unrelated() { other(); }
'''
FILTERS = ("--framework", "express", "--role", "route_declaration")

class Queries(unittest.TestCase):
    def run_tool(self, *args, source=SOURCE, path="routes.js", ok=True):
        raw = source.encode() if isinstance(source, str) else source
        result = subprocess.run([BINARY, "--path", path, *args], input=raw, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0 if ok else 2, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        return json.loads(result.stdout)

    def test_kind_filter_preserves_ids_and_records(self):
        all_facts = self.run_tool()
        selected = self.run_tool("--kind", "call_site")
        expected = [f for f in all_facts["facts"] if f["kind"] == "call_site"]
        self.assertEqual(selected["facts"], expected)
        self.assertEqual(selected["analysis_id"], all_facts["analysis_id"])
        self.assertEqual(selected["page"]["extracted_total"], all_facts["page"]["extracted_total"])
        self.assertEqual(selected["page"]["matched_total"], len(expected))

    def test_framework_and_role_conjunction(self):
        data = self.run_tool(*FILTERS)
        self.assertEqual(data["page"]["matched_total"], 3)
        self.assertTrue(all(f["framework_model"]["role"] == "route_declaration" for f in data["facts"]))
        self.assertEqual(data["query"]["filters"]["framework"], "express")
        self.assertTrue(all(f["framework_model"]["security_effect"] == "not_evaluated" for f in data["facts"]))

    def test_disjoint_filters_do_not_union(self):
        data = self.run_tool(*FILTERS, "--kind", "import_statement")
        self.assertEqual(data["facts"], [])
        self.assertEqual(data["page"]["matched_total"], 0)

    def test_cursor_pages_have_no_duplicates_or_omissions(self):
        expected = self.run_tool(*FILTERS)
        page = self.run_tool(*FILTERS, "--limit", "1")
        found = []
        for _ in range(10):
            found.extend(page["facts"])
            self.assertEqual(page["page"]["matched_total"], 3)
            token = page["page"]["next_cursor"]
            if token is None:
                break
            page = self.run_tool(*FILTERS, "--limit", "1", "--cursor", token)
        else:
            self.fail("cursor did not terminate")
        self.assertEqual(found, expected["facts"])
        self.assertEqual(len(found), len({f["id"] for f in found}))
        self.assertFalse(page["page"]["has_more"])
        self.assertIsNone(page["page"]["next_offset"])

    def test_cursor_replay_is_repeatable(self):
        first = self.run_tool(*FILTERS, "--limit", "1")
        args = (*FILTERS, "--limit", "1", "--cursor", first["page"]["next_cursor"])
        self.assertEqual(self.run_tool(*args), self.run_tool(*args))

    def test_cursor_accepts_page_size_change(self):
        first = self.run_tool(*FILTERS, "--limit", "1")
        second = self.run_tool(*FILTERS, "--limit", "2", "--cursor", first["page"]["next_cursor"])
        self.assertEqual(second["query"]["id"], first["query"]["id"])
        self.assertEqual(second["page"]["returned"], 2)
        self.assertFalse(second["page"]["has_more"])

    def test_cursor_rejects_changed_filter(self):
        first = self.run_tool(*FILTERS, "--limit", "1")
        result = self.run_tool("--framework", "express", "--role", "middleware_attachment", "--cursor", first["page"]["next_cursor"], ok=False)
        self.assertEqual(result["error"]["code"], "query_mismatch")

    def test_cursor_rejects_removed_filters(self):
        first = self.run_tool(*FILTERS, "--limit", "1")
        result = self.run_tool("--cursor", first["page"]["next_cursor"], ok=False)
        self.assertEqual(result["error"]["code"], "query_mismatch")

    def test_cursor_rejects_added_filters(self):
        first = self.run_tool("--limit", "1")
        result = self.run_tool("--cursor", first["page"]["next_cursor"], "--kind", "call_site", ok=False)
        self.assertEqual(result["error"]["code"], "query_mismatch")

    def test_cursor_rejects_changed_source(self):
        first = self.run_tool(*FILTERS, "--limit", "1")
        result = self.run_tool(*FILTERS, "--cursor", first["page"]["next_cursor"], source=SOURCE + b"\n", ok=False)
        self.assertEqual(result["error"]["code"], "query_mismatch")

    def test_cursor_rejects_changed_path(self):
        first = self.run_tool(*FILTERS, "--limit", "1")
        result = self.run_tool(*FILTERS, "--cursor", first["page"]["next_cursor"], path="other.js", ok=False)
        self.assertEqual(result["error"]["code"], "query_mismatch")

    def test_invalid_cursor_shapes(self):
        for token in ("", "a" * 64, "a" * 64 + ":0", "g" * 64 + ":1", "a" * 64 + ":-1", "a" * 64 + ":20001", "a" * 64 + ":1:2"):
            with self.subTest(token=token):
                self.assertEqual(self.run_tool("--cursor", token, ok=False)["error"]["code"], "invalid_cursor")

    def test_cursor_and_offset_are_exclusive(self):
        first = self.run_tool("--limit", "1")
        result = self.run_tool("--cursor", first["page"]["next_cursor"], "--offset", "0", ok=False)
        self.assertEqual(result["error"]["code"], "invalid_arguments")

    def test_legacy_unfiltered_offset_remains_compatible(self):
        first = self.run_tool("--limit", "1")
        old = self.run_tool("--limit", "1", "--offset", "1", "--expect-analysis", first["analysis_id"])
        new = self.run_tool("--limit", "1", "--cursor", first["page"]["next_cursor"])
        self.assertEqual(old, new)

    def test_filtered_legacy_offset_requires_query_cursor(self):
        first = self.run_tool(*FILTERS, "--limit", "1")
        result = self.run_tool(*FILTERS, "--offset", "1", "--expect-analysis", first["analysis_id"], ok=False)
        self.assertEqual(result["error"]["code"], "query_cursor_required")

    def test_offset_beyond_match_set_is_not_empty_success(self):
        first = self.run_tool(*FILTERS, "--limit", "1")
        token = first["query"]["id"] + ":100"
        result = self.run_tool(*FILTERS, "--cursor", token, ok=False)
        self.assertEqual(result["error"]["code"], "offset_out_of_matched_scope")

    def test_enclosing_context_excludes_other_functions(self):
        data = self.run_tool()
        setup = next(f for f in data["facts"] if f["kind"] == "function_declaration" and f["name"]["text_prefix"] == "setup")
        selected = self.run_tool("--enclosing-id", setup["id"])
        expected = [f for f in data["facts"] if f.get("enclosing_id") == setup["id"]]
        self.assertEqual(selected["facts"], expected)
        self.assertTrue(selected["facts"])
        self.assertFalse(any(f.get("name", {}).get("text_prefix") == "other" for f in selected["facts"]))

    def test_enclosing_filter_combines_with_framework(self):
        data = self.run_tool()
        setup = next(f for f in data["facts"] if f["kind"] == "function_declaration" and f["name"]["text_prefix"] == "setup")
        selected = self.run_tool("--enclosing-id", setup["id"], *FILTERS)
        self.assertEqual(len(selected["facts"]), 3)

    def test_unknown_enclosing_is_explicit(self):
        result = self.run_tool("--enclosing-id", "a" * 64, ok=False)
        self.assertEqual(result["error"]["code"], "enclosing_not_found_in_extracted_scope")

    def test_fact_lookup_rejects_filters(self):
        data = self.run_tool()
        result = self.run_tool("--fact-id", data["facts"][0]["id"], "--expect-analysis", data["analysis_id"], "--kind", "call_site", ok=False)
        self.assertEqual(result["error"]["code"], "invalid_arguments")

    def test_invalid_or_duplicate_filter(self):
        for args in (("--kind", ""), ("--role", "a" * 97), ("--framework", "x y"),
                     ("--kind", "call_site", "--kind", "call_site"), ("--enclosing-id", "bad")):
            with self.subTest(args=args):
                self.assertIn("error", self.run_tool(*args, ok=False))

    def test_empty_match_keeps_coverage_unknowns(self):
        data = self.run_tool("--framework", "spring-mvc")
        self.assertEqual(data["facts"], [])
        self.assertIn("absence_is_not_a_security_verdict", data["coverage"]["unknowns"])
        self.assertGreater(data["page"]["extracted_total"], 0)

    def test_syntax_failure_keeps_filtered_lower_bound(self):
        data = self.run_tool("--role", "route_declaration", path="x.py", source='from fastapi import FastAPI\napp = FastAPI()\ndef broken(\n')
        self.assertTrue(data["coverage"]["parse_has_error"])
        self.assertFalse(data["coverage"]["framework_analysis_complete"])
        self.assertEqual(data["facts"], [])
        self.assertTrue(data["page"]["total_is_lower_bound"])

    def test_filtered_output_is_smaller_without_changing_evidence(self):
        all_data = self.run_tool()
        routes = self.run_tool(*FILTERS)
        self.assertLess(len(json.dumps(routes)), len(json.dumps(all_data)))
        by_id = {f["id"]: f for f in all_data["facts"]}
        self.assertTrue(all(by_id[f["id"]] == f for f in routes["facts"]))

    def test_capability_discovery_lists_filters(self):
        data = json.loads(subprocess.check_output([BINARY, "--capabilities"], timeout=10))
        self.assertEqual(data["query_filters"], ["kind", "framework", "role", "enclosing_id"])
        self.assertTrue(data["query_cursor"])
        self.assertFalse(data["value_flow"])

if __name__ == "__main__":
    unittest.main()
