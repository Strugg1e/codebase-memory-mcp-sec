"""Independent ordinary-argument regressions over real MCP processes.

Not recovered candidate tests. Only repository-owned Java text is analyzed;
these unit tests do not execute it or assert business vulnerability outcomes.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

import test_flow as flow

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "security"))
import demo_arguments as demo


class ArgumentOrigins(unittest.TestCase):
    def session(self, case="plain", changes=None):
        sources = demo.fixture_sources(case)
        sources.update(changes or {})
        session = flow.Session(self, sources)
        self.addCleanup(session.close)
        return session

    def trace(self, session, ok=True, **changes):
        arguments = {**session.anchor_at("Service.java", "store"), "argument_index": 1,
                     "scope_paths": ["Service.java", "Facade.java", "Entry.java"]}
        arguments.update(changes)
        return session.call("trace_argument_origins", arguments, ok=ok)

    def origins(self, result):
        self.assertEqual(result["schema"], "cbm.argument-origins.v1")
        self.assertEqual(result["security_verdict"], "not_evaluated")
        self.assertEqual(result["absence_semantics"], "no_negative_security_conclusion")
        for path in result["paths"]:
            self.assertEqual(path["source"]["kind"], "formal_parameter_boundary")
            self.assertEqual(path["source"]["trust"], "not_classified")
            self.assertEqual(path["runtime_dispatch"], "not_verified")
        return {p["source"]["parameter"]["name"]["text_prefix"] for p in result["paths"]}

    def test_plain_call_without_framework_or_root_callee_definition(self):
        session = self.session()
        self.assertTrue(all("@" not in text and "Mapper" not in text for text in session.sources.values()))
        self.assertNotIn("Recorder.java", session.sources)
        result = self.trace(session)
        self.assertEqual(self.origins(result), {"tenant"})
        self.assertEqual(result["paths"][0]["candidate_hops"], 2)
        self.assertNotIn("rule_id", result)
        self.assertFalse(result["truncated"])

    def test_selected_argument_zero_is_not_argument_one(self):
        session = self.session()
        first = self.trace(session, argument_index=0)
        second = self.trace(session, argument_index=1)
        self.assertEqual(self.origins(first), {"id"})
        self.assertEqual(self.origins(second), {"tenant"})
        self.assertNotEqual(first["query_id"], second["query_id"])

    def test_reordered_arguments_follow_formal_positions(self):
        result = self.trace(self.session("swapped"))
        self.assertEqual(self.origins(result), {"id"})
        steps = result["paths"][0]["steps"]
        self.assertEqual([s["argument_index"] for s in steps], [1, 1, 0])
        self.assertEqual([s["formal_parameter_index"] for s in steps], [1, 0, 0])

    def test_two_swaps_restore_original_origin(self):
        entry = demo.SOURCES["Entry.java"].replace("facade.load(id, tenant)", "facade.load(tenant, id)")
        self.assertEqual(self.origins(self.trace(self.session("swapped", {"Entry.java": entry}))), {"tenant"})

    def test_transformation_is_not_identity(self):
        source = demo.SOURCES["Service.java"].replace("store(id, tenant)", "store(id, tenant + 1)")
        result = self.trace(self.session(changes={"Service.java": source}))
        self.assertEqual(self.origins(result), {"tenant"})
        self.assertEqual(result["paths"][0]["relation"], "may_depend_after_transformation")

    def test_overwrite_at_root_has_explicit_frontier(self):
        result = self.trace(self.session("overwritten"))
        self.assertEqual(self.origins(result), set())
        self.assertIn("no_known_formal_dependencies_remain", [f["reason"] for f in result["frontiers"]])

    def test_overwrite_in_caller_does_not_recover_old_value(self):
        source = demo.SOURCES["Facade.java"].replace("return service", "tenant = 0; return service")
        result = self.trace(self.session(changes={"Facade.java": source}))
        self.assertEqual(self.origins(result), set())
        self.assertTrue(result["frontiers"])

    def test_two_branch_sources_remain_separate(self):
        source = demo.SOURCES["Service.java"].replace("return recorder.store(id, tenant);",
            "long chosen=tenant; if(id<0){chosen=id;} return recorder.store(id,chosen);")
        self.assertEqual(self.origins(self.trace(self.session(changes={"Service.java": source}))), {"id", "tenant"})

    def test_constant_branch_does_not_remove_known_branch(self):
        source = demo.SOURCES["Service.java"].replace("return recorder.store(id, tenant);",
            "long chosen=tenant; if(id<0){chosen=0;} return recorder.store(id,chosen);")
        result = self.trace(self.session(changes={"Service.java": source}))
        self.assertEqual(self.origins(result), {"tenant"})
        self.assertTrue(result["paths"][0]["literal_alternative_possible"])

    def test_known_path_does_not_hide_unknown_return(self):
        result = self.trace(self.session("known_and_unknown"))
        self.assertEqual(self.origins(result), {"tenant"})
        self.assertIn("argument_origin_has_unknown_parts", result["gaps"])
        self.assertIn("call_return_not_modeled", result["selected_argument"]["local_value_flow"]["unknown_reasons"])

    def test_external_return_alone_is_not_guessed(self):
        source = demo.SOURCES["Service.java"].replace("store(id, tenant)", "store(id, external.value())")
        result = self.trace(self.session(changes={"Service.java": source}))
        self.assertEqual(self.origins(result), set())
        self.assertIn("unknown_value_origin", [f["reason"] for f in result["frontiers"]])

    def test_wrong_receiver_type_does_not_connect_by_method_name(self):
        source = demo.SOURCES["Facade.java"].replace("Service service;", "OtherService service;")
        result = self.trace(self.session(changes={"Facade.java": source}))
        self.assertTrue(result["call_candidates"])
        self.assertTrue(result["paths"])
        self.assertEqual(result["paths"][0]["candidate_hops"], 0)
        self.origins(result)

    def test_rebound_receiver_is_not_connected(self):
        source = demo.SOURCES["Facade.java"].replace("return service", "service = externalService(); return service")
        result = self.trace(self.session(changes={"Facade.java": source}))
        self.assertTrue(result["call_candidates"])
        self.assertEqual(result["paths"][0]["candidate_hops"], 0)

    def test_overloaded_target_preserves_unresolved_boundary(self):
        source = demo.SOURCES["Service.java"].replace("  Recorder recorder;",
            "  long load(String id, String tenant) { return 0; }\n  Recorder recorder;")
        result = self.trace(self.session(changes={"Service.java": source}))
        self.assertEqual(result["paths"][0]["candidate_hops"], 0)
        self.assertTrue(result["call_candidates"])
        self.origins(result)

    def test_scope_end_is_not_unreachability(self):
        result = self.trace(self.session(), scope_paths=["Service.java"])
        self.assertEqual(self.origins(result), {"tenant"})
        self.assertEqual(result["paths"][0]["candidate_hops"], 0)
        self.assertTrue(result["paths"][0]["boundary_reason"])

    def test_depth_zero_is_explicitly_incomplete(self):
        result = self.trace(self.session(), max_hops=0)
        self.assertEqual(result["paths"][0]["candidate_hops"], 0)
        self.assertTrue(result["truncated"])
        self.assertIn("trace_depth_limit", result["gaps"])
        self.origins(result)

    def test_edge_budget_stops_without_claiming_absence(self):
        result = self.trace(self.session(), max_edge_checks=1)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(result["statistics"]["edge_checks"], 1)
        self.assertTrue(result["gaps"])
        self.origins(result)

    def test_scope_order_keeps_identity_and_content(self):
        session = self.session()
        self.assertEqual(self.trace(session), self.trace(session, scope_paths=["Entry.java", "Facade.java", "Service.java"]))

    def test_scope_and_budget_are_part_of_query_identity(self):
        session = self.session()
        all_files = self.trace(session)
        self.assertNotEqual(all_files["query_id"], self.trace(session, scope_paths=["Service.java"])["query_id"])
        self.assertNotEqual(all_files["query_id"], self.trace(session, max_hops=1)["query_id"])

    def test_requests_do_not_reuse_other_trace_or_operation_caches(self):
        session = self.session()
        result = self.trace(session)
        self.assertEqual(result, self.trace(session))
        counters = session.call("get_snapshot_info")
        self.assertEqual(counters["argument_origin_tracing"]["requests"], 2)
        self.assertEqual(counters["argument_origin_tracing"]["parse_attempts"], 2 * result["statistics"]["source_parse_attempts"])
        self.assertEqual(counters["source_sink_tracing"]["requests"], 0)
        self.assertEqual(counters["operation_context"]["computations"], 0)

    def test_references_match_unicode_source_bytes(self):
        source = "// 中文和 emoji 😀\n" + demo.SOURCES["Service.java"]
        session = self.session(changes={"Service.java": source})
        self.assertGreater(demo.audit_references(self.trace(session), session.sources), 0)

    def test_stale_snapshot_or_analysis_is_rejected(self):
        session = self.session()
        for key, code in (("snapshot_id", "snapshot_mismatch"), ("analysis_id", "analysis_mismatch")):
            with self.subTest(key=key):
                error = self.trace(session, ok=False, **{key: "0" * 64})
                self.assertEqual(error["error"]["code"], code)
                self.assertNotIn("paths", error)

    def test_unselected_or_duplicate_paths_are_rejected(self):
        session = self.session()
        for paths, code in ((["Entry.java"], "trace_scope_must_include_call_file"),
                            (["Service.java", "Service.java"], "duplicate_trace_scope_path"),
                            (["Service.java", "Missing.java"], "trace_path_not_in_snapshot")):
            with self.subTest(paths=paths):
                self.assertEqual(self.trace(session, ok=False, scope_paths=paths)["error"]["code"], code)

    def test_non_java_scope_is_rejected(self):
        session = self.session(changes={"module.py": "def load(id, tenant): return tenant\n"})
        self.assertEqual(self.trace(session, ok=False, scope_paths=["Service.java", "module.py"])["error"]["code"],
                         "unsupported_trace_language")

    def test_specialized_mapping_and_view_options_are_not_accepted(self):
        session = self.session()
        for key, value in (("mapper_path", "M.java"), ("mapping_path", "M.xml"), ("rule_id", "rule"),
                           ("upstream_calls", []), ("view", "summary")):
            with self.subTest(key=key):
                error = self.trace(session, ok=False, **{key: value})
                self.assertIn("error", error)
                self.assertNotIn("paths", error)

    def test_invalid_indices_and_budgets_fail_without_poisoning_next_request(self):
        session = self.session()
        for key, value in (("argument_index", -1), ("argument_index", True), ("argument_index", "1"),
                           ("argument_index", 2), ("argument_index", 64), ("max_hops", 5),
                           ("max_paths", 0), ("max_paths", 33), ("max_edge_checks", 0), ("max_edge_checks", 129)):
            with self.subTest(key=key, value=value):
                self.assertIn("error", self.trace(session, ok=False, **{key: value}))
        self.assertEqual(self.origins(self.trace(session)), {"tenant"})

    def test_file_count_limit_is_enforced(self):
        paths = ["Service.java"] + [f"Extra{i}.java" for i in range(16)]
        session = self.session(changes={p: f"class Extra{i} {{}}" for i, p in enumerate(paths[1:])})
        error = self.trace(session, ok=False, scope_paths=paths)
        self.assertIn("error", error)
        self.assertNotIn("paths", error)

    def test_per_file_byte_limit_is_enforced(self):
        session = self.session(changes={"Large.java": "//" + "x" * (256 * 1024)})
        error = self.trace(session, ok=False, scope_paths=["Service.java", "Large.java"])
        self.assertEqual(error["error"]["code"], "trace_source_limit_exceeded")

    def test_total_scope_byte_limit_is_enforced(self):
        extra = {f"Large{i}.java": "//" + "x" * (250 * 1024) for i in range(9)}
        session = self.session(changes=extra)
        error = self.trace(session, ok=False, scope_paths=["Service.java", *extra])
        self.assertEqual(error["error"]["code"], "trace_source_limit_exceeded")

    def test_documented_demo_runs_four_real_cases(self):
        run = subprocess.run([sys.executable, str(ROOT / "security/demo_arguments.py"), "--mcp", str(flow.harness.MCP)],
                             capture_output=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr.decode("utf-8", "replace"))
        result = json.loads(run.stdout)
        self.assertFalse(result["target_execution"])
        self.assertEqual(result["model_calls"], 0)
        self.assertEqual([c["case"] for c in result["cases"]], list(demo.CASES))
        for case in result["cases"]:
            self.assertTrue(case["expectations_passed"])
            self.assertGreater(case["source_references_checked"], 0)
            self.origins(case["result"])

    def test_demo_failure_never_prints_success(self):
        for arguments, code in (([], 2), (["--mcp", str(ROOT / "build/not-an-executable")], 1)):
            with self.subTest(arguments=arguments):
                run = subprocess.run([sys.executable, str(ROOT / "security/demo_arguments.py"), *arguments],
                                     capture_output=True, timeout=10)
                self.assertEqual(run.returncode, code)
                self.assertEqual(run.stdout, b"")


if __name__ == "__main__":
    unittest.main()
