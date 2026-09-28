"""Single-result cache lifetime contracts over the actual pinned MCP process.

Independent integration tests, not recovered historical candidate results.
"""
from __future__ import annotations

import unittest
import test_flow as flow


class OperationCacheTests(unittest.TestCase):
    def session(self, changes=None):
        sources = {"Service.java": flow.SERVICE, "Facade.java": flow.FACADE,
                   "Controller.java": flow.CONTROLLER,
                   "OrderMapper.java": flow.harness.MAPPER, "OrderMapper.xml": flow.harness.XML}
        sources.update(changes or {})
        session = flow.Session(self, sources)
        self.addCleanup(session.close)
        return session

    def request(self, session, **changes):
        args = {**session.anchor_at("Service.java"), "mapper_path": "OrderMapper.java",
                "mapping_path": "OrderMapper.xml"}
        args.update(changes)
        return args

    def stats(self, session):
        return session.call("get_snapshot_info")["operation_context"]

    def inspect(self, session, args=None, **changes):
        request = dict(self.request(session) if args is None else args)
        request.update(changes)
        return session.call("inspect_operation_context", request)

    def assert_no_recomputation(self, before, after, hits=1):
        self.assertEqual(after["requests"], before["requests"] + hits)
        self.assertEqual(after["cache_hits"], before["cache_hits"] + hits)
        for key in ("computations", "parse_attempts", "cached_bytes", "cache_evictions"):
            self.assertEqual(after[key], before[key], key)

    def test_views_reuse_one_full_result_without_projection_mutation(self):
        session = self.session()
        args = self.request(session)
        full = self.inspect(session, args, view="full")
        before = self.stats(session)
        self.assertEqual(before["cache_capacity"], 1)
        self.assertGreater(before["cached_bytes"], 0)
        self.assertGreater(before["parse_attempts"], 0)
        self.assertEqual(before["computations"], 1)
        for index in (0, 1):
            values = self.inspect(session, args, view="values", argument_index=index)
            self.assertEqual(values["context_id"], full["context_id"])
            self.assertEqual(values["selected_argument_index"], index)
            self.assertEqual(values["total_arguments"], len(full["arguments"]))
            self.assertEqual(values["gaps"], full["gaps"])
        summary = self.inspect(session, args, view="summary")
        self.assertEqual(summary["context_id"], full["context_id"])
        self.assertEqual(summary["gaps"], full["gaps"])
        self.assertEqual(self.inspect(session, args, view="full"), full)
        self.assert_no_recomputation(before, self.stats(session), hits=4)

    def test_summary_first_still_computes_full_analysis_once(self):
        session = self.session()
        summary = self.inspect(session, view="summary")
        before = self.stats(session)
        self.assertEqual(before["computations"], 1)
        self.assertGreater(before["parse_attempts"], 0)
        full = session.call(summary["full_request"]["tool"], summary["full_request"]["arguments"])
        self.assertEqual(full["context_id"], summary["context_id"])
        self.assertIn("local_value_flow", full)
        self.assert_no_recomputation(before, self.stats(session))

    def test_a_b_a_evicts_and_recomputes_instead_of_growing_cache(self):
        service = flow.SERVICE.replace("return mapper.load", "mapper.load(id, 0); return mapper.load")
        session = self.session({"Service.java": service})
        first_args = self.request(session)
        second_args = dict(first_args, **session.anchor_at("Service.java", index=1))
        first = self.inspect(session, first_args)
        before = self.stats(session)
        second = self.inspect(session, second_args)
        middle = self.stats(session)
        again = self.inspect(session, first_args)
        after = self.stats(session)
        self.assertNotEqual(first["context_id"], second["context_id"])
        self.assertEqual(first, again)
        self.assertEqual(middle["computations"], before["computations"] + 1)
        self.assertEqual(after["computations"], before["computations"] + 2)
        self.assertEqual(after["cache_evictions"], before["cache_evictions"] + 2)
        self.assertEqual(after["cache_hits"], before["cache_hits"])
        self.assertEqual(after["cached_bytes"], before["cached_bytes"])

    def test_mapping_inputs_are_part_of_context_key(self):
        session = self.session()
        generic = self.inspect(session, session.anchor_at("Service.java"))
        mapped = self.inspect(session)
        self.assertNotEqual(generic["context_id"], mapped["context_id"])
        self.assertEqual(mapped["mybatis"]["status"], "explicit_mapping_candidate")
        self.assertEqual(self.stats(session)["computations"], 2)
        self.assertEqual(self.stats(session)["cache_evictions"], 1)

    def test_identical_xml_bytes_at_different_paths_keep_provenance(self):
        session = self.session({"Other.xml": flow.harness.XML})
        first = self.inspect(session)
        second = self.inspect(session, mapping_path="Other.xml")
        self.assertNotEqual(first["context_id"], second["context_id"])
        self.assertEqual(second["mybatis"]["status"], "explicit_mapping_candidate")
        self.assertEqual(self.stats(session)["computations"], 2)
        self.assertEqual(self.stats(session)["cache_hits"], 0)

    def test_upstream_chain_is_part_of_key(self):
        session = self.session()
        args = self.request(session)
        short = self.inspect(session, args)
        upstream = [session.anchor_at("Facade.java"), session.anchor_at("Controller.java")]
        long = self.inspect(session, args, upstream_calls=upstream)
        self.assertNotEqual(short["context_id"], long["context_id"])
        self.assertNotIn("argument_flow", short)
        self.assertEqual(long["argument_flow"]["linked_candidate_hops"], 2)
        before = self.stats(session)
        self.assertEqual(self.inspect(session, args, upstream_calls=upstream), long)
        self.assert_no_recomputation(before, self.stats(session))

    def test_preflight_errors_do_not_replace_valid_cached_context(self):
        session = self.session()
        args = self.request(session)
        full = self.inspect(session, args)
        before = self.stats(session)
        invalid = ({"expect_context": "0" * 64}, {"view": "unknown"},
                   {"mapping_path": "missing.xml"}, {"analysis_id": "0" * 64},
                   {"upstream_calls": [session.anchor_at("Service.java")]})
        for change in invalid:
            with self.subTest(change=change):
                error = session.call("inspect_operation_context", dict(args, **change), ok=False)
                self.assertIn("error", error)
                self.assertEqual(self.stats(session), before)
        self.assertEqual(self.inspect(session, args), full)
        self.assert_no_recomputation(before, self.stats(session))

    def test_failed_values_projection_does_not_corrupt_cached_full_result(self):
        session = self.session()
        args = self.request(session)
        full = self.inspect(session, args)
        before = self.stats(session)
        error = session.call("inspect_operation_context", dict(args, view="values", argument_index=63), ok=False)
        self.assertEqual(error["error"]["code"], "argument_index_out_of_range")
        self.assertEqual(self.inspect(session, args), full)
        self.assert_no_recomputation(before, self.stats(session), hits=2)

    def test_inventory_and_fact_queries_do_not_evict_operation_cache(self):
        session = self.session()
        args = self.request(session)
        full = self.inspect(session, args)
        before = self.stats(session)
        session.call("query_security_facts", {"path": "Controller.java", "kind": "method_declaration"})
        session.call("query_resource_operations", {"application_id": "controlled", "scope_paths": list(session.sources)})
        self.assertEqual(self.stats(session), before)
        self.assertEqual(self.inspect(session, args), full)
        self.assert_no_recomputation(before, self.stats(session))

    def test_ordinary_trace_has_separate_request_cache(self):
        session = self.session()
        args = self.request(session)
        full = self.inspect(session, args)
        before = self.stats(session)
        result = session.call("trace_argument_origins", {**session.anchor_at("Service.java"),
            "argument_index": 1, "scope_paths": ["Service.java", "Facade.java", "Controller.java"]})
        self.assertTrue(result["paths"])
        self.assertEqual(self.stats(session), before)
        self.assertEqual(self.inspect(session, args), full)
        self.assert_no_recomputation(before, self.stats(session))

    def test_new_process_with_identical_snapshot_starts_empty(self):
        first, second = self.session(), self.session()
        self.assertEqual(first.snapshot, second.snapshot)
        full = self.inspect(first)
        cold = self.stats(second)
        self.assertFalse(cold["cached"])
        self.assertEqual(cold["computations"], 0)
        self.assertEqual(self.inspect(second), full)
        self.assertEqual(self.stats(second)["cache_hits"], 0)
        self.assertEqual(self.stats(second)["computations"], 1)

    def test_other_snapshot_cannot_reuse_context_even_for_unchanged_call(self):
        first = self.session()
        full = self.inspect(first)
        second = self.session({"Extra.java": "class Extra {}"})
        args = self.request(second)
        before = self.stats(second)
        error = second.call("inspect_operation_context", dict(args, expect_context=full["context_id"]), ok=False)
        self.assertEqual(error["error"]["code"], "context_mismatch")
        self.assertEqual(self.stats(second), before)
        self.assertNotEqual(self.inspect(second, args)["context_id"], full["context_id"])


if __name__ == "__main__":
    unittest.main()
