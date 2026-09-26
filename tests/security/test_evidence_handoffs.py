"""Independent handoff contracts over existing real parser/MCP test fixtures.

These tests were written for the integration branch. They are not recovered
0.15.0-dev candidate tests, evidence from a business repository, or a claim
that the unavailable reference archive has been inspected.
"""
from __future__ import annotations

import hashlib
import unittest

# Reuse the existing subprocess client and controlled source fixtures only.
import test_flow as flow


class EvidenceHandoffTests(unittest.TestCase):
    def session(self, changes=None, only=None):
        sources = {
            "Service.java": flow.SERVICE, "Facade.java": flow.FACADE,
            "Controller.java": flow.CONTROLLER,
            "OrderMapper.java": flow.harness.MAPPER,
            "OrderMapper.xml": flow.harness.XML,
        }
        sources.update(changes or {})
        if only is not None:
            sources = {name: sources[name] for name in only}
        session = flow.Session(self, sources)
        self.addCleanup(session.close)
        return session

    def catalogue(self, session, **changes):
        arguments = {"application_id": "controlled-fixture", "scope_paths": list(session.sources)}
        arguments.update(changes)
        return session.call("query_resource_operations", arguments)

    def trace(self, session, **changes):
        arguments = {
            **session.anchor_at("Service.java"), "argument_index": 1,
            "scope_paths": ["Service.java", "Facade.java", "Controller.java"],
        }
        arguments.update(changes)
        return session.call("trace_argument_origins", arguments)

    def assert_neutral(self, result):
        self.assertEqual(result["security_verdict"], "not_evaluated")
        self.assertEqual(result["absence_semantics"], "no_negative_security_conclusion")

    def assert_references(self, session, value):
        if isinstance(value, dict):
            fields = {"path", "sha256", "start_byte", "end_byte"}
            if fields <= value.keys():
                raw = session.sources[value["path"]].encode("utf-8")
                self.assertEqual(value["sha256"], hashlib.sha256(raw).hexdigest())
                start, end = value["start_byte"], value["end_byte"]
                self.assertGreaterEqual(start, 0)
                self.assertLessEqual(start, end)
                self.assertLessEqual(end, len(raw))
                text = raw[start:end].decode("utf-8")
                self.assertTrue(text.startswith(value.get("text_prefix", "")))
                if "text_prefix" in value and not value.get("text_truncated", False):
                    self.assertEqual(value["text_prefix"], text)
            for child in value.values():
                self.assert_references(session, child)
        elif isinstance(value, list):
            for child in value:
                self.assert_references(session, child)

    def test_inventory_does_not_compute_deep_operation_context(self):
        session = self.session()
        before = session.call("get_snapshot_info")["operation_context"]
        result = self.catalogue(session)
        after = session.call("get_snapshot_info")["operation_context"]
        self.assertEqual(len(result["operations"]), 1)
        self.assertEqual(after, before)
        self.assertEqual(result["statistics"]["local_flow_evaluations"], 0)
        self.assertEqual(result["statistics"]["return_summary_evaluations"], 0)
        self.assertGreater(result["statistics"]["source_parse_attempts"], 0)
        self.assert_neutral(result)

    def test_bound_constant_and_write_operations_are_not_sink_filtered(self):
        examples = [
            ("select", "SELECT * FROM orders WHERE id = #{id}", "read"),
            ("select", "SELECT * FROM orders WHERE id = 1", "read"),
            ("insert", "INSERT INTO orders (id) VALUES (#{id})", "create"),
            ("update", "UPDATE orders SET tenant_id = #{tenant} WHERE id = #{id}", "update"),
            ("delete", "DELETE FROM orders WHERE id = #{id}", "delete"),
        ]
        for tag, sql, kind in examples:
            with self.subTest(kind=kind, sql=sql):
                xml = '<mapper namespace="data.OrderMapper"><%s id="load">%s</%s></mapper>' % (tag, sql, tag)
                session = self.session({"OrderMapper.xml": xml})
                result = self.catalogue(session)
                self.assertEqual(len(result["operations"]), 1)
                operation = result["operations"][0]
                self.assertEqual(operation["operation_kind_candidate"], kind)
                self.assertEqual(operation["security_verdict"], "not_evaluated")
                self.assertEqual(operation["analysis_scope"], "structure_and_mapping_only")
                self.assert_references(session, result)

    def test_inventory_request_summary_full_and_source_round_trip(self):
        session = self.session()
        operation = self.catalogue(session)["operations"][0]
        request = operation["inspection"]
        self.assertEqual(request["tool"], "inspect_operation_context")
        self.assertEqual(request["arguments"], operation["inspection_request"])
        summary = session.call(request["tool"], request["arguments"])
        before = session.call("get_snapshot_info")["operation_context"]
        full_request = summary["full_request"]
        full = session.call(full_request["tool"], full_request["arguments"])
        after = session.call("get_snapshot_info")["operation_context"]
        self.assertEqual(full["context_id"], summary["context_id"])
        self.assertEqual(full["call_id"], summary["call_id"])
        self.assertEqual(full["gaps"], summary["gaps"])
        self.assertEqual(full["authorization_verdict"], "not_evaluated")
        self.assertEqual(before["computations"], 1)
        self.assertEqual(after["computations"], before["computations"])
        self.assertEqual(after["parse_attempts"], before["parse_attempts"])
        self.assertEqual(after["cache_hits"], before["cache_hits"] + 1)
        self.assert_references(session, full)
        reference = full["call"]
        source_request = {key: reference[key] for key in ("path", "sha256", "start_byte", "end_byte")}
        fragment = session.call("read_snapshot_source", source_request)
        self.assertEqual(fragment["text"], "mapper.load(id, tenant)")
        self.assertEqual(fragment["trust"], "untrusted_source_data")

    def test_changed_context_and_source_identity_are_rejected(self):
        session = self.session()
        request = self.catalogue(session)["operations"][0]["inspection"]
        summary = session.call(request["tool"], request["arguments"])
        args = dict(summary["full_request"]["arguments"], expect_context="0" * 64)
        error = session.call("inspect_operation_context", args, ok=False)
        self.assertEqual(error["error"]["code"], "context_mismatch")
        ref = summary["call"]
        args = {key: ref[key] for key in ("path", "sha256", "start_byte", "end_byte")}
        args["sha256"] = "0" * 64
        error = session.call("read_snapshot_source", args, ok=False)
        self.assertIn("error", error)
        self.assertNotIn("text", error)

    def test_no_direct_handler_is_not_a_claim_of_unreachability(self):
        session = self.session()
        operation = self.catalogue(session)["operations"][0]
        self.assertEqual(operation["direct_entry_contexts"], [])
        self.assertEqual(operation["entry_relation"], "no_direct_entry_cross_method_reachability_not_searched")
        self.assertTrue(self.trace(session)["paths"])
        self.assertEqual(operation["business_requirement"], "not_supplied")

    def test_empty_page_is_followed_until_query_completion(self):
        session = self.session()
        arguments = {"max_checks": 1}
        result = self.catalogue(session, **arguments)
        self.assertEqual(result["operations"], [])
        self.assertIsNotNone(result["page"]["next_cursor"])
        query_id = result["query_id"]
        operations, attempts, cursors = [], [], set()
        while True:
            self.assertEqual(result["query_id"], query_id)
            operations.extend(result["operations"])
            attempts.extend(result["attempts"])
            cursor = result["page"]["next_cursor"]
            if cursor is None:
                break
            self.assertNotIn(cursor, cursors)
            cursors.add(cursor)
            self.assertLessEqual(len(cursors), result["page"]["tasks_total"])
            self.assertGreater(result["page"]["next_offset"], result["page"]["offset"])
            result = self.catalogue(session, cursor=cursor, **arguments)
        self.assertEqual(len(operations), 1)
        self.assertEqual(len(attempts), result["page"]["tasks_total"])
        self.assertTrue(result["page"]["enumeration_complete"])
        self.assert_neutral(result)

    def test_unconnected_mapping_declaration_is_retained(self):
        session = self.session(only=["OrderMapper.java", "OrderMapper.xml"])
        result = self.catalogue(session)
        self.assertEqual(result["operations"], [])
        self.assertEqual(len(result["declarations"]), 1)
        self.assertEqual(result["declarations"][0]["call_link_status"], "no_call_nominated_in_selected_subset")
        self.assertEqual(result["declarations"][0]["runtime_binding"], "not_verified")
        self.assert_neutral(result)
        self.assert_references(session, result)

    def test_resource_peer_key_respects_host_application_boundary(self):
        session = self.session()
        first = self.catalogue(session, application_id="fixture-a")["operations"][0]["resource_candidate"]
        second = self.catalogue(session, application_id="fixture-b")["operations"][0]["resource_candidate"]
        self.assertNotEqual(first["peer_group_id"], second["peer_group_id"])
        self.assertEqual(first["identity_status"], "lexical_peer_candidate_only")
        self.assertEqual(first["database_identity"], "not_verified")

    def test_generic_trace_needs_neither_mapper_nor_request_annotations(self):
        controller = flow.CONTROLLER.replace("@RequestParam ", "").replace('  @GetMapping("/orders")\n', "")
        session = self.session({"Controller.java": controller}, only=["Service.java", "Facade.java", "Controller.java"])
        result = self.trace(session)
        self.assertEqual(len(result["paths"]), 1)
        path = result["paths"][0]
        self.assertEqual(path["candidate_hops"], 2)
        self.assertEqual(path["source"]["kind"], "formal_parameter_boundary")
        self.assertEqual(path["source"]["parameter"]["name"]["text_prefix"], "tenant")
        self.assertEqual(path["source"]["trust"], "not_classified")
        self.assertEqual(path["runtime_dispatch"], "not_verified")
        self.assert_neutral(result)

    def test_generic_argument_reordering_follows_positions(self):
        facade = flow.FACADE.replace("service.load(id, tenant)", "service.load(tenant, id)")
        result = self.trace(self.session({"Facade.java": facade}))
        self.assertEqual({p["source"]["parameter"]["name"]["text_prefix"] for p in result["paths"]}, {"id"})
        # The callee argument slot stays 1 at the facade call; its value is
        # facade formal 0 after the swap, hence controller argument 0.
        steps = result["paths"][0]["steps"]
        self.assertEqual([s["argument_index"] for s in steps], [1, 1, 0])
        self.assertEqual([s["formal_parameter_index"] for s in steps], [1, 0, 0])

    def test_constant_overwrite_is_not_a_negative_security_verdict(self):
        service = flow.SERVICE.replace("return mapper", "tenant = 0; return mapper")
        result = self.trace(self.session({"Service.java": service}))
        self.assertEqual(result["paths"], [])
        self.assertIn("no_known_formal_dependencies_remain", [f["reason"] for f in result["frontiers"]])
        self.assert_neutral(result)

    def test_found_path_does_not_hide_unknown_return_alternative(self):
        service = flow.SERVICE.replace("return mapper.load(id, tenant);",
            "long chosen=tenant; if(id<0){chosen=externalValue();} return mapper.load(id, chosen);")
        result = self.trace(self.session({"Service.java": service}))
        self.assertTrue(result["paths"])
        self.assertIn("argument_origin_has_unknown_parts", result["gaps"])
        self.assertIn("call_return_not_modeled", result["selected_argument"]["local_value_flow"]["unknown_reasons"])
        self.assert_neutral(result)

    def test_depth_boundary_is_explicitly_incomplete(self):
        result = self.trace(self.session(), max_hops=0)
        self.assertTrue(result["truncated"])
        self.assertIn("trace_depth_limit", result["gaps"])
        self.assertEqual(result["paths"][0]["candidate_hops"], 0)
        self.assertEqual(result["paths"][0]["boundary_reason"], "trace_depth_limit")
        self.assert_neutral(result)

    def test_scope_order_is_stable_and_trace_cache_is_request_local(self):
        session = self.session()
        first = self.trace(session)
        second = self.trace(session, scope_paths=["Controller.java", "Service.java", "Facade.java"])
        self.assertEqual(first, second)
        metadata = session.call("get_snapshot_info")
        self.assertEqual(metadata["argument_origin_tracing"]["requests"], 2)
        self.assertEqual(metadata["source_sink_tracing"]["requests"], 0)
        self.assertEqual(metadata["operation_context"]["computations"], 0)
        self.assertEqual(metadata["argument_origin_tracing"]["parse_attempts"],
                         2 * first["statistics"]["source_parse_attempts"])

    def test_trace_evidence_ids_are_resolved_inside_their_own_context(self):
        session = self.session()
        result = self.trace(session)
        self.assert_references(session, result)
        self.assertGreater(len(result["contexts"]), 1)
        for path in result["paths"]:
            for step in path["steps"]:
                context = result["contexts"][step["context_index"]]
                self.assertEqual(context["anchor"], step["anchor"])
                self.assertNotIn("context_id", context["operation"])
                evidence_ids = {e["id"] for e in context["operation"]["local_value_flow"]["evidence"]}
                self.assertTrue(step["local_relation"]["evidence_ids"])
                self.assertTrue(set(step["local_relation"]["evidence_ids"]) <= evidence_ids)
                full = session.call("inspect_operation_context", dict(step["anchor"], view="full"))
                self.assertRegex(full["context_id"], r"^[0-9a-f]{64}$")
                self.assertEqual(full["call_id"], step["anchor"]["call_id"])
                self.assertEqual(full["local_value_flow"], context["operation"]["local_value_flow"])


if __name__ == "__main__":
    unittest.main()
