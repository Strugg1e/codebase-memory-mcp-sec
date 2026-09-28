"""Independent inventory contracts using real MCP and controlled source texts.

These tests are not a recovery of the historical 0.15.0-dev candidate.
No target Java, SQL, framework server, network, or model is executed.
"""
from __future__ import annotations

import hashlib
import json
import unittest

import test_flow as flow


class ResourceOperationsTests(unittest.TestCase):
    def session(self, changes=None, only=None):
        sources = {"Service.java": flow.SERVICE, "Facade.java": flow.FACADE,
                   "OrderMapper.java": flow.harness.MAPPER, "OrderMapper.xml": flow.harness.XML}
        sources.update(changes or {})
        if only is not None:
            sources = {key: sources[key] for key in only}
        result = flow.Session(self, sources)
        self.addCleanup(result.close)
        return result

    def query(self, session, ok=True, **changes):
        args = {"application_id": "controlled-resource", "scope_paths": list(session.sources)}
        args.update(changes)
        return session.call("query_resource_operations", args, ok=ok)

    def complete(self, session, **changes):
        pages = []
        cursor = None
        seen = set()
        while True:
            args = dict(changes)
            if cursor is not None:
                args["cursor"] = cursor
            page = self.query(session, **args)
            pages.append(page)
            cursor = page["page"]["next_cursor"]
            if cursor is None:
                break
            self.assertNotIn(cursor, seen, "pagination did not advance")
            seen.add(cursor)
            self.assertLessEqual(len(seen), page["page"]["tasks_total"])
        return pages

    def neutral(self, data):
        self.assertEqual(data["security_verdict"], "not_evaluated")
        self.assertEqual(data["absence_semantics"], "no_negative_security_conclusion")

    def references(self, session, value):
        if isinstance(value, list):
            for child in value:
                self.references(session, child)
        elif isinstance(value, dict):
            if {"path", "sha256", "start_byte", "end_byte"} <= value.keys():
                raw = session.sources[value["path"]].encode("utf-8")
                self.assertEqual(value["sha256"], hashlib.sha256(raw).hexdigest())
                start, end = value["start_byte"], value["end_byte"]
                self.assertGreaterEqual(start, 0)
                self.assertLessEqual(start, end)
                self.assertLessEqual(end, len(raw))
                raw[:start].decode("utf-8")
                raw[:end].decode("utf-8")
                text = raw[start:end].decode("utf-8")
                self.assertTrue(text.startswith(value.get("text_prefix", "")))
                if "text_prefix" in value and not value.get("text_truncated", False):
                    self.assertEqual(text, value["text_prefix"])
            for child in value.values():
                self.references(session, child)

    def test_all_pages_account_for_successful_and_unresolved_mapping_checks(self):
        session = self.session()
        one = self.query(session)
        pages = self.complete(session, max_checks=1, limit=1)
        self.assertEqual(pages[0]["operations"], [])
        attempts = [a for p in pages for a in p["attempts"]]
        operations = [o for p in pages for o in p["operations"]]
        self.assertEqual(attempts, one["attempts"])
        self.assertEqual(operations, one["operations"])
        self.assertEqual([a["task_index"] for a in attempts], list(range(one["page"]["tasks_total"])))
        self.assertTrue(any(a["status"] == "unresolved" for a in attempts))
        for page in pages:
            self.assertEqual(page["query_id"], one["query_id"])
            self.assertEqual(page["declarations"], one["declarations"])
            self.neutral(page)
        self.assertTrue(pages[-1]["page"]["enumeration_complete"])

    def test_page_size_change_does_not_change_query_or_operation_identity(self):
        session = self.session()
        first = self.query(session, max_checks=1, limit=1)
        rest = self.query(session, cursor=first["page"]["next_cursor"], max_checks=32, limit=20)
        full = self.query(session)
        self.assertEqual(first["query_id"], rest["query_id"])
        self.assertEqual(rest["operations"], full["operations"])

    def test_scope_order_is_normalized(self):
        session = self.session()
        self.assertEqual(self.query(session), self.query(session, scope_paths=list(reversed(session.sources))))

    def test_cursor_cannot_change_application_scope_or_filters(self):
        session = self.session()
        first = self.query(session, max_checks=1)
        cursor = first["page"]["next_cursor"]
        self.assertIsNotNone(cursor)
        for change in ({"application_id": "other"}, {"scope_paths": ["Service.java", "OrderMapper.java", "OrderMapper.xml"]},
                       {"operation_kind": "read"}, {"mapping_format": "xml"}):
            with self.subTest(change=change):
                result = self.query(session, ok=False, cursor=cursor, **change)
                self.assertEqual(result["error"]["code"], "resource_query_mismatch")
        self.assertTrue(self.query(session, cursor=cursor)["operations"])

    def test_cursor_cannot_cross_snapshot(self):
        first = self.session()
        cursor = self.query(first, max_checks=1)["page"]["next_cursor"]
        second = self.session({"Service.java": flow.SERVICE + "\n// changed snapshot\n"})
        self.assertEqual(self.query(second, ok=False, cursor=cursor)["error"]["code"], "resource_query_mismatch")

    def test_malformed_and_out_of_range_cursor_rejected_with_recovery(self):
        session = self.session()
        query = self.query(session)
        for suffix in ("", "-1", "1junk", "99999999999999999999", str(query["page"]["tasks_total"] + 1)):
            with self.subTest(suffix=suffix):
                self.query(session, ok=False, cursor=query["query_id"] + "/" + suffix)
        self.assertEqual(self.query(session)["operations"], query["operations"])

    def test_operation_filter_keeps_unfiltered_declarations(self):
        session = self.session()
        full = self.query(session)
        filtered = self.query(session, operation_kind="delete")
        self.assertEqual(filtered["operations"], [])
        self.assertEqual(filtered["declarations"], full["declarations"])
        self.assertIn("filtered_operation_kind", [a["status"] for a in filtered["attempts"]])
        self.assertTrue(filtered["page"]["enumeration_complete"])
        self.neutral(filtered)

    def test_operation_identity_survives_matching_filter(self):
        session = self.session()
        all_result = self.query(session)
        reads = self.query(session, operation_kind="read")
        self.assertNotEqual(all_result["query_id"], reads["query_id"])
        self.assertEqual(all_result["scope_id"], reads["scope_id"])
        self.assertEqual(all_result["operations"], reads["operations"])

    def test_read_create_update_delete_not_just_dangerous_substitutions(self):
        examples = [("select", "SELECT * FROM orders WHERE id=#{id}", "read"),
                    ("select", "SELECT * FROM orders WHERE id=1", "read"),
                    ("insert", "INSERT INTO orders(id) VALUES(#{id})", "create"),
                    ("update", "UPDATE orders SET tenant_id=#{tenant} WHERE id=#{id}", "update"),
                    ("delete", "DELETE FROM orders WHERE id=#{id}", "delete")]
        for tag, sql, kind in examples:
            with self.subTest(kind=kind, sql=sql):
                xml = f'<mapper namespace="data.OrderMapper"><{tag} id="load">{sql}</{tag}></mapper>'
                result = self.query(self.session({"OrderMapper.xml": xml}), operation_kind=kind)
                self.assertEqual(len(result["operations"]), 1)
                self.assertEqual(result["operations"][0]["operation_kind_candidate"], kind)
                self.neutral(result)

    def test_unknown_sql_kind_is_retained_under_kind_filter(self):
        xml = '<mapper namespace="data.OrderMapper"><select id="load">WITH q AS (SELECT 1) SELECT * FROM q</select></mapper>'
        result = self.query(self.session({"OrderMapper.xml": xml}), operation_kind="delete")
        self.assertEqual(len(result["operations"]), 1)
        self.assertEqual(result["operations"][0]["operation_kind_candidate"], "unknown")
        self.assertEqual(result["operations"][0]["filter_status"], "operation_kind_unresolved")
        self.neutral(result)

    def test_xml_and_annotation_candidates_do_not_assume_runtime_precedence(self):
        mapper = flow.harness.MAPPER.replace("import org.apache.ibatis.annotations.Param;",
            "import org.apache.ibatis.annotations.Param; import org.apache.ibatis.annotations.Select;")
        mapper = mapper.replace("Object load(", '@Select("SELECT * FROM orders WHERE id=#{id}") Object load(')
        session = self.session({"OrderMapper.java": mapper})
        all_result = self.query(session)
        self.assertEqual({o["mapping_format"] for o in all_result["operations"]}, {"xml", "annotation"})
        self.assertEqual(len({o["operation_id"] for o in all_result["operations"]}), 2)
        for mode in ("xml", "annotation"):
            result = self.query(session, mapping_format=mode)
            self.assertEqual([o["mapping_format"] for o in result["operations"]], [mode])
            self.assertEqual({d["mapping_format"] for d in result["declarations"]}, {"xml", "annotation"})
            self.assertEqual(result["runtime_mapping_precedence"], "not_resolved")

    def test_duplicate_call_sites_remain_distinct_even_on_same_resource(self):
        service = flow.SERVICE.replace("return mapper.load", "mapper.load(id, 0); return mapper.load")
        session = self.session({"Service.java": service})
        result = self.query(session)
        operations = result["operations"]
        self.assertEqual(len(operations), 2)
        self.assertEqual(len({o["operation_id"] for o in operations}), 2)
        self.assertEqual(len({o["call_source"]["start_byte"] for o in operations}), 2)
        self.assertEqual(len({o["resource_candidate"]["peer_group_id"] for o in operations}), 1)
        for item in operations:
            deep = session.call(item["inspection"]["tool"], item["inspection"]["arguments"])
            self.assertEqual(deep["call"]["start_byte"], item["call_source"]["start_byte"])

    def test_ambiguous_mapper_type_is_not_silently_selected(self):
        session = self.session({"Duplicate.java": flow.harness.MAPPER})
        result = self.query(session)
        self.assertEqual(result["operations"], [])
        self.assertTrue(result["attempts"])
        self.assertEqual({a["reason"] for a in result["attempts"]}, {"mapper_type_not_unique_in_scope"})
        self.assertTrue(result["declarations"])
        self.neutral(result)

    def test_overloaded_mapper_is_not_guessed_from_name(self):
        mapper = flow.harness.MAPPER.replace("public interface OrderMapper {", "public interface OrderMapper { Object load(String id);")
        result = self.query(self.session({"OrderMapper.java": mapper}))
        self.assertEqual(result["operations"], [])
        self.assertTrue(all(a["status"] == "unresolved" for a in result["attempts"]))
        self.assertTrue(result["declarations"])
        self.neutral(result)

    def test_unpaired_xml_declaration_has_explicit_gap(self):
        result = self.query(self.session(only=["OrderMapper.xml"]))
        self.assertEqual(result["operations"], [])
        self.assertEqual(len(result["declarations"]), 1)
        self.assertIn("unpaired_mapper_xml", result["gaps"])
        self.assertEqual(result["declarations"][0]["runtime_binding"], "not_verified")
        self.neutral(result)

    def test_invalid_xml_reports_coverage_not_clean_absence(self):
        result = self.query(self.session({"OrderMapper.xml": '<mapper namespace="data.OrderMapper"><select'}))
        self.assertEqual(result["operations"], [])
        self.assertTrue(result["file_analysis_gaps"])
        coverage = {f["path"]: f for f in result["coverage"]}
        self.assertEqual(coverage["OrderMapper.xml"]["status"], "xml_syntax_incomplete")
        self.neutral(result)

    def test_unparsed_java_does_not_disappear_from_type_scope(self):
        result = self.query(self.session({"Broken.java": "package app; class Broken {"}))
        self.assertTrue(result["file_analysis_gaps"])
        self.assertEqual(len(result["operations"]), 1)
        self.assertFalse(result["operations"][0]["type_identity_scope_complete"])
        self.assertEqual(result["operations"][0]["status"], "operation_with_incomplete_type_scope")
        self.neutral(result)

    def test_non_java_xml_file_is_reported_in_coverage(self):
        result = self.query(self.session({"notes.py": "x = 1\n"}))
        self.assertTrue(result["file_analysis_gaps"])
        entry = next(x for x in result["coverage"] if x["path"] == "notes.py")
        self.assertEqual(entry["status"], "unsupported_resource_language")
        self.assertTrue(result["operations"])

    def test_direct_handler_containment_is_not_cross_method_reachability(self):
        session = self.session({"Direct.java": flow.harness.CALLER})
        result = self.query(session)
        direct = next(o for o in result["operations"] if o["call_source"]["path"] == "Direct.java")
        indirect = next(o for o in result["operations"] if o["call_source"]["path"] == "Service.java")
        self.assertTrue(direct["direct_entry_contexts"])
        self.assertEqual(direct["entry_relation"], "direct_handler_containment")
        self.assertEqual(indirect["direct_entry_contexts"], [])
        self.assertEqual(indirect["entry_relation"], "no_direct_entry_cross_method_reachability_not_searched")

    def test_structure_does_not_embed_full_context_or_local_evidence(self):
        session = self.session()
        before = session.call("get_snapshot_info")["operation_context"]
        result = self.query(session)
        self.assertEqual(session.call("get_snapshot_info")["operation_context"], before)
        for operation in result["operations"]:
            structure = operation["operation_structure"]
            self.assertNotIn("context_id", structure)
            self.assertNotIn("local_value_flow", structure)
            self.assertNotIn("argument_flow", structure)
            self.assertEqual(operation["analysis_scope"], "structure_and_mapping_only")
        self.assertEqual(result["statistics"]["local_flow_evaluations"], 0)
        self.assertEqual(result["statistics"]["return_summary_evaluations"], 0)

    def test_repeated_catalogue_reports_rebuild_not_cross_request_cache(self):
        session = self.session()
        first = self.query(session)
        before = session.call("get_snapshot_info")["resource_operations"]
        second = self.query(session)
        after = session.call("get_snapshot_info")["resource_operations"]
        self.assertEqual(first, second)
        self.assertEqual(after["requests"], before["requests"] + 1)
        self.assertEqual(after["source_parse_attempts"], before["source_parse_attempts"] + second["statistics"]["source_parse_attempts"])
        self.assertEqual(second["statistics"]["cache_scope"], "rebuild_catalog_per_page")

    def test_unicode_source_references_are_exact(self):
        session = self.session({"Service.java": "// 中文😀\n" + flow.SERVICE})
        self.references(session, self.query(session))

    def test_duplicate_or_missing_scope_is_rejected(self):
        session = self.session()
        for scope in ([], ["Service.java", "Service.java"], ["missing.java"]):
            with self.subTest(scope=scope):
                result = self.query(session, ok=False, scope_paths=scope)
                self.assertIn("error", result)
        self.assertTrue(self.query(session)["operations"])

    def test_invalid_filter_and_budget_rejected_with_recovery(self):
        session = self.session()
        cases = ({"operation_kind": "truncate"}, {"mapping_format": "auto"}, {"application_id": "bad\nlabel"},
                 {"limit": 0}, {"limit": 21}, {"max_checks": 0}, {"max_checks": 33}, {"max_checks": True})
        for change in cases:
            with self.subTest(change=change):
                self.assertIn("error", self.query(session, ok=False, **change))
        self.assertTrue(self.query(session)["operations"])

    def test_java_file_count_limit_is_enforced(self):
        session = self.session({f"More{i}.java": f"class More{i} {{}}" for i in range(15)})
        result = self.query(session, ok=False)
        self.assertEqual(result["error"]["code"], "resource_java_scope_limit")
        result = self.query(session, scope_paths=["Service.java", "OrderMapper.java", "OrderMapper.xml"])
        self.assertTrue(result["operations"])

    def test_single_file_size_limit_rejects_before_catalogue(self):
        session = self.session({"Large.java": "//" + "x" * (256 * 1024)})
        result = self.query(session, ok=False)
        self.assertEqual(result["error"]["code"], "resource_source_limit")

    def test_aggregate_size_limit_rejects_before_catalogue(self):
        session = self.session({f"Pad{i}.java": "//" + "x" * (240 * 1024) for i in range(9)})
        result = self.query(session, ok=False)
        self.assertEqual(result["error"]["code"], "resource_source_limit")


if __name__ == "__main__":
    unittest.main()
