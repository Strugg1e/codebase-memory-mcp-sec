"""Operation projections from real Java/XML parsers over the actual MCP process."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

MCP = Path(sys.argv.pop(1)).resolve().with_name("cbm-security-mcp")
CALLER = '''package app;
import data.OrderMapper;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
class Controller {
    OrderMapper mapper;
    @GetMapping("/orders")
    Object find(@RequestParam long id, @RequestParam long tenantId) {
        if (id < 0) { throw new IllegalArgumentException(); }
        return mapper.load(id, tenantId);
    }
}
'''
MAPPER = '''package data;
import org.apache.ibatis.annotations.Param;
public interface OrderMapper {
    Object load(@Param("id") long id, @Param("tenant") long tenantId);
}
'''
XML = '''<mapper namespace="data.OrderMapper">
<select id="load" resultType="map">
  SELECT * FROM orders WHERE id = #{id} AND tenant_id = #{tenant}
</select>
</mapper>'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Session:
    def __init__(self, case, caller=CALLER, mapper=MAPPER, xml=XML):
        self.case = case
        self.sources = {"Controller.java": caller, "OrderMapper.java": mapper, "OrderMapper.xml": xml}
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "source.json"
        raw = json.dumps({"schema": "cbm.security-snapshot.v1", "files": [
            {"path": p, "source": s, "sha256": digest(s.encode())} for p, s in self.sources.items()
        ]}, ensure_ascii=False).encode()
        self.snapshot = digest(raw)
        self.path.write_bytes(raw)
        self.proc = subprocess.Popen([str(MCP), "--snapshot", str(self.path), "--expect-snapshot", self.snapshot],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.i = 0
        self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                "clientInfo": {"name": "operation-regression", "version": "1"}})
        self.proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        self.proc.stdin.flush()

    def close(self):
        try:
            try:
                self.proc.stdin.close()
            except BrokenPipeError:
                pass
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                self.case.fail("operation service did not exit")
            self.case.assertEqual(self.proc.returncode, 0, self.proc.stderr.read().decode("utf8", "replace"))
        finally:
            self.proc.stdout.close()
            self.proc.stderr.close()
            self.tmp.cleanup()

    def rpc(self, method, params):
        self.i += 1
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.i, "method": method, "params": params}).encode() + b"\n")
        self.proc.stdin.flush()
        ready, _, _ = select.select([self.proc.stdout], [], [], 20)
        self.case.assertTrue(ready, "operation response timed out")
        raw = self.proc.stdout.readline()
        self.case.assertTrue(raw, "operation service closed its output")
        result = json.loads(raw)
        self.case.assertEqual(result["id"], self.i)
        return result["result"]

    def call(self, name, args=None, ok=True):
        values = dict(args or {})
        if name != "get_snapshot_info":
            values.setdefault("snapshot_id", self.snapshot)
        result = self.rpc("tools/call", {"name": name, "arguments": values})
        self.case.assertEqual(result["isError"], not ok, result)
        data = result["structuredContent"]
        self.case.assertEqual(json.loads(result["content"][0]["text"]), data)
        return data

    def anchor(self):
        page = self.call("query_security_facts", {"path": "Controller.java", "kind": "call_site", "limit": 200})
        call = next(f for f in page["facts"] if f.get("name", {}).get("text_prefix") == "load")
        return {"path": "Controller.java", "analysis_id": page["analysis_id"], "call_id": call["id"]}

    def inspect(self, mapping=True, **changes):
        args = self.anchor()
        if mapping:
            args.update(mapper_path="OrderMapper.java", mapping_path="OrderMapper.xml")
        args.update(changes)
        return self.call("inspect_operation_context", args)


class OperationTests(unittest.TestCase):
    def session(self, **kwargs):
        session = Session(self, **kwargs)
        self.addCleanup(session.close)
        return session

    def test_direct_mapping_and_param_positions(self):
        data = self.session().inspect()
        self.assertEqual(data["mybatis"]["status"], "explicit_mapping_candidate")
        self.assertEqual(data["mybatis"]["namespace"], "data.OrderMapper")
        self.assertEqual(data["mybatis"]["sql_operation"], "SELECT")
        self.assertEqual(data["mybatis"]["leading_table_candidate"]["text_prefix"], "orders")
        self.assertEqual([b["argument_index"] for b in data["mybatis"]["parameter_bindings"]], [0, 1])
        self.assertEqual([p["argument_index"] for p in data["mybatis"]["parameter_occurrences"]], [0, 1])
        self.assertEqual(data["arguments"][1]["origin"], "request_parameter_declaration_candidate")
        self.assertEqual(data["arguments"][1]["trust"], "not_established")
        self.assertEqual(data["authorization_verdict"], "not_evaluated")
        self.assertFalse(data["truncated"])

    def test_all_source_spans_are_exact(self):
        s = self.session(caller=CALLER.replace("return mapper", 'String note = "中文"; return mapper'))
        data = s.inspect()
        def visit(value):
            if isinstance(value, dict):
                if "start_byte" in value:
                    raw = s.sources[value["path"]].encode()
                    self.assertEqual(value["sha256"], digest(raw))
                    actual = raw[value["start_byte"]:value["end_byte"]]
                    preview = value["text_prefix"].encode()
                    self.assertTrue(actual.startswith(preview))
                    if not value["text_truncated"]:
                        self.assertEqual(actual, preview)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(data)

    def test_local_context_without_mapping(self):
        data = self.session().inspect(mapping=False)
        self.assertEqual(data["mybatis"]["status"], "not_requested")
        self.assertEqual(len(data["java_context"]["parameters"]), 2)
        self.assertEqual(data["java_context"]["conditions"][0]["relation"], "lexically_before_call")
        self.assertTrue(any(v["kind"] == "throw_statement" for v in data["java_context"]["returns_and_throws"]))

    def test_untrusted_and_identity_like_values_are_not_conflated(self):
        caller = CALLER.replace("mapper.load(id, tenantId)", "mapper.load(id, principal.getTenantId())")
        data = self.session(caller=caller).inspect()
        self.assertEqual(data["arguments"][1]["origin"], "expression_not_traced")
        self.assertEqual(data["arguments"][1]["trust"], "not_established")

    def test_parameter_reassignment_cancels_origin_relation(self):
        caller = CALLER.replace("return mapper", "tenantId = serverValue(); return mapper")
        data = self.session(caller=caller).inspect()
        self.assertEqual(data["arguments"][1]["origin"], "parameter_written_or_shadowed")
        self.assertTrue(data["java_context"]["assignments"])

    def test_after_call_condition_is_not_before_guard(self):
        caller = CALLER.replace("return mapper.load(id, tenantId);", "Object result = mapper.load(id, tenantId); if (!allowed()) throw new Error(); return result;")
        conditions = self.session(caller=caller).inspect()["java_context"]["conditions"]
        self.assertEqual([v["relation"] for v in conditions], ["lexically_before_call", "lexically_after_or_overlapping"])
        self.assertTrue(all(v["enforcement"] == "not_proved" for v in conditions))

    def test_then_and_else_membership(self):
        for clause, expected in [("if (allowed()) return mapper.load(id, tenantId); return null;", "call_in_then_branch"),
                                 ("if (allowed()) return null; else return mapper.load(id, tenantId);", "call_in_else_branch")]:
            s = self.session(caller=CALLER.replace("return mapper.load(id, tenantId);", clause))
            self.assertIn(expected, [v["relation"] for v in s.inspect()["java_context"]["conditions"]])

    def test_this_receiver_and_explicit_type(self):
        caller = CALLER.replace("mapper.load", "this.mapper.load").replace("OrderMapper mapper", "data.OrderMapper mapper")
        self.assertEqual(self.session(caller=caller).inspect()["mybatis"]["status"], "explicit_mapping_candidate")

    def test_typed_parameter_receiver(self):
        caller = CALLER.replace("OrderMapper mapper;", "").replace("Object find(", "Object find(OrderMapper mapper, ")
        self.assertEqual(self.session(caller=caller).inspect()["mybatis"]["status"], "explicit_mapping_candidate")

    def test_param_fully_qualified_and_value_member(self):
        mapper = MAPPER.replace('@Param("id")', '@org.apache.ibatis.annotations.Param(value="id")')
        self.assertEqual(len(self.session(mapper=mapper).inspect()["mybatis"]["parameter_bindings"]), 2)

    def test_wrong_param_import_does_not_bind(self):
        mapper = MAPPER.replace("org.apache.ibatis.annotations.Param", "custom.Param")
        data = self.session(mapper=mapper).inspect()
        self.assertEqual(data["mybatis"]["parameter_bindings"], [])
        self.assertTrue(all(p["binding_status"] == "unresolved" for p in data["mybatis"]["parameter_occurrences"]))

    def test_missing_param_does_not_guess_compiler_names(self):
        mapper = MAPPER.replace('@Param("id") ', '').replace('@Param("tenant") ', '')
        data = self.session(mapper=mapper).inspect()
        self.assertEqual(data["mybatis"]["parameter_bindings"], [])
        self.assertIn("mapper_parameter_requires_explicit_Param", data["gaps"])

    def test_duplicate_alias_does_not_choose_a_parameter(self):
        mapper = MAPPER.replace('@Param("tenant")', '@Param("id")')
        data = self.session(mapper=mapper).inspect()
        self.assertEqual(data["mybatis"]["parameter_bindings"], [])
        self.assertTrue(all(p["binding_status"] == "unresolved" for p in data["mybatis"]["parameter_occurrences"]))

    def test_dynamic_condition_is_preserved(self):
        xml = XML.replace("AND tenant_id = #{tenant}", '<if test="tenant != null"> AND tenant_id = #{tenant}</if>')
        data = self.session(xml=xml).inspect()
        parameter = next(p for p in data["mybatis"]["parameter_occurrences"] if p.get("parameter_name") == "tenant")
        self.assertEqual(parameter["xml_conditions"][0]["text_prefix"], '"tenant != null"')
        self.assertIn("dynamic_sql_not_expanded", data["gaps"])
        self.assertTrue(all(not p["guaranteed_scope"] for p in data["mybatis"]["comparison_candidates"]))

    def test_foreach_binding_is_not_mapper_parameter(self):
        xml = XML.replace("AND tenant_id = #{tenant}", '<foreach collection="items" item="tenant"> AND tenant_id = #{tenant}</foreach>')
        data = self.session(xml=xml).inspect()
        p = data["mybatis"]["parameter_occurrences"][-1]
        self.assertEqual(p["binding_status"], "dynamic_scope_not_bound")
        self.assertNotIn("argument_index", p)

    def test_or_is_not_guaranteed_filter(self):
        data = self.session(xml=XML.replace("AND tenant_id", "OR tenant_id")).inspect()
        self.assertTrue(all(not c["guaranteed_scope"] for c in data["mybatis"]["comparison_candidates"]))
        self.assertEqual(data["mybatis"]["predicate_enforcement"], "not_proved")

    def test_xml_select_tag_does_not_override_update_sql(self):
        xml = XML.replace("SELECT * FROM orders WHERE id = #{id} AND tenant_id = #{tenant}",
                          "UPDATE orders SET tenant_id = #{tenant} WHERE id = #{id} RETURNING id")
        data = self.session(xml=xml).inspect()
        self.assertEqual(data["mybatis"]["sql_operation"], "UPDATE")
        self.assertEqual(data["mybatis"]["declared_xml_tag"]["text_prefix"], "select")

    def test_sql_comments_and_quoted_fake_markers(self):
        xml = XML.replace("SELECT * FROM orders", "SELECT 'FROM fake #{not_a_binding}' FROM orders /* #{ignored} */")
        data = self.session(xml=xml).inspect()
        self.assertEqual(data["mybatis"]["leading_table_candidate"]["text_prefix"], "orders")
        self.assertEqual(len(data["mybatis"]["parameter_occurrences"]), 2)

    def test_cdata_is_not_dropped(self):
        xml = XML.replace("SELECT * FROM orders WHERE id = #{id} AND tenant_id = #{tenant}",
                          "<![CDATA[SELECT * FROM orders WHERE id = #{id} AND tenant_id = #{tenant}]]>")
        self.assertEqual(len(self.session(xml=xml).inspect()["mybatis"]["parameter_occurrences"]), 2)

    def test_substitution_marker_is_not_prepared_parameter(self):
        data = self.session(xml=XML.replace("#{tenant}", "${tenant}")).inspect()
        self.assertEqual(data["mybatis"]["parameter_occurrences"][-1]["form"], "text_substitution_marker")

    def test_property_placeholder_is_not_whole_parameter(self):
        data = self.session(xml=XML.replace("#{tenant}", "#{tenant.owner}")).inspect()
        self.assertEqual(data["mybatis"]["parameter_occurrences"][-1]["binding_status"], "unresolved")

    def test_entity_declarations_do_not_read_external_content(self):
        xml = '<!DOCTYPE mapper [<!ENTITY external SYSTEM "file:///etc/passwd">]>' + XML.replace("SELECT *", "&external; SELECT *")
        data = self.session(xml=xml).inspect()
        self.assertNotIn("root:x:", json.dumps(data))
        self.assertTrue(any("xml_" in v for v in data["gaps"]))

    def test_repeatability_and_real_work_counters(self):
        s = self.session()
        a, b = s.inspect(), s.inspect()
        self.assertEqual(a, b)
        info = s.call("get_snapshot_info")
        self.assertEqual(info["operation_context"]["requests"], 2)
        self.assertEqual(info["operation_context"]["parse_attempts"], 6)
        self.assertFalse(info["operation_context"]["cached"])

    def test_stale_analysis_rejected_before_operation_parse(self):
        s = self.session()
        data = s.call("inspect_operation_context", {"path": "Controller.java", "analysis_id": "0" * 64, "call_id": "1" * 64}, ok=False)
        self.assertEqual(data["error"]["code"], "analysis_mismatch")
        self.assertEqual(s.call("get_snapshot_info")["operation_context"]["parse_attempts"], 0)

    def test_missing_and_out_of_snapshot_inputs(self):
        s = self.session()
        args = s.anchor()
        self.assertEqual(s.call("inspect_operation_context", {**args, "mapper_path": "OrderMapper.java"}, ok=False)["error"]["code"], "mapping_inputs_required_together")
        for path in ("../outside.xml", "/etc/passwd", "absent.xml"):
            self.assertEqual(s.call("inspect_operation_context", {**args, "mapper_path": "OrderMapper.java", "mapping_path": path}, ok=False)["error"]["code"], "mapping_path_not_in_snapshot")

    def test_call_identity_is_not_a_method_name(self):
        s = self.session()
        data = s.call("inspect_operation_context", {**s.anchor(), "call_id": "0" * 64}, ok=False)
        self.assertEqual(data["error"]["code"], "fact_not_found_in_extracted_scope")

    def test_node_collection_limit_and_item_truncation(self):
        caller = CALLER.replace("return mapper", "int x=0;" + "x=1;" * 80 + "return mapper")
        data = self.session(caller=caller).inspect()
        self.assertTrue(data["truncated"])
        self.assertEqual(len(data["java_context"]["assignments"]), 64)

    def test_six_tools_advertise_operation_schema(self):
        tools = self.session().rpc("tools/list", {})["tools"]
        tool = next(t for t in tools if t["name"] == "inspect_operation_context")
        self.assertEqual(set(tool["inputSchema"]["required"]), {"snapshot_id", "path", "analysis_id", "call_id"})
        self.assertTrue(tool["annotations"]["readOnlyHint"])


UNRESOLVED = [
    ("wrong_namespace", {}, XML.replace("data.OrderMapper", "other.OrderMapper"), "mapper_namespace_mismatch"),
    ("duplicate_statement", {}, XML.replace("</mapper>", '<select id="load">SELECT 1</select></mapper>'), "duplicate_statement_or_database_variants"),
    ("database_variant", {}, XML.replace('id="load"', 'id="load" databaseId="oracle"'), "database_variant_not_selected"),
    ("missing_statement", {}, XML.replace('id="load"', 'id="different"'), "statement_not_found"),
    ("malformed_xml", {}, "<mapper>", "operation_syntax_incomplete"),
    ("wrong_receiver_type", {"caller": CALLER.replace("import data.OrderMapper;", "import other.OrderMapper;")}, XML, "receiver_type_unresolved_or_changed"),
    ("nested_receiver", {"caller": CALLER.replace("mapper.load", "mapper.database.load")}, XML, "receiver_type_unresolved_or_changed"),
    ("local_shadow", {"caller": CALLER.replace("return mapper", "Other mapper = other; return mapper")}, XML, "receiver_type_unresolved_or_changed"),
    ("overloaded_mapper", {"mapper": MAPPER.replace("public interface OrderMapper {", "public interface OrderMapper { Object load(long id);")}, XML, "mapper_method_overloaded"),
    ("default_method", {"mapper": MAPPER.replace("Object load(", "default Object load(").replace("long tenantId);", "long tenantId) { return null; }")}, XML, "mapper_method_has_implementation"),
]


def unresolved_test(options, xml, expected):
    def run(self):
        data = self.session(**options, xml=xml).inspect()
        self.assertEqual(data["mybatis"]["status"], "unresolved", data)
        self.assertEqual(data["mybatis"]["reason"], expected)
        self.assertIn("java_context", data)
        self.assertEqual(data["authorization_verdict"], "not_evaluated")
    return run


for name, options, xml, expected in UNRESOLVED:
    setattr(OperationTests, "test_" + name, unresolved_test(options, xml, expected))

if __name__ == "__main__":
    unittest.main()
