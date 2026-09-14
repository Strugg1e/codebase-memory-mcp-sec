"""Additional scope/identity tests. Reuse transport helpers, not test results."""
import unittest
import test_operation as base


class OperationEdges(unittest.TestCase):
    def session(self, **kwargs):
        s = base.Session(self, **kwargs)
        self.addCleanup(s.close)
        return s

    def test_bind_prevents_false_parameter_link(self):
        xml = base.XML.replace("SELECT *", '<bind name="tenant" value="1"/> SELECT *')
        data = self.session(xml=xml).inspect()
        self.assertIn("dynamic_binding_scope_not_resolved", data["gaps"])
        self.assertTrue(all("argument_index" not in v for v in data["mybatis"]["parameter_occurrences"]))

    def test_include_is_not_silently_expanded(self):
        xml = base.XML.replace("AND tenant_id = #{tenant}", '<include refid="tenantScope"/>')
        data = self.session(xml=xml).inspect()
        self.assertIn("dynamic_binding_scope_not_resolved", data["gaps"])
        self.assertFalse(data["truncated"])

    def test_bad_arity_is_not_linked(self):
        caller = base.CALLER.replace("mapper.load(id, tenantId)", "mapper.load(id)")
        data = self.session(caller=caller).inspect()
        self.assertEqual(data["mybatis"]["reason"], "mapper_arguments_not_positionally_aligned")

    def test_custom_xml_language_is_unknown(self):
        xml = base.XML.replace('id="load"', 'id="load" lang="custom.Driver"')
        data = self.session(xml=xml).inspect()
        self.assertEqual(data["mybatis"]["reason"], "custom_scripting_language_not_supported")

    def test_constructor_wiring_stays_a_type_candidate(self):
        caller = base.CALLER.replace("OrderMapper mapper;", "final OrderMapper mapper; Controller(OrderMapper value) { this.mapper = value; }")
        data = self.session(caller=caller).inspect()
        self.assertEqual(data["mybatis"]["status"], "explicit_mapping_candidate")
        self.assertEqual(data["mybatis"]["runtime_binding"], "not_verified")

    def test_schema_qualified_table_location(self):
        data = self.session(xml=base.XML.replace("FROM orders", "FROM shop.orders")).inspect()
        self.assertEqual(data["mybatis"]["leading_table_candidate"]["text_prefix"], "shop.orders")

    def test_mapping_snapshot_cannot_change_after_start(self):
        s = self.session()
        before = s.inspect()
        s.path.unlink()
        self.assertEqual(s.inspect(), before)

    def test_wrong_snapshot_does_no_operation_work(self):
        s = self.session()
        args = {**s.anchor(), "snapshot_id": "0" * 64}
        self.assertEqual(s.call("inspect_operation_context", args, ok=False)["error"]["code"], "snapshot_mismatch")
        self.assertEqual(s.call("get_snapshot_info")["operation_context"]["parse_attempts"], 0)

    def test_standard_mapper_doctype_is_not_loaded(self):
        header = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "https://mybatis.org/dtd/mybatis-3-mapper.dtd">\n'
        data = self.session(xml=header + base.XML).inspect()
        self.assertEqual(data["mybatis"]["status"], "explicit_mapping_candidate")
        self.assertIn("xml_dtd_not_loaded_or_validated", data["gaps"])

    def test_xml_parse_error_identifies_the_failed_input(self):
        data = self.session(xml="<mapper>").inspect()
        self.assertEqual(data["mybatis"]["status"], "unresolved")
        self.assertEqual(data["mybatis"]["reason"], "operation_syntax_incomplete")
        self.assertIn("xml_mapping_not_parsed", data["gaps"])
        self.assertTrue(data["java_context"]["parameters"])


if __name__ == "__main__":
    unittest.main()
