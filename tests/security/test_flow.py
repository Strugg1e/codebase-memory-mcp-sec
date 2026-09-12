"""Explicit caller-path regressions over real Java parsers and MCP subprocesses."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

# Reuse the protocol client, not its TestCase classes or recorded results.
import test_operation as harness

SERVICE = '''package app;
import data.OrderMapper;
class OrderService {
  OrderMapper mapper;
  Object load(long id, long tenant) { return mapper.load(id, tenant); }
}
'''
FACADE = '''package app;
class OrderFacade {
  OrderService service;
  Object load(long id, long tenant) { return service.load(id, tenant); }
}
'''
CONTROLLER = '''package app;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
class Controller {
  OrderFacade facade;
  @GetMapping("/orders")
  Object find(@RequestParam long id, @RequestParam long tenant) {
    return facade.load(id, tenant);
  }
}
'''


class Session(harness.Session):
    def __init__(self, case, sources):
        self.case = case
        self.sources = sources
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "source.json"
        raw = json.dumps({"schema": "cbm.security-snapshot.v1", "files": [
            {"path": p, "source": s, "sha256": harness.digest(s.encode())}
            for p, s in sources.items()]}, ensure_ascii=False).encode()
        self.snapshot = harness.digest(raw)
        self.path.write_bytes(raw)
        self.proc = subprocess.Popen([str(harness.MCP), "--snapshot", str(self.path),
                                      "--expect-snapshot", self.snapshot], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.i = 0
        self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                "clientInfo": {"name": "flow-regression", "version": "1"}})
        self.proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        self.proc.stdin.flush()

    def anchor_at(self, path, name="load", index=0):
        page = self.call("query_security_facts", {"path": path, "kind": "call_site", "limit": 200})
        calls = [f for f in page["facts"] if f.get("name", {}).get("text_prefix") == name]
        return {"path": path, "analysis_id": page["analysis_id"], "call_id": calls[index]["id"]}


class FlowTests(unittest.TestCase):
    def session(self, service=SERVICE, facade=FACADE, controller=CONTROLLER, extra=None):
        sources = {"Service.java": service, "Facade.java": facade, "Controller.java": controller,
                   "OrderMapper.java": harness.MAPPER, "OrderMapper.xml": harness.XML}
        sources.update(extra or {})
        s = Session(self, sources)
        self.addCleanup(s.close)
        return s

    def inspect(self, s, mapping=True, upstream=None, ok=True):
        args = s.anchor_at("Service.java")
        if upstream is None:
            upstream = [s.anchor_at("Facade.java"), s.anchor_at("Controller.java")]
        args["upstream_calls"] = upstream
        if mapping:
            args.update(mapper_path="OrderMapper.java", mapping_path="OrderMapper.xml")
        return s.call("inspect_operation_context", args, ok=ok)

    def test_two_hops_connect_request_to_existing_mapper_context(self):
        data = self.inspect(self.session())
        flow = data["argument_flow"]
        self.assertEqual(flow["linked_candidate_hops"], 2)
        self.assertEqual(flow["evaluated_hops"], 2)
        self.assertEqual(data["mybatis"]["status"], "explicit_mapping_candidate")
        for p in flow["paths"]:
            self.assertEqual(p["candidate_hops_followed"], 2)
            self.assertEqual(p["origin"], "request_parameter_declaration_candidate")
            self.assertEqual(p["stop_reason"], "selected_path_exhausted")
            self.assertEqual(p["trust"], "not_established")
        self.assertEqual(data["authorization_verdict"], "not_evaluated")

    def test_parameter_reordering_preserves_positions(self):
        data = self.inspect(self.session(service=SERVICE.replace("mapper.load(id, tenant)", "mapper.load(tenant, id)")))
        path = data["argument_flow"]["paths"][0]
        self.assertEqual([s["argument_index"] for s in path["steps"]], [0, 1, 1])

    def test_mutated_downstream_parameter_is_not_forwarded(self):
        data = self.inspect(self.session(service=SERVICE.replace("return mapper", "tenant = 0; return mapper")))
        p = data["argument_flow"]["paths"][1]
        self.assertEqual(p["stop_reason"], "parameter_written_or_shadowed")
        self.assertEqual(p["candidate_hops_followed"], 0)

    def test_mutated_intermediate_parameter_stops_before_entrypoint(self):
        data = self.inspect(self.session(facade=FACADE.replace("return service", "tenant = 0; return service")))
        p = data["argument_flow"]["paths"][1]
        self.assertEqual(p["candidate_hops_followed"], 1)
        self.assertEqual(p["origin"], "parameter_written_or_shadowed")

    def test_local_alias_remains_a_visible_gap(self):
        data = self.inspect(self.session(service=SERVICE.replace("return mapper.load(id, tenant)", "long alias = tenant; return mapper.load(id, alias)")))
        p = data["argument_flow"]["paths"][1]
        self.assertEqual(p["origin"], "expression_not_traced")
        self.assertEqual(p["candidate_hops_followed"], 0)

    def test_arithmetic_is_not_identity_preserving_flow(self):
        data = self.inspect(self.session(service=SERVICE.replace("mapper.load(id, tenant)", "mapper.load(id, tenant + 1)")))
        self.assertEqual(data["argument_flow"]["paths"][1]["origin"], "expression_not_traced")
        self.assertEqual(data["argument_flow"]["taint_transformations"], "not_modeled")

    def test_identity_looking_name_is_not_trusted(self):
        data = self.inspect(self.session(controller=CONTROLLER.replace("facade.load(id, tenant)", "facade.load(id, principal.getTenantId())")))
        p = data["argument_flow"]["paths"][1]
        self.assertEqual(p["origin"], "expression_not_traced")
        self.assertEqual(p["trust"], "not_established")

    def test_literal_and_request_calls_do_not_cross_contaminate(self):
        s = self.session(facade=FACADE.replace("return service.load(id, tenant);", "service.load(id, 0); return service.load(id, tenant);"))
        fixed = self.inspect(s, upstream=[s.anchor_at("Facade.java", index=0)])
        tainted = self.inspect(s, upstream=[s.anchor_at("Facade.java", index=1)])
        self.assertNotEqual(fixed["context_id"], tainted["context_id"])
        self.assertEqual(fixed["argument_flow"]["paths"][1]["origin"], "expression_not_traced")
        self.assertEqual(tainted["argument_flow"]["paths"][1]["origin"], "formal_parameter_reference")

    def test_wrong_method_does_not_connect(self):
        s = self.session(facade=FACADE.replace("service.load", "service.other"))
        data = self.inspect(s, upstream=[s.anchor_at("Facade.java", name="other")])
        self.assertEqual(data["argument_flow"]["links"][0]["reason"], "callee_method_mismatch")
        self.assertEqual(data["argument_flow"]["linked_candidate_hops"], 0)

    def test_wrong_declared_type_does_not_connect(self):
        data = self.inspect(self.session(facade=FACADE.replace("OrderService service", "OtherService service")))
        self.assertEqual(data["argument_flow"]["linked_candidate_hops"], 0)
        self.assertEqual(data["argument_flow"]["status"], "partial")

    def test_receiver_reassignment_does_not_connect(self):
        data = self.inspect(self.session(facade=FACADE.replace("return service", "service = other; return service")))
        self.assertEqual(data["argument_flow"]["linked_candidate_hops"], 0)

    def test_explicit_this_receiver_is_supported(self):
        data = self.inspect(self.session(facade=FACADE.replace("service.load", "this.service.load")))
        self.assertEqual(data["argument_flow"]["linked_candidate_hops"], 2)

    def test_receiver_parameter_is_supported(self):
        s = self.session(facade=FACADE.replace("OrderService service;", "").replace("load(long id, long tenant)", "load(OrderService service, long id, long tenant)"))
        data = self.inspect(s, upstream=[s.anchor_at("Facade.java")])
        self.assertEqual(data["argument_flow"]["linked_candidate_hops"], 1)

    def test_overload_is_not_selected_by_argument_count(self):
        service = SERVICE.replace("OrderMapper mapper;", "OrderMapper mapper; Object load(String x) { return null; }")
        data = self.inspect(self.session(service=service))
        self.assertEqual(data["argument_flow"]["links"][0]["reason"], "ambiguous_or_overloaded_target")

    def test_interface_dispatch_is_not_guessed(self):
        data = self.inspect(self.session(facade=FACADE.replace("OrderService service", "IOrderService service")))
        self.assertEqual(data["argument_flow"]["linked_candidate_hops"], 0)

    def test_inherited_target_is_not_assumed(self):
        data = self.inspect(self.session(service=SERVICE.replace("class OrderService {", "class OrderService extends Base {")))
        self.assertEqual(data["argument_flow"]["links"][0]["reason"], "inheritance_or_generics_not_modeled")

    def test_argument_count_mismatch_stops_link(self):
        data = self.inspect(self.session(facade=FACADE.replace("service.load(id, tenant)", "service.load(id)")))
        self.assertEqual(data["argument_flow"]["links"][0]["reason"], "caller_argument_count_mismatch")

    def test_varargs_are_not_positionally_guessed(self):
        data = self.inspect(self.session(service=SERVICE.replace("long tenant)", "long... tenant)")))
        self.assertEqual(data["argument_flow"]["links"][0]["reason"], "varargs_or_receiver_not_modeled")

    def test_branch_conditions_are_not_path_feasibility_proofs(self):
        data = self.inspect(self.session(facade=FACADE.replace("return service.load(id, tenant);", "if (allowed) return service.load(id, tenant); return null;")))
        self.assertEqual(data["argument_flow"]["path_feasibility"], "not_evaluated")
        self.assertTrue(data["argument_flow"]["upstream_contexts"][0]["java_context"]["conditions"])

    def test_link_references_match_original_bytes(self):
        s = self.session(facade=FACADE.replace("class OrderFacade", "// 中文\nclass OrderFacade"))
        data = self.inspect(s)
        def visit(v):
            if isinstance(v, dict):
                if "start_byte" in v and "sha256" in v:
                    raw = s.sources[v["path"]].encode()
                    self.assertEqual(v["sha256"], harness.digest(raw))
                    exact = raw[v["start_byte"]:v["end_byte"]]
                    self.assertTrue(exact.startswith(v["text_prefix"].encode()))
                for child in v.values(): visit(child)
            elif isinstance(v, list):
                for child in v: visit(child)
        visit(data)
        self.assertIn("receiver_declaration", data["argument_flow"]["links"][0])

    def test_missing_upstream_preserves_old_operation_api(self):
        s = self.session()
        data = s.call("inspect_operation_context", s.anchor_at("Service.java"))
        self.assertNotIn("argument_flow", data)

    def test_repeated_queries_keep_identity_and_facts(self):
        s = self.session()
        first = self.inspect(s)
        second = self.inspect(s)
        self.assertEqual(first, second)
        self.assertEqual(s.call("get_snapshot_info")["operation_context"]["parse_attempts"], 22)

    def test_upstream_change_changes_context_identity(self):
        s = self.session()
        one = self.inspect(s, upstream=[s.anchor_at("Facade.java")])
        two = self.inspect(s)
        self.assertNotEqual(one["context_id"], two["context_id"])

    def test_schema_advertises_the_same_bound_as_validation(self):
        s = self.session()
        tools = s.rpc("tools/list", {})["tools"]
        self.assertEqual(len(tools), 10)
        schema = next(t for t in tools if t["name"] == "inspect_operation_context")["inputSchema"]["properties"]["upstream_calls"]
        self.assertEqual(schema["type"], "array")
        self.assertEqual(schema["maxItems"], 4)
        self.assertEqual(set(schema["items"]["required"]), {"path", "analysis_id", "call_id"})
        self.assertFalse(schema["items"]["additionalProperties"])

    def test_stale_upstream_rejected_before_operation_parse(self):
        s = self.session()
        root = s.anchor_at("Service.java")
        up = s.anchor_at("Facade.java")
        up["analysis_id"] = "0" * 64
        before = s.call("get_snapshot_info")
        data = s.call("inspect_operation_context", {**root, "upstream_calls": [up]}, ok=False)
        self.assertEqual(data["error"]["code"], "analysis_mismatch")
        self.assertEqual(before["operation_context"], s.call("get_snapshot_info")["operation_context"])

    def test_unknown_upstream_path_rejected(self):
        s = self.session(); up = s.anchor_at("Facade.java"); up["path"] = "../outside.java"
        data = self.inspect(s, upstream=[up], ok=False)
        self.assertEqual(data["error"]["code"], "flow_path_not_in_snapshot")

    def test_repeated_anchor_is_rejected(self):
        s = self.session(); up = s.anchor_at("Facade.java")
        self.assertEqual(self.inspect(s, upstream=[up, up], ok=False)["error"]["code"], "repeated_flow_anchor")

    def test_root_cannot_be_its_own_upstream(self):
        s = self.session()
        self.assertEqual(self.inspect(s, upstream=[s.anchor_at("Service.java")], ok=False)["error"]["code"], "repeated_flow_anchor")

    def test_invalid_upstream_shapes_are_rejected(self):
        s = self.session()
        for path in ([], {}, "path", [1], [None], [{"path": "Facade.java"}], [{"path":"Facade.java", "analysis_id":1,"call_id":"0"*64}]):
            with self.subTest(path=path):
                self.assertIn("error", self.inspect(s, upstream=path, ok=False))

    def test_hop_limit_is_rejected_not_silently_clipped(self):
        s = self.session(); up = s.anchor_at("Facade.java")
        data = self.inspect(s, upstream=[up] * 5, ok=False)
        self.assertEqual(data["error"]["code"], "invalid_flow_path")

    def test_unknown_call_id_is_not_accepted_as_a_link(self):
        s = self.session(); up = s.anchor_at("Facade.java"); up["call_id"] = "0" * 64
        data = self.inspect(s, upstream=[up], ok=False)
        self.assertEqual(data["error"]["code"], "fact_not_found_in_extracted_scope")
        self.assertTrue(s.call("get_snapshot_info"))

    def test_four_hops_run_without_recursion(self):
        sources = {"L0.java": "package app; class L0 { Object load(long x) { return target.save(x); }}"}
        for i in range(1, 5):
            sources[f"L{i}.java"] = f"package app; class L{i} {{ L{i-1} next; Object load(long x) {{ return next.load(x); }} }}"
        s = Session(self, sources); self.addCleanup(s.close)
        root = s.anchor_at("L0.java", name="save")
        upstream = [s.anchor_at(f"L{i}.java") for i in range(1, 5)]
        data = s.call("inspect_operation_context", {**root, "upstream_calls": upstream})
        self.assertEqual(data["argument_flow"]["linked_candidate_hops"], 4)
        self.assertEqual(len(data["argument_flow"]["paths"][0]["steps"]), 5)


if __name__ == "__main__":
    unittest.main()
