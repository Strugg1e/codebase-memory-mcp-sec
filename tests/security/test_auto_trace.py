"""Automatic paths over real parser/MCP processes, without supplied upstream paths.
Fixtures are test source, not evidence of a production vulnerability.
"""
from __future__ import annotations
import copy
import hashlib
import json
import random
import unittest
import test_flow as flow

RULE = "spring-mybatis-text-substitution"
XML = flow.harness.XML.replace("#{tenant}", "${tenant}")


class AutoTraceTests(unittest.TestCase):
    def session(self, service=flow.SERVICE, facade=flow.FACADE,
                controller=flow.CONTROLLER, mapper=flow.harness.MAPPER, xml=XML, extra=None):
        sources = {"Service.java": service, "Facade.java": facade, "Controller.java": controller,
                   "OrderMapper.java": mapper, "OrderMapper.xml": xml}
        sources.update(extra or {})
        s = flow.Session(self, sources)
        self.addCleanup(s.close)
        return s

    def trace(self, s, **changes):
        args = {**s.anchor_at("Service.java"), "mapper_path": "OrderMapper.java",
                "mapping_path": "OrderMapper.xml",
                "scope_paths": ["Service.java", "Facade.java", "Controller.java"]}
        ok = changes.pop("ok", True)
        args.update(changes)
        return s.call("trace_source_to_sink", args, ok=ok)

    @staticmethod
    def origins(r):
        return {p["source"]["parameter"]["name"] for p in r["paths"]}

    def assert_references(self, s, value):
        if isinstance(value, dict):
            if {"path", "sha256", "start_byte", "end_byte"} <= value.keys():
                raw = s.sources[value["path"]].encode()
                self.assertEqual(value["sha256"], hashlib.sha256(raw).hexdigest())
                a, b = value["start_byte"], value["end_byte"]
                self.assertLessEqual(a, b); self.assertLessEqual(b, len(raw))
                snippet = raw[a:b].decode()
                self.assertTrue(snippet.startswith(value.get("text_prefix", "")))
                if not value.get("text_truncated", False):
                    self.assertEqual(value.get("text_prefix", snippet), snippet)
            for child in value.values(): self.assert_references(s, child)
        elif isinstance(value, list):
            for child in value: self.assert_references(s, child)

    def test_two_hops_without_upstream_anchors(self):
        r = self.trace(self.session())
        self.assertEqual(r["status"], "candidate_paths_found")
        self.assertEqual(self.origins(r), {"tenant"})
        self.assertEqual(r["paths"][0]["candidate_hops"], 2)
        self.assertEqual(r["rule_id"], RULE)
        self.assertFalse(r["truncated"])

    def test_root_is_a_mapped_handler(self):
        s = self.session(service=flow.harness.CALLER)
        r = self.trace(s, scope_paths=["Service.java"])
        self.assertEqual(self.origins(r), {"tenantId"})
        self.assertEqual(r["paths"][0]["candidate_hops"], 0)

    def test_scope_permutation_same_result_and_identity(self):
        s = self.session(); a = self.trace(s)
        b = self.trace(s, scope_paths=["Controller.java", "Facade.java", "Service.java"])
        self.assertEqual(a, b)

    def test_repeat_has_request_local_caches_not_global_state(self):
        s = self.session(); a = self.trace(s); b = self.trace(s)
        self.assertEqual(a, b)
        meta = s.call("get_snapshot_info")
        self.assertEqual(meta["source_sink_tracing"]["requests"], 2)
        self.assertGreater(a["statistics"]["context_cache_hits"], 0)
        self.assertEqual(meta["source_sink_tracing"]["parse_attempts"],
                         2 * a["statistics"]["source_parse_attempts"])

    def test_local_alias_is_traced(self):
        s = self.session(service=flow.SERVICE.replace("return mapper.load(id, tenant);", "long x=tenant; return mapper.load(id,x);"))
        self.assertEqual(self.origins(self.trace(s)), {"tenant"})

    def test_parameter_reordering(self):
        s = self.session(facade=flow.FACADE.replace("service.load(id, tenant)", "service.load(tenant, id)"))
        self.assertEqual(self.origins(self.trace(s)), {"id"})

    def test_multiple_reorderings_cancel(self):
        s = self.session(service=flow.SERVICE.replace("mapper.load(id, tenant)", "mapper.load(tenant, id)"),
                         facade=flow.FACADE.replace("service.load(id, tenant)", "service.load(tenant, id)"))
        self.assertEqual(self.origins(self.trace(s)), {"tenant"})

    def test_derived_expression_not_identity(self):
        s = self.session(service=flow.SERVICE.replace("mapper.load(id, tenant)", "mapper.load(id, tenant+1)"))
        r = self.trace(s)
        self.assertEqual(r["paths"][0]["relation"], "may_depend_after_transformation")

    def test_overwrite_at_sink_stops_formal_flow(self):
        s = self.session(service=flow.SERVICE.replace("return mapper", "tenant=0; return mapper"))
        r = self.trace(s); self.assertFalse(r["paths"])
        self.assertIn("no_known_formal_dependencies_remain", [x["reason"] for x in r["frontiers"]])
        self.assertEqual(r["security_verdict"], "not_evaluated")

    def test_overwrite_at_middle_stops_formal_flow(self):
        s = self.session(facade=flow.FACADE.replace("return service", "tenant=0; return service"))
        self.assertFalse(self.trace(s)["paths"])

    def test_branch_two_sources(self):
        s = self.session(service=flow.SERVICE.replace("return mapper.load(id, tenant);",
            "long x=tenant; if(id>0){x=id;} return mapper.load(id,x);"))
        self.assertEqual(self.origins(self.trace(s)), {"id", "tenant"})

    def test_branch_source_and_literal(self):
        s = self.session(service=flow.SERVICE.replace("return mapper.load(id, tenant);",
            "long x=tenant; if(id>0){x=0;} return mapper.load(id,x);"))
        r = self.trace(s); self.assertEqual(self.origins(r), {"tenant"})
        self.assertTrue(r["paths"][0]["literal_alternative_possible"])

    def test_known_source_plus_unknown_return_keeps_gap(self):
        s = self.session(service=flow.SERVICE.replace("return mapper.load(id, tenant);",
            "long x=tenant; if(id>0){x=other();} return mapper.load(id,x);"))
        r = self.trace(s); self.assertEqual(self.origins(r), {"tenant"})
        self.assertTrue(r["paths"][0]["unknown_reasons"])
        self.assertEqual(r["paths"][0]["status"], "candidate_with_unknowns")

    def test_unknown_return_only_not_guessed(self):
        s = self.session(service=flow.SERVICE.replace("mapper.load(id, tenant)", "mapper.load(id, identity.getTenantId())"))
        r = self.trace(s); self.assertFalse(r["paths"])
        self.assertEqual(r["frontiers"][0]["reason"], "unknown_value_origin")

    def test_helper_return_reuses_existing_summary(self):
        service=flow.SERVICE.replace("OrderMapper mapper;", "OrderMapper mapper; private long copy(long x){return x;}")
        s=self.session(service=service.replace("mapper.load(id, tenant)", "mapper.load(id, copy(tenant))"))
        r=self.trace(s);self.assertEqual(self.origins(r),{"tenant"})
        self.assertEqual(r["contexts"][0]["operation"]["local_value_flow"]["return_summaries"]["computed_methods"],1)

    def test_sanitizer_name_does_not_clear_flow(self):
        service=flow.SERVICE.replace("OrderMapper mapper;", "OrderMapper mapper; private long sanitize(long x){return x;}")
        r=self.trace(self.session(service=service.replace("mapper.load(id, tenant)", "mapper.load(id, sanitize(tenant))")))
        self.assertEqual(self.origins(r),{"tenant"});self.assertEqual(r["sanitizer_effects"],"not_modeled")

    def test_same_callee_two_calls_are_separate(self):
        s=self.session(facade=flow.FACADE.replace("return service.load(id, tenant);",
            "service.load(id,0); return service.load(id,tenant);"))
        r=self.trace(s);self.assertEqual(len(r["paths"]),1)
        self.assertIn("no_known_formal_dependencies_remain",[x["reason"] for x in r["frontiers"]])

    def test_two_real_callers_both_returned(self):
        extra={"OtherController.java":flow.CONTROLLER.replace("class Controller", "class OtherController").replace('"/orders"','"/other"')}
        r=self.trace(self.session(extra=extra),scope_paths=["Service.java","Facade.java","Controller.java","OtherController.java"])
        self.assertEqual(len(r["paths"]),2)
        self.assertEqual({p["source"]["entry"]["path"] for p in r["paths"]},{"Controller.java","OtherController.java"})

    def test_same_name_wrong_type_never_linked(self):
        s=self.session(facade=flow.FACADE.replace("OrderService service","WrongService service"))
        r=self.trace(s);self.assertFalse(r["paths"])
        self.assertTrue(any(x.get("reason")=="receiver_type_unresolved_or_rebound" for x in r["call_candidates"]))

    def test_overload_not_selected_by_name(self):
        s=self.session(service=flow.SERVICE.replace("OrderMapper mapper;","OrderMapper mapper; Object load(String x){return null;}"))
        r=self.trace(s);self.assertFalse(r["paths"])
        self.assertTrue(any(x.get("reason")=="ambiguous_or_overloaded_target" for x in r["call_candidates"]))

    def test_inheritance_not_guessed(self):
        r=self.trace(self.session(service=flow.SERVICE.replace("class OrderService", "class OrderService extends Base")))
        self.assertFalse(r["paths"])
        self.assertTrue(any(x.get("reason")=="inheritance_or_generics_not_modeled" for x in r["call_candidates"]))

    def test_duplicate_top_level_type_in_scope_stops_link(self):
        r=self.trace(self.session(extra={"Copy.java":flow.SERVICE}),
            scope_paths=["Service.java","Facade.java","Controller.java","Copy.java"])
        self.assertFalse(r["paths"])
        self.assertTrue(any(x.get("reason")=="target_type_not_unique_in_selected_scope" for x in r["call_candidates"]))

    def test_receiver_rebound_not_linked(self):
        s=self.session(facade=flow.FACADE.replace("return service", "service=other; return service"))
        self.assertFalse(self.trace(s)["paths"])

    def test_explicit_this_field_receiver(self):
        self.assertEqual(self.origins(self.trace(self.session(facade=flow.FACADE.replace("service.load","this.service.load")))),{"tenant"})

    def test_unmapped_request_annotation_is_not_source_endpoint(self):
        r=self.trace(self.session(controller=flow.CONTROLLER.replace('@GetMapping("/orders")','')))
        self.assertFalse(r["paths"])

    def test_no_request_annotation_no_source(self):
        r=self.trace(self.session(controller=flow.CONTROLLER.replace("@RequestParam ","")))
        self.assertFalse(r["paths"])

    def test_wrong_annotation_import_no_source(self):
        r=self.trace(self.session(controller=flow.CONTROLLER.replace("org.springframework.web.bind.annotation.RequestParam","other.RequestParam")))
        self.assertFalse(r["paths"])

    def test_identity_context_not_source(self):
        c=flow.CONTROLLER.replace("org.springframework.web.bind.annotation.RequestParam","org.springframework.security.core.annotation.AuthenticationPrincipal").replace("@RequestParam","@AuthenticationPrincipal")
        self.assertFalse(self.trace(self.session(controller=c))["paths"])

    def test_object_source_not_promoted_to_scalar_contents(self):
        c=flow.CONTROLLER.replace("long tenant)","Query tenant)")
        r=self.trace(self.session(controller=c));self.assertFalse(r["paths"])
        self.assertTrue(any(x["reason"]=="request_object_contents_not_modeled" for x in r["frontiers"]))

    def test_request_body_string_source(self):
        c=flow.CONTROLLER.replace("org.springframework.web.bind.annotation.RequestParam","org.springframework.web.bind.annotation.RequestBody").replace("@RequestParam long tenant","@RequestBody String tenant")
        r=self.trace(self.session(controller=c));self.assertEqual(self.origins(r),{"tenant"})

    def test_method_control_does_not_clear_dependency(self):
        c=flow.CONTROLLER.replace("class Controller", "class Controller").replace('@GetMapping("/orders")','@org.springframework.security.access.prepost.PreAuthorize("hasRole(\"ADMIN\")")\n @GetMapping("/orders")')
        # Use a syntactically valid annotation rather than relying on parse recovery.
        c=c.replace('hasRole("ADMIN")',"hasRole('ADMIN')")
        r=self.trace(self.session(controller=c));self.assertEqual(self.origins(r),{"tenant"})
        self.assertEqual(r["paths"][0]["source"]["entry"]["authorization"],"not_evaluated")

    def test_no_substitution_is_not_whole_program_safe(self):
        r=self.trace(self.session(xml=flow.harness.XML))
        self.assertEqual(r["status"],"no_matching_sink_in_selected_mapping");self.assertFalse(r["paths"])
        self.assertEqual(r["absence_semantics"],"no_negative_security_conclusion")

    def test_quoted_substitution_preserved(self):
        r=self.trace(self.session(xml=XML.replace("${tenant}","'${tenant}'")))
        self.assertEqual(self.origins(r),{"tenant"})

    def test_sql_comment_substitution_preserved(self):
        r=self.trace(self.session(xml=flow.harness.XML.replace("</select>"," /* ${tenant} */ </select>")))
        self.assertEqual(self.origins(r),{"tenant"})

    def test_property_sink_not_whole_object_taint(self):
        r=self.trace(self.session(xml=XML.replace("${tenant}","${tenant.owner}")))
        self.assertFalse(r["paths"])
        self.assertEqual(r["sinks"][0]["trace_status"],"binding_or_property_value_unresolved")
        self.assertIn("sink_value_binding_unresolved",r["gaps"])

    def test_missing_param_binding_stays_unknown(self):
        r=self.trace(self.session(mapper=flow.harness.MAPPER.replace('@Param("tenant") ','')))
        self.assertFalse(r["paths"]);self.assertTrue(r["sinks"])

    def test_dynamic_condition_preserved_at_sink(self):
        x=XML.replace('AND tenant_id = ${tenant}','<if test="tenant != null">AND tenant_id = ${tenant}</if>')
        r=self.trace(self.session(xml=x));self.assertEqual(self.origins(r),{"tenant"})
        self.assertTrue(r["sinks"][0]["xml_conditions"])

    def test_annotation_mapping_supported(self):
        mapper=flow.harness.MAPPER.replace('Object load(', '@org.apache.ibatis.annotations.Select("SELECT * FROM orders WHERE tenant_id=${tenant}") Object load(')
        s=self.session(mapper=mapper)
        args={**s.anchor_at("Service.java"),"mapper_path":"OrderMapper.java","mapping_format":"annotation",
              "scope_paths":["Service.java","Facade.java","Controller.java"]}
        self.assertEqual(self.origins(s.call("trace_source_to_sink",args)),{"tenant"})

    def test_mapping_mismatch_not_no_sink(self):
        r=self.trace(self.session(xml=XML.replace('data.OrderMapper','data.Wrong')))
        self.assertEqual(r["status"],"sink_mapping_unresolved")
        self.assertIn("sink_mapping_not_resolved",r["gaps"])

    def test_distinct_substitutions_preserved(self):
        r=self.trace(self.session(xml=XML.replace('#{id}','${id}')))
        self.assertEqual(self.origins(r),{"id","tenant"})
        self.assertEqual({x["sink_index"] for x in r["paths"]},{0,1})

    def test_repeated_marker_is_not_collapsed(self):
        r=self.trace(self.session(xml=XML.replace('${tenant}','${tenant} + ${tenant}')))
        self.assertEqual(len(r["sinks"]),2);self.assertEqual(len(r["paths"]),2)
        self.assertNotEqual(r["paths"][0]["path_id"],r["paths"][1]["path_id"])
        self.assertGreater(r["statistics"]["edge_cache_hits"],0)

    def test_four_hop_budget(self):
        bridge=flow.FACADE.replace("OrderFacade","Bridge").replace("OrderService","OrderFacade")
        gateway=flow.FACADE.replace("OrderFacade","Gateway").replace("OrderService","Bridge")
        c=flow.CONTROLLER.replace("OrderFacade facade", "Gateway facade")
        r=self.trace(self.session(controller=c,extra={"Bridge.java":bridge,"Gateway.java":gateway}),
            scope_paths=["Service.java","Facade.java","Bridge.java","Gateway.java","Controller.java"])
        self.assertEqual(r["paths"][0]["candidate_hops"],4)

    def test_depth_limit_keeps_frontier(self):
        r=self.trace(self.session(),max_hops=1)
        self.assertFalse(r["paths"]);self.assertTrue(r["truncated"])
        self.assertIn("trace_depth_limit",r["gaps"])

    def test_local_only_limit_zero(self):
        r=self.trace(self.session(service=flow.harness.CALLER),scope_paths=["Service.java"],max_hops=0)
        self.assertEqual(len(r["paths"]),1);self.assertFalse(r["truncated"])

    def test_edge_budget_keeps_frontier(self):
        r=self.trace(self.session(),max_edge_checks=1)
        self.assertLessEqual(r["statistics"]["edge_checks"],1);self.assertTrue(r["truncated"])
        self.assertIn("trace_edge_check_limit",r["gaps"])

    def test_path_budget_preserves_found_result(self):
        extra={"OtherController.java":flow.CONTROLLER.replace("class Controller","class OtherController")}
        r=self.trace(self.session(extra=extra),scope_paths=["Service.java","Facade.java","Controller.java","OtherController.java"],max_paths=1)
        self.assertEqual(len(r["paths"]),1);self.assertTrue(r["truncated"])
        self.assertIn("trace_path_limit",r["gaps"])

    def test_unselected_caller_not_used(self):
        r=self.trace(self.session(),scope_paths=["Service.java","Facade.java"])
        self.assertFalse(r["paths"])
        self.assertEqual({f["path"] for f in r["coverage"]},{"Service.java","Facade.java"})

    def test_same_class_recursion_preserves_unresolved_dispatch(self):
        facade=flow.FACADE.replace("OrderService service;","OrderService service; OrderFacade self;").replace("return service.load(id, tenant);","self.load(id,tenant); return service.load(id,tenant);")
        r=self.trace(self.session(facade=facade))
        self.assertEqual(self.origins(r),{"tenant"})
        self.assertTrue(any(x.get("reason")=="receiver_type_unresolved_or_rebound" for x in r["call_candidates"]))

    def test_cross_file_recursion_cycle_is_cut(self):
        service=flow.SERVICE.replace("OrderMapper mapper;","OrderMapper mapper; OrderFacade facade;").replace("return mapper.load(id, tenant);","facade.load(id,tenant); return mapper.load(id,tenant);")
        s=self.session(service=service)
        r=self.trace(s,**s.anchor_at("Service.java",index=1))
        self.assertEqual(self.origins(r),{"tenant"})
        self.assertTrue(any(x["reason"]=="recursive_call_cycle_cut" for x in r["frontiers"]))

    def test_parse_failure_in_scope_preserved(self):
        r=self.trace(self.session(extra={"Broken.java":"class { !!!"}),scope_paths=["Service.java","Facade.java","Controller.java","Broken.java"])
        self.assertEqual(self.origins(r),{"tenant"});self.assertTrue(r["file_analysis_gaps"])
        self.assertTrue(any(f["status"]=="trace_file_analysis_incomplete" for f in r["coverage"]))

    def test_scope_changes_trace_id(self):
        s=self.session();self.assertNotEqual(self.trace(s)["trace_id"],self.trace(s,scope_paths=["Service.java"])["trace_id"])

    def test_budget_changes_trace_id(self):
        s=self.session();self.assertNotEqual(self.trace(s)["trace_id"],self.trace(s,max_hops=3)["trace_id"])

    def test_scope_requires_root_file(self):
        self.assertEqual(self.trace(self.session(),scope_paths=["Controller.java"],ok=False)["error"]["code"],"trace_scope_must_include_sink_file")

    def test_duplicate_scope_rejected(self):
        self.assertEqual(self.trace(self.session(),scope_paths=["Service.java","Service.java"],ok=False)["error"]["code"],"duplicate_trace_scope_path")

    def test_outside_snapshot_rejected(self):
        self.assertEqual(self.trace(self.session(),scope_paths=["Service.java","Missing.java"],ok=False)["error"]["code"],"trace_path_not_in_snapshot")

    def test_old_snapshot_rejected(self):
        self.assertEqual(self.trace(self.session(),snapshot_id='0'*64,ok=False)["error"]["code"],"snapshot_mismatch")

    def test_old_analysis_rejected(self):
        self.assertEqual(self.trace(self.session(),analysis_id='0'*64,ok=False)["error"]["code"],"analysis_mismatch")

    def test_unsupported_rule_rejected(self):
        self.assertEqual(self.trace(self.session(),rule_id='arbitrary-executable-rule',ok=False)["error"]["code"],"unsupported_trace_rule")

    def test_zero_path_budget_rejected(self):
        self.assertEqual(self.trace(self.session(),max_paths=0,ok=False)["error"]["code"],"invalid_trace_budget")

    def test_zero_check_budget_rejected(self):
        self.assertEqual(self.trace(self.session(),max_edge_checks=0,ok=False)["error"]["code"],"invalid_trace_budget")

    def test_too_many_hops_rejected(self):
        r=self.trace(self.session(),max_hops=5,ok=False);self.assertIn("error",r)

    def test_non_java_scope_rejected(self):
        s=self.session(extra={"other.py":"def f(): pass"})
        self.assertEqual(self.trace(s,scope_paths=["Service.java","other.py"],ok=False)["error"]["code"],"unsupported_trace_language")

    def test_new_tool_advertises_read_only(self):
        t=next(x for x in self.session().rpc("tools/list",{})["tools"] if x["name"]=="trace_source_to_sink")
        self.assertTrue(t["annotations"]["readOnlyHint"])
        self.assertNotIn("upstream_calls",t["inputSchema"]["properties"])
        self.assertIn("scope_paths",t["inputSchema"]["required"])

    def test_all_output_source_references_exact(self):
        s=self.session(controller=flow.CONTROLLER.replace('class Controller','// 中文注释\nclass Controller'))
        r=self.trace(s);self.assert_references(s,r)

    def test_steps_reference_local_context_and_evidence(self):
        r=self.trace(self.session())
        for path in r["paths"]:
            for step in path["steps"]:
                ctx=r["contexts"][step["context_index"]]["operation"]
                evidence={x["id"] for x in ctx["local_value_flow"]["evidence"]}
                self.assertTrue(set(step["local_relation"]["evidence_ids"])<=evidence)
                self.assertLess(step["argument_index"],len(ctx["arguments"]))

    def test_retains_mapper_and_control_materials(self):
        r=self.trace(self.session())
        root=r["contexts"][r["root_context_index"]]["operation"]
        self.assertEqual(root["mybatis"]["namespace"],"data.OrderMapper")
        self.assertIn("xml_configuration_properties_not_supplied",root["mybatis"]["template_analysis"]["gaps"])

    def test_source_shadowed_string_type_is_not_scalar(self):
        c=flow.CONTROLLER.replace("long tenant)","String tenant)").replace("class Controller", "import custom.String;\nclass Controller")
        r=self.trace(self.session(controller=c));self.assertFalse(r["paths"])
        self.assertTrue(any(x["reason"]=="request_object_contents_not_modeled" for x in r["frontiers"]))

    def test_same_package_string_class_not_scalar(self):
        c=flow.CONTROLLER.replace("long tenant)","String tenant)")
        r=self.trace(self.session(controller=c,extra={"String.java":"package app; class String {}"}),
            scope_paths=["Service.java","Facade.java","Controller.java","String.java"])
        self.assertFalse(r["paths"])

    def test_fully_qualified_string_source(self):
        c=flow.CONTROLLER.replace("long tenant)","java.lang.String tenant)")
        self.assertEqual(self.origins(self.trace(self.session(controller=c))),{"tenant"})

    def test_path_id_binds_source_snapshot(self):
        a=self.trace(self.session());b=self.trace(self.session(extra={"unused.txt":"a different snapshot"}))
        self.assertNotEqual(a["paths"][0]["path_id"],b["paths"][0]["path_id"])

    def test_partial_states_have_replay_anchors(self):
        r=self.trace(self.session(),max_hops=1)
        for frontier in r["frontiers"]:
            self.assertIn("call_id",frontier["anchor"])
            state=r["states"][frontier["state_index"]]
            self.assertEqual(frontier["anchor"],state["anchor"])

    def test_retains_call_link_source_evidence(self):
        r=self.trace(self.session())
        for edge in r["call_candidates"]:
            if edge["status"]=="declared_target_candidate":
                self.assertIn("sha256",edge["caller_call"])
                self.assertIn("call_id",edge["caller_anchor"])

    def test_catalog_budget_explicit(self):
        service=flow.harness.CALLER.replace("return mapper.load(id, tenantId);",
            "mapper.load(id,tenantId);"+"other();"*1050+"return null;")
        r=self.trace(self.session(service=service),scope_paths=["Service.java"])
        self.assertTrue(r["truncated"]);self.assertIn("trace_call_catalog_limit",r["gaps"])
        self.assertLessEqual(r["statistics"]["call_catalog_size"],1024)

    def test_sink_script_not_reported_as_no_sink(self):
        mapper=flow.harness.MAPPER.replace("Object load(",
            '@org.apache.ibatis.annotations.Select("<script>select ${tenant}</script>") Object load(')
        s=self.session(mapper=mapper)
        r=s.call("trace_source_to_sink",{**s.anchor_at("Service.java"),"mapper_path":"OrderMapper.java",
            "mapping_format":"annotation","scope_paths":["Service.java","Facade.java","Controller.java"]})
        self.assertNotEqual(r["status"],"no_matching_sink_in_selected_mapping")
        self.assertFalse(r["paths"])

    def test_wrong_sink_call_selection_keeps_mapping_unknown(self):
        service=flow.SERVICE.replace("return mapper", "other.load(id,tenant); return mapper")
        r=self.trace(self.session(service=service));self.assertEqual(r["status"],"sink_mapping_unresolved")

    def test_data_access_path_rejects_user_upstream_override(self):
        s=self.session();r=self.trace(s,upstream_calls=[s.anchor_at("Facade.java")],ok=False)
        self.assertIn("error",r)

    def test_input_source_metadata_remains_unverified(self):
        r=self.trace(self.session());source=r["paths"][0]["source"]
        self.assertFalse(source["entry"]["runtime_registration_verified"])
        self.assertFalse(source["parameter"]["input_trust_verified"])

    def test_different_arguments_do_not_share_sources(self):
        c=flow.CONTROLLER.replace("facade.load(id, tenant)","facade.load(id, 0)")
        r=self.trace(self.session(controller=c,xml=XML.replace("#{id}","${id}")))
        self.assertEqual(self.origins(r),{"id"})
        self.assertEqual({p["sink_index"] for p in r["paths"]},{0})

    def test_capability_reports_only_bounded_rule(self):
        r=self.session().call("get_snapshot_info")["product_capabilities"]
        self.assertEqual(r["source_sink_rules"][0]["id"],RULE)
        self.assertIn("complete_taint_engine",r["not_implemented"])
        self.assertIn("whole_repository_sink_discovery",r["not_implemented"])

    def test_small_generated_permutations_against_independent_model(self):
        rng=random.Random(2414)
        for _ in range(12):
            root_order=[rng.randrange(2),rng.randrange(2)]
            middle_order=[rng.randrange(2),rng.randrange(2)]
            names=['id','tenant']
            service=flow.SERVICE.replace('mapper.load(id, tenant)',f'mapper.load({names[root_order[0]]}, {names[root_order[1]]})')
            facade=flow.FACADE.replace('service.load(id, tenant)',f'service.load({names[middle_order[0]]}, {names[middle_order[1]]})')
            with self.subTest(root=root_order,middle=middle_order):
                r=self.trace(self.session(service=service,facade=facade))
                expected=names[middle_order[root_order[1]]]
                self.assertEqual(self.origins(r),{expected})


if __name__ == '__main__':
    unittest.main()
