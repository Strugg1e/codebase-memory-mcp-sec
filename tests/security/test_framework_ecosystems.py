"""Framework declarations from real parsers; no framework runtime or target execution."""
from __future__ import annotations
import hashlib
import json
import subprocess
import unittest
from test_flow import Session
import test_operation as harness

CLI = harness.MCP.with_name('cbm-security-facts')

def run(path, source, *args):
    p = subprocess.run([str(CLI), '--path', path, '--limit', '200', *args],
                       input=source.encode(), capture_output=True, timeout=20)
    if p.returncode: raise AssertionError(p.stdout.decode() + p.stderr.decode())
    return json.loads(p.stdout)

def selected(data, framework=None, role=None):
    return [f for f in data['facts'] if 'framework_model' in f
            and (framework is None or f['framework_model']['framework'] == framework)
            and (role is None or f['framework_model']['role'] == role)]

def model(data, framework=None, role=None):
    fs = selected(data, framework, role)
    if len(fs) != 1: raise AssertionError([(f.get('name'), f.get('framework_model')) for f in fs])
    return fs[0]['framework_model']

FAST = 'import fastify from "fastify"; const app = fastify(); '
ECHO = 'package p\nimport "github.com/labstack/echo/v4"\nfunc f() { e := echo.New(); %s }\n'
CHI = 'package p\nimport "github.com/go-chi/chi/v5"\nfunc f() { r := chi.NewRouter(); %s }\n'
FA = 'from fastapi import FastAPI, APIRouter\napp = FastAPI()\nr = APIRouter()\n'
FL = 'from flask import Flask, Blueprint\napp = Flask(__name__)\nbp = Blueprint("api", __name__)\n'

# Independent behavioral cases, rather than reading the production rule table.
CASES = [
 ('jaxrs_jakarta_get','A.java','import jakarta.ws.rs.GET; class A { @GET Object f(){ return null; } }','jax-rs','route_declaration',1),
 ('jaxrs_javax_get','A.java','import javax.ws.rs.GET; class A { @GET Object f(){ return null; } }','jax-rs','route_declaration',1),
 ('jaxrs_custom_get','A.java','import custom.GET; class A { @GET Object f(){ return null; } }','jax-rs','route_declaration',0),
 ('jaxrs_no_import','A.java','class A { @GET Object f(){ return null; } }','jax-rs','route_declaration',0),
 ('jaxrs_wildcard_not_guessed','A.java','import jakarta.ws.rs.*; class A { @GET Object f(){ return null; } }','jax-rs','route_declaration',0),
 ('jaxrs_conflicting_import','A.java','import jakarta.ws.rs.GET; import custom.GET; class A { @GET Object f(){ return null; } }','jax-rs','route_declaration',0),
 ('jaxrs_shadow_annotation','A.java','import jakarta.ws.rs.GET; @interface GET {} class A { @GET Object f(){ return null; } }','jax-rs','route_declaration',0),
 ('spring_secured','A.java','import org.springframework.security.access.annotation.Secured; class A { @Secured("ROLE_ADMIN") void f(){} }','spring-security','authorization_declaration',1),
 ('spring_identity_not_input','A.java','import org.springframework.security.core.annotation.AuthenticationPrincipal; class A { void f(@AuthenticationPrincipal Object user){} }','spring-security','request_input_declaration',0),
 ('spring_identity_context','A.java','import org.springframework.security.core.annotation.AuthenticationPrincipal; class A { void f(@AuthenticationPrincipal Object user){} }','spring-security','identity_context_declaration',1),
 ('permit_all_not_guard','A.java','import jakarta.annotation.security.PermitAll; @PermitAll class A {}','jakarta-security','authorization_declaration',0),
 ('permit_all_declared','A.java','import jakarta.annotation.security.PermitAll; @PermitAll class A {}','jakarta-security','access_policy_declaration',1),
 ('bean_valid_not_auth','A.java','import jakarta.validation.Valid; class A { void f(@Valid Object x){} }','bean-validation','authorization_declaration',0),
 ('bean_valid','A.java','import javax.validation.Valid; class A { void f(@Valid Object x){} }','bean-validation','validation_declaration',1),
 ('mybatis_select','A.java','import org.apache.ibatis.annotations.Select; interface A { @Select("SELECT * FROM orders") Object f(); }','mybatis','data_operation_declaration',1),
 ('mybatis_provider','A.java','import org.apache.ibatis.annotations.SelectProvider; interface A { @SelectProvider(type=P.class,method="sql") Object f(); }','mybatis','sql_provider_declaration',1),
 ('mybatis_custom_select','A.java','import custom.Select; interface A { @Select("query") Object f(); }','mybatis','data_operation_declaration',0),
 ('jpa_query','A.java','import org.springframework.data.jpa.repository.Query; interface A { @Query("from Order o") Object f(); }','spring-data-jpa','data_query_declaration',1),
 ('fastapi_include','a.py',FA+'app.include_router(r, prefix="/api", dependencies=[guard])\n','fastapi','router_attachment',1),
 ('fastapi_nested_include','a.py',FA+'r.include_router(other)\n','fastapi','router_attachment',1),
 ('fastapi_missing_router','a.py',FA+'app.include_router()\n','fastapi','router_attachment',0),
 ('fastapi_expanded_router','a.py',FA+'app.include_router(**options)\n','fastapi','router_attachment',0),
 ('fastapi_reassigned','a.py',FA+'app = unrelated\napp.include_router(r)\n','fastapi','router_attachment',0),
 ('fastapi_websocket','a.py',FA+'@r.websocket("/ws")\nasync def ws(socket): pass\n','fastapi','websocket_route_declaration',1),
 ('fastapi_add_websocket','a.py',FA+'r.add_api_websocket_route(path="/ws", endpoint=handler)\n','fastapi','websocket_route_declaration',1),
 ('fastapi_add_middleware','a.py',FA+'app.add_middleware(Auth, mode="strict")\n','fastapi','middleware_attachment',1),
 ('fastapi_router_no_middleware','a.py',FA+'r.add_middleware(Auth)\n','fastapi','middleware_attachment',0),
 ('fastapi_scheme','a.py','from fastapi.security import HTTPBearer\nbearer = HTTPBearer(auto_error=False)\n','fastapi','security_scheme_declaration',1),
 ('fastapi_custom_scheme','a.py','from custom import HTTPBearer\nbearer = HTTPBearer()\n','fastapi','security_scheme_declaration',0),
 ('flask_registration','a.py',FL+'app.add_url_rule("/x", "name", handler)\n','flask','route_declaration',1),
 ('flask_keyword_registration','a.py',FL+'app.add_url_rule(rule="/x", view_func=handler, methods=["POST"])\n','flask','route_declaration',1),
 ('flask_late_endpoint','a.py',FL+'app.add_url_rule("/x", "name")\n','flask','route_declaration',1),
 ('flask_blueprint_registration','a.py',FL+'app.register_blueprint(bp, url_prefix="/v1")\n','flask','router_attachment',1),
 ('flask_bp_registration','a.py',FL+'bp.add_url_rule("/x", view_func=handler)\n','flask','route_declaration',1),
 ('flask_endpoint','a.py',FL+'@app.endpoint("name")\ndef handler(): pass\n','flask','handler_alias_declaration',1),
 ('flask_lookalike','a.py','app = Other()\napp.add_url_rule("/x", view_func=handler)\n','flask','route_declaration',0),
 ('drf_api_view','a.py','from rest_framework.decorators import api_view\n@api_view(["GET"])\ndef f(request): pass\n','django-rest-framework','route_handler_declaration',1),
 ('drf_alias','a.py','from rest_framework import decorators as d\n@d.permission_classes([AllowAny])\ndef f(request): pass\n','django-rest-framework','control_declaration',1),
 ('drf_action','a.py','from rest_framework.decorators import action\nclass View:\n @action(detail=True, methods=["post"], url_path="approve")\n def f(self, request): pass\n','django-rest-framework','route_action_declaration',1),
 ('drf_non_decorator','a.py','from rest_framework.decorators import api_view\nvalue = api_view(["GET"])\n','django-rest-framework','route_handler_declaration',0),
 ('drf_custom','a.py','from local import api_view\n@api_view(["GET"])\ndef f(request): pass\n','django-rest-framework','route_handler_declaration',0),
 ('drf_shadowed','a.py','from rest_framework.decorators import api_view\napi_view = other\n@api_view(["GET"])\ndef f(request): pass\n','django-rest-framework','route_handler_declaration',0),
 ('fastify_named','x.ts','import {fastify as make} from "fastify"; const app=make(); app.post("/x", {}, handler);','fastify','route_declaration',1),
 ('fastify_commonjs','x.cjs','const make=require("fastify"); const app=make(); app.get("/x", handler);','fastify','route_declaration',1),
 ('fastify_inline_require','x.cjs','const app=require("fastify")(); app.get("/x", handler);','fastify','route_declaration',1),
 ('fastify_require_shadowed','x.cjs','function require(x){return other;} const app=require("fastify")(); app.get("/x", handler);','fastify','route_declaration',0),
 ('fastify_type_only','x.ts','import type {fastify} from "fastify"; const app=fastify(); app.get("/x", handler);','fastify','route_declaration',0),
 ('fastify_shadowed','x.js',FAST+'function x(app){app.get("/x", handler);}','fastify','route_declaration',0),
 ('fastify_nested_not_direct','x.js',FAST+'app.database.get("/x", handler);','fastify','route_declaration',0),
 ('fastify_wrong_case','x.js',FAST+'app.GET("/x", handler);','fastify','route_declaration',0),
 ('fastify_spread_arguments','x.js',FAST+'app.get("/x", ...handlers);','fastify','route_declaration',0),
 ('fastify_object','x.js',FAST+'app.route({url:"/x", method:["GET","POST"], handler});','fastify','route_declaration',1),
 ('fastify_object_method','x.ts',FAST+'app.route({path:"/x", method:"GET", handler(req, reply){return 1;}});','fastify','route_declaration',1),
 ('fastify_object_nested_no_url','x.js',FAST+'app.route({schema:{url:"/x"}, method:"GET", handler});','fastify','route_declaration',0),
 ('fastify_object_spread','x.js',FAST+'app.route({...other,url:"/x", method:"GET", handler});','fastify','route_declaration',0),
 ('fastify_object_computed','x.js',FAST+'app.route({[key]:"/x", method:"GET", handler});','fastify','route_declaration',0),
 ('fastify_object_duplicate','x.js',FAST+'app.route({url:"/x",url:"/y", method:"GET", handler});','fastify','route_declaration',0),
 ('fastify_object_getter','x.js',FAST+'app.route({url:"/x", method:"GET", get handler(){return h;}});','fastify','route_declaration',0),
 ('fastify_options_handler','x.js',FAST+'app.get("/x",{preHandler:auth,handler});','fastify','route_declaration',1),
 ('fastify_duplicate_handler','x.js',FAST+'app.get("/x",{handler:h},other);','fastify','route_declaration',0),
 ('fastify_register','x.js',FAST+'app.register(plugin,{prefix:"/v1"});','fastify','plugin_registration',1),
 ('fastify_hook','x.js',FAST+'app.addHook("preHandler",auth);','fastify','request_hook_declaration',1),
 ('fastify_non_request_hook','x.js',FAST+'app.addHook("onClose",cleanup);','fastify','request_hook_declaration',0),
 ('echo_default_package','x.go',ECHO%'e.GET("/x",handler,auth)','echo','route_declaration',1),
 ('echo_group','x.go',ECHO%'g := e.Group("/api", auth); g.POST("/x",handler)','echo','route_declaration',1),
 ('echo_match','x.go',ECHO%'e.Match([]string{"GET","POST"},"/x",handler)','echo','route_declaration',1),
 ('echo_pre','x.go',ECHO%'e.Pre(auth)','echo','middleware_attachment',1),
 ('echo_group_no_pre','x.go',ECHO%'g := e.Group("/api"); g.Pre(auth)','echo','middleware_attachment',0),
 ('echo_alias','x.go','package p\nimport e "github.com/labstack/echo/v4"\nfunc f(){ app:=e.New(); app.GET("/x",handler) }\n','echo','route_declaration',1),
 ('echo_unknown_major','x.go','package p\nimport "github.com/labstack/echo/v999"\nfunc f(){ app:=echo.New(); app.GET("/x",handler) }\n','echo','route_declaration',0),
 ('echo_shadow','x.go',ECHO%'e = other; e.GET("/x",handler)','echo','route_declaration',0),
 ('chi_default_package','x.go',CHI%'r.Get("/x",handler)','chi','route_declaration',1),
 ('chi_with','x.go',CHI%'scoped := r.With(auth); scoped.Get("/x",handler)','chi','route_declaration',1),
 ('chi_method','x.go',CHI%'r.MethodFunc("POST","/x",handler)','chi','route_declaration',1),
 ('chi_mount','x.go',CHI%'r.Mount("/api", sub)','chi','router_attachment',1),
 ('chi_wrong_case','x.go',CHI%'r.GET("/x",handler)','chi','route_declaration',0),
 ('chi_rebound_parent','x.go',CHI%'scoped := r.With(auth); r = other; scoped.Get("/x",handler)','chi','route_declaration',0),
]

class FrameworkEcosystems(unittest.TestCase):
    def assert_spans(self, data, raw):
        if isinstance(data, dict):
            if 'start_byte' in data and 'text_prefix' in data:
                actual = raw[data['start_byte']:data['end_byte']]
                prefix = data['text_prefix'].encode()
                self.assertTrue(actual.startswith(prefix))
                self.assertEqual(len(prefix), data['text_bytes_returned'])
                if not data['text_truncated']: self.assertEqual(actual, prefix)
            for item in data.values(): self.assert_spans(item, raw)
        elif isinstance(data, list):
            for item in data: self.assert_spans(item, raw)

    def test_jaxrs_paths_are_not_http_methods(self):
        s='import jakarta.ws.rs.Path; @Path("/root") class A { @Path("/child") Object locate(){return null;} }'
        d=run('A.java',s)
        self.assertEqual(len(selected(d,'jax-rs','route_prefix_declaration')),1)
        self.assertEqual(len(selected(d,'jax-rs','resource_path_declaration')),1)
        self.assertEqual(selected(d,'jax-rs','route_declaration'),[])

    def test_jaxrs_input_kinds_both_namespaces(self):
        names={'PathParam':'path','QueryParam':'query','HeaderParam':'header','CookieParam':'cookie','FormParam':'form','MatrixParam':'matrix','BeanParam':'bean_binding'}
        for ns in ['jakarta','javax']:
            for name, expected in names.items():
                with self.subTest(ns=ns,name=name):
                    args='' if name=='BeanParam' else '("x")'
                    s=f'import {ns}.ws.rs.{name}; class A {{ void f(@{name}{args} Object x){{}} }}'
                    m=model(run('A.java',s),'jax-rs','request_input_declaration')
                    self.assertEqual(m['input_kind'],expected)
                    self.assertEqual(m['security_effect'],'not_evaluated')

    def test_full_qualification_and_utf8_sql(self):
        s='interface A { @org.apache.ibatis.annotations.Select({"SELECT * FROM 订单", "WHERE id=#{id}"}) Object f(); }'
        m=model(run('A.java',s),'mybatis')
        self.assertEqual(m['data_operation'],'read')
        self.assertEqual(m['expressions']['sql']['text_prefix'],'{"SELECT * FROM 订单", "WHERE id=#{id}"}')
        self.assert_spans(m,s.encode())

    def test_mybatis_all_operation_kinds_and_providers(self):
        for name,operation in [('Select','read'),('Insert','insert'),('Update','update'),('Delete','delete')]:
            for provider in [False,True]:
                with self.subTest(name=name,provider=provider):
                    annotation=name+('Provider' if provider else '')
                    args='type=P.class,method="sql"' if provider else '"SQL ${unresolved}"'
                    s=f'import org.apache.ibatis.annotations.{annotation}; interface A {{ @{annotation}({args}) Object f(); }}'
                    m=model(run('A.java',s),'mybatis')
                    self.assertEqual(m['data_operation'],operation)
                    self.assertEqual('sql' in m['expressions'],not provider)
                    self.assertEqual(m['runtime_binding'],'not_verified')

    def test_jpa_query_is_not_assumed_sql_or_read_only(self):
        s='import org.springframework.data.jpa.repository.Query; interface A { @Query(value="UPDATE orders SET done=true",nativeQuery=true) int f(); }'
        m=model(run('A.java',s),'spring-data-jpa')
        self.assertNotIn('data_operation',m)
        self.assertEqual(m['expressions']['native_query']['text_prefix'],'true')
        self.assertIn('query',m['expressions']);self.assertNotIn('sql',m['expressions'])

    def test_spring_control_phase_and_expression(self):
        for name,phase in [('PreAuthorize','before_invocation'),('PostAuthorize','after_invocation'),('PreFilter','before_invocation'),('PostFilter','after_invocation')]:
            s=f'import org.springframework.security.access.prepost.{name}; class A {{ @{name}("#id > 0") void f(){{}} }}'
            m=model(run('A.java',s),'spring-security')
            self.assertEqual(m['control_phase'],phase)
            self.assertEqual(m['expressions']['access_expression']['text_prefix'],'"#id > 0"')

    def test_flask_endpoint_slot_is_not_handler(self):
        m=model(run('a.py',FL+'app.add_url_rule("/x", "endpoint_name", view)\n'),'flask','route_declaration')
        self.assertEqual(m['handler_expression']['text_prefix'],'view')
        self.assertEqual(m['expressions']['endpoint_name']['text_prefix'],'"endpoint_name"')
        m=model(run('a.py',FL+'app.add_url_rule("/x", "endpoint_name")\n'),'flask','route_declaration')
        self.assertNotIn('handler_expression',m)

    def test_router_attachment_does_not_invent_composed_url(self):
        m=model(run('a.py',FA+'app.include_router(router=r, prefix=PREFIX, dependencies=[guard])\n'),'fastapi','router_attachment')
        self.assertEqual(m['expressions']['router']['text_prefix'],'r')
        self.assertEqual(m['expressions']['prefix']['text_prefix'],'PREFIX')
        self.assertEqual(m['expressions']['dependencies']['text_prefix'],'[guard]')
        self.assertEqual(m['full_route_resolution'],'not_attempted')

    def test_fastapi_scheme_auto_error_false_not_protection(self):
        m=model(run('a.py','from fastapi.security import APIKeyHeader\nscheme=APIKeyHeader(name="X-Key",auto_error=False)\n'),'fastapi')
        self.assertEqual(m['expressions']['auto_error']['text_prefix'],'False')
        self.assertEqual(m['security_effect'],'not_evaluated')

    def test_fastify_object_path_method_handler_and_options(self):
        s=FAST+'app.route({url:"/中文",method:["GET","POST"],preHandler:auth,handler:read});'
        m=model(run('x.ts',s),'fastify')
        self.assertEqual(m['path_expression']['text_prefix'],'"/中文"')
        self.assertEqual(m['handler_expression']['text_prefix'],'read')
        self.assertEqual(m['expressions']['methods']['text_prefix'],'["GET","POST"]')
        self.assertIn('preHandler:auth',m['expressions']['options']['text_prefix'])
        self.assert_spans(m,s.encode())

    def test_fastify_unknown_object_options_are_not_handlers(self):
        d=run('x.js',FAST+'app.get("/x",options);')
        f=selected(d,'fastify')[0];m=f['framework_model']
        self.assertNotIn('handler_expression',m)
        self.assertEqual(m['expressions']['handler_or_options']['text_prefix'],'options')
        self.assertEqual(f['framework_model_gap'],'fastify_handler_or_options_not_resolved')

    def test_fastify_ambiguous_object_preserves_raw_call_and_gap(self):
        s=FAST+'app.route({...extra,url:"/x",method:"GET",handler});'
        d=run('x.js',s)
        f=next(f for f in d['facts'] if f.get('name',{}).get('text_prefix')=='route')
        self.assertIn('framework_model_gap',f);self.assertNotIn('framework_model',f)
        self.assertEqual(f['argument_total'],1)

    def test_fastify_hook_phase_not_auth_verdict(self):
        for hook,phase in [('preHandler','before_handler'),('onResponse','response_or_error_lifecycle')]:
            m=model(run('x.js',FAST+f'app.addHook("{hook}",guard);'),'fastify')
            self.assertEqual(m['control_phase'],phase)
            self.assertEqual(m['security_effect'],'not_evaluated')

    def test_echo_handler_is_before_optional_middleware(self):
        m=model(run('x.go',ECHO%'e.GET("/x",read,auth,rateLimit)'),'echo','route_declaration')
        self.assertEqual(m['handler_expression']['text_prefix'],'read')
        self.assertIn('auth',m['expressions']['declaration_arguments']['text_prefix'])

    def test_echo_group_retains_prefix_as_separate_declaration(self):
        d=run('x.go',ECHO%'g := e.Group("/v1"); g.GET("/x",read)')
        self.assertEqual(model(d,'echo','route_group_declaration')['expressions']['prefix']['text_prefix'],'"/v1"')
        self.assertEqual(model(d,'echo','route_declaration')['path_expression']['text_prefix'],'"/x"')

    def test_chi_method_positions(self):
        m=model(run('x.go',CHI%'r.Method("POST","/x",h)'),'chi','route_declaration')
        self.assertEqual(m['expressions']['methods']['text_prefix'],'"POST"')
        self.assertEqual(m['handler_expression']['text_prefix'],'h')
        self.assertEqual(m['path_expression']['text_prefix'],'"/x"')

    def test_declaration_only_files_suppress_new_models(self):
        for path,source in [('x.d.ts',FAST+'app.get("/x",handler);'),('x.pyi',FA+'app.include_router(r)\n')]:
            self.assertEqual(selected(run(path,source)),[])

    def test_new_models_available_over_mcp_and_filters_page(self):
        source=FAST+'app.get("/a",h);app.post("/b",{},h);app.addHook("preHandler",auth);'
        s=Session(self,{'x.ts':source});self.addCleanup(s.close)
        a={'path':'x.ts','framework':'fastify','role':'route_declaration','limit':1}
        first=s.call('query_security_facts',a)
        second=s.call('query_security_facts',dict(a,cursor=first['page']['next_cursor']))
        cli=run('x.ts',source,'--framework','fastify','--role','route_declaration')
        self.assertEqual(first['facts']+second['facts'],cli['facts'])
        caps=s.call('get_snapshot_info',{})['product_capabilities']
        self.assertIn('fastify',caps['frameworks'])
        self.assertFalse(caps['framework_runtime_activation'])
        self.assertEqual(caps,json.loads(subprocess.check_output([str(CLI),'--capabilities']))['product_capabilities'])

    def test_jaxrs_inputs_reach_java_operation_view(self):
        source='import jakarta.ws.rs.QueryParam; class A { void f(@QueryParam("id") long id){sink(id);} }'
        s=Session(self,{'A.java':source});self.addCleanup(s.close)
        d=s.call('inspect_operation_context',s.anchor_at('A.java','sink'))
        self.assertEqual(d['arguments'][0]['origin'],'request_parameter_declaration_candidate')
        self.assertEqual(d['arguments'][0]['local_value_flow']['formal_parameter_indices'],[0])
        self.assertEqual(d['authorization_verdict'],'not_evaluated')
        # The declaration is retained in both condensed and complete views.
        for view in ['full','summary','values']:
            out=s.call('inspect_operation_context',dict(s.anchor_at('A.java','sink'),view=view))
            def collect(x):
                if isinstance(x,dict):
                    if x.get('framework')=='jax-rs': yield x
                    for v in x.values(): yield from collect(v)
                elif isinstance(x,list):
                    for v in x: yield from collect(v)
            self.assertTrue(any(m.get('input_kind')=='query' for m in collect(out)))

    def test_identity_context_is_not_automatically_trusted(self):
        source='import org.springframework.security.core.annotation.AuthenticationPrincipal; class A { void f(@AuthenticationPrincipal Object user){sink(user);} }'
        s=Session(self,{'A.java':source});self.addCleanup(s.close)
        d=s.call('inspect_operation_context',s.anchor_at('A.java','sink'))
        self.assertNotEqual(d['arguments'][0]['origin'],'request_parameter_declaration_candidate')
        self.assertEqual(d['arguments'][0]['local_value_flow']['trust'],'not_established')
        self.assertEqual(d['authorization_verdict'],'not_evaluated')

    def test_malformed_source_does_not_emit_framework_labels(self):
        data=run('A.java','import jakarta.ws.rs.GET; class A { @GET void f( {')
        self.assertTrue(data['coverage']['parse_has_error'])
        self.assertEqual(selected(data),[])

    def test_new_declarations_can_be_fetched_by_id(self):
        source='import jakarta.ws.rs.QueryParam; class A { void f(@QueryParam("id") long id){} }'
        first=run('A.java',source,'--framework','jax-rs')
        f=first['facts'][0]
        second=run('A.java',source,'--fact-id',f['id'],'--expect-analysis',first['analysis_id'])
        self.assertEqual(second['facts'],[f])

    def test_readme_and_capabilities_do_not_add_language_claims(self):
        caps=json.loads(subprocess.check_output([str(CLI),'--capabilities']))
        self.assertEqual(caps['languages'],['java','python','javascript','typescript','tsx','go'])
        self.assertEqual(caps['frameworks'],caps['product_capabilities']['frameworks'])
        self.assertFalse(caps['value_flow'])

    def test_long_sql_preview_is_marked_truncated(self):
        source='import org.apache.ibatis.annotations.Select; interface A { @Select("'+('中文'*180)+'") Object f(); }'
        m=model(run('A.java',source),'mybatis')
        self.assertTrue(m['expressions']['sql']['text_truncated'])
        self.assert_spans(m,source.encode())


def case_test(path,source,fw,role,count):
    def test(self):
        d=run(path,source)
        self.assertFalse(d['coverage']['parse_has_error'])
        found=selected(d,fw,role)
        self.assertEqual(len(found),count,[(f.get('name'),f.get('framework_model')) for f in d['facts']])
        for f in found:
            m=f['framework_model']
            self.assertEqual(m['security_effect'],'not_evaluated')
            self.assertEqual(m['runtime_binding'],'not_verified')
            self.assert_spans(m,source.encode())
    return test

for name,path,source,fw,role,count in CASES:
    setattr(FrameworkEcosystems,'test_'+name,case_test(path,source,fw,role,count))

if __name__ == '__main__': unittest.main()
