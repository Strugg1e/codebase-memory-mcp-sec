"""Real parser/MCP tests for declaration relationships, not deployed-route proofs."""
from __future__ import annotations
import hashlib
import json
import unittest
from test_flow import Session

IMPORTS = '''import org.springframework.web.bind.annotation.RestController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import jakarta.validation.Valid;
'''

def source(cls='@RestController @RequestMapping("/api")', mapping='@GetMapping("/orders/{id}")', params='@PathVariable("id") long id, @RequestParam("tenant") long tenant', body='return sink(id, tenant);', extra='', suffix=''):
    return IMPORTS + f'{cls} class C {{ {mapping} Object read({params}) {{ {body} }} {extra} }} {suffix}'

class EntryTests(unittest.TestCase):
    def session(self, text=None, sources=None):
        s=Session(self, sources if sources is not None else {'src/C.java':text if text is not None else source()})
        self.addCleanup(s.close);return s

    def page(self,s,**args): return s.call('query_entry_points',args)
    def entry(self,text=None,**args):
        r=self.page(self.session(text),**args);self.assertEqual(len(r['entries']),1,r);return r['entries'][0]
    def error(self,s,code,**args): self.assertEqual(s.call('query_entry_points',args,ok=False)['error']['code'],code)

    def test_unknown_mapping_attribute_is_explicit_gap(self):
        e=self.entry(source(mapping='@GetMapping(path="/x",version="2")'))
        self.assertIn('mapping_attribute_not_modeled',e['gaps']);self.assertFalse(e['declared_paths'])
    def test_method_attribute_on_shortcut_is_not_accepted(self):
        e=self.entry(source(mapping='@GetMapping(path="/x",method=RequestMethod.POST)'))
        self.assertIn('mapping_attribute_not_modeled',e['gaps']);self.assertIsNone(e['conditions']['methods'])
    def test_simple_relation(self):
        e=self.entry();self.assertEqual(e['declared_paths'],['/api/orders/{id}']);self.assertEqual(e['handler'],'read')
        self.assertEqual(e['conditions']['methods'],['GET']);self.assertEqual(len(e['inputs']),2)
    def test_controller_is_not_registration_proof(self):
        e=self.entry();self.assertEqual(e['controller_marker'],'direct_declaration');self.assertFalse(e['runtime_registration_verified'])
        self.assertEqual(e['authorization'],'not_evaluated');self.assertEqual(e['security_control_effectiveness'],'not_evaluated')
    def test_plain_controller_marker(self): self.assertEqual(self.entry(source(cls='@Controller'))['controller_marker'],'direct_declaration')
    def test_missing_controller_keeps_candidate(self): self.assertIn('controller_registration_not_established',self.entry(source(cls=''))['gaps'])
    def test_class_path_without_method_mapping_not_entry(self): self.assertEqual(self.page(self.session(source(mapping='')))['entries'],[])
    def test_class_method_paths_cartesian_product(self):
        e=self.entry(source(cls='@RestController @RequestMapping({"/v1","/v2"})',mapping='@GetMapping({"/a","/b"})'))
        self.assertEqual(e['declared_paths'],['/v1/a','/v1/b','/v2/a','/v2/b'])
    def test_path_alias(self): self.assertEqual(self.entry(source(mapping='@GetMapping(path="x")'))['declared_paths'],['/api/x'])
    def test_equal_path_value_alias(self): self.assertEqual(self.entry(source(mapping='@GetMapping(path="x",value="x")'))['declared_paths'],['/api/x'])
    def test_conflicting_alias_not_selected(self):
        e=self.entry(source(mapping='@GetMapping(path="x",value="y")'));self.assertFalse(e['declared_paths']);self.assertIn('path_value_alias_conflict',e['gaps'])
    def test_missing_method_path_uses_class(self): self.assertEqual(self.entry(source(mapping='@GetMapping'))['declared_paths'],['/api'])
    def test_empty_path_alternatives(self): self.assertEqual(self.entry(source(cls='@RestController',mapping='@GetMapping'))['declared_paths'],['','/'])
    def test_separator_only_join(self): self.assertEqual(self.entry(source(cls='@RestController @RequestMapping("api/")',mapping='@GetMapping("/x/")'))['declared_paths'],['/api/x/'])
    def test_placeholder_preserved_unknown(self):
        e=self.entry(source(cls='@RestController @RequestMapping("${api.prefix}")'));self.assertFalse(e['declared_paths']);self.assertIn('path_pattern_or_placeholder_not_composed',e['gaps'])
    def test_constant_expression_not_evaluated(self):
        e=self.entry(source(mapping='@GetMapping(PATH)',extra='static final String PATH="/x";'));self.assertFalse(e['declared_paths']);self.assertIn('path_expression_not_resolved',e['gaps'])
    def test_escape_not_silently_decoded(self): self.assertFalse(self.entry(source(mapping=r'@GetMapping("/a\u0062")'))['declared_paths'])
    def test_wildcard_combination_not_guessed(self): self.assertFalse(self.entry(source(cls='@RestController @RequestMapping("/api/**")'))['declared_paths'])
    def test_regex_path_not_guessed(self): self.assertFalse(self.entry(source(mapping=r'@GetMapping("/{id:[0-9]+}")'))['declared_paths'])
    def test_path_product_limit(self):
        xs=','.join(f'"/{n}"' for n in range(9));e=self.entry(source(cls='@RestController @RequestMapping({'+xs+'})',mapping='@GetMapping({'+xs+'})'))
        self.assertIn('path_product_limit',e['gaps']);self.assertFalse(e['declared_paths'])
    def test_method_union_not_intersection(self):
        e=self.entry(source(cls='@RestController @RequestMapping(path="/api",method=RequestMethod.POST)',mapping='@GetMapping("/x")'))
        self.assertEqual(e['conditions']['methods'],['POST','GET'])
    def test_request_mapping_methods_array(self):
        e=self.entry(source(mapping='@RequestMapping(value="/x",method={RequestMethod.POST,RequestMethod.GET})'))
        self.assertEqual(e['conditions']['methods'],['POST','GET'])
    def test_method_not_declared_does_not_default_get(self): self.assertEqual(self.entry(source(mapping='@RequestMapping("/x")'))['conditions']['methods'],[])
    def test_wrong_method_enum_keeps_unknown(self): self.assertIsNone(self.entry(source(mapping='@RequestMapping(value="/x",method=Fake.GET)'))['conditions']['methods'])
    def test_fully_qualified_method_enum(self): self.assertEqual(self.entry(source(mapping='@RequestMapping(value="/x",method=org.springframework.web.bind.annotation.RequestMethod.HEAD)'))['conditions']['methods'],['HEAD'])
    def test_method_enum_shadowed(self):
        e=self.entry(source(mapping='@RequestMapping(value="/x",method=RequestMethod.GET)',suffix='enum RequestMethod { GET }'))
        self.assertIsNone(e['conditions']['methods'])
    def test_param_header_conjunction_and_media_override(self):
        e=self.entry(source(cls='@RestController @RequestMapping(path="/api",params="a",headers="X-App",consumes="text/plain",produces="text/plain")',mapping='@GetMapping(path="/x",params="b",headers="X-Mode=on",consumes="application/json",produces="application/json")'))
        self.assertEqual(e['conditions']['params'],['a','b']);self.assertEqual(e['conditions']['headers'],['X-App','X-Mode=on'])
        self.assertEqual(e['conditions']['consumes'],['application/json']);self.assertEqual(e['conditions']['produces'],['application/json'])
    def test_media_header_not_treated_as_ordinary_header(self):
        e=self.entry(source(mapping='@GetMapping(path="/x",headers="Content-Type=application/json")'))
        self.assertIn('media_type_header_conditions_not_normalized',e['gaps']);self.assertIsNone(e['conditions']['consumes'])
    def test_method_mapping_on_class_not_composed(self):
        e=self.entry(source(cls='@RestController @GetMapping("/api")'))
        self.assertFalse(e['declared_paths']);self.assertIn('method_specific_mapping_on_type',e['gaps'])
    def test_media_inherited_when_method_empty(self): self.assertEqual(self.entry(source(cls='@RestController @RequestMapping(consumes="text/plain")'))['conditions']['consumes'],['text/plain'])
    def test_dynamic_conditions_remain_unknown(self): self.assertIsNone(self.entry(source(mapping='@GetMapping(path="/x",params=PARAMS)'))['conditions']['params'])
    def test_multiple_method_mappings_not_first_selected(self):
        e=self.entry(source(mapping='@GetMapping("/x") @PostMapping("/y")'));self.assertIn('multiple_mapping_declarations_not_selected',e['gaps']);self.assertEqual(len(e['mapping_declarations']),3);self.assertFalse(e['declared_paths'])
    def test_multiple_class_mappings_not_first_selected(self): self.assertFalse(self.entry(source(cls='@RestController @RequestMapping("/a") @RequestMapping("/b")'))['declared_paths'])
    def test_class_method_controls_are_separate(self):
        e=self.entry(source(cls='@RestController @PreAuthorize("classRule()")',mapping='@GetMapping("/x") @PostAuthorize("methodRule()")'))
        self.assertEqual([(x['level'],x['control_phase']) for x in e['control_declarations']],[('class','before_invocation'),('method','after_invocation')])
    def test_parameter_controls_do_not_become_method_guards(self):
        e=self.entry(source(params='@Valid @RequestBody Object x'));self.assertEqual(e['control_declarations'],[])
        self.assertEqual(len(e['inputs'][0]['declarations']),2)
    def test_identity_parameter_not_called_request_binding(self):
        e=self.entry(source(params='@AuthenticationPrincipal Object principal'))
        self.assertEqual(e['inputs'][0]['declarations'][0]['input_kind'],'identity_context_candidate');self.assertFalse(e['inputs'][0]['input_trust_verified'])
    def test_other_method_controls_do_not_leak(self): self.assertEqual(self.entry(source(extra='@PreAuthorize("other()") void other(){}'))['control_declarations'],[])
    def test_inheritance_gap(self):
        text=source().replace('class C {','class C extends Base {');self.assertIn('inherited_mappings_and_controls_not_resolved',self.entry(text)['gaps'])
    def test_nested_class_not_normalized(self):
        text=IMPORTS+'class Outer { @RestController class Inner { @GetMapping("/x") void f(){} } }';self.assertIn('class_structure_not_modeled',self.entry(text)['gaps'])
    def test_interface_not_silently_registered(self):
        text=IMPORTS+'interface C { @GetMapping("/x") Object f(); }';e=self.entry(text);self.assertFalse(e['declared_paths']);self.assertFalse(e['runtime_registration_verified'])
    def test_unrelated_import_not_recognized(self):
        text=source().replace('import org.springframework.web.bind.annotation.GetMapping;','import unrelated.GetMapping;');self.assertEqual(self.page(self.session(text))['entries'],[])
    def test_custom_annotation_no_route_invention(self): self.assertEqual(self.page(self.session(source(mapping='@CustomGet("/x")')))['entries'],[])
    def test_extra_custom_annotation_keeps_gap(self): self.assertIn('additional_annotation_semantics_not_modeled',self.entry(source(mapping='@GetMapping("/x") @Custom'))['gaps'])
    def test_unicode_paths_and_parameter_names(self):
        e=self.entry(source(mapping='@GetMapping("/订单/{编号}")',params='@PathVariable("编号") long 编号'))
        self.assertEqual(e['declared_paths'],['/api/订单/{编号}']);self.assertEqual(e['inputs'][0]['name'],'编号')
    def test_all_references_point_to_exact_snapshot(self):
        text=source();e=self.entry(text);count=0
        def walk(v):
            nonlocal count
            if isinstance(v,dict):
                if 'start_byte' in v and 'text_prefix' in v:
                    count+=1;b=text.encode()[v['start_byte']:v['end_byte']];self.assertTrue(b.decode().startswith(v['text_prefix']));self.assertEqual(v['sha256'],hashlib.sha256(text.encode()).hexdigest())
                for x in v.values():walk(x)
            elif isinstance(v,list):
                for x in v:walk(x)
        walk(e);self.assertGreater(count,8)
    def test_handler_anchor_retrieves_exact_fact(self):
        s=self.session();e=self.page(s)['entries'][0];f=s.call('get_security_evidence',e['handler_anchor'])['facts'][0];self.assertEqual(f['id'],e['handler_anchor']['fact_id'])
    def test_call_query_and_operation_work(self):
        s=self.session();e=self.page(s)['entries'][0];r=s.call('query_security_facts',e['call_query']);calls=[f for f in r['facts'] if f.get('name',{}).get('text_prefix')=='sink'];self.assertEqual(len(calls),1)
        op=s.call('inspect_operation_context',{'path':e['path'],'analysis_id':e['analysis_id'],'call_id':calls[0]['id'],'view':'summary'});self.assertIn('local_value_flow',op)
    def test_entry_id_stable_across_filters(self):
        s=self.session();e=self.page(s)['entries'][0];b=self.page(s,handler='read',entry_id=e['entry_id'])['entries'][0];self.assertEqual(e['entry_id'],b['entry_id'])
    def test_hash_and_source_change_entry_id(self): self.assertNotEqual(self.entry()['entry_id'],self.entry(source()+'\n')['entry_id'])
    def test_same_path_different_handlers_are_not_deduplicated(self):
        s=self.session(source(mapping='@GetMapping("/x")',extra='@GetMapping("/x") Object other(){return null;}'));e=self.page(s)['entries'];self.assertEqual(len(e),2);self.assertEqual(len({x['entry_id'] for x in e}),2)
    def test_filter_handler_exact(self): self.assertEqual(self.page(self.session(),handler='re.*')['entries'],[])
    def test_path_prefix_component_boundary(self):
        s=self.session(sources={'src/C.java':source(),'src-other/C.java':source()});r=self.page(s,path_prefix='src');self.assertEqual([x['path'] for x in r['entries']],['src/C.java'])
    def test_filter_route_path_exact(self): self.assertEqual(self.page(self.session(),route_path='/api/orders/{id}')['entries'][0]['handler'],'read')
    def test_unresolved_path_survives_filter(self):
        s=self.session(source(mapping='@GetMapping(DYNAMIC)'));e=self.page(s,route_path='/a')['entries'][0];self.assertEqual(e['filter_status'],'route_path_not_resolved')
    def test_pagination_no_duplicates(self):
        extra=' '.join(f'@GetMapping("/x{i}") void x{i}() {{}}' for i in range(5));s=self.session(source(extra=extra));r=self.page(s,limit=2);ids=[]
        while True:
            ids.extend(x['entry_id'] for x in r['entries'])
            if not r['page']['next_cursor']:break
            r=self.page(s,limit=3,cursor=r['page']['next_cursor'])
        self.assertEqual(len(ids),6);self.assertEqual(len(set(ids)),6)
    def test_cursor_binds_filters(self):
        s=self.session(source(extra='@GetMapping("/x") void x(){}'));r=self.page(s,limit=1)
        self.error(s,'entry_query_mismatch',handler='read',cursor=r['page']['next_cursor'])
    def test_cursor_binds_snapshot(self):
        s=self.session(source(extra='@GetMapping("/x") void x(){}'));r=self.page(s,limit=1)
        self.error(self.session(source()+'\n'),'entry_query_mismatch',cursor=r['page']['next_cursor'])
    def test_page_can_be_empty_with_continuation(self):
        sources={f'{i:02}.txt':'text' for i in range(16)};sources['z.java']=source();s=self.session(sources=sources)
        r=self.page(s);self.assertFalse(r['entries']);self.assertIsNotNone(r['page']['next_cursor']);self.assertEqual(len(r['coverage']),16)
        self.assertEqual(len(self.page(s,cursor=r['page']['next_cursor'])['entries']),1)
    def test_empty_snapshot(self):
        r=self.page(self.session(sources={}));self.assertEqual(r['entries'],[]);self.assertTrue(r['page']['enumeration_finished'])
    def test_unsupported_language_reported(self): self.assertEqual(self.page(self.session(sources={'api.py':'pass'}))['coverage'][0]['status'],'unsupported_entry_language')
    def test_syntax_error_coverage(self):
        r=self.page(self.session(source()+' broken {'));self.assertEqual(r['coverage'][0]['status'],'incomplete');self.assertIn('syntax_errors',r['coverage'][0]['analysis']['gaps'])
    def test_budget_limit_explicit(self):
        extra=' '.join(f'@GetMapping("/x{i}") void x{i}() {{}}' for i in range(260));r=self.page(self.session(source(extra=extra)))
        self.assertTrue(r['coverage'][0]['analysis']['truncated']);self.assertIn('entry_budget_exhausted',r['coverage'][0]['analysis']['gaps'])
    def test_same_file_cache_reused_without_reparse(self):
        s=self.session();self.page(s);a=s.call('get_snapshot_info',{});self.page(s);b=s.call('get_snapshot_info',{})
        self.assertEqual(a['cache']['parse_attempts'],b['cache']['parse_attempts']);self.assertEqual(b['entry_points']['catalog_builds'],1);self.assertEqual(b['entry_points']['cache_hits'],1)
    def test_source_bundle_deleted_after_start_stays_pinned(self):
        s=self.session();a=self.page(s);s.path.unlink();b=self.page(s);self.assertEqual(a,b)
    def test_wrong_snapshot_rejected(self): self.error(self.session(),'snapshot_mismatch',snapshot_id='0'*64)
    def test_wrong_framework_rejected(self): self.error(self.session(),'unsupported_entry_framework',framework='fastapi')
    def test_bad_scope_rejected(self): self.error(self.session(),'invalid_entry_filter',path_prefix='../src')
    def test_invalid_cursor_rejected(self): self.error(self.session(),'entry_query_mismatch',cursor='not-a-cursor')
    def test_zero_limit_rejected(self): self.error(self.session(),'invalid_arguments',limit=0)
    def test_limit_max_rejected(self): self.error(self.session(),'invalid_arguments',limit=51)
    def test_unknown_argument_rejected(self): self.error(self.session(),'unknown_argument',execute_target=True)
    def test_capability_schema(self): self.assertEqual(self.session().call('get_snapshot_info',{})['product_capabilities']['entry_point_schema'],'cbm.spring-entry-points.v1')

if __name__=='__main__':unittest.main()
