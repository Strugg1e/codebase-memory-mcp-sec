"""Real Java/MCP return-dependency tests. Fixtures are not vulnerability claims."""
from __future__ import annotations
import unittest
import hashlib
from test_flow import Session, SERVICE, FACADE, CONTROLLER
import test_operation as harness


class StringModels(unittest.TestCase):
    def inspect(self, body, params='String input, String other, int start, int end',
                imports='import java.lang.String;', extra='', helpers='', selected=0):
        source=imports+'\nclass C { void f('+params+') {'+body+'} '+helpers+' } '+extra
        s=Session(self,{'C.java':source}); self.addCleanup(s.close)
        return s,s.call('inspect_operation_context',s.anchor_at('C.java','sink',selected))

    def origin(self,body,argument=0,**kw):
        _,r=self.inspect(body,**kw)
        self.assertEqual(r['authorization_verdict'],'not_evaluated')
        self.assertEqual(r['local_value_flow']['library_models']['sanitization'],'not_modeled')
        return r['arguments'][argument]['local_value_flow']

    def test_concat_receiver_and_argument(self):
        v=self.origin('sink(input.concat(other));')
        self.assertEqual(v['derived_parameter_indices'],[0,1])
        self.assertEqual(v['unknown_reasons'],[])

    def test_concat_literal_receiver(self):
        v=self.origin('sink("prefix".concat(input));')
        self.assertEqual(v['formal_parameter_indices'],[0])

    def test_receiver_is_captured_before_argument_reassignment(self):
        v=self.origin('sink(input.concat(input="fixed"));')
        self.assertEqual(v['derived_parameter_indices'],[0])

    def test_receiver_call_before_argument_has_old_value(self):
        v=self.origin('sink(input.trim().concat(input="fixed"));')
        self.assertEqual(v['formal_parameter_indices'],[0])

    def test_later_call_sees_overwrite(self):
        v=self.origin('sink(input.trim()); input="fixed"; sink(input.trim());',selected=1)
        self.assertEqual(v['formal_parameter_indices'],[])
        self.assertTrue(v['literal_possible'])

    def test_chain_propagates_without_clearing_source(self):
        v=self.origin('sink(input.strip().substring(0).toLowerCase());')
        self.assertEqual(v['derived_parameter_indices'],[0])
        self.assertEqual(v['unknown_reasons'],[])

    def test_to_string_is_receiver_value_identity(self):
        v=self.origin('sink(input.toString());')
        self.assertEqual(v['value_identity_parameter_indices'],[0])
        self.assertEqual(v['derived_parameter_indices'],[])

    def test_substring_includes_index_dependencies(self):
        v=self.origin('sink(input.substring(start,end));')
        self.assertEqual(v['derived_parameter_indices'],[0,2,3])

    def test_replace_string_arguments_are_dependencies(self):
        v=self.origin('sink(input.replace(other,"fixed"));')
        self.assertEqual(v['derived_parameter_indices'],[0,1])

    def test_replace_char_arguments(self):
        v=self.origin('sink(input.replace(a,b));',params='String input, char a, char b')
        self.assertEqual(v['derived_parameter_indices'],[0,1,2])

    def test_replace_does_not_act_as_sanitizer(self):
        v=self.origin("sink(input.replace('\'','_'));".replace("'''",r"'\''"))
        self.assertEqual(v['formal_parameter_indices'],[0])
        self.assertEqual(v['trust'],'not_established')

    def test_charsequence_heap_contents_are_not_assumed(self):
        v=self.origin('sink(input.replace(a,b));',params='String input, CharSequence a, CharSequence b')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_char_literal_overload(self):
        v=self.origin("sink(input.replace('x','y')); ")
        self.assertEqual(v['formal_parameter_indices'],[0])

    def test_case_sensitive_method_lookup(self):
        v=self.origin('sink(input.Trim());')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_wrong_arity_is_not_modeled(self):
        v=self.origin('sink(input.trim(other));')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_unknown_method_not_guessed(self):
        v=self.origin('sink(input.sanitize());')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_static_valueof_remains_unknown(self):
        v=self.origin('sink(String.valueOf(input));')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_locale_overload_remains_unknown(self):
        v=self.origin('sink(input.toLowerCase(locale));',params='String input, java.util.Locale locale')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_regex_replacement_not_in_catalog(self):
        v=self.origin('sink(input.replaceAll("x",other));')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_plain_object_receiver_not_assumed_string(self):
        v=self.origin('sink(input.toString());',params='Object input')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_string_assigned_to_object_is_not_typed_as_string(self):
        v=self.origin('Object x=input; sink(x.toString());')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_wrong_import_blocks_unqualified_receiver(self):
        v=self.origin('sink(input.trim());',imports='import example.String;')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_same_file_type_shadow_is_not_library(self):
        v=self.origin('sink(input.trim());',imports='',extra='class String { String trim(){return this;} }')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_type_parameter_shadow_blocks_model(self):
        v=self.origin('sink(input.trim());',helpers=' <String> void helper(String x) {}')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_unknown_wildcard_import_blocks_model(self):
        v=self.origin('sink(input.trim());',imports='import example.*;')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_implicit_String_type_preserves_assumption(self):
        v=self.origin('sink(input.trim());',imports='')
        self.assertEqual(v['formal_parameter_indices'],[0])
        self.assertIn('implicit_java_lang_String_requires_no_external_shadow',v['unknown_reasons'])

    def test_qualified_type_avoids_simple_name_shadow(self):
        v=self.origin('sink(input.trim());',params='java.lang.String input',imports='import example.String;')
        self.assertEqual(v['formal_parameter_indices'],[0])
        self.assertEqual(v['unknown_reasons'],[])

    def test_qualified_type_prefix_shadow_is_gap(self):
        v=self.origin('sink(input.trim());',params='java.lang.String input',extra='class java {}')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_string_literal_works_despite_simple_name_shadow(self):
        v=self.origin('sink("fixed".trim());',extra='class String {}',params='int unused',imports='')
        self.assertEqual(v['unknown_reasons'],[])
        self.assertTrue(v['literal_possible'])

    def test_prefix_array_dimensions_are_not_scalar_string(self):
        v=self.origin('sink(input.toString());',params='String[] input')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_postfix_parameter_dimensions_are_not_scalar_string(self):
        v=self.origin('sink(input.toString());',params='String input[]')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_postfix_local_dimensions_are_not_scalar_string(self):
        v=self.origin('String x[]=unknown(); sink(x.toString());')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_var_alias_tracks_inferred_string(self):
        v=self.origin('var x=input; sink(x.strip());')
        self.assertEqual(v['formal_parameter_indices'],[0])

    def test_cast_tracks_dependency_and_explicit_type(self):
        v=self.origin('sink(((java.lang.String) input).trim());',params='Object input')
        self.assertEqual(v['formal_parameter_indices'],[0])
        self.assertEqual(v['unknown_reasons'],[])

    def test_binary_concat_returns_string_type(self):
        v=self.origin('sink((input+other).trim());')
        self.assertEqual(v['formal_parameter_indices'],[0,1])

    def test_unknown_origin_remains_unknown_after_trim(self):
        v=self.origin('String x=external(); sink(x.trim());')
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_known_and_unknown_branch_both_survive(self):
        v=self.origin('String x=input; if(start>0) x=external(); sink(x.trim());')
        self.assertEqual(v['formal_parameter_indices'],[0])
        self.assertIn('call_return_not_modeled',v['unknown_reasons'])

    def test_helper_returns_string_then_library_model(self):
        v=self.origin('sink(copy(input).strip());',helpers='private String copy(String v) { return v; }')
        self.assertEqual(v['formal_parameter_indices'],[0])
        self.assertEqual(v['unknown_reasons'],[])

    def test_helper_model_provenance_survives_summary(self):
        s,r=self.inspect('sink(copy(input));',helpers='private String copy(String v) { return v.strip(); }')
        self.assertEqual(r['arguments'][0]['local_value_flow']['formal_parameter_indices'],[0])
        events=r['local_value_flow']['evidence']
        self.assertTrue(any(e.get('model_id')=='java.lang.String.strip/0' for e in events))
        self.check_references(s,r)

    def test_selected_argument_inside_library_call(self):
        _,r=self.inspect('input.concat(sink(other));')
        self.assertEqual(r['arguments'][0]['local_value_flow']['formal_parameter_indices'],[1])

    def test_library_result_does_not_change_original_receiver(self):
        _,r=self.inspect('input.trim(); sink(input);')
        self.assertEqual(r['arguments'][0]['local_value_flow']['value_identity_parameter_indices'],[0])

    def test_evidence_and_rule_revision(self):
        s,r=self.inspect('// 中文\n sink(input.strip().concat(other));')
        events=[e for e in r['local_value_flow']['evidence'] if e.get('model_id')]
        self.assertEqual(len(events),2)
        self.assertTrue(all(e['model_revision']==1 and e['sanitizer'] is False for e in events))
        self.assertEqual(r['local_value_flow']['library_models']['applications'],2)
        self.check_references(s,r)

    def test_compact_views_preserve_model_evidence(self):
        s,_=self.inspect('sink(input.strip());')
        args=s.anchor_at('C.java','sink')
        for view in ('full','summary','values'):
            r=s.call('inspect_operation_context',{**args,'view':view})
            self.assertEqual(r['arguments'][0]['local_value_flow']['formal_parameter_indices'],[0])
            self.assertEqual(r['authorization_verdict'],'not_evaluated')

    def check_references(self,s,v):
        if isinstance(v,dict):
            if {'path','sha256','start_byte','end_byte'} <= v.keys():
                raw=s.sources[v['path']].encode()
                self.assertEqual(v['sha256'],hashlib.sha256(raw).hexdigest())
                a,b=v['start_byte'],v['end_byte']
                self.assertTrue(0<=a<=b<=len(raw))
                self.assertTrue(raw[a:b].decode().startswith(v.get('text_prefix','')))
            for child in v.values(): self.check_references(s,child)
        elif isinstance(v,list):
            for child in v: self.check_references(s,child)

    def test_automatic_trace_through_library_calls(self):
        self.pipeline('tenant.strip().substring(0)',True)

    def test_automatic_trace_constant_overwrite_remains_disconnected(self):
        self.pipeline('"fixed".strip()',False)

    def pipeline(self,expr,expected):
        sources={'Service.java':SERVICE,'Facade.java':FACADE,'Controller.java':CONTROLLER,
                 'OrderMapper.java':harness.MAPPER,'OrderMapper.xml':harness.XML.replace('#{tenant}','${tenant}')}
        for name in list(sources):
            if name.endswith('.java'):
                sources[name]=sources[name].replace('long tenant','String tenant').replace(';\n',';\nimport java.lang.String;\n',1)
        sources['Service.java']=sources['Service.java'].replace('mapper.load(id, tenant)',f'mapper.load(id, {expr})')
        s=Session(self,sources); self.addCleanup(s.close)
        r=s.call('trace_source_to_sink',{**s.anchor_at('Service.java'),
            'mapper_path':'OrderMapper.java','mapping_path':'OrderMapper.xml',
            'scope_paths':['Service.java','Facade.java','Controller.java']})
        self.assertEqual(bool(r['paths']),expected)
        self.assertEqual(r['security_verdict'],'not_evaluated')
        if expected:
            self.assertEqual(r['paths'][0]['candidate_hops'],2)
            self.assertEqual(r['paths'][0]['relation'],'may_depend_after_transformation')
        self.check_references(s,r)


def add_model_case(name,expression):
    def test(self):
        v=self.origin('sink('+expression+');')
        self.assertEqual(v['formal_parameter_indices'],[0])
        self.assertEqual(v['unknown_reasons'],[])
    setattr(StringModels,'test_catalog_'+name,test)

for name,expr in (
    ('trim','input.trim()'),('strip','input.strip()'),('stripLeading','input.stripLeading()'),
    ('stripTrailing','input.stripTrailing()'),('lower','input.toLowerCase()'),('upper','input.toUpperCase()'),
    ('substring1','input.substring(0)'),('substring2','input.substring(0,1)'),
    ('concat','input.concat("suffix")'),('repeat','input.repeat(2)'),('replace','input.replace("x","y")')
): add_model_case(name,expr)

if __name__=='__main__': unittest.main()
