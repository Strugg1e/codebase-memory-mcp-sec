"""Source-derived returns over real Java trees and MCP; no target execution."""
from __future__ import annotations

import unittest
import random
from test_flow import Session, SERVICE, FACADE, CONTROLLER
import test_operation as harness


class ReturnSummaries(unittest.TestCase):
    def inspect(self, body, helpers='', params='long id, long tenant, boolean flag',
                owner='class C', extra='', anchor='sink', call_index=0):
        source = (owner + ' { void f(' + params + ') { ' + body + ' } ' + helpers + ' } ' + extra)
        s = Session(self, {'C.java': source})
        self.addCleanup(s.close)
        return s.call('inspect_operation_context', s.anchor_at('C.java', anchor, call_index))

    def origin(self, body, helpers='', index=1, **kwargs):
        d = self.inspect(body, helpers, **kwargs)
        self.assertEqual(d['authorization_verdict'], 'not_evaluated')
        v = d['arguments'][index]['local_value_flow']
        self.assertEqual(v['trust'], 'not_established')
        return v

    def test_private_identity(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long x) { return x; }')
        self.assertEqual(v['value_identity_parameter_indices'], [1])
        self.assertEqual(v['unknown_reasons'], [])

    def test_static_helper(self):
        v = self.origin('sink(id,copy(tenant));', 'static long copy(long x) { return x; }')
        self.assertEqual(v['formal_parameter_indices'], [1])

    def test_final_helper(self):
        v = self.origin('sink(id,copy(tenant));', 'final long copy(long x) { return x; }')
        self.assertEqual(v['formal_parameter_indices'], [1])

    def test_final_owner(self):
        v = self.origin('sink(id,copy(tenant));', 'long copy(long x) { return x; }', owner='final class C')
        self.assertEqual(v['formal_parameter_indices'], [1])

    def test_explicit_this(self):
        v = self.origin('sink(id,this.copy(tenant));', 'private long copy(long x) { return x; }')
        self.assertEqual(v['formal_parameter_indices'], [1])

    def test_casted_receiver_not_resolved(self):
        v = self.origin('sink(id,((C)this).copy(tenant));', 'private long copy(long x) { return x; }')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_external_receiver_not_resolved(self):
        v = self.origin('sink(id,other.copy(tenant));', 'private long copy(long x) { return x; }')
        self.assertEqual(v['formal_parameter_indices'], [])
        self.assertIn('call_return_not_modeled', v['unknown_reasons'])

    def test_class_qualified_static_is_explicit_gap(self):
        v = self.origin('sink(id,C.copy(tenant));', 'static long copy(long x) { return x; }')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_virtual_method_is_not_assumed(self):
        v = self.origin('sink(id,copy(tenant));', 'long copy(long x) { return x; }')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_overloads_not_selected_by_arity(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long x){return x;} private long copy(){return 0;}')
        self.assertEqual(v['formal_parameter_indices'], [])
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_inherited_owner_is_not_resolved(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long x){return x;}', owner='class C extends Base', extra='class Base {}')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_interface_owner_is_not_resolved(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long x){return x;}', owner='class C implements Marker', extra='interface Marker {}')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_generic_owner_is_not_resolved(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long x){return x;}', owner='class C<T>')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_generic_method_is_not_resolved(self):
        v = self.origin('sink(id,copy(tenant));', 'private <T> long copy(long x){return x;}')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_varargs_not_flattened(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long... x){return 0;}')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_arity_mismatch_is_not_resolved(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long x,long y){return x;}')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_synchronized_method_is_not_silent(self):
        v = self.origin('sink(id,copy(tenant));', 'private synchronized long copy(long x){return x;}')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_native_method_is_not_resolved(self):
        v = self.origin('sink(id,copy(tenant));', 'private native long copy(long x);')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_void_method_is_not_return_model(self):
        v = self.origin('sink(id,copy(tenant));', 'private void copy(long x){}')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_object_method_name_not_resolved(self):
        v = self.origin('sink(id,equals(tenant));', 'private boolean equals(long x){return true;}')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_same_name_in_other_class_not_used(self):
        v = self.origin('sink(id,copy(tenant));', extra='class Other {private long copy(long x){return x;}}')
        self.assertIn('return_summary_target_not_resolved', v['unknown_reasons'])

    def test_parameter_reordering(self):
        v = self.origin('sink(id,second(tenant,id));', 'private long second(long x,long y){return y;}')
        self.assertEqual(v['value_identity_parameter_indices'], [0])

    def test_unused_argument_does_not_taint_return(self):
        v = self.origin('sink(id,second(external(tenant),id));', 'private long second(long x,long y){return y;}')
        self.assertEqual(v['formal_parameter_indices'], [0])
        self.assertEqual(v['unknown_reasons'], [])

    def test_actuals_captured_before_later_assignment(self):
        d = self.inspect('sink(first(tenant,tenant=0),tenant);', 'private long first(long a,long b){return a;}')
        self.assertEqual(d['arguments'][0]['local_value_flow']['formal_parameter_indices'], [1])
        self.assertEqual(d['arguments'][1]['local_value_flow']['formal_parameter_indices'], [])

    def test_callee_parameter_write_does_not_write_caller(self):
        d = self.inspect('sink(reset(tenant),tenant);', 'private long reset(long x){x=0;return x;}')
        self.assertTrue(d['arguments'][0]['local_value_flow']['literal_possible'])
        self.assertEqual(d['arguments'][1]['local_value_flow']['formal_parameter_indices'], [1])

    def test_callee_alias_chain(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long x){long a=x,b=a;return b;}')
        self.assertEqual(v['value_identity_parameter_indices'], [1])

    def test_callee_overwrite(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long x){x=0;return x;}')
        self.assertEqual(v['formal_parameter_indices'], [])
        self.assertTrue(v['literal_possible'])

    def test_derived_return(self):
        v = self.origin('sink(id,add(tenant,id));', 'private long add(long a,long b){return a+b;}')
        self.assertEqual(v['derived_parameter_indices'], [0,1])
        self.assertEqual(v['value_identity_parameter_indices'], [])

    def test_string_return(self):
        v = self.origin('sink(id,decorate(tenant));', 'private String decorate(String x){return "prefix"+x;}', params='String id,String tenant,boolean flag')
        self.assertEqual(v['derived_parameter_indices'], [1])

    def test_derived_actual_instantiation(self):
        v = self.origin('sink(id,copy(tenant+id));', 'private long copy(long x){return x;}')
        self.assertEqual(v['derived_parameter_indices'], [0,1])

    def test_branch_returns_are_joined(self):
        v = self.origin('sink(id,pick(flag,tenant,id));', 'private long pick(boolean c,long a,long b){if(c)return a;else return b;}')
        self.assertEqual(v['formal_parameter_indices'], [0,1])
        self.assertNotIn(2, v['formal_parameter_indices'])

    def test_early_return_and_fallthrough_return(self):
        v = self.origin('sink(id,pick(flag,tenant,id));', 'private long pick(boolean c,long a,long b){if(c)return a;return b;}')
        self.assertEqual(v['formal_parameter_indices'], [0,1])

    def test_known_return_and_unknown_return_coexist(self):
        v = self.origin('sink(id,pick(flag,tenant));', 'private long pick(boolean c,long a){if(c)return a;return external();}')
        self.assertEqual(v['formal_parameter_indices'], [1])
        self.assertIn('call_return_not_modeled', v['unknown_reasons'])

    def test_throw_branch_is_not_a_return_value(self):
        v = self.origin('sink(id,pick(flag,tenant));', 'private long pick(boolean c,long a){if(c)throw new Error();return a;}')
        self.assertEqual(v['formal_parameter_indices'], [1])
        self.assertEqual(v['unknown_reasons'], [])

    def test_throw_only_helper_returns_unknown(self):
        v = self.origin('sink(id,fail(tenant));', 'private long fail(long a){throw new Error();}')
        self.assertIn('normal_return_not_established', v['unknown_reasons'])

    def test_incomplete_return_keeps_gap(self):
        v = self.origin('sink(id,pick(flag,tenant));', 'private long pick(boolean c,long a){if(c)return a;}')
        self.assertIn('normal_return_not_established', v['unknown_reasons'])

    def test_finally_return_is_not_ignored(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long a){try{return a;}finally{return 0;}}')
        self.assertIn('control_construct_not_modeled', v['unknown_reasons'])

    def test_hidden_return_in_loop_keeps_unknown(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long a){while(true){if(a>0)return a;}return 0;}')
        self.assertIn('control_construct_not_modeled', v['unknown_reasons'])
        self.assertTrue(v['literal_possible'])

    def test_recursive_summary_stops_with_known_base(self):
        v = self.origin('sink(id,copy(tenant));', 'private long copy(long a){if(a==0)return a;return copy(a-1);}')
        self.assertEqual(v['formal_parameter_indices'], [1])
        self.assertIn('recursive_return_summary_not_solved', v['unknown_reasons'])

    def test_mutual_recursion_stops(self):
        v = self.origin('sink(id,a(tenant));', 'private long a(long x){return b(x);}private long b(long y){return a(y);}')
        self.assertIn('recursive_return_summary_not_solved', v['unknown_reasons'])

    def test_nested_helpers(self):
        v = self.origin('sink(id,a(tenant));', 'private long a(long x){return b(x);}private long b(long y){return y+1;}')
        self.assertEqual(v['derived_parameter_indices'], [1])
        self.assertEqual(v['unknown_reasons'], [])

    def test_summary_cache_does_not_mix_calls(self):
        d = self.inspect('long a=copy(tenant);long b=copy(0);sink(a,b,copy(id));', 'private long copy(long x){return x;}')
        values = [a['local_value_flow'] for a in d['arguments']]
        self.assertEqual([v['formal_parameter_indices'] for v in values], [[1],[],[0]])
        meta = d['local_value_flow']['return_summaries']
        self.assertEqual(meta['computed_methods'], 1)
        self.assertEqual(meta['requests'], 3)
        self.assertEqual(meta['cache_hits'], 2)

    def test_cached_summary_keeps_callee_index_scope(self):
        d = self.inspect('sink(id,second(tenant,id));', 'private long second(long a,long b){return b;}')
        m = d['local_value_flow']['return_summaries']['methods'][0]
        self.assertEqual(m['return_relation']['formal_parameter_indices'], [1])
        self.assertEqual(d['arguments'][1]['local_value_flow']['formal_parameter_indices'], [0])

    def test_cache_is_not_shared_between_operations(self):
        src = 'class C{private long copy(long x){return x;}void f(long x){sink(copy(x));}}'
        s = Session(self, {'C.java': src}); self.addCleanup(s.close)
        anchor = s.anchor_at('C.java','sink')
        a = s.call('inspect_operation_context', anchor)
        b = s.call('inspect_operation_context', anchor)
        self.assertEqual(a['local_value_flow']['return_summaries'], b['local_value_flow']['return_summaries'])
        self.assertEqual(b['local_value_flow']['return_summaries']['cache_hits'], 0)

    def test_depth_limit_is_explicit(self):
        helpers = ''.join(f'private long h{i}(long x){{return h{i+1}(x);}}' for i in range(10)) + 'private long h10(long x){return x;}'
        d = self.inspect('sink(id,h0(tenant));', helpers)
        v = d['arguments'][1]['local_value_flow']
        self.assertIn('return_summary_budget_exceeded', v['unknown_reasons'])
        self.assertTrue(d['truncated'])

    def test_method_cache_limit_is_explicit(self):
        helpers = ''.join(f'private long h{i}(long x){{return x;}}' for i in range(34))
        body = ''.join(f'h{i}(tenant);' for i in range(33)) + 'sink(id,h33(tenant));'
        d = self.inspect(body, helpers)
        self.assertTrue(d['truncated'])
        self.assertLessEqual(d['local_value_flow']['return_summaries']['computed_methods'],32)

    def test_heap_return_is_not_whole_object_propagation(self):
        v = self.origin('sink(id,get(tenant));', 'private long get(Dto x){return x.value;}', params='long id,Dto tenant')
        self.assertEqual(v['formal_parameter_indices'], [])
        self.assertIn('heap_contents_not_modeled', v['unknown_reasons'])

    def test_name_sanitize_does_not_clear_dependencies(self):
        v = self.origin('sink(id,sanitize(tenant));', 'private long sanitize(long x){return x;}')
        self.assertEqual(v['formal_parameter_indices'], [1])
        self.assertEqual(v['trust'], 'not_established')

    def test_utf8_references_and_summary_evidence(self):
        src = 'class C { private long copy(long x){/* 中文 */return x;}void f(long tenant){sink(copy(tenant));}}'
        s = Session(self, {'C.java':src});self.addCleanup(s.close)
        d = s.call('inspect_operation_context',s.anchor_at('C.java','sink'))
        raw = src.encode()
        def walk(v):
            if isinstance(v,dict):
                if all(k in v for k in ('path','sha256','start_byte','end_byte','text_prefix')):
                    self.assertEqual(v['sha256'],harness.digest(raw))
                    span = raw[v['start_byte']:v['end_byte']].decode()
                    self.assertTrue(span.startswith(v['text_prefix']))
                for x in v.values():walk(x)
            elif isinstance(v,list):
                for x in v:walk(x)
        walk(d)
        summaries = d['local_value_flow']['return_summaries']['methods']
        self.assertEqual(len(summaries),1)
        self.assertTrue(summaries[0]['return_relation']['evidence_ids'])
        for ident in summaries[0]['return_relation']['evidence_ids']:
            self.assertLess(ident,len(summaries[0]['evidence']))
        ids=d['arguments'][0]['local_value_flow']['evidence_ids']
        events=d['local_value_flow']['evidence']
        self.assertTrue(any(events[i]['kind']=='return_summary_application' for i in ids))

    def test_selected_anchor_inside_helper_still_works(self):
        d = self.inspect('copy(tenant);', 'private long copy(long x){sink(x);return x;}', anchor='sink')
        self.assertEqual(d['arguments'][0]['local_value_flow']['formal_parameter_indices'],[0])

    def test_helper_before_call_declaration_order_does_not_matter(self):
        src = 'class C{private long copy(long x){return x;}void f(long x){sink(copy(x));}}'
        s=Session(self,{'C.java':src});self.addCleanup(s.close)
        d=s.call('inspect_operation_context',s.anchor_at('C.java','sink'))
        self.assertEqual(d['arguments'][0]['local_value_flow']['formal_parameter_indices'],[0])

    def test_multihop_uses_summary_result(self):
        svc=SERVICE.replace('mapper.load(id, tenant)','mapper.load(id, copy(tenant))').replace('\n}', '\nprivate long copy(long x){return x;}\n}')
        s=Session(self,{'Service.java':svc,'Facade.java':FACADE,'Controller.java':CONTROLLER})
        self.addCleanup(s.close)
        args=s.anchor_at('Service.java')
        args['upstream_calls']=[s.anchor_at('Facade.java'),s.anchor_at('Controller.java')]
        d=s.call('inspect_operation_context',args)
        p=d['argument_flow']['local_value_paths'][1]
        self.assertEqual(p['candidate_hops_followed'],2)
        self.assertEqual(p['result']['formal_parameter_indices'],[1])
        self.assertEqual(p['result']['unknown_reasons'],[])

    def test_no_implicit_control_taint_is_invented(self):
        v=self.origin('sink(id,pick(flag));','private long pick(boolean b){if(b)return 1;return 2;}')
        self.assertEqual(v['formal_parameter_indices'],[])
        self.assertTrue(v['literal_possible'])

    def test_early_return_does_not_collect_dead_return(self):
        v=self.origin('sink(id,copy(tenant));','private long copy(long x){return 0;return x;}')
        self.assertEqual(v['formal_parameter_indices'],[])
        self.assertTrue(v['literal_possible'])

    def test_sibling_branch_literal_and_derived(self):
        v=self.origin('sink(id,pick(flag,tenant));','private long pick(boolean b,long x){if(b)return x+1;return 0;}')
        self.assertEqual(v['derived_parameter_indices'],[1])
        self.assertTrue(v['literal_possible'])


    def test_nested_owner_is_not_guessed(self):
        src='class Outer {class Inner {private long copy(long x){return x;}void f(long x){sink(copy(x));}}}'
        s=Session(self,{'C.java':src});self.addCleanup(s.close)
        d=s.call('inspect_operation_context',s.anchor_at('C.java','sink'))
        self.assertIn('return_summary_target_not_resolved',d['arguments'][0]['local_value_flow']['unknown_reasons'])

    def test_no_stale_summary_between_source_versions(self):
        first=self.origin('sink(id,copy(tenant));','private long copy(long x){return x;}')
        second=self.origin('sink(id,copy(tenant));','private long copy(long x){return 0;}')
        self.assertEqual(first['formal_parameter_indices'],[1])
        self.assertEqual(second['formal_parameter_indices'],[])

    def test_helper_unicode_escape_not_clean(self):
        v=self.origin('sink(id,copy(tenant));',r'private long copy(long x){/* \u002a */ return x;}')
        self.assertIn('java_unicode_escape_not_modeled',v['unknown_reasons'])

    def test_unused_local_class_return_does_not_leak(self):
        v=self.origin('sink(id,copy(tenant));','private long copy(long x){class L{long f(){return 0;}}return x;}')
        self.assertEqual(v['formal_parameter_indices'],[1])
        self.assertFalse(v['literal_possible'])

    def test_ternary_return(self):
        v=self.origin('sink(id,pick(flag,tenant,id));','private long pick(boolean b,long a,long c){return b?a:c;}')
        self.assertEqual(v['formal_parameter_indices'],[0,1])

    def test_branch_identity_and_derived_are_both_kept(self):
        v=self.origin('sink(id,pick(flag,tenant));','private long pick(boolean b,long a){if(b)return a;return a+1;}')
        self.assertEqual(v['value_identity_parameter_indices'],[1])
        self.assertEqual(v['derived_parameter_indices'],[1])

    def test_summary_event_limit_not_silent(self):
        d=self.inspect('sink(id,copy(tenant));','private long copy(long x){'+'x=x+1;'*300+'return x;}')
        self.assertTrue(d['truncated'])
        self.assertIn('return_summary_budget_exceeded',d['arguments'][1]['local_value_flow']['unknown_reasons'])
        self.assertLessEqual(len(d['local_value_flow']['return_summaries']['methods'][0]['evidence']),256)

    def test_zero_argument_constant_helper(self):
        v=self.origin('sink(id,fixed());','private long fixed(){return 7;}')
        self.assertEqual(v['formal_parameter_indices'],[])
        self.assertTrue(v['literal_possible'])
        self.assertEqual(v['unknown_reasons'],[])

    def test_summary_before_unrelated_unknown_control_keeps_gap(self):
        v=self.origin('sink(id,copy(tenant));','private long copy(long x){try{external();}finally{external();}return 0;}')
        self.assertTrue(v['literal_possible'])
        self.assertIn('control_construct_not_modeled',v['unknown_reasons'])

    def test_isolated_return_environment_shadow_names(self):
        v=self.origin('sink(id,copy(tenant));','private long copy(long id){long tenant=0;return id;}')
        self.assertEqual(v['formal_parameter_indices'],[1])

    def test_generated_helper_assignments_against_reference_sets(self):
        # Independent dependency-set model. No runtime execution of Java.
        for seed in range(24):
            rng=random.Random(seed)
            names=['a','b','c']
            origins={'a':{0},'b':{1},'c':set()}
            statements=['long c=0;']
            for _ in range(8):
                target=rng.choice(names)
                source=rng.choice(names+['0'])
                value=set() if source=='0' else set(origins[source])
                statements.append(f'{target}={source};')
                origins[target]=value
            result=rng.choice(names)
            helper='private long project(long a,long b){'+''.join(statements)+'return '+result+';}'
            with self.subTest(seed=seed):
                v=self.origin('sink(id,project(tenant,id));',helper)
                expected=sorted({1 if i==0 else 0 for i in origins[result]})
                self.assertEqual(v['formal_parameter_indices'],expected)
                self.assertEqual(v['unknown_reasons'],[])


if __name__=='__main__':
    unittest.main()
