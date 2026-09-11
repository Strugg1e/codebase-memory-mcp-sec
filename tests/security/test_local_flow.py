"""Real Java parsers and MCP; no target execution or simulated tool responses."""
from __future__ import annotations

import json
import random
import unittest
from test_flow import Session, SERVICE, FACADE, CONTROLLER
import test_operation as harness


class LocalFlow(unittest.TestCase):
    def inspect(self, body, parameters='long id, long tenant, boolean flag', call='sink', index=0):
        source = 'class C { void f(' + parameters + ') { ' + body + ' } }'
        s = Session(self, {'C.java': source})
        self.addCleanup(s.close)
        data = s.call('inspect_operation_context', s.anchor_at('C.java', call, index))
        return data

    def value(self, body, index=1, **kwargs):
        data = self.inspect(body, **kwargs)
        v = data['arguments'][index]['local_value_flow']
        self.assertEqual(data['authorization_verdict'], 'not_evaluated')
        self.assertEqual(data['local_value_flow']['heap_contents'], 'not_modeled')
        self.assertEqual(v['trust'], 'not_established')
        return v

    def test_qualified_creation_evaluates_qualifier(self):
        v = self.value('(tenant=id).new Inner(); sink(id,tenant);', parameters='Outer id, Outer tenant')
        self.assertEqual(v['formal_parameter_indices'], [0])
        self.assertEqual(v['unknown_reasons'], [])

    def test_anchor_in_qualified_creation_is_evaluated(self):
        d = self.inspect('(sink(id,tenant)).new Inner();')
        self.assertEqual(d['arguments'][1]['local_value_flow']['formal_parameter_indices'], [1])

    def test_constructor_arguments_evaluate_left_to_right(self):
        v = self.value('new Box(tenant=id, tenant); sink(id,tenant);')
        self.assertEqual(v['formal_parameter_indices'], [0])

    def test_left_to_right_argument_capture(self):
        data = self.inspect('sink(tenant, tenant=0, tenant);')
        values = [v['local_value_flow'] for v in data['arguments']]
        self.assertEqual([v['formal_parameter_indices'] for v in values], [[1], [], []])

    def test_assignment_before_later_argument(self):
        d = self.inspect('sink(tenant=id, tenant);')
        self.assertEqual([x['local_value_flow']['formal_parameter_indices'] for x in d['arguments']], [[0], [0]])

    def test_two_calls_do_not_share_later_state(self):
        body = 'sink(id,tenant); tenant=0; sink(id,tenant);'
        a, b = self.inspect(body), self.inspect(body, index=1)
        self.assertEqual(a['arguments'][1]['local_value_flow']['formal_parameter_indices'], [1])
        self.assertEqual(b['arguments'][1]['local_value_flow']['formal_parameter_indices'], [])

    def test_unreachable_after_unconditional_return_is_unknown(self):
        v = self.value('return; sink(id,tenant);')
        self.assertIn('anchor_not_reached_in_supported_structure', v['unknown_reasons'])
        self.assertEqual(v['status'], 'partial')

    def test_unknown_branch_preserves_known_alternative(self):
        v = self.value('long a=tenant; if(flag) a=external(); sink(id,a);')
        self.assertEqual(v['formal_parameter_indices'], [1])
        self.assertIn('call_return_not_modeled', v['unknown_reasons'])

    def test_unsupported_loop_invalidates_prior_value(self):
        v = self.value('while(flag) {tenant=id;} sink(id,tenant);')
        self.assertIn('control_construct_not_modeled', v['unknown_reasons'])

    def test_loop_anchor_is_not_linearized(self):
        d = self.inspect('while(flag) { sink(id,tenant); tenant=0; }')
        self.assertEqual(d['local_value_flow']['status'], 'anchor_not_evaluated')
        self.assertIn('control_construct_not_modeled', d['arguments'][1]['local_value_flow']['unknown_reasons'])

    def test_try_catch_is_not_silently_flattened(self):
        v = self.value('try { tenant=0; } catch(Exception ex) { tenant=id; } sink(id,tenant);')
        self.assertIn('control_construct_not_modeled', v['unknown_reasons'])

    def test_finally_anchor_is_unknown(self):
        d = self.inspect('try { tenant=0; } finally { sink(id,tenant); }')
        self.assertEqual(d['local_value_flow']['status'], 'anchor_not_evaluated')

    def test_external_call_is_not_an_invented_propagator(self):
        v = self.value('long a=external(tenant); sink(id,a);')
        self.assertEqual(v['formal_parameter_indices'], [])
        self.assertIn('call_return_not_modeled', v['unknown_reasons'])

    def test_field_read_is_not_whole_object_taint(self):
        v = self.value('sink(id,obj.tenant);', parameters='long id, Dto obj')
        self.assertEqual(v['formal_parameter_indices'], [])
        self.assertIn('heap_contents_not_modeled', v['unknown_reasons'])

    def test_array_read_is_not_value_identity(self):
        v = self.value('sink(id,values[0]);', parameters='long id, long[] values')
        self.assertIn('heap_contents_not_modeled', v['unknown_reasons'])

    def test_same_spelling_field_write_does_not_kill_local(self):
        v = self.value('this.tenant=0; sink(id,tenant);')
        self.assertEqual(v['formal_parameter_indices'], [1])
        self.assertEqual(v['unknown_reasons'], [])

    def test_lambda_body_does_not_run_during_creation(self):
        v = self.value('Runnable r=()->{ external(tenant); }; sink(id,tenant);')
        self.assertEqual(v['formal_parameter_indices'], [1])
        self.assertEqual(v['unknown_reasons'], [])

    def test_unicode_preprocessing_gap_is_explicit(self):
        v = self.value(r'/* \u002a */ sink(id,tenant);')
        self.assertIn('java_unicode_escape_not_modeled', v['unknown_reasons'])

    def test_varargs_are_not_mapped_as_fixed_parameters(self):
        v = self.value('sink(id,tenant);', parameters='long id, long... tenant')
        self.assertIn('parameter_form_not_modeled', v['unknown_reasons'])

    def test_budget_exhaustion_is_not_clean_output(self):
        d = self.inspect('long a=tenant;' + 'a=a+1;' * 300 + 'sink(id,a);')
        self.assertTrue(d['local_value_flow']['truncated'])
        self.assertTrue(d['truncated'])
        self.assertIn('local_flow_budget_exceeded', d['arguments'][1]['local_value_flow']['unknown_reasons'])
        self.assertLessEqual(len(d['local_value_flow']['evidence']), 256)

    def test_evidence_points_to_exact_utf8_source(self):
        body = '// 中文\nlong 拷贝=tenant; sink(id,拷贝);'
        d = self.inspect(body)
        raw = ('class C { void f(long id, long tenant, boolean flag) { '+body+' } }').encode()
        records = d['local_value_flow']['evidence']
        for item in records:
            r = item['source']
            self.assertEqual(r['sha256'], harness.digest(raw))
            self.assertEqual(raw[r['start_byte']:r['end_byte']].decode()[:len(r['text_prefix'])], r['text_prefix'])
        selected = d['arguments'][1]['local_value_flow']['evidence_ids']
        self.assertTrue(selected)
        self.assertTrue(all(0 <= i < len(records) for i in selected))
        self.assertTrue(any(records[i]['kind']=='local_declaration' for i in selected))

    def test_old_direct_origin_is_retained(self):
        d = self.inspect('long alias=tenant; sink(id,alias);')
        self.assertEqual(d['arguments'][1]['origin'], 'expression_not_traced')
        self.assertEqual(d['arguments'][1]['local_value_flow']['formal_parameter_indices'], [1])

    def test_no_implicit_flow_claim(self):
        d = self.inspect('long a; if(flag) a=1; else a=2; sink(id,a);')
        self.assertEqual(d['arguments'][1]['local_value_flow']['formal_parameter_indices'], [])
        self.assertEqual(d['local_value_flow']['implicit_flows'], 'not_modeled')

    def test_randomized_straight_line_origin_reference(self):
        # Independent Python oracle for an explicit assignment/addition subset.
        rng = random.Random(1707)
        for trial in range(32):
            env = {'id': {0}, 'tenant': {1}, 'a': set(), 'b': set()}
            parts = ['long a=0,b=0;']
            for _ in range(10):
                dst = rng.choice(list(env))
                left, right = rng.choice(list(env)), rng.choice(list(env))
                kind = rng.randrange(3)
                if kind == 0:
                    parts.append(f'{dst}=7;'); env[dst] = set()
                elif kind == 1:
                    parts.append(f'{dst}={left};'); env[dst] = set(env[left])
                else:
                    parts.append(f'{dst}={left}+{right};'); env[dst] = env[left] | env[right]
            parts.append('sink(id,a);')
            s = Session(self, {'C.java':'class C {void f(long id,long tenant){'+''.join(parts)+'}}'})
            try:
                d = s.call('inspect_operation_context', s.anchor_at('C.java','sink'))
                v = d['arguments'][1]['local_value_flow']
                with self.subTest(trial=trial):
                    self.assertEqual(v['formal_parameter_indices'], sorted(env['a']))
                    self.assertEqual(v['unknown_reasons'], [])
            finally:
                s.close()


# Each named case is a distinct unittest, not a multiplied compiler-run count.
CASES = {
    'direct': ('sink(id,tenant);', [1], [], False),
    'alias': ('long a=tenant; sink(id,a);', [1], [], False),
    'alias_chain': ('long a=tenant,b=a,c=b; sink(id,c);', [1], [], False),
    'overwrite_literal': ('tenant=0; sink(id,tenant);', [], [], True),
    'overwrite_from_other_formal': ('tenant=id; sink(id,tenant);', [0], [], False),
    'overwrite_alias': ('long a=tenant; a=id; sink(id,a);', [0], [], False),
    'postcall_write': ('sink(id,tenant); tenant=0;', [1], [], False),
    'scope_exit': ('{long a=tenant;} long a=id; sink(id,a);', [0], [], False),
    'nested_update_outer': ('long a=0; {a=tenant;} sink(id,a);', [1], [], False),
    'if_join': ('long a; if(flag){a=tenant;} else {a=id;} sink(id,a);', [0,1], [], False),
    'if_constant_alternative': ('long a=0; if(flag) a=tenant; sink(id,a);', [1], [], True),
    'both_branches_overwrite': ('long a=tenant; if(flag) a=0; else a=1; sink(id,a);', [], [], True),
    'return_branch_removed': ('long a=tenant; if(flag){a=id; return;} sink(id,a);', [1], [], False),
    'throw_branch_removed': ('long a=tenant; if(flag){a=id; throw new Error();} sink(id,a);', [1], [], False),
    'else_survives': ('if(flag){tenant=id;} else return; sink(id,tenant);', [0], [], False),
    'then_anchor': ('if(flag){tenant=id; sink(id,tenant);} else tenant=0;', [0], [], False),
    'else_anchor': ('if(flag){tenant=0;} else {tenant=id; sink(id,tenant);}', [0], [], False),
    'ternary_join': ('long a=flag?tenant:id; sink(id,a);', [0,1], [], False),
    'ternary_state_effects': ('long a=flag?(tenant=id):(tenant=0); sink(id,tenant);', [0], [], True),
    'binary_transform': ('long a=tenant+id; sink(id,a);', [0,1], [0,1], False),
    'compound_assignment': ('long a=tenant; a+=id; sink(id,a);', [0,1], [0,1], False),
    'unary_transform': ('sink(id,-tenant);', [1], [1], False),
    'primitive_cast': ('sink(id,(int)tenant);', [1], [1], False),
    'parentheses': ('sink(id,((tenant)));', [1], [], False),
    'short_circuit_effect': ('boolean ok=flag && ((tenant=id)>0); sink(id,tenant);', [0,1], [], False),
    'short_circuit_or_effect': ('boolean ok=flag || ((tenant=id)>0); sink(id,tenant);', [0,1], [], False),
    'nested_rhs_assignment': ('tenant += (tenant=id); sink(id,tenant);', [0,1], [0,1], False),
    'string_concat': ('String a="prefix"+tenant; sink(id,a);', [1], [1], False),
    'postfix_old_value': ('long a=tenant++; sink(id,a);', [1], [], False),
    'prefix_new_value': ('long a=++tenant; sink(id,a);', [1], [1], False),
    'constant_expression': ('long a=1+2; sink(id,a);', [], [], True),
    'no_arg_return_propagation': ('external(tenant); sink(id,tenant);', [1], [], False),
    'comment_in_argument': ('sink(id, /* comment */ tenant);', [1], [], False),
    'comment_in_parentheses': ('sink(id,(/* comment */ tenant));', [1], [], False),
}


def make_case(body, params, derived, literal):
    def test(self):
        v = self.value(body)
        self.assertEqual(v['formal_parameter_indices'], params)
        self.assertEqual(v['derived_parameter_indices'], derived)
        self.assertEqual(v['literal_possible'], literal)
        self.assertEqual(v['unknown_reasons'], [])
    return test


for name, args in CASES.items():
    setattr(LocalFlow, 'test_' + name, make_case(*args))


class Composition(unittest.TestCase):
    def run_flow(self, service=SERVICE, facade=FACADE, controller=CONTROLLER):
        s = Session(self, {'Service.java':service, 'Facade.java':facade, 'Controller.java':controller})
        self.addCleanup(s.close)
        root = s.anchor_at('Service.java')
        root['upstream_calls'] = [s.anchor_at('Facade.java'), s.anchor_at('Controller.java')]
        return s.call('inspect_operation_context',root)

    def test_alias_across_two_hops(self):
        d = self.run_flow(service=SERVICE.replace('return mapper.load(id, tenant);','long a=tenant; return mapper.load(id,a);'))
        self.assertEqual(d['argument_flow']['paths'][1]['candidate_hops_followed'],0)
        p = d['argument_flow']['local_value_paths'][1]
        self.assertEqual(p['candidate_hops_followed'],2)
        self.assertEqual(p['result']['formal_parameter_indices'],[1])

    def test_transform_survives_composition(self):
        d = self.run_flow(service=SERVICE.replace('mapper.load(id, tenant)','mapper.load(id, tenant+id)'))
        p = d['argument_flow']['local_value_paths'][1]
        self.assertEqual(p['result']['derived_parameter_indices'],[0,1])
        self.assertEqual(p['candidate_hops_followed'],2)

    def test_overwrite_terminates_new_relation_not_old(self):
        d = self.run_flow(service=SERVICE.replace('return mapper','tenant=0; return mapper'))
        p = d['argument_flow']['local_value_paths'][1]
        self.assertEqual(p['candidate_hops_followed'],0)
        self.assertEqual(p['result']['formal_parameter_indices'],[])
        self.assertTrue(p['result']['literal_possible'])
        self.assertEqual(d['argument_flow']['paths'][1]['stop_reason'],'parameter_written_or_shadowed')

    def test_parameter_swap_after_alias(self):
        d = self.run_flow(service=SERVICE.replace('mapper.load(id, tenant)','mapper.load(id, tenant+id)'),
                          facade=FACADE.replace('service.load(id, tenant)','service.load(tenant,id)'))
        self.assertEqual(d['argument_flow']['local_value_paths'][1]['result']['formal_parameter_indices'],[0,1])

    def test_partial_call_preserves_other_known_origin(self):
        d = self.run_flow(service=SERVICE.replace('return mapper.load(id, tenant);','long a=tenant; if(id>0) a=external(); return mapper.load(id,a);'))
        p = d['argument_flow']['local_value_paths'][1]
        self.assertEqual(p['candidate_hops_followed'],2)
        self.assertEqual(p['result']['formal_parameter_indices'],[1])
        self.assertIn('call_return_not_modeled',p['result']['unknown_reasons'])

    def test_unverified_link_never_composes(self):
        d = self.run_flow(facade=FACADE.replace('OrderService service','OtherService service'))
        p = d['argument_flow']['local_value_paths'][1]
        self.assertEqual(p['candidate_hops_followed'],0)
        self.assertEqual(p['stop_reason'],'selected_call_link_unresolved')

    def test_intermediate_overwrite_removes_dependency(self):
        d = self.run_flow(facade=FACADE.replace('return service','tenant=0; return service'))
        p = d['argument_flow']['local_value_paths'][1]
        self.assertEqual(p['candidate_hops_followed'],1)
        self.assertEqual(p['result']['formal_parameter_indices'],[])

    def test_nested_branch_composes_multiple_frontier_positions(self):
        d = self.run_flow(service=SERVICE.replace('return mapper.load(id, tenant);','long a; if(id>0) a=id; else a=tenant; return mapper.load(id,a);'))
        p = d['argument_flow']['local_value_paths'][1]
        self.assertEqual(p['steps'][0]['input_argument_indices'],[0,1])
        self.assertEqual(p['result']['formal_parameter_indices'],[0,1])
        self.assertEqual(p['runtime_dispatch'],'not_verified')
        self.assertEqual(p['path_feasibility'],'not_evaluated')


if __name__ == '__main__':
    unittest.main()
