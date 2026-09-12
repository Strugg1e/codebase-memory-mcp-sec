"""Compare pinned static queries with actual checked-in Spring Security configuration."""
from pathlib import Path
import json
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
reference_path=Path(sys.argv.pop(2))
sys.path.insert(0,str(ROOT/'tests/security'))
from test_flow import Session
from test_entry_security import ENTRY


def main():
    reference=json.loads(reference_path.read_text())
    check=unittest.TestCase();compared=0;unknowns=0;decision_checks=0
    for filename in ['ReferenceConfiguration.java','UnknownConfiguration.java']:
        source=(Path(__file__).parent/'src/main/java/reference'/filename).read_text()
        s=Session(check,{'Entry.java':ENTRY,filename:source})
        try:
            entry=s.call('query_entry_points',{'path_prefix':'Entry.java'})['entries'][0]
            for case in reference['cases']:
                if case['config']!=filename:continue
                r=s.call('inspect_entry_security',{'path':'Entry.java','entry_id':entry['entry_id'],'config_paths':[filename],
                    'request_method':case['method'],'request_path':case['path'],'string_matcher_semantics':'ant-path'})
                selection=r['selection'];check.assertEqual(r['authorization_verdict'],'not_evaluated');check.assertFalse(r['runtime_registration_verified'])
                if filename=='UnknownConfiguration.java':
                    check.assertEqual(selection['status'],'ambiguous_chain_selection',r)
                    possible={x['factory'] for x in r['configurations'] if x['id'] in selection['candidate_chain_ids']}
                    check.assertIn(case['factory'],possible);check.assertEqual(possible,{'custom','fallback'});unknowns+=1;continue
                compared+=1
                if case['status']=='no_chain':check.assertEqual(selection['status'],'no_matching_chain_in_selected_scope',r);continue
                if case['status']=='ignored':check.assertEqual(selection['status'],'ignored_in_selected_configuration',r);continue
                check.assertEqual(selection['status'],'conditional_chain_selected',r)
                selected=next(x for x in r['configurations'] if x['id']==selection['selected_chain_id'])
                check.assertEqual(selected['factory'],case['factory'])
                rule=selection['rule_selection']
                if case['rule_index']==-1:
                    check.assertEqual(rule['status'],'default_deny_in_supported_authorization_configurer');expected=(False,False,False)
                else:
                    check.assertEqual(rule['status'],'conditional_rule_selected',r);check.assertEqual(rule['candidate_rule_indices'],[case['rule_index']])
                    kind=rule['requirement']['kind']
                    expected={'permitAll':(True,True,True),'denyAll':(False,False,False),'authenticated':(False,True,True),'hasAuthority':(False,False,True),'hasRole':(False,False,True)}[kind]
                check.assertEqual(tuple(case[k] for k in ['guest_granted','member_granted','admin_granted']),expected,case);decision_checks+=3
        finally:s.close()
    check.assertEqual(compared,16);check.assertEqual(unknowns,2)
    print(json.dumps({'spring_security_version':reference['spring_security_version'],'request_cases_compared':compared,'unknown_matcher_cases_preserved':unknowns,
        'authorization_manager_decisions_checked':decision_checks,'scope':'checked_in_factories_request_selection_not_full_filter_chain_or_business_verdict','http_listener':False},indent=2))
if __name__=='__main__':main()
