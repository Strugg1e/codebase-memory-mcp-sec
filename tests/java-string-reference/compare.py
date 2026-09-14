"""Observed input perturbations are a lower-bound check, not proof of all paths."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
if len(sys.argv)!=3: raise SystemExit('usage: compare.py FACTS_BINARY RUNTIME_TSV')
binary,reference=sys.argv[1:]; sys.argv=[sys.argv[0],binary]
sys.path.insert(0,str(ROOT/'tests/security'))
from test_flow import Session

def main():
    source=(ROOT/'tests/java-string-reference/StringReference.java').read_text()
    checker=unittest.TestCase(); s=Session(checker,{'StringReference.java':source})
    details=[]
    try:
        declarations=s.call('query_security_facts',{'path':'StringReference.java','kind':'method_declaration','limit':200})
        for row in Path(reference).read_text().splitlines():
            name,*outputs=row.split('\t'); assert len(outputs)==5
            method=next(f for f in declarations['facts'] if f['name']['text_prefix']==name)
            calls=s.call('query_security_facts',{'path':'StringReference.java','kind':'call_site','enclosing_id':method['id'],'limit':200})
            call=next(f for f in calls['facts'] if f['name']['text_prefix']=='sink')
            r=s.call('inspect_operation_context',{'path':'StringReference.java','analysis_id':calls['analysis_id'],'call_id':call['id']})
            relation=r['arguments'][0]['local_value_flow']
            observed=[i for i in range(4) if outputs[i+1]!=outputs[0]]
            checker.assertTrue(set(observed)<=set(relation['formal_parameter_indices']),(name,observed,relation))
            checker.assertEqual(relation['unknown_reasons'],[],name)
            if name=='overwritten':
                checker.assertEqual(relation['formal_parameter_indices'],[])
                checker.assertTrue(relation['literal_possible'])
            details.append({'method':name,'runtime_changed_parameter_indices':observed,
                            'static_parameter_indices':relation['formal_parameter_indices']})
        checker.assertEqual(len(details),14)
    finally: s.close()
    print(json.dumps({'schema':'cbm.java-string-reference.v1','methods_checked':len(details),
        'runtime_evaluations':len(details)*5,'observed_changes_included':True,
        'scope':'checked_in_fixture_finite_input_perturbations_no_general_semantic_or_vulnerability_proof',
        'java_target_from_user_executed':False,'results':details},indent=2))
if __name__=='__main__':main()
