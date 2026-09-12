"""Compare real framework output with static materials. Never execute target code."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
if len(sys.argv)!=3:raise SystemExit('usage: compare.py FACTS_BINARY REFERENCE_JSON')
binary,reference=sys.argv[1:];sys.argv=[sys.argv[0],binary]
sys.path.insert(0,str(ROOT/'tests/security'))
from test_operation import Session


def active(marker, present):
    # Reference fixture has exactly these two checked-in conditions. This is
    # test expectation code, not the production expression evaluator.
    for cond in marker['xml_conditions']:
        if cond['xml_element'] in ('if','when'):
            assert cond['text_prefix']=='"tenant != null"'
            if not present:return False
        elif cond['xml_element']=='otherwise':
            if present:return False
        else:raise AssertionError(cond)
    return True


def main():
    document=json.loads(Path(reference).read_text());assert document['mybatis_version']=='3.5.19'
    check=unittest.TestCase();count=0;marker_count=0
    for case in document['cases']:
        owner=case['owner'];name=owner.rsplit('.',1)[1];method=case['method']
        mapper=(ROOT/f'tests/mybatis-reference/src/main/java/data/{name}.java').read_text()
        xml=(ROOT/'tests/mybatis-reference/fixtures/XmlMapper.xml').read_text()
        caller=f'package app; import {owner}; class Caller {{ {name} mapper; Object run(long id, String tenant) {{ return mapper.{method}(id,tenant); }} }}'
        s=Session(check,caller=caller,mapper=mapper,xml=xml)
        try:
            page=s.call('query_security_facts',{'path':'Controller.java','kind':'call_site','limit':200})
            call=next(f for f in page['facts'] if f.get('name',{}).get('text_prefix')==method)
            args={'path':'Controller.java','analysis_id':page['analysis_id'],'call_id':call['id'],'mapper_path':'OrderMapper.java'}
            if case['kind']=='xml':args['mapping_path']='OrderMapper.xml'
            else:args['mapping_format']='annotation'
            result=s.call('inspect_operation_context',args);check.assertEqual(result['authorization_verdict'],'not_evaluated')
            markers=result['mybatis']['parameter_occurrences']; selected=[v for v in markers if active(v,case['tenant_present'])]
            expected=[v['parameter_name'] for v in selected if v['form']=='parameter_marker']
            check.assertEqual(case['parameters'],expected,case)
            replacements=sum(v['form']=='text_substitution_marker' for v in selected)
            check.assertEqual(case['sql'].count('MB_SENTINEL'),replacements,case)
            # The same marker-to-argument relation is checked on both input forms.
            for v in markers:check.assertEqual(v['argument_index'],{'id':0,'tenant':1}[v['parameter_name']])
            count+=1;marker_count+=len(selected)
        finally:s.close()
    print(json.dumps({'mybatis_version':'3.5.19','framework_cases_compared':count,
        'active_marker_observations_compared':marker_count,'parameter_order_and_substitution_counts_match':True,
        'scope':'checked_in_BoundSql_fixtures_no_database','security_verdicts_tested':False},indent=2))

if __name__=='__main__':main()
