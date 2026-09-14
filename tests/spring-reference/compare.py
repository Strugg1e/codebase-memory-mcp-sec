"""Compare actual Spring registration with CBM Sec for the checked-in fixture only."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest

if len(sys.argv) != 3:
    raise SystemExit("usage: compare.py FACTS_BINARY REFERENCE_JSON")
reference_file=Path(sys.argv.pop(2)).resolve()
root=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(root/'tests/security'))
from test_flow import Session  # consumes the remaining binary argument

source_dir=Path(__file__).parent/'src/main/java/reference'
sources={p.name:p.read_text() for p in source_dir.glob('*.java') if p.name!='EntryOracle.java'}
reference=json.loads(reference_file.read_text())
if reference['spring_version']!='6.2.6': raise SystemExit('unexpected Spring version')
s=Session(unittest.TestCase(),sources)
try:
    page=s.call('query_entry_points',{});entries=page['entries']
    if page['page']['next_cursor'] is not None: raise AssertionError('fixture unexpectedly exceeded page size')
    actual={(e['class_name'],e['handler']):e for e in entries if e['controller_marker']=='direct_declaration'}
    expected={(e['class_name'],e['handler']):e for e in reference['handlers']}
    assert actual.keys()==expected.keys(), (actual.keys(),expected.keys())
    fields=0
    for key,row in expected.items():
        e=actual[key]
        assert set(e['declared_paths'])==set(row['paths']), (key,'paths',e['declared_paths'],row['paths'])
        for name in ['methods','params','headers','consumes','produces']:
            assert set(e['conditions'][name])==set(row[name]), (key,name,e['conditions'][name],row[name])
        assert e['authorization']=='not_evaluated' and not e['runtime_registration_verified']
        fields+=6
    orphan=[e for e in entries if e['handler']=='notRegistered']
    assert len(orphan)==1 and orphan[0]['controller_marker']=='not_observed'
    assert not any(k[1]=='notRegistered' for k in expected)
    print(json.dumps({'spring_version':'6.2.6','registered_handlers_compared':len(expected),
        'mapping_fields_compared':fields,'unregistered_candidate_distinguished':True,
        'scope':'checked_in_fixture_registration_only','security_verdicts_tested':False},indent=2))
finally:
    s.close()
