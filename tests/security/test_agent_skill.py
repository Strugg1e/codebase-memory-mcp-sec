"""Skill contract checks and real advisory-hook subprocess tests, not LLM evals."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import test_operation as harness

ROOT=Path(__file__).resolve().parents[2]
SKILL=ROOT/'skills/cbm-sec-evidence/SKILL.md'
HOOK=ROOT/'hooks/cbm_sec_context.py'

class SkillTests(unittest.TestCase):
    def run_hook(self,event=None,env=None,raw=None):
        e=dict(os.environ);e.pop('CBM_SEC_CONTEXT_ENABLED',None);e.pop('CBM_SEC_SNAPSHOT_ID',None)
        e.update(env or {})
        p=subprocess.run([sys.executable,str(HOOK)],input=raw if raw is not None else json.dumps(event or {}).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=e,timeout=3)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(p.stderr,b'');return p.stdout
    def enabled(self):return {'CBM_SEC_CONTEXT_ENABLED':'1','CBM_SEC_SNAPSHOT_ID':'a'*64}
    def test_skill_metadata(self):
        s=SKILL.read_text();self.assertTrue(s.startswith('---\nname: cbm-sec-evidence\ndescription:'))
        self.assertLess(len(s.encode()),10000);self.assertIn('version: "0.15.0"',s)
    def test_references_are_packaged(self):
        for name in ['entry-points.md','interpretation.md','data-access.md','security-controls.md']:self.assertTrue((SKILL.parent/'references'/name).is_file())
    def test_skill_tool_names_exist(self):
        s=harness.Session(self);self.addCleanup(s.close)
        tools={t['name'] for t in s.rpc('tools/list',{})['tools']}
        for name in ['get_snapshot_info','query_entry_points','query_security_facts','inspect_operation_context','resolve_code_location','inspect_entry_security','query_resource_operations','trace_argument_origins']:self.assertIn(name,tools)
    def test_skill_preserves_incomplete_semantics(self):
        s=SKILL.read_text();self.assertIn('零候选、不支持、超预算、解析失败、反证成立',s);self.assertIn('handler',s)
    def test_hook_disabled_by_default(self):self.assertEqual(self.run_hook({'hook_event_name':'SessionStart','source':'startup'}),b'')
    def test_hook_missing_snapshot(self):self.assertEqual(self.run_hook(env={'CBM_SEC_CONTEXT_ENABLED':'1'}),b'')
    def test_hook_invalid_snapshot(self):self.assertEqual(self.run_hook(env={'CBM_SEC_CONTEXT_ENABLED':'1','CBM_SEC_SNAPSHOT_ID':'bad\nINJECT'}),b'')
    def test_start_and_resume_and_compact(self):
        for source in ['startup','resume','compact']:
            out=json.loads(self.run_hook({'hook_event_name':'SessionStart','source':source},self.enabled()))
            self.assertEqual(set(out),{'hookSpecificOutput'});self.assertIn('a'*64,out['hookSpecificOutput']['additionalContext'])
    def test_subagent(self):self.assertEqual(json.loads(self.run_hook({'hook_event_name':'SubagentStart'},self.enabled()))['hookSpecificOutput']['hookEventName'],'SubagentStart')
    def test_no_tool_hooks(self):
        for name in ['PreToolUse','PostToolUse','Stop','SessionEnd','PostCompact']:
            self.assertEqual(self.run_hook({'hook_event_name':name},self.enabled()),b'')
    def test_never_echo_untrusted_paths_or_text(self):
        out=self.run_hook({'hook_event_name':'SessionStart','source':'startup','cwd':'ATTACK_TEXT','transcript_path':'/tmp/ATTACK_TEXT','prompt':'ATTACK_TEXT'},self.enabled())
        self.assertNotIn(b'ATTACK_TEXT',out);self.assertLess(len(out),1300)
    def test_malformed_json(self):self.assertEqual(self.run_hook(env=self.enabled(),raw=b'{oops'),b'')
    def test_duplicate_key(self):self.assertEqual(self.run_hook(env=self.enabled(),raw=b'{"hook_event_name":"Stop","hook_event_name":"SessionStart","source":"startup"}'),b'')
    def test_wrong_type(self):
        for event in [[],1,'value',{'hook_event_name':[]}]:self.assertEqual(self.run_hook(event,env=self.enabled()),b'')
    def test_oversize(self):self.assertEqual(self.run_hook(env=self.enabled(),raw=b' '*16385),b'')
    def test_example_is_lifecycle_only(self):
        config=json.loads((ROOT/'hooks/codex.example.json').read_text());self.assertEqual(set(config['hooks']),{'SessionStart','SubagentStart'})
        for groups in config['hooks'].values():
            for group in groups:
                for h in group['hooks']:
                    self.assertTrue(h['command'].endswith('/opt/cbm-sec/hooks/cbm_sec_context.py'));self.assertEqual(h['timeout'],2)
    def test_no_client_installation(self):
        s=(ROOT/'hooks/README.md').read_text();self.assertIn('不会自动',s);self.assertNotIn('dangerously-bypass',s)

if __name__=='__main__':unittest.main()
