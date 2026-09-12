"""Verify the documented automatic-path demo using the real MCP process."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
import unittest

CLI = Path(sys.argv.pop(1)).resolve()
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'security/demo_trace.py'


class TraceDemo(unittest.TestCase):
    def test_three_real_scenarios(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '--mcp', str(CLI.with_name('cbm-security-mcp'))],
                             capture_output=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr.decode('utf8', 'replace'))
        value = json.loads(run.stdout)
        self.assertFalse(value['target_execution']); self.assertEqual(value['model_calls'], 0)
        self.assertEqual(len(value['cases']), 3)
        for case in value['cases']:
            self.assertTrue(case['expectations_passed'])
            self.assertFalse(case['supplied_upstream_paths'])
            self.assertNotIn('upstream_calls', case['request'])
            self.assertGreater(case['source_references_checked'], 0)
        direct, overwritten, unknown = [x['result'] for x in value['cases']]
        self.assertEqual(direct['paths'][0]['candidate_hops'], 2)
        self.assertFalse(overwritten['paths'])
        self.assertEqual(unknown['paths'][0]['status'], 'candidate_with_unknowns')

    def test_missing_binary(self):
        run = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 2); self.assertEqual(run.stdout, b'')

    def test_invalid_executable(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '--mcp', str(ROOT / 'build/absent')],
                             capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1); self.assertEqual(run.stdout, b'')
        self.assertIn(b'demo_failed', run.stderr)


if __name__ == '__main__':
    unittest.main()
