"""Exercise the shipped example against the real analyzer, not a mock."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
import unittest

CLI = Path(sys.argv.pop(1)).resolve()
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "security/demo_flow.py"


class Preview(unittest.TestCase):
    def test_real_mcp_example_pair(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "--mcp", str(CLI.with_name("cbm-security-mcp"))],
                             capture_output=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr.decode("utf8", "replace"))
        result = json.loads(run.stdout)
        self.assertTrue(result["uses_test_fixtures"])
        self.assertEqual(result["model_calls"], 0)
        self.assertFalse(result["target_execution"])
        self.assertEqual(len(result["cases"]), 2)
        self.assertTrue(all(case["expectations_passed"] for case in result["cases"]))
        self.assertEqual(result["cases"][0]["tenant_parameter"]["candidate_hops_followed"], 2)
        self.assertEqual(result["cases"][1]["tenant_parameter"]["candidate_hops_followed"], 0)
        self.assertTrue(all(case["authorization_verdict"] == "not_evaluated" for case in result["cases"]))

    def test_missing_binary_argument_is_an_error(self):
        run = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, b"")

    def test_nonexistent_binary_is_an_error(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "--mcp", str(ROOT / "build/does-not-exist")],
                             capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(run.stdout, b"")
        self.assertIn(b"demo_failed", run.stderr)


if __name__ == "__main__":
    unittest.main()
