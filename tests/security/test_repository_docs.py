"""Repository layout checks, separate from program-analysis semantics."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("cbm_docs", ROOT / "scripts/check_cbm_sec_docs.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

class RepositoryDocsTests(unittest.TestCase):
    def test_links_catalog_and_preserved_originals(self):
        result = checker.validate()
        self.assertTrue(result["passed"], result["errors"])
        self.assertGreater(result["local_link_targets_checked"], 30)
        self.assertEqual(result["mcp_tools_checked"], 12)

    def test_make_help_does_not_build_or_install(self):
        p = subprocess.run(["make", "--no-print-directory", "help"], cwd=ROOT,
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("CBM Sec", p.stdout)
        self.assertNotIn("install.sh", p.stdout)

    def test_default_build_is_security(self):
        content = (ROOT / "Makefile").read_text()
        self.assertIn(".DEFAULT_GOAL := all", content)
        self.assertIn("include Makefile.security", content)
        self.assertNotIn("include Makefile.cbm", content)

    def test_original_upstream_readme_identity(self):
        data = (ROOT / "docs/upstream/originals/README.md").read_bytes()
        digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        self.assertEqual(digest, "c6ab67ee254a614b66c167f104a69a93fb6aaf89")

    def test_unpublished_registry_is_not_advertised(self):
        obj = json.loads((ROOT / "cbm-sec.json").read_text())
        self.assertEqual(obj["package_registry_status"], "not_declared")
        self.assertNotIn("packages", obj)
        self.assertFalse((ROOT / "server.json").exists())

    def test_upstream_release_fixture_remains_explicit(self):
        t = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("cp docs/upstream/originals/server.json server.json", t)
        self.assertIn("mcp-publisher publish", t)
        self.assertTrue((ROOT / "DCO").is_file())

    def test_current_security_docs_are_no_longer_root_files(self):
        self.assertFalse(list(ROOT.glob("SECURITY_*.md")))
        self.assertTrue((ROOT / "SECURITY.md").is_file())
        self.assertGreater(len(list((ROOT / "docs/reference").glob("*.md"))), 10)

    def test_contribution_instructions_match_product(self):
        t = (ROOT / "CONTRIBUTING.md").read_text()
        self.assertIn("make docs-check", t)
        self.assertIn("make test", t)
        self.assertNotIn("git clone https://github.com/DeusData", t)
        self.assertNotIn("core.hooksPath", t)

if __name__ == "__main__":
    unittest.main(argv=[__file__])
