"""Resource inventory -> explicit full operation -> offline evidence contracts.

Real MCP responses and controlled source text, with independent offline processes.
These tests are not the original candidate export suite or a security verdict.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_flow as flow
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "security"))
import export_evidence as evidence


class ResourceExportTests(unittest.TestCase):
    def capture_operations(self, service=flow.SERVICE, annotations=False):
        mapper = flow.harness.MAPPER
        if annotations:
            mapper = mapper.replace("import org.apache.ibatis.annotations.Param;",
                "import org.apache.ibatis.annotations.Param; import org.apache.ibatis.annotations.Select;")
            mapper = mapper.replace("Object load(", '@Select("SELECT * FROM orders WHERE id=#{id}") Object load(')
        session = flow.Session(self, {"Service.java": service, "OrderMapper.java": mapper,
                                      "OrderMapper.xml": flow.harness.XML})
        try:
            inventory = session.call("query_resource_operations", {
                "application_id": "controlled-export", "scope_paths": list(session.sources)})
            producer = session.call("get_snapshot_info")["product_capabilities"]
            captures, summaries = [], []
            for operation in inventory["operations"]:
                summary = session.call(operation["inspection"]["tool"], operation["inspection"]["arguments"])
                request = summary["full_request"]
                args = dict(request["arguments"], snapshot_id=session.snapshot)
                full = session.call(request["tool"], args)
                captures.append(evidence.make_capture(args, full, producer))
                summaries.append(evidence.make_capture(dict(args, view="summary"), summary, producer))
            raw_snapshot = session.path.read_bytes()
        finally:
            session.close()
        self.assertIsNotNone(session.proc.returncode)
        self.assertEqual(session.proc.returncode, 0)
        return inventory, raw_snapshot, captures, summaries

    def test_both_mapping_formats_export_and_verify_after_analyzer_exit(self):
        inventory, snapshot, captures, _ = self.capture_operations(annotations=True)
        self.assertEqual(len(captures), 2)
        self.assertEqual({o["mapping_format"] for o in inventory["operations"]}, {"xml", "annotation"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "snapshot.json"
            snapshot_path.write_bytes(snapshot)
            for index, capture in enumerate(captures):
                with self.subTest(index=index):
                    capture_path, bundle_path = root / f"capture-{index}.json", root / f"bundle-{index}.json"
                    capture_path.write_bytes(capture)
                    common = ["--snapshot", str(snapshot_path), "--expect-snapshot", evidence.digest(snapshot),
                              "--expect-capture", evidence.digest(capture)]
                    outputs = []
                    for mode, extra in (("export", ["--capture", str(capture_path), "--output", str(bundle_path)]),
                                        ("verify", ["--bundle", str(bundle_path)])):
                        result = subprocess.run([sys.executable, str(ROOT / "security/export_evidence.py"), mode,
                                                 *common, *extra], capture_output=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        outputs.append(json.loads(result.stdout))
                        self.assertEqual(outputs[-1]["status"], "source_references_verified")
                        self.assertEqual(outputs[-1]["program_relations"], "not_reverified")
                        self.assertEqual(outputs[-1]["security_verdict"], "not_evaluated")
                    self.assertEqual(outputs[0]["bundle_sha256"], outputs[1]["bundle_sha256"])
                    bundle = json.loads(bundle_path.read_bytes())
                    self.assertEqual(bundle["capture_json"].encode("utf-8"), capture)
                    self.assertTrue(bundle["references"])
                    self.assertTrue(all(r["trust"] == "untrusted_source_data" for r in bundle["references"]))

    def test_structural_inventory_and_summary_cannot_impersonate_full_response(self):
        inventory, snapshot, captures, summaries = self.capture_operations()
        capture = json.loads(captures[0])
        for structure in (inventory, inventory["operations"][0]["operation_structure"]):
            changed = dict(capture, result=structure)
            raw = evidence.encode(changed)
            with self.assertRaisesRegex(evidence.EvidenceError, "full_operation_required"):
                evidence.build_bundle(raw, snapshot, evidence.digest(raw), evidence.digest(snapshot))
        for raw in summaries:
            with self.assertRaisesRegex(evidence.EvidenceError, "full_operation_required"):
                evidence.build_bundle(raw, snapshot, evidence.digest(raw), evidence.digest(snapshot))

    def test_same_resource_different_call_results_are_not_interchangeable(self):
        service = flow.SERVICE.replace("return mapper.load", "mapper.load(id, 0); return mapper.load")
        inventory, snapshot, captures, _ = self.capture_operations(service)
        self.assertEqual(len(captures), 2)
        self.assertEqual(len({o["resource_candidate"]["peer_group_id"] for o in inventory["operations"]}), 1)
        first, second = (json.loads(raw) for raw in captures)
        self.assertNotEqual(first["result"]["context_id"], second["result"]["context_id"])
        raw = evidence.encode(dict(first, result=second["result"]))
        with self.assertRaises(evidence.EvidenceError):
            evidence.build_bundle(raw, snapshot, evidence.digest(raw), evidence.digest(snapshot))
        with self.assertRaisesRegex(evidence.EvidenceError, "capture_digest_mismatch"):
            evidence.build_bundle(captures[1], snapshot, evidence.digest(captures[0]), evidence.digest(snapshot))

    def test_known_and_unknown_local_alternatives_survive_full_handoff(self):
        service = flow.SERVICE.replace("return mapper.load(id, tenant);",
            "long chosen=tenant; if(id<0){chosen=externalValue();} return mapper.load(id, chosen);")
        inventory, snapshot, captures, _ = self.capture_operations(service)
        self.assertEqual(len(captures), 1)
        full = json.loads(captures[0])["result"]
        relation = full["arguments"][1]["local_value_flow"]
        # A copy preserves identity; the union field includes both identity and derived sources.
        self.assertEqual(relation["formal_parameter_indices"], [1])
        self.assertEqual(relation["value_identity_parameter_indices"], [1])
        self.assertEqual(relation["derived_parameter_indices"], [])
        self.assertIn("call_return_not_modeled", relation["unknown_reasons"])
        bundle = evidence.build_bundle(captures[0], snapshot, evidence.digest(captures[0]), evidence.digest(snapshot))
        checked = evidence.verify_bundle(evidence.encode(bundle), snapshot, evidence.digest(captures[0]), evidence.digest(snapshot))
        self.assertEqual(json.loads(checked["capture_json"])["result"], full)
        self.assertEqual(checked["capture_json"].encode(), captures[0])
        self.assertNotIn("local_value_flow", inventory["operations"][0]["operation_structure"])


if __name__ == "__main__":
    unittest.main()
