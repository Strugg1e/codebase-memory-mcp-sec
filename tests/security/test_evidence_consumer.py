"""Consumer-side evidence contracts over real controlled MCP captures.

These are independent regression tests, not recovered historical candidate tests.
Mutated captures below test reference validation, not producer authenticity.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_flow as flow

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "security"))
import export_evidence as evidence
from demo_context import SOURCE

SOURCE_UTF8 = SOURCE.replace('"prefix-"', '"pré前😀-"')


class EvidenceConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        session = flow.Session(unittest.TestCase(), {
            "Example.java": SOURCE_UTF8, "Unused.txt": "unreferenced fixture data\n"})
        try:
            args = {"snapshot_id": session.snapshot,
                    **session.anchor_at("Example.java", name="store"), "view": "full"}
            result = session.call("inspect_operation_context", args)
            producer = session.call("get_snapshot_info")["product_capabilities"]
            cls.capture = evidence.make_capture(args, result, producer)
            cls.snapshot = session.path.read_bytes()
        finally:
            session.close()
        cls.snapshot_hash = evidence.digest(cls.snapshot)
        cls.source = SOURCE_UTF8.encode("utf-8")

    def capture_with_spans(self, spans):
        capture = json.loads(self.capture)
        capture["result"]["consumer_reference_fixtures"] = [
            {"path": "Example.java", "sha256": evidence.digest(self.source),
             "start_byte": start, "end_byte": end} for start, end in spans]
        return evidence.encode(capture)

    def build(self, capture):
        return evidence.build_bundle(capture, self.snapshot, evidence.digest(capture), self.snapshot_hash)

    def test_empty_span_cannot_split_utf8_codepoint(self):
        for character in ("é", "前", "😀"):
            encoded = character.encode("utf-8")
            start = self.source.index(encoded)
            for offset in range(1, len(encoded)):
                with self.subTest(character=character, offset=offset):
                    capture = self.capture_with_spans([(start + offset, start + offset)])
                    with self.assertRaisesRegex(evidence.EvidenceError, "reference_utf8_boundary"):
                        self.build(capture)

    def test_valid_empty_spans_preserve_each_occurrence(self):
        positions = [0, len(self.source)]
        for character in ("é", "前", "😀"):
            start = self.source.index(character.encode("utf-8"))
            positions.extend((start, start + len(character.encode("utf-8"))))
        capture = self.capture_with_spans([(position, position) for position in positions])
        bundle = self.build(capture)
        references = [r for r in bundle["references"]
                      if r["pointer"].startswith("/result/consumer_reference_fixtures/")]
        self.assertEqual(len(references), len(positions))
        self.assertEqual([r["start_byte"] for r in references], positions)
        self.assertTrue(all(r["start_byte"] == r["end_byte"] and r["text"] == "" for r in references))
        self.assertEqual(len({r["pointer"] for r in references}), len(positions))
        checked = evidence.verify_bundle(evidence.encode(bundle), self.snapshot,
                                         evidence.digest(capture), self.snapshot_hash)
        self.assertEqual(checked["capture_json"].encode("utf-8"), capture)

    def test_nonempty_span_still_rejects_partial_codepoint(self):
        for character in ("é", "前", "😀"):
            encoded = character.encode("utf-8")
            start = self.source.index(encoded)
            for span in ((start + 1, start + len(encoded)), (start, start + len(encoded) - 1)):
                with self.subTest(character=character, span=span):
                    with self.assertRaisesRegex(evidence.EvidenceError, "reference_utf8_boundary"):
                        self.build(self.capture_with_spans([span]))

    def test_cli_rejects_split_empty_span_without_success_or_output(self):
        start = self.source.index("前".encode("utf-8"))
        valid = self.capture_with_spans([(start, start)])
        bad = self.capture_with_spans([(start + 1, start + 1)])
        # Build a consistent-looking invalid package without using the function
        # under test to approve the invalid reference. Neither hash is trusted
        # production evidence: both belong solely to this mutation fixture.
        bundle = self.build(valid)
        bundle["capture_json"] = bad.decode("utf-8")
        bundle["capture_sha256"] = evidence.digest(bad)
        ref = next(r for r in bundle["references"]
                   if r["pointer"] == "/result/consumer_reference_fixtures/0")
        ref.update(start_byte=start + 1, end_byte=start + 1)
        with tempfile.TemporaryDirectory(prefix="cbm-consumer-contract-") as temporary:
            root = Path(temporary)
            (root / "snapshot.json").write_bytes(self.snapshot)
            (root / "capture.json").write_bytes(bad)
            (root / "bundle.json").write_bytes(evidence.encode(bundle))
            common = ["--snapshot", str(root / "snapshot.json"), "--expect-snapshot", self.snapshot_hash,
                      "--expect-capture", evidence.digest(bad)]
            for mode, args in (("export", ["--capture", str(root / "capture.json"),
                                           "--output", str(root / "output.json")]),
                               ("verify", ["--bundle", str(root / "bundle.json")])):
                with self.subTest(mode=mode):
                    completed = subprocess.run([sys.executable, str(ROOT / "security/export_evidence.py"),
                        mode, *common, *args], capture_output=True, timeout=20)
                    self.assertEqual(completed.returncode, 2, completed.stdout)
                    self.assertEqual(completed.stdout, b"")
                    self.assertEqual(json.loads(completed.stderr),
                                     {"error": "reference_utf8_boundary", "verified": False})
            self.assertFalse((root / "output.json").exists())

    def test_context_identity_is_not_a_capture_digest(self):
        changed = json.loads(self.capture)
        changed["result"]["gaps"].append("consumer_fixture_unknown")
        changed["result"]["truncated"] = True
        changed["result"]["consumer_conditions"] = [None, False, 0, [], {}, "unknown", "not_searched"]
        raw = evidence.encode(changed)
        first, second = self.build(self.capture), self.build(raw)
        self.assertEqual(first["identity"]["context_id"], second["identity"]["context_id"])
        self.assertNotEqual(first["capture_sha256"], second["capture_sha256"])
        self.assertEqual(json.loads(second["capture_json"])["result"], changed["result"])
        with self.assertRaisesRegex(evidence.EvidenceError, "capture_digest_mismatch"):
            evidence.verify_bundle(evidence.encode(second), self.snapshot,
                                   evidence.digest(self.capture), self.snapshot_hash)

    def test_unreferenced_source_still_requires_its_exact_hash(self):
        snapshot = json.loads(self.snapshot)
        next(f for f in snapshot["files"] if f["path"] == "Unused.txt")["source"] += "changed"
        raw = evidence.encode(snapshot)
        with self.assertRaisesRegex(evidence.EvidenceError, "source_digest_mismatch"):
            evidence.snapshot_files(raw, evidence.digest(raw))

    def test_snapshot_paths_are_not_host_file_reads(self):
        # The source files exist only inside the snapshot. Pure export/verify
        # must not open result paths in the host filesystem or run other tools.
        with patch.object(Path, "open", side_effect=AssertionError("unexpected host file read")), \
             patch.object(subprocess, "run", side_effect=AssertionError("unexpected tool execution")):
            bundle = self.build(self.capture)
            checked = evidence.verify_bundle(evidence.encode(bundle), self.snapshot,
                                             evidence.digest(self.capture), self.snapshot_hash)
        self.assertEqual(checked["capture_json"].encode("utf-8"), self.capture)
        self.assertEqual(checked["checks"]["program_relations"], "not_reverified")


if __name__ == "__main__":
    unittest.main()
