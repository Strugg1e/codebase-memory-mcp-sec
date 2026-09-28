"""Release guard tests use synthetic metadata, never GitHub credentials or writes."""
from __future__ import annotations

import copy
import contextlib
import io
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("preview_release", ROOT / "security/preview_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
SHA = "a" * 40
HEAD = "b" * 40


def metadata():
    pr = {"number": 5, "merged": True, "state": "closed", "draft": False, "merge_commit_sha": SHA,
          "base": {"ref": "main", "repo": {"full_name": release.REPO}},
          "head": {"sha": HEAD, "repo": {"full_name": release.REPO}}}
    runs = [{"id": i + 1, "path": ".github/workflows/" + name, "head_sha": HEAD,
             "event": "pull_request", "status": "completed", "conclusion": "success",
             "repository": {"full_name": release.REPO}, "head_repository": {"full_name": release.REPO},
             "pull_requests": [{"number": 5}]} for i, name in enumerate(release.WORKFLOWS)]
    return pr, [{"workflow_runs": runs}]


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cbm-sec-release-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def put(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def source(self):
        for name in release.REQUIRED:
            self.put(name, "# release test fixture, not a product implementation\n")
        self.put("security/facts.h", f'#define SF_VERSION "{release.VERSION}"\n')
        self.put("tests/java-argument-reference/Fixture.java", "class Fixture {}\n")
        self.put("tests/security/test_resource_operations.py", "# fixture\n")
        self.put("tests/security/test_export_evidence.py", "# fixture\n")
        self.put(release.RECEIPT, json.dumps({"schema": "cbm.sec.candidate-receipt.v1", **release.ORIGINALS,
                 "scope": "raw_archive_hashes_only_not_integration_or_test_verdict"}))

    def assets(self):
        info = {"commit": SHA, "tag": release.TAG, "analyzer_version": release.VERSION,
                "maturity": "preview", "system": "Linux", "architecture": "x86_64"}
        for name in release.ASSETS:
            self.put(name, "synthetic asset used only by checksum-unit tests\n")
        self.put("BUILD_INFO.json", json.dumps(info))
        self.put("TEST_RESULTS.json", json.dumps({"commit": SHA}))
        self.hashes()

    def hashes(self):
        self.put("SHA256SUMS", "".join(f"{release.digest(self.root / n)}  {n}\n" for n in release.ASSETS))

    def logs(self):
        self.put("tests/security/test_one.py", "# fixture\n")
        self.put("tests/security/test_two.py", "# fixture\n")
        core = "security core: input validation, hashing, identity, paging, lookup, span and UTF-8 tests passed\n"
        body = core + "".join(f"Running tests/security/test_{name}.py\nRan 3 tests in 0.1s\n\nOK\n" for name in ("one", "two"))
        for compiler in ("clang", "gcc"):
            self.put(f"logs/{compiler}.log", body)
        return self.root / "logs"

    def test_complete_merged_pr_all_seven_checks(self):
        pr, pages = metadata()
        self.assertEqual(len(release.check_pr(SHA, pr, pages)["checks"]), 7)

    def test_draft_open_and_unmerged_each_block(self):
        for key, value in (("draft", True), ("state", "open"), ("merged", False)):
            pr, pages = metadata(); pr[key] = value
            with self.subTest(key=key), self.assertRaises(release.Blocked):
                release.check_pr(SHA, pr, pages)

    def test_non_main_target_blocks(self):
        pr, pages = metadata(); pr["base"]["ref"] = "dev"
        with self.assertRaises(release.Blocked): release.check_pr(SHA, pr, pages)

    def test_other_repository_blocks(self):
        for side in ("base", "head"):
            pr, pages = metadata(); pr[side]["repo"]["full_name"] = "fixture/other"
            with self.subTest(side=side), self.assertRaises(release.Blocked): release.check_pr(SHA, pr, pages)

    def test_wrong_release_commit_blocks(self):
        pr, pages = metadata()
        with self.assertRaises(release.Blocked): release.check_pr("c" * 40, pr, pages)

    def test_short_or_injected_sha_blocks(self):
        for value in ("main", "a" * 7, SHA + ";touch x", "A" * 40):
            with self.subTest(value=value), self.assertRaises(release.Blocked):
                release.check_pr(value, *metadata())

    def test_dco_failure_cannot_use_other_green_checks(self):
        pr, pages = metadata(); pages[0]["workflow_runs"][2]["conclusion"] = "failure"
        with self.assertRaisesRegex(release.Blocked, "dco.yml"): release.check_pr(SHA, pr, pages)

    def test_pending_failed_cancelled_and_skipped_block(self):
        for state in ("failure", "cancelled", "skipped", None):
            pr, pages = metadata(); pages[0]["workflow_runs"][0]["conclusion"] = state
            with self.subTest(state=state), self.assertRaises(release.Blocked): release.check_pr(SHA, pr, pages)

    def test_newest_pending_does_not_reuse_old_success(self):
        pr, pages = metadata(); newer = copy.deepcopy(pages[0]["workflow_runs"][0])
        newer.update(id=100, status="in_progress", conclusion=None); pages[0]["workflow_runs"].append(newer)
        with self.assertRaises(release.Blocked): release.check_pr(SHA, pr, pages)

    def test_stale_head_check_does_not_count(self):
        pr, pages = metadata(); pages[0]["workflow_runs"][0]["head_sha"] = "c" * 40
        with self.assertRaises(release.Blocked): release.check_pr(SHA, pr, pages)

    def test_wrong_pr_event_repo_or_workflow_blocks(self):
        for key, value in (("event", "push"), ("pull_requests", [{"number": 99}]),
                           ("path", ".github/workflows/fake.yml"),
                           ("head_repository", {"full_name": "fixture/other"})):
            pr, pages = metadata(); pages[0]["workflow_runs"][0][key] = value
            with self.subTest(key=key), self.assertRaises(release.Blocked): release.check_pr(SHA, pr, pages)

    def test_paginated_checks_are_combined(self):
        pr, pages = metadata(); runs = pages[0]["workflow_runs"]
        self.assertEqual(len(release.check_pr(SHA, pr, [{"workflow_runs": runs[:3]}, {"workflow_runs": runs[3:]}])["checks"]), 7)

    def test_missing_check_blocks(self):
        pr, pages = metadata(); pages[0]["workflow_runs"].pop()
        with self.assertRaises(release.Blocked): release.check_pr(SHA, pr, pages)

    def test_source_fixture_complete(self):
        self.source(); self.assertEqual(release.check_source(self.root)["source_sha256"], release.ORIGINALS["source_sha256"])

    def test_missing_source_is_not_a_release(self):
        with self.assertRaisesRegex(release.Blocked, "candidate files missing"): release.check_source(self.root)

    def test_missing_receipt_blocks(self):
        self.source(); (self.root / release.RECEIPT).unlink()
        with self.assertRaises(release.Blocked): release.check_source(self.root)

    def test_wrong_receipt_hash_blocks(self):
        self.source(); value = release.read_json(self.root / release.RECEIPT); value["source_sha256"] = "f" * 64
        self.put(release.RECEIPT, json.dumps(value))
        with self.assertRaises(release.Blocked): release.check_source(self.root)

    def test_missing_reference_or_export_tests_block(self):
        for name in ("tests/java-argument-reference/Fixture.java", "tests/security/test_export_evidence.py"):
            self.source(); (self.root / name).unlink()
            with self.subTest(name=name), self.assertRaises(release.Blocked): release.check_source(self.root)

    def test_old_internal_version_blocks(self):
        self.source(); self.put("security/facts.h", '#define SF_VERSION "0.15.0-dev"\n')
        with self.assertRaises(release.Blocked): release.check_source(self.root)

    def test_real_hash_receipt_generation_with_fixture_hashes(self):
        a = self.put("source", "fixture source"); b = self.put("record", "fixture record")
        expected = {"source_sha256": release.digest(a), "validation_sha256": release.digest(b)}
        with patch.object(release, "ORIGINALS", expected): release.candidate_receipt(a, b, self.root / "receipt.json")
        self.assertEqual(release.read_json(self.root / "receipt.json")["source_sha256"], expected["source_sha256"])

    def test_wrong_original_bytes_cannot_create_receipt(self):
        a = self.put("source", "wrong"); b = self.put("record", "wrong")
        with self.assertRaises(release.Blocked): release.candidate_receipt(a, b, self.root / "receipt.json")
        self.assertFalse((self.root / "receipt.json").exists())

    def test_receipt_cannot_overwrite_existing_file(self):
        p = self.put("receipt.json", "preserve")
        with self.assertRaises(FileExistsError): release.write_json(p, {})
        self.assertEqual(p.read_text(), "preserve")

    def test_duplicate_json_rejected(self):
        with self.assertRaises(release.Blocked): release.loads('{"draft":true,"draft":false}')

    def test_exact_asset_set_and_hashes(self):
        self.assets(); release.verify_assets(self.root, SHA)

    def test_tampered_asset_blocks(self):
        self.assets(); self.put(release.ASSETS[0], "changed")
        with self.assertRaises(release.Blocked): release.verify_assets(self.root, SHA)

    def test_missing_and_extra_asset_block(self):
        self.assets(); extra = self.put("unexpected.txt", "extra")
        with self.assertRaises(release.Blocked): release.verify_assets(self.root, SHA)
        extra.unlink(); (self.root / release.ASSETS[0]).unlink()
        with self.assertRaises(release.Blocked): release.verify_assets(self.root, SHA)

    def test_checksum_traversal_and_duplicates_block(self):
        self.assets(); original = (self.root / "SHA256SUMS").read_text()
        for extra in (original.splitlines()[0] + "\n", "a" * 64 + "  ../secret\n"):
            self.put("SHA256SUMS", original + extra)
            with self.subTest(extra=extra), self.assertRaises(release.Blocked): release.verify_assets(self.root, SHA)

    def test_wrong_commit_and_stable_maturity_block(self):
        self.assets()
        for key, value in (("commit", "c" * 40), ("maturity", "stable"), ("architecture", "arm64")):
            original = release.read_json(self.root / "BUILD_INFO.json")
            changed = dict(original); changed[key] = value; self.put("BUILD_INFO.json", json.dumps(changed)); self.hashes()
            with self.subTest(key=key), self.assertRaises(release.Blocked): release.verify_assets(self.root, SHA)
            self.put("BUILD_INFO.json", json.dumps(original))

    def test_complete_test_logs(self):
        result = release.summarize_tests(self.root, self.logs())
        self.assertEqual(result["gcc"]["python_tests"], 6)

    def test_incomplete_and_skipped_suite_logs_block(self):
        logs = self.logs(); text = (logs / "gcc.log").read_text()
        for altered in (text.rsplit("OK", 1)[0], text.replace("OK", "OK (skipped=1)", 1), text.replace("Ran 3", "Ran 0", 1)):
            self.put("logs/gcc.log", altered)
            with self.subTest(altered=altered[-60:]), self.assertRaises(release.Blocked): release.summarize_tests(self.root, logs)

    def test_duplicate_and_missing_suites_block(self):
        logs = self.logs(); original = (logs / "gcc.log").read_text()
        for altered in (original + "Running tests/security/test_one.py\nRan 3 tests in 0.1s\nOK\n",
                        original.replace("test_two.py", "test_other.py")):
            self.put("logs/gcc.log", altered)
            with self.assertRaises(release.Blocked): release.summarize_tests(self.root, logs)

    def test_unequal_compiler_counts_block(self):
        logs = self.logs(); self.put("logs/gcc.log", (logs / "gcc.log").read_text().replace("Ran 3", "Ran 4", 1))
        with self.assertRaises(release.Blocked): release.summarize_tests(self.root, logs)

    def test_missing_core_blocks(self):
        logs = self.logs(); self.put("logs/gcc.log", (logs / "gcc.log").read_text().split("\n", 1)[1])
        with self.assertRaises(release.Blocked): release.summarize_tests(self.root, logs)

    def test_publish_outside_exact_main_stops_before_api(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(release, "gh_json") as api:
            with self.assertRaises(release.Blocked): release.publish(SHA, 5, self.root)
            api.assert_not_called()

    def test_existing_tag_blocks_before_release_creation(self):
        pr, pages = metadata()
        with patch.object(release, "gh_json", side_effect=[pr, {"object": {"sha": SHA}}]) as api, \
             patch.object(release, "run", return_value=json.dumps(pages)):
            with self.assertRaisesRegex(release.Blocked, "tag already exists"): release.remote_gate(SHA, 5)
            self.assertEqual(api.call_count, 2)
            self.assertTrue(all(c.kwargs.get("method", "GET") == "GET" for c in api.call_args_list))

    def test_workflow_is_manual_and_read_only_until_publish(self):
        text = (ROOT / ".github/workflows/cbm-sec-preview-015.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("  push:", text); self.assertNotIn("  pull_request:", text)
        self.assertIn("default: false", text)
        before, publish = text.split("  publish-preview:\n", 1)
        self.assertNotIn("contents: write", before); self.assertIn("contents: write", publish)
        self.assertIn("test \"$RELEASE_COMMIT\" = \"$GITHUB_SHA\"", text)
        self.assertNotIn("--clobber", text)

    def test_cli_help_and_unknown_argument(self):
        script = ROOT / "security/preview_release.py"
        for args, expected in ((["--help"], 0), (["--unknown"], 2)):
            p = subprocess.run([sys.executable, str(script), *args], capture_output=True, timeout=10)
            self.assertEqual(p.returncode, expected)


    def publish_fixture(self, failure=None):
        self.assets()
        calls = []
        downloads = []
        def api(endpoint, **kw):
            calls.append((endpoint, kw))
            if endpoint == "git/refs": return {}
            if endpoint.startswith("git/ref/tags/"): return {"object": {"sha": SHA, "type": "commit"}}
            if endpoint == "releases": return {"id": 7}
            if endpoint == "releases/7" and kw.get("method") == "PATCH": return {}
            if endpoint == "releases/7":
                published = any(k.get("method") == "PATCH" for _, k in calls)
                assets = [{"name": n} for n in (*release.ASSETS, "SHA256SUMS")]
                if published and failure == "published_missing": assets.pop()
                if published and failure == "published_extra": assets.append({"name": "extra.txt"})
                if published and failure == "published_duplicate": assets[-1] = assets[0].copy()
                return {"draft": not published, "prerelease": True, "tag_name": release.TAG,
                        "html_url": "https://github.com/" + release.REPO + "/releases/tag/" + release.TAG,
                        "assets": assets}
            raise AssertionError("unexpected API endpoint: " + endpoint)
        def command(args, **kw):
            self.assertNotIn("--clobber", args)
            if args[:3] == ["gh", "release", "upload"]:
                if failure == "upload": raise release.Blocked("fixture upload failure")
            elif args[:3] == ["gh", "release", "download"]:
                import shutil
                target = Path(args[args.index("--dir") + 1])
                published = any(k.get("method") == "PATCH" for _, k in calls)
                downloads.append(published)
                if published and failure == "published_download_error":
                    raise release.Blocked("fixture public download failure")
                for f in self.root.iterdir(): shutil.copy2(f, target / f.name)
                if failure == "download" or published and failure == "published_tamper":
                    (target / release.ASSETS[0]).write_text("tampered")
                if published and failure == "published_manifest":
                    (target / "SHA256SUMS").write_text("changed manifest")
            else: raise AssertionError("unexpected command")
            return ""
        env = {"GITHUB_REPOSITORY": release.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SHA}
        with patch.dict("os.environ", env, clear=True), patch.object(release, "check_source", return_value={}), \
             patch.object(release, "remote_gate", return_value={}), patch.object(release, "remote_pr_checks", return_value={}), \
             patch.object(release, "gh_json", side_effect=api), \
             patch.object(release, "run", side_effect=command), contextlib.redirect_stdout(io.StringIO()) as output:
            if failure:
                with self.assertRaises(release.Blocked): release.publish(SHA, 5, self.root)
                self.assertFalse(any(json.loads(line).get("published") is True
                                     for line in output.getvalue().splitlines()))
                if failure.startswith("published_"):
                    self.assertEqual(downloads, [False, True])
                    self.assertEqual(sum(kw.get("method") == "PATCH" for _, kw in calls), 1)
            else:
                release.publish(SHA, 5, self.root)
                self.assertEqual(downloads, [False, True], "verify both draft and public bytes")
                result = json.loads(output.getvalue().splitlines()[-1])
                self.assertTrue(result["published"])
                self.assertEqual(result["assets"], len(release.ASSETS) + 1)
        return calls

    def test_mock_publication_draft_before_upload_and_no_latest(self):
        calls = self.publish_fixture()
        creation = next(kw["payload"] for endpoint, kw in calls if endpoint == "releases")
        self.assertIs(creation["draft"], True); self.assertIs(creation["prerelease"], True)
        self.assertEqual(creation["make_latest"], "false")
        writes = [(endpoint, kw) for endpoint, kw in calls if kw.get("method") == "PATCH"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1]["payload"], {"draft": False, "prerelease": True, "make_latest": "false"})

    def test_upload_failure_leaves_draft_unpublished(self):
        calls = self.publish_fixture("upload")
        self.assertFalse(any(kw.get("method") == "PATCH" for _, kw in calls))

    def test_download_hash_failure_leaves_draft_unpublished(self):
        calls = self.publish_fixture("download")
        self.assertFalse(any(kw.get("method") == "PATCH" for _, kw in calls))

    def test_public_readback_rejects_missing_asset(self):
        self.publish_fixture("published_missing")

    def test_public_readback_rejects_extra_asset(self):
        self.publish_fixture("published_extra")

    def test_public_readback_rejects_duplicate_asset(self):
        self.publish_fixture("published_duplicate")

    def test_public_readback_rejects_changed_bytes(self):
        self.publish_fixture("published_tamper")

    def test_public_readback_rejects_changed_manifest(self):
        self.publish_fixture("published_manifest")

    def test_public_download_failure_does_not_report_completion(self):
        self.publish_fixture("published_download_error")

    def test_transport_errors_are_not_missing_tags(self):
        failure = subprocess.CompletedProcess([], 1, '{"status":"403"}', "forbidden")
        with patch.object(release.subprocess, "run", return_value=failure):
            with self.assertRaises(release.Blocked): release.gh_json("git/ref/tags/test", absent=True)
        missing = subprocess.CompletedProcess([], 1, '{"status":"404"}', "not found")
        with patch.object(release.subprocess, "run", return_value=missing):
            self.assertIsNone(release.gh_json("git/ref/tags/test", absent=True))

    def test_old_release_workflow_bytes_unchanged(self):
        raw = (ROOT / ".github/workflows/security-preview.yml").read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        self.assertEqual(actual, "39f764a9369b446fb9b32ccc858961851a7602e9")

    def test_dco_policy_bytes_unchanged(self):
        text = (ROOT / ".github/workflows/dco.yml").read_text(encoding="utf-8")
        self.assertIn('scripts/check-dco.sh "$RANGE"', text)
        self.assertNotIn("continue-on-error", text)


    def test_package_roundtrip_uses_isolated_synthetic_repository(self):
        # A throwaway git repository and dummy example programs exercise packaging only.
        # The candidate and binary gates are tested separately, not certified here.
        self.put(".gitignore", "build/\n")
        self.put("README.md", "# Synthetic packaging test\n")
        self.put("LICENSE", "Synthetic license fixture\n")
        self.put("THIRD_PARTY.md", "Synthetic notice fixture\n")
        self.put("docs/releases/0.15.0-preview.1.md", "# Synthetic preview notes\n")
        for name in ("demo_context.py", "demo_trace.py", "demo_flow.py", "demo_arguments.py"):
            self.put("security/" + name, 'print(\'{"synthetic_packaging_fixture": true}\')\n')
        for name in ("cbm-security-facts", "cbm-security-mcp"):
            self.put("build/preview-gcc/" + name, "synthetic program bytes, never executed\n")
        for name in ("gcc.log", "clang.log", "docs.log"):
            self.put("build/logs/" + name, "synthetic packaging-only log\n")
        def git(*args):
            return subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True, check=True).stdout.strip()
        git("init", "-q"); git("add", ".")
        git("-c", "user.name=Packaging test fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "test fixture")
        commit = git("rev-parse", "HEAD")
        with patch.object(release, "check_source", return_value={"synthetic": True}), \
             patch.object(release, "summarize_tests", return_value={"synthetic": True}), \
             patch.object(release, "binary_identity", return_value={"analyzer_version": release.VERSION, "build_id": "f" * 64}):
            release.package(self.root, commit, self.root / "build/logs", self.root / "build/dist")
        release.verify_assets(self.root / "build/dist", commit)
        import tarfile
        with tarfile.open(self.root / "build/dist" / release.ASSETS[1]) as archive:
            self.assertIn(release.TAG + "-linux-x86_64/security/demo_arguments.py", archive.getnames())
        with self.assertRaises(release.Blocked):
            release.verify_assets(self.root / "build/dist", "d" * 40)

    def test_failed_remote_read_cannot_create_tag(self):
        with patch.object(release, "gh_json", side_effect=release.Blocked("network failed")) as api:
            with self.assertRaises(release.Blocked): release.remote_gate(SHA, 5)
            self.assertEqual(api.call_count, 1)
            self.assertNotIn("method", api.call_args.kwargs)


if __name__ == "__main__":
    unittest.main(argv=[__file__])
