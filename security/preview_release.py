"""CBM Sec 0.15 preview packaging gates. No analysis or contribution certification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPO = "Strugg1e/codebase-memory-mcp-sec"
TAG = "cbm-sec-v0.15.0-preview.1"
VERSION = "0.15.0-preview.1"
RECEIPT = "docs/releases/0.15.0-candidate-receipt.json"
ORIGINALS = {
    "source_sha256": "2c1b8caac79dfb371b87932e60963bc2211f5c364f73f0a8b28c3a6c833940f6",
    "validation_sha256": "486c38815611e50053df097197efc0c00f168b0208fc661597ec71076024e313",
}
WORKFLOWS = (
    "pr.yml", "codeql.yml", "dco.yml", "security-facts.yml",
    "security-entry-reference.yml", "security-mybatis-reference.yml",
    "security-control-reference.yml",
)
REQUIRED = (
    "security/export_evidence.py", "security/demo_arguments.py",
    "tests/security/test_argument_origins.py", "security/facts.h",
)
ASSETS = (
    f"{TAG}-source.tar.gz", f"{TAG}-linux-x86_64.tar.gz",
    "BUILD_INFO.json", "TEST_RESULTS.json", "DEMO_RESULTS.json",
    "CANDIDATE_RECEIPT.json", "RELEASE_NOTES.md",
)
TOOLS = {
    "get_snapshot_info", "list_snapshot_files", "query_security_facts",
    "get_security_evidence", "read_snapshot_source", "resolve_code_location",
    "query_entry_points", "query_resource_operations", "inspect_operation_context",
    "inspect_entry_security", "trace_argument_origins", "trace_source_to_sink",
}


class Blocked(RuntimeError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise Blocked(message)


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"not a regular file: {path.name}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def loads(text: str):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs)


def read_json(path: Path):
    require(path.is_file() and not path.is_symlink(), f"missing JSON: {path}")
    require(path.stat().st_size <= 16 * 1024 * 1024, "JSON input too large")
    return loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def run(args: list[str], *, cwd: Path = ROOT, data: str | None = None,
        timeout: int = 90) -> str:
    result = subprocess.run(args, cwd=cwd, input=data, capture_output=True,
                            encoding="utf-8", timeout=timeout, check=False)
    require(result.returncode == 0, f"command failed ({result.returncode}): {args[0]}")
    return result.stdout


def candidate_receipt(source: Path, validation: Path, output: Path) -> None:
    actual = {"source_sha256": digest(source), "validation_sha256": digest(validation)}
    require(actual == ORIGINALS, "original candidate hashes do not match handoff")
    write_json(output, {"schema": "cbm.sec.candidate-receipt.v1", **actual,
                       "scope": "raw_archive_hashes_only_not_integration_or_test_verdict"})


def check_source(root: Path) -> dict:
    missing = [name for name in REQUIRED if not (root / name).is_file()
               or (root / name).is_symlink() or (root / name).stat().st_size == 0]
    require(not missing, "candidate files missing: " + ", ".join(missing))
    reference = root / "tests/java-argument-reference"
    require(reference.is_dir() and any(reference.rglob("*.java")), "Java argument reference missing")
    for pattern in ("test_*resource*.py", "test_*export*.py"):
        require(any((root / "tests/security").glob(pattern)), f"candidate tests missing: {pattern}")
    text = (root / "security/facts.h").read_text(encoding="utf-8")
    version = re.search(r'^#define SF_VERSION "([^"]+)"$', text, re.M)
    require(version is not None and version[1] == VERSION, "source version mismatch")
    receipt = read_json(root / RECEIPT)
    require(isinstance(receipt, dict) and receipt.get("schema") == "cbm.sec.candidate-receipt.v1",
            "candidate receipt schema mismatch")
    require(all(receipt.get(k) == v for k, v in ORIGINALS.items()), "candidate receipt hash mismatch")
    require(receipt.get("scope") == "raw_archive_hashes_only_not_integration_or_test_verdict",
            "candidate receipt scope mismatch")
    return receipt


def check_pr(commit: str, pr: dict, pages: list[dict]) -> dict:
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "full commit SHA required")
    require(pr.get("merged") is True and pr.get("state") == "closed" and pr.get("draft") is False,
            "PR must be merged, closed and non-draft")
    require(pr.get("merge_commit_sha") == commit, "release commit is not the merged PR commit")
    for side in ("base", "head"):
        require(pr.get(side, {}).get("repo", {}).get("full_name") == REPO, "PR repository mismatch")
    require(pr["base"].get("ref") == "main", "PR does not target main")
    head = pr["head"].get("sha", "")
    require(re.fullmatch(r"[0-9a-f]{40}", head) is not None, "invalid PR head")
    require(isinstance(pages, list) and pages, "workflow pages missing")
    all_runs = [entry for page in pages for entry in page["workflow_runs"]]
    selected = {}
    for workflow in WORKFLOWS:
        path = ".github/workflows/" + workflow
        matches = [r for r in all_runs if r.get("path") == path and r.get("head_sha") == head
                   and r.get("event") == "pull_request"
                   and r.get("repository", {}).get("full_name") == REPO
                   and r.get("head_repository", {}).get("full_name") == REPO
                   and any(p.get("number") == pr.get("number") for p in r.get("pull_requests", []))]
        require(bool(matches), f"no matching PR check: {workflow}")
        latest = max(matches, key=lambda r: (r["id"], r.get("run_attempt", 1)))
        require(latest.get("status") == "completed" and latest.get("conclusion") == "success",
                f"latest PR check has not succeeded: {workflow}")
        selected[workflow] = {"id": latest["id"], "head_sha": head, "conclusion": "success"}
    return {"commit": commit, "pr": pr["number"], "head_sha": head, "checks": selected}


def summarize_tests(root: Path, logs: Path) -> dict:
    expected = {"tests/security/" + p.name for p in (root / "tests/security").glob("test_*.py")}
    require(bool(expected), "no security suites")
    result = {}
    for compiler in ("clang", "gcc"):
        text = (logs / (compiler + ".log")).read_text(encoding="utf-8")
        require("security core: input validation, hashing, identity, paging, lookup, span and UTF-8 tests passed" in text,
                f"missing C core result: {compiler}")
        sections = re.split(r"^Running (tests/security/test_[^\s]+\.py)\s*$", text, flags=re.M)
        counts = {}
        for i in range(1, len(sections), 2):
            name, body = sections[i:i + 2]
            require(name not in counts, f"duplicate suite: {name}")
            found = re.findall(r"^Ran (\d+) tests? in ", body, re.M)
            require(len(found) == 1 and int(found[0]) > 0, f"incomplete suite: {name}")
            require(len(re.findall(r"^OK\s*$", body, re.M)) == 1,
                    f"suite not successful: {name}")
            require(not re.search(r"^FAILED|^OK \(|\bskipped=", body, re.M), f"failed/skipped suite: {name}")
            counts[name] = int(found[0])
        require(set(counts) == expected, f"suite set mismatch: {compiler}")
        result[compiler] = {"suites": counts, "python_tests": sum(counts.values()), "c_core": "passed"}
    require(result["gcc"]["suites"] == result["clang"]["suites"], "compiler suite counts differ")
    return result


def binary_identity(root: Path, binaries: Path) -> dict:
    build_id = run([sys.executable, str(root / "security/build_id.py")], cwd=root).strip()
    facts = run([str(binaries / "cbm-security-facts"), "--version"], cwd=root).strip().split()
    require(len(facts) == 3 and facts[1:] == [VERSION, build_id], "facts version/build identity mismatch")
    with tempfile.TemporaryDirectory(prefix="cbm-sec-release-identity-") as directory:
        bundle = Path(directory) / "snapshot.json"
        raw = json.dumps({"schema": "cbm.security-snapshot.v1", "files": []}).encode()
        bundle.write_bytes(raw)
        bundle.chmod(0o600)
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "cbm-sec-preview-identity", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "get_snapshot_info", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
        ]
        out = run([str(binaries / "cbm-security-mcp"), "--snapshot", str(bundle),
                   "--expect-snapshot", hashlib.sha256(raw).hexdigest()], cwd=root,
                  data="".join(json.dumps(m) + "\n" for m in messages))
        responses = [loads(line) for line in out.splitlines()]
        require([r.get("id") for r in responses] == [1, 2, 3], "MCP identity protocol mismatch")
        require(all("error" not in r for r in responses), "MCP identity protocol error")
        require(responses[0]["result"]["serverInfo"]["version"] == VERSION, "MCP version mismatch")
        query = responses[1]["result"]
        require(query.get("isError") is False, "MCP snapshot query failed")
        info = query["structuredContent"]
        require(info.get("build_id") == build_id and info.get("analyzer_version") == VERSION,
                "MCP build identity mismatch")
        tools = responses[2]["result"]["tools"]
        require(len(tools) == len(TOOLS) and {t["name"] for t in tools} == TOOLS, "MCP tool registry mismatch")
    return {"analyzer_version": VERSION, "build_id": build_id}


def verify_assets(directory: Path, commit: str) -> None:
    require(directory.is_dir() and not directory.is_symlink(), "asset directory missing")
    require({p.name for p in directory.iterdir()} == set(ASSETS) | {"SHA256SUMS"}, "asset set mismatch")
    for path in directory.iterdir():
        require(path.is_file() and not path.is_symlink(), "asset is not a regular file")
    checksums = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        require(match is not None, "invalid checksum line")
        value, name = match.groups()
        require(name not in checksums and name in ASSETS, "unexpected/duplicate checksum entry")
        checksums[name] = value
    require(set(checksums) == set(ASSETS), "incomplete checksum set")
    require(all(digest(directory / name) == value for name, value in checksums.items()), "asset hash mismatch")
    info = read_json(directory / "BUILD_INFO.json")
    require(info.get("commit") == commit and info.get("tag") == TAG
            and info.get("analyzer_version") == VERSION and info.get("maturity") == "preview",
            "asset release identity mismatch")
    require(info.get("system") == "Linux" and info.get("architecture") == "x86_64", "unsupported release platform")
    tests = read_json(directory / "TEST_RESULTS.json")
    require(tests.get("commit") == commit, "test commit mismatch")


def package(root: Path, commit: str, logs: Path, output: Path) -> None:
    receipt = check_source(root)
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "full commit SHA required")
    require(run(["git", "rev-parse", "HEAD"], cwd=root).strip() == commit, "checkout commit mismatch")
    require(not run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root).strip(), "dirty checkout")
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "only Linux x86_64 is packaged")
    results = summarize_tests(root, logs)
    binaries = root / "build/preview-gcc"
    identity = binary_identity(root, binaries)
    require(not output.exists(), "output already exists; no overwrite")
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="cbm-sec-preview-package-") as directory:
        stage = Path(directory) / (TAG + "-linux-x86_64")
        stage.mkdir()
        tracked = run(["git", "ls-files", "-z"], cwd=root).split("\0")
        for name in filter(None, tracked):
            path = Path(name)
            copy = (name in {"README.md", "LICENSE", "THIRD_PARTY.md"}
                    or name.startswith(("docs/", "skills/cbm-sec-evidence/", "tests/security/"))
                    or name.startswith("security/") and path.suffix == ".py"
                    or name.startswith("tests/") and "-reference/" in name
                    or name.startswith(("internal/cbm/vendored/", "vendored/yyjson/"))
                    and path.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")))
            if copy:
                require((root / path).is_file() and not (root / path).is_symlink(), "package source link or non-file")
                target = stage / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(root / path, target)
        (stage / "bin").mkdir()
        for name in ("cbm-security-facts", "cbm-security-mcp"):
            shutil.copy2(binaries / name, stage / "bin" / name)
        demos = {}
        for name in ("demo_context.py", "demo_trace.py", "demo_flow.py", "demo_arguments.py"):
            demos[name] = loads(run([sys.executable, str(stage / "security" / name), "--mcp",
                                    str(stage / "bin/cbm-security-mcp")], cwd=stage, timeout=120))
        info = {"commit": commit, "tree": run(["git", "rev-parse", "HEAD^{tree}"], cwd=root).strip(),
                "tag": TAG, "maturity": "preview", **identity, "system": platform.system(),
                "architecture": platform.machine(), "libc": platform.libc_ver(),
                "compiler": run(["gcc", "--version"], cwd=root).splitlines()[0],
                "binary_sha256": {name: digest(stage / "bin" / name) for name in ("cbm-security-facts", "cbm-security-mcp")}}
        write_json(output / "BUILD_INFO.json", info)
        write_json(output / "TEST_RESULTS.json", {"commit": commit, "environments": results})
        write_json(output / "DEMO_RESULTS.json", {"commit": commit, "scope": "repository_controlled_fixtures", "demos": demos})
        write_json(output / "CANDIDATE_RECEIPT.json", receipt)
        shutil.copy2(root / "docs/releases/0.15.0-preview.1.md", output / "RELEASE_NOTES.md")
        with (output / "RELEASE_NOTES.md").open("a", encoding="utf-8") as stream:
            stream.write(f"\n实际发布提交：`{commit}`；程序版本：`{VERSION}`。\n"
                         "本包为 Linux x86_64 预览版，不是稳定版；实际范围见 BUILD_INFO.json 和 TEST_RESULTS.json。\n")
        (stage / "COMMIT.txt").write_text(commit + "\n", encoding="ascii")
        (stage / "test-logs").mkdir()
        for name in ("gcc.log", "clang.log", "docs.log"):
            shutil.copy2(logs / name, stage / "test-logs" / name)
        for name in ASSETS[2:]:
            shutil.copy2(output / name, stage / name)
        with tarfile.open(output / ASSETS[1], "w:gz") as archive:
            archive.add(stage, arcname=stage.name)
    with (output / ASSETS[0]).open("xb") as stream:
        subprocess.run(["git", "archive", "--format=tar.gz", f"--prefix={TAG}-source/", commit],
                       cwd=root, stdout=stream, check=True, timeout=180)
    (output / "SHA256SUMS").write_text("".join(f"{digest(output / n)}  {n}\n" for n in ASSETS), encoding="ascii")
    verify_assets(output, commit)
    # Exercise the archive contents, not only the pre-archive staging directory.
    with tempfile.TemporaryDirectory(prefix="cbm-sec-package-readback-") as temporary:
        unpacked = Path(temporary)
        with tarfile.open(output / ASSETS[1], "r:gz") as archive:
            for member in archive.getmembers():
                path = Path(member.name)
                require(not path.is_absolute() and ".." not in path.parts and
                        (member.isfile() or member.isdir()), "unsafe packaged member")
            archive.extractall(unpacked, filter="data")
        packaged = unpacked / (TAG + "-linux-x86_64")
        for name in ("cbm-security-facts", "cbm-security-mcp"):
            require(digest(packaged / "bin" / name) == info["binary_sha256"][name], "packaged binary changed")
        for name in demos:
            loads(run([sys.executable, str(packaged / "security" / name), "--mcp",
                       str(packaged / "bin/cbm-security-mcp")], cwd=packaged, timeout=120))


def gh_json(endpoint: str, *, payload: dict | None = None, method: str = "GET", absent: bool = False):
    args = ["gh", "api", "--method", method, f"repos/{REPO}/{endpoint}"]
    if payload is not None:
        args += ["--input", "-"]
    p = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                       capture_output=True, encoding="utf-8", timeout=90, check=False)
    if p.returncode:
        if absent and method == "GET":
            try:
                value = loads(p.stdout)
                if str(value.get("status")) == "404":
                    return None
            except (ValueError, AttributeError):
                pass
        raise Blocked(f"GitHub request failed: {method} {endpoint}")
    return loads(p.stdout)


def remote_pr_checks(commit: str, pr_number: int) -> dict:
    require(pr_number > 0, "positive PR number required")
    pr = gh_json(f"pulls/{pr_number}")
    head = pr.get("head", {}).get("sha", "")
    require(re.fullmatch(r"[0-9a-f]{40}", head) is not None, "invalid remote head")
    pages = loads(run(["gh", "api", "--paginate", "--slurp",
                      f"repos/{REPO}/actions/runs?event=pull_request&head_sha={head}&per_page=100"]))
    return check_pr(commit, pr, pages)


def remote_gate(commit: str, pr_number: int) -> dict:
    result = remote_pr_checks(commit, pr_number)
    require(gh_json(f"git/ref/tags/{TAG}", absent=True) is None, "tag already exists; do not retarget")
    require(gh_json(f"releases/tags/{TAG}", absent=True) is None, "release already exists; do not overwrite")
    return result


def publish(commit: str, pr_number: int, directory: Path) -> None:
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_SHA") == commit, "publish only from exact main workflow commit")
    check_source(ROOT)
    verify_assets(directory, commit)
    remote_gate(commit, pr_number)
    gh_json("git/refs", method="POST", payload={"ref": "refs/tags/" + TAG, "sha": commit})
    tag = gh_json("git/ref/tags/" + TAG)
    require(tag["object"].get("sha") == commit and tag["object"].get("type") == "commit", "tag target mismatch")
    release = gh_json("releases", method="POST", payload={"tag_name": TAG, "target_commitish": commit,
                      "name": "CBM Sec 0.15.0 Preview 1 — 受限代码取证工具", "draft": True,
                      "prerelease": True, "make_latest": "false",
                      "body": (directory / "RELEASE_NOTES.md").read_text(encoding="utf-8")})
    release_id = release["id"]
    print(json.dumps({"tag": TAG, "draft_release_id": release_id, "published": False}), flush=True)
    run(["gh", "release", "upload", TAG, *[str(directory / n) for n in (*ASSETS, "SHA256SUMS")],
         "--repo", REPO], timeout=900)
    expected_manifest = (directory / "SHA256SUMS").read_bytes()

    def verify_download() -> None:
        # Each readback uses a new directory; public bytes cannot reuse draft files.
        with tempfile.TemporaryDirectory(prefix="cbm-sec-release-readback-") as temporary:
            downloaded = Path(temporary)
            run(["gh", "release", "download", TAG, "--repo", REPO, "--dir", str(downloaded)], timeout=900)
            require(expected_manifest == (downloaded / "SHA256SUMS").read_bytes(),
                    "downloaded checksum manifest mismatch")
            verify_assets(downloaded, commit)

    verify_download()
    observed = gh_json(f"releases/{release_id}")
    require(observed.get("draft") is True and observed.get("prerelease") is True
            and observed.get("tag_name") == TAG, "draft state changed")
    assets = observed.get("assets", [])
    require(len(assets) == len(ASSETS) + 1 and {a["name"] for a in assets} == set(ASSETS) | {"SHA256SUMS"},
            "remote asset set mismatch")
    remote_pr_checks(commit, pr_number)
    require(gh_json("git/ref/tags/" + TAG)["object"]["sha"] == commit, "tag changed before publication")
    gh_json(f"releases/{release_id}", method="PATCH",
            payload={"draft": False, "prerelease": True, "make_latest": "false"})
    # Publication is not completion until the public attachment bytes are verified.
    # A failure here leaves the remote release intact for inspection, not rollback.
    verify_download()
    final = gh_json(f"releases/{release_id}")
    require(final.get("draft") is False and final.get("prerelease") is True and final.get("tag_name") == TAG,
            "published state not confirmed")
    final_assets = final.get("assets", [])
    require(len(final_assets) == len(ASSETS) + 1
            and {a["name"] for a in final_assets} == set(ASSETS) | {"SHA256SUMS"},
            "published asset set mismatch")
    require(gh_json("git/ref/tags/" + TAG)["object"]["sha"] == commit, "published tag target mismatch")
    print(json.dumps({"published": True, "release_id": release_id, "tag": TAG,
                      "commit": commit, "assets": len(final_assets), "url": final["html_url"]}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    receipt = sub.add_parser("candidate-receipt")
    receipt.add_argument("--source", type=Path, required=True)
    receipt.add_argument("--validation", type=Path, required=True)
    receipt.add_argument("--output", type=Path, required=True)
    check = sub.add_parser("check-source")
    check.add_argument("--root", type=Path, default=ROOT)
    for command in ("preflight", "package", "verify-assets", "publish"):
        child = sub.add_parser(command)
        child.add_argument("--commit", required=True)
        if command in ("preflight", "publish"):
            child.add_argument("--pr", type=int, required=True)
        if command in ("package", "verify-assets", "publish"):
            child.add_argument("--directory", type=Path, required=True)
        if command == "package":
            child.add_argument("--logs", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "candidate-receipt":
            candidate_receipt(args.source, args.validation, args.output)
        elif args.command == "check-source":
            check_source(args.root)
        elif args.command == "preflight":
            check_source(ROOT)
            require(run(["git", "rev-parse", "HEAD"]).strip() == args.commit, "checkout commit mismatch")
            print(json.dumps(remote_gate(args.commit, args.pr)))
        elif args.command == "package":
            package(ROOT, args.commit, args.logs.resolve(), args.directory.resolve())
        elif args.command == "verify-assets":
            verify_assets(args.directory.resolve(), args.commit)
        elif args.command == "publish":
            publish(args.commit, args.pr, args.directory.resolve())
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"preview_release_blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
