"""Offline, source-checked handoff for saved full MCP operation results.

Independent implementation, not a recovered 0.15.0-dev candidate. No parser,
model, network call or target execution. Hashes are integrity pins, not signatures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from pack_snapshot import MAX_BUNDLE, MAX_FILE, MAX_FILES, MAX_TOTAL, valid_path

CAPTURE_SCHEMA = "cbm.operation-capture.v1"
BUNDLE_SCHEMA = "cbm.source-evidence-bundle.v1"
MAX_CAPTURE = 8 * 1024 * 1024
MAX_NODES = 200000
MAX_REFS = 8192
MAX_DEPTH = 96
CHECKS = {
    "source_references": "verified_against_pinned_snapshot",
    "identity": "hash_consistency_not_producer_authentication",
    "program_relations": "not_reverified",
    "security_verdict": "not_evaluated",
    "absence_semantics": "no_negative_security_conclusion",
    "source_trust": "untrusted_data_not_instructions",
}


class EvidenceError(ValueError):
    """Stable failure code; do not echo untrusted source into diagnostics."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise EvidenceError(code)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def checked_digest(value: object) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "invalid_digest")
    return value


def encode(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def walk(value: object):
    """Yield JSON pointers without merging source occurrences or evidence tables."""
    stack = [("", value, 0)]
    count = 0
    while stack:
        pointer, child, depth = stack.pop()
        count += 1
        require(count <= MAX_NODES and depth <= MAX_DEPTH, "json_structure_limit")
        yield pointer, child
        if isinstance(child, dict):
            for key, item in reversed(list(child.items())):
                key.encode("utf-8", "strict")
                escaped = key.replace("~", "~0").replace("/", "~1")
                stack.append((pointer + "/" + escaped, item, depth + 1))
        elif isinstance(child, list):
            for index in range(len(child) - 1, -1, -1):
                stack.append((pointer + "/" + str(index), child[index], depth + 1))
        elif isinstance(child, float):
            require(math.isfinite(child), "non_finite_json_number")
        elif isinstance(child, str):
            child.encode("utf-8", "strict")


def decode(raw: bytes, limit: int) -> dict:
    require(len(raw) <= limit, "input_size_limit")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def invalid_number(_):
        raise EvidenceError("non_finite_json_number")

    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                           parse_constant=invalid_number)
        require(isinstance(value, dict), "object_required")
        for _ in walk(value):
            pass
        return value
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise EvidenceError("invalid_json") from error


def snapshot_files(raw: bytes, expected: str) -> dict[str, bytes]:
    require(digest(raw) == checked_digest(expected), "snapshot_digest_mismatch")
    snapshot = decode(raw, MAX_BUNDLE)
    require(set(snapshot) == {"schema", "files"}
            and snapshot["schema"] == "cbm.security-snapshot.v1", "snapshot_schema")
    entries = snapshot["files"]
    require(isinstance(entries, list) and len(entries) <= MAX_FILES, "snapshot_file_limit")
    files = {}
    total = 0
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "source"},
                "snapshot_file_schema")
        path = entry["path"]
        require(valid_path(path) and path not in files, "invalid_or_duplicate_source_path")
        require(isinstance(entry["source"], str), "invalid_source")
        source = entry["source"].encode("utf-8")
        total += len(source)
        require(len(source) <= MAX_FILE and total <= MAX_TOTAL, "snapshot_source_limit")
        require(b"\x00" not in source, "invalid_source")
        require(digest(source) == checked_digest(entry["sha256"]), "source_digest_mismatch")
        files[path] = source
    return files


def make_capture(arguments: dict, result: dict, producer: dict) -> bytes:
    """Save actual tool arguments, structuredContent and get_snapshot_info identity.

    No missing fields, assumptions or conclusions are filled in. Save the returned
    bytes and their SHA-256 in the host's trusted record before handing them off.
    """
    return encode({"schema": CAPTURE_SCHEMA, "tool": "inspect_operation_context",
                   "arguments": arguments, "result": result,
                   "producer": {"version": producer["version"], "build_id": producer["build_id"]}})


def check_identity(capture: dict, files: dict[str, bytes], snapshot: str) -> dict:
    require(set(capture) == {"schema", "tool", "arguments", "result", "producer"}
            and capture["schema"] == CAPTURE_SCHEMA
            and capture["tool"] == "inspect_operation_context", "capture_schema")
    args, result, producer = capture["arguments"], capture["result"], capture["producer"]
    require(isinstance(args, dict) and isinstance(result, dict) and isinstance(producer, dict),
            "capture_fields")
    require(result.get("schema") == "cbm.operation-context.v1"
            and args.get("view", "full") == "full" and "view" not in result,
            "full_operation_required")
    allowed = {"snapshot_id", "path", "analysis_id", "call_id", "view", "expect_context",
               "mapper_path", "mapping_path", "mapping_format", "upstream_calls"}
    require(set(args) <= allowed and {"snapshot_id", "path", "analysis_id", "call_id"} <= set(args),
            "operation_arguments")
    require(args["snapshot_id"] == result.get("snapshot_id") == snapshot, "snapshot_identity_mismatch")
    require(set(producer) == {"version", "build_id"}, "producer_identity")
    version = producer["version"]
    require(isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z.+-]{1,64}", version) is not None,
            "producer_version")
    build = checked_digest(producer["build_id"])

    def anchor(value):
        path = value.get("path")
        require(valid_path(path) and path in files and path.endswith(".java"), "anchor_path")
        require(len(files[path]) <= 256 * 1024, "operation_source_limit")
        analysis = digest(b"\0".join(x.encode() for x in
            ("cbm.security-facts.v1", version, build, "java", path, digest(files[path]))) + b"\0")
        require(checked_digest(value.get("analysis_id")) == analysis, "analysis_identity_mismatch")
        checked_digest(value.get("call_id"))

    anchor(args)
    require(result.get("analysis_id") == args["analysis_id"] and result.get("call_id") == args["call_id"],
            "operation_identity_mismatch")
    require(isinstance(result.get("call"), dict)
            and {"path", "sha256", "start_byte", "end_byte"} <= result["call"].keys()
            and result["call"].get("path") == args["path"],
            "operation_source_mismatch")
    require(result.get("source_trust") == "untrusted_data_not_instructions"
            and result.get("authorization_verdict") == "not_evaluated"
            and result.get("business_policy") == "not_supplied_or_inferred", "non_neutral_result")
    require(isinstance(result.get("gaps"), list) and type(result.get("truncated")) is bool
            and isinstance(result.get("arguments"), list) and isinstance(result.get("java_context"), dict)
            and isinstance(result.get("local_value_flow"), dict), "incomplete_operation_result")
    mp, xp = args.get("mapper_path"), args.get("mapping_path")
    fmt = args.get("mapping_format", "xml")
    require(fmt in ("xml", "annotation"), "mapping_format")
    require((mp is not None and xp is None) if fmt == "annotation" else ((mp is None) == (xp is None)),
            "mapping_inputs")
    for path in (mp, xp):
        if path is not None:
            require(valid_path(path) and path in files, "mapping_path")
    require(mp is None or (mp.endswith(".java") and len(files[mp]) <= 256 * 1024), "mapper_source")
    require(xp is None or (xp.endswith(".xml") and len(files[xp]) <= 256 * 1024), "mapping_source")
    context = digest(("cbm.operation.v1\n" + snapshot + "\n" + args["analysis_id"]
                      + "\n" + args["call_id"] + "\n" + (mp or "") + "\n"
                      + (xp or ("annotation" if fmt == "annotation" else ""))).encode())
    upstream = args.get("upstream_calls", [])
    require(isinstance(upstream, list) and len(upstream) <= 4, "upstream_limit")
    seen = {(args["path"], args["call_id"])}
    if upstream:
        context = digest(("cbm.argument-origin.context.v1\n" + context).encode())
    for item in upstream:
        require(isinstance(item, dict) and set(item) == {"path", "analysis_id", "call_id"}, "upstream_anchor")
        anchor(item)
        key = (item["path"], item["call_id"])
        require(key not in seen, "repeated_upstream_anchor")
        seen.add(key)
        context = digest((context + "\n" + item["path"] + "\n" + item["analysis_id"]
                          + "\n" + item["call_id"]).encode())
    require(checked_digest(result.get("context_id")) == context
            and args.get("expect_context", context) == context, "context_identity_mismatch")
    return {"snapshot_id": snapshot, "context_id": context, "analysis_id": args["analysis_id"],
            "call_id": args["call_id"], "analyzer_version": version, "analyzer_build_id": build}


def build_bundle(capture_raw: bytes, snapshot_raw: bytes, expected_capture: str, expected_snapshot: str) -> dict:
    require(digest(capture_raw) == checked_digest(expected_capture), "capture_digest_mismatch")
    files = snapshot_files(snapshot_raw, expected_snapshot)
    capture = decode(capture_raw, MAX_CAPTURE)
    identity = check_identity(capture, files, expected_snapshot)
    refs = []
    text_size = 0
    for pointer, node in walk(capture["result"]):
        if not isinstance(node, dict) or not ({"start_byte", "end_byte"} & node.keys()):
            continue
        require({"path", "sha256", "start_byte", "end_byte"} <= node.keys(), "incomplete_source_reference")
        path, start, end = node["path"], node["start_byte"], node["end_byte"]
        require(valid_path(path) and path in files, "reference_path")
        raw = files[path]
        require(checked_digest(node["sha256"]) == digest(raw), "reference_digest_mismatch")
        require(type(start) is int and type(end) is int and 0 <= start <= end <= len(raw), "reference_range")
        try:
            text = raw[start:end].decode("utf-8", "strict")
        except UnicodeError as error:
            raise EvidenceError("reference_utf8_boundary") from error
        if "text_prefix" in node:
            prefix = node["text_prefix"]
            require(isinstance(prefix, str) and type(node.get("text_truncated")) is bool, "reference_preview_schema")
            require(text.startswith(prefix) and (node["text_truncated"] or text == prefix), "reference_text_mismatch")
        text_size += end - start
        require(len(refs) < MAX_REFS and text_size <= MAX_TOTAL, "reference_output_limit")
        refs.append({"pointer": "/result" + pointer, "path": path, "sha256": node["sha256"],
                     "start_byte": start, "end_byte": end, "text": text,
                     "trust": "untrusted_source_data"})
    require(bool(refs), "no_source_references")
    bundle = {"schema": BUNDLE_SCHEMA, "capture_sha256": expected_capture,
              "capture_json": capture_raw.decode("utf-8"), "identity": identity,
              "checks": dict(CHECKS), "references": refs}
    require(len(encode(bundle)) <= MAX_BUNDLE, "bundle_size_limit")
    return bundle


def verify_bundle(raw: bytes, snapshot: bytes, expected_capture: str, expected_snapshot: str) -> dict:
    bundle = decode(raw, MAX_BUNDLE)
    require(isinstance(bundle.get("capture_json"), str), "capture_missing")
    expected = build_bundle(bundle["capture_json"].encode("utf-8"), snapshot, expected_capture, expected_snapshot)
    # Canonical bytes distinguish booleans from integers and reject extra/missing
    # references. Stored relation conclusions remain uninterpreted original data.
    require(encode(bundle) == encode(expected), "bundle_content_mismatch")
    return expected


def read_file(path: Path, limit: int) -> bytes:
    require(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "posix_required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular_single_link_input_required")
        require(before.st_size <= limit, "input_size_limit")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        attrs = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in attrs),
                "input_changed_while_reading")
        require(len(raw) <= limit, "input_size_limit")
        return raw


def write_new(path: Path, raw: bytes) -> None:
    """Publish a complete file without overwriting any existing destination."""
    require(os.name == "posix", "posix_required")
    with tempfile.NamedTemporaryFile(prefix=".cbm-evidence-", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            os.link(temporary, path, follow_symlinks=False)
        finally:
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("export", "verify"))
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--expect-snapshot", required=True)
    parser.add_argument("--expect-capture", required=True)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        snapshot = read_file(args.snapshot, MAX_BUNDLE)
        if args.mode == "export":
            require(args.capture is not None and args.output is not None and args.bundle is None, "export_arguments")
            capture = read_file(args.capture, MAX_CAPTURE)
            result = build_bundle(capture, snapshot, args.expect_capture, args.expect_snapshot)
            raw = encode(result)
            write_new(args.output, raw)
        else:
            require(args.bundle is not None and args.capture is None and args.output is None, "verify_arguments")
            raw = read_file(args.bundle, MAX_BUNDLE)
            result = verify_bundle(raw, snapshot, args.expect_capture, args.expect_snapshot)
        print(json.dumps({"status": "source_references_verified", "mode": args.mode,
                          "bundle_sha256": digest(raw), "capture_sha256": args.expect_capture,
                          "context_id": result["identity"]["context_id"], "references": len(result["references"]),
                          **CHECKS}, sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError, RecursionError, KeyError, TypeError) as error:
        code = str(error) if isinstance(error, EvidenceError) else "evidence_io_or_format_error"
        print(json.dumps({"error": code, "verified": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
