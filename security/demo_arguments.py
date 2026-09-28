"""Replay ordinary Java argument queries on repository-owned source fixtures.

Only the trusted MCP binary runs. No model, network or Java execution occurs.
This is an independent integration example, not the recovered 0.15.0-dev demo.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from demo_flow import Client, require, sha
from demo_trace import audit_references

CASES = ("plain", "swapped", "overwritten", "known_and_unknown")
SOURCES = {
    "Service.java": """package sample;
class Service {
  Recorder recorder;
  External external;
  long load(long id, long tenant) { return recorder.store(id, tenant); }
}
""",
    "Facade.java": """package sample;
class Facade {
  Service service;
  long load(long id, long tenant) { return service.load(id, tenant); }
}
""",
    "Entry.java": """package sample;
class Entry {
  Facade facade;
  long handle(long id, long tenant) { return facade.load(id, tenant); }
}
""",
}


def fixture_sources(case: str) -> dict[str, str]:
    require(case in CASES, "unknown_fixture")
    sources = dict(SOURCES)
    if case == "swapped":
        sources["Facade.java"] = sources["Facade.java"].replace(
            "service.load(id, tenant)", "service.load(tenant, id)")
    elif case == "overwritten":
        sources["Service.java"] = sources["Service.java"].replace(
            "return recorder", "tenant = 0; return recorder")
    elif case == "known_and_unknown":
        sources["Service.java"] = sources["Service.java"].replace(
            "return recorder.store(id, tenant);",
            "long chosen = tenant; if (id < 0) { chosen = external.value(); } "
            "return recorder.store(id, chosen);")
    return sources


def run_case(binary: Path, case: str) -> dict:
    sources = fixture_sources(case)
    raw = json.dumps({"schema": "cbm.security-snapshot.v1", "files": [
        {"path": path, "source": source, "sha256": sha(source.encode("utf-8"))}
        for path, source in sorted(sources.items())]}, ensure_ascii=False).encode("utf-8")
    snapshot_id = sha(raw)
    with tempfile.TemporaryDirectory(prefix="cbm-arguments-") as tmp, tempfile.TemporaryFile() as errors:
        snapshot = Path(tmp) / "snapshot.json"
        snapshot.write_bytes(raw)
        snapshot.chmod(0o600)
        process = subprocess.Popen([str(binary), "--snapshot", str(snapshot), "--expect-snapshot", snapshot_id],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        try:
            client = Client(process)
            client.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                      "clientInfo": {"name": "ordinary-argument-demo", "version": "1"}})
            client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            page = client.tool("query_security_facts", {"snapshot_id": snapshot_id,
                "path": "Service.java", "kind": "call_site", "limit": 200})
            calls = [f for f in page["facts"] if f.get("name", {}).get("text_prefix") == "store"]
            require(len(calls) == 1, "fixture_call_not_unique")
            request = {"snapshot_id": snapshot_id, "path": "Service.java", "analysis_id": page["analysis_id"],
                       "call_id": calls[0]["id"], "argument_index": 1, "scope_paths": sorted(sources)}
            result = client.tool("trace_argument_origins", request)
            require(result["schema"] == "cbm.argument-origins.v1", "wrong_result_schema")
            require(result["security_verdict"] == "not_evaluated", "query_promoted_to_verdict")
            require(result["absence_semantics"] == "no_negative_security_conclusion", "unsafe_absence_semantics")
            if case == "overwritten":
                require(result["paths"] == [], "constant_overwrite_kept_prior_origin")
                require("no_known_formal_dependencies_remain" in [f["reason"] for f in result["frontiers"]],
                        "constant_frontier_missing")
            else:
                require(len(result["paths"]) == 1, "unexpected_origin_count")
                path = result["paths"][0]
                require(path["candidate_hops"] == 2, "caller_hops_not_recovered")
                source = path["source"]
                expected = "id" if case == "swapped" else "tenant"
                require(source["parameter"]["name"]["text_prefix"] == expected, "wrong_formal_origin")
                require(source["kind"] == "formal_parameter_boundary" and source["trust"] == "not_classified",
                        "formal_boundary_misclassified")
                require(path["runtime_dispatch"] == "not_verified", "runtime_dispatch_not_proven")
            if case == "known_and_unknown":
                require("argument_origin_has_unknown_parts" in result["gaps"], "unknown_branch_lost")
                require("call_return_not_modeled" in result["selected_argument"]["local_value_flow"]["unknown_reasons"],
                        "unknown_return_lost")
            references = audit_references(result, sources)
            require(references > 0, "no_source_references")
            info = client.tool("get_snapshot_info", {})
            process.stdin.close()
            process.wait(timeout=15)
            errors.seek(0)
            require(process.returncode == 0, "analyzer_failed: " + errors.read(8192).decode("utf-8", "replace"))
            return {"case": case, "test_fixture": True, "expectations_passed": True,
                    "analyzer_version": info["analyzer_version"], "build_id": info["build_id"],
                    "request": request, "source_references_checked": references, "result": result}
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if not process.stdin.closed:
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
            process.stdout.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp", required=True, type=Path, help="Trusted cbm-security-mcp executable")
    args = parser.parse_args()
    try:
        require(os.name == "posix", "demo_requires_posix_pipes")
        binary = args.mcp.resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), "mcp_not_executable")
        cases = [run_case(binary, case) for case in CASES]
        print(json.dumps({"schema": "cbm.argument-demo.v1", "uses_test_fixtures": True,
                          "target_execution": False, "model_calls": 0, "cases": cases},
                         ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"demo_failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
