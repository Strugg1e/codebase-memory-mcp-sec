"""Replay bounded automatic input paths on labelled Java/MyBatis test source.

Only the trusted analyzer executes. No Java application, model or network runs.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from demo_flow import Client, SOURCES, require, sha


def audit_references(value: object, sources: dict[str, str]) -> int:
    """Check every source span in the actual response, including nested evidence."""
    count = 0
    if isinstance(value, dict):
        if {"path", "sha256", "start_byte", "end_byte"} <= value.keys():
            raw = sources[value["path"]].encode()
            a, b = value["start_byte"], value["end_byte"]
            require(0 <= a <= b <= len(raw), "Source range outside fixture")
            require(sha(raw) == value["sha256"], "Source hash mismatch")
            text = raw[a:b].decode()
            prefix = value.get("text_prefix", text)
            require(text.startswith(prefix), "Source preview mismatch")
            if not value.get("text_truncated", False):
                require(text == prefix, "Unexpected partial source preview")
            count += 1
        for child in value.values():
            count += audit_references(child, sources)
    elif isinstance(value, list):
        for child in value:
            count += audit_references(child, sources)
    return count


def run_case(binary: Path, case: str) -> dict:
    sources = dict(SOURCES)
    sources["Controller.java"] = sources["Controller.java"].replace(
        "class Controller", 'import org.springframework.web.bind.annotation.GetMapping;\nclass Controller').replace(
        "Object find(", '@GetMapping("/orders") Object find(')
    sources["OrderMapper.xml"] = sources["OrderMapper.xml"].replace("#{tenant}", "${tenant}")
    if case == "overwritten":
        sources["Service.java"] = sources["Service.java"].replace("return mapper", "tenant=0; return mapper")
    elif case == "known_and_unknown":
        sources["Service.java"] = sources["Service.java"].replace("return mapper.load(id, tenant);",
            "long x=tenant; if(id>0){x=other();} return mapper.load(id,x);")
    elif case != "automatic_two_hops":
        raise ValueError("Unknown demo case")
    payload = {"schema": "cbm.security-snapshot.v1", "files": [
        {"path": path, "source": source, "sha256": sha(source.encode())}
        for path, source in sorted(sources.items())]}
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    snapshot_id = sha(raw)
    with tempfile.TemporaryDirectory(prefix="cbm-sec-trace-") as directory, tempfile.TemporaryFile() as errors:
        bundle = Path(directory) / "snapshot.json"
        bundle.write_bytes(raw)
        bundle.chmod(0o600)
        process = subprocess.Popen([str(binary), "--snapshot", str(bundle), "--expect-snapshot", snapshot_id],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        try:
            client = Client(process)
            client.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "cbm-sec-auto-trace-demo", "version": "1"}})
            client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            tools = client.rpc("tools/list", {})["tools"]
            require("trace_source_to_sink" in {t["name"] for t in tools}, "Automatic tracing unavailable")
            page = client.tool("query_security_facts", {"snapshot_id": snapshot_id, "path": "Service.java",
                                "kind": "call_site", "limit": 200})
            calls = [f for f in page["facts"] if f.get("name", {}).get("text_prefix") == "load"]
            require(len(calls) == 1, "Expected exactly one selected sink call")
            request = {"snapshot_id": snapshot_id, "path": "Service.java", "analysis_id": page["analysis_id"],
                       "call_id": calls[0]["id"], "mapper_path": "OrderMapper.java", "mapping_path": "OrderMapper.xml",
                       "scope_paths": ["Controller.java", "Facade.java", "Service.java"]}
            result = client.tool("trace_source_to_sink", request)
            require(result["security_verdict"] == "not_evaluated", "A path is not a security verdict")
            if case == "overwritten":
                require(not result["paths"], "Overwrite must not forward the prior source")
                require(any(f["reason"] == "no_known_formal_dependencies_remain" for f in result["frontiers"]),
                        "Missing explicit overwrite frontier")
            else:
                require(len(result["paths"]) == 1, "Expected one source candidate")
                path = result["paths"][0]
                require(path["candidate_hops"] == 2, "Expected two discovered caller hops")
                require(path["source"]["parameter"]["name"] == "tenant", "Wrong source argument")
                if case == "known_and_unknown":
                    require(path["status"] == "candidate_with_unknowns" and path["unknown_reasons"], "Lost unknown branch")
            references = audit_references(result, sources)
            require(references > 0, "No evidence references were checked")
            info = client.tool("get_snapshot_info", {})
            process.stdin.close()
            process.wait(timeout=15)
            errors.seek(0)
            require(process.returncode == 0, "Analyzer failed: " + errors.read(8192).decode("utf8", "replace"))
            return {"case": case, "test_fixture": True, "expectations_passed": True,
                    "analyzer_version": info["analyzer_version"], "build_id": info["build_id"],
                    "request": request, "supplied_upstream_paths": False,
                    "source_references_checked": references, "result": result}
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
        require(os.name == "posix", "Demo client requires POSIX pipes")
        binary = args.mcp.resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), "MCP binary is not executable")
        cases = [run_case(binary, case) for case in ("automatic_two_hops", "overwritten", "known_and_unknown")]
        print(json.dumps({"schema": "cbm.auto-trace-demo.v1", "uses_test_fixtures": True,
                          "target_execution": False, "model_calls": 0, "cases": cases}, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"demo_failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
