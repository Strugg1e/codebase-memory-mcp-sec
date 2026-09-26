"""Run a labelled Java/MyBatis fixture through the real, read-only MCP binary.

This executes the analyzer, never the Java fixture. No model or network is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time

SOURCES = {
    "Controller.java": '''package app;
import org.springframework.web.bind.annotation.RequestParam;
class Controller {
  OrderFacade facade;
  Object find(@RequestParam long id, @RequestParam long tenant) {
    return facade.load(id, tenant);
  }
}''',
    "Facade.java": '''package app;
class OrderFacade {
  OrderService service;
  Object load(long id, long tenant) { return service.load(id, tenant); }
}''',
    "Service.java": '''package app;
import data.OrderMapper;
class OrderService {
  OrderMapper mapper;
  Object load(long id, long tenant) { return mapper.load(id, tenant); }
}''',
    "OrderMapper.java": '''package data;
import org.apache.ibatis.annotations.Param;
public interface OrderMapper {
  Object load(@Param("id") long id, @Param("tenant") long tenant);
}''',
    "OrderMapper.xml": '''<mapper namespace="data.OrderMapper">
<select id="load" resultType="map">
SELECT * FROM orders WHERE id = #{id} AND tenant_id = #{tenant}
</select>
</mapper>''',
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Client:
    def __init__(self, process: subprocess.Popen):
        self.process = process
        self.next_id = 0
        self.buffer = b""
        self.response_bytes = 0

    def send(self, message: dict) -> None:
        data = json.dumps(message, ensure_ascii=False).encode() + b"\n"
        require(len(data) <= 32768, "Demo request exceeds MCP input bound")
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def rpc(self, method: str, params: dict) -> dict:
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        deadline = time.monotonic() + 30
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "MCP response timed out")
            ready, _, _ = select.select([self.process.stdout], [], [], remaining)
            require(bool(ready), "MCP response timed out")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            require(bool(chunk), "MCP exited without a complete response")
            self.buffer += chunk
            require(len(self.buffer) <= 16 * 1024 * 1024, "MCP demo response exceeds limit")
        line, self.buffer = self.buffer.split(b"\n", 1)
        self.response_bytes += len(line) + 1
        response = json.loads(line)
        require(response.get("id") == self.next_id, "MCP response id mismatch")
        require("error" not in response, "MCP protocol error: " + str(response.get("error")))
        return response["result"]

    def tool(self, name: str, arguments: dict) -> dict:
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        require(result.get("isError") is False, "MCP tool error: " + str(result))
        data = result["structuredContent"]
        require(json.loads(result["content"][0]["text"]) == data, "MCP result encodings differ")
        return data


def run_case(binary: Path, overwrite: bool) -> dict:
    sources = dict(SOURCES)
    if overwrite:
        sources["Service.java"] = sources["Service.java"].replace("return mapper", "tenant = 0; return mapper")
    payload = {"schema": "cbm.security-snapshot.v1", "files": [
        {"path": path, "source": source, "sha256": sha(source.encode())}
        for path, source in sorted(sources.items())
    ]}
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    snapshot_id = sha(raw)
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="cbm-sec-demo-") as directory:
        bundle = Path(directory) / "snapshot.json"
        bundle.write_bytes(raw)
        bundle.chmod(0o600)
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen([str(binary), "--snapshot", str(bundle), "--expect-snapshot", snapshot_id],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
            try:
                client = Client(process)
                client.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                          "clientInfo": {"name": "cbm-sec-release-demo", "version": "1"}})
                client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
                tools = client.rpc("tools/list", {})["tools"]
                require({t["name"] for t in tools} == {"get_snapshot_info", "list_snapshot_files", "query_security_facts", "get_security_evidence", "read_snapshot_source", "inspect_operation_context", "resolve_code_location", "query_entry_points", "inspect_entry_security", "trace_source_to_sink", "query_resource_operations", "trace_argument_origins"}, "Unexpected tool set")
                require(len(tools) == 12, "Unexpected tool count or duplicate tool name")
                common = {"snapshot_id": snapshot_id}
                listing = client.tool("list_snapshot_files", common)
                require(listing["total"] == len(sources), "Fixture scope mismatch")
                anchors = []
                for path in ("Service.java", "Facade.java", "Controller.java"):
                    page = client.tool("query_security_facts", {**common, "path": path, "kind": "call_site", "limit": 200})
                    calls = [f for f in page["facts"] if f.get("name", {}).get("text_prefix") == "load"]
                    require(len(calls) == 1, "Expected one explicit load call per fixture file")
                    anchors.append({"path": path, "analysis_id": page["analysis_id"], "call_id": calls[0]["id"]})
                evidence = client.tool("get_security_evidence", {**common, "path": anchors[0]["path"],
                    "analysis_id": anchors[0]["analysis_id"], "fact_id": anchors[0]["call_id"]})
                require(len(evidence["facts"]) == 1, "Single fact lookup failed")
                result = client.tool("inspect_operation_context", {**common, **anchors[0],
                    "mapper_path": "OrderMapper.java", "mapping_path": "OrderMapper.xml", "upstream_calls": anchors[1:]})
                ref = result["call"]
                source = client.tool("read_snapshot_source", {**common, "path": ref["path"], "sha256": ref["sha256"],
                    "start_byte": ref["start_byte"], "end_byte": ref["end_byte"]})
                require(source["text"] == "mapper.load(id, tenant)", "Pinned source lookup mismatch")
                flow = result["argument_flow"]
                require(flow["linked_candidate_hops"] == 2, "Two declared call candidates did not link")
                path = flow["paths"][1]
                if overwrite:
                    require(path["stop_reason"] == "parameter_written_or_shadowed" and path["candidate_hops_followed"] == 0,
                            "Overwritten parameter was incorrectly forwarded")
                else:
                    require(path["origin"] == "request_parameter_declaration_candidate" and path["candidate_hops_followed"] == 2,
                            "Direct request-parameter candidate was not recovered")
                require(result["mybatis"]["status"] == "explicit_mapping_candidate", "Mapper/XML candidate did not link")
                require(result["authorization_verdict"] == "not_evaluated", "Demo must not infer an authorization verdict")
                info = client.tool("get_snapshot_info", {})
                process.stdin.close()
                process.wait(timeout=15)
                errors.seek(0)
                require(process.returncode == 0, "Analyzer failed: " + errors.read(8192).decode("utf8", "replace"))
                return {"fixture": True, "case": "overwritten_parameter" if overwrite else "direct_parameter_forwarding",
                        "expectations_passed": True, "snapshot_id": snapshot_id, "context_id": result["context_id"],
                        "linked_candidate_hops": flow["linked_candidate_hops"], "tenant_parameter": path,
                        "authorization_verdict": result["authorization_verdict"], "analyzer_version": info["analyzer_version"],
                        "build_id": info["build_id"], "operation_counters": info["operation_context"],
                        "elapsed_seconds": round(time.perf_counter() - started, 6), "response_bytes": client.response_bytes}
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
    parser.add_argument("--mcp", required=True, type=Path, help="Path to the trusted cbm-security-mcp executable")
    args = parser.parse_args()
    try:
        require(os.name == "posix", "This demo client requires POSIX pipes")
        binary = args.mcp.resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), "MCP path is not executable")
        results = [run_case(binary, overwrite=False), run_case(binary, overwrite=True)]
        print(json.dumps({"schema": "cbm.security-demo.v1", "uses_test_fixtures": True,
                          "model_calls": 0, "target_execution": False, "cases": results}, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"demo_failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
