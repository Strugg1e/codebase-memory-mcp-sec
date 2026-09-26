"""Controlled MCP -> saved full result -> independent offline verifier example.

No model, business repository, network request or Java execution. This is not a
vulnerability benchmark, a recovered candidate demo, or a runtime proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from demo_context import SOURCE
from demo_flow import Client, require
from export_evidence import digest, encode, make_capture, write_new


def demo(binary: Path, directory: Path) -> dict:
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    snapshot = encode({"schema": "cbm.security-snapshot.v1", "files": [
        {"path": "Example.java", "source": SOURCE, "sha256": digest(SOURCE.encode())}]})
    snapshot_id = digest(snapshot)
    write_new(directory / "snapshot.json", snapshot)
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen([str(binary), "--snapshot", str(directory / "snapshot.json"),
                                    "--expect-snapshot", snapshot_id],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        try:
            client = Client(process)
            client.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                      "clientInfo": {"name": "controlled-evidence-demo", "version": "1"}})
            client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            info = client.tool("get_snapshot_info", {})
            line = SOURCE[:SOURCE.index("store(scope)")].count("\n") + 1
            location = client.tool("resolve_code_location", {"snapshot_id": snapshot_id,
                "path": "Example.java", "sha256": digest(SOURCE.encode()), "start_line": line, "end_line": line})
            require(location["status"] == "unique_candidate", "fixture_call_not_unique")
            request = {"snapshot_id": snapshot_id, **location["candidates"][0]["operation_anchor"], "view": "full"}
            result = client.tool("inspect_operation_context", request)
            relation = result["arguments"][0]["local_value_flow"]
            require(relation["derived_parameter_indices"] == [0], "known_source_lost")
            require("call_return_not_modeled" in relation["unknown_reasons"], "unknown_source_lost")
            capture = make_capture(request, result, info["product_capabilities"])
            write_new(directory / "capture.json", capture)
            process.stdin.close()
            process.wait(timeout=15)
            require(process.returncode == 0, "fixture_mcp_failed")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if not process.stdin.closed:
                process.stdin.close()
            process.stdout.close()
    # The analyzer has exited. Both next steps are new processes with no MCP use.
    script = Path(__file__).with_name("export_evidence.py")
    common = ["--snapshot", str(directory / "snapshot.json"), "--expect-snapshot", snapshot_id,
              "--expect-capture", digest(capture)]
    results = {}
    for mode, arguments in (
        ("export", ["--capture", str(directory / "capture.json"), "--output", str(directory / "evidence.json")]),
        ("verify", ["--bundle", str(directory / "evidence.json")]),
    ):
        completed = subprocess.run([sys.executable, str(script), mode, *common, *arguments],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
        results[mode] = json.loads(completed.stdout)
    stored = json.loads((directory / "evidence.json").read_bytes())
    require(stored["capture_json"].encode() == capture, "capture_bytes_changed")
    require(json.loads(stored["capture_json"])["result"] == result, "result_changed")
    require(results["export"]["bundle_sha256"] == results["verify"]["bundle_sha256"], "bundle_changed")
    receipt = {"schema": "cbm.evidence-demo.v1", "test_fixture": True, "model_calls": 0,
               "target_execution": False, "snapshot_sha256": snapshot_id, "capture_sha256": digest(capture),
               "analyzer_exited_before_verification": True, "capture_bytes_preserved": True,
               "known_and_unknown_preserved": True, "program_relations_reverified": False,
               "export": results["export"], "verify": results["verify"]}
    write_new(directory / "RECEIPT.json", encode(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        binary = args.mcp.resolve(strict=True)
        if args.output_dir is not None:
            result = demo(binary, args.output_dir.resolve())
        else:
            with tempfile.TemporaryDirectory(prefix="cbm-evidence-demo-") as root:
                result = demo(binary, Path(root) / "example")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError):
        print("controlled_evidence_demo_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
