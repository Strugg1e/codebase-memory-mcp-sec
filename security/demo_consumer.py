"""Deterministic host replay with real MCP results and labelled delivery faults.

This tests host rules, not an LLM's reading, reasoning, cost or security verdict.
Only the repository's controlled text is analyzed. No target execution occurs.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys
import tempfile

from consumer_example import ConsumerExample, resource_pages
from demo_flow import Client, SOURCES, require
from export_evidence import decode, digest, encode, make_capture, write_new


def fixture_sources() -> dict[str, str]:
    sources = dict(SOURCES)
    # A source check is deliberately placed outside a short consumer preview.
    # Its presence does not prove that it is an effective security control.
    sources["Service.java"] = "/* controlled preview padding " + "x" * 2304 + " */\n" + sources["Service.java"].replace(
        "return mapper.load(id, tenant);",
        "validateTenant(tenant); long chosen=tenant; "
        "if(id<0){chosen=externalValue();} return mapper.load(id, chosen);")
    return sources


@contextmanager
def fixture_session(binary: Path, directory: Path):
    sources = fixture_sources()
    snapshot = encode({"schema": "cbm.security-snapshot.v1", "files": [
        {"path": path, "source": source, "sha256": digest(source.encode("utf-8"))}
        for path, source in sorted(sources.items())]})
    snapshot_id = digest(snapshot)
    write_new(directory / "snapshot.json", snapshot)
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen([str(binary), "--snapshot", str(directory / "snapshot.json"),
                                    "--expect-snapshot", snapshot_id], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=errors)
        try:
            client = Client(process)
            client.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                     "clientInfo": {"name": "controlled-consumer-replay", "version": "1"}})
            client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            info = client.tool("get_snapshot_info", {})
            require(info["snapshot_id"] == snapshot_id, "bootstrap_snapshot_mismatch")
            write_new(directory / "bootstrap.json", encode(info))
            yield client, sources, snapshot_id, info
            process.stdin.close()
            process.wait(timeout=15)
            require(process.returncode == 0, "controlled_mcp_failed")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if not process.stdin.closed:
                process.stdin.close()
            process.stdout.close()


class TimeoutFixture:
    """Explicit transport fault injection; not an observed MCP timeout."""
    def rpc(self, method, params):
        raise TimeoutError("controlled timeout")


def replay(binary: Path, directory: Path) -> dict:
    directory.mkdir(mode=0o700, exist_ok=False)
    with fixture_session(binary, directory) as (client, sources, snapshot_id, info):
        consumer = ConsumerExample(directory / "calls", snapshot_id, info["build_id"], "controlled-audit")

        def full(tool, args):
            invocation = consumer.invoke(client, tool, args)
            record = consumer.record(invocation)
            require(record["execution"] == "succeeded", "controlled_call_failed")
            return invocation, consumer.read_full(invocation, record["response_sha256"])

        query = {"snapshot_id": snapshot_id, "application_id": "controlled-fixture",
                 "scope_paths": sorted(sources), "max_checks": 1}
        inventory = resource_pages(consumer, client, query)
        require(inventory["stop_reason"] == "enumeration_finished", "inventory_incomplete")
        require(not inventory["pages"][0]["operations"] and len(inventory["pages"]) > 1,
                "empty_page_fixture_not_exercised")
        operations = [op for page in inventory["pages"] for op in page["operations"]]
        require(len(operations) == 1, "fixture_operation_not_unique")
        inspection = operations[0]["inspection"]
        _, summary = full(inspection["tool"], inspection["arguments"])
        request = summary["full_request"]["arguments"]
        operation_invocation, operation = full("inspect_operation_context", request)
        require(operation["context_id"] == summary["context_id"], "operation_changed")
        capture = make_capture(request, operation, info["product_capabilities"])
        write_new(directory / "capture.json", capture)
        trace_request = {key: request[key] for key in ("snapshot_id", "path", "analysis_id", "call_id")}
        trace_request.update(argument_index=1, scope_paths=[p for p in sorted(sources) if p.endswith(".java")])
        trace_invocation, trace = full("trace_argument_origins", trace_request)
        require(trace["paths"] and "argument_origin_has_unknown_parts" in trace["gaps"], "unknown_branch_lost")
        depth_invocation, depth = full("trace_argument_origins", dict(trace_request, max_hops=0))
        require(depth["truncated"] and "trace_depth_limit" in depth["gaps"], "depth_gap_lost")

        source = sources["Service.java"].encode("utf-8")
        source_args = {"snapshot_id": snapshot_id, "path": "Service.java", "sha256": digest(source),
                       "start_byte": 0, "end_byte": len(source)}
        source_invocation = consumer.invoke(client, "read_snapshot_source", source_args)
        source_pin = consumer.record(source_invocation)["response_sha256"]
        preview = consumer.preview(source_invocation, source_pin, 256)
        require(preview["preview_truncated"] and "validateTenant" not in preview["text"], "preview_fixture_not_exercised")
        preview_decision = consumer.decision(source_invocation)
        require(preview_decision["host_status"] == "needs_full_read", "preview_accepted_as_full")
        complete_source = consumer.read_full(source_invocation, source_pin)
        require("validateTenant(tenant)" in complete_source["text"], "full_source_check_missing")

        error_invocation = consumer.invoke(client, "trace_argument_origins", dict(trace_request, argument_index=-1))
        require(consumer.record(error_invocation)["execution"] == "tool_error", "tool_error_not_preserved")

        # Real payload deliberately delivered to the host after a new attempt.
        # No parallel server execution or actual network delay is claimed.
        delayed = consumer.begin("trace_argument_origins", trace_request)
        delayed_payload = client.rpc("tools/call", {"name": "trace_argument_origins", "arguments": trace_request})
        consumer.new_attempt()
        consumer.receive(delayed, delayed_payload)
        stale_decision = consumer.decision(delayed)
        require(stale_decision["host_status"] == "rejected_stale_attempt", "stale_response_accepted")
        current, _ = full("trace_argument_origins", trace_request)
        require(current != delayed, "retry_reused_invocation_id")
        consumer.cancel()
        cancelled_decision = consumer.decision(current)
        require(cancelled_decision["host_status"] == "rejected_cancelled", "cancelled_result_accepted")
        records = consumer.records()
        wire_bytes = client.response_bytes

    # Real analysis has ended. Use the existing export format and verifier.
    script = Path(__file__).with_name("export_evidence.py")
    common = ["--snapshot", str(directory / "snapshot.json"), "--expect-snapshot", snapshot_id,
              "--expect-capture", digest(capture)]
    offline = {}
    for mode, extra in (("export", ["--capture", str(directory / "capture.json"), "--output", str(directory / "evidence.json")]),
                        ("verify", ["--bundle", str(directory / "evidence.json")])):
        run = subprocess.run([sys.executable, str(script), mode, *common, *extra], capture_output=True, timeout=30, check=True)
        offline[mode] = decode(run.stdout, 32768)
    # Metadata reports rejection; these calls did not execute against the server.
    timeout = ConsumerExample(directory / "timeout-fixture", snapshot_id, info["build_id"], "timeout-fixture")
    timeout_invocation = timeout.invoke(TimeoutFixture(), "trace_argument_origins", trace_request)
    require(timeout.record(timeout_invocation)["execution"] == "timed_out", "timeout_became_empty_result")
    report = {
        "schema": "cbm.consumer-replay-example.v1", "controlled_fixture": True,
        "model_calls": 0, "target_execution": False, "faults": {
            "delayed_delivery": "injected_host_order_on_real_payload", "timeout": "injected_transport_exception",
            "tool_error": "real_invalid_argument_request", "preview": "consumer_byte_limit_on_real_source"},
        "snapshot_id": snapshot_id, "build_id": info["build_id"], "records": records,
        "timeout_record": timeout.record(timeout_invocation), "preview": preview,
        "inventory": {"stop_reason": inventory["stop_reason"], "invocations": inventory["invocations"]},
        "trace_invocation": trace_invocation, "depth_invocation": depth_invocation,
        "operation_invocation": operation_invocation, "capture_sha256": digest(capture),
        "observed_host_decisions": {"preview": preview_decision, "late": stale_decision,
                                    "cancelled": cancelled_decision},
        "capture_eligible_after_cancellation": False,
        "source_check_found_after_full_read": True, "control_effectiveness": "not_evaluated",
        "offline": offline, "security_verdict": "not_evaluated",
        "measurements": {"wire_response_bytes_including_bootstrap": wire_bytes,
                         "saved_tool_payload_bytes": sum(r["response_bytes"] for r in records),
                         "unit": "UTF-8 bytes, not tokens", "model_input_measured": False},
        "receipt_boundary": "trusted_host_record_required; local files are not signatures",
    }
    write_new(directory / "RECEIPT.json", encode(report))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = replay(args.mcp.resolve(strict=True), args.output_dir)
        print(encode({"status": "controlled_replay_passed", "calls": len(report["records"]),
                      "security_verdict": "not_evaluated", "model_calls": 0}).decode(), end="")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError):
        print("controlled_consumer_replay_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
