"""Host decisions over real controlled MCP payloads, plus labelled fault mutations.

Recorded payload replay is deterministic test input, not a live agent evaluation.
No historical candidate tests, private source, network or target execution.
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
import consumer_example as host
import demo_consumer as demo
from export_evidence import decode, digest, encode


class PayloadReplay:
    """Replay explicit captured or mutated fixtures without executing a tool."""
    def __init__(self, payloads):
        self.payloads = iter(payloads)
        self.requests = []

    def rpc(self, method, params):
        self.requests.append(copy.deepcopy(params))
        return copy.deepcopy(next(self.payloads))


class ConsumerReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        session = flow.Session(unittest.TestCase(), demo.fixture_sources())
        try:
            cls.snapshot_id = session.snapshot
            cls.build_id = session.call("get_snapshot_info")["build_id"]
            cls.inventory_args = {"snapshot_id": session.snapshot, "application_id": "controlled-fixture",
                                  "scope_paths": sorted(session.sources), "max_checks": 1}
            cls.pages = []
            args = dict(cls.inventory_args)
            for _ in range(32):
                packet = session.rpc("tools/call", {"name": "query_resource_operations", "arguments": args})
                cls.pages.append(packet)
                cursor = packet["structuredContent"]["page"]["next_cursor"]
                if cursor is None:
                    break
                args = dict(cls.inventory_args, cursor=cursor)
            else:
                raise AssertionError("fixture pagination did not terminate")
            op = next(op for p in cls.pages for op in p["structuredContent"]["operations"])
            cls.operation_args = dict(op["inspection"]["arguments"], view="full")
            cls.operation = session.rpc("tools/call", {"name": "inspect_operation_context", "arguments": cls.operation_args})
            cls.trace_args = {k: cls.operation_args[k] for k in ("snapshot_id", "path", "analysis_id", "call_id")}
            cls.trace_args.update(argument_index=1, scope_paths=[p for p in session.sources if p.endswith(".java")])
            cls.trace = session.rpc("tools/call", {"name": "trace_argument_origins", "arguments": cls.trace_args})
            cls.depth = session.rpc("tools/call", {"name": "trace_argument_origins", "arguments": dict(cls.trace_args, max_hops=0)})
            cls.error = session.rpc("tools/call", {"name": "trace_argument_origins", "arguments": dict(cls.trace_args, argument_index=-1)})
            source = session.sources["Service.java"].encode("utf-8")
            cls.source_args = {"snapshot_id": session.snapshot, "path": "Service.java", "sha256": digest(source),
                               "start_byte": 0, "end_byte": len(source)}
            cls.source = session.rpc("tools/call", {"name": "read_snapshot_source", "arguments": cls.source_args})
        finally:
            session.close()

    def consumer(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return host.ConsumerExample(Path(temporary.name) / "calls", self.snapshot_id, self.build_id, "fixture-task")

    def store(self, consumer, payload=None, tool="trace_argument_origins", args=None):
        invocation = consumer.begin(tool, self.trace_args if args is None else args)
        consumer.receive(invocation, self.trace if payload is None else payload)
        return invocation, consumer.record(invocation)["response_sha256"]

    def test_request_and_whole_payload_are_persisted_with_distinct_ids(self):
        consumer = self.consumer()
        invocation, pin = self.store(consumer)
        record = consumer.record(invocation)
        request = (consumer.directory / record["request_file"]).read_bytes()
        response = (consumer.directory / record["response_file"]).read_bytes()
        self.assertEqual(digest(request), record["request_sha256"])
        self.assertEqual(digest(response), pin)
        self.assertEqual(response, encode(self.trace))
        self.assertEqual(json.loads(request)["arguments"], self.trace_args)
        self.assertNotEqual(invocation, self.trace_args["call_id"])
        self.assertEqual(record["logical_identity"]["query_id"], self.trace["structuredContent"]["query_id"])
        self.assertEqual(record["response_encoding"], "canonical_mcp_tool_payload_not_wire_bytes")

    def test_preview_cannot_become_full_input(self):
        consumer = self.consumer()
        invocation, pin = self.store(consumer, self.source, "read_snapshot_source", self.source_args)
        preview = consumer.preview(invocation, pin)
        self.assertTrue(preview["preview_truncated"])
        self.assertNotIn("validateTenant", preview["text"])
        self.assertFalse(preview["eligible_as_full_input"])
        self.assertEqual(consumer.decision(invocation)["host_status"], "needs_full_read")
        self.assertIn("validateTenant(tenant)", consumer.read_full(invocation, pin)["text"])
        self.assertEqual(consumer.decision(invocation)["host_status"], "full_payload_available")

    def test_small_preview_is_still_only_a_preview(self):
        consumer = self.consumer()
        invocation, pin = self.store(consumer, self.pages[0], "query_resource_operations", self.inventory_args)
        consumer.preview(invocation, pin, 16384)
        self.assertEqual(consumer.decision(invocation)["host_status"], "needs_full_read")

    def test_whole_query_keeps_known_paths_unknowns_and_scope(self):
        consumer = self.consumer()
        invocation, pin = self.store(consumer)
        result = consumer.read_full(invocation, pin)
        self.assertEqual(encode(result), encode(self.trace["structuredContent"]))
        self.assertTrue(result["paths"])
        self.assertIn("argument_origin_has_unknown_parts", result["gaps"])
        for key in ("contexts", "frontiers", "coverage", "call_candidates", "truncated"):
            self.assertIn(key, result)
        self.assertEqual(consumer.decision(invocation)["semantic_completeness"], "not_inferred")

    def test_complete_transport_does_not_erase_depth_stop(self):
        consumer = self.consumer()
        invocation, pin = self.store(consumer, self.depth, args=dict(self.trace_args, max_hops=0))
        result = consumer.read_full(invocation, pin)
        self.assertTrue(result["truncated"])
        self.assertIn("trace_depth_limit", result["gaps"])
        self.assertEqual(consumer.decision(invocation)["execution"], "succeeded")
        self.assertEqual(consumer.decision(invocation)["security_verdict"], "not_evaluated")

    def test_late_result_is_stored_but_not_accepted(self):
        consumer = self.consumer()
        old = consumer.begin("trace_argument_origins", self.trace_args)
        consumer.new_attempt()
        consumer.receive(old, self.trace)
        self.assertEqual(consumer.decision(old)["host_status"], "rejected_stale_attempt")
        with self.assertRaisesRegex(host.ConsumerError, "result_not_current"):
            consumer.read_full(old, consumer.record(old)["response_sha256"])
        new, _ = self.store(consumer)
        self.assertNotEqual(old, new)
        self.assertEqual(consumer.record(new)["attempt"], 2)

    def test_previously_read_results_are_invalidated_by_new_attempt(self):
        consumer = self.consumer()
        invocation, pin = self.store(consumer)
        consumer.read_full(invocation, pin)
        consumer.new_attempt()
        self.assertEqual(consumer.decision(invocation)["host_status"], "rejected_stale_attempt")

    def test_cancelled_result_is_not_accepted(self):
        consumer = self.consumer()
        invocation = consumer.begin("trace_argument_origins", self.trace_args)
        consumer.cancel()
        consumer.receive(invocation, self.trace)
        self.assertEqual(consumer.decision(invocation)["host_status"], "rejected_cancelled")
        with self.assertRaises(host.ConsumerError):
            consumer.begin("trace_argument_origins", self.trace_args)

    def test_timeout_is_not_zero_hits_and_retires_transport(self):
        consumer = self.consumer()
        invocation = consumer.invoke(demo.TimeoutFixture(), "trace_argument_origins", self.trace_args)
        record = consumer.record(invocation)
        self.assertEqual(record["execution"], "timed_out")
        self.assertIsNone(record["response_sha256"])
        self.assertIsNone(record["response_file"])
        consumer.new_attempt()
        with self.assertRaisesRegex(host.ConsumerError, "inactive_or_retired_transport"):
            consumer.begin("trace_argument_origins", self.trace_args)
        with self.assertRaisesRegex(host.ConsumerError, "invocation_already_finished"):
            consumer.receive(invocation, self.trace)

    def test_real_tool_error_is_retained_not_emptied(self):
        consumer = self.consumer()
        invocation, pin = self.store(consumer, self.error, args=dict(self.trace_args, argument_index=-1))
        self.assertEqual(consumer.record(invocation)["execution"], "tool_error")
        raw = (consumer.directory / consumer.record(invocation)["response_file"]).read_bytes()
        self.assertIn("error", json.loads(raw)["structuredContent"])
        with self.assertRaises(host.ConsumerError):
            consumer.read_full(invocation, pin)
        valid, _ = self.store(consumer)
        self.assertEqual(consumer.record(valid)["execution"], "succeeded")

    def test_wrong_snapshot_and_build_rejected(self):
        for key in ("snapshot_id", "build_id"):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.trace)
                changed["structuredContent"][key] = "0" * 64
                changed["content"][0]["text"] = encode(changed["structuredContent"]).decode()
                consumer = self.consumer()
                invocation, _ = self.store(consumer, changed)
                self.assertEqual(consumer.record(invocation)["execution"], "invalid_response")

    def test_boolean_and_integer_payload_mismatch_rejected(self):
        changed = copy.deepcopy(self.trace)
        changed["structuredContent"]["fixture_flag"] = False
        changed["content"][0]["text"] = encode(dict(changed["structuredContent"], fixture_flag=0)).decode()
        consumer = self.consumer()
        invocation, _ = self.store(consumer, changed)
        self.assertEqual(consumer.record(invocation)["execution"], "invalid_response")

    def test_missing_and_hidden_error_flags_are_rejected(self):
        for value in (None, 0, 1):
            changed = copy.deepcopy(self.trace)
            changed["isError"] = value
            consumer = self.consumer()
            invocation, _ = self.store(consumer, changed)
            self.assertEqual(consumer.record(invocation)["execution"], "invalid_response")
        changed = copy.deepcopy(self.error)
        changed["isError"] = False
        consumer = self.consumer()
        invocation, _ = self.store(consumer, changed)
        self.assertEqual(consumer.record(invocation)["execution"], "invalid_response")

    def test_readback_requires_original_pin_and_original_bytes(self):
        consumer = self.consumer()
        invocation, pin = self.store(consumer)
        with self.assertRaises(ValueError):
            consumer.read_full(invocation, "0" * 64)
        record = consumer.record(invocation)
        (consumer.directory / record["response_file"]).write_bytes(encode(self.depth))
        with self.assertRaisesRegex(host.ConsumerError, "stored_response_changed"):
            consumer.read_full(invocation, pin)

    def test_response_is_one_shot_and_requests_are_copied(self):
        consumer = self.consumer()
        args = copy.deepcopy(self.trace_args)
        invocation = consumer.begin("trace_argument_origins", args)
        args["scope_paths"].clear()
        consumer.receive(invocation, self.trace)
        self.assertEqual(consumer.record(invocation)["arguments"], self.trace_args)
        with self.assertRaises(host.ConsumerError):
            consumer.receive(invocation, self.depth)
        with self.assertRaises(host.ConsumerError):
            consumer.receive("not-issued", self.trace)

    def test_empty_inventory_page_is_followed_and_all_pages_preserved(self):
        consumer, client = self.consumer(), PayloadReplay(self.pages)
        result = host.resource_pages(consumer, client, self.inventory_args)
        self.assertEqual(result["stop_reason"], "enumeration_finished")
        self.assertFalse(result["pages"][0]["operations"])
        self.assertGreater(len(result["pages"]), 1)
        self.assertEqual(result["pages"], [p["structuredContent"] for p in self.pages])
        self.assertEqual(client.requests[1]["arguments"]["cursor"], self.pages[0]["structuredContent"]["page"]["next_cursor"])

    def test_page_budget_keeps_next_request_and_partial_material(self):
        consumer = self.consumer()
        result = host.resource_pages(consumer, PayloadReplay(self.pages), self.inventory_args, max_pages=1)
        self.assertEqual(result["stop_reason"], "page_budget_exhausted")
        self.assertEqual(len(result["pages"]), 1)
        self.assertEqual(result["next_arguments"]["cursor"], self.pages[0]["structuredContent"]["page"]["next_cursor"])
        self.assertEqual(result["security_verdict"], "not_evaluated")

    def test_query_change_and_repeating_cursor_stop_without_losing_pages(self):
        for kind in ("query", "cursor"):
            changed = copy.deepcopy(self.pages[0])
            if kind == "query":
                changed["structuredContent"]["query_id"] = "0" * 64
            changed["content"][0]["text"] = encode(changed["structuredContent"]).decode()
            consumer = self.consumer()
            result = host.resource_pages(consumer, PayloadReplay([self.pages[0], changed]), self.inventory_args)
            self.assertEqual(result["stop_reason"], "invalid_pagination")
            self.assertEqual(len(result["pages"]), 2)

    def test_skipped_page_offset_cannot_claim_complete_enumeration(self):
        changed = copy.deepcopy(self.pages[-1])
        changed["structuredContent"]["page"]["offset"] += 1
        changed["content"][0]["text"] = encode(changed["structuredContent"]).decode()
        consumer = self.consumer()
        result = host.resource_pages(consumer, PayloadReplay([*self.pages[:-1], changed]), self.inventory_args)
        self.assertEqual(result["stop_reason"], "invalid_pagination")
        self.assertEqual(len(result["pages"]), len(self.pages))

    def test_generic_transport_failure_is_not_relabelled_as_tool_success(self):
        class BrokenTransport:
            def rpc(self, method, params):
                raise RuntimeError("fixture closed pipe")
        consumer = self.consumer()
        invocation = consumer.invoke(BrokenTransport(), "trace_argument_origins", self.trace_args)
        self.assertEqual(consumer.record(invocation)["execution"], "transport_error")
        self.assertFalse(consumer.transport_usable)
        self.assertEqual(consumer.decision(invocation)["host_status"], "not_accepted")

    def test_persistence_failure_cannot_accept_unwritten_response(self):
        consumer = self.consumer()
        invocation = consumer.begin("trace_argument_origins", self.trace_args)
        with patch.object(host, "write_new", side_effect=OSError("fixture disk failure")):
            with self.assertRaises(OSError):
                consumer.receive(invocation, self.trace)
        self.assertEqual(consumer.record(invocation)["execution"], "persistence_error")
        self.assertEqual(consumer.decision(invocation)["host_status"], "not_accepted")

    def test_error_and_timeout_end_paging_without_claiming_enumeration(self):
        for client, reason in ((PayloadReplay([self.error]), "tool_error"), (demo.TimeoutFixture(), "timed_out")):
            consumer = self.consumer()
            result = host.resource_pages(consumer, client, self.inventory_args)
            self.assertEqual(result["stop_reason"], reason)
            self.assertEqual(len(result["invocations"]), 1)
            self.assertNotEqual(result["stop_reason"], "enumeration_finished")

    def test_limits_fail_without_success_or_silent_payload_truncation(self):
        consumer = self.consumer()
        with patch.object(host, "MAX_PAYLOAD", 4):
            invocation, pin = self.store(consumer)
        self.assertIsNone(pin)
        self.assertEqual(consumer.record(invocation)["execution"], "invalid_response")
        with patch.object(host, "MAX_CALLS", 1), self.assertRaises(host.ConsumerError):
            consumer.begin("trace_argument_origins", self.trace_args)
        with self.assertRaises(ValueError):
            host.resource_pages(self.consumer(), None, self.inventory_args, max_pages=0)

    def test_real_subprocess_replay_saves_scope_and_offline_result_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "replay"
            command = [sys.executable, str(ROOT / "security/demo_consumer.py"), "--mcp", str(flow.harness.MCP),
                       "--output-dir", str(directory)]
            run = subprocess.run(command, capture_output=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            receipt = decode((directory / "RECEIPT.json").read_bytes(), host.MAX_STORED)
            by_id = {r["invocation_id"]: r for r in receipt["records"]}
            trace_record = by_id[receipt["trace_invocation"]]
            response = (directory / "calls" / trace_record["response_file"]).read_bytes()
            self.assertEqual(digest(response), trace_record["response_sha256"])
            trace = json.loads(response)["structuredContent"]
            self.assertTrue(trace["paths"])
            self.assertTrue(trace["gaps"])
            for key in ("scope_paths", "argument_index"):
                self.assertIn(key, trace_record["arguments"])
            capture = (directory / "capture.json").read_bytes()
            self.assertEqual(digest(capture), receipt["capture_sha256"])
            self.assertIn("context_id", json.loads(capture)["result"])
            self.assertEqual(receipt["offline"]["verify"]["status"], "source_references_verified")
            self.assertEqual(receipt["observed_host_decisions"]["late"]["host_status"], "rejected_stale_attempt")
            self.assertFalse(receipt["capture_eligible_after_cancellation"])
            self.assertEqual(receipt["timeout_record"]["execution"], "timed_out")
            self.assertEqual(receipt["model_calls"], 0)
            self.assertFalse(receipt["measurements"]["model_input_measured"])
            # Repeating a demo must not overwrite its previous results.
            again = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(again.returncode, 2)
            self.assertEqual(again.stdout, b"")


if __name__ == "__main__":
    unittest.main()
