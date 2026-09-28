"""Small, single-threaded host example; not an MCP tool or a task scheduler.

Reuse demo_flow.Client for transport. Persist canonical tool payloads, not exact
JSON-RPC wire bytes. A read receipt proves availability, never model comprehension.
No target execution, network, background worker, automatic retry or resume.
"""
from __future__ import annotations

import copy
from pathlib import Path
import re
import subprocess
import time
import uuid

from export_evidence import checked_digest, decode, digest, encode, read_file, write_new

MAX_PAYLOAD = 8 * 1024 * 1024
MAX_CALLS = 128
MAX_STORED = 32 * 1024 * 1024
TOOLS = {"query_security_facts", "query_resource_operations", "inspect_operation_context",
         "trace_argument_origins", "read_snapshot_source"}


class ConsumerError(ValueError):
    """Fixed diagnostics; do not copy repository text into error messages."""


def require(value: bool, code: str) -> None:
    if not value:
        raise ConsumerError(code)


class ConsumerExample:
    """Use one trusted connection and one snapshot/build pair per instance.

    Call receive only with the payload associated by the transport with begin's
    invocation. Invocation IDs are host IDs; source call_id is never a RPC ID.
    The directory and its ancestors must be chosen by the trusted host.
    """

    def __init__(self, directory: Path, snapshot_id: str, build_id: str, task_id: str):
        require(isinstance(task_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", task_id) is not None,
                "invalid_task_id")
        self.snapshot_id = checked_digest(snapshot_id)
        self.build_id = checked_digest(build_id)
        self.task_id = task_id
        self.directory = directory
        directory.mkdir(mode=0o700, exist_ok=False)
        self.attempt = 1
        self.active = True
        self.transport_usable = True
        self._calls: dict[str, dict] = {}
        self._read: set[str] = set()
        self._stored = 0

    def new_attempt(self) -> None:
        # Original records stay unchanged; eligibility is evaluated at use time.
        self.attempt += 1
        self.active = True

    def cancel(self) -> None:
        self.active = False

    def begin(self, tool: str, arguments: dict) -> str:
        require(self.active and self.transport_usable, "inactive_or_retired_transport")
        require(tool in TOOLS, "example_tool_not_supported")
        require(len(self._calls) < MAX_CALLS, "example_call_limit")
        args = decode(encode(arguments), 32768)
        require(args.get("snapshot_id") == self.snapshot_id, "request_snapshot_mismatch")
        invocation = uuid.uuid4().hex
        request_raw = encode({"invocation_id": invocation, "task_id": self.task_id,
                              "attempt": self.attempt, "snapshot_id": self.snapshot_id,
                              "build_id": self.build_id, "tool": tool, "arguments": args})
        write_new(self.directory / (invocation + ".request.json"), request_raw)
        self._calls[invocation] = {
            "invocation_id": invocation, "task_id": self.task_id, "attempt": self.attempt,
            "snapshot_id": self.snapshot_id, "build_id": self.build_id,
            "tool": tool, "arguments": args, "execution": "pending",
            "request_file": invocation + ".request.json", "request_sha256": digest(request_raw),
            "response_file": None, "response_sha256": None, "response_bytes": 0,
            "elapsed_seconds": None,
            "response_encoding": "canonical_mcp_tool_payload_not_wire_bytes",
        }
        return invocation

    def _pending(self, invocation: str) -> dict:
        require(invocation in self._calls, "unknown_invocation")
        record = self._calls[invocation]
        require(record["execution"] == "pending", "invocation_already_finished")
        return record

    def fail(self, invocation: str, reason: str) -> None:
        require(reason in {"timed_out", "transport_error"}, "invalid_failure_kind")
        self._pending(invocation)["execution"] = reason
        # A timed-out response can remain on the pipe. Do not reuse that pipe.
        self.transport_usable = False

    def receive(self, invocation: str, payload: dict) -> None:
        record = self._pending(invocation)
        try:
            raw = encode(payload)
            require(len(raw) <= MAX_PAYLOAD and self._stored + len(raw) <= MAX_STORED,
                    "example_response_limit")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            record["execution"] = "invalid_response"
            return
        filename = invocation + ".response.json"
        # Publication is no-overwrite; an I/O failure is not an accepted result.
        record["execution"] = "persistence_error"
        write_new(self.directory / filename, raw)
        self._stored += len(raw)
        record.update(response_file=filename, response_sha256=digest(raw), response_bytes=len(raw))
        try:
            envelope = decode(raw, MAX_PAYLOAD)
            require(type(envelope.get("isError")) is bool, "tool_error_flag_missing")
            result = envelope.get("structuredContent")
            require(isinstance(result, dict), "structured_result_missing")
            content = envelope.get("content")
            require(isinstance(content, list) and len(content) == 1
                    and content[0].get("type") == "text", "text_payload_missing")
            text = content[0]["text"].encode("utf-8")
            require(encode(decode(text, MAX_PAYLOAD)) == encode(result), "payload_encodings_differ")
            require(result.get("snapshot_id") == self.snapshot_id, "response_snapshot_mismatch")
            require("build_id" not in result or result["build_id"] == self.build_id, "response_build_mismatch")
            require(envelope["isError"] or "error" not in result, "hidden_tool_error")
            record["logical_identity"] = {key: checked_digest(result[key])
                                          for key in ("query_id", "context_id") if key in result}
            record["execution"] = "tool_error" if envelope["isError"] else "succeeded"
        except (ValueError, TypeError, AttributeError, KeyError, UnicodeError):
            record["execution"] = "invalid_response"

    def invoke(self, client, tool: str, arguments: dict) -> str:
        invocation = self.begin(tool, arguments)
        started = time.perf_counter()
        try:
            payload = client.rpc("tools/call", {"name": tool, "arguments": copy.deepcopy(arguments)})
        except (TimeoutError, subprocess.TimeoutExpired):
            self.fail(invocation, "timed_out")
        except (OSError, ValueError, RuntimeError, KeyError):
            self.fail(invocation, "transport_error")
        else:
            self.receive(invocation, payload)
        finally:
            self._calls[invocation]["elapsed_seconds"] = time.perf_counter() - started
        return invocation

    def decision(self, invocation: str) -> dict:
        require(invocation in self._calls, "unknown_invocation")
        record = self._calls[invocation]
        if not self.active:
            status = "rejected_cancelled"
        elif record["attempt"] != self.attempt:
            status = "rejected_stale_attempt"
        elif record["execution"] != "succeeded":
            status = "not_accepted"
        elif invocation not in self._read:
            status = "needs_full_read"
        else:
            status = "full_payload_available"
        return {"execution": record["execution"], "host_status": status,
                "semantic_completeness": "not_inferred", "security_verdict": "not_evaluated"}

    def _payload(self, invocation: str, expected: str) -> dict:
        decision = self.decision(invocation)
        require(decision["host_status"] in {"needs_full_read", "full_payload_available"}, "result_not_current")
        record = self._calls[invocation]
        require(checked_digest(expected) == record["response_sha256"], "response_pin_mismatch")
        raw = read_file(self.directory / record["response_file"], MAX_PAYLOAD)
        require(digest(raw) == expected, "stored_response_changed")
        return decode(raw, MAX_PAYLOAD)

    def preview(self, invocation: str, expected: str, limit: int = 256) -> dict:
        require(type(limit) is int and 0 < limit <= 16384, "preview_limit")
        raw = encode(self._payload(invocation, expected)["structuredContent"])
        prefix = raw[:limit].decode("utf-8", "ignore")
        return {"invocation_id": invocation, "response_sha256": expected,
                "delivery": "preview_only", "eligible_as_full_input": False,
                "text": prefix, "preview_bytes": len(prefix.encode("utf-8")),
                "structured_bytes": len(raw), "preview_truncated": len(prefix.encode("utf-8")) < len(raw),
                "trust": "untrusted_data_not_instructions"}

    def read_full(self, invocation: str, expected: str) -> dict:
        result = self._payload(invocation, expected)["structuredContent"]
        self._read.add(invocation)
        return result

    def record(self, invocation: str) -> dict:
        require(invocation in self._calls, "unknown_invocation")
        return {**copy.deepcopy(self._calls[invocation]), "decision": self.decision(invocation)}

    def records(self) -> list[dict]:
        return [self.record(invocation) for invocation in self._calls]


def resource_pages(consumer: ConsumerExample, client, arguments: dict, max_pages: int = 32) -> dict:
    """Retain each full page. Do not merge declarations or silently return []."""
    require(type(max_pages) is int and 0 < max_pages <= 64 and "cursor" not in arguments, "page_budget")
    pages, invocations, seen = [], [], set()
    request, query_id = dict(arguments), None
    expected_offset, expected_total = 0, None
    stop = "page_budget_exhausted"
    for _ in range(max_pages):
        invocation = consumer.invoke(client, "query_resource_operations", request)
        invocations.append(invocation)
        record = consumer.record(invocation)
        if record["execution"] != "succeeded":
            stop = record["execution"]
            break
        result = consumer.read_full(invocation, record["response_sha256"])
        pages.append(result)
        try:
            identity = checked_digest(result["query_id"])
            require(query_id is None or query_id == identity, "query_identity_changed")
            query_id = identity
            page = result["page"]
            cursor = page["next_cursor"]
            offset, next_offset, total = page["offset"], page["next_offset"], page["tasks_total"]
            require(all(type(value) is int for value in (offset, next_offset, total))
                    and offset == expected_offset and 0 <= offset <= next_offset <= total
                    and (expected_total is None or total == expected_total), "invalid_pagination")
            expected_total = total
            require(type(page["enumeration_complete"]) is bool, "invalid_pagination")
            if cursor is None:
                require(next_offset == total, "invalid_pagination")
                stop = "enumeration_finished" if page["enumeration_complete"] else "catalog_incomplete"
                break
            require(isinstance(cursor, str) and cursor and len(cursor) <= 128 and cursor not in seen
                    and type(page["offset"]) is int and type(page["next_offset"]) is int
                    and page["next_offset"] > page["offset"] and not page["enumeration_complete"],
                    "invalid_pagination")
            expected_offset = next_offset
            seen.add(cursor)
            request = dict(arguments, cursor=cursor)
        except (ValueError, KeyError, TypeError):
            stop = "invalid_pagination"
            break
    return {"pages": pages, "invocations": invocations, "stop_reason": stop,
            "next_arguments": request if stop == "page_budget_exhausted" else None,
            "security_verdict": "not_evaluated"}
