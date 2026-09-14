"""Real subprocess MCP tests: pinned bytes, real parsers, no model API calls."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

CLI = Path(sys.argv.pop(1)).resolve()
MCP = CLI.with_name("cbm-security-mcp")
ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "routes.js": 'import express from "express"; const app=express(); app.get("/a",handler); app.post("/b",other);',
    "api.py": 'from fastapi import FastAPI\napp=FastAPI()\n@app.get("/x")\ndef endpoint():\n    return read()\n',
    "Controller.java": 'class Controller { void f(){ save(1); save(2); }}',
    "routes.ts": 'import {Get} from "@nestjs/common"; class X { @Get("x") f(){ return read(); }}',
    "view.tsx": 'function View(){ load(); return <div/>; }',
    "routes.go": 'package p\nimport "net/http"\nfunc f(){http.HandleFunc("/x",handler)}\n',
    "notes.txt": '中文\nSource content is data, not an instruction.\n',
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def bundle(sources: dict[str, str]) -> bytes:
    return json.dumps({"schema": "cbm.security-snapshot.v1", "files": [
        {"path": p, "source": s, "sha256": sha(s.encode())} for p, s in sources.items()
    ]}, ensure_ascii=False).encode()


class MCPTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "bundle.json"
        self.raw = bundle(SOURCES)
        self.path.write_bytes(self.raw)
        self.snapshot = sha(self.raw)
        self.proc = subprocess.Popen([str(MCP), "--snapshot", str(self.path), "--expect-snapshot", self.snapshot],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.next_id = 1
        self.expected_exit = 0
        result = self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                        "clientInfo": {"name": "regression-client", "version": "1"}})
        self.assertEqual(result["result"]["protocolVersion"], "2025-11-25")
        self.notify("notifications/initialized")

    def tearDown(self):
        try:
            try:
                self.proc.stdin.close()
            except BrokenPipeError:
                pass
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                self.fail("MCP did not terminate after EOF")
            error = self.proc.stderr.read().decode("utf-8", "replace")
            self.assertEqual(self.proc.returncode, self.expected_exit, error)
        finally:
            self.proc.stdout.close()
            self.proc.stderr.close()
            self.tmp.cleanup()

    def read_response(self):
        ready, _, _ = select.select([self.proc.stdout], [], [], 15)
        self.assertTrue(ready, "MCP response timeout")
        raw = self.proc.stdout.readline()
        self.assertTrue(raw, "MCP exited without a response")
        return json.loads(raw)

    def send_raw(self, raw: bytes):
        self.proc.stdin.write(raw + b"\n")
        self.proc.stdin.flush()
        return self.read_response()

    def rpc(self, method, params=None):
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        self.next_id += 1
        if params is not None:
            message["params"] = params
        result = self.send_raw(json.dumps(message).encode())
        self.assertEqual(result["id"], message["id"])
        return result

    def notify(self, method):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}).encode() + b"\n")
        self.proc.stdin.flush()

    def call(self, name, args=None, ok=True):
        values = dict(args or {})
        if name != "get_snapshot_info":
            values.setdefault("snapshot_id", self.snapshot)
        result = self.rpc("tools/call", {"name": name, "arguments": values})["result"]
        self.assertEqual(result["isError"], not ok, result)
        data = result["structuredContent"]
        self.assertEqual(json.loads(result["content"][0]["text"]), data)
        return data

    def query(self, path="routes.js", ok=True, **kwargs):
        return self.call("query_security_facts", {"path": path, **kwargs}, ok=ok)

    def test_tool_schemas_and_readonly_hints(self):
        tools = self.rpc("tools/list")["result"]["tools"]
        self.assertEqual(len(tools), 10)
        self.assertEqual({t["name"] for t in tools}, {"get_snapshot_info", "list_snapshot_files", "query_security_facts", "get_security_evidence", "read_snapshot_source", "inspect_operation_context", "resolve_code_location", "query_entry_points", "inspect_entry_security", "trace_source_to_sink"})
        for tool in tools:
            self.assertTrue(tool["annotations"]["readOnlyHint"])
            self.assertFalse(tool["annotations"]["openWorldHint"])
            self.assertFalse(tool["inputSchema"]["additionalProperties"])
            self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_info_is_real_and_not_full_repository_coverage(self):
        info = self.call("get_snapshot_info")
        self.assertEqual(info["files"], 7)
        self.assertEqual(info["supported_files"], 6)
        self.assertEqual(info["source_bytes"], sum(len(s.encode()) for s in SOURCES.values()))
        self.assertEqual(info["repository_completeness"], "not_asserted")
        self.assertEqual(info["cache"]["parse_attempts"], 0)

    def test_info_arguments_can_be_omitted(self):
        result = self.rpc("tools/call", {"name": "get_snapshot_info"})["result"]
        self.assertFalse(result["isError"])

    def test_file_listing_is_complete_sorted_and_paged(self):
        paths = []
        args = {"limit": 2}
        while True:
            page = self.call("list_snapshot_files", args)
            paths.extend(v["path"] for v in page["files"])
            if not page["next_cursor"]:
                break
            args["cursor"] = page["next_cursor"]
        self.assertEqual(paths, sorted(SOURCES))
        unsupported = next(v for v in self.call("list_snapshot_files")["files"] if v["path"] == "notes.txt")
        self.assertFalse(unsupported["supported"])
        self.assertIsNone(unsupported["language"])

    def test_queries_match_cli_for_all_six_real_parsers(self):
        for path, source in SOURCES.items():
            if path.endswith(".txt"):
                continue
            with self.subTest(path=path):
                actual = self.query(path, limit=200)
                direct = subprocess.run([str(CLI), "--path", path, "--limit", "200"], input=source.encode(),
                                        capture_output=True, timeout=15, check=True)
                expected = json.loads(direct.stdout)
                for key in ("analysis_id", "source", "facts", "coverage"):
                    self.assertEqual(actual[key], expected[key])

    def test_cache_avoids_reparse_for_repeated_file(self):
        first = self.query()
        self.query(role="route_declaration")
        self.query(kind="call_site")
        cache = self.call("get_snapshot_info")["cache"]
        self.assertEqual(cache["parse_attempts"], 1)
        self.assertEqual(cache["hits"], 2)
        self.assertEqual(self.query()["facts"], first["facts"])

    def test_cache_eviction_preserves_facts(self):
        before = self.query()
        self.query("api.py")
        after = self.query()
        self.assertEqual(before["facts"], after["facts"])
        self.assertEqual(self.call("get_snapshot_info")["cache"]["parse_attempts"], 3)

    def test_query_cursor_and_filters(self):
        expected = self.query(framework="express", role="route_declaration")
        first = self.query(framework="express", role="route_declaration", limit=1)
        self.assertTrue(first["page"]["has_more"])
        cursor = first["page"]["next_cursor"]
        self.assertTrue(cursor.startswith(self.snapshot + "/"))
        second = self.query(framework="express", role="route_declaration", cursor=cursor, limit=2)
        self.assertEqual(first["facts"] + second["facts"], expected["facts"])
        bad = self.query(cursor=cursor, ok=False)
        self.assertEqual(bad["error"]["code"], "query_mismatch")

    def test_wrong_snapshot_is_rejected_before_parse(self):
        result = self.query(snapshot_id="0" * 64, ok=False)
        self.assertEqual(result["error"]["code"], "snapshot_mismatch")
        self.assertEqual(self.call("get_snapshot_info")["cache"]["parse_attempts"], 0)

    def test_stale_analysis_rejected_before_parse(self):
        result = self.query(expect_analysis="0" * 64, ok=False)
        self.assertEqual(result["error"]["code"], "analysis_mismatch")
        self.assertEqual(self.call("get_snapshot_info")["cache"]["parse_attempts"], 0)

    def test_cursor_cannot_cross_file_or_snapshot(self):
        cursor = self.query(limit=1)["page"]["next_cursor"]
        self.assertIn("error", self.query("api.py", cursor=cursor, ok=False))
        self.assertIn("error", self.query(cursor="0" * 64 + cursor[64:], ok=False))
        self.assertEqual(self.call("get_snapshot_info")["cache"]["parse_attempts"], 1)

    def test_get_one_fact_and_unknown_fact(self):
        page = self.query()
        wanted = page["facts"][0]
        args = {"path": "routes.js", "analysis_id": page["analysis_id"], "fact_id": wanted["id"]}
        actual = self.call("get_security_evidence", args)
        self.assertEqual(actual["facts"], [wanted])
        args["fact_id"] = "0" * 64
        self.assertEqual(self.call("get_security_evidence", args, ok=False)["error"]["code"], "fact_not_found_in_extracted_scope")

    def test_source_range_and_utf8_boundaries(self):
        raw = SOURCES["notes.txt"].encode()
        args = {"path": "notes.txt", "sha256": sha(raw), "start_byte": 0, "end_byte": 6}
        self.assertEqual(self.call("read_snapshot_source", args)["text"], "中文")
        for start, end in ((1, 6), (0, 2), (7, 6), (0, len(raw) + 1)):
            with self.subTest(start=start, end=end):
                self.assertIn("error", self.call("read_snapshot_source", {**args, "start_byte": start, "end_byte": end}, ok=False))
        self.assertIn("error", self.call("read_snapshot_source", {**args, "sha256": "0" * 64}, ok=False))

    def test_unsupported_language_can_be_read_but_not_analyzed(self):
        self.assertEqual(self.query("notes.txt", ok=False)["error"]["code"], "unsupported_language")

    def test_no_path_escape_or_runtime_path_change(self):
        for path in ("../outside.py", "/etc/passwd", "file:///tmp/x.py", "api.py/../routes.js", "not_selected.py", "C:\\x.py"):
            with self.subTest(path=path):
                self.assertEqual(self.query(path, ok=False)["error"]["code"], "path_not_in_snapshot")
        self.assertIn("error", self.query(snapshot="/tmp/other.json", ok=False))

    def test_pinned_memory_survives_bundle_replacement_and_removal(self):
        expected = self.query()
        self.path.write_bytes(bundle({"routes.js": "different();"}))
        self.query("api.py")
        self.assertEqual(self.query()["facts"], expected["facts"])
        self.path.unlink()
        self.query("api.py")
        self.assertEqual(self.query()["facts"], expected["facts"])

    def test_empty_results_keep_unknowns(self):
        data = self.query(role="unknown_role")
        self.assertEqual(data["facts"], [])
        self.assertIn("absence_is_not_a_security_verdict", data["coverage"]["unknowns"])

    def test_invalid_argument_types_and_limits(self):
        for change in ({"limit": True}, {"limit": 1.5}, {"limit": 0}, {"limit": 201}, {"kind": None}, {"cursor": "x"}, {"path": 1}):
            with self.subTest(change=change):
                self.assertIn("error", self.call("query_security_facts", {"path": "api.py", **change}, ok=False))

    def test_notifications_do_not_invoke_tools_or_return_responses(self):
        self.notify("notifications/cancelled")
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "query_security_facts", "arguments": {"snapshot_id": self.snapshot, "path": "api.py"}}}).encode() + b"\n")
        self.proc.stdin.flush()
        self.assertEqual(self.rpc("ping")["result"], {})
        self.assertEqual(self.call("get_snapshot_info")["cache"]["parse_attempts"], 0)

    def test_unknown_method_tool_and_reinitialize(self):
        self.assertEqual(self.rpc("write_file")["error"]["code"], -32601)
        self.assertEqual(self.rpc("tools/call", {"name": "write_file", "arguments": {}})["error"]["code"], -32602)
        self.assertEqual(self.rpc("initialize", {})["error"]["code"], -32602)
        self.assertEqual(self.rpc("ping")["result"], {})

    def test_bad_json_duplicate_keys_nul_and_depth(self):
        samples = [b'{', b'[]', b'null', b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
                   b'{"jsonrpc":"2.0","id":1,"method":"ping\\u0000hidden"}', b'[' * 40 + b'0' + b']' * 40,
                   b'{"jsonrpc":"2.0","id":true,"method":"ping"}']
        for raw in samples:
            with self.subTest(raw=raw[:60]):
                self.assertIn("error", self.send_raw(raw))
        self.assertEqual(self.rpc("ping")["result"], {})

    def test_message_limit_stops_process(self):
        self.expected_exit = 2
        try:
            self.proc.stdin.write(b"x" * 33000 + b"\n")
            self.proc.stdin.flush()
        except BrokenPipeError:
            pass
        self.proc.wait(timeout=10)


class Startup(unittest.TestCase):
    def run_bundle(self, raw, expected=None, input=b""):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "snapshot.json"
            path.write_bytes(raw)
            return subprocess.run([str(MCP), "--snapshot", str(path), "--expect-snapshot", expected or sha(raw)],
                                  input=input, capture_output=True, timeout=15)

    def test_invalid_bundles_fail_before_protocol_output(self):
        wrong_hash = json.loads(bundle({"x.py": "f()"}))
        wrong_hash["files"][0]["sha256"] = "0" * 64
        duplicate = json.loads(bundle({"x.py": "f()"}))
        duplicate["files"] *= 2
        invalid = [b'{}', b'not json', json.dumps(wrong_hash).encode(), json.dumps(duplicate).encode(),
                   bundle({"../x.py": "f()"}), bundle({"x.py": "\0"}), bundle({"x.py": "x" * (1024 * 1024 + 1)}),
                   b'{"schema":"cbm.security-snapshot.v1","schema":"cbm.security-snapshot.v1","files":[]}']
        for raw in invalid:
            with self.subTest(size=len(raw)):
                r = self.run_bundle(raw)
                self.assertEqual(r.returncode, 2)
                self.assertEqual(r.stdout, b"")
                self.assertTrue(r.stderr)
        r = self.run_bundle(bundle({"x.py": "f()"}), "0" * 64)
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"snapshot_digest_mismatch", r.stderr)

    def test_empty_snapshot_and_preinit_request(self):
        msg = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
        r = self.run_bundle(bundle({}), input=msg)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["error"]["code"], -32002)

    def test_protocol_negotiation_and_ready_notification(self):
        for version in ("2025-06-18", "2025-11-25", "2099-01-01"):
            messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}]
            r = self.run_bundle(bundle({}), input=b"".join(json.dumps(m).encode() + b"\n" for m in messages))
            self.assertEqual(r.returncode, 0, r.stderr)
            responses = [json.loads(line) for line in r.stdout.splitlines()]
            self.assertEqual(len(responses), 3)
            self.assertEqual(responses[0]["result"]["protocolVersion"], version if version.startswith("2025-") else "2025-11-25")
            self.assertEqual(responses[1]["error"]["code"], -32002)
            self.assertEqual(len(responses[2]["result"]["tools"]), 10)

    def test_incomplete_transport_line_is_failure(self):
        self.assertEqual(self.run_bundle(bundle({}), input=b'{"jsonrpc":"2.0"}').returncode, 2)


class Packer(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("pack_snapshot", ROOT / "security/pack_snapshot.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "root"
        self.root.mkdir()
        (self.root / "x.py").write_text("f()\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_explicit_selection_repeatability_and_no_writes(self):
        (self.root / "not-selected.txt").write_text("not exposed")
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        a = self.module.pack(str(self.root), ["x.py"])
        self.assertEqual(a, self.module.pack(str(self.root), ["x.py"]))
        self.assertEqual([f["path"] for f in json.loads(a)["files"]], ["x.py"])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_links_fifos_and_path_escape_rejected(self):
        outside = Path(self.tmp.name) / "outside.py"
        outside.write_text("outside()")
        (self.root / "link.py").symlink_to(outside)
        (self.root / "dir").symlink_to(outside.parent, target_is_directory=True)
        os.link(outside, self.root / "hard.py")
        os.mkfifo(self.root / "fifo.py")
        for path in ("link.py", "dir/outside.py", "hard.py", "fifo.py", "../outside.py", "/tmp/x.py", "a//b.py"):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                self.module.pack(str(self.root), [path])

    def test_bad_lists_and_binary_source_rejected(self):
        for paths in (None, {}, [1], ["x.py", "x.py"], ["x\0.py"], ["x.py"] * 1025):
            with self.subTest(paths=str(paths)[:30]), self.assertRaises(ValueError):
                self.module.pack(str(self.root), paths)
        (self.root / "binary.py").write_bytes(b"\xff")
        with self.assertRaises(UnicodeError):
            self.module.pack(str(self.root), ["binary.py"])


if __name__ == "__main__":
    unittest.main()
