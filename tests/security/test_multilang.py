"""Real-parser regression tests. Fixtures are source inputs, never canned output."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
SAMPLES = {
    "java": ("X.java", 'class X { void f() { save(input); save("fixed"); many(1,2,3,4,5,6,7,8,9); } }'),
    "python": ("x.py", 'def f():\n    save(input); save("fixed"); many(1,2,3,4,5,6,7,8,9)\n'),
    "javascript": ("x.js", 'function f() { save(input); save("fixed"); many(1,2,3,4,5,6,7,8,9); }'),
    "typescript": ("x.ts", 'function f(): void { save(input); save("fixed"); many(1,2,3,4,5,6,7,8,9); }'),
    "tsx": ("x.tsx", 'function f() { save(input); save("fixed"); many(1,2,3,4,5,6,7,8,9); return <div/>; }'),
    "go": ("x.go", 'package p\nfunc f() { save(input); save("fixed"); many(1,2,3,4,5,6,7,8,9) }\n'),
}
# name, path, source, framework, role, expected matches
CASES = [
    ("spring_route", "X.java", 'import org.springframework.web.bind.annotation.GetMapping; class X { @GetMapping("/x") void f() {} }', "spring-mvc", "route_declaration", 1),
    ("spring_prefix", "X.java", 'import org.springframework.web.bind.annotation.RequestMapping; @RequestMapping(path="/api") class X {}', "spring-mvc", "route_prefix_declaration", 1),
    ("spring_input", "X.java", 'import org.springframework.web.bind.annotation.RequestParam; class X { void f(@RequestParam String x) {} }', "spring-mvc", "request_input_declaration", 1),
    ("spring_control", "X.java", 'import org.springframework.security.access.prepost.PreAuthorize; class X { @PreAuthorize("hasRole(\'ADMIN\')") void f() {} }', "spring-security", "authorization_declaration", 1),
    ("spring_enable", "X.java", 'import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity; @EnableMethodSecurity class X {}', "spring-security", "security_configuration_declaration", 1),
    ("spring_fully_qualified", "X.java", 'class X { @org.springframework.web.bind.annotation.GetMapping("/x") void f() {} }', "spring-mvc", "route_declaration", 1),
    ("spring_custom", "X.java", '@interface GetMapping {} class X { @GetMapping void f() {} }', "spring-mvc", "route_declaration", 0),
    ("spring_wrong_import", "X.java", 'import example.GetMapping; class X { @GetMapping("/x") void f() {} }', "spring-mvc", "route_declaration", 0),
    ("spring_wildcard", "X.java", 'import org.springframework.web.bind.annotation.*; class X { @GetMapping("/x") void f() {} }', "spring-mvc", "route_declaration", 0),
    ("fastapi_alias", "x.py", 'from fastapi import FastAPI as API\napp = API()\n@app.get("/x")\ndef endpoint():\n    return 1\n', "fastapi", "route_declaration", 1),
    ("fastapi_namespace", "x.py", 'import fastapi as fa\nrouter = fa.APIRouter(prefix="/api")\n@router.post(path="/x")\nasync def endpoint():\n    return 1\n', "fastapi", "route_declaration", 1),
    ("fastapi_depends", "x.py", 'from fastapi import Depends as D\ndef endpoint(value=D(helper)):\n    return value\n', "fastapi", "dependency_declaration", 1),
    ("fastapi_security", "x.py", 'from fastapi import Security\ndef endpoint(user=Security(auth)):\n    return user\n', "fastapi", "security_dependency_declaration", 1),
    ("fastapi_input", "x.py", 'from fastapi import Query\ndef endpoint(q=Query()):\n    return q\n', "fastapi", "request_input_declaration", 1),
    ("fastapi_direct_registration", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\napp.add_api_route("/x", handler)\n', "fastapi", "route_declaration", 1),
    ("fastapi_missing_receiver", "x.py", 'from fastapi import FastAPI\n@app.get("/x")\ndef endpoint():\n    pass\n', "fastapi", "route_declaration", 0),
    ("fastapi_reassignment", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\napp = other\n@app.get("/x")\ndef endpoint():\n    pass\n', "fastapi", "route_declaration", 0),
    ("fastapi_shadowed_factory", "x.py", 'from fastapi import FastAPI\ndef FastAPI():\n    return other\napp = FastAPI()\n@app.get("/x")\ndef endpoint():\n    pass\n', "fastapi", "route_declaration", 0),
    ("fastapi_shadowed_parameter", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\ndef outer(app):\n    @app.get("/x")\n    def endpoint():\n        pass\n', "fastapi", "route_declaration", 0),
    ("flask_route", "x.py", 'from flask import Flask\napp = Flask(__name__)\n@app.route("/x", methods=["GET","POST"])\ndef endpoint():\n    return 1\n', "flask", "route_declaration", 1),
    ("flask_blueprint", "x.py", 'from flask import Blueprint as BP\nbp = BP("name", __name__)\n@bp.post("/x")\ndef endpoint():\n    return 1\n', "flask", "route_declaration", 1),
    ("flask_hook", "x.py", 'import flask\napp = flask.Flask(__name__)\n@app.before_request\ndef check():\n    pass\n', "flask", "request_hook_declaration", 1),
    ("django_path", "x.py", 'from django.urls import path as route\nurlpatterns = [route("x/<int:id>", views.handler)]\n', "django", "route_declaration", 1),
    ("django_regex", "x.py", 'from django.urls import re_path\nurlpatterns = [re_path(r"^x/$", views.handler)]\n', "django", "route_declaration", 1),
    ("django_auth", "x.py", 'from django.contrib.auth.decorators import login_required\n@login_required\ndef endpoint(request):\n    pass\n', "django", "authorization_declaration", 1),
    ("django_exemption", "x.py", 'from django.views.decorators.csrf import csrf_exempt\n@csrf_exempt\ndef endpoint(request):\n    pass\n', "django", "control_exemption_declaration", 1),
    ("express_esm", "x.js", 'import express from "express"; const app = express(); app.get("/x", auth, handler);', "express", "route_declaration", 1),
    ("express_commonjs", "x.cjs", 'const express = require("express"); const app = express(); app.post("/x", handler);', "express", "route_declaration", 1),
    ("express_router_alias", "x.ts", 'import {Router as R} from "express"; const router = R(); router.put("/x", handler);', "express", "route_declaration", 1),
    ("express_middleware", "x.js", 'import express from "express"; const app = express(); app.use(auth);', "express", "middleware_attachment", 1),
    ("express_setting", "x.js", 'import express from "express"; const app = express(); app.get("setting");', "express", "route_declaration", 0),
    ("express_lookalike", "x.js", 'const app = database(); app.get("/x", handler);', "express", "route_declaration", 0),
    ("express_shadowed", "x.js", 'import express from "express"; const app = express(); function f(app) { app.get("/x", handler); }', "express", "route_declaration", 0),
    ("express_arrow_shadow", "x.js", 'import express from "express"; const app = express(); const f = app => app.get("/x", handler);', "express", "route_declaration", 0),
    ("express_reassign", "x.js", 'import express from "express"; let app = express(); app = other; app.get("/x", handler);', "express", "route_declaration", 0),
    ("express_require_shadow", "x.js", 'function require(x) {return other;} const express = require("express"); const app = express(); app.get("/x", handler);', "express", "route_declaration", 0),
    ("express_scope", "x.js", 'import express from "express"; function f() { const app = express(); } function g() { app.get("/x", handler); }', "express", "route_declaration", 0),
    ("nestjs_route", "x.ts", 'import {Controller, Get as Read} from "@nestjs/common"; @Controller("api") class X { @Read("x") f() {return 1;} }', "nestjs", "route_declaration", 1),
    ("nestjs_control", "x.ts", 'import {UseGuards} from "@nestjs/common"; @UseGuards(AuthGuard) class X {}', "nestjs", "control_declaration", 1),
    ("nestjs_custom", "x.ts", 'import {Get} from "custom"; class X { @Get("x") f() {return 1;} }', "nestjs", "route_declaration", 0),
    ("go_http", "x.go", 'package p\nimport "net/http"\nfunc f() { http.HandleFunc("GET /x", handler) }\n', "go-net-http", "route_declaration", 1),
    ("go_http_alias", "x.go", 'package p\nimport h "net/http"\nfunc f() { h.HandleFunc("/x", handler) }\n', "go-net-http", "route_declaration", 1),
    ("go_mux", "x.go", 'package p\nimport "net/http"\nfunc f() { mux := http.NewServeMux(); mux.HandleFunc("/x", handler) }\n', "go-net-http", "route_declaration", 1),
    ("go_gin", "x.go", 'package p\nimport "github.com/gin-gonic/gin"\nfunc f() { r := gin.Default(); r.GET("/x", auth, handler) }\n', "gin", "route_declaration", 1),
    ("go_gin_group", "x.go", 'package p\nimport g "github.com/gin-gonic/gin"\nfunc f() { r := g.New(); api := r.Group("/v1"); api.POST("/x", handler) }\n', "gin", "route_declaration", 1),
    ("go_gin_middleware", "x.go", 'package p\nimport "github.com/gin-gonic/gin"\nfunc f() { r := gin.New(); r.Use(auth) }\n', "gin", "middleware_attachment", 1),
    ("go_gin_rebind_group", "x.go", 'package p\nimport "github.com/gin-gonic/gin"\nfunc f() { r := gin.New(); api := r.Group("/v1"); r = other; api.GET("/x", handler) }\n', "gin", "route_declaration", 0),
]


class MultiLanguage(unittest.TestCase):
    def run_tool(self, path: str, source: str | bytes, *args: str, ok: bool = True) -> dict:
        raw = source.encode() if isinstance(source, str) else source
        result = subprocess.run([BINARY, "--path", path, "--limit", "200", *args], input=raw, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0 if ok else 2, result.stdout.decode("utf-8", "replace") + result.stderr.decode("utf-8", "replace"))
        return json.loads(result.stdout)

    @staticmethod
    def models(data: dict, framework: str | None = None, role: str | None = None) -> list[dict]:
        return [f["framework_model"] for f in data["facts"] if "framework_model" in f
                and (framework is None or f["framework_model"]["framework"] == framework)
                and (role is None or f["framework_model"]["role"] == role)]

    @staticmethod
    def calls(data: dict, name: str) -> list[dict]:
        return [f for f in data["facts"] if f["kind"] == "call_site" and f.get("name", {}).get("text_prefix") == name]

    def assert_spans(self, value, raw: bytes):
        if isinstance(value, dict):
            if "start_byte" in value:
                preview = value["text_prefix"].encode()
                exact = raw[value["start_byte"]:value["end_byte"]]
                self.assertTrue(exact.startswith(preview))
                self.assertEqual(len(preview), value["text_bytes_returned"])
                if not value["text_truncated"]:
                    self.assertEqual(exact, preview)
            for child in value.values():
                self.assert_spans(child, raw)
        elif isinstance(value, list):
            for child in value:
                self.assert_spans(child, raw)

    def test_capabilities(self):
        result = subprocess.run([BINARY, "--capabilities"], capture_output=True, timeout=10, check=True)
        data = json.loads(result.stdout)
        self.assertEqual(set(data["languages"]), set(SAMPLES))
        self.assertFalse(data["value_flow"])
        self.assertFalse(data["security_verdicts"])
        for ext in data["extensions"]:
            self.run_tool("empty" + ext, "")

    def test_arguments_are_slots_not_expanded_values(self):
        samples = [("x.py", "f(1, key=2, *args, **kwargs)"), ("x.js", "f(1, ...args);"),
                   ("x.ts", "f(1, ...args);"), ("x.go", "package p\nfunc main() { f(1, args...) }\n")]
        for path, source in samples:
            with self.subTest(path=path):
                call = self.calls(self.run_tool(path, source), "f")[0]
                self.assertTrue(call["has_argument_expansion"])
                self.assertEqual(call["argument_count_basis"], "syntactic_slots")

    def test_handler_and_receiver_evidence(self):
        source = 'import express from "express"; const app = express(); app.get("/x", auth, handler);'
        data = self.run_tool("x.js", source)
        model = self.models(data, "express", "route_declaration")[0]
        self.assertEqual(model["handler_expression"]["text_prefix"], "handler")
        self.assertIn("express", model["import_evidence"]["text_prefix"])
        self.assertIn("express()", model["receiver_binding_evidence"]["text_prefix"])
        self.assertEqual(model["full_route_resolution"], "not_attempted")
        self.assert_spans(data, source.encode())

    def test_python_route_links_to_handler_declaration(self):
        source = 'from fastapi import FastAPI\napp = FastAPI()\n@app.get("/x")\ndef endpoint():\n    return 1\n'
        data = self.run_tool("x.py", source)
        route = next(f for f in data["facts"] if f.get("framework_model", {}).get("role") == "route_declaration")
        declaration = next(f for f in data["facts"] if f["id"] == route["enclosing_id"])
        self.assertEqual(declaration["name"]["text_prefix"], "endpoint")

    def test_syntax_errors_disable_framework_guesses(self):
        source = 'from fastapi import FastAPI\napp = FastAPI()\n@app.get("/x")\ndef broken(\n'
        data = self.run_tool("x.py", source)
        self.assertTrue(data["coverage"]["parse_has_error"])
        self.assertFalse(data["coverage"]["framework_analysis_complete"])
        self.assertEqual(self.models(data), [])

    def test_binding_budget_is_visible(self):
        source = "\n".join(f"from fastapi import FastAPI as API{i}" for i in range(257))
        data = self.run_tool("x.py", source)
        self.assertTrue(data["coverage"]["framework_bindings_limited"])
        self.assertFalse(data["coverage"]["framework_analysis_complete"])

    def test_dynamic_path_is_not_fabricated(self):
        source = 'import express from "express"; const app = express(); app.get(prefix + suffix, handler);'
        model = self.models(self.run_tool("x.js", source))[0]
        self.assertEqual(model["path_expression"]["text_prefix"], "prefix + suffix")
        self.assertEqual(model["full_route_resolution"], "not_attempted")

    def test_comment_and_string_are_not_frameworks(self):
        sources = [("x.py", '# from fastapi import FastAPI\ns = "app.get(\'/x\')"\n'),
                   ("x.js", '// import express from "express";\nconst s = "app.get(\'/x\', handler)";')]
        for path, source in sources:
            self.assertEqual(self.models(self.run_tool(path, source)), [])


def language_test(language, path, source):
    def test(self):
        data = self.run_tool(path, source)
        self.assertEqual(data["source"]["language"], language)
        self.assertFalse(data["coverage"]["parse_has_error"])
        self.assertEqual(data["source"]["sha256"], hashlib.sha256(source.encode()).hexdigest())
        calls = self.calls(data, "save")
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0]["id"], calls[1]["id"])
        self.assertEqual([f["arguments"][0]["location"]["text_prefix"] for f in calls], ["input", '"fixed"'])
        many = self.calls(data, "many")[0]
        self.assertEqual(many["argument_total"], 9)
        self.assertEqual(len(many["arguments"]), 9)
        self.assert_spans(data, source.encode())
        selected = self.run_tool(path, source, "--fact-id", many["id"], "--expect-analysis", data["analysis_id"])
        self.assertEqual(selected["facts"], [many])
        self.assertEqual(self.run_tool(path, source), data)
        error = self.run_tool(path, source + "\n", "--expect-analysis", data["analysis_id"], ok=False)
        self.assertEqual(error["error"]["code"], "analysis_mismatch")
    return test


def framework_test(path, source, framework, role, count):
    def test(self):
        data = self.run_tool(path, source)
        self.assertFalse(data["coverage"]["parse_has_error"], json.dumps(data))
        matches = self.models(data, framework, role)
        self.assertEqual(len(matches), count, json.dumps(data, ensure_ascii=False))
        self.assert_spans(data, source.encode())
        for model in matches:
            self.assertEqual(model["basis"], "import_and_syntax_candidate")
            self.assertEqual(model["security_effect"], "not_evaluated")
            self.assertEqual(model["runtime_binding"], "not_verified")
    return test


for language, (path, source) in SAMPLES.items():
    setattr(MultiLanguage, "test_language_" + language, language_test(language, path, source))
for name, path, source, framework, role, count in CASES:
    setattr(MultiLanguage, "test_framework_" + name, framework_test(path, source, framework, role, count))

if __name__ == "__main__":
    unittest.main()
