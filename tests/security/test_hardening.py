"""Binding and framework-shape regression tests against the real parser binary."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
# name, path, source, framework, role, expected count
CASES = [
    ("python_local_import_does_not_escape", "x.py", 'def setup():\n    from fastapi import FastAPI\napp = FastAPI()\n@app.get("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_local_import_works_inside", "x.py", 'def setup():\n    from fastapi import FastAPI\n    app = FastAPI()\n    @app.get("/x")\n    def endpoint(): pass\n', "fastapi", "route_declaration", 1),
    ("python_sibling_scope", "x.py", 'def setup():\n    from fastapi import Depends\ndef endpoint(x=Depends(auth)): pass\n', "fastapi", "dependency_declaration", 0),
    ("python_import_after_use", "x.py", 'app = FastAPI()\nfrom fastapi import FastAPI\n@app.get("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_foreign_import_rebind", "x.py", 'from fastapi import FastAPI\nfrom custom import FastAPI\napp = FastAPI()\n@app.get("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_foreign_import_alias", "x.py", 'from fastapi import FastAPI as API\nfrom custom import Factory as API\napp = API()\n@app.get("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_namespace_rebind", "x.py", 'import fastapi as fa\nimport custom as fa\napp = fa.FastAPI()\n@app.get("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_star_import", "x.py", 'from fastapi import FastAPI\nfrom custom import *\napp = FastAPI()\n@app.get("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_tuple_rebind", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\napp, other = pair\n@app.get("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_loop_rebind", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\nfor app in items:\n    @app.get("/x")\n    def endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_delete_binding", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\ndel app\n@app.get("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_nested_receiver", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\n@app.database.get("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_nested_module_input", "x.py", 'import fastapi\ndef endpoint(x=fastapi.custom.Query()): pass\n', "fastapi", "request_input_declaration", 0),
    ("python_nested_decorator_call", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\n@wrapper(app.get("/x"))\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_keyword_registration", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\napp.add_api_route(endpoint=handler, path="/x")\n', "fastapi", "route_declaration", 1),
    ("python_registration_needs_handler", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\napp.add_api_route("/x")\n', "fastapi", "route_declaration", 0),
    ("python_expanded_registration", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\napp.add_api_route(*args, endpoint=handler)\n', "fastapi", "route_declaration", 0),
    ("python_case_sensitive_method", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\n@app.GET("/x")\ndef endpoint(): pass\n', "fastapi", "route_declaration", 0),
    ("python_fastapi_not_flask_hook", "x.py", 'from fastapi import FastAPI\napp = FastAPI()\n@app.before_request\ndef hook(): pass\n', "fastapi", "request_hook_declaration", 0),
    ("python_flask_not_fastapi_registration", "x.py", 'from flask import Flask\napp = Flask(__name__)\napp.add_api_route("/x", handler)\n', "flask", "route_declaration", 0),
    ("django_keyword_registration", "x.py", 'from django.urls import path\nurlpatterns = [path(view=handler, route="x/")]\n', "django", "route_declaration", 1),
    ("django_requires_handler", "x.py", 'from django.urls import path\nurlpatterns = [path("x/")]\n', "django", "route_declaration", 0),
    ("python_stub_has_no_runtime_model", "x.pyi", 'from fastapi import Depends\ndef f(x=Depends(auth)): ...\n', "fastapi", "dependency_declaration", 0),
    ("commonjs_import_after_use", "x.cjs", 'const app = express(); const express = require("express"); app.get("/x", handler);', "express", "route_declaration", 0),
    ("commonjs_import_inside_other_scope", "x.cjs", 'function setup(){ const express = require("express"); } const app = express(); app.get("/x", handler);', "express", "route_declaration", 0),
    ("commonjs_local_import_positive", "x.cjs", 'function setup(){ const express = require("express"); const app = express(); app.get("/x", handler); }', "express", "route_declaration", 1),
    ("express_nested_receiver", "x.js", 'import express from "express"; const app = express(); app.database.get("/x", handler);', "express", "route_declaration", 0),
    ("express_nested_middleware", "x.js", 'import express from "express"; const app = express(); app.database.use(auth);', "express", "middleware_attachment", 0),
    ("express_wrong_case", "x.js", 'import express from "express"; const app = express(); app.GET("/x", handler);', "express", "route_declaration", 0),
    ("express_expanded_arguments", "x.js", 'import express from "express"; const app = express(); app.get(...args, handler);', "express", "route_declaration", 0),
    ("express_destructured_rebind", "x.js", 'import express from "express"; let app = express(); ({app} = other); app.get("/x", handler);', "express", "route_declaration", 0),
    ("express_foreign_require_rebind", "x.cjs", 'var express = require("express"); var express = require("custom"); var app = express(); app.get("/x", handler);', "express", "route_declaration", 0),
    ("ts_type_only_statement", "x.ts", 'import type {Get} from "@nestjs/common"; class X { @Get("/x") f() {} }', "nestjs", "route_declaration", 0),
    ("ts_type_only_specifier", "x.ts", 'import {type Get} from "@nestjs/common"; class X { @Get("/x") f() {} }', "nestjs", "route_declaration", 0),
    ("ts_type_only_alias", "x.ts", 'import {type Get as Read} from "@nestjs/common"; class X { @Read("/x") f() {} }', "nestjs", "route_declaration", 0),
    ("ts_mixed_value_and_type", "x.ts", 'import {type Controller, Get} from "@nestjs/common"; class X { @Get("/x") f() {} }', "nestjs", "route_declaration", 1),
    ("ts_type_only_default", "x.ts", 'import type express from "express"; const app = express(); app.get("/x", handler);', "express", "route_declaration", 0),
    ("ts_foreign_same_name", "x.ts", 'import {Get} from "@nestjs/common"; import {Get} from "custom"; class X { @Get("/x") f() {} }', "nestjs", "route_declaration", 0),
    ("ts_nested_namespace", "x.ts", 'import * as nest from "@nestjs/common"; class X { @nest.custom.Get("/x") f() {} }', "nestjs", "route_declaration", 0),
    ("ts_namespace_positive", "x.ts", 'import * as nest from "@nestjs/common"; class X { @nest.Get("/x") f() {} }', "nestjs", "route_declaration", 1),
    ("ts_nested_decorator_call", "x.ts", 'import {Get} from "@nestjs/common"; class X { @wrap(Get("/x")) f() {} }', "nestjs", "route_declaration", 0),
    ("java_foreign_same_name", "X.java", 'import org.springframework.web.bind.annotation.GetMapping; import custom.GetMapping; class X { @GetMapping("/x") void f() {} }', "spring-mvc", "route_declaration", 0),
    ("go_nested_module", "x.go", 'package p\nimport "net/http"\nfunc f(){ http.custom.HandleFunc("/x", handler) }\n', "go-net-http", "route_declaration", 0),
    ("go_nested_receiver", "x.go", 'package p\nimport "github.com/gin-gonic/gin"\nfunc f(){ r := gin.New(); r.Database.GET("/x", handler) }\n', "gin", "route_declaration", 0),
    ("go_wrong_case", "x.go", 'package p\nimport "github.com/gin-gonic/gin"\nfunc f(){ r := gin.New(); r.get("/x", handler) }\n', "gin", "route_declaration", 0),
    ("go_foreign_alias", "x.go", 'package p\nimport "net/http"\nimport http "custom/http"\nfunc f(){ http.HandleFunc("/x", handler) }\n', "go-net-http", "route_declaration", 0),
]

class BindingRegression(unittest.TestCase):
    def run_case(self, case):
        _, path, source, framework, role, expected = case
        raw = source.encode("utf-8")
        result = subprocess.run([BINARY, "--path", path, "--limit", "200"], input=raw, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        data = json.loads(result.stdout)
        self.assertFalse(data["coverage"]["parse_has_error"], "a broken fixture must not hide a binding bug")
        matched = [f for f in data["facts"] if f.get("framework_model", {}).get("framework") == framework
                   and f["framework_model"]["role"] == role]
        self.assertEqual(len(matched), expected, json.dumps(data, ensure_ascii=False))
        self.assertTrue(data["facts"], "raw facts must survive model suppression")
        for fact in matched:
            model = fact["framework_model"]
            self.assertEqual(model["security_effect"], "not_evaluated")
            self.assertEqual(model["runtime_binding"], "not_verified")
            for field in ("import_evidence", "receiver_binding_evidence", "path_expression", "handler_expression"):
                if field in model:
                    loc = model[field]
                    self.assertTrue(raw[loc["start_byte"]:loc["end_byte"]].startswith(loc["text_prefix"].encode()))
        if case[0] in ("python_keyword_registration", "django_keyword_registration"):
            self.assertEqual(matched[0]["framework_model"]["handler_expression"]["text_prefix"], "handler")

for case in CASES:
    def test(self, case=case):
        self.run_case(case)
    setattr(BindingRegression, "test_" + case[0], test)

if __name__ == "__main__":
    unittest.main()
