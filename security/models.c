#include "parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* These models describe declarations, not runtime reachability or protection.
 * Explicit imports and local constructor bindings are required. Ambiguous
 * rebindings suppress the model across the file rather than guessing a target. */
typedef struct {
    char local[128], canonical[256];
    sf_span name, evidence, initialization, scope;
    bool instance, has_initialization, invalid, commonjs;
    int parent;
} binding;

struct sf_models {
    sf_document *doc;
    TSNode root;
    binding bindings[SF_MAX_BINDINGS];
    size_t count;
    bool usable, require_shadowed;
};

static bool same_span(sf_span a, sf_span b) { return a.start == b.start && a.end == b.end; }
static bool contains(sf_span outer, sf_span inner) { return outer.start <= inner.start && inner.end <= outer.end; }
static bool identifier(TSNode n) {
    return sf_node_is(n, "identifier") || sf_node_is(n, "type_identifier") || sf_node_is(n, "package_identifier");
}
static bool package_allowed(const char *s) {
    static const char *const names[] = {"fastapi", "flask", "django", "django.urls", "django.contrib.auth.decorators", "django.views.decorators.csrf", "express", "@nestjs/common", "net/http", "github.com/gin-gonic/gin"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) if (strcmp(s, names[i]) == 0) return true;
    return strncmp(s, "org.springframework.web.bind.annotation.", sizeof("org.springframework.web.bind.annotation.") - 1) == 0 ||
           strncmp(s, "org.springframework.security.access.prepost.", sizeof("org.springframework.security.access.prepost.") - 1) == 0 ||
           strncmp(s, "org.springframework.security.config.annotation.method.configuration.", sizeof("org.springframework.security.config.annotation.method.configuration.") - 1) == 0;
}
static bool literal(sf_models *m, TSNode n, char *out, size_t capacity) {
    char raw[512];
    if (!sf_node_text(m->doc, n, raw, sizeof(raw))) return false;
    size_t len = strlen(raw);
    if (len < 2 || (raw[0] != '\'' && raw[0] != '"' && raw[0] != '`') || raw[len - 1] != raw[0] || len - 2 >= capacity) return false;
    for (size_t i = 1; i + 1 < len; i++) if (raw[i] == '\\' || raw[i] == '\n' || raw[i] == '\r' || raw[i] == '$') return false;
    memcpy(out, raw + 1, len - 2); out[len - 2] = 0;
    return true;
}
static bool join(char *out, size_t size, const char *a, const char *b) {
    int n = snprintf(out, size, "%s%s%s", a, b[0] ? "." : "", b);
    return n >= 0 && (size_t)n < size;
}
static binding *add_binding(sf_models *m, TSNode name, const char *canonical, TSNode evidence) {
    char local[128];
    if (!sf_node_text(m->doc, name, local, sizeof(local)) || !local[0] || strcmp(local, "_") == 0 || strcmp(local, ".") == 0) return NULL;
    if (strlen(canonical) >= sizeof(m->bindings[0].canonical)) return NULL;
    sf_span position = sf_location(name);
    for (size_t i = 0; i < m->count; i++)
        if (same_span(m->bindings[i].name, position)) return &m->bindings[i];
    if (m->count >= SF_MAX_BINDINGS) { m->doc->framework_bindings_limited = true; return NULL; }
    binding *b = &m->bindings[m->count++]; b->parent = -1;
    strcpy(b->local, local); strcpy(b->canonical, canonical);
    b->name = position; b->evidence = sf_location(evidence); b->scope = sf_location(m->root);
    for (size_t i = 0; i + 1 < m->count; i++) if (strcmp(m->bindings[i].local, local) == 0) { b->invalid = true; m->bindings[i].invalid = true; }
    return b;
}
static binding *lookup(sf_models *m, const char *name, sf_span site) {
    for (size_t i = 0; i < m->count; i++) {
        binding *b = &m->bindings[i];
        if (!b->invalid && strcmp(name, b->local) == 0 && contains(b->scope, site) &&
            (!b->has_initialization || b->initialization.start < site.start)) return b;
    }
    return NULL;
}
static binding *resolve(sf_models *m, TSNode target, char *canonical, size_t capacity) {
    char value[384], local[128];
    if (!sf_node_text(m->doc, target, value, sizeof(value))) return NULL;
    const char *dot = strchr(value, '.');
    size_t length = dot ? (size_t)(dot - value) : strlen(value);
    if (!length || length >= sizeof(local)) return NULL;
    memcpy(local, value, length); local[length] = 0;
    binding *b = lookup(m, local, sf_location(target));
    if (!b || !join(canonical, capacity, b->canonical, dot ? dot + 1 : "")) return NULL;
    return b;
}
static TSNode argument(TSNode call, uint32_t index) {
    TSNode args = sf_field(call, "arguments");
    if (ts_node_is_null(args)) return (TSNode){0};
    TSNode found = (TSNode){0}; uint32_t slot = 0;
    TSTreeCursor cursor = ts_tree_cursor_new(args);
    if (ts_tree_cursor_goto_first_child(&cursor)) {
        do {
            TSNode n = ts_tree_cursor_current_node(&cursor);
            if (!ts_node_is_named(n) || sf_node_is(n, "comment") || sf_node_is(n, "line_comment") || sf_node_is(n, "block_comment")) continue;
            if (slot++ == index) { found = n; break; }
        } while (ts_tree_cursor_goto_next_sibling(&cursor));
    }
    ts_tree_cursor_delete(&cursor);
    return found;
}

static TSNode annotation_path(sf_models *m, TSNode node) {
    TSNode args = sf_field(node, "arguments");
    for (uint32_t i = 0; !ts_node_is_null(args) && i < ts_node_named_child_count(args); i++) {
        TSNode child = ts_node_named_child(args, i);
        if (sf_node_is(child, "element_value_pair")) {
            char key[64];
            if (sf_node_text(m->doc, sf_field(child, "key"), key, sizeof(key)) &&
                (strcmp(key, "path") == 0 || strcmp(key, "value") == 0)) return sf_field(child, "value");
        } else if (sf_node_is(child, "string_literal") || sf_node_is(child, "element_value_array_initializer")) return child;
    }
    return (TSNode){0};
}
static TSNode route_path(sf_models *m, TSNode call) {
    TSNode first = argument(call, 0);
    if (!sf_node_is(first, "keyword_argument")) return first;
    TSNode args = sf_field(call, "arguments");
    for (uint32_t i = 0; i < ts_node_named_child_count(args); i++) {
        TSNode child = ts_node_named_child(args, i);
        char key[64];
        if (sf_node_is(child, "keyword_argument") && sf_node_text(m->doc, sf_field(child, "name"), key, sizeof(key)) &&
            (strcmp(key, "path") == 0 || strcmp(key, "rule") == 0)) return sf_field(child, "value");
    }
    return (TSNode){0};
}
static void java_import(sf_models *m, TSNode node) {
    TSNode name = ts_node_named_child(node, 0);
    char canonical[256];
    if (!sf_node_text(m->doc, name, canonical, sizeof(canonical)) || !package_allowed(canonical)) return;
    /* Wildcards and static imports do not prove the annotation's identity. */
    for (uint32_t i = 0; i < ts_node_child_count(node); i++)
        if (sf_node_is(ts_node_child(node, i), "asterisk") || sf_node_is(ts_node_child(node, i), "static")) return;
    TSNode leaf = sf_field(name, "name");
    if (ts_node_is_null(leaf)) leaf = ts_node_named_child(name, ts_node_named_child_count(name) - 1);
    if (identifier(leaf)) add_binding(m, leaf, canonical, node);
}
static void python_import(sf_models *m, TSNode node) {
    bool from = sf_node_is(node, "import_from_statement");
    TSNode module = sf_field(node, "module_name");
    char package[256] = "";
    if (from && (!sf_node_text(m->doc, module, package, sizeof(package)) || !package_allowed(package))) return;
    for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
        TSNode item = ts_node_named_child(node, i);
        if (!ts_node_is_null(module) && same_span(sf_location(item), sf_location(module))) continue;
        TSNode name = item, alias = (TSNode){0};
        if (sf_node_is(item, "aliased_import")) { name = sf_field(item, "name"); alias = sf_field(item, "alias"); }
        char imported[256], canonical[256];
        if (!sf_node_text(m->doc, name, imported, sizeof(imported))) continue;
        if (from) { if (!join(canonical, sizeof(canonical), package, imported)) continue; }
        else { if (!package_allowed(imported)) continue; strcpy(canonical, imported); }
        if (ts_node_is_null(alias)) {
            alias = name;
            if (!from && strchr(imported, '.')) {
                alias = ts_node_named_child(name, 0);
                char *dot = strchr(canonical, '.'); if (dot) *dot = 0;
            }
        }
        add_binding(m, alias, canonical, node);
    }
}
static void js_import_clause(sf_models *m, TSNode clause, const char *package, TSNode evidence) {
    for (uint32_t i = 0; i < ts_node_named_child_count(clause); i++) {
        TSNode item = ts_node_named_child(clause, i);
        if (identifier(item)) add_binding(m, item, package, evidence);
        else if (sf_node_is(item, "namespace_import")) add_binding(m, ts_node_named_child(item, 0), package, evidence);
        else if (sf_node_is(item, "named_imports")) {
            for (uint32_t j = 0; j < ts_node_named_child_count(item); j++) {
                TSNode spec = ts_node_named_child(item, j), name = sf_field(spec, "name"), alias = sf_field(spec, "alias");
                char imported[128], canonical[256];
                if (sf_node_text(m->doc, name, imported, sizeof(imported)) && join(canonical, sizeof(canonical), package, imported))
                    add_binding(m, ts_node_is_null(alias) ? name : alias, canonical, evidence);
            }
        }
    }
}
static bool imports(TSNode node, void *opaque) {
    sf_models *m = opaque;
    const char *lang = m->doc->language;
    if (strcmp(lang, "java") == 0 && sf_node_is(node, "import_declaration")) java_import(m, node);
    else if (strcmp(lang, "python") == 0 && (sf_node_is(node, "import_statement") || sf_node_is(node, "import_from_statement"))) python_import(m, node);
    else if (strcmp(lang, "go") == 0 && sf_node_is(node, "import_spec")) {
        char package[256]; TSNode path = sf_field(node, "path"), name = sf_field(node, "name");
        if (literal(m, path, package, sizeof(package)) && package_allowed(package)) {
            if (!ts_node_is_null(name)) add_binding(m, name, package, node);
            else {
                const char *slash = strrchr(package, '/'); const char *leaf = slash ? slash + 1 : package;
                size_t leaf_len = strlen(leaf);
                if (leaf_len >= sizeof(m->bindings[0].local)) return true;
                /* The default package spelling is a source slice inside the literal. */
                if (m->count >= SF_MAX_BINDINGS) m->doc->framework_bindings_limited = true;
                else {
                    binding *b = &m->bindings[m->count++]; b->parent = -1;
                    memcpy(b->local, leaf, leaf_len + 1); strcpy(b->canonical, package);
                    b->name = sf_location(path); b->evidence = sf_location(node); b->scope = sf_location(m->root);
                    for (size_t k = 0; k + 1 < m->count; k++) if (strcmp(m->bindings[k].local, b->local) == 0) { b->invalid = true; m->bindings[k].invalid = true; }
                }
            }
        }
    } else if (sf_node_is(node, "import_statement") && strcmp(lang, "python") != 0) {
        char package[256];
        if (literal(m, sf_field(node, "source"), package, sizeof(package)) && package_allowed(package))
            for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
                TSNode clause = ts_node_named_child(node, i);
                if (sf_node_is(clause, "import_clause")) js_import_clause(m, clause, package, node);
            }
    } else if (sf_node_is(node, "variable_declarator") && strcmp(lang, "java") != 0) {
        TSNode value = sf_field(node, "value"), name = sf_field(node, "name");
        char target[128], package[256];
        if (identifier(name) && sf_node_is(value, "call_expression") &&
            sf_node_text(m->doc, sf_call_target(value), target, sizeof(target)) && strcmp(target, "require") == 0 &&
            literal(m, argument(value, 0), package, sizeof(package)) && strcmp(package, "express") == 0 && ts_node_is_null(argument(value, 1))) {
            binding *b = add_binding(m, name, package, node); if (b) b->commonjs = true;
        }
    }
    return !m->doc->framework_bindings_limited;
}

static TSNode assignment_name(TSNode n, TSNode *value) {
    TSNode name = (TSNode){0}; *value = (TSNode){0};
    if (sf_node_is(n, "assignment") || sf_node_is(n, "short_var_declaration") || sf_node_is(n, "assignment_statement") || sf_node_is(n, "assignment_expression") || sf_node_is(n, "augmented_assignment_expression") || sf_node_is(n, "augmented_assignment")) {
        name = sf_single(sf_field(n, "left")); *value = sf_single(sf_field(n, "right"));
    } else if (sf_node_is(n, "variable_declarator") || sf_node_is(n, "var_spec")) {
        name = sf_field(n, "name"); *value = sf_single(sf_field(n, "value"));
    }
    return name;
}
static const char *instance_type(const char *s) {
    if (strcmp(s, "fastapi.FastAPI") == 0 || strcmp(s, "fastapi.APIRouter") == 0 || strcmp(s, "flask.Flask") == 0 || strcmp(s, "flask.Blueprint") == 0) return s;
    if (strcmp(s, "express") == 0 || strcmp(s, "express.Router") == 0) return "express.Router";
    if (strcmp(s, "net/http.NewServeMux") == 0) return "net/http.ServeMux";
    if (strcmp(s, "github.com/gin-gonic/gin.New") == 0 || strcmp(s, "github.com/gin-gonic/gin.Default") == 0 || strcmp(s, "gin.Engine.Group") == 0) return "gin.Engine";
    return NULL;
}
static bool factories(TSNode node, void *opaque) {
    sf_models *m = opaque;
    TSNode value, name = assignment_name(node, &value);
    if (!identifier(name) || ts_node_is_null(value)) return true;
    char canonical[384];
    binding *owner = resolve(m, sf_call_target(value), canonical, sizeof(canonical));
    const char *instance = owner ? instance_type(canonical) : NULL;
    if (!instance) return true;
    char saved[256];
    size_t instance_len = strlen(instance);
    if (instance_len >= sizeof(saved)) return true;
    memcpy(saved, instance, instance_len + 1);
    sf_span import_evidence = owner->evidence;
    int parent_index = (int)(owner - m->bindings);
    binding *b = add_binding(m, name, saved, node);
    if (b) {
        b->parent = parent_index; b->instance = true; b->has_initialization = true; b->initialization = sf_location(node); b->evidence = import_evidence;
        TSNode parent = ts_node_parent(node);
        unsigned depth = 0;
        while (!ts_node_is_null(parent) && depth++ < 128) {
            if (sf_node_is(parent, "block") || sf_node_is(parent, "statement_block")) { b->scope = sf_location(parent); break; }
            parent = ts_node_parent(parent);
        }
        if (!ts_node_is_null(parent) && depth >= 128) b->invalid = true;
    }
    return !m->doc->framework_bindings_limited;
}
static void invalidate_name(sf_models *m, TSNode name) {
    char value[128];
    if (!identifier(name) || !sf_node_text(m->doc, name, value, sizeof(value))) return;
    if (strcmp(value, "require") == 0) m->require_shadowed = true;
    for (size_t i = 0; i < m->count; i++)
        if (strcmp(m->bindings[i].local, value) == 0 && !same_span(m->bindings[i].name, sf_location(name))) m->bindings[i].invalid = true;
}
static bool collisions(TSNode node, void *opaque) {
    sf_models *m = opaque;
    TSNode value, name = assignment_name(node, &value);
    if (!ts_node_is_null(name)) invalidate_name(m, name);
    static const char *const kinds[] = {"function_definition", "class_definition", "function_declaration", "class_declaration", "annotation_type_declaration", "formal_parameter", "parameter_declaration", "default_parameter", "typed_default_parameter", "type_spec", "catch_formal_parameter"};
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) if (sf_node_is(node, kinds[i])) invalidate_name(m, sf_field(node, "name"));
    if (sf_node_is(node, "required_parameter") || sf_node_is(node, "optional_parameter")) invalidate_name(m, sf_field(node, "pattern"));
    TSNode parent = ts_node_parent(node);
    if (identifier(node) && sf_node_is(parent, "arrow_function") && same_span(sf_location(node), sf_location(sf_field(parent, "parameter")))) invalidate_name(m, node);
    if (identifier(node) && (sf_node_is(parent, "parameters") || sf_node_is(parent, "formal_parameters") || sf_node_is(parent, "lambda_parameters") || sf_node_is(parent, "typed_parameter") || sf_node_is(parent, "rest_pattern") || sf_node_is(parent, "list_splat_pattern") || sf_node_is(parent, "dictionary_splat_pattern"))) invalidate_name(m, node);
    return true;
}

sf_models *sf_models_new(sf_document *doc, TSNode root) {
    sf_models *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->doc = doc; m->root = root;
    size_t visited;
    m->usable = !doc->parse_has_error && sf_walk(root, imports, m, &visited) &&
                sf_walk(root, factories, m, &visited) && sf_walk(root, collisions, m, &visited);
    if (m->require_shadowed) for (size_t i = 0; i < m->count; i++) if (m->bindings[i].commonjs) m->bindings[i].invalid = true;
    /* A constructor derived from a later-invalidated import must not survive. */
    for (size_t i = 0; i < m->count; i++) if (m->bindings[i].instance)
        for (size_t j = 0; j < m->count; j++)
            if (m->bindings[j].invalid && !m->bindings[j].instance && same_span(m->bindings[i].evidence, m->bindings[j].evidence)) m->bindings[i].invalid = true;
    for (size_t i = 0; i < m->count; i++) {
        int parent = m->bindings[i].parent;
        if (parent >= 0 && (size_t)parent < i && m->bindings[parent].invalid) m->bindings[i].invalid = true;
    }
    doc->framework_analysis_complete = m->usable;
    return m;
}
void sf_models_free(sf_models *m) { free(m); }

static const char *http_method(const char *name) {
    static const char *const lower[] = {"get", "post", "put", "patch", "delete", "head", "options", "all"};
    static const char *const upper[] = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL"};
    for (size_t i = 0; i < sizeof(lower) / sizeof(lower[0]); i++) if (strcmp(name, lower[i]) == 0 || strcmp(name, upper[i]) == 0) return upper[i];
    return NULL;
}
static bool decorated(TSNode node) {
    for (unsigned i = 0; i < 4 && !ts_node_is_null(node); i++, node = ts_node_parent(node)) if (sf_node_is(node, "decorator")) return true;
    return false;
}
static void mark(sf_fact *f, binding *b, const char *framework, const char *role, const char *rule) {
    f->framework = framework; f->role = role; f->rule_id = rule;
    if (b) {
        f->has_import_evidence = true; f->import_evidence = b->evidence;
        f->has_binding_evidence = b->has_initialization; f->binding_evidence = b->initialization;
    }
}
static void path_and_handler(sf_fact *f, TSNode path, TSNode handler) {
    if (!ts_node_is_null(path)) { f->has_path_expression = true; f->path_expression = sf_location(path); }
    if (!ts_node_is_null(handler)) { f->has_handler = true; f->handler = sf_location(handler); }
}
static void annotation_model(sf_models *m, sf_fact *f, TSNode node) {
    char canonical[384]; TSNode name = sf_field(node, "name");
    binding *b = resolve(m, name, canonical, sizeof(canonical));
    if (!b) {
        if (!sf_node_text(m->doc, name, canonical, sizeof(canonical)) || !package_allowed(canonical)) return;
    }
    static const char *const routes[] = {"GetMapping", "PostMapping", "PutMapping", "PatchMapping", "DeleteMapping", "RequestMapping"};
    static const char *const methods[] = {"GET", "POST", "PUT", "PATCH", "DELETE", "DECLARED_IN_ARGUMENTS"};
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        char expected[256]; join(expected, sizeof(expected), "org.springframework.web.bind.annotation", routes[i]);
        if (strcmp(canonical, expected) == 0) {
            bool prefix = f->has_enclosing && (strcmp(f->enclosing_kind, "class_declaration") == 0 || strcmp(f->enclosing_kind, "interface_declaration") == 0);
            mark(f, b, "spring-mvc", prefix ? "route_prefix_declaration" : "route_declaration", "spring.mapping.v1");
            f->http_method = methods[i]; path_and_handler(f, annotation_path(m, node), (TSNode){0}); return;
        }
    }
    static const char *const inputs[] = {"RequestParam", "RequestBody", "PathVariable", "RequestHeader", "CookieValue", "RequestPart", "ModelAttribute"};
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        char expected[256]; join(expected, sizeof(expected), "org.springframework.web.bind.annotation", inputs[i]);
        if (strcmp(canonical, expected) == 0) { mark(f, b, "spring-mvc", "request_input_declaration", "spring.input.v1"); return; }
    }
    static const char *const controls[] = {"PreAuthorize", "PostAuthorize", "PreFilter", "PostFilter"};
    for (size_t i = 0; i < sizeof(controls) / sizeof(controls[0]); i++) {
        char expected[256]; join(expected, sizeof(expected), "org.springframework.security.access.prepost", controls[i]);
        if (strcmp(canonical, expected) == 0) { mark(f, b, "spring-security", "authorization_declaration", "spring.method-security.v1"); return; }
    }
    if (strcmp(canonical, "org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity") == 0)
        mark(f, b, "spring-security", "security_configuration_declaration", "spring.method-security-enable.v1");
}

void sf_models_apply(sf_models *m, sf_fact *f, TSNode node) {
    if (!m || !m->usable || f->syntax_has_error) return;
    if (strcmp(f->kind, "annotation") == 0) { annotation_model(m, f, node); return; }
    bool decorator = strcmp(f->kind, "decorator") == 0;
    if (strcmp(f->kind, "call_site") != 0 && !decorator) return;
    TSNode target = decorator ? ts_node_named_child(node, 0) : sf_call_target(node);
    if (decorator && (sf_node_is(target, "call") || sf_node_is(target, "call_expression"))) return;
    char canonical[384]; binding *b = resolve(m, target, canonical, sizeof(canonical));
    if (!b) return;
    const char *member = strrchr(canonical, '.'); member = member ? member + 1 : canonical;
    if (!b->instance && (strcmp(canonical, "fastapi.Depends") == 0 || strcmp(canonical, "fastapi.Security") == 0)) {
        mark(f, b, "fastapi", strcmp(member, "Depends") == 0 ? "dependency_declaration" : "security_dependency_declaration", "fastapi.dependency.v1"); return;
    }
    if (!b->instance && strncmp(canonical, "fastapi.", 8) == 0) {
        static const char *const inputs[] = {"Query", "Path", "Body", "Header", "Cookie", "Form", "File"};
        for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) if (strcmp(member, inputs[i]) == 0) {
            mark(f, b, "fastapi", "request_input_declaration", "fastapi.input.v1"); return;
        }
    }
    if (b->instance && (strncmp(b->canonical, "fastapi.", 8) == 0 || strncmp(b->canonical, "flask.", 6) == 0)) {
        const char *fw = b->canonical[1] == 'a' ? "fastapi" : "flask";
        const char *method = http_method(member);
        bool registration = strcmp(member, "add_api_route") == 0;
        if ((decorated(node) || registration) && (method || strcmp(member, "route") == 0 || strcmp(member, "api_route") == 0 || registration)) {
            TSNode path = route_path(m, node);
            if (ts_node_is_null(path)) return;
            mark(f, b, fw, "route_declaration", "python.web-route.v1"); f->http_method = method ? method : "DECLARED_OR_FRAMEWORK_DEFAULT";
            path_and_handler(f, path, registration ? argument(node, 1) : (TSNode){0}); return;
        }
        if (decorated(node) && (strcmp(member, "before_request") == 0 || strcmp(member, "after_request") == 0))
            mark(f, b, fw, "request_hook_declaration", "flask.request-hook.v1");
        return;
    }
    if (!b->instance && (strcmp(canonical, "django.urls.path") == 0 || strcmp(canonical, "django.urls.re_path") == 0)) {
        mark(f, b, "django", "route_declaration", "django.url-pattern.v1"); f->http_method = "UNSPECIFIED";
        path_and_handler(f, argument(node, 0), argument(node, 1)); return;
    }
    if (!b->instance && decorated(node) && (strcmp(canonical, "django.contrib.auth.decorators.login_required") == 0 || strcmp(canonical, "django.contrib.auth.decorators.permission_required") == 0 || strcmp(canonical, "django.views.decorators.csrf.csrf_exempt") == 0)) {
        mark(f, b, "django", strcmp(member, "csrf_exempt") == 0 ? "control_exemption_declaration" : "authorization_declaration", "django.control-decorator.v1"); return;
    }
    if (b->instance && strcmp(b->canonical, "express.Router") == 0) {
        const char *method = http_method(member);
        if (method && f->argument_total >= 2) {
            mark(f, b, "express", "route_declaration", "express.route.v1"); f->http_method = method;
            path_and_handler(f, argument(node, 0), argument(node, f->argument_total - 1));
        } else if (strcmp(member, "use") == 0 && f->argument_total >= 1)
            mark(f, b, "express", "middleware_attachment", "express.middleware.v1");
        return;
    }
    if (!b->instance && decorated(node) && strncmp(canonical, "@nestjs/common.", 15) == 0) {
        if (strcmp(member, "Controller") == 0) { mark(f, b, "nestjs", "route_prefix_declaration", "nestjs.controller.v1"); path_and_handler(f, argument(node, 0), (TSNode){0}); return; }
        static const char *const verbs[] = {"Get", "Post", "Put", "Patch", "Delete", "Head", "Options", "All"};
        static const char *const methods[] = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL"};
        for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) if (strcmp(member, verbs[i]) == 0) {
            mark(f, b, "nestjs", "route_declaration", "nestjs.route.v1"); f->http_method = methods[i]; path_and_handler(f, argument(node, 0), (TSNode){0}); return;
        }
        if (strcmp(member, "UseGuards") == 0 || strcmp(member, "UseInterceptors") == 0 || strcmp(member, "UsePipes") == 0) {
            mark(f, b, "nestjs", "control_declaration", "nestjs.control.v1"); return;
        }
        static const char *const inputs[] = {"Body", "Param", "Query", "Headers", "Req", "Request", "UploadedFile", "UploadedFiles"};
        for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) if (strcmp(member, inputs[i]) == 0) { mark(f, b, "nestjs", "request_input_declaration", "nestjs.input.v1"); return; }
    }
    if (((!b->instance && strcmp(b->canonical, "net/http") == 0) || (b->instance && strcmp(b->canonical, "net/http.ServeMux") == 0)) && (strcmp(member, "HandleFunc") == 0 || strcmp(member, "Handle") == 0) && f->argument_total >= 2) {
        mark(f, b, "go-net-http", "route_declaration", "go.http-route.v1"); f->http_method = "DECLARED_IN_PATTERN_OR_UNSPECIFIED";
        path_and_handler(f, argument(node, 0), argument(node, 1)); return;
    }
    if (b->instance && strcmp(b->canonical, "gin.Engine") == 0) {
        const char *method = http_method(member);
        if ((method || strcmp(member, "Any") == 0) && f->argument_total >= 2) {
            mark(f, b, "gin", "route_declaration", "gin.route.v1"); f->http_method = method ? method : "ALL";
            path_and_handler(f, argument(node, 0), argument(node, f->argument_total - 1));
        } else if (strcmp(member, "Use") == 0 && f->argument_total >= 1) mark(f, b, "gin", "middleware_attachment", "gin.middleware.v1");
    }
}
