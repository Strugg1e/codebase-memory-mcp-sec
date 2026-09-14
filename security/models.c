#include "parser.h"
#include "java_models.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Models describe source declarations, never runtime protection. Unknown imports
 * still participate in name binding: ignoring them can resurrect a stale model. */
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
    bool usable, require_shadowed, ambiguous_import;
};

static bool same_span(sf_span a, sf_span b) { return a.start == b.start && a.end == b.end; }
static bool contains(sf_span outer, sf_span inner) { return outer.start <= inner.start && inner.end <= outer.end; }
static bool identifier(TSNode n) {
    return sf_node_is(n, "identifier") || sf_node_is(n, "type_identifier") || sf_node_is(n, "package_identifier");
}
static bool package_allowed(const char *s) {
    static const char *const names[] = {"fastapi", "flask", "django", "django.urls", "django.contrib.auth.decorators", "django.views.decorators.csrf", "express", "fastify", "@nestjs/common", "net/http", "github.com/gin-gonic/gin", "github.com/go-chi/chi/v5", "github.com/labstack/echo/v4", "rest_framework.decorators", "fastapi.security"};
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
static bool keyword(TSNode node, const char *word) {
    /* Direct anonymous tokens only: an identifier literally named 'type' is not
     * the TypeScript type-only modifier. Comments and nested expressions do not count. */
    for (uint32_t i = 0; i < ts_node_child_count(node); i++) {
        TSNode child = ts_node_child(node, i);
        if (!ts_node_is_named(child) && sf_node_is(child, word)) return true;
    }
    return false;
}
static sf_span local_scope(sf_models *m, TSNode node) {
    TSNode parent = ts_node_parent(node);
    for (unsigned depth = 0; !ts_node_is_null(parent) && depth < 128; depth++, parent = ts_node_parent(parent)) {
        if (sf_node_is(parent, "block") || sf_node_is(parent, "statement_block") || sf_node_is(parent, "class_body"))
            return sf_location(parent);
    }
    if (!ts_node_is_null(parent)) {
        m->doc->framework_bindings_limited = true;
        return (sf_span){0};
    }
    return sf_location(m->root);
}
static binding *add_binding(sf_models *m, TSNode name, const char *canonical, TSNode evidence) {
    char local[128];
    if (!sf_node_text(m->doc, name, local, sizeof(local)) || !local[0]) {
        m->doc->framework_bindings_limited = true; return NULL;
    }
    if (strcmp(local, "_") == 0) return NULL;
    if (strcmp(local, ".") == 0) { m->ambiguous_import = true; return NULL; }
    if (strlen(canonical) >= sizeof(m->bindings[0].canonical)) {
        m->doc->framework_bindings_limited = true; return NULL;
    }
    if (strcmp(local, "require") == 0) m->require_shadowed = true;
    sf_span position = sf_location(name);
    for (size_t i = 0; i < m->count; i++)
        if (same_span(m->bindings[i].name, position)) return &m->bindings[i];
    if (m->count >= SF_MAX_BINDINGS) { m->doc->framework_bindings_limited = true; return NULL; }
    binding *b = &m->bindings[m->count++]; b->parent = -1;
    strcpy(b->local, local); strcpy(b->canonical, canonical);
    b->name = position; b->evidence = sf_location(evidence); b->scope = local_scope(m, evidence);
    /* Python imports execute in source order. This is deliberately more
     * conservative than a complete interpreter for late-bound function bodies. */
    if (strcmp(m->doc->language, "python") == 0) {
        b->has_initialization = true; b->initialization = sf_location(evidence);
    }
    for (size_t i = 0; i + 1 < m->count; i++) if (strcmp(m->bindings[i].local, local) == 0) {
        b->invalid = true; m->bindings[i].invalid = true;
    }
    return b;
}
static binding *lookup(sf_models *m, const char *name, sf_span site) {
    for (size_t i = 0; i < m->count; i++) {
        binding *b = &m->bindings[i];
        if (!b->invalid && strcmp(name, b->local) == 0 && contains(b->scope, site) &&
            (!b->has_initialization || b->initialization.end <= site.start)) return b;
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
    /* An instance member must be direct. app.database.get is not app.get.
     * Module namespaces may contain dots, but each model must match the full name. */
    if (!b || (b->instance && (!dot || strchr(dot + 1, '.'))) ||
        !join(canonical, capacity, b->canonical, dot ? dot + 1 : "")) return NULL;
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
static TSNode python_argument(sf_models *m, TSNode call, uint32_t index, const char *key, const char *alternate) {
    TSNode first = argument(call, index);
    if (!ts_node_is_null(first) && !sf_node_is(first, "keyword_argument")) return first;
    TSNode args = sf_field(call, "arguments"), found = (TSNode){0};
    if (ts_node_is_null(args)) return found;
    TSTreeCursor cursor = ts_tree_cursor_new(args);
    if (ts_tree_cursor_goto_first_child(&cursor)) do {
        TSNode child = ts_tree_cursor_current_node(&cursor);
        char name[64];
        if (sf_node_is(child, "keyword_argument") && sf_node_text(m->doc, sf_field(child, "name"), name, sizeof(name)) &&
            (strcmp(name, key) == 0 || (alternate && strcmp(name, alternate) == 0))) {
            found = sf_field(child, "value"); break;
        }
    } while (ts_tree_cursor_goto_next_sibling(&cursor));
    ts_tree_cursor_delete(&cursor);
    return found;
}
static void java_import(sf_models *m, TSNode node) {
    TSNode name = ts_node_named_child(node, 0);
    char canonical[256];
    if (!sf_node_text(m->doc, name, canonical, sizeof(canonical))) { m->ambiguous_import = true; return; }
    for (uint32_t i = 0; i < ts_node_child_count(node); i++)
        if (sf_node_is(ts_node_child(node, i), "asterisk") || sf_node_is(ts_node_child(node, i), "static")) return;
    TSNode leaf = sf_field(name, "name");
    uint32_t count = ts_node_named_child_count(name);
    if (ts_node_is_null(leaf) && count) leaf = ts_node_named_child(name, count - 1);
    if (identifier(leaf)) add_binding(m, leaf, canonical, node);
}
static void python_import(sf_models *m, TSNode node) {
    bool from = sf_node_is(node, "import_from_statement");
    TSNode module = sf_field(node, "module_name");
    char package[256] = "";
    if (from && !sf_node_text(m->doc, module, package, sizeof(package))) { m->ambiguous_import = true; return; }
    for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
        TSNode item = ts_node_named_child(node, i);
        if (sf_node_is(item, "wildcard_import")) { m->ambiguous_import = true; continue; }
        if (!ts_node_is_null(module) && same_span(sf_location(item), sf_location(module))) continue;
        TSNode name = item, alias = (TSNode){0};
        if (sf_node_is(item, "aliased_import")) { name = sf_field(item, "name"); alias = sf_field(item, "alias"); }
        char imported[256], canonical[256];
        if (!sf_node_text(m->doc, name, imported, sizeof(imported))) { m->ambiguous_import = true; continue; }
        if (from) { if (!join(canonical, sizeof(canonical), package, imported)) { m->ambiguous_import = true; continue; } }
        else strcpy(canonical, imported);
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
    bool type_only = keyword(evidence, "type");
    for (uint32_t i = 0; i < ts_node_named_child_count(clause); i++) {
        TSNode item = ts_node_named_child(clause, i);
        binding *b = NULL;
        if (identifier(item)) b = add_binding(m, item, package, evidence);
        else if (sf_node_is(item, "namespace_import")) b = add_binding(m, ts_node_named_child(item, 0), package, evidence);
        else if (sf_node_is(item, "named_imports")) {
            for (uint32_t j = 0; j < ts_node_named_child_count(item); j++) {
                TSNode spec = ts_node_named_child(item, j), name = sf_field(spec, "name"), alias = sf_field(spec, "alias");
                if (!sf_node_is(spec, "import_specifier")) continue;
                char imported[128], canonical[256];
                if (!sf_node_text(m->doc, name, imported, sizeof(imported)) || !join(canonical, sizeof(canonical), package, imported)) {
                    m->ambiguous_import = true; continue;
                }
                binding *named = add_binding(m, ts_node_is_null(alias) ? name : alias, canonical, evidence);
                if (named && (type_only || keyword(spec, "type"))) named->invalid = true;
            }
        }
        if (b && type_only) b->invalid = true;
    }
}
static bool imports(TSNode node, void *opaque) {
    sf_models *m = opaque;
    const char *lang = m->doc->language;
    if (strcmp(lang, "java") == 0 && sf_node_is(node, "import_declaration")) java_import(m, node);
    else if (strcmp(lang, "python") == 0 && (sf_node_is(node, "import_statement") || sf_node_is(node, "import_from_statement"))) python_import(m, node);
    else if (strcmp(lang, "go") == 0 && sf_node_is(node, "import_spec")) {
        char package[256]; TSNode path = sf_field(node, "path"), name = sf_field(node, "name");
        if (!literal(m, path, package, sizeof(package))) { m->ambiguous_import = true; return true; }
        if (!ts_node_is_null(name)) add_binding(m, name, package, node);
        else if (package_allowed(package)) {
            const char *slash = strrchr(package, '/'); const char *leaf = slash ? slash + 1 : package;
            if (!strcmp(package, "github.com/go-chi/chi/v5")) leaf = "chi";
            if (!strcmp(package, "github.com/labstack/echo/v4")) leaf = "echo";
            size_t leaf_len = strlen(leaf);
            if (leaf_len >= sizeof(m->bindings[0].local) || m->count >= SF_MAX_BINDINGS) m->doc->framework_bindings_limited = true;
            else {
                binding *b = &m->bindings[m->count++]; b->parent = -1;
                memcpy(b->local, leaf, leaf_len + 1); strcpy(b->canonical, package);
                b->name = sf_location(path); b->evidence = sf_location(node); b->scope = sf_location(m->root);
                for (size_t k = 0; k + 1 < m->count; k++) if (strcmp(m->bindings[k].local, b->local) == 0) { b->invalid = true; m->bindings[k].invalid = true; }
            }
        }
    } else if (sf_node_is(node, "import_statement") && strcmp(lang, "python") != 0) {
        char package[256];
        if (!literal(m, sf_field(node, "source"), package, sizeof(package))) { m->ambiguous_import = true; return true; }
        for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
            TSNode clause = ts_node_named_child(node, i);
            if (sf_node_is(clause, "import_clause")) js_import_clause(m, clause, package, node);
        }
    } else if (sf_node_is(node, "variable_declarator") && strcmp(lang, "java") != 0) {
        TSNode value = sf_field(node, "value"), name = sf_field(node, "name");
        char target[128], package[256];
        TSNode factory = sf_call_target(value);
        if (identifier(name) && sf_node_is(value, "call_expression") && sf_node_is(factory, "call_expression") &&
            sf_node_text(m->doc, sf_call_target(factory), target, sizeof(target)) && !strcmp(target, "require") &&
            literal(m, argument(factory, 0), package, sizeof(package)) && ts_node_is_null(argument(factory, 1)) &&
            (!strcmp(package, "fastify") || !strcmp(package, "express"))) {
            binding *b = add_binding(m, name, !strcmp(package, "fastify") ? "fastify.Instance" : "express.Router", factory);
            if (b) { b->instance = true; b->commonjs = true; b->has_initialization = true; b->initialization = sf_location(node); }
        }
        if (identifier(name) && sf_node_is(value, "call_expression") &&
            sf_node_text(m->doc, sf_call_target(value), target, sizeof(target)) && strcmp(target, "require") == 0 &&
            literal(m, argument(value, 0), package, sizeof(package)) && ts_node_is_null(argument(value, 1))) {
            binding *b = add_binding(m, name, package, node);
            if (b) { b->commonjs = true; b->has_initialization = true; b->initialization = sf_location(node); }
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
    if (!strcmp(s, "fastify") || !strcmp(s, "fastify.fastify") || !strcmp(s, "fastify.default")) return "fastify.Instance";
    if (!strcmp(s, "github.com/go-chi/chi/v5.NewRouter") || !strcmp(s, "chi.Router.With")) return "chi.Router";
    if (!strcmp(s, "github.com/labstack/echo/v4.New")) return "echo.Engine";
    if (!strcmp(s, "echo.Engine.Group") || !strcmp(s, "echo.Group.Group")) return "echo.Group";
    if (strcmp(s, "express") == 0 || strcmp(s, "express.Router") == 0) return "express.Router";
    if (strcmp(s, "net/http.NewServeMux") == 0) return "net/http.ServeMux";
    if (strcmp(s, "github.com/gin-gonic/gin.New") == 0 || strcmp(s, "github.com/gin-gonic/gin.Default") == 0 || strcmp(s, "gin.Engine.Group") == 0) return "gin.Engine";
    return NULL;
}
static bool factories(TSNode node, void *opaque) {
    sf_models *m = opaque;
    TSNode value, name = assignment_name(node, &value);
    if (!identifier(name) || ts_node_is_null(value)) return true;
    TSNode factory_args = sf_field(value, "arguments");
    for (uint32_t i = 0; !ts_node_is_null(factory_args) && i < ts_node_named_child_count(factory_args); i++) {
        TSNode arg = ts_node_named_child(factory_args, i);
        if (sf_node_is(arg, "spread_element") || sf_node_is(arg, "list_splat") || sf_node_is(arg, "dictionary_splat") || sf_node_is(arg, "variadic_argument")) return true;
    }
    char canonical[384];
    binding *owner = resolve(m, sf_call_target(value), canonical, sizeof(canonical));
    const char *instance = owner ? instance_type(canonical) : NULL;
    if (!instance) return true;
    char saved[256]; size_t instance_len = strlen(instance);
    if (instance_len >= sizeof(saved)) return true;
    memcpy(saved, instance, instance_len + 1);
    sf_span import_evidence = owner->evidence;
    int parent_index = (int)(owner - m->bindings);
    binding *b = add_binding(m, name, saved, node);
    if (b) {
        b->parent = parent_index; b->instance = true; b->has_initialization = true;
        b->initialization = sf_location(node); b->evidence = import_evidence;
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
static bool invalidate_pattern_node(TSNode node, void *opaque) {
    if (identifier(node) || sf_node_is(node, "shorthand_property_identifier_pattern")) {
        sf_models *m = opaque;
        char name[128];
        if (sf_node_text(m->doc, node, name, sizeof(name))) {
            if (strcmp(name, "require") == 0) m->require_shadowed = true;
            for (size_t i = 0; i < m->count; i++) if (strcmp(m->bindings[i].local, name) == 0) m->bindings[i].invalid = true;
        }
    }
    return true;
}
static void invalidate_pattern(sf_models *m, TSNode node) {
    if (ts_node_is_null(node)) return;
    if (identifier(node)) { invalidate_name(m, node); return; }
    /* Only called for binding positions. Field writes, arbitrary expressions
     * and dynamic object mutation remain outside the model. */
    if (sf_node_is(node, "pattern_list") || sf_node_is(node, "tuple_pattern") || sf_node_is(node, "list_pattern") ||
        sf_node_is(node, "object_pattern") || sf_node_is(node, "array_pattern") || sf_node_is(node, "expression_list")) {
        size_t visited;
        if (!sf_walk(node, invalidate_pattern_node, m, &visited)) m->doc->framework_bindings_limited = true;
    }
}
static bool collisions(TSNode node, void *opaque) {
    sf_models *m = opaque;
    TSNode value, name = assignment_name(node, &value);
    if (!ts_node_is_null(name)) invalidate_pattern(m, name);
    static const char *const kinds[] = {"function_definition", "class_definition", "function_declaration", "class_declaration", "annotation_type_declaration", "formal_parameter", "parameter_declaration", "default_parameter", "typed_default_parameter", "type_spec", "catch_formal_parameter", "named_expression"};
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) if (sf_node_is(node, kinds[i])) invalidate_name(m, sf_field(node, "name"));
    if (sf_node_is(node, "required_parameter") || sf_node_is(node, "optional_parameter")) invalidate_pattern(m, sf_field(node, "pattern"));
    if (sf_node_is(node, "for_statement") || sf_node_is(node, "for_in_statement")) invalidate_pattern(m, sf_field(node, "left"));
    if (sf_node_is(node, "as_pattern")) invalidate_pattern(m, sf_field(node, "alias"));
    TSNode parent = ts_node_parent(node);
    if (identifier(node) && sf_node_is(parent, "arrow_function") && same_span(sf_location(node), sf_location(sf_field(parent, "parameter")))) invalidate_name(m, node);
    if (identifier(node) && (sf_node_is(parent, "parameters") || sf_node_is(parent, "formal_parameters") || sf_node_is(parent, "lambda_parameters") || sf_node_is(parent, "typed_parameter") || sf_node_is(parent, "rest_pattern") || sf_node_is(parent, "list_splat_pattern") || sf_node_is(parent, "dictionary_splat_pattern") || sf_node_is(parent, "delete_statement") || sf_node_is(parent, "global_statement") || sf_node_is(parent, "nonlocal_statement"))) invalidate_name(m, node);
    return !m->doc->framework_bindings_limited;
}
static bool declaration_file(const char *path) {
    const char *const suffixes[] = {".pyi", ".d.ts", ".d.mts", ".d.cts"};
    size_t length = strlen(path);
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        size_t n = strlen(suffixes[i]);
        if (length >= n && strcmp(path + length - n, suffixes[i]) == 0) return true;
    }
    return false;
}
sf_models *sf_models_new(sf_document *doc, TSNode root) {
    sf_models *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->doc = doc; m->root = root;
    size_t visited;
    m->usable = !doc->parse_has_error && !declaration_file(doc->path) &&
                sf_walk(root, imports, m, &visited) && !m->ambiguous_import &&
                sf_walk(root, factories, m, &visited) && sf_walk(root, collisions, m, &visited) &&
                !doc->framework_bindings_limited;
    if (m->require_shadowed) for (size_t i = 0; i < m->count; i++) if (m->bindings[i].commonjs) m->bindings[i].invalid = true;
    /* Dependencies point backwards. Invalidated constructors never leave live
     * derived router bindings behind. No fixed-point guessing is needed. */
    for (size_t i = 0; i < m->count; i++) {
        int parent = m->bindings[i].parent;
        if (parent >= 0 && (size_t)parent < i && m->bindings[parent].invalid) m->bindings[i].invalid = true;
    }
    doc->framework_analysis_complete = m->usable;
    return m;
}
void sf_models_free(sf_models *m) { free(m); }

static const char *http_method(const char *name, bool uppercase) {
    static const char *const lower[] = {"get", "post", "put", "patch", "delete", "head", "options", "all"};
    static const char *const upper[] = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL"};
    for (size_t i = 0; i < sizeof(lower) / sizeof(lower[0]); i++)
        if (strcmp(name, uppercase ? upper[i] : lower[i]) == 0) return upper[i];
    return NULL;
}
static bool decorated(TSNode node) {
    return sf_node_is(node, "decorator") || sf_node_is(ts_node_parent(node), "decorator");
}
static void mark(sf_fact *f, binding *b, const char *framework, const char *role, const char *rule) {
    f->framework = framework; f->role = role; f->rule_id = rule;
    if (b) {
        f->has_import_evidence = true; f->import_evidence = b->evidence;
        f->has_binding_evidence = b->instance && b->has_initialization; f->binding_evidence = b->initialization;
    }
}
static void path_and_handler(sf_fact *f, TSNode path, TSNode handler) {
    if (!ts_node_is_null(path)) { f->has_path_expression = true; f->path_expression = sf_location(path); }
    if (!ts_node_is_null(handler)) { f->has_handler = true; f->handler = sf_location(handler); }
}
/* Only unique direct literal fields are extracted. Spreads, computed keys,
 * accessors and duplicate names can change values, so retain the raw call. */
static bool object_field(sf_models *m, TSNode object, const char *wanted, TSNode *out) {
    *out = (TSNode){0};
    if (!sf_node_is(object, "object")) return false;
    char names[64][64]; size_t count = 0;
    TSTreeCursor cursor = ts_tree_cursor_new(object); bool valid = true;
    if (ts_tree_cursor_goto_first_child(&cursor)) do {
        TSNode item = ts_tree_cursor_current_node(&cursor);
        if (!ts_node_is_named(item) || sf_node_is(item, "comment")) continue;
        TSNode key = {0}, value = {0}; char name[64];
        if (sf_node_is(item,"pair")) { key = sf_field(item,"key"); value = sf_field(item,"value"); }
        else if (sf_node_is(item,"shorthand_property_identifier")) key = value = item;
        else if (sf_node_is(item,"method_definition") && !keyword(item,"get") && !keyword(item,"set")) {
            key = sf_field(item,"name"); value = item;
        } else { valid = false; break; }
        if (sf_node_is(key,"computed_property_name") || count == 64 ||
            !(literal(m,key,name,sizeof(name)) || sf_node_text(m->doc,key,name,sizeof(name)))) { valid = false; break; }
        for (size_t i = 0; i < count; i++) if (!strcmp(names[i],name)) valid = false;
        if (!valid) break;
        strcpy(names[count++],name);
        if (!strcmp(name,wanted)) *out = value;
    } while (ts_tree_cursor_goto_next_sibling(&cursor));
    ts_tree_cursor_delete(&cursor);
    return valid;
}

static void python_web_extra(sf_models *m, sf_fact *f, TSNode node, binding *b, const char *member, bool fastapi) {
    const char *fw = fastapi ? "fastapi" : "flask";
    if (!strcmp(member, fastapi ? "include_router" : "register_blueprint") && !decorated(node)) {
        TSNode router = python_argument(m,node,0,fastapi ? "router" : "blueprint",NULL);
        if (ts_node_is_null(router)) return;
        mark(f,b,fw,"router_attachment","python.router-attachment.v1");
        sf_model_add_detail(f,"router",router);
        sf_model_add_detail(f,"prefix",python_argument(m,node,UINT32_MAX,fastapi ? "prefix" : "url_prefix",NULL));
        sf_model_add_detail(f,"dependencies",python_argument(m,node,UINT32_MAX,"dependencies",NULL));
    } else if (!fastapi && !strcmp(member,"add_url_rule") && !decorated(node)) {
        TSNode path = python_argument(m,node,0,"rule",NULL);
        if (ts_node_is_null(path)) return;
        mark(f,b,fw,"route_declaration","flask.add-url-rule.v1"); f->http_method = "DECLARED_OR_FRAMEWORK_DEFAULT";
        path_and_handler(f,path,python_argument(m,node,2,"view_func",NULL));
        sf_model_add_detail(f,"endpoint_name",python_argument(m,node,1,"endpoint",NULL));
        sf_model_add_detail(f,"methods",python_argument(m,node,UINT32_MAX,"methods",NULL));
    } else if (fastapi && ((!strcmp(member,"websocket") && decorated(node)) || !strcmp(member,"add_api_websocket_route"))) {
        TSNode path = python_argument(m,node,0,"path",NULL);
        TSNode handler = !strcmp(member,"add_api_websocket_route") ? python_argument(m,node,1,"endpoint",NULL) : (TSNode){0};
        if (ts_node_is_null(path) || (!strcmp(member,"add_api_websocket_route") && ts_node_is_null(handler))) return;
        mark(f,b,fw,"websocket_route_declaration","fastapi.websocket.v1");
        path_and_handler(f,path,handler);
    } else if (fastapi && !strcmp(b->canonical,"fastapi.FastAPI") && !strcmp(member,"add_middleware") && !decorated(node)) {
        TSNode middleware = python_argument(m,node,0,"middleware_class",NULL);
        if (ts_node_is_null(middleware)) return;
        mark(f,b,fw,"middleware_attachment","fastapi.middleware.v1");
        sf_model_add_detail(f,"middleware",middleware);
    } else if (fastapi && !strcmp(b->canonical,"fastapi.FastAPI") && !strcmp(member,"middleware") && decorated(node)) {
        mark(f,b,fw,"request_hook_declaration","fastapi.middleware-decorator.v1"); f->control_phase = "around_request";
    } else if (!fastapi && !strcmp(member,"endpoint") && decorated(node)) {
        mark(f,b,fw,"handler_alias_declaration","flask.endpoint.v1");
        sf_model_add_detail(f,"endpoint_name",python_argument(m,node,0,"endpoint",NULL));
    }
}

static void fastify_model(sf_models *m, sf_fact *f, TSNode node, binding *b, const char *member) {
    TSNode a = argument(node,0), second = argument(node,1), third = argument(node,2), path = {0}, handler = {0}, methods = {0};
    const char *method = http_method(member,false);
    if (!strcmp(member,"route") && f->argument_total == 1) {
        TSNode alias = {0};
        if (!object_field(m,a,"url",&path) || !object_field(m,a,"path",&alias) ||
            !object_field(m,a,"method",&methods) || !object_field(m,a,"handler",&handler)) {
            f->model_gap = "fastify_dynamic_or_ambiguous_route_options"; return;
        }
        if (!ts_node_is_null(path) && !ts_node_is_null(alias)) { f->model_gap = "fastify_conflicting_route_paths"; return; }
        if (ts_node_is_null(path)) path = alias;
        if (ts_node_is_null(path) || ts_node_is_null(methods) || ts_node_is_null(handler)) {
            f->model_gap = "fastify_missing_explicit_route_fields"; return;
        }
        mark(f,b,"fastify","route_declaration","fastify.object-route.v1");
        f->http_method = "DECLARED_IN_ARGUMENTS";
        path_and_handler(f,path,handler); sf_model_add_detail(f,"methods",methods); sf_model_add_detail(f,"options",a);
    } else if ((method || !strcmp(member,"trace")) && (f->argument_total == 2 || f->argument_total == 3)) {
        if (!method) method = "TRACE";
        path = a;
        if (sf_node_is(second,"object")) {
            if (!object_field(m,second,"handler",&handler)) { f->model_gap = "fastify_dynamic_or_ambiguous_route_options"; return; }
            if (!ts_node_is_null(handler) && !ts_node_is_null(third)) { f->model_gap = "fastify_duplicate_handler"; return; }
            if (!ts_node_is_null(third)) handler = third;
            if (ts_node_is_null(handler)) { f->model_gap = "fastify_missing_explicit_handler"; return; }
        } else if (!ts_node_is_null(third)) handler = third;
        else if (sf_node_is(second,"arrow_function") || sf_node_is(second,"function_expression")) handler = second;
        mark(f,b,"fastify","route_declaration","fastify.shorthand-route.v1"); f->http_method = method;
        path_and_handler(f,path,handler);
        if (ts_node_is_null(handler)) { sf_model_add_detail(f,"handler_or_options",second); f->model_gap = "fastify_handler_or_options_not_resolved"; }
        else if (sf_node_is(second,"object") || !ts_node_is_null(third)) sf_model_add_detail(f,"options",second);
    } else if (!strcmp(member,"register") && f->argument_total >= 1 && f->argument_total <= 2) {
        mark(f,b,"fastify","plugin_registration","fastify.plugin.v1");
        sf_model_add_detail(f,"plugin",a); sf_model_add_detail(f,"options",second);
        TSNode prefix = {0}; if (object_field(m,second,"prefix",&prefix)) sf_model_add_detail(f,"prefix",prefix);
    } else if (!strcmp(member,"addHook") && f->argument_total == 2) {
        char hook[64]; if (!literal(m,a,hook,sizeof(hook))) return;
        const char *const before[] = {"onRequest","preParsing","preValidation","preHandler"};
        const char *const after[] = {"preSerialization","onSend","onResponse","onError","onTimeout","onRequestAbort"};
        const char *phase = NULL;
        for (size_t i=0;i<sizeof(before)/sizeof(before[0]);i++) if (!strcmp(hook,before[i])) phase="before_handler";
        for (size_t i=0;i<sizeof(after)/sizeof(after[0]);i++) if (!strcmp(hook,after[i])) phase="response_or_error_lifecycle";
        if (!phase) return;
        mark(f,b,"fastify","request_hook_declaration","fastify.hook.v1"); f->control_phase=phase;
        sf_model_add_detail(f,"hook",a); path_and_handler(f,(TSNode){0},second);
    }
}

static void go_router_model(sf_fact *f, TSNode node, binding *b, const char *member) {
    bool echo = !strcmp(b->canonical,"echo.Engine") || !strcmp(b->canonical,"echo.Group");
    const char *fw = echo ? "echo" : "chi", *method = NULL;
    static const char *const chi_methods[] = {"Get","Post","Put","Patch","Delete","Head","Options","Trace","Connect"};
    static const char *const verbs[] = {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","TRACE","CONNECT"};
    for (size_t i=0;i<sizeof(verbs)/sizeof(verbs[0]);i++) if (!strcmp(member,echo ? verbs[i] : chi_methods[i])) method=verbs[i];
    bool all = !strcmp(member,echo ? "Any" : "Handle") || (!echo && !strcmp(member,"HandleFunc"));
    if ((method || all) && f->argument_total >= 2 && (echo || f->argument_total == 2)) {
        mark(f,b,fw,"route_declaration",echo ? "echo.route.v1" : "chi.route.v1");
        f->http_method = method ? method : "ALL";
        /* Echo's handler is argument 1; later arguments are middleware. */
        path_and_handler(f,argument(node,0),argument(node,1));
    } else if ((!strcmp(member,echo ? "Add" : "Method") || !strcmp(member,echo ? "Match" : "MethodFunc")) &&
               f->argument_total >= 3 && (echo || f->argument_total == 3)) {
        mark(f,b,fw,"route_declaration",echo ? "echo.method-route.v1" : "chi.method-route.v1");
        f->http_method="DECLARED_IN_ARGUMENTS";
        path_and_handler(f,argument(node,1),argument(node,2)); sf_model_add_detail(f,"methods",argument(node,0));
    } else if ((!strcmp(member,"Use") || (echo && !strcmp(b->canonical,"echo.Engine") && !strcmp(member,"Pre")) ||
                (!echo && !strcmp(member,"With"))) && f->argument_total) {
        mark(f,b,fw,"middleware_attachment",echo ? "echo.middleware.v1" : "chi.middleware.v1");
        f->control_phase = echo && !strcmp(member,"Pre") ? "before_routing" : "routing_pipeline_candidate";
    } else if (!echo && !strcmp(member,"Mount") && f->argument_total==2) {
        mark(f,b,fw,"router_attachment","chi.mount.v1");
        sf_model_add_detail(f,"prefix",argument(node,0)); sf_model_add_detail(f,"router",argument(node,1));
    } else if ((echo && !strcmp(member,"Group") && f->argument_total) ||
               (!echo && ((!strcmp(member,"Route") && f->argument_total==2) || (!strcmp(member,"Group") && f->argument_total==1)))) {
        mark(f,b,fw,"route_group_declaration",echo ? "echo.group.v1" : "chi.group.v1");
        if (echo || !strcmp(member,"Route")) sf_model_add_detail(f,"prefix",argument(node,0));
        if (!echo) sf_model_add_detail(f,"callback",argument(node,!strcmp(member,"Route") ? 1 : 0));
    }
}

static void annotation_model(sf_models *m, sf_fact *f, TSNode node) {
    char canonical[384]; TSNode name = sf_field(node, "name");
    binding *b = resolve(m, name, canonical, sizeof(canonical));
    if (!b && (!sf_node_text(m->doc, name, canonical, sizeof(canonical)) || !strchr(canonical,'.'))) return;
    if (sf_java_annotation_apply(m->doc, f, node, canonical) && b) {
        f->has_import_evidence = true; f->import_evidence = b->evidence;
    }
}

static void apply_model(sf_models *m, sf_fact *f, TSNode node) {
    if (!m || !m->usable || f->syntax_has_error) return;
    if (strcmp(f->kind, "annotation") == 0) { annotation_model(m, f, node); return; }
    bool decorator = strcmp(f->kind, "decorator") == 0;
    if ((strcmp(f->kind, "call_site") != 0 && !decorator) || f->has_argument_expansion) return;
    TSNode target = decorator ? ts_node_named_child(node, 0) : sf_call_target(node);
    if (decorator && (sf_node_is(target, "call") || sf_node_is(target, "call_expression"))) return;
    char canonical[384]; binding *b = resolve(m, target, canonical, sizeof(canonical));
    if (!b) return;
    const char *member = strrchr(canonical, '.'); member = member ? member + 1 : canonical;
    if (b->instance && !strcmp(b->canonical,"fastify.Instance")) { fastify_model(m,f,node,b,member); return; }
    if (b->instance && (!strcmp(b->canonical,"chi.Router") || !strcmp(b->canonical,"echo.Engine") || !strcmp(b->canonical,"echo.Group"))) {
        go_router_model(f,node,b,member); return;
    }
    if (!b->instance && !strncmp(canonical,"rest_framework.decorators.",26) && decorated(node) && !strchr(canonical+26,'.')) {
        if (!strcmp(member,"api_view")) {
            mark(f,b,"django-rest-framework","route_handler_declaration","drf.api-view.v1");
            f->http_method="DECLARED_OR_FRAMEWORK_DEFAULT"; sf_model_add_detail(f,"methods",argument(node,0));
        } else if (!strcmp(member,"action")) {
            mark(f,b,"django-rest-framework","route_action_declaration","drf.action.v1");
            sf_model_add_detail(f,"methods",python_argument(m,node,0,"methods",NULL));
            sf_model_add_detail(f,"detail",python_argument(m,node,1,"detail",NULL));
            sf_model_add_detail(f,"url_path",python_argument(m,node,2,"url_path",NULL));
        } else if (!strcmp(member,"permission_classes") || !strcmp(member,"authentication_classes") || !strcmp(member,"throttle_classes")) {
            mark(f,b,"django-rest-framework","control_declaration","drf.policy.v1"); f->control_phase="before_handler";
            sf_model_add_detail(f,"classes",argument(node,0));
        }
        return;
    }
    if (!b->instance && !strncmp(canonical,"fastapi.security.",17) && !strchr(canonical+17,'.')) {
        const char *const schemes[] = {"HTTPBasic","HTTPBearer","OAuth2PasswordBearer","OAuth2AuthorizationCodeBearer","APIKeyHeader","APIKeyQuery","APIKeyCookie"};
        for (size_t i=0;i<sizeof(schemes)/sizeof(schemes[0]);i++) if (!strcmp(member,schemes[i])) {
            mark(f,b,"fastapi","security_scheme_declaration","fastapi.security-scheme.v1");
            sf_model_add_detail(f,"auto_error",python_argument(m,node,UINT32_MAX,"auto_error",NULL));
            sf_model_add_detail(f,"credential_name",python_argument(m,node,UINT32_MAX,"name",NULL)); return;
        }
    }
    if (!b->instance && (strcmp(canonical, "fastapi.Depends") == 0 || strcmp(canonical, "fastapi.Security") == 0)) {
        mark(f, b, "fastapi", strcmp(member, "Depends") == 0 ? "dependency_declaration" : "security_dependency_declaration", "fastapi.dependency.v1"); return;
    }
    if (!b->instance) {
        static const char *const inputs[] = {"Query", "Path", "Body", "Header", "Cookie", "Form", "File"};
        for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
            char expected[64]; join(expected, sizeof(expected), "fastapi", inputs[i]);
            if (strcmp(canonical, expected) == 0) { mark(f, b, "fastapi", "request_input_declaration", "fastapi.input.v1"); return; }
        }
    }
    if (b->instance && (strncmp(b->canonical, "fastapi.", 8) == 0 || strncmp(b->canonical, "flask.", 6) == 0)) {
        bool fastapi = strncmp(b->canonical, "fastapi.", 8) == 0;
        const char *fw = fastapi ? "fastapi" : "flask";
        const char *method = http_method(member, false);
        if (method && strcmp(method, "ALL") == 0) method = NULL;
        bool registration = fastapi && strcmp(member, "add_api_route") == 0;
        bool route = fastapi ? strcmp(member, "api_route") == 0 : strcmp(member, "route") == 0;
        if ((decorated(node) || registration) && (method || route || registration)) {
            TSNode path = python_argument(m, node, 0, fastapi ? "path" : "rule", NULL);
            TSNode handler = registration ? python_argument(m, node, 1, "endpoint", NULL) : (TSNode){0};
            if (ts_node_is_null(path) || (registration && ts_node_is_null(handler))) return;
            mark(f, b, fw, "route_declaration", "python.web-route.v1"); f->http_method = method ? method : "DECLARED_OR_FRAMEWORK_DEFAULT";
            path_and_handler(f, path, handler);
            sf_model_add_detail(f,"methods",python_argument(m,node,UINT32_MAX,"methods",NULL));
            sf_model_add_detail(f,"dependencies",python_argument(m,node,UINT32_MAX,"dependencies",NULL));
            return;
        }
        if (!fastapi && decorated(node) && (strcmp(member, "before_request") == 0 || strcmp(member, "after_request") == 0)) {
            mark(f, b, fw, "request_hook_declaration", "flask.request-hook.v1");
            f->control_phase = !strcmp(member,"before_request") ? "before_handler" : "after_handler";
        } else python_web_extra(m,f,node,b,member,fastapi);
        return;
    }
    if (!b->instance && (strcmp(canonical, "django.urls.path") == 0 || strcmp(canonical, "django.urls.re_path") == 0)) {
        TSNode path = python_argument(m, node, 0, "route", NULL), handler = python_argument(m, node, 1, "view", NULL);
        if (ts_node_is_null(path) || ts_node_is_null(handler)) return;
        mark(f, b, "django", "route_declaration", "django.url-pattern.v1"); f->http_method = "UNSPECIFIED";
        path_and_handler(f, path, handler); return;
    }
    if (!b->instance && decorated(node) && (strcmp(canonical, "django.contrib.auth.decorators.login_required") == 0 || strcmp(canonical, "django.contrib.auth.decorators.permission_required") == 0 || strcmp(canonical, "django.views.decorators.csrf.csrf_exempt") == 0)) {
        mark(f, b, "django", strcmp(member, "csrf_exempt") == 0 ? "control_exemption_declaration" : "authorization_declaration", "django.control-decorator.v1"); return;
    }
    if (b->instance && strcmp(b->canonical, "express.Router") == 0) {
        const char *method = http_method(member, false);
        if (method && f->argument_total >= 2) {
            mark(f, b, "express", "route_declaration", "express.route.v1"); f->http_method = method;
            path_and_handler(f, argument(node, 0), argument(node, f->argument_total - 1));
        } else if (strcmp(member, "use") == 0 && f->argument_total >= 1)
            mark(f, b, "express", "middleware_attachment", "express.middleware.v1");
        return;
    }
    if (!b->instance && decorated(node) && strncmp(canonical, "@nestjs/common.", 15) == 0 && !strchr(canonical + 15, '.')) {
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
    if (((!b->instance && (strcmp(canonical, "net/http.HandleFunc") == 0 || strcmp(canonical, "net/http.Handle") == 0)) ||
         (b->instance && strcmp(b->canonical, "net/http.ServeMux") == 0 && (strcmp(member, "HandleFunc") == 0 || strcmp(member, "Handle") == 0))) && f->argument_total >= 2) {
        mark(f, b, "go-net-http", "route_declaration", "go.http-route.v1"); f->http_method = "DECLARED_IN_PATTERN_OR_UNSPECIFIED";
        path_and_handler(f, argument(node, 0), argument(node, 1)); return;
    }
    if (b->instance && strcmp(b->canonical, "gin.Engine") == 0) {
        const char *method = http_method(member, true);
        if (method && strcmp(method, "ALL") == 0) method = NULL;
        if ((method || strcmp(member, "Any") == 0) && f->argument_total >= 2) {
            mark(f, b, "gin", "route_declaration", "gin.route.v1"); f->http_method = method ? method : "ALL";
            path_and_handler(f, argument(node, 0), argument(node, f->argument_total - 1));
        } else if (strcmp(member, "Use") == 0 && f->argument_total >= 1) mark(f, b, "gin", "middleware_attachment", "gin.middleware.v1");
    }
}

void sf_model_add_detail(sf_fact *f, const char *name, TSNode node) {
    if (ts_node_is_null(node)) return;
    for (uint32_t i = 0; i < f->model_detail_count; i++)
        if (!strcmp(f->model_details[i].name, name)) return;
    if (f->model_detail_count >= SF_MAX_MODEL_DETAILS) { f->model_details_limited = true; return; }
    f->model_details[f->model_detail_count].name = name;
    f->model_details[f->model_detail_count++].span = sf_location(node);
}
void sf_models_apply(sf_models *m, sf_fact *f, TSNode node) {
    apply_model(m, f, node);
    if (f->framework) sf_model_add_detail(f, "declaration_arguments", sf_field(node, "arguments"));
}
