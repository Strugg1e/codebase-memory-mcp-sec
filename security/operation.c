#include "operation.h"
#include "local_flow.h"
#include "parser.h"
#include "foundation/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern const TSLanguage *tree_sitter_java(void);
extern const TSLanguage *tree_sitter_xml(void);

#define OP_ITEMS 64U
#define OP_PARAMS 64U
#define OP_NODES 50000U
#define OP_SOURCE (256U * 1024U)
#define OP_PREVIEW 512U

typedef yyjson_mut_val value;
typedef struct {
    yyjson_mut_doc *json;
    const sf_operation_request *request;
    const char *error;
    value *gaps;
    bool limited;
} context;

typedef struct {
    TSNode items[OP_NODES];
    size_t count;
} nodes;

static value *obj(context *c) { return yyjson_mut_obj(c->json); }
static value *arr(context *c) { return yyjson_mut_arr(c->json); }
static value *str(context *c, const char *s) { return yyjson_mut_strcpy(c->json, s); }
static void set(context *c, value *o, const char *key, value *v) {
    value *k = str(c, key);
    if (!o || !k || !v || !yyjson_mut_obj_put(o, k, v)) c->error = "out_of_memory";
}
static void text(context *c, value *o, const char *key, const char *s) { set(c, o, key, str(c, s)); }
static void flag(context *c, value *o, const char *key, bool v) { set(c, o, key, yyjson_mut_bool(c->json, v)); }
static void num(context *c, value *o, const char *key, size_t n) { set(c, o, key, yyjson_mut_uint(c->json, n)); }
static void add(context *c, value *a, value *v) {
    if (!a || !v || !yyjson_mut_arr_append(a, v)) c->error = "out_of_memory";
}
static void gap(context *c, const char *code) {
    if (yyjson_mut_arr_size(c->gaps) < OP_ITEMS) add(c, c->gaps, str(c, code));
    else c->limited = true;
}
static bool same(TSNode a, TSNode b) {
    return !ts_node_is_null(a) && !ts_node_is_null(b) && ts_node_eq(a, b);
}
static bool inside(TSNode outer, TSNode inner) {
    return !ts_node_is_null(outer) && !ts_node_is_null(inner) &&
           ts_node_start_byte(outer) <= ts_node_start_byte(inner) &&
           ts_node_end_byte(inner) <= ts_node_end_byte(outer);
}
static bool word_char(unsigned char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') || ch == '_' || ch == '$';
}
static bool simple_name(const char *s) {
    if (!s || !*s || (*s >= '0' && *s <= '9')) return false;
    for (; *s; s++) if (!word_char((unsigned char)*s)) return false;
    return true;
}
static bool node_text(const sf_operation_source *s, TSNode n, char *out, size_t capacity) {
    if (ts_node_is_null(n)) return false;
    size_t a = ts_node_start_byte(n), b = ts_node_end_byte(n);
    if (a > b || b > s->size || b - a >= capacity) return false;
    memcpy(out, s->source + a, b - a); out[b - a] = 0;
    return true;
}
static bool spells(const sf_operation_source *s, TSNode n, const char *wanted) {
    if (ts_node_is_null(n)) return false;
    size_t a = ts_node_start_byte(n), b = ts_node_end_byte(n), length = strlen(wanted);
    return b >= a && b <= s->size && b - a == length && !memcmp(s->source + a, wanted, length);
}
static value *reference(context *c, const sf_operation_source *s, size_t a, size_t b) {
    value *r = obj(c);
    if (a > b || b > s->size) { c->error = "invalid_operation_span"; return r; }
    size_t n = b - a, preview = n > OP_PREVIEW ? OP_PREVIEW : n;
    while (preview && preview < n && ((unsigned char)s->source[a + preview] & 0xc0U) == 0x80U) preview--;
    text(c, r, "path", s->path); text(c, r, "sha256", s->sha256);
    num(c, r, "start_byte", a); num(c, r, "end_byte", b);
    set(c, r, "text_prefix", yyjson_mut_strncpy(c->json, s->source + a, preview));
    flag(c, r, "text_truncated", preview < n);
    return r;
}
static value *ref(context *c, const sf_operation_source *s, TSNode n) {
    if (ts_node_is_null(n)) return yyjson_mut_null(c->json);
    return reference(c, s, ts_node_start_byte(n), ts_node_end_byte(n));
}
static TSNode child_kind(TSNode n, const char *kind) {
    if (ts_node_is_null(n)) return (TSNode){0};
    TSTreeCursor cursor = ts_tree_cursor_new(n);
    TSNode result = {0};
    if (ts_tree_cursor_goto_first_child(&cursor)) do {
        TSNode child = ts_tree_cursor_current_node(&cursor);
        if (sf_node_is(child, kind)) { result = child; break; }
    } while (ts_tree_cursor_goto_next_sibling(&cursor));
    ts_tree_cursor_delete(&cursor);
    return result;
}
static bool collect(TSNode n, void *opaque) {
    nodes *v = opaque;
    if (v->count >= OP_NODES) return false;
    v->items[v->count++] = n;
    return true;
}
typedef struct { const sf_operation_source *source; clock_t started; } parse_state;
static const char *read_bytes(void *opaque, uint32_t byte, TSPoint point, uint32_t *length) {
    (void)point;
    const sf_operation_source *s = ((parse_state *)opaque)->source;
    size_t left = byte < s->size ? s->size - byte : 0;
    *length = (uint32_t)(left > 4096 ? 4096 : left);
    return left ? s->source + byte : "";
}
static bool cancel_parse(TSParseState *state) {
    parse_state *p = state->payload;
    clock_t now = clock();
    return now == (clock_t)-1 || (double)(now - p->started) / CLOCKS_PER_SEC > 3.0;
}
static TSTree *parse(context *c, const sf_operation_source *s, const TSLanguage *language,
                     nodes *all, const char **error) {
    if (!s || s->size > OP_SOURCE) { *error = "operation_source_limit_exceeded"; return NULL; }
    parse_state state = {.source = s, .started = clock()};
    if (state.started == (clock_t)-1) { *error = "clock_unavailable"; return NULL; }
    TSParser *p = ts_parser_new();
    if (!p) { *error = "out_of_memory"; return NULL; }
    if (!ts_parser_set_language(p, language)) {
        ts_parser_delete(p); *error = "grammar_abi_mismatch"; return NULL;
    }
    if (c->request->parse_attempts) (*c->request->parse_attempts)++;
    TSInput input = {.payload = &state, .read = read_bytes, .encoding = TSInputEncodingUTF8};
    TSParseOptions options = {.payload = &state, .progress_callback = cancel_parse};
    TSTree *tree = ts_parser_parse_with_options(p, NULL, input, options);
    ts_parser_delete(p);
    if (!tree) { *error = "operation_parse_failed"; return NULL; }
    size_t visited;
    if (ts_node_has_error(ts_tree_root_node(tree))) *error = "operation_syntax_incomplete";
    else if (!sf_walk(ts_tree_root_node(tree), collect, all, &visited)) *error = "operation_node_limit_exceeded";
    if (*error) { ts_tree_delete(tree); return NULL; }
    return tree;
}
static TSNode owner_method(TSNode n) {
    for (unsigned depth = 0; !ts_node_is_null(n) && depth < 128; depth++, n = ts_node_parent(n)) {
        if (sf_node_is(n, "lambda_expression") || sf_node_is(n, "class_declaration") ||
            sf_node_is(n, "interface_declaration") || sf_node_is(n, "constructor_declaration")) return (TSNode){0};
        if (sf_node_is(n, "method_declaration")) return n;
    }
    return (TSNode){0};
}
static TSNode owner_type(TSNode n) {
    for (unsigned depth = 0; !ts_node_is_null(n) && depth < 128; depth++, n = ts_node_parent(n))
        if (sf_node_is(n, "class_declaration") || sf_node_is(n, "interface_declaration")) return n;
    return (TSNode){0};
}
static size_t parameters(TSNode method, TSNode out[OP_PARAMS], bool *limited) {
    TSNode p = sf_field(method, "parameters"); size_t count = 0;
    if (ts_node_is_null(p)) return 0;
    TSTreeCursor cursor = ts_tree_cursor_new(p);
    if (ts_tree_cursor_goto_first_child(&cursor)) do {
        TSNode n = ts_tree_cursor_current_node(&cursor);
        if (sf_node_is(n, "formal_parameter") || sf_node_is(n, "spread_parameter") || sf_node_is(n, "receiver_parameter")) {
            if (count >= OP_PARAMS) { *limited = true; break; }
            out[count++] = n;
        }
    } while (ts_tree_cursor_goto_next_sibling(&cursor));
    ts_tree_cursor_delete(&cursor);
    return count;
}
static bool request_parameter(const sf_document *doc, TSNode p) {
    for (size_t i = 0; i < doc->count; i++) {
        const sf_fact *f = &doc->facts[i];
        if (f->framework && f->role && !strcmp(f->role, "request_input_declaration") &&
            f->span.start >= ts_node_start_byte(p) && f->span.end <= ts_node_end_byte(p)) return true;
    }
    return false;
}
/* File-local conservative invalidation. A same-spelling write anywhere in the
 * enclosing method prevents a stronger source relation, even after the call. */
static bool changed(const sf_operation_source *s, const nodes *all, TSNode region,
                    TSNode allowed, const char *name) {
    for (size_t i = 0; i < all->count; i++) {
        TSNode n = all->items[i];
        if (!inside(region, n)) continue;
        TSNode binding = {0};
        if (sf_node_is(n, "assignment_expression")) binding = sf_field(n, "left");
        else if (sf_node_is(n, "variable_declarator") || sf_node_is(n, "formal_parameter") ||
                 sf_node_is(n, "catch_formal_parameter") || sf_node_is(n, "enhanced_for_statement")) binding = sf_field(n, "name");
        else if (sf_node_is(n, "update_expression")) {
            for (uint32_t j = 0; j < ts_node_named_child_count(n); j++)
                if (spells(s, ts_node_named_child(n, j), name)) return true;
        }
        if (!same(binding, allowed) && spells(s, binding, name)) return true;
    }
    return false;
}
static value *argument_origin(context *c, const sf_operation_source *s, const nodes *all,
                              TSNode method, TSNode p[OP_PARAMS], size_t count, sf_span argument) {
    value *r = obj(c);
    set(c, r, "expression", reference(c, s, argument.start, argument.end));
    text(c, r, "basis", "local_syntax_relation");
    text(c, r, "trust", "not_established");
    text(c, r, "origin", "expression_not_traced");
    size_t length = argument.end - argument.start;
    if (!length || length >= 128) return r;
    char name[128]; memcpy(name, s->source + argument.start, length); name[length] = 0;
    if (!simple_name(name)) return r;
    for (size_t i = 0; i < count; i++) {
        TSNode param_name = sf_field(p[i], "name");
        if (!spells(s, param_name, name)) continue;
        set(c, r, "formal_parameter", ref(c, s, p[i]));
        num(c, r, "formal_parameter_index", i);
        if (changed(s, all, method, param_name, name)) {
            text(c, r, "origin", "parameter_written_or_shadowed"); return r;
        }
        text(c, r, "origin", request_parameter(c->request->caller, p[i]) ?
             "request_parameter_declaration_candidate" : "formal_parameter_reference");
        return r;
    }
    return r;
}
static value *java_context(context *c, const sf_operation_source *s, const nodes *all,
                           TSNode call, TSNode method, value **arguments) {
    value *r = obj(c), *params = arr(c), *assignments = arr(c), *conditions = arr(c), *exits = arr(c);
    value *fields = arr(c), *declarations = arr(c);
    set(c, r, "method", ref(c, s, method));
    set(c, r, "parameters", params); set(c, r, "assignments", assignments);
    set(c, r, "conditions", conditions); set(c, r, "returns_and_throws", exits);
    set(c, r, "field_accesses", fields); set(c, r, "framework_declarations", declarations);
    TSNode p[OP_PARAMS]; size_t count = parameters(method, p, &c->limited);
    for (size_t i = 0; i < count; i++) {
        value *v = obj(c); num(c, v, "index", i); set(c, v, "declaration", ref(c, s, p[i]));
        set(c, v, "name", ref(c, s, sf_field(p[i], "name")));
        set(c, v, "type", ref(c, s, sf_field(p[i], "type")));
        flag(c, v, "request_input_candidate", request_parameter(c->request->caller, p[i]));
        add(c, params, v);
    }
    *arguments = arr(c);
    for (uint32_t i = 0; i < c->request->call->argument_count && i < OP_PARAMS; i++) {
        value *v = argument_origin(c, s, all, method, p, count, c->request->call->arguments[i]);
        num(c, v, "index", i); add(c, *arguments, v);
    }
    if (c->request->call->argument_total > OP_PARAMS) c->limited = true;
    for (size_t i = 0; i < all->count; i++) {
        TSNode n = all->items[i];
        if (!same(owner_method(n), method)) continue;
        value *list = NULL, *v = NULL;
        if (sf_node_is(n, "if_statement")) {
            list = conditions; v = obj(c);
            set(c, v, "condition", ref(c, s, sf_field(n, "condition")));
            set(c, v, "then_branch", ref(c, s, sf_field(n, "consequence")));
            set(c, v, "else_branch", ref(c, s, sf_field(n, "alternative")));
            const char *relation = inside(sf_field(n, "consequence"), call) ? "call_in_then_branch" :
                inside(sf_field(n, "alternative"), call) ? "call_in_else_branch" :
                ts_node_end_byte(n) <= ts_node_start_byte(call) ? "lexically_before_call" : "lexically_after_or_overlapping";
            text(c, v, "relation", relation);
            text(c, v, "enforcement", "not_proved");
        } else if (sf_node_is(n, "assignment_expression") || sf_node_is(n, "variable_declarator")) {
            list = assignments; v = obj(c);
            bool declaration = sf_node_is(n, "variable_declarator");
            set(c, v, "left", ref(c, s, sf_field(n, declaration ? "name" : "left")));
            set(c, v, "right", ref(c, s, sf_field(n, declaration ? "value" : "right")));
        } else if (sf_node_is(n, "return_statement") || sf_node_is(n, "throw_statement")) {
            list = exits; v = obj(c); text(c, v, "kind", ts_node_type(n));
        } else if (sf_node_is(n, "field_access")) { list = fields; v = obj(c); }
        if (!list) continue;
        if (yyjson_mut_arr_size(list) >= OP_ITEMS) { c->limited = true; continue; }
        set(c, v, "source", ref(c, s, n)); add(c, list, v);
    }
    const sf_document *doc = c->request->caller;
    for (size_t i = 0; i < doc->count; i++) {
        const sf_fact *f = &doc->facts[i];
        if (!f->framework || !f->has_enclosing || f->enclosing.start != ts_node_start_byte(method) ||
            f->enclosing.end != ts_node_end_byte(method)) continue;
        if (yyjson_mut_arr_size(declarations) >= OP_ITEMS) { c->limited = true; break; }
        value *v = obj(c); text(c, v, "framework", f->framework); text(c, v, "role", f->role);
        char id[65]; sf_fact_id(doc, f, id); text(c, v, "fact_id", id);
        set(c, v, "source", reference(c, s, f->span.start, f->span.end)); add(c, declarations, v);
    }
    text(c, r, "scope", "nearest_method_only");
    text(c, r, "control_flow", "lexical_structure_not_path_proof");
    return r;
}
/* Only package declarations and explicit non-static imports participate. */
static bool package_name(const sf_operation_source *s, const nodes *all, char out[256]) {
    out[0] = 0;
    for (size_t i = 0; i < all->count; i++) if (sf_node_is(all->items[i], "package_declaration")) {
        TSNode n = child_kind(all->items[i], "scoped_identifier");
        if (ts_node_is_null(n)) n = child_kind(all->items[i], "identifier");
        return node_text(s, n, out, 256);
    }
    return true;
}
static bool qualified_type(const sf_operation_source *s, const nodes *all, const char *type,
                           const char *expected) {
    if (strchr(type, '.')) return !strcmp(type, expected);
    if (!simple_name(type)) return false;
    size_t hits = 0; bool matched = false;
    for (size_t i = 0; i < all->count; i++) {
        TSNode n = all->items[i];
        if (sf_node_is(n, "class_declaration") || sf_node_is(n, "interface_declaration") ||
            sf_node_is(n, "annotation_type_declaration") || sf_node_is(n, "type_parameter")) {
            if (spells(s, sf_field(n, "name"), type)) return false;
        }
        if (!sf_node_is(n, "import_declaration") || !ts_node_is_null(child_kind(n, "static"))) continue;
        char import[384];
        TSNode imported = child_kind(n, "scoped_identifier");
        if (!node_text(s, imported, import, sizeof(import))) continue;
        if (!ts_node_is_null(child_kind(n, "asterisk"))) continue;
        const char *leaf = strrchr(import, '.'); leaf = leaf ? leaf + 1 : import;
        if (!strcmp(leaf, type)) { hits++; matched = !strcmp(import, expected); }
    }
    if (hits) return hits == 1 && matched;
    char package[256], combined[512];
    if (!package_name(s, all, package)) return false;
    int n = snprintf(combined, sizeof(combined), "%s%s%s", package, *package ? "." : "", type);
    return n >= 0 && (size_t)n < sizeof(combined) && !strcmp(combined, expected);
}
static bool receiver_matches(context *c, const sf_operation_source *s, const nodes *all,
                             TSNode call, TSNode method, const char *expected, value *mapping) {
    TSNode receiver = sf_field(call, "object"); char name[128];
    bool explicit_this = sf_node_is(receiver, "field_access") && spells(s, sf_field(receiver, "object"), "this");
    TSNode receiver_name = explicit_this ? sf_field(receiver, "field") : receiver;
    if (!node_text(s, receiver_name, name, sizeof(name)) || !simple_name(name)) return false;
    TSNode type = {0}, declaration = {0}; size_t hits = 0;
    TSNode p[OP_PARAMS]; bool limit = false; size_t count = parameters(method, p, &limit);
    if (limit) return false;
    if (!explicit_this) for (size_t i = 0; i < count; i++) if (spells(s, sf_field(p[i], "name"), name)) {
        declaration = p[i]; type = sf_field(p[i], "type"); hits++;
    }
    if (!hits) {
        TSNode owner = owner_type(method);
        for (size_t i = 0; i < all->count; i++) {
            TSNode n = all->items[i], parent = ts_node_parent(n);
            if (sf_node_is(n, "variable_declarator") && sf_node_is(parent, "field_declaration") &&
                same(owner_type(parent), owner) && spells(s, sf_field(n, "name"), name)) {
                declaration = n; type = sf_field(parent, "type"); hits++;
            }
        }
    }
    char type_name[384];
    if (hits != 1 || !node_text(s, type, type_name, sizeof(type_name)) ||
        !qualified_type(s, all, type_name, expected)) return false;
    if (!explicit_this && changed(s, all, method, sf_field(declaration, "name"), name)) return false;
    /* Constructor wiring is not proof of runtime binding. Reject rewrites
     * in this method; other methods and dependency injection remain unknown. */
    for (size_t i = 0; i < all->count; i++) {
        TSNode n = all->items[i], left = sf_field(n, "left");
        if (!inside(method, n) || !sf_node_is(n, "assignment_expression")) continue;
        if (spells(s, left, name) || (sf_node_is(left, "field_access") &&
            spells(s, sf_field(left, "object"), "this") && spells(s, sf_field(left, "field"), name))) return false;
    }
    set(c, mapping, "receiver_declaration", ref(c, s, declaration));
    text(c, mapping, "receiver_resolution", "explicit_declared_type_candidate");
    return true;
}
static TSNode xml_start(TSNode n) {
    if (sf_node_is(n, "EmptyElemTag") || sf_node_is(n, "STag")) return n;
    TSNode tag = child_kind(n, "STag");
    return ts_node_is_null(tag) ? child_kind(n, "EmptyElemTag") : tag;
}
static TSNode xml_name(TSNode n) { return child_kind(xml_start(n), "Name"); }
static TSNode xml_parent(TSNode n) {
    for (unsigned i = 0; i < 128 && !ts_node_is_null(n); i++, n = ts_node_parent(n))
        if (sf_node_is(n, "element")) return n;
    return (TSNode){0};
}
static TSNode attribute(const sf_operation_source *s, TSNode n, const char *key) {
    TSNode tag = xml_start(n), found = {0};
    if (ts_node_is_null(tag)) return found;
    TSTreeCursor cursor = ts_tree_cursor_new(tag);
    if (ts_tree_cursor_goto_first_child(&cursor)) do {
        TSNode a = ts_tree_cursor_current_node(&cursor);
        if (sf_node_is(a, "Attribute") && spells(s, child_kind(a, "Name"), key)) {
            if (!ts_node_is_null(found)) { found = (TSNode){0}; break; }
            found = child_kind(a, "AttValue");
        }
    } while (ts_tree_cursor_goto_next_sibling(&cursor));
    ts_tree_cursor_delete(&cursor);
    return found;
}
static bool literal(const sf_operation_source *s, TSNode n, char *out, size_t capacity) {
    char raw[512];
    if (!node_text(s, n, raw, sizeof(raw))) return false;
    size_t length = strlen(raw);
    if (length < 2 || (raw[0] != '\'' && raw[0] != '"') || raw[length - 1] != raw[0] || length - 2 >= capacity) return false;
    for (size_t i = 1; i + 1 < length; i++) if (raw[i] == '\\' || raw[i] == '&' || raw[i] == '\n' || raw[i] == '\r') return false;
    memcpy(out, raw + 1, length - 2); out[length - 2] = 0; return true;
}
static bool xml_tag(const sf_operation_source *s, TSNode n, const char *name) { return spells(s, xml_name(n), name); }

typedef struct { char name[128]; TSNode annotation; size_t index; } parameter_binding;
static size_t param_bindings(context *c, const sf_operation_source *s, const nodes *all,
                             TSNode method, value *mapping, parameter_binding bindings[OP_PARAMS]) {
    TSNode p[OP_PARAMS]; size_t count = parameters(method, p, &c->limited), used = 0;
    value *items = arr(c); set(c, mapping, "parameter_bindings", items);
    if (count != c->request->call->argument_total || c->request->call->argument_count != count) {
        gap(c, "mapper_argument_count_mismatch"); return 0;
    }
    for (size_t i = 0; i < count; i++) {
        if (!sf_node_is(p[i], "formal_parameter")) { gap(c, "mapper_varargs_or_receiver_not_bound"); return 0; }
        TSNode annotation = {0}; char alias[128] = ""; size_t hits = 0;
        for (size_t j = 0; j < all->count; j++) {
            TSNode n = all->items[j]; char type[384];
            if (!inside(p[i], n) || !sf_node_is(n, "annotation") ||
                !node_text(s, sf_field(n, "name"), type, sizeof(type)) ||
                !qualified_type(s, all, type, "org.apache.ibatis.annotations.Param")) continue;
            TSNode args = sf_field(n, "arguments");
            TSNode value_node = child_kind(args, "string_literal");
            if (ts_node_is_null(value_node)) {
                TSNode pair = child_kind(args, "element_value_pair");
                if (spells(s, sf_field(pair, "key"), "value")) value_node = sf_field(pair, "value");
            }
            if (literal(s, value_node, alias, sizeof(alias)) && simple_name(alias)) { hits++; annotation = n; }
        }
        if (hits != 1) { gap(c, "mapper_parameter_requires_explicit_Param"); continue; }
        for (size_t j = 0; j < used; j++) if (!strcmp(bindings[j].name, alias)) {
            gap(c, "duplicate_mapper_parameter_alias");
            set(c, mapping, "parameter_bindings", arr(c)); return 0;
        }
        strcpy(bindings[used].name, alias); bindings[used].annotation = annotation; bindings[used].index = i; used++;
        value *v = obj(c); text(c, v, "name", alias); num(c, v, "argument_index", i);
        set(c, v, "parameter", ref(c, s, p[i])); set(c, v, "annotation", ref(c, s, annotation));
        add(c, items, v);
    }
    return used;
}
/* SQL tokens remain source observations. No boolean implication, dialect
 * evaluation, string interpolation or dynamic XML expansion is performed. */
typedef struct { size_t start, end; char text[128]; } token;
static size_t tokenize(context *c, const sf_operation_source *s, size_t a, size_t b,
                       token out[512]) {
    size_t used = 0;
    for (size_t i = a; i < b;) {
        unsigned char ch = (unsigned char)s->source[i];
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') { i++; continue; }
        if (i + 1 < b && s->source[i] == '-' && s->source[i + 1] == '-') {
            while (i < b && s->source[i] != '\n') i++;
            continue;
        }
        if (i + 1 < b && s->source[i] == '/' && s->source[i + 1] == '*') {
            i += 2; while (i + 1 < b && !(s->source[i] == '*' && s->source[i + 1] == '/')) i++;
            if (i + 1 >= b) { gap(c, "sql_unclosed_comment"); break; }
            i += 2; continue;
        }
        if (used == 512) { c->limited = true; break; }
        token *t = &out[used++]; memset(t, 0, sizeof(*t)); t->start = i;
        if (ch == '\'' || ch == '"' || ch == '`') {
            i++;
            while (i < b) {
                if ((unsigned char)s->source[i++] != ch) continue;
                if (i < b && (unsigned char)s->source[i] == ch) { i++; continue; }
                break;
            }
            strcpy(t->text, "<quoted>");
        } else if ((ch == '#' || ch == '$') && i + 1 < b && s->source[i + 1] == '{') {
            i += 2; while (i < b && s->source[i] != '}') i++;
            if (i < b) i++;
            size_t length = i - t->start;
            if (length < sizeof(t->text)) { memcpy(t->text, s->source + t->start, length); t->text[length] = 0; }
            else { strcpy(t->text, "<long-binding>"); c->limited = true; }
        } else if (word_char(ch)) {
            i++; while (i < b && word_char((unsigned char)s->source[i])) i++;
            size_t length = i - t->start;
            if (length < sizeof(t->text)) {
                for (size_t k = 0; k < length; k++) {
                    unsigned char v = (unsigned char)s->source[t->start + k];
                    t->text[k] = (char)(v >= 'a' && v <= 'z' ? v - 'a' + 'A' : v);
                }
            } else { strcpy(t->text, "<long-token>"); c->limited = true; }
        } else { t->text[0] = (char)ch; t->text[1] = 0; i++; }
        t->end = i;
    }
    return used;
}
static bool placeholder_name(const token *t, char out[128]) {
    size_t length = strlen(t->text);
    if (length < 4 || t->text[length - 1] != '}' ||
        (t->text[0] != '#' && t->text[0] != '$') || t->text[1] != '{') return false;
    size_t i = 2, n = 0;
    while (t->text[i] && t->text[i] != '}' && t->text[i] != ',' && t->text[i] != '.') {
        if (n + 1 >= 128 || !word_char((unsigned char)t->text[i])) return false;
        out[n++] = t->text[i++];
    }
    out[n] = 0;
    /* Property access is retained in raw SQL but not equated to the whole DTO. */
    return simple_name(out) && (t->text[i] == '}' || t->text[i] == ',');
}
static void sql_context(context *c, const sf_operation_source *s, const nodes *all, TSNode statement,
                        value *mapping, parameter_binding *bindings, size_t binding_count) {
    value *segments = arr(c), *dynamic = arr(c), *occurrences = arr(c), *comparisons = arr(c);
    set(c, mapping, "sql_segments", segments); set(c, mapping, "dynamic_clauses", dynamic);
    set(c, mapping, "parameter_occurrences", occurrences); set(c, mapping, "comparison_candidates", comparisons);
    text(c, mapping, "sql_operation", "unknown"); text(c, mapping, "predicate_enforcement", "not_proved");
    bool first_sql = true, binding_scope_unknown = false;
    for (size_t i = 0; i < all->count; i++) {
        TSNode n = all->items[i];
        if (inside(statement, n) && (sf_node_is(n, "element") || sf_node_is(n, "EmptyElemTag")) &&
            (xml_tag(s, n, "bind") || xml_tag(s, n, "include"))) binding_scope_unknown = true;
    }
    if (binding_scope_unknown) gap(c, "dynamic_binding_scope_not_resolved");
    for (size_t i = 0; i < all->count; i++) {
        TSNode n = all->items[i];
        if (!inside(statement, n)) continue;
        if (sf_node_is(n, "element") && !same(n, statement)) {
            if (yyjson_mut_arr_size(dynamic) >= OP_ITEMS) { c->limited = true; continue; }
            value *v = obj(c); set(c, v, "element", ref(c, s, n));
            set(c, v, "test", ref(c, s, attribute(s, n, "test")));
            text(c, v, "evaluation", "not_attempted"); add(c, dynamic, v);
            gap(c, "dynamic_sql_not_expanded");
        }
        if (sf_node_is(n, "EntityRef") || sf_node_is(n, "CharRef")) gap(c, "xml_entities_not_decoded");
        if (!sf_node_is(n, "CharData") && !sf_node_is(n, "CData")) continue;
        if (yyjson_mut_arr_size(segments) >= OP_ITEMS) { c->limited = true; continue; }
        add(c, segments, ref(c, s, n));
        token tokens[512]; size_t count = tokenize(c, s, ts_node_start_byte(n), ts_node_end_byte(n), tokens);
        if (first_sql && count) {
            first_sql = false;
            const char *op = tokens[0].text;
            if (!strcmp(op, "SELECT") || !strcmp(op, "UPDATE") || !strcmp(op, "INSERT") || !strcmp(op, "DELETE")) {
                text(c, mapping, "sql_operation", op);
                text(c, mapping, "operation_basis", "leading_sql_token_candidate");
                size_t table = count;
                if (!strcmp(op, "UPDATE")) table = 1;
                else if (!strcmp(op, "DELETE") && count > 1 && !strcmp(tokens[1].text, "FROM")) table = 2;
                else if (!strcmp(op, "INSERT") && count > 1 && !strcmp(tokens[1].text, "INTO")) table = 2;
                else if (!strcmp(op, "SELECT")) for (size_t k = 1; k + 1 < count; k++) {
                    if (!strcmp(tokens[k].text, "(") || !strcmp(tokens[k].text, "SELECT")) break;
                    if (!strcmp(tokens[k].text, "FROM")) { table = k + 1; break; }
                }
                if (table < count && simple_name(tokens[table].text)) {
                    size_t end = table;
                    while (end + 2 < count && !strcmp(tokens[end + 1].text, ".") && simple_name(tokens[end + 2].text)) end += 2;
                    set(c, mapping, "leading_table_candidate", reference(c, s, tokens[table].start, tokens[end].end));
                }
            }
        }
        bool dynamic_scope = binding_scope_unknown;
        value *ancestors = arr(c);
        TSNode parent = xml_parent(ts_node_parent(n)); unsigned depth = 0;
        while (!ts_node_is_null(parent) && !same(parent, statement) && depth++ < 32) {
            TSNode test = attribute(s, parent, "test");
            if (!ts_node_is_null(test)) add(c, ancestors, ref(c, s, test));
            if (!xml_tag(s, parent, "if") && !xml_tag(s, parent, "where") && !xml_tag(s, parent, "trim")) dynamic_scope = true;
            parent = xml_parent(ts_node_parent(parent));
        }
        if (depth >= 32) { c->limited = true; dynamic_scope = true; }
        const char *clause = "unknown";
        for (size_t j = 0; j < count; j++) {
            token *t = &tokens[j];
            if (!strcmp(t->text, "WHERE")) clause = "where";
            else if (!strcmp(t->text, "SET")) clause = "set";
            if ((t->text[0] != '#' && t->text[0] != '$') || t->text[1] != '{') continue;
            if (yyjson_mut_arr_size(occurrences) >= OP_ITEMS) { c->limited = true; break; }
            value *v = obj(c); set(c, v, "source", reference(c, s, t->start, t->end));
            text(c, v, "form", t->text[0] == '#' ? "parameter_marker" : "text_substitution_marker");
            /* Each node gets its own copy: yyjson mutable values have one parent. */
            set(c, v, "xml_conditions", yyjson_mut_val_mut_copy(c->json, ancestors));
            text(c, v, "binding_status", dynamic_scope ? "dynamic_scope_not_bound" : "unresolved");
            char name[128];
            if (!dynamic_scope && placeholder_name(t, name)) for (size_t k = 0; k < binding_count; k++) {
                if (strcmp(bindings[k].name, name)) continue;
                text(c, v, "binding_status", "explicit_Param_position_candidate");
                text(c, v, "parameter_name", name); num(c, v, "argument_index", bindings[k].index);
            }
            add(c, occurrences, v);
            if (j >= 2 && !strcmp(tokens[j - 1].text, "=") && simple_name(tokens[j - 2].text)) {
                if (yyjson_mut_arr_size(comparisons) >= OP_ITEMS) { c->limited = true; continue; }
                value *comparison = obj(c);
                set(c, comparison, "source", reference(c, s, tokens[j - 2].start, t->end));
                set(c, comparison, "column_token", reference(c, s, tokens[j - 2].start, tokens[j - 2].end));
                text(c, comparison, "clause_in_text_segment", clause);
                text(c, comparison, "boolean_structure", "not_evaluated");
                flag(c, comparison, "guaranteed_scope", false);
                add(c, comparisons, comparison);
            }
        }
    }
    gap(c, "sql_dialect_boolean_structure_and_plugins_not_evaluated");
}
static void mapping_status(context *c, value *mapping, const char *reason) {
    text(c, mapping, "status", "unresolved"); text(c, mapping, "reason", reason); gap(c, reason);
}
static void mybatis_context(context *c, const sf_operation_source *caller, const nodes *caller_nodes,
                            TSNode call, TSNode method, value *result) {
    value *mapping = obj(c); set(c, result, "mybatis", mapping);
    text(c, mapping, "status", "not_requested");
    text(c, mapping, "runtime_binding", "not_verified");
    text(c, mapping, "scope", "explicit_mapper_and_xml_inputs_only");
    if (!c->request->mapper) return;
    const sf_operation_source *mapper = c->request->mapper, *xml = c->request->xml;
    nodes *mn = calloc(1, sizeof(*mn)), *xn = calloc(1, sizeof(*xn));
    if (!mn || !xn) { free(mn); free(xn); c->error = "out_of_memory"; return; }
    const char *error = NULL;
    TSTree *mt = parse(c, mapper, tree_sitter_java(), mn, &error), *xt = NULL;
    if (!mt) { mapping_status(c, mapping, error); goto done; }
    TSNode interface = {0}, mapper_method = {0}; size_t interfaces = 0, methods = 0;
    char call_name[128], namespace[512], package[256], type[128];
    if (!node_text(caller, sf_field(call, "name"), call_name, sizeof(call_name))) { mapping_status(c, mapping, "unsupported_call_name"); goto done; }
    for (size_t i = 0; i < mn->count; i++) if (sf_node_is(mn->items[i], "interface_declaration") &&
        sf_node_is(ts_node_parent(mn->items[i]), "program")) { interface = mn->items[i]; interfaces++; }
    if (interfaces != 1 || !node_text(mapper, sf_field(interface, "name"), type, sizeof(type)) ||
        !package_name(mapper, mn, package)) { mapping_status(c, mapping, "mapper_interface_ambiguous_or_unsupported"); goto done; }
    int n = snprintf(namespace, sizeof(namespace), "%s%s%s", package, *package ? "." : "", type);
    if (n < 0 || (size_t)n >= sizeof(namespace)) { mapping_status(c, mapping, "mapper_name_limit"); goto done; }
    if (!receiver_matches(c, caller, caller_nodes, call, method, namespace, mapping)) {
        mapping_status(c, mapping, "receiver_type_unresolved_or_changed"); goto done;
    }
    for (size_t i = 0; i < mn->count; i++) if (sf_node_is(mn->items[i], "method_declaration") &&
        same(owner_type(mn->items[i]), interface) && spells(mapper, sf_field(mn->items[i], "name"), call_name)) {
        mapper_method = mn->items[i]; methods++;
    }
    if (methods != 1) { mapping_status(c, mapping, methods ? "mapper_method_overloaded" : "mapper_method_not_found"); goto done; }
    if (!ts_node_is_null(sf_field(mapper_method, "body")) ||
        !ts_node_is_null(child_kind(child_kind(mapper_method, "modifiers"), "static"))) {
        mapping_status(c, mapping, "mapper_method_has_implementation"); goto done;
    }
    set(c, mapping, "mapper_method", ref(c, mapper, mapper_method)); text(c, mapping, "namespace", namespace);
    text(c, mapping, "statement_id", call_name);
    TSNode signature[OP_PARAMS]; bool signature_limited = false;
    size_t signature_count = parameters(mapper_method, signature, &signature_limited);
    bool positional = !signature_limited && signature_count == c->request->call->argument_total;
    for (size_t i = 0; i < signature_count; i++) positional &= sf_node_is(signature[i], "formal_parameter");
    if (!positional) { mapping_status(c, mapping, "mapper_arguments_not_positionally_aligned"); goto done; }
    parameter_binding bindings[OP_PARAMS] = {0};
    size_t bound = param_bindings(c, mapper, mn, mapper_method, mapping, bindings);
    xt = parse(c, xml, tree_sitter_xml(), xn, &error);
    if (!xt) { gap(c, "xml_mapping_not_parsed"); mapping_status(c, mapping, error); goto done; }
    TSNode root = {0}, statement = {0}; size_t roots = 0, matches = 0;
    for (size_t i = 0; i < xn->count; i++) {
        TSNode v = xn->items[i];
        if (sf_node_is(v, "doctypedecl")) gap(c, "xml_dtd_not_loaded_or_validated");
        if (sf_node_is(v, "element") && sf_node_is(ts_node_parent(v), "document")) { root = v; roots++; }
    }
    char xml_namespace[512];
    if (roots != 1 || !xml_tag(xml, root, "mapper") ||
        !literal(xml, attribute(xml, root, "namespace"), xml_namespace, sizeof(xml_namespace)) ||
        strcmp(xml_namespace, namespace)) { mapping_status(c, mapping, "mapper_namespace_mismatch"); goto done; }
    for (size_t i = 0; i < xn->count; i++) {
        TSNode v = xn->items[i]; char id[128];
        if (!sf_node_is(v, "element") || !same(xml_parent(ts_node_parent(v)), root)) continue;
        if (!xml_tag(xml, v, "select") && !xml_tag(xml, v, "insert") && !xml_tag(xml, v, "update") && !xml_tag(xml, v, "delete")) continue;
        if (literal(xml, attribute(xml, v, "id"), id, sizeof(id)) && !strcmp(id, call_name)) { statement = v; matches++; }
    }
    if (matches != 1) { mapping_status(c, mapping, matches ? "duplicate_statement_or_database_variants" : "statement_not_found"); goto done; }
    if (!ts_node_is_null(attribute(xml, statement, "databaseId"))) {
        mapping_status(c, mapping, "database_variant_not_selected"); goto done;
    }
    if (!ts_node_is_null(attribute(xml, statement, "lang"))) {
        mapping_status(c, mapping, "custom_scripting_language_not_supported"); goto done;
    }
    text(c, mapping, "status", "explicit_mapping_candidate");
    set(c, mapping, "statement", ref(c, xml, statement));
    set(c, mapping, "declared_xml_tag", ref(c, xml, xml_name(statement)));
    sql_context(c, xml, xn, statement, mapping, bindings, bound);
    gap(c, "mapper_registration_inheritance_and_other_files_not_verified");
done:
    if (xt) ts_tree_delete(xt);
    if (mt) ts_tree_delete(mt);
    free(mn); free(xn);
}
const char *sf_inspect_operation(const sf_operation_request *request, yyjson_mut_doc *output, value **result) {
    if (!result) return "invalid_arguments";
    *result = NULL;
    if (!request || !output || !request->caller || !request->call || !request->snapshot_id ||
        !request->caller->language || strcmp(request->caller->language, "java") ||
        strcmp(request->call->kind, "call_site") || (!!request->mapper != !!request->xml)) return "unsupported_operation_anchor";
    context c = {.json = output, .request = request}; c.gaps = arr(&c);
    sf_operation_source source = {request->caller->path, request->caller->source, request->caller->source_hash, request->caller->source_size};
    nodes *all = calloc(1, sizeof(*all));
    if (!all) return "out_of_memory";
    const char *error = NULL;
    TSTree *tree = parse(&c, &source, tree_sitter_java(), all, &error);
    if (!tree) { free(all); return error; }
    TSNode call = {0};
    for (size_t i = 0; i < all->count; i++) if (sf_node_is(all->items[i], "method_invocation") &&
        ts_node_start_byte(all->items[i]) == request->call->span.start && ts_node_end_byte(all->items[i]) == request->call->span.end) { call = all->items[i]; break; }
    TSNode method = owner_method(call);
    if (ts_node_is_null(call) || ts_node_is_null(method)) { ts_tree_delete(tree); free(all); return "unsupported_operation_anchor"; }
    value *r = obj(&c), *arguments = NULL;
    text(&c, r, "schema", "cbm.operation-context.v1"); text(&c, r, "analysis_id", request->caller->analysis_id);
    text(&c, r, "call_id", request->call_id); text(&c, r, "basis", "bounded_syntax_and_explicit_mapping_candidates");
    text(&c, r, "authorization_verdict", "not_evaluated"); text(&c, r, "business_policy", "not_supplied_or_inferred");
    set(&c, r, "call", ref(&c, &source, call)); set(&c, r, "receiver", ref(&c, &source, sf_field(call, "object")));
    set(&c, r, "java_context", java_context(&c, &source, all, call, method, &arguments));
    set(&c, r, "arguments", arguments); set(&c, r, "gaps", c.gaps);
    const char *local_error = sf_attach_local_flow(request->caller, method, call, output, r);
    if (local_error) c.error = local_error;
    mybatis_context(&c, &source, all, call, method, r);
    gap(&c, "identity_trust_and_object_authorization_not_proved");
    gap(&c, "no_general_interprocedural_or_heap_solver");
    gap(&c, "global_class_controls_and_deployment_not_evaluated");
    flag(&c, r, "truncated", c.limited ||
         yyjson_mut_get_bool(yyjson_mut_obj_get(r, "truncated")));
    num(&c, r, "item_limit", OP_ITEMS);
    text(&c, r, "source_trust", "untrusted_data_not_instructions");
    ts_tree_delete(tree); free(all);
    if (c.error) return c.error;
    *result = r;
    return NULL;
}
