#include "parser.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

extern const TSLanguage *tree_sitter_java(void);
extern const TSLanguage *tree_sitter_python(void);
extern const TSLanguage *tree_sitter_javascript(void);
extern const TSLanguage *tree_sitter_typescript(void);
extern const TSLanguage *tree_sitter_tsx(void);
extern const TSLanguage *tree_sitter_go(void);

bool sf_node_is(TSNode n, const char *type) {
    return !ts_node_is_null(n) && strcmp(ts_node_type(n), type) == 0;
}
TSNode sf_field(TSNode n, const char *name) {
    if (ts_node_is_null(n)) return (TSNode){0};
    return ts_node_child_by_field_name(n, name, (uint32_t)strlen(name));
}
sf_span sf_location(TSNode n) {
    TSPoint start = ts_node_start_point(n), end = ts_node_end_point(n);
    return (sf_span){ts_node_start_byte(n), ts_node_end_byte(n), start.row + 1, end.row + 1};
}
bool sf_node_text(const sf_document *d, TSNode n, char *out, size_t capacity) {
    if (ts_node_is_null(n) || !capacity) return false;
    sf_span p = sf_location(n);
    if (p.end < p.start || p.end > d->source_size || p.end - p.start >= capacity) return false;
    memcpy(out, d->source + p.start, p.end - p.start); out[p.end - p.start] = 0;
    return true;
}
TSNode sf_single(TSNode n) {
    if ((sf_node_is(n, "expression_list") || sf_node_is(n, "parenthesized_expression")) && ts_node_named_child_count(n) == 1)
        return ts_node_named_child(n, 0);
    return n;
}
TSNode sf_call_target(TSNode n) {
    TSNode target = sf_field(n, "function");
    if (ts_node_is_null(target)) target = sf_field(n, "constructor");
    return target;
}

/* Each walk has a fixed node budget. No recursion on attacker-controlled syntax. */
bool sf_walk(TSNode root, bool (*visit)(TSNode, void *), void *context, size_t *visited) {
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    bool complete = false;
    *visited = 0;
    for (;;) {
        if (*visited >= SF_MAX_NODES) break;
        (*visited)++;
        if (!visit(ts_tree_cursor_current_node(&cursor), context)) break;
        if (ts_tree_cursor_goto_first_child(&cursor)) continue;
        bool next = false;
        for (;;) {
            if (ts_tree_cursor_goto_next_sibling(&cursor)) { next = true; break; }
            if (!ts_tree_cursor_goto_parent(&cursor)) break;
        }
        if (!next) { complete = true; break; }
    }
    ts_tree_cursor_delete(&cursor);
    return complete;
}

static bool declaration(TSNode node) {
    static const char *const types[] = {
        "method_declaration", "constructor_declaration", "compact_constructor_declaration",
        "class_declaration", "interface_declaration", "enum_declaration", "record_declaration",
        "annotation_type_declaration", "function_definition", "class_definition",
        "function_declaration", "generator_function_declaration", "method_definition",
        "arrow_function", "function_expression", "generator_function", "func_literal",
        "type_spec", "function_signature", "abstract_method_signature"
    };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) if (sf_node_is(node, types[i])) return true;
    return false;
}
static const char *kind(TSNode node) {
    if (ts_node_is_error(node) || ts_node_is_missing(node)) return "parse_gap";
    if (sf_node_is(node, "method_invocation") || sf_node_is(node, "object_creation_expression") ||
        sf_node_is(node, "explicit_constructor_invocation") || sf_node_is(node, "call") ||
        sf_node_is(node, "call_expression") || sf_node_is(node, "new_expression")) return "call_site";
    if (sf_node_is(node, "annotation") || sf_node_is(node, "marker_annotation")) return "annotation";
    if (sf_node_is(node, "decorator")) return "decorator";
    if (declaration(node) || sf_node_is(node, "import_declaration") || sf_node_is(node, "import_statement") ||
        sf_node_is(node, "import_from_statement") || sf_node_is(node, "import_spec") ||
        sf_node_is(node, "variable_declarator") || sf_node_is(node, "assignment") ||
        sf_node_is(node, "short_var_declaration") || sf_node_is(node, "var_spec")) return ts_node_type(node);
    return NULL;
}

static void enclosing(sf_fact *f, TSNode node) {
    TSNode parent = ts_node_parent(node);
    unsigned examined = 0;
    while (!ts_node_is_null(parent) && examined++ < 128) {
        if (declaration(parent)) {
            f->has_enclosing = true; f->enclosing = sf_location(parent); f->enclosing_kind = ts_node_type(parent); return;
        }
        if (sf_node_is(parent, "decorated_definition") || sf_node_is(parent, "export_statement")) {
            for (uint32_t i = 0; i < ts_node_named_child_count(parent); i++) {
                TSNode child = ts_node_named_child(parent, i);
                if (declaration(child) && ts_node_start_byte(child) > ts_node_start_byte(node)) {
                    f->has_enclosing = true; f->enclosing = sf_location(child); f->enclosing_kind = ts_node_type(child); return;
                }
            }
        }
        parent = ts_node_parent(parent);
    }
    f->enclosing_search_limited = !ts_node_is_null(parent);
}

static bool comment(TSNode n) {
    return sf_node_is(n, "comment") || sf_node_is(n, "line_comment") || sf_node_is(n, "block_comment");
}
static bool expansion(TSNode n) {
    return sf_node_is(n, "list_splat") || sf_node_is(n, "dictionary_splat") || sf_node_is(n, "spread_element") || sf_node_is(n, "variadic_argument");
}
static bool fill_fact(sf_fact *f, TSNode node, const char *fact_kind) {
    memset(f, 0, sizeof(*f));
    f->kind = fact_kind; f->syntax = ts_node_type(node); f->span = sf_location(node);
    f->syntax_has_error = ts_node_has_error(node) || ts_node_is_missing(node);
    enclosing(f, node);
    TSNode name = sf_field(node, "name"), object = sf_field(node, "object");
    if (ts_node_is_null(name)) name = sf_field(node, "type");
    TSNode target = sf_call_target(node);
    if (strcmp(fact_kind, "call_site") == 0 && !ts_node_is_null(target)) {
        name = target;
        if (sf_node_is(target, "attribute")) { name = sf_field(target, "attribute"); object = sf_field(target, "object"); }
        else if (sf_node_is(target, "member_expression")) { name = sf_field(target, "property"); object = sf_field(target, "object"); }
        else if (sf_node_is(target, "selector_expression")) { name = sf_field(target, "field"); object = sf_field(target, "operand"); }
    }
    if (!ts_node_is_null(name)) { f->has_name = true; f->name = sf_location(name); }
    if (!ts_node_is_null(object)) { f->has_receiver = true; f->receiver = sf_location(object); }
    if (strcmp(fact_kind, "call_site") != 0) return true;
    TSNode args = sf_field(node, "arguments");
    if (ts_node_is_null(args)) return true;
    f->has_arguments = true;
    uint32_t children = ts_node_named_child_count(args);
    uint32_t capacity = children > SF_MAX_ARGUMENTS ? SF_MAX_ARGUMENTS : children;
    if (capacity) {
        f->arguments = calloc(capacity, sizeof(*f->arguments));
        if (!f->arguments) return false;
    }
    TSTreeCursor cursor = ts_tree_cursor_new(args);
    if (ts_tree_cursor_goto_first_child(&cursor)) {
        do {
            TSNode arg = ts_tree_cursor_current_node(&cursor);
            if (!ts_node_is_named(arg) || comment(arg)) continue;
            f->argument_total++;
            f->has_argument_expansion |= expansion(arg);
            if (f->argument_count < capacity) f->arguments[f->argument_count++] = sf_location(arg);
        } while (ts_tree_cursor_goto_next_sibling(&cursor));
    }
    ts_tree_cursor_delete(&cursor);
    return true;
}

typedef struct { const sf_document *doc; clock_t started; } parse_input;
static const char *read_source(void *payload, uint32_t offset, TSPoint point, uint32_t *length) {
    (void)point;
    const sf_document *d = ((parse_input *)payload)->doc;
    size_t remaining = offset < d->source_size ? d->source_size - offset : 0;
    *length = (uint32_t)(remaining > 4096 ? 4096 : remaining);
    return remaining ? d->source + offset : "";
}
static bool stop_parse(TSParseState *state) {
    parse_input *input = state->payload;
    clock_t now = clock();
    return now == (clock_t)-1 || (double)(now - input->started) / CLOCKS_PER_SEC > 3.0;
}
static const TSLanguage *grammar(const char *language) {
    if (strcmp(language, "java") == 0) return tree_sitter_java();
    if (strcmp(language, "python") == 0) return tree_sitter_python();
    if (strcmp(language, "javascript") == 0) return tree_sitter_javascript();
    if (strcmp(language, "typescript") == 0) return tree_sitter_typescript();
    if (strcmp(language, "tsx") == 0) return tree_sitter_tsx();
    if (strcmp(language, "go") == 0) return tree_sitter_go();
    return NULL;
}
typedef struct { sf_document *doc; sf_models *models; const char *error; } extract_context;
static bool extract_node(TSNode node, void *opaque) {
    extract_context *ctx = opaque;
    const char *fact_kind = kind(node);
    if (!fact_kind) return true;
    if (ctx->doc->count >= SF_MAX_FACTS) return false;
    sf_fact *f = &ctx->doc->facts[ctx->doc->count];
    if (!fill_fact(f, node, fact_kind)) { free(f->arguments); memset(f, 0, sizeof(*f)); ctx->error = "out_of_memory"; return false; }
    sf_models_apply(ctx->models, f, node);
    ctx->doc->count++;
    return true;
}

const char *sf_extract_tree(sf_document *d, TSTree **retained) {
    if (retained) *retained = NULL;
    if (!d || !d->language || d->facts || d->source_size > SF_MAX_SOURCE) return "invalid_arguments";
    const TSLanguage *lang = grammar(d->language);
    if (!lang) return "unsupported_language";
    parse_input input = {.doc = d, .started = clock()};
    if (input.started == (clock_t)-1) return "clock_unavailable";
    TSParser *parser = ts_parser_new();
    if (!parser) return "out_of_memory";
    if (!ts_parser_set_language(parser, lang)) { ts_parser_delete(parser); return "grammar_abi_mismatch"; }
    TSInput ts_input = {.payload = &input, .read = read_source, .encoding = TSInputEncodingUTF8};
    TSParseOptions options = {.payload = &input, .progress_callback = stop_parse};
    TSTree *tree = ts_parser_parse_with_options(parser, NULL, ts_input, options);
    if (!tree) { ts_parser_delete(parser); return "parse_cancelled_or_failed"; }
    d->parse_has_error = ts_node_has_error(ts_tree_root_node(tree));
    d->facts = calloc(SF_MAX_FACTS, sizeof(*d->facts));
    if (!d->facts) { ts_tree_delete(tree); ts_parser_delete(parser); return "out_of_memory"; }
    sf_models *models = sf_models_new(d, ts_tree_root_node(tree));
    if (!models) { ts_tree_delete(tree); ts_parser_delete(parser); return "out_of_memory"; }
    extract_context ctx = {.doc = d, .models = models};
    d->traversal_complete = sf_walk(ts_tree_root_node(tree), extract_node, &ctx, &d->nodes_visited);
    d->framework_analysis_complete &= d->traversal_complete;
    sf_models_free(models); ts_parser_delete(parser);
    if (retained && !ctx.error) *retained = tree; else ts_tree_delete(tree);
    return ctx.error;
}

const char *sf_extract(sf_document *d) { return sf_extract_tree(d, NULL); }

const char *sf_extract_java(sf_document *d) {
    if (!d || !d->language || strcmp(d->language, "java") != 0) return "invalid_arguments";
    return sf_extract(d);
}
