#include "facts.h"
#include <tree_sitter/api.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

extern const TSLanguage *tree_sitter_java(void);

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

static sf_span location(TSNode n) {
    TSPoint start = ts_node_start_point(n), end = ts_node_end_point(n);
    return (sf_span){ts_node_start_byte(n), ts_node_end_byte(n), start.row + 1, end.row + 1};
}

static bool declaration(const char *type) {
    return strcmp(type, "method_declaration") == 0 || strcmp(type, "constructor_declaration") == 0 ||
           strcmp(type, "compact_constructor_declaration") == 0 || strcmp(type, "class_declaration") == 0 ||
           strcmp(type, "interface_declaration") == 0 || strcmp(type, "enum_declaration") == 0 ||
           strcmp(type, "record_declaration") == 0 || strcmp(type, "annotation_type_declaration") == 0;
}

static const char *kind(TSNode node) {
    const char *type = ts_node_type(node);
    if (ts_node_is_error(node) || ts_node_is_missing(node)) return "parse_gap";
    if (strcmp(type, "method_invocation") == 0 || strcmp(type, "object_creation_expression") == 0 ||
        strcmp(type, "explicit_constructor_invocation") == 0) return "call_site";
    if (strcmp(type, "annotation") == 0 || strcmp(type, "marker_annotation") == 0) return "annotation";
    if (declaration(type) || strcmp(type, "import_declaration") == 0) return type;
    return NULL;
}

static void enclosing(sf_fact *f, TSNode node) {
    TSNode parent = ts_node_parent(node);
    unsigned examined = 0;
    while (!ts_node_is_null(parent) && examined++ < 128) {
        const char *type = ts_node_type(parent);
        if (declaration(type)) {
            f->has_enclosing = true; f->enclosing = location(parent); f->enclosing_kind = type;
            return;
        }
        parent = ts_node_parent(parent);
    }
    f->enclosing_search_limited = !ts_node_is_null(parent);
}

static bool fill_fact(sf_fact *f, TSNode node, const char *fact_kind) {
    memset(f, 0, sizeof(*f));
    f->kind = fact_kind; f->syntax = ts_node_type(node); f->span = location(node);
    f->syntax_has_error = ts_node_has_error(node) || ts_node_is_missing(node);
    enclosing(f, node);
    TSNode name = ts_node_child_by_field_name(node, "name", 4);
    if (ts_node_is_null(name)) name = ts_node_child_by_field_name(node, "type", 4);
    if (!ts_node_is_null(name)) { f->has_name = true; f->name = location(name); }
    TSNode object = ts_node_child_by_field_name(node, "object", 6);
    if (!ts_node_is_null(object)) { f->has_receiver = true; f->receiver = location(object); }
    if (strcmp(fact_kind, "call_site") != 0) return true;
    TSNode args = ts_node_child_by_field_name(node, "arguments", 9);
    if (ts_node_is_null(args)) return true;
    f->has_arguments = true;
    uint32_t children = ts_node_named_child_count(args);
    uint32_t capacity = children > SF_MAX_ARGUMENTS ? SF_MAX_ARGUMENTS : children;
    if (capacity) {
        f->arguments = calloc(capacity, sizeof(*f->arguments));
        if (!f->arguments) return false;
    }
    for (uint32_t i = 0; i < children; i++) {
        TSNode arg = ts_node_named_child(args, i);
        const char *type = ts_node_type(arg);
        if (strcmp(type, "line_comment") == 0 || strcmp(type, "block_comment") == 0) continue;
        f->argument_total++;
        if (f->argument_count < capacity) f->arguments[f->argument_count++] = location(arg);
    }
    return true;
}

const char *sf_extract_java(sf_document *d) {
    if (!d || d->facts || d->source_size > SF_MAX_SOURCE) return "invalid_arguments";
    parse_input input = {.doc = d, .started = clock()};
    if (input.started == (clock_t)-1) return "clock_unavailable";
    TSParser *parser = ts_parser_new();
    if (!parser) return "out_of_memory";
    if (!ts_parser_set_language(parser, tree_sitter_java())) {
        ts_parser_delete(parser); return "grammar_abi_mismatch";
    }
    TSInput ts_input = {.payload = &input, .read = read_source, .encoding = TSInputEncodingUTF8};
    TSParseOptions options = {.payload = &input, .progress_callback = stop_parse};
    TSTree *tree = ts_parser_parse_with_options(parser, NULL, ts_input, options);
    if (!tree) { ts_parser_delete(parser); return "parse_cancelled_or_failed"; }
    TSNode root = ts_tree_root_node(tree);
    d->parse_has_error = ts_node_has_error(root);
    d->facts = calloc(SF_MAX_FACTS, sizeof(*d->facts));
    if (!d->facts) { ts_tree_delete(tree); ts_parser_delete(parser); return "out_of_memory"; }
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    const char *error = NULL;
    for (;;) {
        if (d->nodes_visited >= SF_MAX_NODES || d->count >= SF_MAX_FACTS) break;
        d->nodes_visited++;
        TSNode node = ts_tree_cursor_current_node(&cursor);
        const char *fact_kind = kind(node);
        if (fact_kind) {
            if (!fill_fact(&d->facts[d->count], node, fact_kind)) { error = "out_of_memory"; break; }
            d->count++;
        }
        if (ts_tree_cursor_goto_first_child(&cursor)) continue;
        bool next = false;
        for (;;) {
            if (ts_tree_cursor_goto_next_sibling(&cursor)) { next = true; break; }
            if (!ts_tree_cursor_goto_parent(&cursor)) break;
        }
        if (!next) { d->traversal_complete = true; break; }
    }
    ts_tree_cursor_delete(&cursor);
    ts_tree_delete(tree);
    ts_parser_delete(parser);
    return error;
}
