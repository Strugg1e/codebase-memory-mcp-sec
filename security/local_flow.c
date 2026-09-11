/* Java local value identities and explicit expression dependencies.
 * References: JLS 14 (completion/blocks), 15.7 (evaluation order), 15.26
 * (assignment). This deliberately does NOT implement Java's full semantics.
 * Unknown controls poison values instead of inventing a clean result. */
#include "local_flow.h"

#include <stdlib.h>
#include <string.h>

#define LF_PARAMS 64U
#define LF_VARS 256U
#define LF_EVENTS 256U
#define LF_WORDS (LF_EVENTS / 64U)
#define LF_STEPS 20000U
#define LF_DEPTH 64U
#define RS_METHODS 32U
#define RS_DEPTH 8U
#define RS_STEPS 60000U

enum {
    U_NAME = 1U, U_UNINITIALIZED = 2U, U_HEAP = 4U, U_CALL = 8U,
    U_EXPRESSION = 16U, U_CONTROL = 32U, U_LIMIT = 64U,
    U_ANCHOR = 128U, U_UNICODE = 256U, U_PARAMETER = 512U,
    U_TARGET = 1024U, U_RECURSION = 2048U, U_SUMMARY_LIMIT = 4096U,
    U_RETURN = 8192U
};
static const struct { unsigned bit; const char *name; } reasons[] = {
    {U_NAME, "local_binding_not_resolved"}, {U_UNINITIALIZED, "local_not_initialized"},
    {U_HEAP, "heap_contents_not_modeled"}, {U_CALL, "call_return_not_modeled"},
    {U_EXPRESSION, "expression_not_modeled"}, {U_CONTROL, "control_construct_not_modeled"},
    {U_LIMIT, "local_flow_budget_exceeded"}, {U_ANCHOR, "anchor_not_reached_in_supported_structure"},
    {U_UNICODE, "java_unicode_escape_not_modeled"}, {U_PARAMETER, "parameter_form_not_modeled"},
    {U_TARGET, "return_summary_target_not_resolved"},
    {U_RECURSION, "recursive_return_summary_not_solved"},
    {U_SUMMARY_LIMIT, "return_summary_budget_exceeded"},
    {U_RETURN, "normal_return_not_established"}
};
/* direct and derived are disjoint only per path. A join can have both bits for
 * the same formal: x in one branch and x+1 in the other. Never collapse them. */
typedef struct {
    uint64_t direct, derived, evidence[LF_WORDS];
    unsigned unknown;
    bool literal;
} origin;
typedef struct { TSNode name; origin value; } variable;
typedef struct { variable vars[LF_VARS]; size_t count; bool alive; } environment;
typedef struct { TSNode node; const char *kind; } event;
/* Symbolic returns use callee parameter positions. Evidence numbering is local
 * to each summary and is remapped when the summary is instantiated at a call. */
typedef struct {
    TSNode method;
    origin returned;
    event events[LF_EVENTS];
    size_t nevents, nparams, return_count;
    bool busy;
} return_summary;
typedef struct {
    return_summary entries[RS_METHODS];
    size_t count, depth, steps, requests, hits;
    bool limited;
} summary_bank;
typedef yyjson_mut_val value;
typedef struct {
    const sf_document *doc;
    TSNode anchor, method, params[LF_PARAMS];
    origin arguments[LF_PARAMS], returned;
    summary_bank *summaries;
    size_t return_count;
    bool summary_mode;
    event events[LF_EVENTS];
    size_t nparams, nargs, nevents, steps;
    unsigned prefix_gaps;
    bool found, limited, aborted;
    yyjson_mut_doc *json;
    const char *error;
} engine;

static bool is(TSNode n, const char *kind) { return sf_node_is(n, kind); }
static bool same(TSNode a, TSNode b) {
    return !ts_node_is_null(a) && !ts_node_is_null(b) && ts_node_eq(a, b);
}
static bool contains(TSNode outer, TSNode inner) {
    return !ts_node_is_null(outer) && !ts_node_is_null(inner) &&
           ts_node_start_byte(outer) <= ts_node_start_byte(inner) &&
           ts_node_end_byte(inner) <= ts_node_end_byte(outer);
}
static bool spells(engine *e, TSNode a, const char *word) {
    if (ts_node_is_null(a)) return false;
    size_t start = ts_node_start_byte(a), end = ts_node_end_byte(a), n = strlen(word);
    return end >= start && end <= e->doc->source_size && end - start == n &&
           !memcmp(e->doc->source + start, word, n);
}
static bool same_name(engine *e, TSNode a, TSNode b) {
    if (ts_node_is_null(a) || ts_node_is_null(b)) return false;
    size_t x = ts_node_start_byte(a), y = ts_node_start_byte(b);
    size_t n = ts_node_end_byte(a) - x, m = ts_node_end_byte(b) - y;
    return n == m && x + n <= e->doc->source_size && y + m <= e->doc->source_size &&
           !memcmp(e->doc->source + x, e->doc->source + y, n);
}
static bool comment(TSNode n) { return is(n, "line_comment") || is(n, "block_comment"); }
static TSNode first_named(TSNode n) {
    TSNode found = {0};
    TSTreeCursor c = ts_tree_cursor_new(n);
    if (ts_tree_cursor_goto_first_child(&c)) do {
        TSNode child = ts_tree_cursor_current_node(&c);
        if (ts_node_is_named(child) && !comment(child)) { found = child; break; }
    } while (ts_tree_cursor_goto_next_sibling(&c));
    ts_tree_cursor_delete(&c); return found;
}
static origin unknown(unsigned reason) { return (origin){.unknown = reason}; }
static origin join(origin a, origin b) {
    a.direct |= b.direct; a.derived |= b.derived; a.unknown |= b.unknown;
    a.literal |= b.literal;
    for (size_t i = 0; i < LF_WORDS; i++) a.evidence[i] |= b.evidence[i];
    return a;
}
static origin transform(origin a) { a.derived |= a.direct; a.direct = 0; return a; }
static bool tick(engine *e, unsigned depth) {
    if (e->found || e->aborted) return false;
    if (++e->steps > LF_STEPS || depth > LF_DEPTH) {
        e->limited = true; e->aborted = true; e->prefix_gaps |= U_LIMIT; return false;
    }
    if (e->summaries && ++e->summaries->steps > RS_STEPS) {
        e->summaries->limited = true; e->limited = e->aborted = true;
        e->prefix_gaps |= U_SUMMARY_LIMIT; return false;
    }
    return true;
}
static origin stamp(engine *e, origin v, TSNode n, const char *kind) {
    if (e->aborted) { v.unknown |= e->prefix_gaps; return v; }
    size_t index = 0;
    for (; index < e->nevents; index++)
        if (same(e->events[index].node, n) && !strcmp(e->events[index].kind, kind)) break;
    if (index == LF_EVENTS) { e->limited = e->aborted = true; e->prefix_gaps |= U_LIMIT; v.unknown |= U_LIMIT; return v; }
    if (index == e->nevents) e->events[e->nevents++] = (event){n, kind};
    v.evidence[index / 64U] |= UINT64_C(1) << (index % 64U);
    return v;
}
static int binding(engine *e, environment *s, TSNode name) {
    for (size_t i = s->count; i; i--)
        if (same_name(e, s->vars[i - 1].name, name)) return (int)(i - 1);
    return -1;
}
static void poison(engine *e, environment *s, unsigned reason, TSNode node) {
    e->prefix_gaps |= reason;
    for (size_t i = 0; i < s->count; i++) {
        s->vars[i].value.unknown |= reason;
        s->vars[i].value = stamp(e, s->vars[i].value, node, "unknown_effect");
    }
}
static environment *copy_state(engine *e, environment *s) {
    environment *r = malloc(sizeof(*r));
    if (!r) { e->error = "out_of_memory"; e->aborted = true; return NULL; }
    *r = *s; return r;
}
static void merge_state(engine *e, environment *a, const environment *b, TSNode node) {
    if (!b->alive) return;
    if (!a->alive) { *a = *b; return; }
    /* Branch block locals have already been popped. Equal indices are the
     * same declaration, not a name-only merge. */
    if (a->count != b->count) { poison(e, a, U_CONTROL, node); return; }
    for (size_t i = 0; i < a->count; i++)
        a->vars[i].value = stamp(e, join(a->vars[i].value, b->vars[i].value), node, "branch_join");
}
static origin expression(engine *, environment *, TSNode, unsigned);
static void statement(engine *, environment *, TSNode, unsigned);
static origin summarized_call(engine *, TSNode, const origin *, size_t);
static void init_parameters(engine *, environment *, TSNode);

/* Iterate siblings with a cursor: large argument/block lists must not turn
 * into quadratic calls to named_child(index). */
static origin arguments(engine *e, environment *s, TSNode list, unsigned depth, bool capture, origin *values, size_t *count) {
    origin all = {.literal = true}; size_t index = 0;
    if (ts_node_is_null(list)) return all;
    TSTreeCursor c = ts_tree_cursor_new(list);
    if (ts_tree_cursor_goto_first_child(&c)) do {
        TSNode n = ts_tree_cursor_current_node(&c);
        if (!ts_node_is_named(n) || comment(n)) continue;
        if (e->found || e->aborted) break;
        origin v = expression(e, s, n, depth + 1);
        bool literals = all.literal && v.literal;
        all = join(all, v); all.literal = literals;
        if (values && index < LF_PARAMS) values[index] = v;
        if (capture) {
            if (index >= LF_PARAMS) { e->limited = e->aborted = true; break; }
            e->arguments[index] = v;
        }
        index++;
    } while (ts_tree_cursor_goto_next_sibling(&c));
    ts_tree_cursor_delete(&c);
    if (capture) e->nargs = index;
    if (count) *count = index;
    return all;
}
static origin expression(engine *e, environment *s, TSNode n, unsigned depth) {
    if (ts_node_is_null(n)) return unknown(U_EXPRESSION);
    if (!tick(e, depth)) return unknown(U_LIMIT);
    if (is(n, "identifier")) {
        int i = binding(e, s, n);
        return stamp(e, i >= 0 ? s->vars[i].value : unknown(U_NAME), n, "local_read");
    }
    if (is(n, "decimal_integer_literal") || is(n, "hex_integer_literal") ||
        is(n, "octal_integer_literal") || is(n, "binary_integer_literal") ||
        is(n, "decimal_floating_point_literal") || is(n, "hex_floating_point_literal") ||
        is(n, "character_literal") || is(n, "string_literal") ||
        is(n, "true") || is(n, "false") || is(n, "null_literal"))
        return stamp(e, (origin){.literal = true}, n, "literal");
    if (is(n, "parenthesized_expression")) return expression(e, s, first_named(n), depth + 1);
    if (is(n, "cast_expression"))
        return stamp(e, transform(expression(e, s, sf_field(n, "value"), depth + 1)), n, "cast_dependency");
    if (is(n, "assignment_expression")) {
        TSNode left = sf_field(n, "left"), op = sf_field(n, "operator");
        int index = is(left, "identifier") ? binding(e, s, left) : -1;
        origin prior = index >= 0 ? s->vars[index].value : unknown(U_HEAP);
        if (!is(left, "identifier")) (void)expression(e, s, left, depth + 1);
        origin v = expression(e, s, sf_field(n, "right"), depth + 1);
        if (!spells(e, op, "=")) {
            bool literals = prior.literal && v.literal;
            v = transform(join(prior, v)); v.literal = literals;
        }
        v = stamp(e, v, n, "assignment");
        if (index >= 0 && !e->found) s->vars[index].value = v;
        return v;
    }
    if (is(n, "update_expression")) {
        TSNode operand = first_named(n);
        int index = is(operand, "identifier") ? binding(e, s, operand) : -1;
        origin old = expression(e, s, operand, depth + 1);
        origin v = stamp(e, transform(old), n, "update_dependency");
        if (index >= 0 && !e->found) s->vars[index].value = v;
        bool postfix = ts_node_start_byte(n) == ts_node_start_byte(operand);
        return postfix ? old : v;
    }
    if (is(n, "unary_expression"))
        return stamp(e, transform(expression(e, s, sf_field(n, "operand"), depth + 1)), n, "unary_dependency");
    if (is(n, "binary_expression")) {
        origin left = expression(e, s, sf_field(n, "left"), depth + 1);
        if (e->found || e->aborted) return left;
        TSNode right = sf_field(n, "right"), op = sf_field(n, "operator");
        bool conditional = spells(e, op, "&&") || spells(e, op, "||");
        environment *skipped = conditional ? copy_state(e, s) : NULL;
        if (conditional && !skipped) return unknown(U_LIMIT);
        origin rhs = expression(e, s, right, depth + 1);
        if (skipped && !e->found) merge_state(e, s, skipped, n);
        free(skipped);
        bool literals = left.literal && rhs.literal;
        origin v = transform(join(left, rhs)); v.literal = literals;
        return stamp(e, v, n, "binary_dependency");
    }
    if (is(n, "ternary_expression")) {
        (void)expression(e, s, sf_field(n, "condition"), depth + 1);
        if (e->found || e->aborted) return unknown(U_ANCHOR);
        TSNode a = sf_field(n, "consequence"), b = sf_field(n, "alternative");
        if (contains(a, e->anchor)) return expression(e, s, a, depth + 1);
        if (contains(b, e->anchor)) return expression(e, s, b, depth + 1);
        environment *other = copy_state(e, s);
        if (!other) return unknown(U_LIMIT);
        origin x = expression(e, s, a, depth + 1), y = expression(e, other, b, depth + 1);
        merge_state(e, s, other, n); free(other);
        return stamp(e, join(x, y), n, "conditional_value_join");
    }
    if (is(n, "method_invocation")) {
        TSNode receiver = sf_field(n, "object");
        if (!ts_node_is_null(receiver)) (void)expression(e, s, receiver, depth + 1);
        if (e->found || e->aborted) return unknown(U_CALL);
        bool selected = same(n, e->anchor);
        origin actual[LF_PARAMS]; size_t count = 0;
        (void)arguments(e, s, sf_field(n, "arguments"), depth + 1, selected, actual, &count);
        if (selected && !e->aborted) e->found = true;
        if (selected || e->found || e->aborted)
            return stamp(e, unknown(U_CALL), n, "unknown_call_return");
        /* Caller locals are independent from callee formals. Only the return
         * relation is instantiated; heap effects and exceptions are not proved. */
        return summarized_call(e, n, actual, count);
    }
    if (is(n, "object_creation_expression")) {
        /* Qualified creation evaluates the expression before '.new'. The
         * grammar does not label that qualifier with an object field. */
        TSTreeCursor c = ts_tree_cursor_new(n);
        if (ts_tree_cursor_goto_first_child(&c)) do {
            TSNode child = ts_tree_cursor_current_node(&c);
            if (spells(e, child, "new")) break;
            if (ts_node_is_named(child) && !comment(child))
                (void)expression(e, s, child, depth + 1);
            if (e->found || e->aborted) break;
        } while (ts_tree_cursor_goto_next_sibling(&c));
        ts_tree_cursor_delete(&c);
        (void)arguments(e, s, sf_field(n, "arguments"), depth + 1, false, NULL, NULL);
        return stamp(e, unknown(U_CALL), n, "unknown_created_value");
    }
    if (is(n, "field_access")) {
        (void)expression(e, s, sf_field(n, "object"), depth + 1);
        return stamp(e, unknown(U_HEAP), n, "unknown_field_read");
    }
    if (is(n, "array_access")) {
        (void)expression(e, s, sf_field(n, "array"), depth + 1);
        (void)expression(e, s, sf_field(n, "index"), depth + 1);
        return stamp(e, unknown(U_HEAP), n, "unknown_array_read");
    }
    if (is(n, "this") || is(n, "super")) return unknown(U_HEAP);
    if (is(n, "lambda_expression")) return stamp(e, unknown(U_EXPRESSION), n, "unevaluated_lambda");
    /* An unsupported expression may contain assignments or pattern bindings.
     * Never silently preserve old locals across it. Do not execute children in
     * guessed order. An anchor inside it is returned as an explicit gap. */
    poison(e, s, U_EXPRESSION, n);
    if (contains(n, e->anchor)) e->aborted = true;
    return stamp(e, unknown(U_EXPRESSION), n, "unsupported_expression");
}

static void statement(engine *e, environment *s, TSNode n, unsigned depth) {
    if (ts_node_is_null(n) || !s->alive || !tick(e, depth)) return;
    if (is(n, "block")) {
        size_t base = s->count;
        TSTreeCursor c = ts_tree_cursor_new(n);
        if (ts_tree_cursor_goto_first_child(&c)) do {
            TSNode child = ts_tree_cursor_current_node(&c);
            if (ts_node_is_named(child) && !comment(child)) statement(e, s, child, depth + 1);
            if (!s->alive || e->found || e->aborted) break;
        } while (ts_tree_cursor_goto_next_sibling(&c));
        ts_tree_cursor_delete(&c); s->count = base; return;
    }
    if (is(n, "local_variable_declaration")) {
        TSTreeCursor c = ts_tree_cursor_new(n);
        if (ts_tree_cursor_goto_first_child(&c)) do {
            TSNode decl = ts_tree_cursor_current_node(&c);
            if (!is(decl, "variable_declarator")) continue;
            if (s->count == LF_VARS) { e->limited = e->aborted = true; break; }
            size_t at = s->count++;
            s->vars[at] = (variable){sf_field(decl, "name"), unknown(U_UNINITIALIZED)};
            TSNode init = sf_field(decl, "value");
            if (!ts_node_is_null(init)) s->vars[at].value = expression(e, s, init, depth + 1);
            s->vars[at].value = stamp(e, s->vars[at].value, decl, "local_declaration");
            if (e->found || e->aborted) break;
        } while (ts_tree_cursor_goto_next_sibling(&c));
        ts_tree_cursor_delete(&c); return;
    }
    if (is(n, "expression_statement")) { (void)expression(e, s, first_named(n), depth + 1); return; }
    if (is(n, "return_statement") || is(n, "throw_statement")) {
        TSNode expr = first_named(n);
        origin v = !ts_node_is_null(expr) ? expression(e, s, expr, depth + 1) : unknown(U_RETURN);
        if (e->summary_mode && is(n, "return_statement")) {
            e->returned = join(e->returned, stamp(e, v, n, "method_return"));
            e->return_count++;
        }
        s->alive = false; return;
    }
    if (is(n, "if_statement")) {
        (void)expression(e, s, sf_field(n, "condition"), depth + 1);
        if (e->found || e->aborted) return;
        TSNode a = sf_field(n, "consequence"), b = sf_field(n, "alternative");
        /* For a target inside one arm, only that arm can lead to that exact
         * call. The predicate is retained as evidence, not proved feasible. */
        if (contains(a, e->anchor) || contains(b, e->anchor)) {
            for (size_t i = 0; i < s->count; i++)
                s->vars[i].value = stamp(e, s->vars[i].value, sf_field(n, "condition"), "selected_branch_condition");
            statement(e, s, contains(a, e->anchor) ? a : b, depth + 1); return;
        }
        environment *other = copy_state(e, s);
        if (!other) return;
        statement(e, s, a, depth + 1); statement(e, other, b, depth + 1);
        merge_state(e, s, other, n); free(other); return;
    }
    if (is(n, "empty_statement") || comment(n) || is(n, "class_declaration") ||
        is(n, "interface_declaration") || is(n, "record_declaration")) return;
    /* Loops, try/finally, switch, labels, assertions and synchronization are
     * explicit gaps in this slice. Invalidating all live locals is deliberate.
     * Their bodies are not linearized and a call inside is not guessed. */
    poison(e, s, U_CONTROL, n);
    if (contains(n, e->anchor)) e->aborted = true;
}


static void init_parameters(engine *e, environment *s, TSNode method) {
    TSNode params = sf_field(method, "parameters");
    TSTreeCursor cursor = ts_tree_cursor_new(params);
    if (ts_tree_cursor_goto_first_child(&cursor)) do {
        TSNode p = ts_tree_cursor_current_node(&cursor);
        if (!ts_node_is_named(p) || comment(p)) continue;
        if (!is(p, "formal_parameter") || e->nparams == LF_PARAMS) {
            e->prefix_gaps |= U_PARAMETER; e->aborted = true; break;
        }
        size_t index = e->nparams++;
        e->params[index] = p;
        s->vars[s->count++] = (variable){sf_field(p, "name"),
            stamp(e, (origin){.direct = UINT64_C(1) << index}, p, "formal_parameter")};
    } while (ts_tree_cursor_goto_next_sibling(&cursor));
    ts_tree_cursor_delete(&cursor);
}

static TSNode child_kind(TSNode n, const char *kind) {
    TSNode r = {0};
    if (ts_node_is_null(n)) return r;
    TSTreeCursor cursor = ts_tree_cursor_new(n);
    if (ts_tree_cursor_goto_first_child(&cursor)) do {
        TSNode c = ts_tree_cursor_current_node(&cursor);
        if (is(c, kind)) { r = c; break; }
    } while (ts_tree_cursor_goto_next_sibling(&cursor));
    ts_tree_cursor_delete(&cursor); return r;
}
static bool modifier(TSNode n, const char *kind) {
    return !ts_node_is_null(child_kind(child_kind(n, "modifiers"), kind));
}
/* Deliberately no name-only search across files or arbitrary receivers.
 * Inheritance, overloads, generic method selection and nested owners are gaps.
 * Private/static/final methods (or a final owner) cannot be overridden under
 * ordinary Java dispatch. Instrumentation and type correctness remain outside
 * this source-only model. */
static TSNode summary_target(engine *e, TSNode call, size_t argc) {
    TSNode none = {0}, body = ts_node_parent(e->method), owner = ts_node_parent(body);
    TSNode receiver = sf_field(call, "object"), name = sf_field(call, "name");
    if (!is(body, "class_body") || !is(owner, "class_declaration") ||
        !is(ts_node_parent(owner), "program") ||
        !ts_node_is_null(sf_field(owner, "superclass")) ||
        !ts_node_is_null(sf_field(owner, "interfaces")) ||
        !ts_node_is_null(sf_field(owner, "type_parameters")) ||
        (!ts_node_is_null(receiver) && !is(receiver, "this")) || argc > LF_PARAMS)
        return none;
    const char *object_methods[] = {"wait", "notify", "notifyAll", "clone", "equals",
                                    "finalize", "getClass", "hashCode", "toString"};
    for (size_t i = 0; i < sizeof(object_methods) / sizeof(object_methods[0]); i++)
        if (spells(e, name, object_methods[i])) return none;
    TSNode target = {0}; size_t matches = 0;
    TSTreeCursor c = ts_tree_cursor_new(body);
    if (ts_tree_cursor_goto_first_child(&c)) do {
        TSNode n = ts_tree_cursor_current_node(&c);
        if (!tick(e, 0)) break;
        if (is(n, "method_declaration") && same_name(e, sf_field(n, "name"), name)) {
            target = n; matches++;
        }
    } while (ts_tree_cursor_goto_next_sibling(&c));
    ts_tree_cursor_delete(&c);
    if (matches != 1 || e->aborted || ts_node_is_null(sf_field(target, "body")) ||
        spells(e, sf_field(target, "type"), "void") ||
        modifier(target, "abstract") || modifier(target, "native") || modifier(target, "synchronized") ||
        !ts_node_is_null(sf_field(target, "type_parameters")) ||
        (!modifier(target, "private") && !modifier(target, "static") &&
         !modifier(target, "final") && !modifier(owner, "final"))) return none;
    size_t count = 0; bool valid = true;
    c = ts_tree_cursor_new(sf_field(target, "parameters"));
    if (ts_tree_cursor_goto_first_child(&c)) do {
        TSNode n = ts_tree_cursor_current_node(&c);
        if (!ts_node_is_named(n) || comment(n)) continue;
        if (!is(n, "formal_parameter") || ++count > LF_PARAMS) { valid = false; break; }
    } while (ts_tree_cursor_goto_next_sibling(&c));
    ts_tree_cursor_delete(&c);
    return valid && count == argc ? target : none;
}
static return_summary *get_summary(engine *e, TSNode method, unsigned *reason) {
    summary_bank *bank = e->summaries;
    bank->requests++;
    for (size_t i = 0; i < bank->count; i++) if (same(bank->entries[i].method, method)) {
        if (bank->entries[i].busy) { *reason = U_CALL | U_RECURSION; return NULL; }
        bank->hits++; return &bank->entries[i];
    }
    if (bank->count == RS_METHODS || bank->depth == RS_DEPTH || bank->steps >= RS_STEPS) {
        bank->limited = true; *reason = U_CALL | U_SUMMARY_LIMIT; return NULL;
    }
    return_summary *r = &bank->entries[bank->count++];
    r->method = method; r->busy = true; bank->depth++;
    engine *callee = calloc(1, sizeof(*callee));
    environment *state = calloc(1, sizeof(*state));
    if (!callee || !state) {
        free(callee); free(state); bank->depth--; r->busy = false;
        e->error = "out_of_memory"; e->aborted = true; *reason = U_CALL; return NULL;
    }
    callee->doc = e->doc; callee->method = method; callee->json = e->json;
    callee->summaries = bank; callee->summary_mode = true; state->alive = true;
    init_parameters(callee, state, method);
    if (!callee->aborted) statement(callee, state, sf_field(method, "body"), 0);
    r->returned = callee->returned;
    /* A hidden return in unsupported control (especially finally) must not
     * disappear just because a later literal assignment overwrites all locals. */
    r->returned.unknown |= callee->prefix_gaps;
    if (!callee->return_count || state->alive) r->returned.unknown |= U_RETURN;
    if (callee->limited) { r->returned.unknown |= U_SUMMARY_LIMIT; bank->limited = true; }
    r->nevents = callee->nevents; r->nparams = callee->nparams;
    r->return_count = callee->return_count;
    memcpy(r->events, callee->events, r->nevents * sizeof(event));
    if (callee->error) { e->error = callee->error; e->aborted = true; }
    r->busy = false; bank->depth--; free(callee); free(state); return r;
}
static origin summarized_call(engine *e, TSNode call, const origin *actual, size_t count) {
    TSNode method = summary_target(e, call, count);
    if (ts_node_is_null(method))
        return stamp(e, unknown(U_CALL | U_TARGET | (e->aborted ? U_SUMMARY_LIMIT : 0)), call, "unresolved_call_return");
    unsigned reason = 0; return_summary *summary = get_summary(e, method, &reason);
    if (!summary) return stamp(e, unknown(reason), call, "unresolved_call_return");
    origin v = {.unknown = summary->returned.unknown, .literal = summary->returned.literal};
    for (size_t i = 0; i < count; i++) {
        uint64_t bit = UINT64_C(1) << i;
        if (summary->returned.direct & bit) v = join(v, actual[i]);
        if (summary->returned.derived & bit) v = join(v, transform(actual[i]));
    }
    for (size_t i = 0; i < summary->nevents; i++)
        if (summary->returned.evidence[i / 64U] & (UINT64_C(1) << (i % 64U)))
            v = stamp(e, v, summary->events[i].node, summary->events[i].kind);
    v = stamp(e, v, method, "return_summary_target");
    return stamp(e, v, call, "return_summary_application");
}

static value *object(engine *e) { return yyjson_mut_obj(e->json); }
static value *array(engine *e) { return yyjson_mut_arr(e->json); }
static void put(engine *e, value *o, const char *k, value *v) {
    value *key = yyjson_mut_strcpy(e->json, k);
    if (!key || !v || !o || !yyjson_mut_obj_put(o, key, v)) e->error = "out_of_memory";
}
static void text(engine *e, value *o, const char *k, const char *v) { put(e, o, k, yyjson_mut_strcpy(e->json, v)); }
static void num(engine *e, value *o, const char *k, size_t v) { put(e, o, k, yyjson_mut_uint(e->json, v)); }
static void flag(engine *e, value *o, const char *k, bool v) { put(e, o, k, yyjson_mut_bool(e->json, v)); }
static void add(engine *e, value *a, value *v) {
    if (!a || !v || !yyjson_mut_arr_append(a, v)) e->error = "out_of_memory";
}
static value *reason_list(engine *e, unsigned bits) {
    value *a = array(e);
    for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++)
        if (bits & reasons[i].bit) add(e, a, yyjson_mut_strcpy(e->json, reasons[i].name));
    return a;
}
static value *indices(engine *e, uint64_t mask) {
    value *a = array(e);
    for (size_t i = 0; i < LF_PARAMS; i++)
        if (mask & (UINT64_C(1) << i)) add(e, a, yyjson_mut_uint(e->json, i));
    return a;
}
static value *ref(engine *e, TSNode n) {
    if (ts_node_is_null(n)) return yyjson_mut_null(e->json);
    size_t start = ts_node_start_byte(n), end = ts_node_end_byte(n);
    if (end < start || end > e->doc->source_size) { e->error = "invalid_local_flow_span"; return NULL; }
    size_t size = end - start, prefix = size > 256 ? 256 : size;
    while (prefix && prefix < size && ((unsigned char)e->doc->source[start + prefix] & 0xc0U) == 0x80U) prefix--;
    value *v = object(e);
    text(e, v, "path", e->doc->path); text(e, v, "sha256", e->doc->source_hash);
    num(e, v, "start_byte", start); num(e, v, "end_byte", end);
    put(e, v, "text_prefix", yyjson_mut_strncpy(e->json, e->doc->source + start, prefix));
    flag(e, v, "text_truncated", prefix < size); return v;
}
static value *render_origin(engine *e, origin v) {
    value *r = object(e), *evidence = array(e);
    put(e, r, "formal_parameter_indices", indices(e, v.direct | v.derived));
    put(e, r, "value_identity_parameter_indices", indices(e, v.direct));
    put(e, r, "derived_parameter_indices", indices(e, v.derived));
    flag(e, r, "literal_possible", v.literal);
    put(e, r, "unknown_reasons", reason_list(e, v.unknown));
    text(e, r, "status", v.unknown ? "partial" : "modeled_in_supported_subset");
    text(e, r, "trust", "not_established");
    for (size_t i = 0; i < e->nevents; i++)
        if (v.evidence[i / 64U] & (UINT64_C(1) << (i % 64U))) add(e, evidence, yyjson_mut_uint(e->json, i));
    put(e, r, "evidence_ids", evidence); return r;
}
static value *render_events(engine *e) {
    value *events = array(e);
    for (size_t i = 0; i < e->nevents; i++) {
        value *v = object(e); num(e, v, "id", i); text(e, v, "kind", e->events[i].kind);
        put(e, v, "source", ref(e, e->events[i].node)); add(e, events, v);
    }
    return events;
}
static value *render_summaries(engine *e) {
    summary_bank *bank = e->summaries;
    value *r = object(e), *items = array(e);
    text(e, r, "schema", "cbm.java-return-summaries.v1");
    text(e, r, "scope", "same_top_level_class_non_overridable_methods");
    text(e, r, "cache_scope", "current_operation_context_only");
    text(e, r, "effects", "return_dependencies_only_heap_and_exceptions_not_proved");
    text(e, r, "security_semantics", "no_sanitizer_or_authorization_inference");
    num(e, r, "computed_methods", bank->count); num(e, r, "requests", bank->requests);
    num(e, r, "cache_hits", bank->hits); num(e, r, "total_steps", bank->steps);
    num(e, r, "method_limit", RS_METHODS); num(e, r, "depth_limit", RS_DEPTH);
    num(e, r, "total_step_limit", RS_STEPS); flag(e, r, "truncated", bank->limited);
    for (size_t i = 0; i < bank->count; i++) {
        return_summary *summary = &bank->entries[i];
        engine *view = calloc(1, sizeof(*view));
        if (!view) { e->error = "out_of_memory"; break; }
        view->doc = e->doc; view->json = e->json; view->nevents = summary->nevents;
        memcpy(view->events, summary->events, summary->nevents * sizeof(event));
        value *item = object(e); num(e, item, "id", i);
        put(e, item, "method", ref(e, summary->method));
        num(e, item, "formal_parameter_count", summary->nparams);
        num(e, item, "return_statements_evaluated", summary->return_count);
        text(e, item, "parameter_index_scope", "callee_formals_not_caller_formals");
        put(e, item, "return_relation", render_origin(view, summary->returned));
        put(e, item, "evidence", render_events(view));
        if (view->error) e->error = view->error;
        free(view); add(e, items, item);
    }
    put(e, r, "methods", items); return r;
}
const char *sf_attach_local_flow(const sf_document *doc, TSNode method, TSNode call,
                                 yyjson_mut_doc *json, value *result) {
    if (!doc || !json || !result || ts_node_is_null(method) || ts_node_is_null(call)) return "invalid_local_flow_input";
    engine *e = calloc(1, sizeof(*e)); environment *s = calloc(1, sizeof(*s));
    summary_bank *bank = calloc(1, sizeof(*bank));
    if (!e || !s || !bank) { free(e); free(s); free(bank); return "out_of_memory"; }
    e->doc = doc; e->anchor = call; e->method = method; e->json = json;
    e->summaries = bank; s->alive = true;
    init_parameters(e, s, method);
    for (size_t i = 1; i < doc->source_size; i++)
        if (doc->source[i - 1] == '\\' && doc->source[i] == 'u') {
            e->prefix_gaps |= U_UNICODE; e->aborted = true; break;
        }
    if (!e->aborted) statement(e, s, sf_field(method, "body"), 0);
    value *a = yyjson_mut_obj_get(result, "arguments"), *meta = object(e);
    size_t nargs = yyjson_mut_arr_size(a);
    unsigned gaps = e->prefix_gaps;
    for (size_t i = 0; i < nargs; i++) {
        origin v = e->found && i < e->nargs ? e->arguments[i] : unknown(U_ANCHOR | e->prefix_gaps);
        if (e->limited) v.unknown |= U_LIMIT;
        gaps |= v.unknown;
        put(e, yyjson_mut_arr_get(a, i), "local_value_flow", render_origin(e, v));
    }
    text(e, meta, "schema", "cbm.local-value-flow.v1");
    text(e, meta, "domain", "local_value_identity_and_explicit_expression_dependencies");
    text(e, meta, "path_feasibility", "not_evaluated");
    text(e, meta, "heap_contents", "not_modeled"); text(e, meta, "implicit_flows", "not_modeled");
    text(e, meta, "security_verdict", "not_evaluated");
    text(e, meta, "evidence_semantics", "dependency_evidence_set_not_execution_trace");
    text(e, meta, "status", !e->found ? "anchor_not_evaluated" : gaps ? "partial" : "modeled_in_supported_subset");
    flag(e, meta, "truncated", e->limited || bank->limited); num(e, meta, "steps", e->steps);
    put(e, meta, "gaps", reason_list(e, gaps)); put(e, meta, "evidence", render_events(e));
    put(e, meta, "return_summaries", render_summaries(e));
    put(e, result, "local_value_flow", meta);
    if (e->limited || bank->limited) flag(e, result, "truncated", true);
    const char *error = e->error; free(e); free(s); free(bank); return error;
}

/* Composition consumes source-derived local relations, never caller-supplied
 * origins. Multiple formal candidates survive joins and parameter reordering. */
static uint64_t mask(value *array_value) {
    uint64_t bits = 0;
    size_t i, n; value *v;
    yyjson_mut_arr_foreach(array_value, i, n, v)
        if (yyjson_mut_is_uint(v) && yyjson_mut_get_uint(v) < LF_PARAMS)
            bits |= UINT64_C(1) << yyjson_mut_get_uint(v);
    return bits;
}
static origin from_json(value *v) {
    origin r = {.direct = mask(yyjson_mut_obj_get(v, "value_identity_parameter_indices")),
                .derived = mask(yyjson_mut_obj_get(v, "derived_parameter_indices")),
                .literal = yyjson_mut_get_bool(yyjson_mut_obj_get(v, "literal_possible"))};
    if (!v) return unknown(U_ANCHOR);
    size_t i, n; value *reason;
    yyjson_mut_arr_foreach(yyjson_mut_obj_get(v, "unknown_reasons"), i, n, reason) {
        const char *name = yyjson_mut_get_str(reason); bool known = false;
        for (size_t j = 0; name && j < sizeof(reasons) / sizeof(reasons[0]); j++)
            if (!strcmp(name, reasons[j].name)) { r.unknown |= reasons[j].bit; known = true; }
        if (!known) r.unknown |= U_EXPRESSION;
    }
    return r;
}
const char *sf_compose_local_flows(yyjson_mut_doc *json, value *result, size_t linked, size_t requested) {
    engine e = {.json = json};
    value *flow = yyjson_mut_obj_get(result, "argument_flow"), *paths = array(&e);
    value *layers = yyjson_mut_obj_get(flow, "upstream_contexts");
    if (!flow || linked > yyjson_mut_arr_size(layers)) return "invalid_local_flow_layers";
    value *root_args = yyjson_mut_obj_get(result, "arguments");
    size_t n = yyjson_mut_arr_size(root_args);
    for (size_t i = 0; i < n; i++) {
        origin current = from_json(yyjson_mut_obj_get(yyjson_mut_arr_get(root_args, i), "local_value_flow"));
        value *path = object(&e), *steps = array(&e);
        num(&e, path, "argument_index", i); put(&e, path, "steps", steps);
        value *root_value = yyjson_mut_obj_get(yyjson_mut_arr_get(root_args, i), "local_value_flow");
        value *root_evidence = yyjson_mut_obj_get(root_value, "evidence_ids");
        put(&e, path, "root_evidence_ids", root_evidence ?
            yyjson_mut_val_mut_copy(json, root_evidence) : array(&e));
        size_t followed = 0;
        for (size_t layer = 0; layer < linked && (current.direct | current.derived); layer++) {
            value *local = yyjson_mut_arr_get(layers, layer);
            value *args = yyjson_mut_obj_get(local, "arguments"), *step = object(&e);
            put(&e, step, "input_argument_indices", indices(&e, current.direct | current.derived));
            origin next = {.unknown = current.unknown, .literal = current.literal};
            value *refs = array(&e); put(&e, step, "local_evidence", refs);
            for (size_t j = 0; j < LF_PARAMS; j++) {
                uint64_t bit = UINT64_C(1) << j;
                if (!((current.direct | current.derived) & bit)) continue;
                value *local_value = yyjson_mut_obj_get(yyjson_mut_arr_get(args, j), "local_value_flow");
                value *r = object(&e); num(&e, r, "argument_index", j);
                value *ids = yyjson_mut_obj_get(local_value, "evidence_ids");
                put(&e, r, "evidence_ids", ids ? yyjson_mut_val_mut_copy(json, ids) : array(&e));
                add(&e, refs, r);
                origin v = from_json(local_value);
                if (current.direct & bit) next = join(next, v);
                if (current.derived & bit) next = join(next, transform(v));
            }
            current = next; followed++;
            num(&e, step, "layer", layer + 1);
            put(&e, step, "result", render_origin(&e, current));
            text(&e, step, "evidence", "see_upstream_context_at_layer_and_argument_indices"); add(&e, steps, step);
        }
        put(&e, path, "result", render_origin(&e, current));
        num(&e, path, "candidate_hops_followed", followed);
        num(&e, path, "formal_parameter_context_layer", followed);
        text(&e, path, "relation_semantics", "may_depend_not_path_proof");
        text(&e, path, "stop_reason", !(current.direct | current.derived) ? "no_known_formal_dependencies_remain" :
             linked < requested ? "selected_call_link_unresolved" : "selected_path_exhausted");
        text(&e, path, "runtime_dispatch", "not_verified");
        text(&e, path, "path_feasibility", "not_evaluated"); add(&e, paths, path);
    }
    put(&e, flow, "local_value_paths", paths);
    text(&e, flow, "local_value_path_schema", "cbm.local-value-paths.v1");
    return e.error;
}
