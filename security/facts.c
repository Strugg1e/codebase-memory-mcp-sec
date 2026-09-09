#include "facts.h"
#include "foundation/sha256.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keep this boundary independent from the parser and the navigation database. */
bool sf_utf8(const char *s, size_t n) {
    if (!s) return false;
    for (size_t i = 0; i < n;) {
        unsigned char c = (unsigned char)s[i++];
        if (c == 0) return false;
        if (c < 0x80) continue;
        unsigned extra;
        uint32_t value, minimum;
        if (c >= 0xc2 && c <= 0xdf) { extra = 1; value = c & 31U; minimum = 0x80; }
        else if (c >= 0xe0 && c <= 0xef) { extra = 2; value = c & 15U; minimum = 0x800; }
        else if (c >= 0xf0 && c <= 0xf4) { extra = 3; value = c & 7U; minimum = 0x10000; }
        else return false;
        if (extra > n - i) return false;
        for (unsigned j = 0; j < extra; j++) {
            c = (unsigned char)s[i++];
            if ((c & 0xc0U) != 0x80U) return false;
            value = (value << 6) | (c & 63U);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
    }
    return true;
}

bool sf_path_valid(const char *path) {
    if (!path) return false;
    size_t n = strlen(path);
    if (!n || n > 1024 || path[0] == '/' || !sf_utf8(path, n)) return false;
    const char *part = path;
    for (size_t i = 0; i <= n; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c == '\\' || c == ':' || (c && (c < 32 || c == 127))) return false;
        if (c == '/' || c == 0) {
            size_t length = (size_t)(path + i - part);
            if (!length || (length == 1 && part[0] == '.') ||
                (length == 2 && part[0] == '.' && part[1] == '.')) return false;
            part = path + i + 1;
        }
    }
    return n >= 5 && strcmp(path + n - 5, ".java") == 0;
}

bool sf_digest_valid(const char *s) {
    if (!s || strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static void hash_field(cbm_sha256_ctx *hash, const char *value) {
    cbm_sha256_update(hash, value, strlen(value) + 1);
}

static void finish_hash(cbm_sha256_ctx *hash, char out[65]) {
    uint8_t bytes[32];
    static const char hex[] = "0123456789abcdef";
    cbm_sha256_final(hash, bytes);
    for (size_t i = 0; i < 32; i++) {
        out[2 * i] = hex[bytes[i] >> 4];
        out[2 * i + 1] = hex[bytes[i] & 15];
    }
    out[64] = 0;
}

bool sf_document_init(sf_document *d, const char *source, size_t size, const char *path) {
    if (!d || size > SF_MAX_SOURCE || !sf_path_valid(path) || !sf_utf8(source, size)) return false;
    memset(d, 0, sizeof(*d));
    d->source = source; d->source_size = size; d->path = path;
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
    cbm_sha256_update(&hash, source, size);
    finish_hash(&hash, d->source_hash);
    cbm_sha256_init(&hash);
    hash_field(&hash, SF_SCHEMA); hash_field(&hash, SF_VERSION); hash_field(&hash, SF_BUILD_ID);
    hash_field(&hash, "java"); hash_field(&hash, path); hash_field(&hash, d->source_hash);
    finish_hash(&hash, d->analysis_id);
    return true;
}

void sf_fact_id(const sf_document *d, const sf_fact *f, char out[65]) {
    cbm_sha256_ctx hash;
    char range[64];
    snprintf(range, sizeof(range), "%u:%u", f->span.start, f->span.end);
    cbm_sha256_init(&hash);
    hash_field(&hash, d->analysis_id); hash_field(&hash, f->kind);
    hash_field(&hash, f->syntax); hash_field(&hash, range);
    finish_hash(&hash, out);
}

typedef struct { char *text; size_t used; bool failed; } writer;

static void append(writer *w, const char *s, size_t n) {
    if (w->failed) return;
    if (n > SF_MAX_OUTPUT - 1 - w->used) { w->failed = true; return; }
    memcpy(w->text + w->used, s, n); w->used += n; w->text[w->used] = 0;
}

static void emit(writer *w, const char *s) { append(w, s, strlen(s)); }
static void number(writer *w, size_t n) {
    char buf[32]; snprintf(buf, sizeof(buf), "%zu", n); emit(w, buf);
}
static void boolean(writer *w, bool b) { emit(w, b ? "true" : "false"); }
static void string(writer *w, const char *s, size_t n) {
    static const char hex[] = "0123456789abcdef";
    emit(w, "\"");
    for (size_t i = 0; i < n && !w->failed; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { emit(w, "\\"); append(w, s + i, 1); }
        else if (c < 32) {
            char escaped[] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
            append(w, escaped, sizeof(escaped));
        } else append(w, s + i, 1);
    }
    emit(w, "\"");
}
static void text(writer *w, const char *s) { string(w, s, strlen(s)); }

static bool span_valid(const sf_document *d, sf_span p) {
    if (p.start > p.end || p.end > d->source_size) return false;
    if (p.start < d->source_size && ((unsigned char)d->source[p.start] & 0xc0U) == 0x80U) return false;
    if (p.end < d->source_size && ((unsigned char)d->source[p.end] & 0xc0U) == 0x80U) return false;
    return true;
}

static void span(writer *w, const sf_document *d, sf_span p) {
    size_t n = p.end - p.start;
    size_t preview = n > SF_PREVIEW_BYTES ? SF_PREVIEW_BYTES : n;
    while (preview && preview < n && ((unsigned char)d->source[p.start + preview] & 0xc0U) == 0x80U) preview--;
    emit(w, "{\"start_byte\":"); number(w, p.start);
    emit(w, ",\"end_byte\":"); number(w, p.end);
    emit(w, ",\"start_line\":"); number(w, p.start_line);
    emit(w, ",\"end_line\":"); number(w, p.end_line);
    emit(w, ",\"text_prefix\":"); string(w, d->source + p.start, preview);
    emit(w, ",\"text_bytes_returned\":"); number(w, preview);
    emit(w, ",\"text_truncated\":"); boolean(w, preview < n); emit(w, "}");
}

static bool fact_valid(const sf_document *d, const sf_fact *f) {
    if (!f->kind || !f->syntax || !span_valid(d, f->span) ||
        f->argument_count > SF_MAX_ARGUMENTS || f->argument_count > f->argument_total ||
        (f->argument_count && !f->arguments) ||
        (f->has_name && !span_valid(d, f->name)) ||
        (f->has_receiver && !span_valid(d, f->receiver)) ||
        (f->has_enclosing && (!f->enclosing_kind || !span_valid(d, f->enclosing)))) return false;
    for (uint32_t i = 0; i < f->argument_count; i++)
        if (!span_valid(d, f->arguments[i]) || f->arguments[i].start < f->span.start ||
            f->arguments[i].end > f->span.end) return false;
    return true;
}

static void fact(writer *w, const sf_document *d, const sf_fact *f) {
    char id[65]; sf_fact_id(d, f, id);
    emit(w, "{\"id\":"); text(w, id);
    emit(w, ",\"kind\":"); text(w, f->kind);
    emit(w, ",\"syntax_kind\":"); text(w, f->syntax);
    emit(w, ",\"basis\":\"syntax_observation\",\"location\":"); span(w, d, f->span);
    emit(w, ",\"syntax_has_error\":"); boolean(w, f->syntax_has_error);
    if (f->has_name) { emit(w, ",\"name\":"); span(w, d, f->name); }
    if (f->has_receiver) { emit(w, ",\"receiver\":"); span(w, d, f->receiver); }
    if (f->has_enclosing) {
        sf_fact parent = {.kind = f->enclosing_kind, .syntax = f->enclosing_kind, .span = f->enclosing};
        sf_fact_id(d, &parent, id);
        emit(w, ",\"enclosing_id\":"); text(w, id);
    }
    emit(w, ",\"enclosing_search_limited\":"); boolean(w, f->enclosing_search_limited);
    if (strcmp(f->kind, "call_site") == 0) {
        emit(w, ",\"target_resolution\":\"not_attempted\",\"arguments_available\":"); boolean(w, f->has_arguments);
        emit(w, ",\"argument_total\":");
        if (f->has_arguments) number(w, f->argument_total); else emit(w, "null");
        emit(w, ",\"arguments_truncated\":"); boolean(w, f->argument_count < f->argument_total);
        emit(w, ",\"arguments\":[");
        for (uint32_t i = 0; i < f->argument_count; i++) {
            if (i) emit(w, ",");
            emit(w, "{\"index\":"); number(w, i);
            emit(w, ",\"location\":"); span(w, d, f->arguments[i]); emit(w, "}");
        }
        emit(w, "]");
    }
    if (strcmp(f->kind, "annotation") == 0)
        emit(w, ",\"security_effect\":\"not_evaluated\"");
    emit(w, "}");
}

const char *sf_render(const sf_document *d, const sf_query *q, char **out) {
    if (!out) return "invalid_arguments";
    *out = NULL;
    if (!d || !q || !q->limit || q->limit > 200 ||
        d->count > SF_MAX_FACTS || (d->count && !d->facts)) return "invalid_arguments";
    if ((q->offset || q->fact_id) && !q->expected_analysis) return "analysis_id_required";
    if (q->expected_analysis && (!sf_digest_valid(q->expected_analysis) ||
        strcmp(q->expected_analysis, d->analysis_id) != 0)) return "analysis_mismatch";
    if (q->offset > d->count || (q->fact_id && (!sf_digest_valid(q->fact_id) || q->offset))) return "invalid_arguments";
    size_t begin = q->offset, end = d->count;
    if (end - begin > q->limit) end = begin + q->limit;
    if (q->fact_id) {
        bool found = false;
        for (size_t i = 0; i < d->count; i++) {
            char id[65]; sf_fact_id(d, &d->facts[i], id);
            if (strcmp(id, q->fact_id) == 0) { begin = i; end = i + 1; found = true; break; }
        }
        if (!found) return "fact_not_found_in_extracted_scope";
    }
    for (size_t i = begin; i < end; i++) if (!fact_valid(d, &d->facts[i])) return "invalid_evidence_span";
    writer w = {.text = malloc(SF_MAX_OUTPUT)};
    if (!w.text) return "out_of_memory";
    w.text[0] = 0;
    emit(&w, "{\"schema\":\"" SF_SCHEMA "\",\"producer\":{\"name\":\"cbm-security-facts\",\"version\":\"" SF_VERSION "\",\"build_id\":");
    text(&w, SF_BUILD_ID); emit(&w, "},\"analysis_id\":"); text(&w, d->analysis_id);
    emit(&w, ",\"source\":{\"path\":"); text(&w, d->path);
    emit(&w, ",\"language\":\"java\",\"sha256\":"); text(&w, d->source_hash);
    emit(&w, ",\"bytes\":"); number(&w, d->source_size);
    emit(&w, "},\"scope\":\"single_file\",\"coverage\":{\"status\":\"syntax_only\",\"parse_has_error\":");
    boolean(&w, d->parse_has_error); emit(&w, ",\"traversal_complete\":"); boolean(&w, d->traversal_complete);
    emit(&w, ",\"nodes_visited\":"); number(&w, d->nodes_visited);
    emit(&w, ",\"node_limit\":"); number(&w, SF_MAX_NODES);
    emit(&w, ",\"fact_limit\":"); number(&w, SF_MAX_FACTS);
    emit(&w, ",\"unknowns\":[\"cross_file_resolution_not_attempted\",\"value_flow_not_attempted\",\"authorization_effect_not_evaluated\",\"absence_is_not_a_security_verdict\",\"java_unicode_escape_preprocessing_not_modeled\"]},\"page\":{\"offset\":");
    number(&w, begin); emit(&w, ",\"returned\":"); number(&w, end - begin);
    emit(&w, ",\"extracted_total\":"); number(&w, d->count);
    emit(&w, ",\"total_is_lower_bound\":"); boolean(&w, !d->traversal_complete || d->parse_has_error);
    bool more = !q->fact_id && end < d->count;
    emit(&w, ",\"has_more\":"); boolean(&w, more);
    emit(&w, ",\"next_offset\":"); if (more) number(&w, end); else emit(&w, "null");
    emit(&w, "},\"facts\":[");
    for (size_t i = begin; i < end; i++) { if (i > begin) emit(&w, ","); fact(&w, d, &d->facts[i]); }
    emit(&w, "]}\n");
    if (w.failed) { free(w.text); return "output_budget_exceeded_reduce_limit"; }
    *out = w.text;
    return NULL;
}

void sf_document_free(sf_document *d) {
    if (!d) return;
    for (size_t i = 0; i < d->count; i++) free(d->facts[i].arguments);
    free(d->facts); d->facts = NULL; d->count = 0;
}
