#include "facts.h"
#include "foundation/sha256.h"

#include <string.h>

static bool filtered(const sf_query *q) {
    return q->kind || q->framework || q->role || q->enclosing_id;
}
static bool selector(const char *s) {
    if (!s) return true;
    size_t n = strlen(s);
    if (!n || n > 96) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
    }
    return true;
}
const char *sf_query_validate(const sf_query *q) {
    if (!q || !q->limit || q->limit > SF_MAX_PAGE || q->offset > SF_MAX_FACTS ||
        !selector(q->kind) || !selector(q->framework) || !selector(q->role) ||
        (q->expected_analysis && !sf_digest_valid(q->expected_analysis)) ||
        (q->expected_query && !sf_digest_valid(q->expected_query)) ||
        (q->enclosing_id && !sf_digest_valid(q->enclosing_id)) ||
        (q->fact_id && (!sf_digest_valid(q->fact_id) || q->offset || filtered(q) || q->expected_query)))
        return "invalid_arguments";
    if ((q->fact_id || (q->offset && !q->expected_query)) && !q->expected_analysis)
        return "analysis_id_required";
    if (q->offset && filtered(q) && !q->expected_query) return "query_cursor_required";
    return NULL;
}
static void hash_field(cbm_sha256_ctx *hash, const char *value) {
    const char *s = value ? value : "";
    cbm_sha256_update(hash, s, strlen(s) + 1);
}
static void query_identity(const sf_document *d, const sf_query *q, char out[65]) {
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
    hash_field(&hash, "cbm.security-facts.query.v1");
    hash_field(&hash, d->analysis_id);
    hash_field(&hash, q->kind); hash_field(&hash, q->framework);
    hash_field(&hash, q->role); hash_field(&hash, q->enclosing_id);
    hash_field(&hash, q->fact_id);
    /* Page size is not semantic: a continuation can use a smaller output budget. */
    uint8_t bytes[32];
    static const char hex[] = "0123456789abcdef";
    cbm_sha256_final(&hash, bytes);
    for (size_t i = 0; i < sizeof(bytes); i++) {
        out[2 * i] = hex[bytes[i] >> 4]; out[2 * i + 1] = hex[bytes[i] & 15];
    }
    out[64] = 0;
}
const char *sf_query_check(const sf_document *d, const sf_query *q) {
    const char *error = sf_query_validate(q);
    if (error) return error;
    if (!d || !d->language || !sf_digest_valid(d->analysis_id)) return "invalid_arguments";
    if (q->expected_analysis && strcmp(q->expected_analysis, d->analysis_id) != 0) return "analysis_mismatch";
    if (q->expected_query) {
        char id[65]; query_identity(d, q, id);
        if (strcmp(q->expected_query, id) != 0) return "query_mismatch";
    }
    return NULL;
}
static bool matches(const sf_document *d, const sf_query *q, const sf_fact *f) {
    if (q->kind && strcmp(q->kind, f->kind) != 0) return false;
    if (q->framework && (!f->framework || strcmp(q->framework, f->framework) != 0)) return false;
    if (q->role && (!f->framework || !f->role || strcmp(q->role, f->role) != 0)) return false;
    if (q->enclosing_id) {
        if (!f->has_enclosing || !f->enclosing_kind) return false;
        sf_fact parent = {.kind = f->enclosing_kind, .syntax = f->enclosing_kind, .span = f->enclosing};
        char id[65]; sf_fact_id(d, &parent, id);
        if (strcmp(id, q->enclosing_id) != 0) return false;
    }
    return true;
}
const char *sf_query_select(const sf_document *d, const sf_query *q, sf_selection *out) {
    if (!out) return "invalid_arguments";
    memset(out, 0, sizeof(*out));
    const char *error = sf_query_check(d, q);
    if (error) return error;
    if (d->count > SF_MAX_FACTS || (d->count && !d->facts)) return "invalid_arguments";
    query_identity(d, q, out->query_id);
    out->offset = q->offset;
    bool enclosing_found = q->enclosing_id == NULL, fact_found = q->fact_id == NULL;
    for (size_t i = 0; i < d->count; i++) {
        const sf_fact *f = &d->facts[i];
        if (!f->kind || !f->syntax) return "invalid_evidence_span";
        if (q->enclosing_id || q->fact_id) {
            char id[65]; sf_fact_id(d, f, id);
            if (q->enclosing_id && strcmp(id, q->enclosing_id) == 0) enclosing_found = true;
            if (q->fact_id) {
                if (strcmp(id, q->fact_id) == 0) {
                    out->indices[0] = i; out->count = out->total = 1; out->offset = i; fact_found = true;
                }
                continue;
            }
        }
        if (!matches(d, q, f)) continue;
        if (out->total >= q->offset && out->count < q->limit) out->indices[out->count++] = i;
        out->total++;
    }
    if (!enclosing_found) return "enclosing_not_found_in_extracted_scope";
    if (!fact_found) return "fact_not_found_in_extracted_scope";
    if (!q->fact_id && q->offset > out->total) return "offset_out_of_matched_scope";
    out->has_more = !q->fact_id && out->offset + out->count < out->total;
    return NULL;
}
