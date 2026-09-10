#ifndef CBM_SECURITY_FACTS_H
#define CBM_SECURITY_FACTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SF_SCHEMA "cbm.security-facts.v1"
#define SF_VERSION "0.5.0"
#ifndef SF_BUILD_ID
#define SF_BUILD_ID "unversioned"
#endif
#define SF_MAX_SOURCE (1024U * 1024U)
#define SF_MAX_NODES 200000U
#define SF_MAX_FACTS 20000U
#define SF_MAX_ARGUMENTS 256U
#define SF_MAX_OUTPUT (4U * 1024U * 1024U)
#define SF_PREVIEW_BYTES 256U
#define SF_MAX_BINDINGS 256U
#define SF_MAX_PAGE 200U

typedef struct {
    uint32_t start, end;
    uint32_t start_line, end_line;
} sf_span;

typedef struct {
    const char *kind;
    const char *syntax;
    sf_span span, name, receiver, enclosing;
    const char *enclosing_kind;
    bool has_name, has_receiver, has_enclosing, enclosing_search_limited;
    bool syntax_has_error;
    sf_span *arguments;
    uint32_t argument_count, argument_total;
    bool has_arguments;
    /* Argument expressions are syntax slots, not expanded runtime arguments. */
    bool has_argument_expansion;
    const char *framework, *role, *rule_id, *http_method;
    sf_span import_evidence, binding_evidence, path_expression, handler;
    bool has_import_evidence, has_binding_evidence, has_path_expression, has_handler;
} sf_fact;

typedef struct {
    const char *source, *path, *language;
    size_t source_size;
    char source_hash[65], analysis_id[65];
    sf_fact *facts;
    size_t count, nodes_visited;
    bool parse_has_error, traversal_complete;
    bool framework_analysis_complete, framework_bindings_limited;
} sf_document;

typedef struct {
    size_t offset, limit;
    const char *expected_analysis, *fact_id;
    const char *kind, *framework, *role, *enclosing_id;
    /* Decoded from the cursor. The query identity includes the analysis identity. */
    const char *expected_query;
} sf_query;

typedef struct {
    size_t indices[SF_MAX_PAGE];
    size_t count, total, offset;
    char query_id[65];
    bool has_more;
} sf_selection;

/* No filesystem access. The caller owns the immutable source buffer. */
bool sf_utf8(const char *text, size_t size);
bool sf_path_valid(const char *path);
const char *sf_language_for_path(const char *path);
bool sf_digest_valid(const char *digest);
bool sf_document_init(sf_document *doc, const char *source, size_t size, const char *path);
void sf_fact_id(const sf_document *doc, const sf_fact *fact, char out[65]);
/* Validate CLI/API input before reading or parsing source. */
const char *sf_query_validate(const sf_query *query);
/* Also check source-bound identities before spending parser work. */
const char *sf_query_check(const sf_document *doc, const sf_query *query);
const char *sf_query_select(const sf_document *doc, const sf_query *query, sf_selection *out);
/* Output is allocated only on success. Errors never return half a JSON document. */
const char *sf_render(const sf_document *doc, const sf_query *query, char **out);
const char *sf_extract(sf_document *doc);
const char *sf_extract_java(sf_document *doc);
void sf_document_free(sf_document *doc);

#endif
