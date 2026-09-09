#ifndef CBM_SECURITY_FACTS_H
#define CBM_SECURITY_FACTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SF_SCHEMA "cbm.security-facts.v1"
#define SF_VERSION "0.1.0"
#ifndef SF_BUILD_ID
#define SF_BUILD_ID "unversioned"
#endif
#define SF_MAX_SOURCE (1024U * 1024U)
#define SF_MAX_NODES 200000U
#define SF_MAX_FACTS 20000U
#define SF_MAX_ARGUMENTS 256U
#define SF_MAX_OUTPUT (4U * 1024U * 1024U)
#define SF_PREVIEW_BYTES 256U

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
} sf_fact;

typedef struct {
    const char *source, *path;
    size_t source_size;
    char source_hash[65], analysis_id[65];
    sf_fact *facts;
    size_t count;
    size_t nodes_visited;
    bool parse_has_error, traversal_complete;
} sf_document;

typedef struct {
    size_t offset, limit;
    const char *expected_analysis, *fact_id;
} sf_query;

/* No filesystem access. The caller owns the immutable source buffer. */
bool sf_utf8(const char *text, size_t size);
bool sf_path_valid(const char *path);
bool sf_digest_valid(const char *digest);
bool sf_document_init(sf_document *doc, const char *source, size_t size, const char *path);
void sf_fact_id(const sf_document *doc, const sf_fact *fact, char out[65]);
/* Output is allocated only on success. Errors never return half a JSON document. */
const char *sf_render(const sf_document *doc, const sf_query *query, char **out);
const char *sf_extract_java(sf_document *doc);
void sf_document_free(sf_document *doc);

#endif
