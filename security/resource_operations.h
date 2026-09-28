#ifndef CBM_SECURITY_RESOURCE_OPERATIONS_H
#define CBM_SECURITY_RESOURCE_OPERATIONS_H
#include "auto_trace.h"
#define SF_RESOURCE_SCHEMA "cbm.resource-operations.v2"
#define SF_RESOURCE_FILES 32U
#define SF_RESOURCE_PAGE_CHECKS 32U
#define SF_RESOURCE_PAGE_TARGETS 20U

typedef struct {
    const char *snapshot_id, *application_id, *cursor, *mapping_format, *operation_kind;
    const sf_operation_source *scope;
    size_t scope_count, limit, max_checks;
    size_t *parse_attempts;
} sf_resource_request;

/* Enumerate ordinary MyBatis operations, including bound and constant queries.
 * The application label is a host boundary assertion, not an inferred fact.
 * Pagination covers bounded mapping checks, including rejected candidates.
 * Listing never evaluates local-flow or return summaries. */
const char *sf_query_resource_operations(const sf_resource_request *request,
                                        yyjson_mut_doc *output, yyjson_mut_val **result);
#endif
