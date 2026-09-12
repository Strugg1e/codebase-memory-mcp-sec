#ifndef CBM_SECURITY_MYBATIS_TEMPLATE_H
#define CBM_SECURITY_MYBATIS_TEMPLATE_H

#include "operation.h"

#define SF_MB_SEGMENTS 64U
#define SF_MB_MARKERS 128U
/* All spans refer to the original fixed source, never synthesized SQL. */
typedef struct {
    sf_span span;
    yyjson_mut_val *conditions;
    yyjson_mut_val *include_sites;
    bool binding_scope_unknown;
} sf_mb_segment;
typedef struct { const char *name; size_t argument_index; } sf_mb_binding;

/* Scan the template BEFORE SQL lexing. No OGNL, SQL or target execution.
 * Conditions and include sites are copied; caller retains their ownership. */
const char *sf_mybatis_template(yyjson_mut_doc *doc, const sf_operation_source *source,
    const sf_mb_segment *segments, size_t count, const sf_mb_binding *bindings,
    size_t binding_count, bool incomplete, yyjson_mut_val **result);
#endif
