#ifndef CBM_SECURITY_OPERATION_H
#define CBM_SECURITY_OPERATION_H

#include "facts.h"
#include "yyjson.h"

/* Borrowed, startup-verified bytes. This module never opens a path. */
typedef struct {
    const char *path, *source, *sha256;
    size_t size;
} sf_operation_source;

typedef struct {
    const char *snapshot_id, *call_id;
    const sf_document *caller;
    const sf_fact *call;
    const sf_operation_source *mapper, *xml;
    size_t *parse_attempts;
} sf_operation_request;

/* A bounded source projection, not a call graph or an authorization verdict.
 * Optional mapper and XML inputs must be supplied together. */
const char *sf_inspect_operation(const sf_operation_request *request,
                                yyjson_mut_doc *output, yyjson_mut_val **result);
#endif
