#ifndef CBM_SECURITY_FLOW_H
#define CBM_SECURITY_FLOW_H

#include "operation.h"

#define SF_FLOW_HOPS 4U
#define SF_FLOW_SOURCE (256U * 1024U)

typedef struct {
    const sf_document *identity;
    const char *call_id;
} sf_flow_anchor;

/* Shared source-based link verifier. Success establishes a declared target
 * candidate only, not runtime dispatch. Output owns its source references. */
const char *sf_check_declared_call_link(const sf_operation_request *down,
                                      const sf_operation_request *up,
                                      yyjson_mut_doc *output, yyjson_mut_val **link);

/* Optional, nearest-caller-first path. Each proposed hop is checked against
 * source. This attaches a projection to result, not a trusted call assertion. */
const char *sf_attach_argument_flow(const sf_operation_request *root,
                                    const sf_flow_anchor *upstream, size_t count,
                                    yyjson_mut_doc *output, yyjson_mut_val *result);
#endif
