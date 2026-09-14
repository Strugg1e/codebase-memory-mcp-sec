#ifndef CBM_SECURITY_LOCAL_FLOW_H
#define CBM_SECURITY_LOCAL_FLOW_H

#include "parser.h"
#include "yyjson.h"

/* Bounded Java local-value analysis over an already parsed tree. No path reads,
 * target execution, heap model, arbitrary external-library summaries, or security verdicts. Typed String
 * instance returns use a checked-in normal-return dependency model. Same-class
 * non-overridable return summaries are computed and cached only for this call. The
 * caller owns all tree/source memory; JSON owns copies of emitted references. */
const char *sf_attach_local_flow(const sf_document *source, TSNode method, TSNode call,
                                 yyjson_mut_doc *json, yyjson_mut_val *result);
/* Compose ONLY the links the existing explicit-call verifier has accepted.
 * This does not discover callers or promote declared dispatch to runtime fact. */
const char *sf_compose_local_flows(yyjson_mut_doc *json, yyjson_mut_val *result,
                                   size_t linked, size_t requested);
#endif
