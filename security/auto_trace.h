#ifndef CBM_SECURITY_AUTO_TRACE_H
#define CBM_SECURITY_AUTO_TRACE_H
#include "operation.h"

#define SF_TRACE_SCHEMA "cbm.source-sink-paths.v1"
#define SF_TRACE_RULE "spring-mybatis-text-substitution"
#define SF_TRACE_FILES 16U
#define SF_TRACE_TOTAL (2U * 1024U * 1024U)
#define SF_TRACE_CHECKS 128U
#define SF_TRACE_PATHS 32U
#define SF_TRACE_STATES 128U

/* A built-in rule, not executable configuration loaded from the target. */
#define SF_TRACE_CATALOG_JSON "[{\"id\":\"" SF_TRACE_RULE "\",\"revision\":\"1\",\"language\":\"java\",\"source\":\"explicit_scalar_Spring_MVC_input_on_mapped_method\",\"sink\":\"explicit_MyBatis_text_substitution_argument\",\"propagation\":\"existing_local_flow_and_declared_call_verifier\",\"sanitizers\":\"not_modeled\",\"verdict\":\"candidate_only\"}]"

typedef struct {
    sf_operation_request operation;
    const sf_operation_source *scope;
    size_t scope_count, max_hops, max_paths, max_checks;
} sf_trace_request;

/* Finds callers within explicit, pinned source files. Never opens a path,
 * executes target code, or treats incomplete exploration as absence of risk. */
const char *sf_trace_source_to_sink(const sf_trace_request *request,
                                  yyjson_mut_doc *output, yyjson_mut_val **result);
#endif
