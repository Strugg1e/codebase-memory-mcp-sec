#ifndef CBM_SEC_ENTRY_SECURITY_H
#define CBM_SEC_ENTRY_SECURITY_H
#include "parser.h"
#include "yyjson.h"
#define SF_SECURITY_SCHEMA "cbm.spring-security.v1"
#define SF_SECURITY_FILES 16U
#define SF_SECURITY_FILE_BYTES (256U * 1024U)
#define SF_SECURITY_TOTAL_BYTES (2U * 1024U * 1024U)
typedef struct { const char *path, *source; size_t size; } sf_security_source;
/* All input bytes are already pinned. No IO, class loading, or target evaluation. */
const char *sf_inspect_entry_security(const char *snapshot_id, yyjson_val *entry,
    const sf_security_source *sources, size_t count, const char *method,
    const char *request_path, const char *string_semantics, size_t *parse_attempts, yyjson_mut_doc *json,
    yyjson_mut_val **out);
#endif
