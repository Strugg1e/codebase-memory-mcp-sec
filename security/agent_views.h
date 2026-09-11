#ifndef CBM_SECURITY_AGENT_VIEWS_H
#define CBM_SECURITY_AGENT_VIEWS_H
#include "yyjson.h"
/* Project already computed evidence. Never changes the underlying analysis. */
const char *sf_operation_view(yyjson_mut_doc *doc, yyjson_mut_val *full,
                              yyjson_val *request, yyjson_mut_val **out);
#endif
