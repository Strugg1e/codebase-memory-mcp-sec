#ifndef CBM_SECURITY_ENTRY_POINTS_H
#define CBM_SECURITY_ENTRY_POINTS_H
#include "parser.h"
#include "yyjson.h"
#define SF_ENTRY_SCHEMA "cbm.spring-entry-points.v1"
#define SF_ENTRY_MAX_RECORDS 256U
#define SF_ENTRY_MAX_BYTES (4U * 1024U * 1024U)
/* Reuses facts and the same parse tree. Output owns all copied strings; no target IO. */
const char *sf_spring_entry_points(const sf_document *source, TSNode root, yyjson_doc **out);
#endif
