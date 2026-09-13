#ifndef CBM_SECURITY_JAVA_STRING_MODELS_H
#define CBM_SECURITY_JAVA_STRING_MODELS_H

#include "parser.h"

/* These are expression-type hints, not an independent Java type checker. */
enum {
    SF_JT_UNKNOWN = 1U, SF_JT_STRING = 2U,
    SF_JT_IMPLICIT_STRING = 4U, SF_JT_CHAR = 8U
};
typedef struct {
    bool simple_allowed, qualified_allowed, explicit_import, truncated;
    size_t nodes;
} sf_string_type_context;
typedef struct {
    const char *name, *id;
    size_t arity;
    bool identity, replace_overload;
} sf_string_return_model;

void sf_string_types_init(const sf_document *, TSNode, sf_string_type_context *);
unsigned sf_string_declared_type(const sf_document *, TSNode,
                                 const sf_string_type_context *);
bool sf_string_type(unsigned);
const sf_string_return_model *sf_string_model(const char *, size_t, const unsigned *);
#define SF_STRING_MODELS_REVISION 1U
#endif
