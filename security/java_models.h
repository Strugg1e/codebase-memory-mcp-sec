#ifndef CBM_SEC_JAVA_MODELS_H
#define CBM_SEC_JAVA_MODELS_H
#include "parser.h"
/* The caller resolves explicit imports; this function only matches exact APIs. */
bool sf_java_annotation_apply(const sf_document *doc, sf_fact *fact,
                              TSNode node, const char *canonical);
#endif
