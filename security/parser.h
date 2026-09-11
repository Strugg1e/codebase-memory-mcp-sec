#ifndef CBM_SECURITY_PARSER_H
#define CBM_SECURITY_PARSER_H

#include "facts.h"
#include <tree_sitter/api.h>

bool sf_node_is(TSNode node, const char *type);
TSNode sf_field(TSNode node, const char *name);
sf_span sf_location(TSNode node);
bool sf_node_text(const sf_document *doc, TSNode node, char *out, size_t capacity);
bool sf_walk(TSNode root, bool (*visit)(TSNode, void *), void *context, size_t *visited);
TSNode sf_call_target(TSNode node);
TSNode sf_single(TSNode node);

typedef struct sf_models sf_models;
sf_models *sf_models_new(sf_document *doc, TSNode root);
void sf_model_add_detail(sf_fact *fact, const char *name, TSNode expression);
void sf_models_apply(sf_models *models, sf_fact *fact, TSNode node);
void sf_models_free(sf_models *models);

#endif
