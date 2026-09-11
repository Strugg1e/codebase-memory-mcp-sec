#include "java_models.h"
#include <string.h>

/* An annotation identifies a declaration, not its activation or effectiveness.
 * API names are matched in full after import resolution; no name heuristics. */
typedef struct {
    const char *name, *framework, *role, *rule, *method;
    const char *input, *phase, *operation, *detail;
} annotation_rule;
static const annotation_rule rules[] = {
    {"org.springframework.web.bind.annotation.GetMapping", "spring-mvc", "route_declaration", "spring.mapping.v1", "GET", NULL, NULL, NULL, "path"},
    {"org.springframework.web.bind.annotation.PostMapping", "spring-mvc", "route_declaration", "spring.mapping.v1", "POST", NULL, NULL, NULL, "path"},
    {"org.springframework.web.bind.annotation.PutMapping", "spring-mvc", "route_declaration", "spring.mapping.v1", "PUT", NULL, NULL, NULL, "path"},
    {"org.springframework.web.bind.annotation.PatchMapping", "spring-mvc", "route_declaration", "spring.mapping.v1", "PATCH", NULL, NULL, NULL, "path"},
    {"org.springframework.web.bind.annotation.DeleteMapping", "spring-mvc", "route_declaration", "spring.mapping.v1", "DELETE", NULL, NULL, NULL, "path"},
    {"org.springframework.web.bind.annotation.RequestMapping", "spring-mvc", "route_declaration", "spring.mapping.v1", "DECLARED_IN_ARGUMENTS", NULL, NULL, NULL, "path"},
    {"org.springframework.web.bind.annotation.RequestParam", "spring-mvc", "request_input_declaration", "spring.input.v1", NULL, "query_or_form", NULL, NULL, "binding"},
    {"org.springframework.web.bind.annotation.RequestBody", "spring-mvc", "request_input_declaration", "spring.input.v1", NULL, "body", NULL, NULL, "binding"},
    {"org.springframework.web.bind.annotation.PathVariable", "spring-mvc", "request_input_declaration", "spring.input.v1", NULL, "path", NULL, NULL, "binding"},
    {"org.springframework.web.bind.annotation.RequestHeader", "spring-mvc", "request_input_declaration", "spring.input.v1", NULL, "header", NULL, NULL, "binding"},
    {"org.springframework.web.bind.annotation.CookieValue", "spring-mvc", "request_input_declaration", "spring.input.v1", NULL, "cookie", NULL, NULL, "binding"},
    {"org.springframework.web.bind.annotation.RequestPart", "spring-mvc", "request_input_declaration", "spring.input.v1", NULL, "multipart", NULL, NULL, "binding"},
    {"org.springframework.web.bind.annotation.ModelAttribute", "spring-mvc", "request_input_declaration", "spring.input.v1", NULL, "model_binding", NULL, NULL, "binding"},
    {"org.springframework.security.access.prepost.PreAuthorize", "spring-security", "authorization_declaration", "spring.method-security.v1", NULL, NULL, "before_invocation", NULL, "access"},
    {"org.springframework.security.access.prepost.PostAuthorize", "spring-security", "authorization_declaration", "spring.method-security.v1", NULL, NULL, "after_invocation", NULL, "access"},
    {"org.springframework.security.access.prepost.PreFilter", "spring-security", "authorization_declaration", "spring.method-security.v1", NULL, NULL, "before_invocation", NULL, "access"},
    {"org.springframework.security.access.prepost.PostFilter", "spring-security", "authorization_declaration", "spring.method-security.v1", NULL, NULL, "after_invocation", NULL, "access"},
    {"org.springframework.security.access.annotation.Secured", "spring-security", "authorization_declaration", "spring.secured.v1", NULL, NULL, "before_invocation", NULL, "access"},
    {"org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity", "spring-security", "security_configuration_declaration", "spring.method-security-enable.v1", NULL, NULL, NULL, NULL, NULL},
    {"org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity", "spring-security", "security_configuration_declaration", "spring.method-security-enable.v1", NULL, NULL, NULL, NULL, NULL},
    {"org.springframework.security.core.annotation.AuthenticationPrincipal", "spring-security", "identity_context_declaration", "spring.identity-context.v1", NULL, "identity_context_candidate", NULL, NULL, "access"},
    {"org.springframework.security.core.annotation.CurrentSecurityContext", "spring-security", "identity_context_declaration", "spring.identity-context.v1", NULL, "identity_context_candidate", NULL, NULL, "access"},
    {"jakarta.ws.rs.Path", "jax-rs", "resource_path_declaration", "jaxrs.path.v1", NULL, NULL, NULL, NULL, "path"},
    {"jakarta.ws.rs.GET", "jax-rs", "route_declaration", "jaxrs.method.v1", "GET", NULL, NULL, NULL, NULL},
    {"jakarta.ws.rs.POST", "jax-rs", "route_declaration", "jaxrs.method.v1", "POST", NULL, NULL, NULL, NULL},
    {"jakarta.ws.rs.PUT", "jax-rs", "route_declaration", "jaxrs.method.v1", "PUT", NULL, NULL, NULL, NULL},
    {"jakarta.ws.rs.PATCH", "jax-rs", "route_declaration", "jaxrs.method.v1", "PATCH", NULL, NULL, NULL, NULL},
    {"jakarta.ws.rs.DELETE", "jax-rs", "route_declaration", "jaxrs.method.v1", "DELETE", NULL, NULL, NULL, NULL},
    {"jakarta.ws.rs.HEAD", "jax-rs", "route_declaration", "jaxrs.method.v1", "HEAD", NULL, NULL, NULL, NULL},
    {"jakarta.ws.rs.OPTIONS", "jax-rs", "route_declaration", "jaxrs.method.v1", "OPTIONS", NULL, NULL, NULL, NULL},
    {"jakarta.ws.rs.QueryParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "query", NULL, NULL, "binding"},
    {"jakarta.ws.rs.PathParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "path", NULL, NULL, "binding"},
    {"jakarta.ws.rs.HeaderParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "header", NULL, NULL, "binding"},
    {"jakarta.ws.rs.CookieParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "cookie", NULL, NULL, "binding"},
    {"jakarta.ws.rs.FormParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "form", NULL, NULL, "binding"},
    {"jakarta.ws.rs.MatrixParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "matrix", NULL, NULL, "binding"},
    {"jakarta.ws.rs.BeanParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "bean_binding", NULL, NULL, "binding"},
    {"jakarta.ws.rs.core.Context", "jax-rs", "context_parameter_declaration", "jaxrs.context.v1", NULL, "request_context_candidate", NULL, NULL, NULL},
    {"javax.ws.rs.Path", "jax-rs", "resource_path_declaration", "jaxrs.path.v1", NULL, NULL, NULL, NULL, "path"},
    {"javax.ws.rs.GET", "jax-rs", "route_declaration", "jaxrs.method.v1", "GET", NULL, NULL, NULL, NULL},
    {"javax.ws.rs.POST", "jax-rs", "route_declaration", "jaxrs.method.v1", "POST", NULL, NULL, NULL, NULL},
    {"javax.ws.rs.PUT", "jax-rs", "route_declaration", "jaxrs.method.v1", "PUT", NULL, NULL, NULL, NULL},
    {"javax.ws.rs.PATCH", "jax-rs", "route_declaration", "jaxrs.method.v1", "PATCH", NULL, NULL, NULL, NULL},
    {"javax.ws.rs.DELETE", "jax-rs", "route_declaration", "jaxrs.method.v1", "DELETE", NULL, NULL, NULL, NULL},
    {"javax.ws.rs.HEAD", "jax-rs", "route_declaration", "jaxrs.method.v1", "HEAD", NULL, NULL, NULL, NULL},
    {"javax.ws.rs.OPTIONS", "jax-rs", "route_declaration", "jaxrs.method.v1", "OPTIONS", NULL, NULL, NULL, NULL},
    {"javax.ws.rs.QueryParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "query", NULL, NULL, "binding"},
    {"javax.ws.rs.PathParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "path", NULL, NULL, "binding"},
    {"javax.ws.rs.HeaderParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "header", NULL, NULL, "binding"},
    {"javax.ws.rs.CookieParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "cookie", NULL, NULL, "binding"},
    {"javax.ws.rs.FormParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "form", NULL, NULL, "binding"},
    {"javax.ws.rs.MatrixParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "matrix", NULL, NULL, "binding"},
    {"javax.ws.rs.BeanParam", "jax-rs", "request_input_declaration", "jaxrs.input.v1", NULL, "bean_binding", NULL, NULL, "binding"},
    {"javax.ws.rs.core.Context", "jax-rs", "context_parameter_declaration", "jaxrs.context.v1", NULL, "request_context_candidate", NULL, NULL, NULL},
    {"jakarta.annotation.security.RolesAllowed", "jakarta-security", "authorization_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"jakarta.annotation.security.PermitAll", "jakarta-security", "access_policy_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"jakarta.annotation.security.DenyAll", "jakarta-security", "access_policy_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"jakarta.annotation.security.DeclareRoles", "jakarta-security", "access_policy_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"jakarta.annotation.security.RunAs", "jakarta-security", "access_policy_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"javax.annotation.security.RolesAllowed", "jakarta-security", "authorization_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"javax.annotation.security.PermitAll", "jakarta-security", "access_policy_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"javax.annotation.security.DenyAll", "jakarta-security", "access_policy_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"javax.annotation.security.DeclareRoles", "jakarta-security", "access_policy_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"javax.annotation.security.RunAs", "jakarta-security", "access_policy_declaration", "jakarta.policy.v1", NULL, NULL, "container_dependent", NULL, "access"},
    {"jakarta.validation.Valid", "bean-validation", "validation_declaration", "validation.cascade.v1", NULL, NULL, NULL, NULL, NULL},
    {"jakarta.validation.constraints.NotNull", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"jakarta.validation.constraints.NotBlank", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"jakarta.validation.constraints.NotEmpty", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"jakarta.validation.constraints.Size", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"jakarta.validation.constraints.Min", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"jakarta.validation.constraints.Max", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"jakarta.validation.constraints.Pattern", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"javax.validation.Valid", "bean-validation", "validation_declaration", "validation.cascade.v1", NULL, NULL, NULL, NULL, NULL},
    {"javax.validation.constraints.NotNull", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"javax.validation.constraints.NotBlank", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"javax.validation.constraints.NotEmpty", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"javax.validation.constraints.Size", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"javax.validation.constraints.Min", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"javax.validation.constraints.Max", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"javax.validation.constraints.Pattern", "bean-validation", "validation_constraint_declaration", "validation.constraint.v1", NULL, NULL, NULL, NULL, NULL},
    {"org.apache.ibatis.annotations.Select", "mybatis", "data_operation_declaration", "mybatis.annotation-sql.v1", NULL, NULL, NULL, "read", "sql"},
    {"org.apache.ibatis.annotations.SelectProvider", "mybatis", "sql_provider_declaration", "mybatis.provider.v1", NULL, NULL, NULL, "read", NULL},
    {"org.apache.ibatis.annotations.Insert", "mybatis", "data_operation_declaration", "mybatis.annotation-sql.v1", NULL, NULL, NULL, "insert", "sql"},
    {"org.apache.ibatis.annotations.InsertProvider", "mybatis", "sql_provider_declaration", "mybatis.provider.v1", NULL, NULL, NULL, "insert", NULL},
    {"org.apache.ibatis.annotations.Update", "mybatis", "data_operation_declaration", "mybatis.annotation-sql.v1", NULL, NULL, NULL, "update", "sql"},
    {"org.apache.ibatis.annotations.UpdateProvider", "mybatis", "sql_provider_declaration", "mybatis.provider.v1", NULL, NULL, NULL, "update", NULL},
    {"org.apache.ibatis.annotations.Delete", "mybatis", "data_operation_declaration", "mybatis.annotation-sql.v1", NULL, NULL, NULL, "delete", "sql"},
    {"org.apache.ibatis.annotations.DeleteProvider", "mybatis", "sql_provider_declaration", "mybatis.provider.v1", NULL, NULL, NULL, "delete", NULL},
    {"org.apache.ibatis.annotations.Param", "mybatis", "parameter_binding_declaration", "mybatis.param.v1", NULL, NULL, NULL, NULL, "binding"},
    {"org.apache.ibatis.annotations.Mapper", "mybatis", "mapper_declaration", "mybatis.mapper.v1", NULL, NULL, NULL, NULL, NULL},
    {"org.springframework.data.jpa.repository.Query", "spring-data-jpa", "data_query_declaration", "spring-data.query.v1", NULL, NULL, NULL, NULL, "query"},
    {"org.springframework.data.jpa.repository.Modifying", "spring-data-jpa", "data_modification_declaration", "spring-data.modifying.v1", NULL, NULL, NULL, NULL, NULL},
};

static TSNode attribute(const sf_document *doc, TSNode node, const char *key, bool positional) {
    TSNode args = sf_field(node, "arguments"), result = {0};
    if (ts_node_is_null(args)) return result;
    TSTreeCursor cursor = ts_tree_cursor_new(args);
    if (ts_tree_cursor_goto_first_child(&cursor)) do {
        TSNode child = ts_tree_cursor_current_node(&cursor);
        if (!ts_node_is_named(child) || sf_node_is(child, "line_comment") || sf_node_is(child, "block_comment")) continue;
        if (sf_node_is(child, "element_value_pair")) {
            char name[64];
            if (sf_node_text(doc, sf_field(child, "key"), name, sizeof(name)) && !strcmp(name, key)) {
                if (!ts_node_is_null(result)) { result = (TSNode){0}; break; }
                result = sf_field(child, "value");
            }
        } else if (positional) {
            if (!ts_node_is_null(result)) { result = (TSNode){0}; break; }
            result = child;
        }
    } while (ts_tree_cursor_goto_next_sibling(&cursor));
    ts_tree_cursor_delete(&cursor);
    return result;
}

bool sf_java_annotation_apply(const sf_document *doc, sf_fact *f, TSNode node, const char *canonical) {
    for (size_t i = 0; i < sizeof(rules)/sizeof(rules[0]); i++) {
        const annotation_rule *r = &rules[i];
        if (strcmp(r->name, canonical)) continue;
        f->framework = r->framework; f->role = r->role; f->rule_id = r->rule;
        f->http_method = r->method; f->input_kind = r->input;
        f->control_phase = r->phase; f->data_operation = r->operation;
        TSNode value = attribute(doc, node, "value", true);
        if (r->detail && !strcmp(r->detail, "path")) {
            TSNode path = attribute(doc, node, "path", false);
            if (ts_node_is_null(path)) path = value;
            if (!ts_node_is_null(path)) { f->has_path_expression = true; f->path_expression = sf_location(path); }
            if (f->has_enclosing && (!strcmp(f->enclosing_kind, "class_declaration") || !strcmp(f->enclosing_kind, "interface_declaration")))
                f->role = "route_prefix_declaration";
            if (r->method && !strcmp(r->method, "DECLARED_IN_ARGUMENTS"))
                sf_model_add_detail(f, "methods", attribute(doc, node, "method", false));
        } else if (r->detail) {
            const char *field = !strcmp(r->detail,"sql") ? "sql" : !strcmp(r->detail,"query") ? "query" :
                                !strcmp(r->detail,"access") ? "access_expression" : "binding_name";
            sf_model_add_detail(f, field, value);
            if (!strcmp(r->detail,"query")) sf_model_add_detail(f, "native_query", attribute(doc,node,"nativeQuery",false));
        }
        return true;
    }
    return false;
}
