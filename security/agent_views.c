#include "agent_views.h"
#include <stdbool.h>
#include <string.h>

typedef yyjson_mut_val V;
typedef struct { yyjson_mut_doc *doc; bool summary; bool failed; } view;
static V *obj(view *p) { V *v=yyjson_mut_obj(p->doc); if (!v) p->failed=true; return v; }
static V *arr(view *p) { V *v=yyjson_mut_arr(p->doc); if (!v) p->failed=true; return v; }
static V *get(V *v,const char *k) { return yyjson_mut_obj_get(v,k); }
static void set(view *p,V *v,const char *k,V *x) {
    V *key=yyjson_mut_strcpy(p->doc,k);
    if (!v || !x || !key || !yyjson_mut_obj_put(v,key,x)) p->failed=true;
}
static void text(view *p,V *v,const char *k,const char *s) { set(p,v,k,yyjson_mut_strcpy(p->doc,s)); }
static void num(view *p,V *v,const char *k,size_t n) { set(p,v,k,yyjson_mut_uint(p->doc,n)); }
static void add(view *p,V *a,V *v) { if (!a || !v || !yyjson_mut_arr_append(a,v)) p->failed=true; }
static bool eq(const char *a,const char *b) { return a && !strcmp(a,b); }
static V *copy(view *p,V *v) {
    V *r=v ? yyjson_mut_val_mut_copy(p->doc,v) : yyjson_mut_null(p->doc);
    if (!r) p->failed=true;
    return r;
}
static void take(view *p,V *out,V *in,const char *key) {
    V *v=get(in,key); if (v) set(p,out,key,copy(p,v));
}
/* Only omit indexed dependency evidence in SUMMARY. Source locations, gaps,
 * truncation, control candidates and every relation remain visible. */
static V *relation_copy(view *p,V *v,unsigned depth) {
    if (depth>40) { p->failed=true; return NULL; }
    if (yyjson_mut_is_obj(v)) {
        V *r=obj(p), *k, *child; size_t i,n;
        yyjson_mut_obj_foreach(v,i,n,k,child) {
            const char *name=yyjson_mut_get_str(k);
            if (p->summary && (eq(name,"evidence_ids") || eq(name,"root_evidence_ids") ||
                eq(name,"local_evidence"))) continue;
            if (p->summary && eq(name,"evidence") && yyjson_mut_is_arr(child)) {
                num(p,r,"omitted_evidence_items",yyjson_mut_arr_size(child)); continue;
            }
            set(p,r,name,relation_copy(p,child,depth+1));
        }
        return r;
    }
    if (yyjson_mut_is_arr(v)) {
        V *r=arr(p), *child; size_t i,n;
        yyjson_mut_arr_foreach(v,i,n,child) add(p,r,relation_copy(p,child,depth+1));
        return r;
    }
    return copy(p,v);
}
static V *arguments(view *p,V *full,bool focused,size_t focus) {
    V *r=arr(p), *v; size_t i,n;
    yyjson_mut_arr_foreach(full,i,n,v) {
        if (focused && i!=focus) continue;
        V *a=obj(p); take(p,a,v,"index"); take(p,a,v,"expression");
        set(p,a,"local_value_flow",relation_copy(p,get(v,"local_value_flow"),0)); add(p,r,a);
    }
    return r;
}
static V *layer(view *p,V *full,bool focused,size_t focus) {
    V *r=obj(p);
    const char *common[]={"schema","analysis_id","call_id","basis","authorization_verdict",
        "business_policy","call","receiver","gaps","truncated","item_limit","source_trust","layer"};
    for (size_t i=0;i<sizeof(common)/sizeof(common[0]);i++) take(p,r,full,common[i]);
    V *jc=get(full,"java_context"), *j=obj(p), *omitted=obj(p);
    const char *kept[]={"method","parameters","conditions","framework_declarations","scope","control_flow"};
    for (size_t i=0;i<sizeof(kept)/sizeof(kept[0]);i++) take(p,j,jc,kept[i]);
    const char *removed[]={"assignments","field_accesses","returns_and_throws"};
    for (size_t i=0;i<sizeof(removed)/sizeof(removed[0]);i++)
        num(p,omitted,removed[i],yyjson_mut_arr_size(get(jc,removed[i])));
    set(p,j,"omitted_source_context_items",omitted); set(p,r,"java_context",j);
    set(p,r,"arguments",arguments(p,get(full,"arguments"),focused,focus));
    num(p,r,"total_arguments",yyjson_mut_arr_size(get(full,"arguments")));
    set(p,r,"local_value_flow",relation_copy(p,get(full,"local_value_flow"),0));
    /* SQL and control context is not filtered by argument_index. */
    take(p,r,full,"mybatis"); return r;
}
const char *sf_operation_view(yyjson_mut_doc *doc,V *full,yyjson_val *request,V **out) {
    const char *name=yyjson_get_str(yyjson_obj_get(request,"view"));
    if (!name || !strcmp(name,"full")) { *out=full; return NULL; }
    if (strcmp(name,"summary") && strcmp(name,"values")) return "invalid_operation_view";
    view p={.doc=doc,.summary=!strcmp(name,"summary")};
    yyjson_val *fv=yyjson_obj_get(request,"argument_index");
    bool focused=fv!=NULL; size_t focus=(size_t)yyjson_get_uint(fv);
    if (focused && (p.summary || !yyjson_is_uint(fv))) return "invalid_view_argument_filter";
    if (focused && focus>=yyjson_mut_arr_size(get(full,"arguments"))) return "argument_index_out_of_range";
    V *r=layer(&p,full,focused,focus); take(&p,r,full,"context_id");
    text(&p,r,"schema","cbm.agent-operation-view.v1");
    text(&p,r,"full_schema",yyjson_mut_get_str(get(full,"schema")));
    text(&p,r,"view",name);
    text(&p,r,"relation_semantics","may_dependencies_not_executable_path_or_security_verdict");
    text(&p,r,"legacy_projection","omitted_use_local_value_flow");
    text(&p,r,"evidence_access",p.summary ? "indexed_evidence_omitted_use_full_request" : "indices_scoped_to_each_local_evidence_table");
    text(&p,r,"analysis_cost","view_projection_not_analysis_depth_see_cache_counters");
    if (focused) num(&p,r,"selected_argument_index",focus);
    V *flow=get(full,"argument_flow");
    if (flow) {
        V *f=obj(&p), *k,*v; size_t i,n;
        yyjson_mut_obj_foreach(flow,i,n,k,v) {
            const char *s=yyjson_mut_get_str(k);
            if (eq(s,"upstream_contexts") || eq(s,"paths") || eq(s,"local_value_paths") ||
                eq(s,"basis") || eq(s,"taint_transformations")) continue;
            set(&p,f,s,copy(&p,v));
        }
        text(&p,f,"basis","declared_call_candidates_and_local_value_dependencies");
        V *layers=arr(&p);
        yyjson_mut_arr_foreach(get(flow,"upstream_contexts"),i,n,v) add(&p,layers,layer(&p,v,false,0));
        set(&p,f,"upstream_contexts",layers);
        V *paths=arr(&p);
        yyjson_mut_arr_foreach(get(flow,"local_value_paths"),i,n,v)
            if (!focused || yyjson_mut_get_uint(get(v,"argument_index"))==focus)
                add(&p,paths,relation_copy(&p,v,0));
        num(&p,f,"returned_argument_paths",yyjson_mut_arr_size(paths));
        set(&p,f,"local_value_paths",paths); set(&p,r,"argument_flow",f);
    }
    V *again=yyjson_val_mut_copy(doc,request);
    if (!again) return "out_of_memory";
    yyjson_mut_obj_remove_str(again,"argument_index"); set(&p,again,"view",yyjson_mut_strcpy(doc,"full"));
    set(&p,again,"expect_context",copy(&p,get(full,"context_id")));
    V *retrieval=obj(&p); text(&p,retrieval,"tool","inspect_operation_context");
    set(&p,retrieval,"arguments",again); set(&p,r,"full_request",retrieval);
    if (p.failed) return "out_of_memory";
    *out=r; return NULL;
}
