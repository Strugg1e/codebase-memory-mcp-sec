/* Automatic backward exploration for one explicit MyBatis call. The explorer
 * consumes existing local relations; it is not a second value-flow evaluator. */
#include "auto_trace.h"
#include "entry_points.h"
#include "flow.h"
#include "foundation/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TRACE_CALLS 1024U
#define TRACE_FACTS 20000U
#define TRACE_CONTEXT_BYTES (2U * 1024U * 1024U)
#define TRACE_CPU_SECONDS 10.0
#define NO_INDEX ((size_t)-1)
typedef yyjson_mut_val V;
typedef struct {
    sf_document doc;
    TSTree *tree;
    yyjson_doc *entries;
    const char *failure;
    bool entries_attempted;
    char package[256];
} file_info;
typedef struct {
    size_t file, context_index;
    const sf_fact *fact, *method;
    char id[65], owner[512];
    yyjson_mut_doc *context_doc;
    V *context;
    const char *failure;
    bool attempted;
} call_info;
typedef struct {
    size_t down, up, index;
    bool accepted;
} edge_info;
typedef struct {
    size_t call, argument, sink, depth;
    size_t parent, parent_formal, edge;
    bool derived;
} state;
typedef struct {
    const sf_trace_request *request;
    yyjson_mut_doc *json;
    V *result, *contexts, *paths, *frontiers, *edges, *coverage, *gaps;
    file_info files[SF_TRACE_FILES];
    call_info calls[TRACE_CALLS];
    edge_info links[SF_TRACE_CHECKS];
    state queue[SF_TRACE_STATES];
    size_t nfiles, ncalls, nlinks, nstates, processed, context_count, context_bytes;
    size_t parses, context_hits, edge_hits, budget_stops;
    bool truncated, file_gaps;
    const char *error;
    clock_t start;
} engine;

static bool eq(const char *a, const char *b) { return a && b && !strcmp(a,b); }
static V *obj(engine *e) { return yyjson_mut_obj(e->json); }
static V *arr(engine *e) { return yyjson_mut_arr(e->json); }
static V *str(engine *e, const char *s) { return yyjson_mut_strcpy(e->json,s); }
static void put(engine *e, V *o, const char *k, V *v) {
    V *key=str(e,k);
    if (!o || !v || !key || !yyjson_mut_obj_put(o,key,v)) e->error="out_of_memory";
}
static void text(engine *e, V *o, const char *k, const char *v) { put(e,o,k,str(e,v)); }
static void num(engine *e, V *o, const char *k, size_t v) { put(e,o,k,yyjson_mut_uint(e->json,v)); }
static void flag(engine *e, V *o, const char *k, bool v) { put(e,o,k,yyjson_mut_bool(e->json,v)); }
static void add(engine *e, V *a, V *v) {
    if (!a || !v || !yyjson_mut_arr_append(a,v)) e->error="out_of_memory";
}
static V *get(V *v, const char *key) { return yyjson_mut_obj_get(v,key); }
static const char *word(V *v, const char *key) { return yyjson_mut_get_str(get(v,key)); }
static bool mapping_ready(V *mapping) {
    return eq(word(mapping,"status"),"explicit_mapping_candidate") ||
           eq(word(mapping,"status"),"explicit_annotation_candidate");
}
static V *copy(engine *e, V *v) { return v ? yyjson_mut_val_mut_copy(e->json,v) : yyjson_mut_null(e->json); }
static void unique(engine *e, V *list, const char *s) {
    size_t i,n; V *v;
    yyjson_mut_arr_foreach(list,i,n,v) if (eq(yyjson_mut_get_str(v),s)) return;
    add(e,list,str(e,s));
}
static void limit(engine *e, const char *reason) {
    e->truncated=true; e->budget_stops++; unique(e,e->gaps,reason);
}
static bool time_left(engine *e) {
    clock_t now=clock();
    if (now==(clock_t)-1 || (double)(now-e->start)/CLOCKS_PER_SEC>TRACE_CPU_SECONDS) {
        limit(e,"trace_cpu_budget_exceeded"); return false;
    }
    return true;
}
static bool span_eq(sf_span a, sf_span b) { return a.start==b.start && a.end==b.end; }
static bool span_text(const sf_document *d, sf_span p, char *out, size_t cap) {
    if (p.start>p.end || p.end>d->source_size || p.end-p.start>=cap) return false;
    memcpy(out,d->source+p.start,p.end-p.start); out[p.end-p.start]=0; return true;
}
static V *anchor(engine *e, size_t index) {
    call_info *c=&e->calls[index];file_info *f=&e->files[c->file];
    V *r=obj(e);text(e,r,"path",f->doc.path);text(e,r,"analysis_id",f->doc.analysis_id);
    text(e,r,"call_id",c->id);return r;
}
static sf_operation_request operation(engine *e, size_t index) {
    call_info *c=&e->calls[index];
    sf_operation_request r={.snapshot_id=e->request->operation.snapshot_id,
        .caller=&e->files[c->file].doc,.call=c->fact,.call_id=c->id,.parse_attempts=&e->parses};
    return r;
}
static const sf_fact *enclosing(const sf_document *d, const sf_fact *f, const char *kind) {
    if (!f->has_enclosing || !eq(f->enclosing_kind,kind)) return NULL;
    for (size_t i=0;i<d->count;i++)
        if (eq(d->facts[i].kind,kind) && span_eq(f->enclosing,d->facts[i].span)) return &d->facts[i];
    return NULL;
}
static bool qualified_owner(file_info *f, const sf_fact *method, char out[512]) {
    const sf_fact *owner=enclosing(&f->doc,method,"class_declaration");char name[256];
    if (!owner || owner->has_enclosing || !owner->has_name || !span_text(&f->doc,owner->name,name,sizeof(name))) return false;
    int n=snprintf(out,512,"%s%s%s",f->package,*f->package?".":"",name);
    return n>=0 && n<512;
}
static size_t owner_count(engine *e, const char *qualified) {
    size_t count=0;
    for (size_t i=0;i<e->nfiles;i++) {
        file_info *f=&e->files[i];if(f->failure)continue;
        for(size_t j=0;j<f->doc.count;j++) {
            const sf_fact *v=&f->doc.facts[j];char name[256],full[512];
            if ((!eq(v->kind,"class_declaration") && !eq(v->kind,"interface_declaration")) ||
                v->has_enclosing || !v->has_name || !span_text(&f->doc,v->name,name,sizeof(name)))continue;
            int n=snprintf(full,sizeof(full),"%s%s%s",f->package,*f->package?".":"",name);
            if(n>=0 && (size_t)n<sizeof(full) && eq(full,qualified))count++;
        }
    }
    return count;
}
static void read_package(file_info *f) {
    TSNode root=ts_tree_root_node(f->tree);
    for(uint32_t i=0;i<ts_node_named_child_count(root);i++) {
        TSNode n=ts_node_named_child(root,i);
        if(!sf_node_is(n,"package_declaration"))continue;
        for(uint32_t j=0;j<ts_node_named_child_count(n);j++) {
            TSNode v=ts_node_named_child(n,j);
            if(sf_node_is(v,"identifier") || sf_node_is(v,"scoped_identifier")) {
                if(!sf_node_text(&f->doc,v,f->package,sizeof(f->package)))f->failure="package_name_limit";
                return;
            }
        }
        f->failure="package_not_resolved";
    }
}
static const char *load_files(engine *e, size_t *root_call) {
    size_t facts=0;*root_call=NO_INDEX;
    for(size_t i=0;i<e->request->scope_count;i++) {
        const sf_operation_source *s=&e->request->scope[i];file_info *f=&e->files[i];e->nfiles++;
        V *record=obj(e);text(e,record,"path",s->path);text(e,record,"sha256",s->sha256);add(e,e->coverage,record);
        if(!sf_document_init(&f->doc,s->source,s->size,s->path) || !eq(f->doc.source_hash,s->sha256))return "invalid_trace_source_identity";
        if(!eq(f->doc.language,"java"))return "unsupported_trace_language";
        if(!time_left(e))f->failure="trace_cpu_budget_exceeded";
        else if(facts>=TRACE_FACTS)f->failure="trace_fact_budget_exceeded";
        else {
            e->parses++;f->failure=sf_extract_tree(&f->doc,&f->tree);facts+=f->doc.count;
            if(!f->failure && facts>TRACE_FACTS){f->failure="trace_fact_budget_exceeded";limit(e,f->failure);}
            if(!f->failure && (f->doc.parse_has_error || !f->doc.traversal_complete))f->failure="trace_file_analysis_incomplete";
            if(!f->failure)read_package(f);
        }
        if(f->failure) {
            text(e,record,"status",f->failure);e->file_gaps=true;
            if(eq(s->path,e->request->operation.caller->path))return f->failure;
            continue;
        }
        text(e,record,"status","parsed_in_supported_subset");num(e,record,"fact_count",f->doc.count);
        flag(e,record,"framework_analysis_complete",f->doc.framework_analysis_complete);
        flag(e,record,"framework_bindings_limited",f->doc.framework_bindings_limited);
        if(!f->doc.framework_analysis_complete || f->doc.framework_bindings_limited)e->file_gaps=true;
        for(size_t j=0;j<f->doc.count;j++) {
            const sf_fact *v=&f->doc.facts[j];
            if(!eq(v->kind,"call_site"))continue;
            const sf_fact *method=enclosing(&f->doc,v,"method_declaration");
            if(!method){unique(e,e->gaps,"non_method_call_contexts_not_searched");continue;}
            if(e->ncalls>=TRACE_CALLS){limit(e,"trace_call_catalog_limit");break;}
            call_info *c=&e->calls[e->ncalls];c->file=i;c->fact=v;c->method=method;c->context_index=NO_INDEX;
            sf_fact_id(&f->doc,v,c->id);qualified_owner(f,method,c->owner);
            if(eq(s->path,e->request->operation.caller->path) && eq(c->id,e->request->operation.call_id))*root_call=e->ncalls;
            e->ncalls++;
        }
    }
    if(*root_call==NO_INDEX)return "trace_root_call_not_available";
    return e->error;
}
static V *context(engine *e, size_t index, bool root) {
    call_info *c=&e->calls[index];
    if(c->attempted){e->context_hits++;return c->context;}
    c->attempted=true;
    if(!time_left(e)){c->failure="trace_cpu_budget_exceeded";return NULL;}
    c->context_doc=yyjson_mut_doc_new(NULL);if(!c->context_doc){e->error="out_of_memory";return NULL;}
    sf_operation_request request=operation(e,index);
    if(root){request.mapper=e->request->operation.mapper;request.xml=e->request->operation.xml;request.annotation_sql=e->request->operation.annotation_sql;}
    c->failure=sf_inspect_operation(&request,c->context_doc,&c->context);
    if(c->failure){c->context=NULL;return NULL;}
    size_t size=0;char *raw=yyjson_mut_val_write(c->context,0,&size);
    if(!raw){e->error="out_of_memory";c->context=NULL;return NULL;}free(raw);
    if(size>TRACE_CONTEXT_BYTES-e->context_bytes) {
        limit(e,"trace_context_bytes_exceeded");c->failure="trace_context_bytes_exceeded";
        c->context=NULL;yyjson_mut_doc_free(c->context_doc);c->context_doc=NULL;return NULL;
    }
    e->context_bytes+=size;c->context_index=e->context_count++;
    V *record=obj(e);num(e,record,"index",c->context_index);put(e,record,"anchor",anchor(e,index));
    put(e,record,"operation",copy(e,c->context));add(e,e->contexts,record);return c->context;
}
static V *indexed(V *a, size_t index) {
    size_t i,n;V *v;yyjson_mut_arr_foreach(a,i,n,v)
        if(yyjson_mut_is_uint(get(v,"index")) && yyjson_mut_get_uint(get(v,"index"))==index)return v;
    return NULL;
}
static V *argument(engine *e, size_t call, size_t index) {
    V *c=context(e,call,false);return c ? indexed(get(c,"arguments"),index) : NULL;
}
static bool has_index(V *a,size_t target) {
    size_t i,n;V *v;yyjson_mut_arr_foreach(a,i,n,v)
        if(yyjson_mut_is_uint(v)&&yyjson_mut_get_uint(v)==target)return true;
    return false;
}
static yyjson_val *source_entry(engine *e,size_t call,size_t formal,yyjson_val **input) {
    call_info *c=&e->calls[call];file_info *f=&e->files[c->file];*input=NULL;
    if(!f->entries_attempted){f->entries_attempted=true;const char *err=sf_spring_entry_points(&f->doc,ts_tree_root_node(f->tree),&f->entries);
        if(err){unique(e,e->gaps,err);e->file_gaps=true;}}
    if(!f->entries)return NULL;
    yyjson_val *catalog_coverage=yyjson_obj_get(yyjson_doc_get_root(f->entries),"coverage");
    if(yyjson_get_bool(yyjson_obj_get(catalog_coverage,"truncated")))limit(e,"source_entry_catalog_truncated");
    if(!yyjson_get_bool(yyjson_obj_get(catalog_coverage,"syntax_complete")))e->file_gaps=true;
    yyjson_val *entries=yyjson_obj_get(yyjson_doc_get_root(f->entries),"entries"),*entry;size_t i,n;
    yyjson_arr_foreach(entries,i,n,entry) {
        yyjson_val *method=yyjson_obj_get(entry,"handler_source");
        if(yyjson_get_uint(yyjson_obj_get(method,"start_byte"))!=c->method->span.start ||
           yyjson_get_uint(yyjson_obj_get(method,"end_byte"))!=c->method->span.end)continue;
        yyjson_val *inputs=yyjson_obj_get(entry,"inputs"),*v;size_t j,k;
        yyjson_arr_foreach(inputs,j,k,v) {
            if(yyjson_get_uint(yyjson_obj_get(v,"index"))!=formal)continue;
            yyjson_val *decls=yyjson_obj_get(v,"declarations"),*d;size_t a,b;
            yyjson_arr_foreach(decls,a,b,d)if(eq(yyjson_get_str(yyjson_obj_get(d,"framework")),"spring-mvc") &&
                eq(yyjson_get_str(yyjson_obj_get(d,"role")),"request_input_declaration")){*input=v;return entry;}
        }
    }
    return NULL;
}
static bool scalar_input(engine *e,size_t call,yyjson_val *input) {
    yyjson_val *type=yyjson_obj_get(input,"type");
    const char *s=yyjson_get_str(yyjson_obj_get(type,"text_prefix"));
    if(yyjson_get_bool(yyjson_obj_get(type,"text_truncated")))return false;
    const char *types[]={"String","java.lang.String","byte","short","int","long","float","double","boolean","char",
        "Byte","Short","Integer","Long","Float","Double","Boolean","Character",
        "java.lang.Byte","java.lang.Short","java.lang.Integer","java.lang.Long","java.lang.Float","java.lang.Double","java.lang.Boolean","java.lang.Character"};
    bool allowed=false;
    for(size_t i=0;i<sizeof(types)/sizeof(types[0]);i++)if(eq(s,types[i]))allowed=true;
    if(!allowed)return false;
    if(strchr(s,'.') || (*s>='a' && *s<='z'))return true;
    /* String and boxed names may name application classes. Do not classify
     * them by spelling alone when the selected scope exposes a conflict. */
    file_info *f=&e->files[e->calls[call].file];
    char expected[128],qualified[512];
    int written=snprintf(expected,sizeof(expected),"java.lang.%s",s);
    if(written<0 || (size_t)written>=sizeof(expected))return false;
    TSNode root=ts_tree_root_node(f->tree);size_t explicit_imports=0;
    for(uint32_t i=0;i<ts_node_named_child_count(root);i++) {
        TSNode item=ts_node_named_child(root,i);if(!sf_node_is(item,"import_declaration"))continue;
        bool star=false;char imported[512]="";
        for(uint32_t j=0;j<ts_node_child_count(item);j++) {
            TSNode part=ts_node_child(item,j);if(sf_node_is(part,"asterisk"))star=true;
            if(sf_node_is(part,"scoped_identifier"))sf_node_text(&f->doc,part,imported,sizeof(imported));
        }
        if(star)return false;
        const char *leaf=strrchr(imported,'.');leaf=leaf?leaf+1:imported;
        if(eq(leaf,s)){explicit_imports++;if(!eq(imported,expected))return false;}
    }
    if(explicit_imports>1)return false;
    written=snprintf(qualified,sizeof(qualified),"%s%s%s",f->package,*f->package?".":"",s);
    return written>=0 && (size_t)written<sizeof(qualified) && owner_count(e,qualified)==0;
}
static void termination(engine *e,size_t state_id,const char *reason,size_t formal) {
    V *r=obj(e);num(e,r,"state_index",state_id);num(e,r,"sink_index",e->queue[state_id].sink);
    size_t context_id=e->calls[e->queue[state_id].call].context_index;
    if(context_id!=NO_INDEX)num(e,r,"context_index",context_id);
    put(e,r,"anchor",anchor(e,e->queue[state_id].call));
    num(e,r,"argument_index",e->queue[state_id].argument);text(e,r,"reason",reason);
    if(formal!=NO_INDEX)num(e,r,"formal_parameter_index",formal);
    add(e,e->frontiers,r);
}
static bool cycle(engine *e,const state *s,size_t call) {
    for(;;){if(s->call==call)return true;if(s->parent==NO_INDEX)return false;s=&e->queue[s->parent];}
}
static void emit_path(engine *e,size_t state_id,size_t formal,yyjson_val *entry,yyjson_val *input,bool derived) {
    if(yyjson_mut_arr_size(e->paths)>=e->request->max_paths){limit(e,"trace_path_limit");termination(e,state_id,"trace_path_limit",formal);return;}
    state *s=&e->queue[state_id];V *r=obj(e),*steps=arr(e),*source_value=obj(e),*unknowns=arr(e);
    num(e,r,"sink_index",s->sink);num(e,r,"candidate_hops",s->depth);
    text(e,r,"snapshot_id",e->request->operation.snapshot_id);text(e,r,"rule_id",SF_TRACE_RULE);
    text(e,r,"relation",derived?"may_depend_after_transformation":"may_preserve_value");
    text(e,r,"security_verdict","not_evaluated");text(e,r,"path_feasibility","not_evaluated");
    text(e,r,"runtime_dispatch","not_verified");
    put(e,source_value,"entry",yyjson_val_mut_copy(e->json,entry));
    put(e,source_value,"parameter",yyjson_val_mut_copy(e->json,input));num(e,source_value,"formal_parameter_index",formal);
    text(e,source_value,"model","spring-mvc-explicit-scalar-input.v1");put(e,r,"source",source_value);
    size_t order[SF_FLOW_HOPS+1],count=0,current=state_id;
    while(current!=NO_INDEX && count<SF_FLOW_HOPS+1){order[count++]=current;current=e->queue[current].parent;}
    bool literal=false;
    for(size_t i=count;i>0;i--) {
        state *part=&e->queue[order[i-1]];V *step=obj(e);call_info *call=&e->calls[part->call];
        num(e,step,"context_index",call->context_index);num(e,step,"argument_index",part->argument);
        put(e,step,"anchor",anchor(e,part->call));
        size_t param=i>1?e->queue[order[i-2]].parent_formal:formal;num(e,step,"formal_parameter_index",param);
        if(part->edge!=NO_INDEX)num(e,step,"incoming_edge_index",part->edge);
        V *local=get(argument(e,part->call,part->argument),"local_value_flow");
        literal|=yyjson_mut_get_bool(get(local,"literal_possible"));
        size_t j,n;V *v;yyjson_mut_arr_foreach(get(local,"unknown_reasons"),j,n,v){const char *name=yyjson_mut_get_str(v);if(name)unique(e,unknowns,name);}
        put(e,step,"local_relation",copy(e,local));add(e,steps,step);
    }
    put(e,r,"steps",steps);text(e,r,"steps_order","sink_to_source");put(e,r,"unknown_reasons",unknowns);
    flag(e,r,"literal_alternative_possible",literal);text(e,r,"status",yyjson_mut_arr_size(unknowns)?"candidate_with_unknowns":"candidate_in_supported_subset");
    char id[65];size_t bytes=0;char *raw=yyjson_mut_val_write(r,0,&bytes);
    if(!raw){e->error="out_of_memory";return;}cbm_sha256_hex(raw,bytes,id);free(raw);text(e,r,"path_id",id);add(e,e->paths,r);
}
static bool lexical_name(engine *e,size_t down,size_t up) {
    call_info *a=&e->calls[down],*b=&e->calls[up];char target[256],name[256];
    return a->method->has_name && b->fact->has_name &&
        span_text(&e->files[a->file].doc,a->method->name,target,sizeof(target)) &&
        span_text(&e->files[b->file].doc,b->fact->name,name,sizeof(name)) && eq(target,name);
}
static size_t check_edge(engine *e,size_t down,size_t up) {
    for(size_t i=0;i<e->nlinks;i++)if(e->links[i].down==down&&e->links[i].up==up){e->edge_hits++;return i;}
    if(e->nlinks>=e->request->max_checks){limit(e,"trace_edge_check_limit");return NO_INDEX;}
    if(!time_left(e))return NO_INDEX;
    sf_operation_request a=operation(e,down),b=operation(e,up);V *link=NULL;
    const char *reason=NULL;
    if(!*e->calls[down].owner || owner_count(e,e->calls[down].owner)!=1)reason="target_type_not_unique_in_selected_scope";
    else reason=sf_check_declared_call_link(&a,&b,e->json,&link);
    if(eq(reason,"out_of_memory")){e->error=reason;return NO_INDEX;}
    if(!link)link=obj(e);
    size_t index=e->nlinks;e->links[e->nlinks++]=(edge_info){down,up,index,reason==NULL};
    num(e,link,"index",index);put(e,link,"callee_anchor",anchor(e,down));put(e,link,"caller_anchor",anchor(e,up));
    text(e,link,"status",reason?"unresolved_candidate":"declared_target_candidate");
    text(e,link,"runtime_dispatch","not_verified");if(reason)text(e,link,"reason",reason);
    add(e,e->edges,link);return index;
}
static void explore(engine *e,size_t state_id) {
    state s=e->queue[state_id];V *ctx=context(e,s.call,false);
    if(!ctx){termination(e,state_id,e->calls[s.call].failure?e->calls[s.call].failure:"context_unavailable",NO_INDEX);return;}
    V *local=get(indexed(get(ctx,"arguments"),s.argument),"local_value_flow");
    if(!local){termination(e,state_id,"argument_relation_not_available",NO_INDEX);return;}
    size_t i,n;V *formal_value;
    V *indices=get(local,"formal_parameter_indices");
    if(!yyjson_mut_arr_size(indices)){termination(e,state_id,yyjson_mut_arr_size(get(local,"unknown_reasons"))?"unknown_value_origin":"no_known_formal_dependencies_remain",NO_INDEX);return;}
    yyjson_mut_arr_foreach(indices,i,n,formal_value) {
        if(!yyjson_mut_is_uint(formal_value)||yyjson_mut_get_uint(formal_value)>=64){termination(e,state_id,"formal_parameter_index_not_supported",NO_INDEX);continue;}
        size_t formal=(size_t)yyjson_mut_get_uint(formal_value);
        bool derived=s.derived || has_index(get(local,"derived_parameter_indices"),formal);
        yyjson_val *input=NULL,*entry=source_entry(e,s.call,formal,&input);
        if(entry) {
            if(scalar_input(e,s.call,input))emit_path(e,state_id,formal,entry,input,derived);
            else termination(e,state_id,"request_object_contents_not_modeled",formal);
            continue;
        }
        if(s.depth>=e->request->max_hops){limit(e,"trace_depth_limit");termination(e,state_id,"trace_depth_limit",formal);continue;}
        size_t accepted=0,lexical=0;
        for(size_t up=0;up<e->ncalls&&!e->error;up++) {
            if(!lexical_name(e,s.call,up))continue;
            lexical++;
            size_t edge=check_edge(e,s.call,up);if(edge==NO_INDEX){termination(e,state_id,"caller_search_budget_exceeded",formal);break;}
            if(!e->links[edge].accepted)continue;
            accepted++;
            if(cycle(e,&s,up)){termination(e,state_id,"recursive_call_cycle_cut",formal);continue;}
            if(e->nstates>=SF_TRACE_STATES){limit(e,"trace_state_limit");termination(e,state_id,"trace_state_limit",formal);break;}
            e->queue[e->nstates++]=(state){.call=up,.argument=formal,.sink=s.sink,.depth=s.depth+1,
                .parent=state_id,.parent_formal=formal,.edge=edge,.derived=derived};
        }
        if(!accepted)termination(e,state_id,lexical?"caller_targets_unresolved_in_selected_scope":"no_candidate_callers_in_selected_scope",formal);
    }
}
static int source_order(const void *a,const void *b) {return strcmp(((const sf_operation_source *)a)->path,((const sf_operation_source *)b)->path);}
static const char *validate(const sf_trace_request *r) {
    if(!r || !r->operation.caller || !r->operation.call || !r->operation.mapper || !r->scope ||
       !r->scope_count || r->scope_count>SF_TRACE_FILES || r->max_hops>SF_FLOW_HOPS ||
       !r->max_paths || r->max_paths>SF_TRACE_PATHS || !r->max_checks || r->max_checks>SF_TRACE_CHECKS)return "invalid_trace_arguments";
    size_t bytes=0;bool root=false;
    for(size_t i=0;i<r->scope_count;i++) {
        const sf_operation_source *s=&r->scope[i];
        if(!s->path || !s->source || !sf_path_valid(s->path) || !sf_digest_valid(s->sha256))return "invalid_trace_scope";
        if(s->size>SF_FLOW_SOURCE || s->size>SF_TRACE_TOTAL-bytes)return "trace_source_limit_exceeded";
        bytes+=s->size;root|=eq(s->path,r->operation.caller->path);
        if(i && strcmp(r->scope[i-1].path,s->path)>=0)return "trace_scope_not_unique_and_sorted";
    }
    return root?NULL:"trace_scope_must_include_sink_file";
}
const char *sf_trace_source_to_sink(const sf_trace_request *input,yyjson_mut_doc *output,V **result) {
    if(!result || !output || !input)return "invalid_trace_arguments";
    *result=NULL;
    sf_trace_request request=*input;sf_operation_source sorted[SF_TRACE_FILES];
    if(!request.scope || !request.scope_count || request.scope_count>SF_TRACE_FILES)return "invalid_trace_scope";
    memcpy(sorted,request.scope,request.scope_count*sizeof(*sorted));
    for(size_t i=0;i<request.scope_count;i++)if(!sorted[i].path)return "invalid_trace_scope";
    qsort(sorted,request.scope_count,sizeof(*sorted),source_order);request.scope=sorted;
    const char *error=validate(&request);if(error)return error;
    engine *e=calloc(1,sizeof(*e));if(!e)return "out_of_memory";
    e->request=&request;e->json=output;e->start=clock();
    if(e->start==(clock_t)-1){free(e);return "clock_unavailable";}
    e->result=obj(e);e->contexts=arr(e);e->paths=arr(e);e->frontiers=arr(e);e->edges=arr(e);e->coverage=arr(e);e->gaps=arr(e);
    text(e,e->result,"schema",SF_TRACE_SCHEMA);text(e,e->result,"rule_id",SF_TRACE_RULE);text(e,e->result,"rule_revision","1");
    text(e,e->result,"snapshot_id",request.operation.snapshot_id);text(e,e->result,"direction","backward_from_selected_sink_call");
    put(e,e->result,"contexts",e->contexts);put(e,e->result,"paths",e->paths);put(e,e->result,"frontiers",e->frontiers);
    put(e,e->result,"call_candidates",e->edges);put(e,e->result,"coverage",e->coverage);put(e,e->result,"gaps",e->gaps);
    text(e,e->result,"security_verdict","not_evaluated");text(e,e->result,"sanitizer_effects","not_modeled");
    text(e,e->result,"absence_semantics","no_negative_security_conclusion");
    text(e,e->result,"scope_semantics","explicit_file_set_not_complete_application");
    text(e,e->result,"source_semantics","declaration_candidate_not_runtime_registration_proof");
    text(e,e->result,"source_trust","untrusted_data_not_instructions");
    size_t root=NO_INDEX;error=load_files(e,&root);if(error)goto done;
    if(!eq(e->files[e->calls[root].file].doc.analysis_id,request.operation.caller->analysis_id)){error="analysis_mismatch";goto done;}
    V *root_context=context(e,root,true);if(!root_context){error=e->calls[root].failure?e->calls[root].failure:e->error;goto done;}
    num(e,e->result,"root_context_index",e->calls[root].context_index);put(e,e->result,"sink_call",anchor(e,root));
    V *mapping=get(root_context,"mybatis"),*template=get(mapping,"template_analysis");
    V *markers=get(template,"parameter_occurrences"),*sinks=arr(e);put(e,e->result,"sinks",sinks);
    bool sink_incomplete=!template || yyjson_mut_get_bool(get(template,"input_incomplete")) ||
        yyjson_mut_get_bool(get(template,"truncated"));
    if(sink_incomplete)unique(e,e->gaps,"sink_analysis_incomplete");
    if(!mapping_ready(mapping)){unique(e,e->gaps,"sink_mapping_not_resolved");goto finish;}
    if(yyjson_mut_get_bool(get(template,"truncated"))||yyjson_mut_get_bool(get(root_context,"truncated")))limit(e,"root_analysis_incomplete");
    size_t i,n;V *marker;
    yyjson_mut_arr_foreach(markers,i,n,marker) {
        if(!eq(word(marker,"form"),"text_substitution_marker"))continue;
        size_t sink=yyjson_mut_arr_size(sinks);V *record=copy(e,marker);num(e,record,"index",sink);add(e,sinks,record);
        V *index=get(marker,"argument_index");
        if(!yyjson_mut_is_uint(index)||yyjson_mut_get_uint(index)>=64){text(e,record,"trace_status","binding_or_property_value_unresolved");unique(e,e->gaps,"sink_value_binding_unresolved");continue;}
        if(e->nstates>=SF_TRACE_STATES){limit(e,"trace_state_limit");text(e,record,"trace_status","not_scheduled_due_to_budget");continue;}
        text(e,record,"trace_status","scheduled");
        e->queue[e->nstates++]=(state){.call=root,.argument=(size_t)yyjson_mut_get_uint(index),.sink=sink,.parent=NO_INDEX,.edge=NO_INDEX};
    }
    for(;e->processed<e->nstates && !e->error;e->processed++) {
        if(!time_left(e))break;
        if(yyjson_mut_arr_size(e->paths)>=request.max_paths){limit(e,"trace_path_limit");break;}
        explore(e,e->processed);
    }
    for(size_t i=e->processed;i<e->nstates;i++)termination(e,i,"queued_state_not_evaluated_due_to_budget",NO_INDEX);
finish:
    text(e,e->result,"status",yyjson_mut_arr_size(e->paths)?"candidate_paths_found":
         !mapping_ready(mapping)?"sink_mapping_unresolved":
         !yyjson_mut_arr_size(sinks)?(sink_incomplete?"sink_analysis_incomplete":"no_matching_sink_in_selected_mapping"):"no_candidate_path_in_analyzed_subset");
    flag(e,e->result,"truncated",e->truncated);flag(e,e->result,"file_analysis_gaps",e->file_gaps);
    flag(e,e->result,"queue_exhausted",e->processed==e->nstates);
    V *states=arr(e);
    for(size_t i=0;i<e->nstates;i++) {
        state *s=&e->queue[i];V *v=obj(e);num(e,v,"index",i);put(e,v,"anchor",anchor(e,s->call));
        num(e,v,"argument_index",s->argument);num(e,v,"sink_index",s->sink);num(e,v,"depth",s->depth);
        flag(e,v,"evaluated",i<e->processed);
        if(s->parent!=NO_INDEX){num(e,v,"parent_state_index",s->parent);num(e,v,"parent_formal_index",s->parent_formal);}
        if(s->edge!=NO_INDEX)num(e,v,"edge_index",s->edge);
        if(e->calls[s->call].context_index!=NO_INDEX)num(e,v,"context_index",e->calls[s->call].context_index);
        add(e,states,v);
    }
    put(e,e->result,"states",states);
    V *stats=obj(e);num(e,stats,"source_parse_attempts",e->parses);num(e,stats,"call_catalog_size",e->ncalls);
    num(e,stats,"edge_checks",e->nlinks);num(e,stats,"edge_cache_hits",e->edge_hits);
    num(e,stats,"contexts_computed",e->context_count);num(e,stats,"context_cache_hits",e->context_hits);
    num(e,stats,"states_scheduled",e->nstates);num(e,stats,"states_evaluated",e->processed);
    num(e,stats,"budget_stops",e->budget_stops);text(e,stats,"cache_scope","current_request_only");put(e,e->result,"statistics",stats);
    V *budgets=obj(e);num(e,budgets,"max_hops",request.max_hops);num(e,budgets,"max_paths",request.max_paths);
    num(e,budgets,"max_edge_checks",request.max_checks);num(e,budgets,"max_states",SF_TRACE_STATES);put(e,e->result,"budgets",budgets);
    /* Hash the request identity, not timing/counter-dependent search results. */
    V *identity=obj(e);text(e,identity,"schema",SF_TRACE_SCHEMA);text(e,identity,"rule",SF_TRACE_RULE);
    text(e,identity,"rule_revision","1");text(e,identity,"snapshot",request.operation.snapshot_id);
    text(e,identity,"build",SF_BUILD_ID);put(e,identity,"root",anchor(e,root));put(e,identity,"budgets",copy(e,budgets));
    V *files=arr(e);for(size_t i=0;i<request.scope_count;i++){V *f=obj(e);text(e,f,"path",sorted[i].path);text(e,f,"sha256",sorted[i].sha256);add(e,files,f);}put(e,identity,"scope",files);
    text(e,identity,"mapper_path",request.operation.mapper->path);text(e,identity,"mapper_sha256",request.operation.mapper->sha256);
    text(e,identity,"mapping_format",request.operation.annotation_sql?"annotation":"xml");
    if(request.operation.xml){text(e,identity,"mapping_path",request.operation.xml->path);text(e,identity,"mapping_sha256",request.operation.xml->sha256);}
    size_t length=0;char *raw=yyjson_mut_val_write(identity,0,&length),id[65];
    if(!raw)e->error="out_of_memory";else{cbm_sha256_hex(raw,length,id);free(raw);text(e,e->result,"trace_id",id);}
    raw=yyjson_mut_val_write(e->result,0,&length);
    if(!raw)e->error="out_of_memory";else{free(raw);if(length>SF_MAX_OUTPUT)e->error="trace_output_limit_exceeded";}
    if(!e->error)*result=e->result;
done:
    if(request.operation.parse_attempts)*request.operation.parse_attempts+=e->parses;
    for(size_t i=0;i<e->ncalls;i++)if(e->calls[i].context_doc)yyjson_mut_doc_free(e->calls[i].context_doc);
    for(size_t i=0;i<e->nfiles;i++){if(e->files[i].entries)yyjson_doc_free(e->files[i].entries);if(e->files[i].tree)ts_tree_delete(e->files[i].tree);sf_document_free(&e->files[i].doc);}
    if(!error)error=e->error;
    free(e);return error;
}
