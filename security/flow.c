#include "flow.h"
#include "parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern const TSLanguage *tree_sitter_java(void);
#define FLOW_NODES 50000U
#define FLOW_ARGS 64U

typedef yyjson_mut_val val;
typedef struct { yyjson_mut_doc *json; const char *error; } writer;
static val *object(writer *w) { return yyjson_mut_obj(w->json); }
static val *array(writer *w) { return yyjson_mut_arr(w->json); }
static val *string(writer *w, const char *s) { return yyjson_mut_strcpy(w->json, s); }
static void put(writer *w, val *o, const char *key, val *v) {
    val *k = string(w, key);
    if (!o || !v || !k || !yyjson_mut_obj_put(o, k, v)) w->error = "out_of_memory";
}
static void text(writer *w, val *o, const char *key, const char *s) { put(w,o,key,string(w,s)); }
static void number(writer *w, val *o, const char *key, size_t n) { put(w,o,key,yyjson_mut_uint(w->json,n)); }
static void add(writer *w, val *a, val *v) {
    if (!a || !v || !yyjson_mut_arr_append(a,v)) w->error = "out_of_memory";
}
static val *get(val *o, const char *k) { return yyjson_mut_obj_get(o,k); }
static const char *word(val *o, const char *k) { return yyjson_mut_get_str(get(o,k)); }
static bool equal(const char *a, const char *b) { return a && b && !strcmp(a,b); }
static bool same(TSNode a, TSNode b) {
    return !ts_node_is_null(a) && !ts_node_is_null(b) && ts_node_eq(a,b);
}
static bool inside(TSNode a, TSNode b) {
    return !ts_node_is_null(a) && !ts_node_is_null(b) && ts_node_start_byte(a)<=ts_node_start_byte(b) && ts_node_end_byte(b)<=ts_node_end_byte(a);
}
static bool spells(const sf_document *d, TSNode n, const char *s) {
    if (ts_node_is_null(n)) return false;
    size_t a=ts_node_start_byte(n), b=ts_node_end_byte(n), z=strlen(s);
    return b>=a && b<=d->source_size && b-a==z && !memcmp(d->source+a,s,z);
}
static bool simple(const char *s) {
    if (!s || !*s || (*s>='0' && *s<='9')) return false;
    for (;*s;s++) if (!((*s>='A' && *s<='Z') || (*s>='a' && *s<='z') || (*s>='0' && *s<='9') || *s=='_' || *s=='$')) return false;
    return true;
}
static val *source_ref(writer *w, const sf_document *d, TSNode node) {
    val *r=object(w);
    if (ts_node_is_null(node)) return yyjson_mut_null(w->json);
    size_t a=ts_node_start_byte(node), b=ts_node_end_byte(node);
    if (a>b || b>d->source_size) { w->error="invalid_flow_span"; return r; }
    size_t bytes=b-a, preview=bytes>512 ? 512 : bytes;
    while (preview && preview<bytes && ((unsigned char)d->source[a+preview]&0xc0U)==0x80U) preview--;
    text(w,r,"path",d->path); text(w,r,"sha256",d->source_hash);
    number(w,r,"start_byte",a); number(w,r,"end_byte",b);
    put(w,r,"text_prefix",yyjson_mut_strncpy(w->json,d->source+a,preview));
    put(w,r,"text_truncated",yyjson_mut_bool(w->json,preview<bytes)); return r;
}
static TSNode direct(TSNode n, const char *kind) {
    TSNode found={0};
    if (ts_node_is_null(n)) return found;
    TSTreeCursor c=ts_tree_cursor_new(n);
    if (ts_tree_cursor_goto_first_child(&c)) do {
        TSNode x=ts_tree_cursor_current_node(&c);
        if (sf_node_is(x,kind)) { found=x; break; }
    } while (ts_tree_cursor_goto_next_sibling(&c));
    ts_tree_cursor_delete(&c); return found;
}
static TSNode method_of(TSNode n) {
    for (unsigned i=0;i<128 && !ts_node_is_null(n);i++,n=ts_node_parent(n)) {
        if (sf_node_is(n,"method_declaration")) return n;
        if (sf_node_is(n,"lambda_expression") || sf_node_is(n,"class_body") || sf_node_is(n,"constructor_declaration")) break;
    }
    return (TSNode){0};
}
static TSNode type_of(TSNode n) {
    for (unsigned i=0;i<128 && !ts_node_is_null(n);i++,n=ts_node_parent(n))
        if (sf_node_is(n,"class_declaration") || sf_node_is(n,"interface_declaration")) return n;
    return (TSNode){0};
}

typedef struct {
    TSNode nodes[FLOW_NODES]; size_t count;
    const sf_document *doc; clock_t start;
    TSTree *tree;
} parsed;
static bool collect(TSNode n, void *p) {
    parsed *t=p;
    if (t->count>=FLOW_NODES) return false;
    t->nodes[t->count++]=n; return true;
}
static const char *read_input(void *p, uint32_t at, TSPoint point, uint32_t *size) {
    (void)point; const sf_document *d=((parsed *)p)->doc;
    size_t left=at<d->source_size ? d->source_size-at : 0;
    *size=(uint32_t)(left>4096 ? 4096 : left);
    return left ? d->source+at : "";
}
static bool stop(TSParseState *state) {
    parsed *p=state->payload; clock_t now=clock();
    return now==(clock_t)-1 || (double)(now-p->start)/CLOCKS_PER_SEC>3.0;
}
static const char *parse(parsed *p, const sf_document *d, size_t *attempts) {
    if (d->source_size>SF_FLOW_SOURCE) return "flow_source_limit_exceeded";
    /* Raw Unicode escapes can change Java tokens before parsing. */
    for (size_t i=1;i<d->source_size;i++) if (d->source[i-1]=='\\' && d->source[i]=='u') return "java_unicode_escape_not_modeled";
    p->doc=d; p->start=clock();
    if (p->start==(clock_t)-1) return "clock_unavailable";
    TSParser *parser=ts_parser_new();
    if (!parser) return "out_of_memory";
    if (!ts_parser_set_language(parser,tree_sitter_java())) { ts_parser_delete(parser); return "grammar_abi_mismatch"; }
    if (attempts) (*attempts)++;
    TSInput in={.payload=p,.read=read_input,.encoding=TSInputEncodingUTF8};
    TSParseOptions options={.payload=p,.progress_callback=stop};
    p->tree=ts_parser_parse_with_options(parser,NULL,in,options); ts_parser_delete(parser);
    if (!p->tree) return "flow_parse_failed";
    if (ts_node_has_error(ts_tree_root_node(p->tree))) return "flow_syntax_incomplete";
    size_t visited;
    if (!sf_walk(ts_tree_root_node(p->tree),collect,p,&visited)) return "flow_node_limit_exceeded";
    return NULL;
}
static TSNode call_node(const parsed *p, const sf_fact *f) {
    for (size_t i=0;i<p->count;i++) if (sf_node_is(p->nodes[i],"method_invocation") && ts_node_start_byte(p->nodes[i])==f->span.start && ts_node_end_byte(p->nodes[i])==f->span.end) return p->nodes[i];
    return (TSNode){0};
}
static bool package(const parsed *p, char out[256]) {
    out[0]=0;
    for (size_t i=0;i<p->count;i++) if (sf_node_is(p->nodes[i],"package_declaration")) {
        TSNode n=direct(p->nodes[i],"scoped_identifier");
        if (ts_node_is_null(n)) n=direct(p->nodes[i],"identifier");
        return sf_node_text(p->doc,n,out,256);
    }
    return true;
}
static bool type_matches(const parsed *p, TSNode n, const char *qualified) {
    char name[384];
    if (!sf_node_text(p->doc,n,name,sizeof(name))) return false;
    if (strchr(name,'.')) return !strcmp(name,qualified);
    if (!simple(name)) return false;
    size_t hits=0; bool matches=false;
    for (size_t i=0;i<p->count;i++) {
        TSNode x=p->nodes[i];
        if ((sf_node_is(x,"type_parameter") || sf_node_is(x,"class_declaration") || sf_node_is(x,"interface_declaration") || sf_node_is(x,"enum_declaration") || sf_node_is(x,"record_declaration")) && spells(p->doc,sf_field(x,"name"),name)) return false;
        if (!sf_node_is(x,"import_declaration") || !ts_node_is_null(direct(x,"static")) || !ts_node_is_null(direct(x,"asterisk"))) continue;
        char imported[384];
        if (!sf_node_text(p->doc,direct(x,"scoped_identifier"),imported,sizeof(imported))) continue;
        const char *leaf=strrchr(imported,'.'); leaf=leaf ? leaf+1 : imported;
        if (!strcmp(leaf,name)) { hits++; matches=!strcmp(imported,qualified); }
    }
    if (hits) return hits==1 && matches;
    char pkg[256], full[512];
    if (!package(p,pkg)) return false;
    int size=snprintf(full,sizeof(full),"%s%s%s",pkg,*pkg ? "." : "",name);
    return size>=0 && (size_t)size<sizeof(full) && !strcmp(full,qualified);
}
static bool receiver_type(const parsed *p, TSNode call, TSNode method, const char *expected, TSNode *evidence) {
    TSNode receiver=sf_field(call,"object");
    bool this_field=sf_node_is(receiver,"field_access") && spells(p->doc,sf_field(receiver,"object"),"this");
    TSNode name_node=this_field ? sf_field(receiver,"field") : receiver;
    char name[128];
    if (!sf_node_text(p->doc,name_node,name,sizeof(name)) || !simple(name)) return false;
    TSNode declaration={0}, type={0}; size_t found=0;
    TSNode owner=type_of(method), params=sf_field(method,"parameters");
    if (!this_field) for (size_t i=0;i<p->count;i++) {
        TSNode n=p->nodes[i];
        if (sf_node_is(n,"formal_parameter") && same(ts_node_parent(n),params) && spells(p->doc,sf_field(n,"name"),name)) { found++; declaration=n; type=sf_field(n,"type"); }
    }
    if (!found) for (size_t i=0;i<p->count;i++) {
        TSNode n=p->nodes[i], parent=ts_node_parent(n);
        if (sf_node_is(n,"variable_declarator") && sf_node_is(parent,"field_declaration") && same(type_of(parent),owner) && spells(p->doc,sf_field(n,"name"),name)) { found++; declaration=n; type=sf_field(parent,"type"); }
    }
    if (found!=1 || !type_matches(p,type,expected)) return false;
    TSNode allowed=sf_field(declaration,"name");
    for (size_t i=0;i<p->count;i++) {
        TSNode n=p->nodes[i];
        if (!inside(method,n)) continue;
        if (sf_node_is(n,"assignment_expression")) {
            TSNode left=sf_field(n,"left");
            if ((!this_field && spells(p->doc,left,name)) || (sf_node_is(left,"field_access") && spells(p->doc,sf_field(left,"object"),"this") && spells(p->doc,sf_field(left,"field"),name))) return false;
        }
        if (!this_field && (sf_node_is(n,"variable_declarator") || sf_node_is(n,"formal_parameter") || sf_node_is(n,"catch_formal_parameter") || sf_node_is(n,"enhanced_for_statement"))) {
            TSNode binding=sf_field(n,"name");
            if (!same(binding,allowed) && spells(p->doc,binding,name)) return false;
        }
    }
    *evidence=declaration; return true;
}
/* The selected downstream CALL must belong to the uniquely named method that
 * the upstream receiver type identifies. Selecting a file alone proves nothing.
 * Virtual dispatch and runtime wiring are intentionally not promoted to facts. */
static const char *check_link(const sf_operation_request *down, const sf_operation_request *up, writer *w, val *link) {
    parsed *a=calloc(1,sizeof(*a)), *b=calloc(1,sizeof(*b));
    if (!a || !b) { free(a); free(b); return "out_of_memory"; }
    const char *error=parse(a,down->caller,down->parse_attempts);
    if (!error) error=parse(b,up->caller,down->parse_attempts);
    if (error) goto done;
    TSNode dc=call_node(a,down->call), uc=call_node(b,up->call);
    TSNode dm=method_of(dc), um=method_of(uc), owner=type_of(dm);
    if (ts_node_is_null(dm) || ts_node_is_null(um)) { error="caller_method_not_resolved"; goto done; }
    if (!sf_node_is(owner,"class_declaration") || !sf_node_is(ts_node_parent(owner),"program")) { error="callee_requires_top_level_concrete_class"; goto done; }
    if (!ts_node_is_null(sf_field(owner,"superclass")) || !ts_node_is_null(sf_field(owner,"interfaces")) || !ts_node_is_null(sf_field(owner,"type_parameters")) || !ts_node_is_null(sf_field(dm,"type_parameters"))) { error="inheritance_or_generics_not_modeled"; goto done; }
    char pkg[256], name[128], expected[512], method[128];
    if (!package(a,pkg) || !sf_node_text(a->doc,sf_field(owner,"name"),name,sizeof(name)) || !sf_node_text(a->doc,sf_field(dm,"name"),method,sizeof(method))) { error="callee_name_not_resolved"; goto done; }
    int n=snprintf(expected,sizeof(expected),"%s%s%s",pkg,*pkg ? "." : "",name);
    if (n<0 || (size_t)n>=sizeof(expected)) { error="callee_name_limit"; goto done; }
    size_t methods=0, types=0;
    for (size_t i=0;i<a->count;i++) {
        TSNode x=a->nodes[i];
        if (sf_node_is(x,"class_declaration") && sf_node_is(ts_node_parent(x),"program") && spells(a->doc,sf_field(x,"name"),name)) types++;
        if (sf_node_is(x,"method_declaration") && same(type_of(x),owner) && spells(a->doc,sf_field(x,"name"),method)) methods++;
    }
    if (types!=1 || methods!=1) { error="ambiguous_or_overloaded_target"; goto done; }
    if (!spells(b->doc,sf_field(uc,"name"),method)) { error="callee_method_mismatch"; goto done; }
    TSNode receiver_evidence={0};
    if (!receiver_type(b,uc,um,expected,&receiver_evidence)) { error="receiver_type_unresolved_or_rebound"; goto done; }
    text(w,link,"declared_callee_type",expected);
    put(w,link,"callee_method",source_ref(w,a->doc,dm));
    put(w,link,"caller_call",source_ref(w,b->doc,uc));
    put(w,link,"receiver_declaration",source_ref(w,b->doc,receiver_evidence));
    size_t count=0; TSNode params=sf_field(dm,"parameters");
    for (size_t i=0;i<a->count;i++) if (same(ts_node_parent(a->nodes[i]),params)) {
        TSNode x=a->nodes[i];
        if (sf_node_is(x,"formal_parameter")) count++;
        else if (sf_node_is(x,"spread_parameter") || sf_node_is(x,"receiver_parameter")) { error="varargs_or_receiver_not_modeled"; goto done; }
    }
    if (count>FLOW_ARGS || count!=up->call->argument_total || up->call->argument_count!=count || up->call->has_argument_expansion) error="caller_argument_count_mismatch";
done:
    if (a->tree) ts_tree_delete(a->tree);
    if (b->tree) ts_tree_delete(b->tree);
    free(a); free(b); return error;
}

typedef struct { val *record, *steps; size_t argument, followed; bool active; } path_state;
static void path_step(writer *w, path_state *p, val *context, size_t layer) {
    val *a=yyjson_mut_arr_get(get(context,"arguments"),p->argument);
    if (!a) { text(w,p->record,"stop_reason","argument_not_available"); p->active=false; return; }
    val *step=object(w); number(w,step,"layer",layer); number(w,step,"argument_index",p->argument);
    const char *origin=word(a,"origin"); text(w,step,"origin",origin ? origin : "unknown"); add(w,p->steps,step);
    text(w,p->record,"origin",origin ? origin : "unknown");
    if (!equal(origin,"formal_parameter_reference") && !equal(origin,"request_parameter_declaration_candidate")) {
        text(w,p->record,"stop_reason",origin ? origin : "origin_unknown"); p->active=false; return;
    }
    val *index=get(a,"formal_parameter_index");
    if (!yyjson_mut_is_uint(index) || yyjson_mut_get_uint(index)>=FLOW_ARGS) { text(w,p->record,"stop_reason","formal_index_unavailable"); p->active=false; return; }
    p->argument=(size_t)yyjson_mut_get_uint(index); number(w,step,"formal_parameter_index",p->argument);
}

const char *sf_attach_argument_flow(const sf_operation_request *root, const sf_flow_anchor *upstream,
                                    size_t count, yyjson_mut_doc *output, val *result) {
    if (!root || !root->caller || !root->call || !output || !result || !upstream || !count || count>SF_FLOW_HOPS) return "invalid_flow_arguments";
    writer w={.json=output};
    val *flow=object(&w), *layers=array(&w), *links=array(&w), *paths=array(&w);
    put(&w,result,"argument_flow",flow); put(&w,flow,"upstream_contexts",layers); put(&w,flow,"links",links); put(&w,flow,"paths",paths);
    text(&w,flow,"schema","cbm.argument-origin.v1"); text(&w,flow,"scope","explicit_caller_path");
    text(&w,flow,"direction","backward"); text(&w,flow,"basis","declared_call_candidates_and_unmodified_formal_references");
    text(&w,flow,"runtime_dispatch","not_verified"); text(&w,flow,"path_feasibility","not_evaluated");
    text(&w,flow,"object_contents","not_traced"); text(&w,flow,"taint_transformations","not_modeled");
    text(&w,flow,"absence_semantics","no_negative_security_conclusion"); number(&w,flow,"requested_hops",count);
    bool limited=yyjson_mut_get_bool(get(result,"truncated"));
    clock_t started=clock();
    if (started==(clock_t)-1) return "clock_unavailable";
    path_state states[FLOW_ARGS]={0};
    size_t nargs=yyjson_mut_arr_size(get(result,"arguments"));
    if (nargs>FLOW_ARGS) return "flow_argument_limit_exceeded";
    for (size_t i=0;i<nargs;i++) {
        path_state *p=&states[i]; p->record=object(&w); p->steps=array(&w); p->argument=i; p->active=true;
        number(&w,p->record,"argument_index",i); put(&w,p->record,"steps",p->steps); add(&w,paths,p->record);
        path_step(&w,p,result,0);
    }
    sf_document held[SF_FLOW_HOPS]={0};
    sf_operation_request previous=*root;
    const char *error=NULL; size_t linked=0;
    for (size_t i=0;i<count && !w.error;i++) {
        clock_t now=clock();
        if (now==(clock_t)-1 || (double)(now-started)/CLOCKS_PER_SEC>5.0) { error="flow_cpu_budget_exceeded"; break; }
        const sf_flow_anchor *anchor=&upstream[i];
        if (!anchor->identity || !equal(anchor->identity->language,"java") || anchor->identity->source_size>SF_FLOW_SOURCE) { error="unsupported_flow_input"; break; }
        sf_document *doc=&held[i]; *doc=*anchor->identity;
        /* Only identity-only documents are accepted, never borrowed fact arrays. */
        if (doc->facts) { memset(doc,0,sizeof(*doc)); error="invalid_flow_identity"; break; }
        if (root->parse_attempts) (*root->parse_attempts)++;
        error=sf_extract(doc); if (error) break;
        sf_query q={.limit=1,.expected_analysis=doc->analysis_id,.fact_id=anchor->call_id}; sf_selection selected;
        error=sf_query_select(doc,&q,&selected); if (error) break;
        const sf_fact *call=&doc->facts[selected.indices[0]];
        if (!equal(call->kind,"call_site")) { error="unsupported_operation_anchor"; break; }
        sf_operation_request request={.snapshot_id=root->snapshot_id,.call_id=anchor->call_id,.caller=doc,.call=call,.parse_attempts=root->parse_attempts};
        val *local=NULL; error=sf_inspect_operation(&request,output,&local); if (error) break;
        limited |= yyjson_mut_get_bool(get(local,"truncated"));
        number(&w,local,"layer",i+1); add(&w,layers,local);
        val *link=object(&w);
        const char *reason=check_link(&previous,&request,&w,link);
        if (equal(reason,"out_of_memory")) { error=reason; break; }
        number(&w,link,"caller_layer",i+1); number(&w,link,"callee_layer",i);
        text(&w,link,"status",reason ? "unresolved" : "declared_target_candidate");
        text(&w,link,"caller_call_id",anchor->call_id); text(&w,link,"callee_call_id",previous.call_id);
        text(&w,link,"runtime_dispatch","not_verified"); add(&w,links,link);
        if (reason) {
            text(&w,link,"reason",reason);
            for (size_t j=0;j<nargs;j++) if (states[j].active) { text(&w,states[j].record,"stop_reason",reason); states[j].active=false; }
            break;
        }
        linked++;
        for (size_t j=0;j<nargs;j++) if (states[j].active) { states[j].followed++; path_step(&w,&states[j],local,i+1); }
        previous=request;
    }
    for (size_t i=0;i<nargs;i++) {
        if (states[i].active) text(&w,states[i].record,"stop_reason","selected_path_exhausted");
        number(&w,states[i].record,"candidate_hops_followed",states[i].followed);
        text(&w,states[i].record,"trust","not_established");
    }
    number(&w,flow,"linked_candidate_hops",linked); number(&w,flow,"evaluated_hops",yyjson_mut_arr_size(links));
    text(&w,flow,"status",linked==count ? "selected_call_candidates_linked" : "partial");
    put(&w,flow,"truncated",yyjson_mut_bool(output,limited));
    number(&w,flow,"root_argument_total",root->call->argument_total);
    number(&w,flow,"returned_argument_paths",nargs);
    for (size_t i=0;i<SF_FLOW_HOPS;i++) sf_document_free(&held[i]);
    return error ? error : w.error;
}
