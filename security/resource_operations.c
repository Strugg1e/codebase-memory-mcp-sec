/* Neutral resource-operation discovery for reconnaissance and hypotheses.
 * Reuses source-based mapping checks and template parsing, without local value-flow.
 * No dangerous-marker predicate, security verdict, or model invocation. */
#include "resource_operations.h"
#include "entry_points.h"
#include "flow.h"
#include "parser.h"
#include "foundation/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern const TSLanguage *tree_sitter_xml(void);
#define CATALOG_CALLS 1024U
#define CATALOG_METHODS 512U
#define CATALOG_TASKS 2048U
#define CATALOG_TYPES 1024U
#define CATALOG_DECLARATIONS 512U
#define CATALOG_PAIRS 200000U
#define ITEM_BYTES (128U * 1024U)
#define PAGE_BYTES (1536U * 1024U)
#define NONE ((size_t)-1)

typedef yyjson_mut_val V;
typedef struct {
    sf_operation_source source;
    sf_document doc;
    TSTree *tree;
    bool java, xml, ready;
    char package[256], namespace[512];
    const sf_fact *interface;
    V *coverage;
    yyjson_doc *entries;
    bool entries_attempted;
} file_info;
typedef struct { size_t file; const sf_fact *fact; char name[128], id[65]; } call_info;
typedef struct { size_t file; const sf_fact *fact; char name[128]; bool annotation; } method_info;
typedef struct { size_t call, method, xml; } task_info;
typedef struct {
    sf_resource_request request;
    yyjson_mut_doc *json;
    V *result, *coverage, *gaps, *attempts, *targets, *declarations;
    file_info files[SF_RESOURCE_FILES];
    call_info calls[CATALOG_CALLS];
    method_info methods[CATALOG_METHODS];
    task_info tasks[CATALOG_TASKS];
    char types[CATALOG_TYPES][512];
    size_t nfiles, njava, nxml, ncalls, nmethods, ntasks, ntypes, parses, facts, pairs;
    bool catalog_truncated, file_gaps, type_catalog_incomplete;
    const char *error;
    char query_id[65], scope_id[65];
} catalog;

static bool eq(const char *a,const char *b){return a&&b&&!strcmp(a,b);}
static V *obj(catalog *c){return yyjson_mut_obj(c->json);}
static V *arr(catalog *c){return yyjson_mut_arr(c->json);}
static V *str(catalog *c,const char *s){return yyjson_mut_strcpy(c->json,s);}
static V *get(V *v,const char *k){return yyjson_mut_obj_get(v,k);}
static const char *word(V *v,const char *k){return yyjson_mut_get_str(get(v,k));}
static void put(catalog *c,V *o,const char *k,V *v){
    V *key=str(c,k);if(!key||!v||!o||!yyjson_mut_obj_put(o,key,v))c->error="out_of_memory";
}
static void text(catalog *c,V *o,const char *k,const char *s){put(c,o,k,str(c,s));}
static void num(catalog *c,V *o,const char *k,size_t n){put(c,o,k,yyjson_mut_uint(c->json,n));}
static void flag(catalog *c,V *o,const char *k,bool b){put(c,o,k,yyjson_mut_bool(c->json,b));}
static void add(catalog *c,V *a,V *v){if(!v||!a||!yyjson_mut_arr_append(a,v))c->error="out_of_memory";}
static V *copy(catalog *c,V *v){return v?yyjson_mut_val_mut_copy(c->json,v):yyjson_mut_null(c->json);}
static void gap(catalog *c,const char *s){
    size_t i,n;V *v;yyjson_mut_arr_foreach(c->gaps,i,n,v)if(eq(yyjson_mut_get_str(v),s))return;
    add(c,c->gaps,str(c,s));
}
static void cut(catalog *c,const char *s){c->catalog_truncated=true;gap(c,s);}
static void failed(catalog *c,file_info *f,const char *s){
    text(c,f->coverage,"status",s);c->file_gaps=true;f->ready=false;
    if(f->java)c->type_catalog_incomplete=true;
}
static bool raw_text(const sf_document *d,sf_span s,char *out,size_t cap){
    if(s.start>s.end||s.end>d->source_size||s.end-s.start>=cap)return false;
    memcpy(out,d->source+s.start,s.end-s.start);out[s.end-s.start]=0;return true;
}
static bool logical_scope_path(const char *s){
    if(!s||!*s||strlen(s)>1024||!sf_utf8(s,strlen(s)))return false;
    const char *part=s;
    for(const char *p=s;;p++){
        unsigned char ch=(unsigned char)*p;
        if(ch=='\\'||ch==':'||(ch&&(ch<32||ch==127)))return false;
        if(!ch||ch=='/'){
            size_t n=(size_t)(p-part);
            if(!n||(n==1&&part[0]=='.')||(n==2&&part[0]=='.'&&part[1]=='.'))return false;
            if(!ch)return true;
            part=p+1;
        }
    }
}
static bool same_span(sf_span a,sf_span b){return a.start==b.start&&a.end==b.end;}
static TSNode child(TSNode n,const char *kind){
    for(uint32_t i=0;i<ts_node_named_child_count(n);i++){
        TSNode p=ts_node_named_child(n,i);if(sf_node_is(p,kind))return p;
    }return (TSNode){0};
}
static bool node_eq(file_info *f,TSNode n,const char *s){
    char name[512];return sf_node_text(&f->doc,n,name,sizeof(name))&&eq(name,s);
}
static V *reference(catalog *c,file_info *f,sf_span s){
    V *r=obj(c);text(c,r,"path",f->source.path);text(c,r,"sha256",f->source.sha256);
    num(c,r,"start_byte",s.start);num(c,r,"end_byte",s.end);
    size_t bytes=s.end-s.start,n=bytes>SF_PREVIEW_BYTES?SF_PREVIEW_BYTES:bytes;
    while(n&&n<bytes&&((unsigned char)f->source.source[s.start+n]&0xc0U)==0x80U)n--;
    put(c,r,"text_prefix",yyjson_mut_strncpy(c->json,f->source.source+s.start,n));
    flag(c,r,"text_truncated",n<bytes);return r;
}
static bool package_name(file_info *f){
    TSNode root=ts_tree_root_node(f->tree);bool seen=false;
    for(uint32_t i=0;i<ts_node_named_child_count(root);i++){
        TSNode n=ts_node_named_child(root,i);if(!sf_node_is(n,"package_declaration"))continue;
        if(seen)return false;
        seen=true;bool found=false;
        for(uint32_t j=0;j<ts_node_named_child_count(n);j++){
            TSNode p=ts_node_named_child(n,j);
            if(sf_node_is(p,"identifier")||sf_node_is(p,"scoped_identifier")){
                if(found||!sf_node_text(&f->doc,p,f->package,sizeof(f->package)))return false;
                found=true;
            }
        }if(!found)return false;
    }return true;
}
static bool qualified(file_info *f,const sf_fact *v,char out[512]){
    char name[256];if(!v->has_name||!raw_text(&f->doc,v->name,name,sizeof(name)))return false;
    int n=snprintf(out,512,"%s%s%s",f->package,*f->package?".":"",name);
    return n>=0&&n<512;
}
static size_t type_count(catalog *c,const char *name){
    size_t count=0;for(size_t i=0;i<c->ntypes;i++)if(eq(c->types[i],name))count++;return count;
}
static bool method_annotation(file_info *f,const sf_fact *method){
    /* Broad nomination on declared framework facts. The existing mapper
     * checker validates exact imports and the direct method before use. */
    for(size_t i=0;i<f->doc.count;i++){
        sf_fact *v=&f->doc.facts[i];
        if(eq(v->framework,"mybatis")&&(eq(v->role,"data_operation_declaration")||eq(v->role,"sql_provider_declaration"))&&
           v->has_enclosing&&eq(v->enclosing_kind,"method_declaration")&&same_span(v->enclosing,method->span))return true;
    }return false;
}
static void declaration(catalog *c,file_info *f,sf_span span,const char *name,
                        const char *kind,const char *format){
    if(yyjson_mut_arr_size(c->declarations)>=CATALOG_DECLARATIONS){cut(c,"declaration_catalog_limit");return;}
    V *v=obj(c);put(c,v,"source",reference(c,f,span));text(c,v,"mapping_format",format);
    if(name&&*name)text(c,v,"method_or_statement",name);
    else {text(c,v,"declaration_gap","name_not_resolved");c->file_gaps=true;}
    text(c,v,"namespace",f->namespace);text(c,v,"operation_kind_declaration",kind?kind:"unknown");
    text(c,v,"call_link_status","not_verified_by_declaration_catalog");
    text(c,v,"runtime_binding","not_verified");add(c,c->declarations,v);
}
static void java_catalog(catalog *c,size_t index){
    file_info *f=&c->files[index];size_t interfaces=0;
    for(size_t i=0;i<f->doc.count;i++){
        sf_fact *v=&f->doc.facts[i];
        if(!v->has_enclosing&&(eq(v->kind,"class_declaration")||eq(v->kind,"interface_declaration"))){
            if(c->ntypes>=CATALOG_TYPES){cut(c,"type_catalog_limit");c->type_catalog_incomplete=true;}
            else if(qualified(f,v,c->types[c->ntypes]))c->ntypes++;
            else {gap(c,"type_name_not_resolved");c->file_gaps=true;c->type_catalog_incomplete=true;}
        }
        if(eq(v->kind,"interface_declaration")&&!v->has_enclosing){interfaces++;f->interface=v;}
        if(!eq(v->kind,"call_site"))continue;
        if(!eq(v->syntax,"method_invocation")||!v->has_enclosing||!eq(v->enclosing_kind,"method_declaration")){
            gap(c,"non_method_invocations_not_cataloged");continue;
        }
        if(c->ncalls>=CATALOG_CALLS){cut(c,"call_catalog_limit");continue;}
        call_info *call=&c->calls[c->ncalls];
        if(!v->has_name||!raw_text(&f->doc,v->name,call->name,sizeof(call->name))){gap(c,"call_name_limit");continue;}
        call->file=index;call->fact=v;sf_fact_id(&f->doc,v,call->id);c->ncalls++;
    }
    if(!interfaces)return;
    if(interfaces!=1||!qualified(f,f->interface,f->namespace)){
        gap(c,"mapper_interface_not_unique_or_name_unresolved");c->file_gaps=true;return;
    }
    for(size_t i=0;i<f->doc.count;i++){
        sf_fact *v=&f->doc.facts[i];
        if(eq(v->framework,"mybatis")&&v->has_enclosing&&eq(v->enclosing_kind,"method_declaration")&&
           (eq(v->role,"data_operation_declaration")||eq(v->role,"sql_provider_declaration"))){
            char name[128]="";
            for(size_t j=0;j<f->doc.count;j++){
                sf_fact *method=&f->doc.facts[j];
                if(eq(method->kind,"method_declaration")&&same_span(method->span,v->enclosing)&&method->has_name){
                    (void)raw_text(&f->doc,method->name,name,sizeof(name));break;
                }
            }
            declaration(c,f,v->span,name,v->data_operation,"annotation");
        }
        if(!eq(v->kind,"method_declaration")||!v->has_enclosing||!eq(v->enclosing_kind,"interface_declaration")||
           !same_span(v->enclosing,f->interface->span))continue;
        if(c->nmethods>=CATALOG_METHODS){cut(c,"mapper_method_catalog_limit");break;}
        method_info *m=&c->methods[c->nmethods];
        if(!v->has_name||!raw_text(&f->doc,v->name,m->name,sizeof(m->name))){gap(c,"mapper_method_name_limit");continue;}
        /* One task per name; overload rejection belongs to the shared verifier. */
        bool seen=false;for(size_t j=0;j<c->nmethods;j++)if(c->methods[j].file==index&&eq(c->methods[j].name,m->name)){
            c->methods[j].annotation|=method_annotation(f,v);seen=true;break;
        }
        if(!seen){m->file=index;m->fact=v;m->annotation=method_annotation(f,v);c->nmethods++;}
    }
}
static bool xml_attribute(file_info *f,TSNode tag,const char *key,char *out,size_t cap){
    size_t hits=0;TSNode value={0};
    for(uint32_t i=0;i<ts_node_named_child_count(tag);i++){
        TSNode n=ts_node_named_child(tag,i);
        if(sf_node_is(n,"Attribute")&&node_eq(f,child(n,"Name"),key)){hits++;value=child(n,"AttValue");}
    }
    char raw[512];if(hits!=1||!sf_node_text(&f->doc,value,raw,sizeof(raw)))return false;
    size_t n=strlen(raw);if(n<3||n-2>=cap||(raw[0]!='\''&&raw[0]!='"')||raw[n-1]!=raw[0])return false;
    for(size_t i=1;i+1<n;i++)if(raw[i]=='&'||raw[i]=='\\'||raw[i]=='\n'||raw[i]=='\r')return false;
    memcpy(out,raw+1,n-2);out[n-2]=0;return true;
}
typedef struct { catalog *c; file_info *f; TSNode root; size_t visited; } xml_visit;
static bool xml_declaration(TSNode n,void *opaque){
    xml_visit *v=opaque;
    if(++v->visited>50000U)return false;
    if(!sf_node_is(n,"element"))return true;
    TSNode parent=ts_node_parent(n);
    while(!ts_node_is_null(parent)&&!sf_node_is(parent,"element")&&!sf_node_is(parent,"document"))parent=ts_node_parent(parent);
    if(ts_node_is_null(parent)||!ts_node_eq(parent,v->root))return true;
    TSNode tag=child(n,"STag");if(ts_node_is_null(tag))tag=child(n,"EmptyElemTag");
    const char *kind=node_eq(v->f,child(tag,"Name"),"select")?"read":
        node_eq(v->f,child(tag,"Name"),"insert")?"create":
        node_eq(v->f,child(tag,"Name"),"update")?"update":
        node_eq(v->f,child(tag,"Name"),"delete")?"delete":NULL;
    if(!kind)return true;
    char name[128]="";(void)xml_attribute(v->f,tag,"id",name,sizeof(name));
    declaration(v->c,v->f,sf_location(n),name,kind,"xml");return true;
}
typedef struct { file_info *file; clock_t started; } xml_input;
static const char *xml_read(void *opaque,uint32_t offset,TSPoint point,uint32_t *length){
    (void)point;file_info *f=((xml_input *)opaque)->file;
    size_t left=offset<f->source.size?f->source.size-offset:0;
    *length=(uint32_t)(left>4096?4096:left);return left?f->source.source+offset:"";
}
static bool xml_cancel(TSParseState *state){
    xml_input *in=state->payload;clock_t now=clock();
    return now==(clock_t)-1||(double)(now-in->started)/CLOCKS_PER_SEC>3.0;
}
static void xml_catalog(catalog *c,file_info *f){
    TSParser *parser=ts_parser_new();if(!parser){c->error="out_of_memory";return;}
    if(!ts_parser_set_language(parser,tree_sitter_xml())){ts_parser_delete(parser);failed(c,f,"xml_parser_unavailable");return;}
    xml_input input={f,clock()};
    if(input.started==(clock_t)-1){ts_parser_delete(parser);failed(c,f,"clock_unavailable");return;}
    TSInput bytes={.payload=&input,.read=xml_read,.encoding=TSInputEncodingUTF8};
    TSParseOptions options={.payload=&input,.progress_callback=xml_cancel};
    c->parses++;f->tree=ts_parser_parse_with_options(parser,NULL,bytes,options);ts_parser_delete(parser);
    if(!f->tree){failed(c,f,"xml_parse_failed");return;}
    TSNode root=ts_tree_root_node(f->tree),element={0};size_t count=0;
    if(ts_node_has_error(root)){failed(c,f,"xml_syntax_incomplete");return;}
    for(uint32_t i=0;i<ts_node_named_child_count(root);i++){
        TSNode v=ts_node_named_child(root,i);if(sf_node_is(v,"element")){element=v;count++;}
    }
    TSNode tag=child(element,"STag");if(ts_node_is_null(tag))tag=child(element,"EmptyElemTag");
    if(count!=1||!node_eq(f,child(tag,"Name"),"mapper")){
        text(c,f->coverage,"status","not_a_mapper_xml");return;
    }
    if(!xml_attribute(f,tag,"namespace",f->namespace,sizeof(f->namespace))){failed(c,f,"xml_namespace_not_resolved");return;}
    f->ready=true;text(c,f->coverage,"status","mapper_namespace_candidate");text(c,f->coverage,"namespace",f->namespace);
    xml_visit visit={c,f,element,0};size_t visited=0;
    if(!sf_walk(element,xml_declaration,&visit,&visited)){cut(c,"xml_declaration_walk_limit");c->file_gaps=true;}
}
static const char *load(catalog *c){
    for(size_t i=0;i<c->request.scope_count;i++){
        file_info *f=&c->files[i];c->nfiles++;f->source=c->request.scope[i];
        f->java=eq(sf_language_for_path(f->source.path),"java");
        const char *ext=strrchr(f->source.path,'.');f->xml=eq(ext,".xml");
        f->coverage=obj(c);text(c,f->coverage,"path",f->source.path);text(c,f->coverage,"sha256",f->source.sha256);add(c,c->coverage,f->coverage);
        if(f->java){
            if(++c->njava>SF_TRACE_FILES)return "resource_java_scope_limit";
            if(!sf_document_init(&f->doc,f->source.source,f->source.size,f->source.path))return "invalid_resource_source";
            if(c->facts>=SF_MAX_FACTS){failed(c,f,"fact_catalog_limit");cut(c,"fact_catalog_limit");continue;}
            c->parses++;const char *error=sf_extract_tree(&f->doc,&f->tree);c->facts+=f->doc.count;
            if(error){failed(c,f,error);continue;}
            if(c->facts>SF_MAX_FACTS){failed(c,f,"fact_catalog_limit");cut(c,"fact_catalog_limit");continue;}
            if(f->doc.parse_has_error||!f->doc.traversal_complete){failed(c,f,"java_analysis_incomplete");continue;}
            if(!package_name(f)){failed(c,f,"package_name_not_resolved");continue;}
            f->ready=true;text(c,f->coverage,"status","parsed_in_supported_subset");num(c,f->coverage,"fact_count",f->doc.count);
            flag(c,f->coverage,"framework_analysis_complete",f->doc.framework_analysis_complete);
            if(!f->doc.framework_analysis_complete||f->doc.framework_bindings_limited){gap(c,"framework_catalog_incomplete");c->file_gaps=true;}
            java_catalog(c,i);
        }else if(f->xml){
            c->nxml++;
            f->doc.source=f->source.source;f->doc.source_size=f->source.size;f->doc.path=f->source.path;
            xml_catalog(c,f);
        }else failed(c,f,"unsupported_resource_language");
        if(c->error)return c->error;
    }return NULL;
}
static void task(catalog *c,size_t call,size_t method,size_t xml){
    if(c->ntasks>=CATALOG_TASKS){cut(c,"mapping_task_catalog_limit");return;}
    c->tasks[c->ntasks++]=(task_info){call,method,xml};
}
static void build_tasks(catalog *c){
    bool annotations=!eq(c->request.mapping_format,"xml"),xmls=!eq(c->request.mapping_format,"annotation");
    for(size_t i=0;i<c->ncalls;i++)for(size_t j=0;j<c->nmethods;j++){
        if(++c->pairs>CATALOG_PAIRS){cut(c,"nomination_pair_budget");return;}
        if(!eq(c->calls[i].name,c->methods[j].name))continue;
        method_info *m=&c->methods[j];file_info *f=&c->files[m->file];
        if(annotations&&m->annotation)task(c,i,j,NONE);
        if(xmls)for(size_t k=0;k<c->nfiles;k++)if(c->files[k].xml&&c->files[k].ready&&eq(c->files[k].namespace,f->namespace))task(c,i,j,k);
    }
    for(size_t i=0;i<c->nfiles;i++)if(c->files[i].xml&&c->files[i].ready&&!type_count(c,c->files[i].namespace)){
        text(c,c->files[i].coverage,"association","no_mapper_type_in_selected_scope");gap(c,"unpaired_mapper_xml");c->file_gaps=true;
    }
}
/* These arguments are executable by the existing operation query, not a new
 * claim or evidence format. No presumed upstream chain is added. */
static V *inspection_request(catalog *c,task_info *t){
    call_info *call=&c->calls[t->call];file_info *f=&c->files[call->file],*m=&c->files[c->methods[t->method].file];
    V *r=obj(c);text(c,r,"snapshot_id",c->request.snapshot_id);text(c,r,"path",f->source.path);
    text(c,r,"analysis_id",f->doc.analysis_id);text(c,r,"call_id",call->id);text(c,r,"mapper_path",m->source.path);
    text(c,r,"mapping_format",t->xml==NONE?"annotation":"xml");if(t->xml!=NONE)text(c,r,"mapping_path",c->files[t->xml].source.path);
    text(c,r,"view","summary");return r;
}
static void id_value(catalog *c,V *value,char out[65]){
    size_t n=0;char *raw=yyjson_mut_val_write(value,0,&n);if(!raw){c->error="out_of_memory";out[0]=0;return;}
    cbm_sha256_hex(raw,n,out);free(raw);
}
static void identity(catalog *c){
    V *scope=obj(c),*files=arr(c);text(c,scope,"schema",SF_RESOURCE_SCHEMA);
    text(c,scope,"snapshot_id",c->request.snapshot_id);text(c,scope,"build_id",SF_BUILD_ID);
    text(c,scope,"application_id",c->request.application_id);
    for(size_t i=0;i<c->request.scope_count;i++){
        V *f=obj(c);text(c,f,"path",c->request.scope[i].path);text(c,f,"sha256",c->request.scope[i].sha256);add(c,files,f);
    }put(c,scope,"files",files);id_value(c,scope,c->scope_id);
    V *id=obj(c);text(c,id,"scope_id",c->scope_id);text(c,id,"mapping_format",c->request.mapping_format);
    text(c,id,"operation_kind",c->request.operation_kind?c->request.operation_kind:"");id_value(c,id,c->query_id);
}
static bool cursor_offset(catalog *c,size_t *offset){
    *offset=0;const char *p=c->request.cursor;if(!p)return true;
    if(strlen(p)<66||strncmp(p,c->query_id,64)||p[64]!='/')return false;
    p+=65;if(!*p)return false;
    for(;*p;p++){if(*p<'0'||*p>'9'||*offset>CATALOG_TASKS/10)return false;*offset=*offset*10+(size_t)(*p-'0');if(*offset>CATALOG_TASKS)return false;}
    return *offset<=c->ntasks;
}
static bool mapping_ready(V *m){return eq(word(m,"status"),"explicit_mapping_candidate")||eq(word(m,"status"),"explicit_annotation_candidate");}
static const char *operation_kind(V *mapping){
    const char *sql=word(mapping,"sql_operation");
    if(eq(sql,"SELECT"))return "read";
    if(eq(sql,"INSERT"))return "create";
    if(eq(sql,"UPDATE"))return "update";
    if(eq(sql,"DELETE"))return "delete";
    return "unknown";
}
/* An intentionally conservative peer key, NOT a canonical database resource.
 * Different apps or mappers never merge merely because a table name matches. */
static V *resource_candidate(catalog *c,file_info *m,V *mapping){
    V *r=obj(c),*table=get(mapping,"leading_table_candidate");
    text(c,r,"identity_status","not_resolved");
    text(c,r,"grouping_basis","selected_application_mapper_and_exact_table_spelling");
    text(c,r,"database_identity","not_verified");
    put(c,r,"table_source",copy(c,table));
    const char *name=word(table,"text_prefix");
    if(name&&*name&&!yyjson_mut_get_bool(get(table,"text_truncated"))){
        V *id=obj(c);text(c,id,"schema",SF_RESOURCE_SCHEMA);text(c,id,"snapshot_id",c->request.snapshot_id);
        text(c,id,"application_id",c->request.application_id);text(c,id,"namespace",m->namespace);text(c,id,"table",name);
        char key[65];id_value(c,id,key);text(c,r,"peer_group_id",key);text(c,r,"name_candidate",name);
        text(c,r,"identity_status","lexical_peer_candidate_only");
    }else put(c,r,"peer_group_id",yyjson_mut_null(c->json));
    return r;
}
/* Direct containment only. A call in a Service method is NOT declared to be
 * reachable from every Controller with a similar name. Reuse the entry parser. */
static V *direct_entries(catalog *c,file_info *f,const sf_fact *call){
    V *out=arr(c);
    if(!f->entries_attempted){
        f->entries_attempted=true;
        const char *error=sf_spring_entry_points(&f->doc,ts_tree_root_node(f->tree),&f->entries);
        if(error){gap(c,"entry_context_not_resolved");c->file_gaps=true;return out;}
    }
    if(!f->entries)return out;
    yyjson_val *catalogue=yyjson_doc_get_root(f->entries),*entries=yyjson_obj_get(catalogue,"entries"),*v;
    put(c,f->coverage,"entry_catalog_coverage",yyjson_val_mut_copy(c->json,yyjson_obj_get(catalogue,"coverage")));
    size_t i,n;yyjson_arr_foreach(entries,i,n,v){
        yyjson_val *at=yyjson_obj_get(v,"handler_source");
        if(!call->has_enclosing||!eq(call->enclosing_kind,"method_declaration")||
           yyjson_get_uint(yyjson_obj_get(at,"start_byte"))!=call->enclosing.start||
           yyjson_get_uint(yyjson_obj_get(at,"end_byte"))!=call->enclosing.end)continue;
        V *entry=yyjson_val_mut_copy(c->json,v);
        text(c,entry,"snapshot_id",c->request.snapshot_id);
        V *cq=get(entry,"call_query");if(cq)text(c,cq,"snapshot_id",c->request.snapshot_id);
        add(c,out,entry);
    }
    return out;
}
static V *evaluate(catalog *c,task_info *t,V *attempt){
    call_info *call=&c->calls[t->call];file_info *f=&c->files[call->file],*m=&c->files[c->methods[t->method].file];
    if(type_count(c,m->namespace)!=1){
        text(c,attempt,"status","unresolved");text(c,attempt,"reason","mapper_type_not_unique_in_scope");return NULL;
    }
    yyjson_mut_doc *d=yyjson_mut_doc_new(NULL);if(!d){c->error="out_of_memory";return NULL;}
    sf_operation_request r={.snapshot_id=c->request.snapshot_id,.call_id=call->id,.caller=&f->doc,.call=call->fact,
        .mapper=&m->source,.xml=t->xml==NONE?NULL:&c->files[t->xml].source,.annotation_sql=t->xml==NONE,.parse_attempts=&c->parses};
    V *operation=NULL;const char *error=sf_inspect_operation_structure(&r,d,&operation);V *target=NULL;
    V *mapping=get(operation,"mybatis"),*tmpl=get(mapping,"template_analysis");
    if(error||!mapping_ready(mapping)){
        text(c,attempt,"status","unresolved");text(c,attempt,"reason",error?error:word(mapping,"reason")?word(mapping,"reason"):"mapping_not_resolved");
        put(c,attempt,"gaps",copy(c,get(operation,"gaps")));goto done;
    }
    const char *kind=operation_kind(mapping);
    bool unknown=eq(kind,"unknown");
    if(c->request.operation_kind&&!unknown&&!eq(kind,c->request.operation_kind)){
        text(c,attempt,"status","filtered_operation_kind");text(c,attempt,"observed_kind",kind);goto done;
    }
    bool incomplete=!tmpl||yyjson_mut_get_bool(get(tmpl,"input_incomplete"))||yyjson_mut_get_bool(get(tmpl,"truncated"))||yyjson_mut_get_bool(get(operation,"truncated"));
    target=obj(c);text(c,target,"application_id",c->request.application_id);
    text(c,target,"status",incomplete?"operation_with_incomplete_mapping":
         c->type_catalog_incomplete?"operation_with_incomplete_type_scope":"operation_in_supported_mapping");
    flag(c,target,"type_identity_scope_complete",!c->type_catalog_incomplete);
    if(c->type_catalog_incomplete)text(c,target,"type_identity_assumption","unparsed_files_may_contain_conflicting_type_definitions");
    text(c,target,"operation_kind_candidate",kind);text(c,target,"operation_kind_basis","leading_SQL_token_not_database_effect");
    text(c,target,"filter_status",unknown&&c->request.operation_kind?"operation_kind_unresolved":"matched");
    put(c,target,"call_source",reference(c,f,call->fact->span));
    put(c,target,"resource_candidate",resource_candidate(c,m,mapping));
    text(c,target,"namespace",m->namespace);text(c,target,"method_name",call->name);
    text(c,target,"mapping_format",t->xml==NONE?"annotation":"xml");
    text(c,target,"runtime_mapping_precedence","not_resolved");text(c,target,"security_verdict","not_evaluated");
    text(c,target,"business_requirement","not_supplied");
    flag(c,target,"mapping_incomplete",incomplete);
    V *request=inspection_request(c,t);put(c,target,"inspection_request",request);
    /* Structural results are not a shortened deep analysis. They have their
     * own schema and no local-flow evidence, context ID or security verdict. */
    put(c,target,"operation_structure",copy(c,operation));
    V *deep=obj(c);text(c,deep,"tool","inspect_operation_context");
    put(c,deep,"arguments",copy(c,request));put(c,target,"inspection",deep);
    text(c,target,"analysis_scope","structure_and_mapping_only");
    text(c,target,"evidence_interpretation","neutral_material_not_a_threat_hypothesis");
    V *entries=direct_entries(c,f,call->fact);put(c,target,"direct_entry_contexts",entries);
    text(c,target,"entry_relation",yyjson_mut_arr_size(entries)?"direct_handler_containment":"no_direct_entry_cross_method_reachability_not_searched");
    V *id=obj(c);text(c,id,"scope_id",c->scope_id);put(c,id,"request",copy(c,request));char digest[65];id_value(c,id,digest);text(c,target,"operation_id",digest);
    text(c,attempt,"status","resource_operation");text(c,attempt,"operation_id",digest);
    size_t bytes=0;char *raw=yyjson_mut_val_write(target,0,&bytes);
    if(!raw)c->error="out_of_memory";
    free(raw);
    if(bytes>ITEM_BYTES){target=NULL;text(c,attempt,"status","operation_output_limit");gap(c,"operation_output_limit");}
done:
    yyjson_mut_doc_free(d);return target;
}
static int order(const void *a,const void *b){return strcmp(((const sf_operation_source *)a)->path,((const sf_operation_source *)b)->path);}
const char *sf_query_resource_operations(const sf_resource_request *input,yyjson_mut_doc *output,V **result){
    if(!input||!output||!result||!input->scope||!input->scope_count||input->scope_count>SF_RESOURCE_FILES||
       !input->limit||input->limit>SF_RESOURCE_PAGE_TARGETS||!input->max_checks||input->max_checks>SF_RESOURCE_PAGE_CHECKS||
       !sf_digest_valid(input->snapshot_id)||!input->application_id||!*input->application_id||strlen(input->application_id)>128||!sf_utf8(input->application_id,strlen(input->application_id)))return "invalid_resource_arguments";
    for(const char *p=input->application_id;*p;p++)if((unsigned char)*p<32||(unsigned char)*p==127)return "invalid_application_id";
    if(input->operation_kind&&!eq(input->operation_kind,"read")&&!eq(input->operation_kind,"create")&&
       !eq(input->operation_kind,"update")&&!eq(input->operation_kind,"delete"))return "invalid_resource_operation_kind";
    *result=NULL;catalog *c=calloc(1,sizeof(*c));if(!c)return "out_of_memory";
    sf_operation_source sorted[SF_RESOURCE_FILES];memcpy(sorted,input->scope,input->scope_count*sizeof(*sorted));
    const char *error=NULL;size_t total=0;
    for(size_t i=0;i<input->scope_count;i++){
        if(!logical_scope_path(sorted[i].path)||!sorted[i].source||!sf_digest_valid(sorted[i].sha256)||!sf_utf8(sorted[i].source,sorted[i].size)){
            error="invalid_resource_source";goto done;
        }
        if(sorted[i].size>SF_FLOW_SOURCE||sorted[i].size>SF_TRACE_TOTAL-total){error="resource_source_limit";goto done;}
        char hash[65];cbm_sha256_hex(sorted[i].source,sorted[i].size,hash);if(!eq(hash,sorted[i].sha256)){error="resource_source_hash_mismatch";goto done;}
        total+=sorted[i].size;
    }
    qsort(sorted,input->scope_count,sizeof(*sorted),order);
    for(size_t i=1;i<input->scope_count;i++)if(eq(sorted[i-1].path,sorted[i].path)){error="duplicate_resource_scope_path";goto done;}
    c->request=*input;c->request.scope=sorted;c->json=output;
    if(!c->request.mapping_format)c->request.mapping_format="all";
    if(!eq(c->request.mapping_format,"all")&&!eq(c->request.mapping_format,"xml")&&!eq(c->request.mapping_format,"annotation")){
        error="invalid_resource_mapping_format";goto done;
    }
    c->result=obj(c);c->coverage=arr(c);c->gaps=arr(c);c->attempts=arr(c);c->targets=arr(c);c->declarations=arr(c);
    identity(c);if(c->error){error=c->error;goto done;}
    error=load(c);if(error)goto done;
    build_tasks(c);size_t offset=0;if(!cursor_offset(c,&offset)){error="resource_query_mismatch";goto done;}
    size_t next=offset,checked=0,bytes=0;clock_t started=clock();bool cpu_stop=false;
    for(;next<c->ntasks&&checked<input->max_checks&&yyjson_mut_arr_size(c->targets)<input->limit&&!c->error;next++){
        clock_t now=clock();if(started==(clock_t)-1||now==(clock_t)-1||(double)(now-started)/CLOCKS_PER_SEC>5.0){cpu_stop=true;gap(c,"resource_page_cpu_budget");break;}
        task_info *t=&c->tasks[next];V *a=obj(c);num(c,a,"task_index",next);put(c,a,"request",inspection_request(c,t));
        V *target=evaluate(c,t,a);checked++;
        if(target){size_t size=0;char *raw=yyjson_mut_val_write(target,0,&size);if(!raw)c->error="out_of_memory";free(raw);
            if(size>PAGE_BYTES-bytes){gap(c,"resource_page_response_budget");break;}
            bytes+=size;add(c,c->targets,target);
        }add(c,c->attempts,a);
    }
    text(c,c->result,"schema",SF_RESOURCE_SCHEMA);text(c,c->result,"query_id",c->query_id);text(c,c->result,"snapshot_id",input->snapshot_id);
    text(c,c->result,"application_id",input->application_id);text(c,c->result,"scope_id",c->scope_id);
    text(c,c->result,"application_boundary","host_asserted_not_independently_verified");text(c,c->result,"mapping_format",c->request.mapping_format);
    /* Declarations are independent of call selection and operation filtering.
     * Nomination is only name/namespace evidence, never a resolved call edge. */
    size_t di,dn;V *dv;
    yyjson_mut_arr_foreach(c->declarations,di,dn,dv){
        size_t matches=0;
        for(size_t ti=0;ti<c->ntasks;ti++){
            task_info *t=&c->tasks[ti];file_info *mf=&c->files[c->methods[t->method].file];
            const char *path=t->xml==NONE?mf->source.path:c->files[t->xml].source.path;
            if(eq(word(dv,"method_or_statement"),c->calls[t->call].name)&&eq(word(dv,"namespace"),mf->namespace)&&
               eq(word(get(dv,"source"),"path"),path))matches++;
        }
        num(c,dv,"nominated_calls_in_scope",matches);
        text(c,dv,"call_link_status",matches?"nominations_require_per_call_checks":"no_call_nominated_in_selected_subset");
    }
    put(c,c->result,"declarations",c->declarations);
    text(c,c->result,"declaration_filter_semantics","unfiltered_structural_inventory_not_runtime_operations");
    put(c,c->result,"operations",c->targets);put(c,c->result,"attempts",c->attempts);put(c,c->result,"coverage",c->coverage);put(c,c->result,"gaps",c->gaps);
    text(c,c->result,"security_verdict","not_evaluated");text(c,c->result,"absence_semantics","no_negative_security_conclusion");
    text(c,c->result,"scope_semantics","selected_application_files_and_supported_MyBatis_calls_only");text(c,c->result,"runtime_mapping_precedence","not_resolved");
    flag(c,c->result,"catalog_truncated",c->catalog_truncated);flag(c,c->result,"file_analysis_gaps",c->file_gaps);
    size_t unresolved=0;size_t ai,an;V *av;
    yyjson_mut_arr_foreach(c->attempts,ai,an,av)if(!eq(word(av,"status"),"resource_operation")&&!eq(word(av,"status"),"filtered_operation_kind"))unresolved++;
    num(c,c->result,"unresolved_attempts_on_page",unresolved);
    V *page=obj(c);num(c,page,"offset",offset);num(c,page,"next_offset",next);num(c,page,"tasks_total",c->ntasks);
    flag(c,page,"enumeration_complete",next==c->ntasks&&!c->catalog_truncated);flag(c,page,"retryable_page_budget_stop",cpu_stop);
    if(next<c->ntasks){char cursor[96];snprintf(cursor,sizeof(cursor),"%s/%zu",c->query_id,next);text(c,page,"next_cursor",cursor);}
    else put(c,page,"next_cursor",yyjson_mut_null(output));
    put(c,c->result,"page",page);
    V *stats=obj(c);num(c,stats,"source_parse_attempts",c->parses);num(c,stats,"calls_cataloged",c->ncalls);num(c,stats,"methods_cataloged",c->nmethods);
    num(c,stats,"mapping_checks",checked);num(c,stats,"operations_returned",yyjson_mut_arr_size(c->targets));text(c,stats,"cache_scope","rebuild_catalog_per_page");
    num(c,stats,"local_flow_evaluations",0);num(c,stats,"return_summary_evaluations",0);put(c,c->result,"statistics",stats);
    text(c,c->result,"status",yyjson_mut_arr_size(c->targets)?"resource_operations_found":next<c->ntasks?"no_operations_on_this_page":"no_operations_in_examined_subset");
    size_t length=0;char *raw=yyjson_mut_val_write(c->result,0,&length);if(!raw)c->error="out_of_memory";free(raw);
    if(length>SF_MAX_OUTPUT)c->error="resource_output_limit";
    if(!c->error)*result=c->result;
done:
    if(input->parse_attempts)*input->parse_attempts+=c->parses;
    for(size_t i=0;i<c->nfiles;i++){if(c->files[i].entries)yyjson_doc_free(c->files[i].entries);if(c->files[i].tree)ts_tree_delete(c->files[i].tree);sf_document_free(&c->files[i].doc);}
    if(!error)error=c->error;
    free(c);return error;
}
