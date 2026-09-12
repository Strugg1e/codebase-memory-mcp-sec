#include "entry_points.h"
#include "foundation/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EP_ITEMS 64U
#define EP_VALUES 16U
#define EP_STRING 512U
#define EP_STEPS 200000U

typedef yyjson_mut_val V;
typedef struct {
    const sf_document *src;
    yyjson_mut_doc *json;
    V *entries, *gaps;
    const char *error;
    size_t steps, bytes, unsupported, entries_with_gaps;
    bool limited;
} C;
typedef struct { char items[EP_VALUES][EP_STRING]; size_t n; bool known, present; } strings;
typedef struct { TSNode node; const sf_fact *fact; } annotation;
typedef struct { annotation items[EP_ITEMS]; size_t n; bool limited; } annotations;
typedef struct { strings paths, methods, params, headers, consumes, produces; bool valid; } mapping;

static V *obj(C *c) { return yyjson_mut_obj(c->json); }
static V *arr(C *c) { return yyjson_mut_arr(c->json); }
static V *txt(C *c, const char *s) { return yyjson_mut_strcpy(c->json, s); }
static void put(C *c, V *o, const char *k, V *v) {
    V *key=txt(c,k);
    if (!o || !key || !v || !yyjson_mut_obj_put(o,key,v)) c->error="out_of_memory";
}
static void text(C *c,V *o,const char *k,const char *s) { put(c,o,k,txt(c,s)); }
static void num(C *c,V *o,const char *k,size_t n) { put(c,o,k,yyjson_mut_uint(c->json,n)); }
static void flag(C *c,V *o,const char *k,bool b) { put(c,o,k,yyjson_mut_bool(c->json,b)); }
static void add(C *c,V *a,V *v) { if (!a || !v || !yyjson_mut_arr_append(a,v)) c->error="out_of_memory"; }
static void gap(C *c,const char *reason) {
    size_t i,n; V *v;
    yyjson_mut_arr_foreach(c->gaps,i,n,v) if (!strcmp(yyjson_mut_get_str(v),reason)) return;
    if (yyjson_mut_arr_size(c->gaps)<EP_ITEMS) add(c,c->gaps,txt(c,reason)); else c->limited=true;
}
static bool step(C *c) { if (++c->steps>EP_STEPS) { c->limited=true; return false; } return true; }
static bool eq(const char *a,const char *b) { return a && b && !strcmp(a,b); }
static bool comment(TSNode n) { return sf_node_is(n,"line_comment") || sf_node_is(n,"block_comment"); }
static TSNode child(TSNode n,const char *kind) {
    if (ts_node_is_null(n)) return (TSNode){0};
    TSTreeCursor cur=ts_tree_cursor_new(n); TSNode result={0};
    if (ts_tree_cursor_goto_first_child(&cur)) do {
        TSNode item=ts_tree_cursor_current_node(&cur);
        if (sf_node_is(item,kind)) { result=item; break; }
    } while (ts_tree_cursor_goto_next_sibling(&cur));
    ts_tree_cursor_delete(&cur); return result;
}
static const sf_fact *fact_at(C *c,TSNode n,const char *kind) {
    if (ts_node_is_null(n)) return NULL;
    uint32_t start=ts_node_start_byte(n),end=ts_node_end_byte(n); size_t lo=0,hi=c->src->count;
    while (lo<hi) { size_t mid=lo+(hi-lo)/2; if(c->src->facts[mid].span.start<start)lo=mid+1;else hi=mid; }
    for (;lo<c->src->count && c->src->facts[lo].span.start==start;lo++) {
        const sf_fact *f=&c->src->facts[lo];
        if(f->span.end==end && eq(f->kind,kind))return f;
    }
    return NULL;
}
static V *reference(C *c,TSNode n) {
    if (ts_node_is_null(n)) return yyjson_mut_null(c->json);
    size_t a=ts_node_start_byte(n),b=ts_node_end_byte(n);
    V *v=obj(c);
    if (a>b || b>c->src->source_size) { c->error="invalid_entry_span"; return v; }
    size_t length=b-a,show=length>SF_PREVIEW_BYTES?SF_PREVIEW_BYTES:length;
    while(show && show<length && ((unsigned char)c->src->source[a+show]&0xc0U)==0x80U)show--;
    text(c,v,"path",c->src->path);text(c,v,"sha256",c->src->source_hash);
    num(c,v,"start_byte",a);num(c,v,"end_byte",b);
    num(c,v,"start_line",ts_node_start_point(n).row+1);num(c,v,"end_line",ts_node_end_point(n).row+1);
    put(c,v,"text_prefix",yyjson_mut_strncpy(c->json,c->src->source+a,show));
    flag(c,v,"text_truncated",show<length);return v;
}
static V *node_text(C *c,TSNode n) {
    char buffer[EP_STRING];
    if(sf_node_text(c->src,n,buffer,sizeof(buffer)))return txt(c,buffer);
    gap(c,"identifier_not_represented");return yyjson_mut_null(c->json);
}
static annotations annotations_at(C *c,TSNode owner) {
    annotations out={0}; TSNode mods=child(owner,"modifiers");
    if(ts_node_is_null(mods))return out;
    TSTreeCursor cur=ts_tree_cursor_new(mods);
    if(ts_tree_cursor_goto_first_child(&cur))do {
        TSNode n=ts_tree_cursor_current_node(&cur);
        if(!step(c))break;
        if(!sf_node_is(n,"annotation") && !sf_node_is(n,"marker_annotation"))continue;
        if(out.n>=EP_ITEMS){out.limited=true;gap(c,"annotation_limit");break;}
        out.items[out.n++]=(annotation){n,fact_at(c,n,"annotation")};
    }while(ts_tree_cursor_goto_next_sibling(&cur));
    ts_tree_cursor_delete(&cur);return out;
}
static bool is_mapping(const annotation *a) {
    return a->fact && eq(a->fact->framework,"spring-mvc") &&
        (eq(a->fact->role,"route_declaration") || eq(a->fact->role,"route_prefix_declaration"));
}
static V *annotation_json(C *c,annotation a,const char *level) {
    V *v=obj(c);put(c,v,"source",reference(c,a.node));text(c,v,"level",level);
    if(a.fact){
        char id[65];sf_fact_id(c->src,a.fact,id);text(c,v,"fact_id",id);
        if(a.fact->framework)text(c,v,"framework",a.fact->framework);
        if(a.fact->role)text(c,v,"role",a.fact->role);
        if(a.fact->input_kind)text(c,v,"input_kind",a.fact->input_kind);
        if(a.fact->control_phase)text(c,v,"control_phase",a.fact->control_phase);
    }
    flag(c,v,"runtime_effect_verified",false);return v;
}
static TSNode attribute(C *c,TSNode node,const char *key,bool positional,bool *valid) {
    TSNode args=sf_field(node,"arguments"),result={0};
    if(ts_node_is_null(args))return result;
    TSTreeCursor cur=ts_tree_cursor_new(args);
    if(ts_tree_cursor_goto_first_child(&cur))do{
        TSNode n=ts_tree_cursor_current_node(&cur); if(!step(c)){*valid=false;break;}
        if(!ts_node_is_named(n)||comment(n))continue;
        bool matches=false;TSNode value=n;
        if(sf_node_is(n,"element_value_pair")){
            char name[64];matches=sf_node_text(c->src,sf_field(n,"key"),name,sizeof(name)) && !strcmp(name,key);
            value=sf_field(n,"value");
        }else matches=positional;
        if(matches){if(!ts_node_is_null(result)){*valid=false;gap(c,"duplicate_annotation_attribute");}result=value;}
    }while(ts_tree_cursor_goto_next_sibling(&cur));
    ts_tree_cursor_delete(&cur);return result;
}
static bool string_value(C *c,TSNode n,char out[EP_STRING]) {
    char raw[EP_STRING];
    if(!sf_node_is(n,"string_literal") || !sf_node_text(c->src,n,raw,sizeof(raw)))return false;
    size_t len=strlen(raw);
    if(len<2 || raw[0]!='"' || raw[len-1]!='"')return false;
    for(size_t i=1;i+1<len;i++)if(raw[i]=='\\' || (unsigned char)raw[i]<32)return false;
    memcpy(out,raw+1,len-2);out[len-2]=0;return true;
}
static strings string_values(C *c,TSNode n) {
    strings r={.known=true,.present=!ts_node_is_null(n)};
    if(!r.present)return r;
    if(!sf_node_is(n,"element_value_array_initializer")){
        r.known=string_value(c,n,r.items[0]);if(r.known)r.n=1;return r;
    }
    TSTreeCursor cur=ts_tree_cursor_new(n);
    if(ts_tree_cursor_goto_first_child(&cur))do{
        TSNode v=ts_tree_cursor_current_node(&cur);
        if(!step(c)){r.known=false;break;}
        if(!ts_node_is_named(v)||comment(v))continue;
        if(r.n>=EP_VALUES){r.known=false;gap(c,"mapping_value_limit");break;}
        if(!string_value(c,v,r.items[r.n]))r.known=false;else r.n++;
    }while(ts_tree_cursor_goto_next_sibling(&cur));
    ts_tree_cursor_delete(&cur);return r;
}
static V *strings_json(C *c,const strings *s) {
    if(!s->known)return yyjson_mut_null(c->json);
    V *out=arr(c);for(size_t i=0;i<s->n;i++)add(c,out,txt(c,s->items[i]));return out;
}
static bool strings_equal(const strings *a,const strings *b) {
    if(!a->known||!b->known||a->n!=b->n)return false;
    for(size_t i=0;i<a->n;i++)if(strcmp(a->items[i],b->items[i]))return false;
    return true;
}
static void unique(C *c,V *a,const char *s) {
    size_t i,n;V *v;yyjson_mut_arr_foreach(a,i,n,v)if(eq(yyjson_mut_get_str(v),s))return;
    add(c,a,txt(c,s));
}
static bool request_method(C *c,TSNode n,char out[EP_STRING]) {
    char value[EP_STRING];if(!sf_node_text(c->src,n,value,sizeof(value)))return false;
    const char *prefix="org.springframework.web.bind.annotation.RequestMethod.";
    const char *name=NULL;
    if(!strncmp(value,prefix,strlen(prefix)))name=value+strlen(prefix);
    else if(!strncmp(value,"RequestMethod.",14)){
        bool found=false,conflict=false;
        for(size_t i=0;i<c->src->count;i++){
            if(!step(c))return false;
            const sf_fact *f=&c->src->facts[i];
            if(eq(f->kind,"import_declaration")){
                size_t size=f->span.end-f->span.start;
                if(size>=sizeof(value))continue;
                char raw[EP_STRING];memcpy(raw,c->src->source+f->span.start,size);raw[size]=0;
                if(strstr(raw,"RequestMethod;") && !strstr(raw,"import static")){
                    if(strstr(raw,"org.springframework.web.bind.annotation.RequestMethod;"))found=true;else conflict=true;
                }
            }
            if(f->has_name && (eq(f->kind,"class_declaration")||eq(f->kind,"enum_declaration")||eq(f->kind,"interface_declaration")||eq(f->kind,"record_declaration")) &&
                f->name.end-f->name.start==13 && !memcmp(c->src->source+f->name.start,"RequestMethod",13))conflict=true;
        }
        if(!found||conflict)return false;
        /* value was not modified by the import checks. */
        name=value+14;
    }
    static const char *const allowed[]={"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","TRACE"};
    for(size_t i=0;name && i<sizeof(allowed)/sizeof(allowed[0]);i++)if(!strcmp(name,allowed[i])){strcpy(out,name);return true;}
    return false;
}
static strings methods(C *c,annotation a,TSNode n) {
    strings r={.known=true,.present=!ts_node_is_null(n)};
    if(a.fact && a.fact->http_method && !eq(a.fact->http_method,"DECLARED_IN_ARGUMENTS")){
        strcpy(r.items[0],a.fact->http_method);r.n=1;r.present=true;return r;
    }
    if(!r.present)return r;
    if(!sf_node_is(n,"element_value_array_initializer")){r.known=request_method(c,n,r.items[0]);r.n=r.known?1:0;return r;}
    TSTreeCursor cur=ts_tree_cursor_new(n);
    if(ts_tree_cursor_goto_first_child(&cur))do{
        TSNode v=ts_tree_cursor_current_node(&cur);if(!ts_node_is_named(v)||comment(v))continue;
        if(!step(c)||r.n>=EP_VALUES){r.known=false;break;}
        if(!request_method(c,v,r.items[r.n]))r.known=false;else r.n++;
    }while(ts_tree_cursor_goto_next_sibling(&cur));
    ts_tree_cursor_delete(&cur);return r;
}
static bool known_attributes(C *c,annotation a) {
    TSNode args=sf_field(a.node,"arguments");if(ts_node_is_null(args))return true;
    bool valid=true;TSTreeCursor cur=ts_tree_cursor_new(args);
    if(ts_tree_cursor_goto_first_child(&cur))do{
        TSNode n=ts_tree_cursor_current_node(&cur);if(!step(c)){valid=false;break;}
        if(!sf_node_is(n,"element_value_pair"))continue;
        char key[64];bool known=false;
        if(sf_node_text(c->src,sf_field(n,"key"),key,sizeof(key))){
            static const char *const allowed[]={"path","value","params","headers","consumes","produces","name"};
            for(size_t i=0;i<sizeof(allowed)/sizeof(allowed[0]);i++)if(eq(key,allowed[i]))known=true;
            if(eq(key,"method")&&eq(a.fact->http_method,"DECLARED_IN_ARGUMENTS"))known=true;
        }
        if(!known){valid=false;gap(c,"mapping_attribute_not_modeled");}
    }while(ts_tree_cursor_goto_next_sibling(&cur));
    ts_tree_cursor_delete(&cur);return valid;
}
static mapping parse_mapping(C *c,annotation a) {
    mapping m={.valid=true};bool valid=known_attributes(c,a);
    TSNode p=attribute(c,a.node,"path",false,&valid),v=attribute(c,a.node,"value",true,&valid);
    strings ps=string_values(c,p),vs=string_values(c,v);
    m.paths=ps.present?ps:vs;
    if(ps.present&&vs.present&&!strings_equal(&ps,&vs)){m.paths.known=false;gap(c,"path_value_alias_conflict");}
    m.methods=methods(c,a,attribute(c,a.node,"method",false,&valid));
    m.params=string_values(c,attribute(c,a.node,"params",false,&valid));
    m.headers=string_values(c,attribute(c,a.node,"headers",false,&valid));
    m.consumes=string_values(c,attribute(c,a.node,"consumes",false,&valid));
    m.produces=string_values(c,attribute(c,a.node,"produces",false,&valid));
    m.valid=valid;
    if(!valid){m.paths.known=false;m.methods.known=false;}
    if(!m.paths.known)gap(c,"path_expression_not_resolved");
    if(!m.methods.known)gap(c,"http_method_expression_not_resolved");
    if(!m.params.known||!m.headers.known||!m.consumes.known||!m.produces.known)gap(c,"request_condition_expression_not_resolved");
    return m;
}
static V *mapping_json(C *c,annotation a,const mapping *m,const char *level) {
    V *v=annotation_json(c,a,level);
    put(c,v,"paths",strings_json(c,&m->paths));put(c,v,"methods",strings_json(c,&m->methods));
    put(c,v,"params",strings_json(c,&m->params));put(c,v,"headers",strings_json(c,&m->headers));
    put(c,v,"consumes",strings_json(c,&m->consumes));put(c,v,"produces",strings_json(c,&m->produces));return v;
}
static bool plain_path(const char *s) {
    if(strstr(s,"${")||strstr(s,"#{")||strpbrk(s,"*?:")||strstr(s,"//"))return false;
    unsigned braces=0;for(;*s;s++){if(*s=='{'){if(braces++)return false;}else if(*s=='}'){if(!braces)return false;braces--;}}
    return braces==0;
}
static V *paths(C *c,const strings *base,const strings *method) {
    V *r=arr(c);
    if(!base->known||!method->known)return r;
    size_t an=base->n?base->n:1,bn=method->n?method->n:1;
    if(an*bn>EP_ITEMS){gap(c,"path_product_limit");return r;}
    /* Reject the entire normalized set on a dynamic alternative; keep raw mappings. */
    for(size_t a=0;a<an;a++)for(size_t b=0;b<bn;b++)if(!plain_path(base->n?base->items[a]:"")||!plain_path(method->n?method->items[b]:"")){
        gap(c,"path_pattern_or_placeholder_not_composed");return r;
    }
    for(size_t a=0;a<an;a++)for(size_t b=0;b<bn;b++){
        const char *x=base->n?base->items[a]:"",*y=method->n?method->items[b]:"";
        char out[EP_STRING*2+4],left[EP_STRING+2],right[EP_STRING+2];
        snprintf(left,sizeof(left),"%s%s",*x&&*x!='/'?"/":"",x);
        snprintf(right,sizeof(right),"%s%s",*y&&*y!='/'?"/":"",y);
        if(!*left&&!*right){unique(c,r,"");unique(c,r,"/");continue;}
        size_t len=strlen(left);
        snprintf(out,sizeof(out),"%s%s",left,len&&left[len-1]=='/'&&right[0]=='/'?right+1:right);
        unique(c,r,out);
    }
    return r;
}
static V *combined_strings(C *c,const strings *a,const strings *b,bool override) {
    if(!b->known||(!override&& !a->known)||(override&&!b->n&&!a->known))return yyjson_mut_null(c->json);
    V *r=arr(c);if(!override||!b->n)for(size_t i=0;i<a->n;i++)unique(c,r,a->items[i]);
    for(size_t i=0;i<b->n;i++)unique(c,r,b->items[i]);
    return r;
}
static void attach_annotations(C *c,annotations a,const char *level,V *controls,V *other,bool *controller) {
    for(size_t i=0;i<a.n;i++){
        annotation x=a.items[i];const sf_fact *f=x.fact;if(is_mapping(&x))continue;
        if(f&&eq(f->role,"controller_declaration")){*controller=true;add(c,other,annotation_json(c,x,level));}
        else if(f&&(eq(f->framework,"spring-security")||eq(f->framework,"jakarta-security")||eq(f->framework,"bean-validation")))add(c,controls,annotation_json(c,x,level));
        else {add(c,other,annotation_json(c,x,level));gap(c,"additional_annotation_semantics_not_modeled");}
    }
}
static V *parameters(C *c,TSNode method) {
    V *out=arr(c);TSNode ps=sf_field(method,"parameters");
    if(ts_node_is_null(ps)){gap(c,"parameters_not_available");return out;}
    TSTreeCursor cur=ts_tree_cursor_new(ps);size_t index=0;
    if(ts_tree_cursor_goto_first_child(&cur))do{
        TSNode p=ts_tree_cursor_current_node(&cur);if(!ts_node_is_named(p)||comment(p))continue;
        if(!step(c)||index>=EP_ITEMS){gap(c,"parameter_limit");break;}
        V *v=obj(c),*decls=arr(c);num(c,v,"index",index++);put(c,v,"source",reference(c,p));
        put(c,v,"name",node_text(c,sf_field(p,"name")));put(c,v,"type",reference(c,sf_field(p,"type")));
        annotations a=annotations_at(c,p);bool input=false;
        for(size_t i=0;i<a.n;i++){
            annotation x=a.items[i];add(c,decls,annotation_json(c,x,"parameter"));
            if(x.fact && eq(x.fact->role,"request_input_declaration"))input=true;
        }
        put(c,v,"declarations",decls);text(c,v,"binding_status",input?"explicit_declaration":"implicit_or_custom_binding_not_modeled");
        flag(c,v,"input_trust_verified",false);add(c,out,v);
    }while(ts_tree_cursor_goto_next_sibling(&cur));
    ts_tree_cursor_delete(&cur);return out;
}
static bool visit(TSNode method,void *opaque) {
    C *c=opaque;if(!step(c)||c->error)return false;
    if(!sf_node_is(method,"method_declaration"))return true;
    annotations ma=annotations_at(c,method);size_t mn=0;annotation selected={0};
    for(size_t i=0;i<ma.n;i++)if(is_mapping(&ma.items[i])){mn++;selected=ma.items[i];}
    if(!mn)return true;
    if(yyjson_mut_arr_size(c->entries)>=SF_ENTRY_MAX_RECORDS){c->limited=true;return false;}
    TSNode parent=ts_node_parent(method),cl=ts_node_parent(parent);
    V *file_gaps=c->gaps; c->gaps=arr(c);V *entry=obj(c),*mapping_list=arr(c),*controls=arr(c),*other=arr(c);
    const sf_fact *mf=fact_at(c,method,"method_declaration");
    if(!mf){gap(c,"method_identity_missing");c->limited=true;c->gaps=file_gaps;return false;}
    char method_id[65],entry_id[65],identity[256];sf_fact_id(c->src,mf,method_id);
    int len=snprintf(identity,sizeof(identity),"%s\n%s\n%s",SF_ENTRY_SCHEMA,c->src->analysis_id,method_id);
    cbm_sha256_hex(identity,(size_t)len,entry_id);text(c,entry,"entry_id",entry_id);
    text(c,entry,"framework","spring-mvc");text(c,entry,"path",c->src->path);text(c,entry,"analysis_id",c->src->analysis_id);
    put(c,entry,"handler",node_text(c,sf_field(method,"name")));put(c,entry,"handler_source",reference(c,method));
    put(c,entry,"class_name",node_text(c,sf_field(cl,"name")));put(c,entry,"class_source",reference(c,cl));
    V *anchor=obj(c);text(c,anchor,"path",c->src->path);text(c,anchor,"analysis_id",c->src->analysis_id);text(c,anchor,"fact_id",method_id);
    put(c,entry,"handler_anchor",anchor);
    V *q=obj(c);text(c,q,"path",c->src->path);text(c,q,"kind","call_site");text(c,q,"enclosing_id",method_id);text(c,q,"expect_analysis",c->src->analysis_id);put(c,entry,"call_query",q);
    bool structure=sf_node_is(parent,"class_body")&&sf_node_is(cl,"class_declaration")&&sf_node_is(ts_node_parent(cl),"program");
    if(!structure){gap(c,"class_structure_not_modeled");c->unsupported++;}
    if(!ts_node_is_null(sf_field(cl,"superclass"))||!ts_node_is_null(sf_field(cl,"interfaces")))gap(c,"inherited_mappings_and_controls_not_resolved");
    if(ts_node_is_null(sf_field(method,"body")))gap(c,"method_body_not_available");
    annotations ca=annotations_at(c,cl);size_t cn=0;annotation cs={0};
    for(size_t i=0;i<ca.n;i++)if(is_mapping(&ca.items[i])){cn++;cs=ca.items[i];}
    mapping base={.valid=true,.paths={.known=true},.methods={.known=true},.params={.known=true},.headers={.known=true},.consumes={.known=true},.produces={.known=true}};
    mapping met=base;
    for(size_t i=0;i<ca.n;i++)if(is_mapping(&ca.items[i])){mapping m=parse_mapping(c,ca.items[i]);add(c,mapping_list,mapping_json(c,ca.items[i],&m,"class"));}
    for(size_t i=0;i<ma.n;i++)if(is_mapping(&ma.items[i])){mapping m=parse_mapping(c,ma.items[i]);add(c,mapping_list,mapping_json(c,ma.items[i],&m,"method"));}
    if(cn==1)base=parse_mapping(c,cs);
    if(mn==1)met=parse_mapping(c,selected);
    bool unique_mapping=cn<=1&&mn==1&&!ma.limited&&!ca.limited;
    if(cn==1 && !eq(cs.fact->http_method,"DECLARED_IN_ARGUMENTS")){
        unique_mapping=false;gap(c,"method_specific_mapping_on_type");
    }
    if(!unique_mapping)gap(c,"multiple_mapping_declarations_not_selected");
    V *path_values=arr(c),*conditions=obj(c);
    if(unique_mapping && structure){path_values=paths(c,&base.paths,&met.paths);
        put(c,conditions,"methods",combined_strings(c,&base.methods,&met.methods,false));
        put(c,conditions,"params",combined_strings(c,&base.params,&met.params,false));
        put(c,conditions,"headers",combined_strings(c,&base.headers,&met.headers,false));
        put(c,conditions,"consumes",combined_strings(c,&base.consumes,&met.consumes,true));
        put(c,conditions,"produces",combined_strings(c,&base.produces,&met.produces,true));
    }
    bool media_header=false;
    const strings *hs[2]={&base.headers,&met.headers};
    for(size_t h=0;h<2;h++)for(size_t i=0;i<hs[h]->n;i++){
        char lower[EP_STRING];size_t j=0;
        for(;hs[h]->items[i][j] && j+1<sizeof(lower);j++){
            unsigned char ch=(unsigned char)hs[h]->items[i][j];lower[j]=(char)(ch>='A'&&ch<='Z'?ch+('a'-'A'):ch);
        }
        lower[j]=0;
        if(strstr(lower,"content-type")||strstr(lower,"accept"))media_header=true;
    }
    if(media_header){
        gap(c,"media_type_header_conditions_not_normalized");
        put(c,conditions,"headers",yyjson_mut_null(c->json));
        put(c,conditions,"consumes",yyjson_mut_null(c->json));
        put(c,conditions,"produces",yyjson_mut_null(c->json));
    }
    text(c,conditions,"semantics","declarative_union_methods_conjunction_params_headers_method_media_override");
    flag(c,conditions,"head_options_expanded",false);flag(c,conditions,"request_matching_executed",false);
    put(c,entry,"declared_paths",path_values);put(c,entry,"conditions",conditions);put(c,entry,"mapping_declarations",mapping_list);
    bool controller=false;attach_annotations(c,ca,"class",controls,other,&controller);bool ignored=false;attach_annotations(c,ma,"method",controls,other,&ignored);
    text(c,entry,"controller_marker",controller?"direct_declaration":"not_observed");
    if(!controller)gap(c,"controller_registration_not_established");
    put(c,entry,"inputs",parameters(c,method));put(c,entry,"control_declarations",controls);put(c,entry,"other_annotations",other);
    bool has_gaps=yyjson_mut_arr_size(c->gaps)>0;
    text(c,entry,"status",yyjson_mut_arr_size(c->gaps)?"candidate_with_gaps":"declarative_candidate");
    put(c,entry,"gaps",c->gaps);flag(c,entry,"runtime_registration_verified",false);text(c,entry,"security_control_effectiveness","not_evaluated");
    text(c,entry,"authorization","not_evaluated");text(c,entry,"public_url","not_resolved");
    c->gaps=file_gaps;size_t bytes=0;char *raw=yyjson_mut_val_write(entry,0,&bytes);
    if(!raw){c->error="out_of_memory";return false;}free(raw);
    if(bytes>SF_ENTRY_MAX_BYTES-c->bytes){c->limited=true;return false;}
    c->bytes+=bytes;add(c,c->entries,entry);if(has_gaps&&!c->error)c->entries_with_gaps++;return !c->error;
}
const char *sf_spring_entry_points(const sf_document *source,TSNode root,yyjson_doc **out) {
    *out=NULL;if(!source||!eq(source->language,"java")||ts_node_is_null(root))return "unsupported_entry_language";
    C c={.src=source,.json=yyjson_mut_doc_new(NULL)};if(!c.json)return "out_of_memory";
    c.entries=arr(&c);c.gaps=arr(&c);V *top=obj(&c),*coverage=obj(&c);size_t nodes=0;
    bool walked=sf_walk(root,visit,&c,&nodes);
    if(source->parse_has_error)gap(&c,"syntax_errors");
    if(!source->framework_analysis_complete)gap(&c,"framework_binding_incomplete");
    if(!source->traversal_complete)gap(&c,"fact_traversal_incomplete");
    if(!walked||c.limited)gap(&c,"entry_budget_exhausted");
    text(&c,top,"schema",SF_ENTRY_SCHEMA);put(&c,top,"entries",c.entries);
    put(&c,coverage,"gaps",c.gaps);flag(&c,coverage,"truncated",!walked||c.limited);
    flag(&c,coverage,"syntax_complete",!source->parse_has_error&&source->traversal_complete&&source->framework_analysis_complete&&walked&&!c.limited);
    num(&c,coverage,"entries_with_gaps",c.entries_with_gaps);
    num(&c,coverage,"steps",c.steps);num(&c,coverage,"entry_count",yyjson_mut_arr_size(c.entries));
    text(&c,coverage,"scope","direct_spring_annotations_only");flag(&c,coverage,"repository_completeness",false);
    put(&c,top,"coverage",coverage);yyjson_mut_doc_set_root(c.json,top);
    if(!c.error){*out=yyjson_mut_doc_imut_copy(c.json,NULL);if(!*out)c.error="out_of_memory";}
    yyjson_mut_doc_free(c.json);return c.error;
}
