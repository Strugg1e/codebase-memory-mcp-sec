/* Bounded Java SecurityFilterChain declarations and conditional selection.
 * Not a Spring container emulator, authorization verdict, or URL router. */
#include "entry_security.h"
#include "foundation/sha256.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECORDS 64U
#define RULES 32U
#define PATTERNS 8U
#define STRING 512U
#define CALLS 128U
#define STEPS 200000U
#define CHAIN_TYPE "org.springframework.security.web.SecurityFilterChain"
#define HTTP_TYPE "org.springframework.security.config.annotation.web.builders.HttpSecurity"
#define WEB_TYPE "org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer"
#define ANT_TYPE "org.springframework.security.web.util.matcher.AntPathRequestMatcher"
typedef yyjson_mut_val V;
typedef enum { NO=0, YES=1, UNKNOWN=2 } truth;
typedef struct { char path[STRING], method[32]; bool explicit_ant; } pattern;
typedef struct { pattern items[PATTERNS]; size_t n; bool any, unknown, ambiguous_overload; V *json; } matcher;
typedef struct { matcher match; V *json; } rule;
typedef struct {
    char id[65], name[128]; matcher match; rule rules[RULES]; size_t n;
    int order; bool order_known, ignored, structural_gap, rules_gap, auth_seen, built, any_seen;
    V *json, *gaps, *rule_list, *other;
} record;
typedef struct {
    yyjson_mut_doc *json; V *root, *records, *coverage, *gaps;
    sf_document *src; TSNode tree_root; record *current;
    record *all[RECORDS]; size_t n, steps; bool incomplete;
    const char *error, *method, *path; bool ant_strings;
} C;
static bool eq(const char *a,const char *b){return a&&b&&!strcmp(a,b);}
static V *obj(C *c){return yyjson_mut_obj(c->json);}
static V *arr(C *c){return yyjson_mut_arr(c->json);}
static V *txt(C *c,const char *s){return yyjson_mut_strcpy(c->json,s);}
static void put(C *c,V *o,const char *k,V *v){V *key=txt(c,k);if(!o||!key||!v||!yyjson_mut_obj_put(o,key,v))c->error="out_of_memory";}
static void text(C *c,V *o,const char *k,const char *v){put(c,o,k,txt(c,v));}
static void flag(C *c,V *o,const char *k,bool v){put(c,o,k,yyjson_mut_bool(c->json,v));}
static void num(C *c,V *o,const char *k,size_t n){put(c,o,k,yyjson_mut_uint(c->json,n));}
static void add(C *c,V *a,V *v){if(!a||!v||!yyjson_mut_arr_append(a,v))c->error="out_of_memory";}
static void unique(C *c,V *a,const char *s){size_t i,n;V *v;yyjson_mut_arr_foreach(a,i,n,v)if(eq(yyjson_mut_get_str(v),s))return;if(yyjson_mut_arr_size(a)<64)add(c,a,txt(c,s));else c->incomplete=true;}
static void gap(C *c,const char *s){unique(c,c->current?c->current->gaps:c->gaps,s);}
static bool step(C *c){if(++c->steps>STEPS){c->incomplete=true;return false;}return true;}
static bool kind(TSNode n,const char *s){return !ts_node_is_null(n)&&sf_node_is(n,s);}
static bool comment(TSNode n){return kind(n,"line_comment")||kind(n,"block_comment");}
static bool spells(C *c,TSNode n,const char *s){char b[STRING];return sf_node_text(c->src,n,b,sizeof(b))&&eq(b,s);}
static TSNode child(TSNode n,const char *k){
    if(ts_node_is_null(n))return (TSNode){0};
    TSTreeCursor cur=ts_tree_cursor_new(n);TSNode out={0};
    if(ts_tree_cursor_goto_first_child(&cur))do{TSNode x=ts_tree_cursor_current_node(&cur);if(kind(x,k)){out=x;break;}}while(ts_tree_cursor_goto_next_sibling(&cur));
    ts_tree_cursor_delete(&cur);return out;
}
static size_t children(C *c,TSNode n,TSNode *out,size_t max,bool *ok){
    size_t used=0;if(ts_node_is_null(n))return 0;TSTreeCursor cur=ts_tree_cursor_new(n);
    if(ts_tree_cursor_goto_first_child(&cur))do{
        TSNode x=ts_tree_cursor_current_node(&cur);if(!step(c)){*ok=false;break;}
        if(!ts_node_is_named(x)||comment(x))continue;
        if(used==max){*ok=false;break;}out[used++]=x;
    }while(ts_tree_cursor_goto_next_sibling(&cur));
    ts_tree_cursor_delete(&cur);return used;
}
static V *ref(C *c,TSNode n){
    if(ts_node_is_null(n))return yyjson_mut_null(c->json);
    size_t a=ts_node_start_byte(n),b=ts_node_end_byte(n);V *v=obj(c);
    if(a>b||b>c->src->source_size){c->error="invalid_security_span";return v;}
    size_t len=b-a,show=len>SF_PREVIEW_BYTES?SF_PREVIEW_BYTES:len;
    while(show&&show<len&&((unsigned char)c->src->source[a+show]&0xc0U)==0x80U)show--;
    text(c,v,"path",c->src->path);text(c,v,"sha256",c->src->source_hash);
    num(c,v,"start_byte",a);num(c,v,"end_byte",b);
    put(c,v,"text_prefix",yyjson_mut_strncpy(c->json,c->src->source+a,show));flag(c,v,"text_truncated",show<len);return v;
}
/* Exact explicit imports only. Local type declarations invalidate short names. */
static bool type_is(C *c,TSNode n,const char *full){
    char raw[STRING];if(!sf_node_text(c->src,n,raw,sizeof(raw)))return false;
    if(strchr(raw,'.'))return eq(raw,full);
    const char *leaf=strrchr(full,'.');leaf=leaf?leaf+1:full;if(!eq(raw,leaf))return false;
    size_t hits=0;bool correct=false,ok=true;TSNode top[256];size_t count=children(c,c->tree_root,top,256,&ok);if(!ok)return false;
    for(size_t i=0;i<c->src->count;i++){
        if(!step(c)){return false;}
        const sf_fact *f=&c->src->facts[i];
        if(f->has_name&&(eq(f->kind,"class_declaration")||eq(f->kind,"interface_declaration")||eq(f->kind,"enum_declaration")||eq(f->kind,"record_declaration")||eq(f->kind,"annotation_type_declaration"))&&
            f->name.end-f->name.start==strlen(raw)&&!memcmp(c->src->source+f->name.start,raw,strlen(raw)))return false;
    }
    for(size_t i=0;i<count;i++)if(kind(top[i],"import_declaration")){
        if(!ts_node_is_null(child(top[i],"static"))||!ts_node_is_null(child(top[i],"asterisk")))continue;
        char imp[STRING];if(!sf_node_text(c->src,child(top[i],"scoped_identifier"),imp,sizeof(imp)))continue;
        const char *end=strrchr(imp,'.');if(end&&eq(end+1,raw)){hits++;correct=eq(imp,full);}
    }
    return hits==1&&correct;
}
static TSNode annotation(C *c,TSNode owner,const char *full,bool *ok){
    TSNode items[64],found={0};size_t n=children(c,child(owner,"modifiers"),items,64,ok);
    for(size_t i=0;i<n;i++)if((kind(items[i],"annotation")||kind(items[i],"marker_annotation"))&&type_is(c,sf_field(items[i],"name"),full)){
        if(!ts_node_is_null(found)){*ok=false;}
        found=items[i];
    }
    return found;
}
static TSNode attr(C *c,TSNode ann,const char *key,bool *ok){
    TSNode items[16],out={0};size_t n=children(c,sf_field(ann,"arguments"),items,16,ok);
    for(size_t i=0;i<n;i++){
        TSNode x=items[i];if(kind(x,"element_value_pair")){if(!spells(c,sf_field(x,"key"),key))continue;x=sf_field(x,"value");}
        else if(!eq(key,"value"))continue;
        if(!ts_node_is_null(out)){*ok=false;}
        out=x;
    }return out;
}
static bool string(C *c,TSNode n,char out[STRING]){
    char raw[STRING];if(!kind(n,"string_literal")||!sf_node_text(c->src,n,raw,sizeof(raw)))return false;
    size_t len=strlen(raw);if(len<2||raw[0]!='"'||raw[len-1]!='"')return false;
    for(size_t i=1;i+1<len;i++)if(raw[i]=='\\'||(unsigned char)raw[i]<32)return false;
    memcpy(out,raw+1,len-2);out[len-2]=0;return true;
}
static bool http_method(const char *s){return eq(s,"GET")||eq(s,"HEAD")||eq(s,"POST")||eq(s,"PUT")||eq(s,"PATCH")||eq(s,"DELETE")||eq(s,"OPTIONS")||eq(s,"TRACE");}
static bool method_enum(C *c,TSNode n,char out[32]){
    if(!kind(n,"field_access")||!type_is(c,sf_field(n,"object"),"org.springframework.http.HttpMethod"))return false;
    if(!sf_node_text(c->src,sf_field(n,"field"),out,32)){return false;}
    return http_method(out);
}
/* Only exact paths and a terminal slash-double-star are evaluated. No silent MVC/regex fallback. */
static bool safe_path(const char *s,bool pattern_mode){
    if(!s||s[0]!='/'||strlen(s)>=STRING)return false;
    if(strstr(s,"//")||strstr(s,"/./")||strstr(s,"/../")||eq(s,"/.")||eq(s,"/.."))return false;
    for(size_t i=0;s[i];i++){
        unsigned char b=(unsigned char)s[i];if(b<32||b==127||strchr("\\%;?#{}",b))return false;
        if(b=='*'&&(!pattern_mode||i==0||s[i-1]!='/'||strcmp(s+i,"**")))return false;
        if(b=='*')break;
    }return true;
}
static truth path_match(const char *pattern_text,const char *path){
    if(!safe_path(pattern_text,true)||!safe_path(path,false))return UNKNOWN;
    size_t n=strlen(pattern_text);
    if(n>=3&&eq(pattern_text+n-3,"/**")){size_t base=n-3;return !strncmp(pattern_text,path,base)&&(path[base]==0||path[base]=='/')?YES:NO;}
    return eq(pattern_text,path)?YES:NO;
}
static const char *truth_name(truth t){return t==YES?"matches":t==NO?"does_not_match":"unknown";}
static truth match(C *c,const matcher *m){
    if(!c->path){return UNKNOWN;}
    if(m->ambiguous_overload){return UNKNOWN;}
    if(m->any){return YES;}
    bool unknown=m->unknown;
    for(size_t i=0;i<m->n;i++){
        const pattern *p=&m->items[i];if(*p->method&&!eq(p->method,c->method))continue;
        truth t=(!p->explicit_ant&&!c->ant_strings)?UNKNOWN:path_match(p->path,c->path);
        if(t==YES){return YES;}
        if(t==UNKNOWN){unknown=true;}
    }return unknown?UNKNOWN:NO;
}
static void matcher_json(C *c,matcher *m,TSNode source){
    V *v=obj(c),*items=arr(c);put(c,v,"source",ref(c,source));flag(c,v,"any_request",m->any);flag(c,v,"has_unknown_alternative",m->unknown);flag(c,v,"overload_not_resolved",m->ambiguous_overload);
    for(size_t i=0;i<m->n;i++){V *p=obj(c);text(c,p,"pattern",m->items[i].path);text(c,p,"method",m->items[i].method);
        text(c,p,"semantics",m->items[i].explicit_ant?"explicit_ant_case_sensitive":"framework_selected_string_matcher");add(c,items,p);}
    put(c,v,"alternatives",items);text(c,v,"request_match",c->path?truth_name(match(c,m)):"not_evaluated");m->json=v;
}
static bool ant_pattern(C *c,TSNode n,pattern *p){
    TSNode a[4];bool ok=true;size_t count=0;bool constructor=kind(n,"object_creation_expression");
    if(constructor){if(!type_is(c,sf_field(n,"type"),ANT_TYPE))return false;}
    else return false; /* Static factories need value-namespace binding; intentionally not guessed. */
    count=children(c,sf_field(n,"arguments"),a,4,&ok);if(!ok||count<1||count>2||!string(c,a[0],p->path))return false;
    if(count==2){char m[STRING];if(kind(a[1],"null_literal"))p->method[0]=0;
        else if(string(c,a[1],m)&&strlen(m)<sizeof(p->method)&&http_method(m))memcpy(p->method,m,strlen(m)+1);else return false;}
    p->explicit_ant=true;return true;
}
static matcher parse_matcher(C *c,TSNode call,bool allow_http_method){
    matcher m={0};TSNode a[PATTERNS+1];bool ok=true;size_t n=children(c,sf_field(call,"arguments"),a,PATTERNS+1,&ok),start=0;char method[32]="";
    if(!ok||!n){m.unknown=true;gap(c,"matcher_arguments_not_resolved");}
    if(allow_http_method&&n&&method_enum(c,a[0],method))start=1;
    bool has_string=false,has_object=false,has_other=false;
    for(size_t i=start;i<n;i++){
        if(kind(a[i],"string_literal"))has_string=true;
        else if(kind(a[i],"object_creation_expression"))has_object=true;
        else has_other=true;
    }
    if(!ok||(has_string&&(has_other||has_object))){m.ambiguous_overload=true;gap(c,"matcher_overload_not_resolved");}
    for(size_t i=start;i<n;i++){
        if(m.n==PATTERNS){m.unknown=true;gap(c,"matcher_limit");break;}
        pattern p={0};if(string(c,a[i],p.path)){memcpy(p.method,method,sizeof(method));m.items[m.n++]=p;}
        else if(!*method&&ant_pattern(c,a[i],&p))m.items[m.n++]=p;
        else{m.unknown=true;gap(c,"custom_or_dynamic_matcher_not_resolved");}
    }
    if(!m.n){m.unknown=true;}
    matcher_json(c,&m,call);return m;
}
static size_t flatten(C *c,TSNode expr,TSNode calls[CALLS],TSNode *root,bool *ok){
    TSNode reverse[CALLS];size_t n=0;while(kind(expr,"method_invocation")){
        if(!step(c)||n==CALLS){*ok=false;break;}reverse[n++]=expr;expr=sf_field(expr,"object");
    }*root=expr;for(size_t i=0;i<n;i++)calls[i]=reverse[n-i-1];if(!n)*ok=false;return n;
}
static TSNode lambda_body(C *c,TSNode lambda,char name[128],bool *ok){
    if(!kind(lambda,"lambda_expression")){*ok=false;return (TSNode){0};}
    TSNode p=sf_field(lambda,"parameters");if(!kind(p,"identifier")){TSNode ps[2];size_t n=children(c,p,ps,2,ok);if(n!=1)*ok=false;else p=ps[0];}
    if(!kind(p,"identifier")||!sf_node_text(c->src,p,name,128))*ok=false;
    return sf_field(lambda,"body");
}
static void requirement(C *c,rule *r,TSNode call){
    char name[64]="";TSNode a[PATTERNS];bool ok=true;size_t n=children(c,sf_field(call,"arguments"),a,PATTERNS,&ok);V *req=obj(c),*vals=arr(c);
    if(!sf_node_text(c->src,sf_field(call,"name"),name,sizeof(name)))ok=false;
    bool no_args=eq(name,"permitAll")||eq(name,"denyAll")||eq(name,"authenticated");
    bool one=eq(name,"hasRole")||eq(name,"hasAuthority");bool several=eq(name,"hasAnyRole")||eq(name,"hasAnyAuthority");
    if(!no_args&&!one&&!several){ok=false;}
    if(no_args&&n){ok=false;}
    if(one&&n!=1){ok=false;}
    if(several&&!n){ok=false;}
    for(size_t i=0;i<n;i++){char s[STRING];if(!string(c,a[i],s)||!*s)ok=false;else{if((eq(name,"hasRole")||eq(name,"hasAnyRole"))&&!strncmp(s,"ROLE_",5))ok=false;add(c,vals,txt(c,s));}}
    text(c,req,"kind",ok?name:"unknown");put(c,req,"values",vals);put(c,req,"source",ref(c,call));
    text(c,req,"evaluation","requirement_only_not_user_authorization");if(!ok)gap(c,"authorization_requirement_not_resolved");put(c,r->json,"requirement",req);
}
static void registry_expression(C *c,record *r,TSNode expr,const char *registry){
    TSNode cs[CALLS],root;bool ok=true;size_t n=flatten(c,expr,cs,&root,&ok);
    if(!ok||!spells(c,root,registry)){r->rules_gap=true;gap(c,"authorization_registry_expression_not_resolved");return;}
    for(size_t i=0;i<n;i++){
        if(r->n==RULES){r->rules_gap=true;gap(c,"rule_limit");return;}
        if(r->any_seen){r->rules_gap=true;gap(c,"rule_after_any_request_not_validated");return;}
        rule *q=&r->rules[r->n];q->json=obj(c);num(c,q->json,"index",r->n);put(c,q->json,"source",ref(c,cs[i]));
        if(spells(c,sf_field(cs[i],"name"),"anyRequest")){
            TSNode a[1];bool good=true;if(children(c,sf_field(cs[i],"arguments"),a,1,&good)||!good){r->rules_gap=true;gap(c,"invalid_any_request");return;}
            q->match.any=true;r->any_seen=true;matcher_json(c,&q->match,cs[i]);
        }else if(spells(c,sf_field(cs[i],"name"),"requestMatchers"))q->match=parse_matcher(c,cs[i],true);
        else{r->rules_gap=true;gap(c,"authorization_matcher_method_not_supported");return;}
        put(c,q->json,"matcher",q->match.json);if(++i>=n){r->rules_gap=true;gap(c,"missing_authorization_terminal");return;}
        requirement(c,q,cs[i]);add(c,r->rule_list,q->json);r->n++;
    }
}
static void parse_authorization(C *c,record *r,TSNode call){
    TSNode a[2];bool ok=true;size_t n=children(c,sf_field(call,"arguments"),a,2,&ok);char registry[128]="";TSNode body={0};
    if(n==1&&ok)body=lambda_body(c,a[0],registry,&ok);else ok=false;
    if(!ok){r->rules_gap=true;gap(c,"authorization_lambda_not_resolved");return;}
    if(!kind(body,"block")){registry_expression(c,r,body,registry);return;}
    TSNode stmts[RULES];n=children(c,body,stmts,RULES,&ok);if(!ok){r->rules_gap=true;gap(c,"authorization_statement_limit");}
    for(size_t i=0;i<n;i++){
        if(kind(stmts[i],"expression_statement"))registry_expression(c,r,child(stmts[i],"method_invocation"),registry);
        else{r->rules_gap=true;gap(c,"authorization_control_or_side_effect_not_resolved");}
    }
}
static bool inert_customizer(C *c,TSNode call){
    TSNode a[2];bool ok=true;size_t n=children(c,sf_field(call,"arguments"),a,2,&ok);if(!ok||n!=1)return false;
    if(kind(a[0],"method_invocation")&&spells(c,sf_field(a[0],"name"),"withDefaults")&&type_is(c,sf_field(a[0],"object"),"org.springframework.security.config.Customizer")){
        TSNode args[1];return children(c,sf_field(a[0],"arguments"),args,1,&ok)==0&&ok;
    }
    char param[128]="";TSNode b=lambda_body(c,a[0],param,&ok),cs[CALLS],root;
    if(kind(b,"block")){TSNode stmts[2];size_t count=children(c,b,stmts,2,&ok);if(count!=1||!kind(stmts[0],"expression_statement"))return false;b=child(stmts[0],"method_invocation");}
    size_t count=flatten(c,b,cs,&root,&ok);if(!ok||count!=1||!spells(c,root,param)||!spells(c,sf_field(cs[0],"name"),"disable"))return false;
    TSNode args[1];return children(c,sf_field(cs[0],"arguments"),args,1,&ok)==0&&ok;
}
static void builder_expression(C *c,record *r,TSNode expr,const char *builder,bool returning){
    TSNode cs[CALLS],root;bool ok=true;size_t n=flatten(c,expr,cs,&root,&ok);
    if(!ok||!spells(c,root,builder)){r->structural_gap=true;gap(c,"builder_expression_not_resolved");return;}
    for(size_t i=0;i<n;i++){
        if(r->built){r->structural_gap=true;gap(c,"builder_used_after_build");return;}
        TSNode call=cs[i];char name[64]="";sf_node_text(c->src,sf_field(call,"name"),name,sizeof(name));
        if(eq(name,"securityMatcher"))r->match=parse_matcher(c,call,false);
        else if(eq(name,"authorizeHttpRequests")){
            if(r->auth_seen){r->rules_gap=true;gap(c,"multiple_authorization_configurers");}
            r->auth_seen=true;parse_authorization(c,r,call);
        }else if(eq(name,"build")){
            TSNode args[1];bool good=true;size_t count=children(c,sf_field(call,"arguments"),args,1,&good);
            if(!returning||i+1!=n||count||!good){r->structural_gap=true;gap(c,"build_return_not_resolved");}r->built=true;
        }else{
            V *other=obj(c);text(c,other,"method",name);put(c,other,"source",ref(c,call));add(c,r->other,other);
            bool standard=eq(name,"csrf")||eq(name,"httpBasic")||eq(name,"formLogin")||eq(name,"headers")||eq(name,"cors")||eq(name,"logout");
            if(standard&&inert_customizer(c,call)){text(c,other,"effect","outside_request_rule_analysis");}
            else{r->structural_gap=true;gap(c,"custom_builder_effect_not_resolved");}
        }
    }
    if(returning&&!r->built){r->structural_gap=true;gap(c,"return_does_not_build_selected_instance");}
}
static void ignored_expression(C *c,record *r,TSNode expr,const char *web){
    TSNode cs[CALLS],root;bool ok=true;size_t n=flatten(c,expr,cs,&root,&ok);
    if(!ok||!spells(c,root,web)||n<2||!spells(c,sf_field(cs[0],"name"),"ignoring")){r->structural_gap=true;gap(c,"ignored_configuration_not_resolved");return;}
    TSNode empty[1];if(children(c,sf_field(cs[0],"arguments"),empty,1,&ok)||!ok)r->structural_gap=true;
    for(size_t i=1;i<n;i++){
        if(!spells(c,sf_field(cs[i],"name"),"requestMatchers")||r->n==RULES){r->structural_gap=true;gap(c,"ignored_matcher_not_resolved");break;}
        rule *q=&r->rules[r->n];q->match=parse_matcher(c,cs[i],true);q->json=obj(c);num(c,q->json,"index",r->n);put(c,q->json,"matcher",q->match.json);add(c,r->rule_list,q->json);r->n++;
    }
}
static void ignored_body(C *c,record *r,TSNode expr){
    char web[128]="";bool ok=true;TSNode body=lambda_body(c,expr,web,&ok);
    if(!ok){r->structural_gap=true;gap(c,"web_customizer_lambda_not_resolved");return;}
    if(!kind(body,"block")){ignored_expression(c,r,body,web);return;}
    TSNode stmts[RULES];size_t n=children(c,body,stmts,RULES,&ok);if(!ok)r->structural_gap=true;
    for(size_t i=0;i<n;i++)if(kind(stmts[i],"expression_statement"))ignored_expression(c,r,child(stmts[i],"method_invocation"),web);
        else{r->structural_gap=true;gap(c,"web_customizer_side_effect_not_resolved");}
}
static void parse_order(C *c,record *r,TSNode method){
    bool ok=true;TSNode a=annotation(c,method,"org.springframework.core.annotation.Order",&ok);r->order=INT_MAX;r->order_known=true;
    if(!ts_node_is_null(a)){
        TSNode value=attr(c,a,"value",&ok);char raw[64];char *end=NULL;long long number=0;
        if(!sf_node_text(c->src,value,raw,sizeof(raw)))ok=false;
        else{const char *digits=raw+(*raw=='-'||*raw=='+');
            if(!*digits||(digits[0]=='0'&&digits[1]))ok=false;
            number=strtoll(raw,&end,10);if(!*raw||*end||number<INT_MIN||number>INT_MAX)ok=false;}
        if(ok){r->order=(int)number;}
        put(c,r->json,"order_source",ref(c,a));
    }
    if(!ok){r->order_known=false;gap(c,"order_not_resolved");}
    put(c,r->json,"order",r->order_known?yyjson_mut_sint(c->json,r->order):yyjson_mut_null(c->json));
    text(c,r->json,"order_basis",ts_node_is_null(a)?"default_lowest_precedence_assuming_no_external_order":"explicit_method_Order");
}
static bool visit(C *c,TSNode method){
    if(!step(c)){return false;}
    if(!kind(method,"method_declaration")){return true;}
    TSNode type=sf_field(method,"type");char raw[STRING]="";sf_node_text(c->src,type,raw,sizeof(raw));
    bool chain=type_is(c,type,CHAIN_TYPE),ignored=type_is(c,type,WEB_TYPE);
    if(!chain&&!ignored){if(eq(raw,"SecurityFilterChain")||eq(raw,"WebSecurityCustomizer")){c->incomplete=true;gap(c,"candidate_configuration_type_not_resolved");}return true;}
    bool ok=true;TSNode bean=annotation(c,method,"org.springframework.context.annotation.Bean",&ok);
    if(ts_node_is_null(bean)||!ok){gap(c,"unregistered_factory_candidate_not_selected");c->incomplete=true;return true;}
    if(c->n==RECORDS){c->incomplete=true;gap(c,"security_record_limit");return false;}
    record *r=calloc(1,sizeof(*r));if(!r){c->error="out_of_memory";return false;}c->all[c->n++]=r;c->current=r;
    r->json=obj(c);r->gaps=arr(c);r->rule_list=arr(c);r->other=arr(c);r->ignored=ignored;r->match.any=true;
    char id_source[256];snprintf(id_source,sizeof(id_source),"%s:%u:%u:%s",c->src->analysis_id,ts_node_start_byte(method),ts_node_end_byte(method),ignored?"ignored":"chain");cbm_sha256_hex(id_source,strlen(id_source),r->id);
    sf_node_text(c->src,sf_field(method,"name"),r->name,sizeof(r->name));text(c,r->json,"id",r->id);text(c,r->json,"factory",r->name);
    text(c,r->json,"kind",ignored?"ignored_request_customizer":"security_filter_chain");put(c,r->json,"source",ref(c,method));put(c,r->json,"bean_declaration",ref(c,bean));
    put(c,r->json,"gaps",r->gaps);put(c,r->json,"rules",r->rule_list);put(c,r->json,"other_customizations",r->other);parse_order(c,r,method);
    TSNode owner=ts_node_parent(ts_node_parent(method));bool top=kind(owner,"class_declaration")&&kind(ts_node_parent(owner),"program");
    if(!top||!ts_node_is_null(sf_field(owner,"superclass"))||!ts_node_is_null(sf_field(owner,"interfaces"))||!ts_node_is_null(sf_field(owner,"type_parameters"))||!ts_node_is_null(sf_field(method,"type_parameters"))){r->structural_gap=true;gap(c,"configuration_inheritance_or_nesting_not_resolved");}
    TSNode annotations[64];size_t an=children(c,child(owner,"modifiers"),annotations,64,&ok);if(!ok)r->structural_gap=true;
    V *class_ann=arr(c);put(c,r->json,"configuration_annotations",class_ann);
    for(size_t i=0;i<an;i++)if(kind(annotations[i],"annotation")||kind(annotations[i],"marker_annotation")){
        add(c,class_ann,ref(c,annotations[i]));gap(c,"configuration_activation_not_verified");
        TSNode name=sf_field(annotations[i],"name");
        if(!type_is(c,name,"org.springframework.context.annotation.Configuration") &&
           !type_is(c,name,"org.springframework.security.config.annotation.web.configuration.EnableWebSecurity")){
            r->structural_gap=true;gap(c,"conditional_or_custom_configuration_annotation");
        }
    }
    an=children(c,child(method,"modifiers"),annotations,64,&ok);
    V *method_ann=arr(c);put(c,r->json,"factory_annotations",method_ann);
    for(size_t i=0;i<an;i++)if(kind(annotations[i],"annotation")||kind(annotations[i],"marker_annotation")){
        add(c,method_ann,ref(c,annotations[i]));TSNode name=sf_field(annotations[i],"name");
        if(!type_is(c,name,"org.springframework.context.annotation.Bean") &&
           !type_is(c,name,"org.springframework.core.annotation.Order")){
            r->structural_gap=true;gap(c,"conditional_or_custom_factory_annotation");
        }
    }
    if(!ts_node_is_null(sf_field(bean,"arguments"))){r->structural_gap=true;gap(c,"bean_options_not_resolved");}
    V *imports=arr(c);put(c,r->json,"binding_evidence",imports);
    for(size_t i=0;i<c->src->count;i++)if(eq(c->src->facts[i].kind,"import_declaration")){
        const sf_fact *f=&c->src->facts[i];
        V *v=obj(c);text(c,v,"path",c->src->path);text(c,v,"sha256",c->src->source_hash);
        num(c,v,"start_byte",f->span.start);num(c,v,"end_byte",f->span.end);add(c,imports,v);
        if(yyjson_mut_arr_size(imports)>=64){r->structural_gap=true;gap(c,"import_evidence_limit");break;}
    }
    matcher_json(c,&r->match,(TSNode){0});
    TSNode body=sf_field(method,"body"),stmts[CALLS];size_t n=children(c,body,stmts,CALLS,&ok);if(!ok||ts_node_is_null(body))r->structural_gap=true;
    char builder[128]="";TSNode ps[32];size_t pn=children(c,sf_field(method,"parameters"),ps,32,&ok),hits=0;
    for(size_t i=0;i<pn;i++)if(kind(ps[i],"formal_parameter")&&type_is(c,sf_field(ps[i],"type"),HTTP_TYPE)){
        hits++;if(!sf_node_text(c->src,sf_field(ps[i],"name"),builder,sizeof(builder)))ok=false;put(c,r->json,"builder_parameter",ref(c,ps[i]));}
    if(!ignored&&(hits!=1||!ok)){r->structural_gap=true;gap(c,"unique_HttpSecurity_parameter_required");}
    for(size_t i=0;i<n;i++){
        TSNode st=stmts[i];if(kind(st,"return_statement")){
            if(i+1!=n){r->structural_gap=true;gap(c,"return_order_not_resolved");}
            TSNode items[2];bool good=true;size_t len=children(c,st,items,2,&good);
            if(len!=1||!good){r->structural_gap=true;gap(c,"factory_return_not_resolved");continue;}
            if(ignored){ignored_body(c,r,items[0]);r->built=true;}else if(hits==1)builder_expression(c,r,items[0],builder,true);
        }else if(!ignored&&kind(st,"expression_statement")&&hits==1)builder_expression(c,r,child(st,"method_invocation"),builder,false);
        else{r->structural_gap=true;gap(c,"factory_control_or_assignment_not_resolved");}
    }
    if(!r->built){r->structural_gap=true;gap(c,"factory_return_not_resolved");}
    if(!ignored&&(!r->auth_seen||!r->n)){r->rules_gap=true;gap(c,"authorization_configuration_not_resolved");}
    if(c->src->parse_has_error||!c->src->traversal_complete||!c->src->framework_analysis_complete){r->structural_gap=true;c->incomplete=true;gap(c,"configuration_parse_incomplete");}
    put(c,r->json,"chain_matcher",r->match.json);flag(c,r->json,"selection_structure_complete",!r->structural_gap);
    flag(c,r->json,"rule_sequence_complete",!r->rules_gap);flag(c,r->json,"runtime_registration_verified",false);
    add(c,c->records,r->json);c->current=NULL;return !c->error;
}
static bool visitor(TSNode n,void *ctx){return visit(ctx,n);}
static void selection(C *c){
    V *out=obj(c),*candidates=arr(c),*trace=arr(c);put(c,c->root,"selection",out);put(c,out,"candidate_chain_ids",candidates);put(c,out,"trace",trace);
    text(c,out,"scope","selected_configurations_assumed_active_only");text(c,out,"authorization","not_evaluated");
    if(!c->path){text(c,out,"status","request_not_supplied");return;}
    if(!safe_path(c->path,false)){text(c,out,"status","request_path_not_supported");return;}
    bool ignore_unknown=c->incomplete,ignore_yes=false;truth matches[RECORDS];
    for(size_t i=0;i<c->n;i++){
        record *r=c->all[i];truth t=r->structural_gap?UNKNOWN:match(c,&r->match);
        if(r->ignored){t=r->structural_gap?UNKNOWN:NO;for(size_t j=0;!r->structural_gap&&j<r->n;j++){truth x=match(c,&r->rules[j].match);if(x==YES){t=YES;break;}if(x==UNKNOWN)t=UNKNOWN;}
            if(t==YES){ignore_yes=true;}
            if(t==UNKNOWN){ignore_unknown=true;}}
        matches[i]=t;V *item=obj(c);text(c,item,"id",r->id);text(c,item,"kind",r->ignored?"ignored":"chain");text(c,item,"match",truth_name(t));add(c,trace,item);
    }
    if(ignore_yes){text(c,out,"status",c->incomplete?"incomplete_configuration_scope":"ignored_in_selected_configuration");text(c,out,"filter_chain_effect","ignored_not_permitAll");return;}
    record *winner=NULL;size_t possible=0;truth winner_match=UNKNOWN;
    for(size_t i=0;i<c->n;i++){
        record *r=c->all[i];if(r->ignored||matches[i]==NO)continue;bool blocked=false;
        for(size_t j=0;j<c->n;j++){record *p=c->all[j];if(!p->ignored&&matches[j]==YES&&p->order_known&&r->order_known&&p->order<r->order){blocked=true;break;}}
        if(!blocked){add(c,candidates,txt(c,r->id));possible++;winner=r;winner_match=matches[i];}
    }
    if(ignore_unknown){text(c,out,"status","incomplete_configuration_or_ignoring");return;}
    if(!possible){text(c,out,"status","no_matching_chain_in_selected_scope");return;}
    if(possible!=1||winner_match!=YES){text(c,out,"status","ambiguous_chain_selection");return;}
    text(c,out,"status","conditional_chain_selected");text(c,out,"selected_chain_id",winner->id);
    V *rsel=obj(c),*rc=arr(c);put(c,out,"rule_selection",rsel);put(c,rsel,"candidate_rule_indices",rc);
    if(winner->rules_gap){text(c,rsel,"status","incomplete_rule_sequence");return;}
    size_t active=0;rule *selected=NULL;bool definite=false;
    for(size_t i=0;i<winner->n;i++){
        rule *r=&winner->rules[i];truth t=match(c,&r->match);if(t==NO)continue;add(c,rc,yyjson_mut_uint(c->json,i));active++;selected=r;
        if(t==YES){definite=true;break;}
    }
    if(!active){text(c,rsel,"status","default_deny_in_supported_authorization_configurer");return;}
    if(active==1&&definite){text(c,rsel,"status","conditional_rule_selected");put(c,rsel,"requirement",yyjson_mut_val_mut_copy(c->json,yyjson_mut_obj_get(selected->json,"requirement")));}
    else text(c,rsel,"status","ambiguous_rule_selection");
}
const char *sf_inspect_entry_security(const char *snapshot_id,yyjson_val *entry,
    const sf_security_source *sources,size_t count,const char *method,const char *request_path,
    const char *string_semantics,size_t *parse_attempts,yyjson_mut_doc *json,V **out){
    *out=NULL;*parse_attempts=0;if(!count||count>SF_SECURITY_FILES||!json||!yyjson_is_obj(entry))return "invalid_security_scope";
    if((method&&!request_path)||(!method&&request_path)|| (method&&!http_method(method)))return "invalid_security_request";
    if(string_semantics&&!eq(string_semantics,"unresolved")&&!eq(string_semantics,"ant-path"))return "unsupported_string_matcher_semantics";
    C c={.json=json,.method=method,.path=request_path,.ant_strings=eq(string_semantics,"ant-path")};c.root=obj(&c);c.records=arr(&c);c.coverage=arr(&c);c.gaps=arr(&c);
    text(&c,c.root,"schema",SF_SECURITY_SCHEMA);put(&c,c.root,"configurations",c.records);put(&c,c.root,"coverage",c.coverage);put(&c,c.root,"gaps",c.gaps);
    V *entry_copy=yyjson_val_mut_copy(json,entry);put(&c,c.root,"entry",entry_copy);
    text(&c,entry_copy,"snapshot_id",snapshot_id);
    V *call_query=yyjson_mut_obj_get(entry_copy,"call_query"),*handler_anchor=yyjson_mut_obj_get(entry_copy,"handler_anchor");
    if(call_query)text(&c,call_query,"snapshot_id",snapshot_id);
    if(handler_anchor){text(&c,handler_anchor,"snapshot_id",snapshot_id);}
    text(&c,c.root,"snapshot_id",snapshot_id);text(&c,c.root,"build_id",SF_BUILD_ID);
    text(&c,c.root,"string_matcher_assumption",c.ant_strings?"ant_path_case_sensitive_unverified":"unresolved");
    text(&c,c.root,"reference_semantics","spring-security-6.5.0-supported-subset");
    V *req=obj(&c);put(&c,c.root,"request",req);text(&c,req,"method",method?method:"");text(&c,req,"path",request_path?request_path:"");
    text(&c,req,"path_meaning","servletPath_plus_pathInfo_no_decoding");text(&c,req,"entry_routing","not_verified_no_path_set_inclusion_claim");
    text(&c,c.root,"scope_completeness","selected_files_only_not_whole_application");text(&c,c.root,"authorization_verdict","not_evaluated");
    flag(&c,c.root,"runtime_registration_verified",false);flag(&c,c.root,"security_control_effectiveness_verified",false);
    V *pre=arr(&c);put(&c,c.root,"assumptions",pre);
    const char *assumptions[]={"selected_factories_registered_and_active","no_unselected_security_configuration_or_external_order","no_external_builder_postprocessing","original_request_not_rewritten_before_rule_matching","reference_version_and_supported_semantics_apply"};
    for(size_t i=0;i<sizeof(assumptions)/sizeof(assumptions[0]);i++)add(&c,pre,txt(&c,assumptions[i]));
    size_t bytes=0;
    for(size_t i=0;i<count;i++){
        const sf_security_source *s=&sources[i];if(s->size>SF_SECURITY_FILE_BYTES||s->size>SF_SECURITY_TOTAL_BYTES-bytes){c.error="security_input_limit";break;}bytes+=s->size;
        sf_document doc={0};TSTree *tree=NULL;
        if(!sf_document_init(&doc,s->source,s->size,s->path)||!eq(doc.language,"java")){c.error="unsupported_security_language";break;}
        c.src=&doc;V *cov=obj(&c);text(&c,cov,"path",s->path);text(&c,cov,"sha256",doc.source_hash);add(&c,c.coverage,cov);
        (*parse_attempts)++;const char *err=sf_extract_tree(&doc,&tree);size_t before=c.n,walked=0;
        if(err||!tree){c.incomplete=true;text(&c,cov,"status","analysis_failed");text(&c,cov,"error",err?err:"missing_parse_tree");}
        else{c.tree_root=ts_tree_root_node(tree);bool finished=sf_walk(c.tree_root,visitor,&c,&walked);
            bool complete=finished&&!doc.parse_has_error&&doc.traversal_complete&&doc.framework_analysis_complete;
            if(!complete){c.incomplete=true;}
            text(&c,cov,"status",complete?"supported_subset_visited":"parse_or_budget_incomplete");num(&c,cov,"records",c.n-before);}
        if(tree){ts_tree_delete(tree);}
        sf_document_free(&doc);c.src=NULL;if(c.error)break;
    }
    for(size_t i=0;i<c.n;i++)for(size_t j=0;j<i;j++)if(eq(c.all[i]->name,c.all[j]->name)){
        c.incomplete=true;unique(&c,c.gaps,"duplicate_bean_factory_name_not_resolved");
    }
    if(c.incomplete){unique(&c,c.gaps,"configuration_scope_incomplete");}
    num(&c,c.root,"analysis_steps",c.steps);flag(&c,c.root,"truncated",c.steps>STEPS||c.n==RECORDS);
    selection(&c);
    size_t len=0;char *raw=yyjson_mut_val_write(c.root,0,&len);
    if(!raw)c.error="out_of_memory";else if(len>SF_MAX_OUTPUT)c.error="security_output_limit";
    if(!c.error){char id[65];cbm_sha256_hex(raw,len,id);text(&c,c.root,"context_id",id);*out=c.root;}free(raw);
    for(size_t i=0;i<c.n;i++){free(c.all[i]);}
    return c.error;
}
