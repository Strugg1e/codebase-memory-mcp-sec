#include "mybatis_template.h"

#include <string.h>

typedef yyjson_mut_val V;
typedef struct { yyjson_mut_doc *d; V *gaps; const char *error; bool limited; } scan;
static V *obj(scan *s) { return yyjson_mut_obj(s->d); }
static V *arr(scan *s) { return yyjson_mut_arr(s->d); }
static void put(scan *s,V *v,const char *k,V *x) {
    V *key=yyjson_mut_strcpy(s->d,k);
    if(!key||!x||!v||!yyjson_mut_obj_put(v,key,x))s->error="out_of_memory";
}
static void text(scan *s,V *v,const char *k,const char *x) { put(s,v,k,yyjson_mut_strcpy(s->d,x)); }
static void number(scan *s,V *v,const char *k,size_t x) { put(s,v,k,yyjson_mut_uint(s->d,x)); }
static void flag(scan *s,V *v,const char *k,bool x) { put(s,v,k,yyjson_mut_bool(s->d,x)); }
static void add(scan *s,V *v,V *x) { if(!v||!x||!yyjson_mut_arr_append(v,x))s->error="out_of_memory"; }
static void gap(scan *s,const char *x) {
    size_t i,n;V *v;yyjson_mut_arr_foreach(s->gaps,i,n,v)if(!strcmp(yyjson_mut_get_str(v),x))return;
    if(yyjson_mut_arr_size(s->gaps)<32)add(s,s->gaps,yyjson_mut_strcpy(s->d,x));else s->limited=true;
}
static V *copy(scan *s,V *v) { return v?yyjson_mut_val_mut_copy(s->d,v):arr(s); }
static V *ref(scan *s,const sf_operation_source *src,size_t a,size_t b) {
    V *r=obj(s);
    if(a>b||b>src->size){s->error="invalid_template_span";return r;}
    size_t len=b-a,n=len>512?512:len;
    while(n&&n<len&&((unsigned char)src->source[a+n]&0xc0U)==0x80U)n--;
    text(s,r,"path",src->path);text(s,r,"sha256",src->sha256);
    number(s,r,"start_byte",a);number(s,r,"end_byte",b);
    put(s,r,"text_prefix",yyjson_mut_strncpy(s->d,src->source+a,n));flag(s,r,"text_truncated",n<len);
    return r;
}
static bool space(char c) { return c==' '||c=='\t'||c=='\n'||c=='\r'; }
static bool first(char c) { return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'; }
static bool rest(char c) { return first(c)||(c>='0'&&c<='9'); }
/* Simple roots and dotted property paths only. Never evaluate OGNL or equate
 * a property value with the root object's scalar value. */
static bool path(const char *raw,size_t a,size_t b,char root[128],char prop[256]) {
    while(a<b&&space(raw[a]))a++;
    while(b>a&&space(raw[b-1]))b--;
    if(a==b||!first(raw[a]))return false;
    size_t start=a++;while(a<b&&rest(raw[a]))a++;
    if(a-start>=128)return false;
    memcpy(root,raw+start,a-start);root[a-start]=0;
    size_t p=a;
    while(a<b&&raw[a]=='.') {
        a++;if(a==b||!first(raw[a]))return false;
        a++;while(a<b&&rest(raw[a]))a++;
    }
    if(a-p>=256)return false;
    memcpy(prop,raw+p,a-p);prop[a-p]=0;
    while(a<b&&space(raw[a]))a++;
    return a==b;
}
const char *sf_mybatis_template(yyjson_mut_doc *d,const sf_operation_source *src,
    const sf_mb_segment *segments,size_t count,const sf_mb_binding *bindings,
    size_t binding_count,bool xml_property_phase,bool incomplete,V **result) {
    if(!d||!src||!result||count>SF_MB_SEGMENTS||binding_count>64)return "invalid_template_input";
    scan s={.d=d};s.gaps=arr(&s);V *out=obj(&s),*occ=arr(&s),*parts=arr(&s),*escaped=arr(&s);
    text(&s,out,"schema","cbm.mybatis-template.v1");text(&s,out,"stage","template_before_sql_lexing");
    text(&s,out,"evaluation","source_candidates_no_ognl_or_database_execution");
    put(&s,out,"gaps",s.gaps);put(&s,out,"segments",parts);put(&s,out,"parameter_occurrences",occ);
    put(&s,out,"escaped_markers",escaped);
    text(&s,out,"input_kind",xml_property_phase?"xml_template":"plain_annotation_literals");
    text(&s,out,"configuration_properties",xml_property_phase?"not_supplied":"not_applied_to_plain_annotation");
    if(incomplete)gap(&s,"template_material_incomplete");
    for(size_t part=0;part<count;part++) {
        const sf_mb_segment *p=&segments[part];size_t a=p->span.start,b=p->span.end;
        if(a>b||b>src->size)return "invalid_template_span";
        V *piece=obj(&s);put(&s,piece,"source",ref(&s,src,a,b));
        put(&s,piece,"conditions",copy(&s,p->conditions));put(&s,piece,"include_sites",copy(&s,p->include_sites));
        flag(&s,piece,"binding_scope_unknown",p->binding_scope_unknown);add(&s,parts,piece);
        for(size_t i=a;i<b;) {
            char kind=src->source[i];
            if((kind!='#'&&kind!='$')||i+1==b||src->source[i+1]!='{'){i++;continue;}
            size_t start=i;i+=2;
            /* XML XNode applies PropertyParser before TextSqlNode. A single
             * slash before ${ is removed there and is NOT a runtime barrier.
             * Keep original bytes; never synthesize source offsets. Additional
             * passes (include/configuration) and multiple slashes stay unknown. */
            size_t slashes=0;
            while(start>a+slashes&&src->source[start-slashes-1]=='\\')slashes++;
            bool escape_unknown=slashes>1&&xml_property_phase&&kind=='$';
            if(slashes) {
                V *e=ref(&s,src,start-slashes,i);
                text(&s,e,"effect",xml_property_phase&&kind=='$'?
                    (escape_unknown?"xml_escape_stages_not_resolved":"xml_property_unescape_before_runtime"):
                    "escaped_at_marker_stage");
                if(yyjson_mut_arr_size(escaped)<SF_MB_MARKERS)add(&s,escaped,e);
                else s.limited=true;
                if(!xml_property_phase||kind!='$')continue;
            }
            bool escaped_close=false,nested=false;
            while(i<b) {
                if(src->source[i]=='}') {
                    if(i>start+2&&src->source[i-1]=='\\'){escaped_close=true;i++;continue;}
                    break;
                }
                if(i+1<b&&(src->source[i]=='#'||src->source[i]=='$')&&src->source[i+1]=='{')nested=true;
                i++;
            }
            if(i==b){gap(&s,"unterminated_or_cross_segment_template_marker");break;}
            size_t close=i++;
            if(yyjson_mut_arr_size(occ)>=SF_MB_MARKERS){s.limited=true;gap(&s,"template_marker_limit");break;}
            V *v=obj(&s);put(&s,v,"source",ref(&s,src,start,i));put(&s,v,"expression",ref(&s,src,start+2,close));
            number(&s,v,"segment_index",part);
            text(&s,v,"form",kind=='#'?"parameter_marker":"text_substitution_marker");
            text(&s,v,"processing",kind=='#'?"parameter_mapping_candidate":
                escape_unknown?"xml_escape_stages_not_resolved":
                slashes?"xml_property_unescape_then_substitution_candidate":"text_substitution");
            if(xml_property_phase&&kind=='$') {
                text(&s,v,"parameter_binding_assumption","marker_survives_configuration_property_phase");
                gap(&s,"xml_configuration_properties_not_supplied");
                if(slashes)put(&s,v,"escape_source",ref(&s,src,start-slashes,start+2));
                if(escape_unknown)gap(&s,"xml_escape_stages_not_resolved");
            }
            put(&s,v,"xml_conditions",copy(&s,p->conditions));put(&s,v,"include_sites",copy(&s,p->include_sites));
            text(&s,v,"condition_evaluation","not_performed");flag(&s,v,"guaranteed_scope",false);
            text(&s,v,"binding_status",escape_unknown?"preprocessing_not_resolved":p->binding_scope_unknown?"dynamic_scope_not_bound":"unresolved");
            size_t end=close;
            if(kind=='#')for(size_t j=start+2;j<close;j++)if(src->source[j]==','){end=j;break;}
            char root[128]={0},prop[256]={0};
            bool simple=!nested&&!escaped_close&&path(src->source,start+2,end,root,prop);
            if(simple) {
                text(&s,v,"parameter_name",root);text(&s,v,"property_path",prop);
                bool reserved=!strcmp(root,"_parameter")||!strcmp(root,"_databaseId");
                if(reserved)gap(&s,"reserved_binding_context_not_resolved");
                for(size_t k=0;!reserved&&!escape_unknown&&!p->binding_scope_unknown&&k<binding_count;k++)if(!strcmp(root,bindings[k].name)) {
                    if(*prop) {
                        number(&s,v,"root_argument_index",bindings[k].argument_index);
                        text(&s,v,"binding_status","property_path_candidate_value_not_resolved");
                        gap(&s,"property_value_not_equated_to_root_argument");
                    }else {
                        number(&s,v,"argument_index",bindings[k].argument_index);
                        text(&s,v,"binding_status","explicit_Param_position_candidate");
                        V *link=obj(&s);number(&s,link,"argument_index",bindings[k].argument_index);
                        text(&s,link,"relation","same_root_operation_argument");
                        text(&s,link,"local_collection","arguments");
                        text(&s,link,"match_field","index");text(&s,link,"value_field","local_value_flow");
                        text(&s,link,"upstream_field","argument_flow.local_value_paths");
                        put(&s,v,"value_origin_ref",link);
                    }
                    break;
                }
            }else gap(&s,"template_expression_not_resolved");
            if(nested)gap(&s,"nested_template_stages_not_resolved");
            if(escaped_close)gap(&s,"escaped_template_expression_not_normalized");
            if(kind=='$')gap(&s,"substitution_can_change_sql_and_later_parameter_structure");
            add(&s,occ,v);
        }
        if(b>a&&(src->source[b-1]=='$'||src->source[b-1]=='#'))gap(&s,"segment_boundary_marker_may_be_split");
    }
    flag(&s,out,"truncated",s.limited);flag(&s,out,"input_incomplete",incomplete);
    text(&s,out,"status",s.limited||incomplete||yyjson_mut_arr_size(s.gaps)?"with_gaps":"supported_template_subset");
    text(&s,out,"security_verdict","not_evaluated");*result=out;return s.error;
}
