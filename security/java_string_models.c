/* Checked-in may-dependency models for Java SE 17 String return values.
 * No string/regex execution, heap traversal, sanitizer or trust inference.
 * API basis: https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/String.html
 */
#include "java_string_models.h"
#include <string.h>

static bool word(const sf_document *d, TSNode n, const char *s) {
    if (ts_node_is_null(n)) return false;
    size_t a=ts_node_start_byte(n), b=ts_node_end_byte(n), len=strlen(s);
    return a<=b && b<=d->source_size && b-a==len && !memcmp(d->source+a,s,len);
}
void sf_string_types_init(const sf_document *d, TSNode root, sf_string_type_context *c) {
    *c=(sf_string_type_context){.simple_allowed=true,.qualified_allowed=true};
    if (!d || ts_node_is_null(root)) { c->simple_allowed=c->qualified_allowed=false; return; }
    TSTreeCursor walk=ts_tree_cursor_new(root);
    for (;;) {
        TSNode n=ts_tree_cursor_current_node(&walk);
        if (++c->nodes>20000U) { c->truncated=true; break; }
        const char *kind=ts_node_type(n);
        if (!strcmp(kind,"import_declaration")) {
            /* Import syntax has already been parsed. Reject unknown wildcard
             * type providers and explicit shadowing instead of matching names. */
            char text[1024];
            if (!sf_node_text(d,n,text,sizeof(text))) c->simple_allowed=c->qualified_allowed=false;
            else {
                char compact[1024]; size_t used=0;
                for (size_t i=0;text[i] && used+1<sizeof(compact);i++)
                    if (text[i]!=' ' && text[i]!='\t' && text[i]!='\n' && text[i]!='\r') compact[used++]=text[i];
                compact[used]=0;
                if (!strcmp(compact,"importjava.lang.String;")) c->explicit_import=true;
                else if (strstr(compact,"String;") || strstr(compact,"java;")) {
                    if (strstr(compact,"String;")) c->simple_allowed=false;
                    if (strstr(compact,"java;")) c->qualified_allowed=false;
                }
                if (strchr(compact,'*') && strcmp(compact,"importjava.lang.*;"))
                    c->simple_allowed=c->qualified_allowed=false;
            }
        }
        if (strstr(kind,"class_declaration") || !strcmp(kind,"interface_declaration") ||
            !strcmp(kind,"enum_declaration") || !strcmp(kind,"record_declaration") ||
            !strcmp(kind,"annotation_type_declaration") || !strcmp(kind,"type_parameter")) {
            TSNode name=sf_field(n,"name");
            if (ts_node_is_null(name) && !strcmp(kind,"type_parameter")) name=ts_node_named_child(n,0);
            if (word(d,name,"String")) c->simple_allowed=false;
            if (word(d,name,"java")) c->qualified_allowed=false;
            /* Inherited member types are not resolved by this file model. */
            if (!ts_node_is_null(sf_field(n,"superclass")) || !ts_node_is_null(sf_field(n,"interfaces")))
                c->simple_allowed=false;
        }
        if (ts_tree_cursor_goto_first_child(&walk)) continue;
        bool next=false;
        for (;;) {
            if (ts_tree_cursor_goto_next_sibling(&walk)) { next=true; break; }
            if (!ts_tree_cursor_goto_parent(&walk)) break;
        }
        if (!next) break;
    }
    ts_tree_cursor_delete(&walk);
    if (c->truncated) c->simple_allowed=c->qualified_allowed=false;
}
unsigned sf_string_declared_type(const sf_document *d, TSNode type, const sf_string_type_context *c) {
    if (word(d,type,"char")) return SF_JT_CHAR;
    if (word(d,type,"java.lang.String") && c->qualified_allowed) return SF_JT_STRING;
    if (word(d,type,"String") && c->simple_allowed)
        return c->explicit_import ? SF_JT_STRING : SF_JT_IMPLICIT_STRING;
    return SF_JT_UNKNOWN;
}
bool sf_string_type(unsigned type) {
    return type && !(type & ~(SF_JT_STRING | SF_JT_IMPLICIT_STRING));
}
const sf_string_return_model *sf_string_model(const char *name,size_t arity,const unsigned *args) {
    static const sf_string_return_model models[]={
        {"trim","java.lang.String.trim/0",0,false,false},
        {"strip","java.lang.String.strip/0",0,false,false},
        {"stripLeading","java.lang.String.stripLeading/0",0,false,false},
        {"stripTrailing","java.lang.String.stripTrailing/0",0,false,false},
        {"toLowerCase","java.lang.String.toLowerCase/0",0,false,false},
        {"toUpperCase","java.lang.String.toUpperCase/0",0,false,false},
        {"substring","java.lang.String.substring/1",1,false,false},
        {"substring","java.lang.String.substring/2",2,false,false},
        {"concat","java.lang.String.concat/1",1,false,false},
        {"repeat","java.lang.String.repeat/1",1,false,false},
        {"replace","java.lang.String.replace/2",2,false,true},
        {"toString","java.lang.String.toString/0",0,true,false}
    };
    for (size_t i=0;i<sizeof(models)/sizeof(models[0]);i++) {
        const sf_string_return_model *m=&models[i];
        if (strcmp(name,m->name) || arity!=m->arity) continue;
        if (!strcmp(name,"concat") && !sf_string_type(args[0])) return NULL;
        if (m->replace_overload && !((args[0]==SF_JT_CHAR && args[1]==SF_JT_CHAR) ||
                                    (sf_string_type(args[0]) && sf_string_type(args[1])))) return NULL;
        return m;
    }
    return NULL;
}
