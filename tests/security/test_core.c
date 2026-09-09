#include "facts.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)

int main(void) {
    sf_document d, other;
    sf_query q = {.limit = 50};
    char *out = NULL;
    CHECK(sf_path_valid("src/例子.java"));
    const char *bad_paths[] = {"../A.java", "/A.java", "a/../A.java", "a//A.java", "a/./A.java",
                              "C:A.java", "a\\A.java", "A.py", "", "x\n.java", NULL};
    for (size_t i = 0; bad_paths[i]; i++) CHECK(!sf_path_valid(bad_paths[i]));
    CHECK(sf_utf8("你好\xf0\x9f\x98\x80", 10));
    CHECK(!sf_utf8("\xc0\x80", 2)); CHECK(!sf_utf8("\xed\xa0\x80", 3));
    CHECK(!sf_utf8("\xf4\x90\x80\x80", 4)); CHECK(!sf_utf8("\xe4\xb8", 2));
    CHECK(!sf_utf8("a\0b", 3)); CHECK(!sf_utf8(NULL, 0));
    CHECK(sf_document_init(&d, "abc", 3, "A.java"));
    CHECK(strcmp(d.source_hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    CHECK(sf_render(&d, &q, &out) == NULL);
    CHECK(strstr(out, "absence_is_not_a_security_verdict"));
    CHECK(strstr(out, "\"total_is_lower_bound\":true"));
    CHECK(strstr(out, "\"facts\":[]")); free(out);
    CHECK(sf_document_init(&other, "abd", 3, "A.java"));
    CHECK(strcmp(d.analysis_id, other.analysis_id) != 0);
    CHECK(sf_document_init(&other, "abc", 3, "B.java"));
    CHECK(strcmp(d.analysis_id, other.analysis_id) != 0);
    CHECK(sf_document_init(&other, "abc", 3, "A.java"));
    CHECK(strcmp(d.analysis_id, other.analysis_id) == 0);
    q.expected_analysis = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    CHECK(strcmp(sf_render(&d, &q, &out), "analysis_mismatch") == 0); CHECK(out == NULL);

    const char *source = "f(1,2,3,4,5,6,7,8,9);f(0);";
    CHECK(sf_document_init(&d, source, strlen(source), "Calls.java"));
    d.facts = calloc(2, sizeof(*d.facts)); CHECK(d.facts); d.count = 2; d.traversal_complete = true;
    d.facts[0] = (sf_fact){.kind = "call_site", .syntax = "method_invocation", .span = {0,20,1,1},
                          .has_arguments = true, .argument_total = 9, .argument_count = 9};
    d.facts[0].arguments = calloc(9, sizeof(sf_span)); CHECK(d.facts[0].arguments);
    for (uint32_t i = 0; i < 9; i++) d.facts[0].arguments[i] = (sf_span){2 + i * 2,3 + i * 2,1,1};
    d.facts[1] = (sf_fact){.kind = "call_site", .syntax = "method_invocation", .span = {21,25,1,1}};
    char first[65], second[65]; sf_fact_id(&d, &d.facts[0], first); sf_fact_id(&d, &d.facts[1], second);
    CHECK(strcmp(first, second) != 0);
    q = (sf_query){.limit = 1};
    CHECK(sf_render(&d, &q, &out) == NULL);
    CHECK(strstr(out, "\"argument_total\":9")); CHECK(strstr(out, "\"index\":8"));
    CHECK(strstr(out, "\"has_more\":true")); CHECK(strstr(out, "\"next_offset\":1")); free(out);
    q.offset = 1;
    CHECK(strcmp(sf_render(&d, &q, &out), "analysis_id_required") == 0); CHECK(out == NULL);
    q.expected_analysis = d.analysis_id;
    CHECK(sf_render(&d, &q, &out) == NULL); CHECK(strstr(out, second));
    CHECK(!strstr(out, first)); CHECK(strstr(out, "\"next_offset\":null")); free(out);
    q.offset = 0; q.fact_id = first;
    CHECK(sf_render(&d, &q, &out) == NULL); CHECK(strstr(out, first)); CHECK(!strstr(out, second)); free(out);
    q.fact_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    CHECK(strcmp(sf_render(&d, &q, &out), "fact_not_found_in_extracted_scope") == 0);
    q.fact_id = NULL; q.limit = 201;
    CHECK(strcmp(sf_render(&d, &q, &out), "invalid_arguments") == 0);
    q.limit = 2; d.facts[1].span.end = 1000;
    CHECK(strcmp(sf_render(&d, &q, &out), "invalid_evidence_span") == 0); CHECK(out == NULL);
    sf_document_free(&d);

    char long_source[700];
    memset(long_source, 'a', 255); memcpy(long_source + 255, "中\n\"\\", 6);
    memset(long_source + 261, 'b', 439);
    CHECK(sf_document_init(&d, long_source, sizeof(long_source), "Unicode.java"));
    d.facts = calloc(1, sizeof(*d.facts)); CHECK(d.facts); d.count = 1;
    d.facts[0] = (sf_fact){.kind = "annotation", .syntax = "annotation", .span = {0,700,1,2}};
    q = (sf_query){.limit = 50};
    CHECK(sf_render(&d, &q, &out) == NULL); CHECK(sf_utf8(out, strlen(out)));
    CHECK(strstr(out, "\"text_bytes_returned\":255")); CHECK(strstr(out, "\"text_truncated\":true")); free(out);
    d.facts[0].span = (sf_span){255,261,1,2};
    CHECK(sf_render(&d, &q, &out) == NULL); CHECK(strstr(out, "中\\u000a\\\"\\\\")); free(out);
    d.facts[0].span.start = 256;
    CHECK(strcmp(sf_render(&d, &q, &out), "invalid_evidence_span") == 0);
    sf_document_free(&d);
    puts("security core: input validation, hashing, identity, paging, lookup, span and UTF-8 tests passed");
    return 0;
}
