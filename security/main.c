#include "facts.h"
#include "capabilities.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static int error(const char *code) {
    if (printf("{\"schema\":\"%s\",\"error\":{\"code\":\"%s\"}}\n", SF_SCHEMA, code) < 0 || fflush(stdout) != 0) return 3;
    return 2;
}
static bool integer(const char *text, size_t *out) {
    if (!text || !*text) return false;
    for (const char *p = text; *p; p++) if (*p < '0' || *p > '9') return false;
    errno = 0; char *end = NULL;
    unsigned long n = strtoul(text, &end, 10);
    if (errno || !end || *end || n > SF_MAX_FACTS) return false;
    *out = (size_t)n; return true;
}
static bool cursor(const char *text, char id[65], size_t *offset) {
    size_t n = strlen(text);
    if (n < 66 || n > 70 || text[64] != ':') return false;
    memcpy(id, text, 64); id[64] = 0;
    return sf_digest_valid(id) && integer(text + 65, offset) && *offset > 0;
}
static void capabilities(void) {
    fputs("{\"schema\":\"" SF_SCHEMA "\",\"version\":\"" SF_VERSION "\","
         "\"languages\":[\"java\",\"python\",\"javascript\",\"typescript\",\"tsx\",\"go\"],"
         "\"extensions\":[\".java\",\".py\",\".pyi\",\".js\",\".jsx\",\".mjs\",\".cjs\",\".ts\",\".mts\",\".cts\",\".tsx\",\".go\"],"
         "\"frameworks\":[\"spring-mvc\",\"spring-security\",\"fastapi\",\"flask\",\"django\",\"express\",\"nestjs\",\"go-net-http\",\"gin\"],"
         "\"query_filters\":[\"kind\",\"framework\",\"role\",\"enclosing_id\"],\"query_cursor\":true,"
         "\"enclosing_scope\":\"direct_children_only\","
         "\"scope\":\"single_file\",\"framework_basis\":\"import_and_syntax_candidate\","
         "\"cross_file_resolution\":false,\"value_flow\":false,\"security_verdicts\":false,\"product_capabilities\":", stdout);
    fputs(sf_product_capabilities(), stdout); puts("}");
}

int main(int argc, char **argv) {
    const char *path = NULL;
    char cursor_id[65] = {0};
    sf_query query = {.limit = 50}; unsigned seen = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 && argc == 2) {
            puts("cbm-security-facts --path relative/File.ext [--limit 1..200] < File.ext\n"
                 "  [--kind KIND] [--framework FRAMEWORK] [--role ROLE] [--enclosing-id SHA256]\n"
                 "  [--cursor CURSOR] [--expect-analysis SHA256]\n"
                 "  [--fact-id SHA256 --expect-analysis SHA256]\n"
                 "Filters combine with AND. Repeat the same filters when using page.next_cursor.\n"
                 "Legacy --offset N requires --expect-analysis and cannot continue a filtered query.\n"
                 "--capabilities lists languages, framework candidates and query features.\n"
                 "Reads at most 1 MiB of UTF-8 source from stdin. No target files are opened.\n"
                 "Enclosing queries return direct syntax children, not a proof of protection."); return 0;
        }
        if (strcmp(argv[i], "--version") == 0 && argc == 2) { puts("cbm-security-facts " SF_VERSION " " SF_BUILD_ID); return 0; }
        if (strcmp(argv[i], "--capabilities") == 0 && argc == 2) { capabilities(); return 0; }
        if (i + 1 >= argc) return error("invalid_arguments");
        const char *option = argv[i++], *value = argv[i]; unsigned bit = 0;
        if (strcmp(option, "--path") == 0) { bit = 1; path = value; }
        else if (strcmp(option, "--offset") == 0) { bit = 2; if (!integer(value, &query.offset)) return error("invalid_arguments"); }
        else if (strcmp(option, "--limit") == 0) { bit = 4; if (!integer(value, &query.limit)) return error("invalid_arguments"); }
        else if (strcmp(option, "--expect-analysis") == 0) { bit = 8; query.expected_analysis = value; }
        else if (strcmp(option, "--fact-id") == 0) { bit = 16; query.fact_id = value; }
        else if (strcmp(option, "--kind") == 0) { bit = 32; query.kind = value; }
        else if (strcmp(option, "--framework") == 0) { bit = 64; query.framework = value; }
        else if (strcmp(option, "--role") == 0) { bit = 128; query.role = value; }
        else if (strcmp(option, "--enclosing-id") == 0) { bit = 256; query.enclosing_id = value; }
        else if (strcmp(option, "--cursor") == 0) {
            bit = 512;
            if (!cursor(value, cursor_id, &query.offset)) return error("invalid_cursor");
            query.expected_query = cursor_id;
        } else return error("invalid_arguments");
        if (seen & bit) return error("duplicate_argument");
        seen |= bit;
    }
    if (!sf_path_valid(path) || ((seen & 2U) && (seen & 512U))) return error("invalid_arguments");
    const char *failure = sf_query_validate(&query);
    if (failure) return error(failure);
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) < 0 || _setmode(_fileno(stdout), _O_BINARY) < 0) return error("binary_stdio_unavailable");
#endif
    char *source = malloc(SF_MAX_SOURCE + 1);
    if (!source) return error("out_of_memory");
    size_t used = 0;
    while (used < SF_MAX_SOURCE + 1) {
        size_t n = fread(source + used, 1, SF_MAX_SOURCE + 1 - used, stdin); used += n;
        if (!n) break;
    }
    if (ferror(stdin) || used > SF_MAX_SOURCE) {
        const char *code = ferror(stdin) ? "source_read_failed" : "source_limit_exceeded";
        free(source); return error(code);
    }
    sf_document doc;
    if (!sf_document_init(&doc, source, used, path)) { free(source); return error("invalid_utf8_or_source"); }
    /* Both source and query mismatch are rejected before parser work. */
    failure = sf_query_check(&doc, &query);
    if (!failure) failure = sf_extract(&doc);
    char *output = NULL;
    if (!failure) failure = sf_render(&doc, &query, &output);
    int rc = 0;
    if (failure) rc = error(failure);
    else if (fputs(output, stdout) == EOF || fflush(stdout) != 0) rc = 3;
    free(output); sf_document_free(&doc); free(source); return rc;
}
