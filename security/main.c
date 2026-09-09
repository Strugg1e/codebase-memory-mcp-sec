#include "facts.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static int error(const char *code) {
    /* Codes are internal constants, never interpolated source or CLI text. */
    printf("{\"schema\":\"%s\",\"error\":{\"code\":\"%s\"}}\n", SF_SCHEMA, code);
    return 2;
}

static bool integer(const char *text, size_t *out) {
    if (!text || !*text) return false;
    for (const char *p = text; *p; p++) if (*p < '0' || *p > '9') return false;
    errno = 0;
    char *end = NULL;
    unsigned long n = strtoul(text, &end, 10);
    if (errno || !end || *end || n > SF_MAX_FACTS) return false;
    *out = (size_t)n;
    return true;
}

int main(int argc, char **argv) {
    const char *path = NULL;
    sf_query query = {.limit = 50};
    unsigned seen = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 && argc == 2) {
            puts("cbm-security-facts --path relative/File.java [--offset N --limit 1..200]\n"
                 "  [--expect-analysis SHA256] [--fact-id SHA256] < File.java\n"
                 "Reads at most 1 MiB of UTF-8 Java source from stdin. No files are opened.\n"
                 "Use --expect-analysis for continuation and fact lookup. Syntax facts are not vulnerability verdicts.");
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0 && argc == 2) {
            puts("cbm-security-facts " SF_VERSION " " SF_BUILD_ID); return 0;
        }
        if (i + 1 >= argc) return error("invalid_arguments");
        const char *option = argv[i++], *value = argv[i];
        unsigned bit = 0;
        if (strcmp(option, "--path") == 0) { bit = 1; path = value; }
        else if (strcmp(option, "--offset") == 0) { bit = 2; if (!integer(value, &query.offset)) return error("invalid_arguments"); }
        else if (strcmp(option, "--limit") == 0) { bit = 4; if (!integer(value, &query.limit)) return error("invalid_arguments"); }
        else if (strcmp(option, "--expect-analysis") == 0) { bit = 8; query.expected_analysis = value; }
        else if (strcmp(option, "--fact-id") == 0) { bit = 16; query.fact_id = value; }
        else return error("invalid_arguments");
        if (seen & bit) return error("duplicate_argument");
        seen |= bit;
    }
    if (!sf_path_valid(path) || !query.limit || query.limit > 200 ||
        (query.fact_id && (query.offset || !sf_digest_valid(query.fact_id))) ||
        (query.expected_analysis && !sf_digest_valid(query.expected_analysis))) return error("invalid_arguments");
    if ((query.offset || query.fact_id) && !query.expected_analysis) return error("analysis_id_required");
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) < 0 || _setmode(_fileno(stdout), _O_BINARY) < 0)
        return error("binary_stdio_unavailable");
#endif
    char *source = malloc(SF_MAX_SOURCE + 1);
    if (!source) return error("out_of_memory");
    size_t used = 0;
    while (used < SF_MAX_SOURCE + 1) {
        size_t n = fread(source + used, 1, SF_MAX_SOURCE + 1 - used, stdin);
        used += n;
        if (!n) break;
    }
    if (ferror(stdin) || used > SF_MAX_SOURCE) {
        const char *code = ferror(stdin) ? "source_read_failed" : "source_limit_exceeded";
        free(source); return error(code);
    }
    sf_document doc;
    if (!sf_document_init(&doc, source, used, path)) { free(source); return error("invalid_utf8_or_source"); }
    /* Reject stale requests before spending any parser work. */
    const char *failure = NULL;
    if (query.expected_analysis && strcmp(query.expected_analysis, doc.analysis_id) != 0) failure = "analysis_mismatch";
    if (!failure) failure = sf_extract_java(&doc);
    char *output = NULL;
    if (!failure) failure = sf_render(&doc, &query, &output);
    int rc = 0;
    if (failure) rc = error(failure);
    else if (fputs(output, stdout) == EOF || fflush(stdout) != 0) rc = 3;
    free(output); sf_document_free(&doc); free(source);
    return rc;
}
