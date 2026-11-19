#include "engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_entire_stream(FILE *fp) {
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    while (true) {
        if (len + 2048 >= cap) {
            cap *= 2;
            char *next = (char *)realloc(buf, cap);
            if (!next) { free(buf); return NULL; }
            buf = next;
        }
        size_t n = fread(buf + len, 1, cap - len - 1, fp);
        len += n;
        if (n == 0) {
            if (ferror(fp)) { free(buf); return NULL; }
            break;
        }
    }
    buf[len] = '\0';
    return buf;
}

int main(int argc, char **argv) {
    char *sql_text = NULL;
    bool owned = false;
    if (argc == 3 && strcmp(argv[1], "-e") == 0) {
        sql_text = argv[2];
    } else if (argc == 2) {
        FILE *fp = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "rb");
        if (!fp) { fprintf(stderr, "ERROR: failed to open '%s'\n", argv[1]); return 1; }
        sql_text = read_entire_stream(fp);
        if (fp != stdin) fclose(fp);
        owned = true;
        if (!sql_text) { fprintf(stderr, "ERROR: failed to read SQL input\n"); return 1; }
    } else {
        fprintf(stderr, "Usage: %s <script.sql | - | -e \"SQL\">\n", argv[0]);
        return 1;
    }

    Catalog cat;
    catalog_init(&cat);
    char err[256] = {0};
    int rc = engine_run_script(&cat, sql_text, stdout, err, sizeof(err));
    if (rc != 0) fprintf(stderr, "ERROR: %s\n", err[0] ? err : "execution error");
    catalog_free(&cat);
    if (owned) free(sql_text);
    return rc == 0 ? 0 : 1;
}
