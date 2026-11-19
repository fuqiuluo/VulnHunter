#include "engine.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static char *dup_slice(const char *s, size_t n) {
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static int push_token(TokenStream *ts, TokKind kind, const char *lex, size_t len,
                      int64_t i64, double f64, int line, int col) {
    if (ts->count == ts->cap) {
        size_t nc = ts->cap == 0 ? 64 : ts->cap * 2;
        Token *next = (Token *)realloc(ts->items, nc * sizeof(Token));
        if (!next) return -1;
        ts->items = next;
        ts->cap = nc;
    }
    char *copy = lex ? dup_slice(lex, len) : NULL;
    if (lex && !copy) return -1;
    ts->items[ts->count++] = (Token){.kind = kind, .lexeme = copy, .i64 = i64, .f64 = f64, .line = line, .col = col};
    return 0;
}

static TokKind classify_keyword(const char *s) {
    static const struct { const char *kw; TokKind kind; } kws[] = {
        {"CREATE", TOK_KW_CREATE}, {"TABLE", TOK_KW_TABLE}, {"INSERT", TOK_KW_INSERT},
        {"INTO", TOK_KW_INTO}, {"VALUES", TOK_KW_VALUES}, {"SELECT", TOK_KW_SELECT},
        {"FROM", TOK_KW_FROM}, {"WHERE", TOK_KW_WHERE}, {"GROUP", TOK_KW_GROUP},
        {"BY", TOK_KW_BY}, {"HAVING", TOK_KW_HAVING}, {"ORDER", TOK_KW_ORDER},
        {"ASC", TOK_KW_ASC}, {"DESC", TOK_KW_DESC}, {"LIMIT", TOK_KW_LIMIT},
        {"OFFSET", TOK_KW_OFFSET}, {"AS", TOK_KW_AS}, {"DISTINCT", TOK_KW_DISTINCT},
        {"AND", TOK_KW_AND}, {"OR", TOK_KW_OR}, {"NOT", TOK_KW_NOT},
        {"IS", TOK_KW_IS}, {"NULL", TOK_KW_NULL},
        {"INT", TOK_KW_INT}, {"INTEGER", TOK_KW_INT}, {"BIGINT", TOK_KW_INT},
        {"FLOAT", TOK_KW_FLOAT}, {"REAL", TOK_KW_FLOAT}, {"DOUBLE", TOK_KW_FLOAT},
        {"TEXT", TOK_KW_TEXT}, {"VARCHAR", TOK_KW_TEXT},
    };
    for (size_t i = 0; i < sizeof(kws) / sizeof(kws[0]); i++) {
        if (str_ieq(s, kws[i].kw)) return kws[i].kind;
    }
    return TOK_IDENT;
}

void token_stream_free(TokenStream *ts) {
    if (!ts) return;
    for (size_t i = 0; i < ts->count; i++) free(ts->items[i].lexeme);
    free(ts->items);
    memset(ts, 0, sizeof(*ts));
}

bool token_stream_at_end(const TokenStream *ts) {
    return !ts || ts->pos >= ts->count || ts->items[ts->pos].kind == TOK_EOF;
}

int sql_tokenize(const char *src, TokenStream *out, char *err, size_t err_cap) {
    memset(out, 0, sizeof(*out));
    int line = 1, col = 1;
    size_t i = 0;

    while (src[i] != '\0') {
        unsigned char c = (unsigned char)src[i];
        if (isspace(c)) {
            if (c == '\n') { line++; col = 1; } else col++;
            i++;
            continue;
        }
        if (src[i] == '-' && src[i + 1] == '-') {
            while (src[i] != '\0' && src[i] != '\n') i++;
            continue;
        }
        if (src[i] == '/' && src[i + 1] == '*') {
            int sline = line;
            i += 2; col += 2;
            bool closed = false;
            while (src[i] != '\0') {
                if (src[i] == '*' && src[i + 1] == '/') { i += 2; col += 2; closed = true; break; }
                if (src[i++] == '\n') { line++; col = 1; } else col++;
            }
            if (!closed) { snprintf(err, err_cap, "unterminated comment at line %d", sline); goto fail; }
            continue;
        }

        int tline = line, tcol = col;
        if (isalpha(c) || c == '_') {
            size_t start = i;
            while (isalnum((unsigned char)src[i]) || src[i] == '_') { i++; col++; }
            size_t len = i - start;
            if (len >= AGG_IDENT_MAX) { snprintf(err, err_cap, "identifier too long at %d:%d", tline, tcol); goto fail; }
            char buf[AGG_IDENT_MAX];
            memcpy(buf, src + start, len);
            buf[len] = '\0';
            if (push_token(out, classify_keyword(buf), buf, len, 0, 0.0, tline, tcol) != 0) goto fail;
            continue;
        }

        if (isdigit(c)) {
            size_t start = i;
            bool is_float = false;
            while (isdigit((unsigned char)src[i])) { i++; col++; }
            if (src[i] == '.' && isdigit((unsigned char)src[i + 1])) {
                is_float = true;
                i++; col++;
                while (isdigit((unsigned char)src[i])) { i++; col++; }
            }
            if (isalpha((unsigned char)src[i]) || src[i] == '_') {
                snprintf(err, err_cap, "invalid numeric literal at %d:%d", tline, tcol);
                goto fail;
            }
            char *num_str = dup_slice(src + start, i - start);
            if (!num_str) goto fail;
            errno = 0;
            char *endp = NULL;
            int rc;
            if (is_float) {
                double dv = strtod(num_str, &endp);
                if (errno == ERANGE || !endp || *endp != '\0') {
                    free(num_str);
                    snprintf(err, err_cap, "float literal out of range at %d:%d", tline, tcol);
                    goto fail;
                }
                rc = push_token(out, TOK_FLOAT_LIT, num_str, i - start, 0, dv, tline, tcol);
            } else {
                unsigned long long uv = strtoull(num_str, &endp, 10);
                if (errno == ERANGE || !endp || *endp != '\0' || uv > (unsigned long long)INT64_MAX) {
                    free(num_str);
                    snprintf(err, err_cap, "integer literal out of range at %d:%d", tline, tcol);
                    goto fail;
                }
                rc = push_token(out, TOK_INT_LIT, num_str, i - start, (int64_t)uv, 0.0, tline, tcol);
            }
            free(num_str);
            if (rc != 0) goto fail;
            continue;
        }

        if (src[i] == '\'') {
            i++; col++;
            size_t cap = 32, len = 0;
            char *buf = (char *)malloc(cap);
            if (!buf) goto fail;
            bool closed = false;
            while (src[i] != '\0') {
                if (len + 2 >= cap) {
                    cap *= 2;
                    char *nb = (char *)realloc(buf, cap);
                    if (!nb) { free(buf); goto fail; }
                    buf = nb;
                }
                if (src[i] == '\'') {
                    if (src[i + 1] == '\'') { buf[len++] = '\''; i += 2; col += 2; continue; }
                    i++; col++; closed = true; break;
                }
                if (src[i] == '\n') { line++; col = 1; } else col++;
                buf[len++] = src[i++];
            }
            if (!closed) { free(buf); snprintf(err, err_cap, "unterminated string at %d:%d", tline, tcol); goto fail; }
            buf[len] = '\0';
            int rc = push_token(out, TOK_STR_LIT, buf, len, 0, 0.0, tline, tcol);
            free(buf);
            if (rc != 0) goto fail;
            continue;
        }

        TokKind sym = TOK_EOF;
        size_t adv = 1;
        if ((src[i] == '!' && src[i + 1] == '=') || (src[i] == '<' && src[i + 1] == '>')) { sym = TOK_NEQ; adv = 2; }
        else if (src[i] == '<' && src[i + 1] == '=') { sym = TOK_LE; adv = 2; }
        else if (src[i] == '>' && src[i + 1] == '=') { sym = TOK_GE; adv = 2; }
        else {
            static const char ops[] = ",;().+-*/%=<>";
            static const TokKind kinds[] = {
                TOK_COMMA, TOK_SEMI, TOK_LPAREN, TOK_RPAREN, TOK_DOT,
                TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT, TOK_EQ, TOK_LT, TOK_GT
            };
            const char *hit = strchr(ops, src[i]);
            if (!hit) { snprintf(err, err_cap, "unexpected '%c' at %d:%d", src[i], tline, tcol); goto fail; }
            sym = kinds[(size_t)(hit - ops)];
        }
        if (push_token(out, sym, src + i, adv, 0, 0.0, tline, tcol) != 0) goto fail;
        i += adv;
        col += (int)adv;
    }

    if (push_token(out, TOK_EOF, "", 0, 0, 0.0, line, col) != 0) goto fail;
    return 0;

fail:
    token_stream_free(out);
    return -1;
}
