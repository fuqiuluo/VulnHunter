#include "engine.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

int str_ieq(const char *a, const char *b) {
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

Val val_null(void)  { return (Val){.type = VAL_NULL}; }
Val val_int(int64_t x) { return (Val){.type = VAL_INT, .i64 = x}; }
Val val_float(double x) { return (Val){.type = VAL_FLOAT, .f64 = (x == 0.0) ? 0.0 : x}; }

Val val_text_copy(const char *s) {
    Val v = {.type = VAL_TEXT};
    size_t n = s ? strlen(s) : 0;
    v.text = (char *)malloc(n + 1);
    if (v.text) {
        if (n > 0) memcpy(v.text, s, n);
        v.text[n] = '\0';
    }
    return v;
}

Val val_clone(const Val *src) {
    if (!src) return val_null();
    return (src->type == VAL_TEXT) ? val_text_copy(src->text ? src->text : "") : *src;
}

void val_free(Val *v) {
    if (!v) return;
    if (v->type == VAL_TEXT) free(v->text);
    *v = val_null();
}

int val_compare_sql(const Val *a, const Val *b) {
    if (a->type == VAL_NULL || b->type == VAL_NULL) return (a->type != VAL_NULL) - (b->type != VAL_NULL);
    if (a->type == VAL_INT && b->type == VAL_INT) return (a->i64 > b->i64) - (a->i64 < b->i64);
    if ((a->type == VAL_INT || a->type == VAL_FLOAT) && (b->type == VAL_INT || b->type == VAL_FLOAT)) {
        double da = (a->type == VAL_INT) ? (double)a->i64 : a->f64;
        double db = (b->type == VAL_INT) ? (double)b->i64 : b->f64;
        return (da > db) - (da < db);
    }
    if (a->type == VAL_TEXT && b->type == VAL_TEXT) {
        int c = strcmp(a->text ? a->text : "", b->text ? b->text : "");
        return (c > 0) - (c < 0);
    }
    return (int)a->type - (int)b->type;
}

bool val_key_equal(const Val *a, const Val *b) {
    if (a->type != b->type) return false;
    if (a->type == VAL_NULL) return true;
    if (a->type == VAL_INT) return a->i64 == b->i64;
    if (a->type == VAL_FLOAT) return a->f64 == b->f64;
    return strcmp(a->text ? a->text : "", b->text ? b->text : "") == 0;
}

static uint64_t fnv1a_step(uint64_t h, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    for (size_t i = 0; i < len; i++) h = (h ^ p[i]) * 1099511628211ULL;
    return h;
}

uint64_t val_hash(const Val *v) {
    uint8_t tag = (uint8_t)v->type;
    uint64_t h = fnv1a_step(14695981039346656037ULL, &tag, 1);
    if (v->type == VAL_INT) return fnv1a_step(h, &v->i64, sizeof(v->i64));
    if (v->type == VAL_FLOAT) {
        double norm = (v->f64 == 0.0) ? 0.0 : v->f64;
        return fnv1a_step(h, &norm, sizeof(norm));
    }
    if (v->type == VAL_TEXT && v->text) return fnv1a_step(h, v->text, strlen(v->text));
    return h;
}

void catalog_init(Catalog *cat) { memset(cat, 0, sizeof(*cat)); }

void catalog_free(Catalog *cat) {
    if (!cat) return;
    for (size_t t = 0; t < cat->n_tables; t++) {
        Table *tbl = &cat->tables[t];
        for (size_t r = 0; r < tbl->n_rows; r++) {
            for (size_t c = 0; c < tbl->rows[r].n_vals; c++) val_free(&tbl->rows[r].vals[c]);
            free(tbl->rows[r].vals);
        }
        free(tbl->rows);
    }
    memset(cat, 0, sizeof(*cat));
}

Table *catalog_find_table(Catalog *cat, const char *name) {
    for (size_t i = 0; i < cat->n_tables; i++) {
        if (str_ieq(cat->tables[i].name, name)) return &cat->tables[i];
    }
    return NULL;
}

int table_find_col(const Table *tbl, const char *name) {
    for (size_t i = 0; i < tbl->n_cols; i++) {
        if (str_ieq(tbl->cols[i].name, name)) return (int)i;
    }
    return -1;
}

int catalog_exec_create(Catalog *cat, const AstCreate *stmt, char *err, size_t err_cap) {
    if (catalog_find_table(cat, stmt->table_name)) {
        snprintf(err, err_cap, "table '%s' already exists", stmt->table_name);
        return -1;
    }
    if (cat->n_tables >= AGG_MAX_TABLES || stmt->n_cols == 0) {
        snprintf(err, err_cap, "invalid CREATE TABLE '%s'", stmt->table_name);
        return -1;
    }
    for (size_t i = 0; i < stmt->n_cols; i++) {
        for (size_t j = i + 1; j < stmt->n_cols; j++) {
            if (str_ieq(stmt->cols[i].name, stmt->cols[j].name)) {
                snprintf(err, err_cap, "duplicate column '%s'", stmt->cols[i].name);
                return -1;
            }
        }
    }
    Table *tbl = &cat->tables[cat->n_tables++];
    memset(tbl, 0, sizeof(*tbl));
    strncpy(tbl->name, stmt->table_name, AGG_IDENT_MAX - 1);
    tbl->n_cols = stmt->n_cols;
    for (size_t i = 0; i < stmt->n_cols; i++) tbl->cols[i] = stmt->cols[i];
    return 0;
}

int catalog_exec_insert(Catalog *cat, const AstInsert *stmt, char *err, size_t err_cap) {
    Table *tbl = catalog_find_table(cat, stmt->table_name);
    if (!tbl) { snprintf(err, err_cap, "unknown table '%s'", stmt->table_name); return -1; }
    for (size_t i = 0; i < stmt->n_tuples; i++) {
        const InsertTuple *tup = &stmt->tuples[i];
        if (tup->n_vals != tbl->n_cols) { snprintf(err, err_cap, "column count mismatch"); return -1; }
        for (size_t c = 0; c < tbl->n_cols; c++) {
            ValType vt = tup->vals[c].type;
            ColType ct = tbl->cols[c].type;
            if (vt != VAL_NULL && ((ct == COL_INT && vt != VAL_INT) ||
                (ct == COL_FLOAT && vt != VAL_INT && vt != VAL_FLOAT) ||
                (ct == COL_TEXT && vt != VAL_TEXT))) {
                snprintf(err, err_cap, "type mismatch for column '%s'", tbl->cols[c].name);
                return -1;
            }
        }
    }
    for (size_t i = 0; i < stmt->n_tuples; i++) {
        if (tbl->n_rows == tbl->cap_rows) {
            size_t nc = tbl->cap_rows == 0 ? 16 : tbl->cap_rows * 2;
            Row *nr = (Row *)realloc(tbl->rows, nc * sizeof(Row));
            if (!nr) return -1;
            tbl->rows = nr;
            tbl->cap_rows = nc;
        }
        Val *rvals = (Val *)calloc(tbl->n_cols, sizeof(Val));
        if (!rvals) return -1;
        for (size_t c = 0; c < tbl->n_cols; c++) {
            const Val *sv = &stmt->tuples[i].vals[c];
            rvals[c] = (tbl->cols[c].type == COL_FLOAT && sv->type == VAL_INT)
                     ? val_float((double)sv->i64) : val_clone(sv);
        }
        tbl->rows[tbl->n_rows++] = (Row){.vals = rvals, .n_vals = tbl->n_cols};
    }
    return 0;
}
