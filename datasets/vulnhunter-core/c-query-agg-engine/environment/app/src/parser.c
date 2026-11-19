#include "engine.h"

#include <stdlib.h>
#include <string.h>

static const Token *peek_tok(const TokenStream *ts) { return &ts->items[ts->pos]; }
static const Token *next_tok(TokenStream *ts) {
    const Token *t = &ts->items[ts->pos];
    if (t->kind != TOK_EOF) ts->pos++;
    return t;
}
static bool match_tok(TokenStream *ts, TokKind k) {
    if (peek_tok(ts)->kind != k) return false;
    next_tok(ts);
    return true;
}
static int expect_tok(TokenStream *ts, TokKind k, const char *desc, char *err, size_t err_cap) {
    const Token *t = peek_tok(ts);
    if (t->kind != k) {
        snprintf(err, err_cap, "expected %s near '%s' (line %d:%d)", desc, t->lexeme ? t->lexeme : "", t->line, t->col);
        return -1;
    }
    next_tok(ts);
    return 0;
}

static Expr *alloc_expr(ExprKind kind) {
    Expr *e = (Expr *)calloc(1, sizeof(Expr));
    if (e) *e = (Expr){.kind = kind, .bound_col = -1, .bound_group = -1, .bound_proj = -1, .agg_slot = -1};
    return e;
}

void ast_expr_free(Expr *e) {
    if (!e) return;
    val_free(&e->lit);
    ast_expr_free(e->left);
    ast_expr_free(e->right);
    free(e);
}

void ast_stmt_free(AstStmt *stmt) {
    if (!stmt) return;
    if (stmt->kind == STMT_INSERT) {
        for (size_t i = 0; i < stmt->insert_s.n_tuples; i++) {
            for (size_t j = 0; j < stmt->insert_s.tuples[i].n_vals; j++) val_free(&stmt->insert_s.tuples[i].vals[j]);
            free(stmt->insert_s.tuples[i].vals);
        }
        free(stmt->insert_s.tuples);
    } else if (stmt->kind == STMT_SELECT) {
        AstSelect *s = &stmt->select_s;
        for (size_t i = 0; i < s->n_proj; i++) ast_expr_free(s->proj_exprs[i]);
        ast_expr_free(s->where_expr);
        for (size_t i = 0; i < s->n_group; i++) ast_expr_free(s->group_exprs[i]);
        ast_expr_free(s->having_expr);
        for (size_t i = 0; i < s->n_order; i++) ast_expr_free(s->order_terms[i].expr);
    }
    memset(stmt, 0, sizeof(*stmt));
}

static Expr *parse_prec(TokenStream *ts, int min_prec, char *err, size_t err_cap);

static bool parse_agg_name(const char *name, AggFunc *fn_out) {
    static const struct { const char *n; AggFunc fn; } aggs[] = {
        {"COUNT", AGG_FN_COUNT}, {"SUM", AGG_FN_SUM}, {"AVG", AGG_FN_AVG}, {"MIN", AGG_FN_MIN}, {"MAX", AGG_FN_MAX}
    };
    for (size_t i = 0; i < 5; i++) {
        if (str_ieq(name, aggs[i].n)) { *fn_out = aggs[i].fn; return true; }
    }
    return false;
}

static Expr *parse_primary(TokenStream *ts, char *err, size_t err_cap) {
    const Token *t = peek_tok(ts);
    if (match_tok(ts, TOK_LPAREN)) {
        Expr *inner = parse_prec(ts, 1, err, err_cap);
        if (!inner || expect_tok(ts, TOK_RPAREN, "')'", err, err_cap) != 0) { ast_expr_free(inner); return NULL; }
        return inner;
    }
    if (match_tok(ts, TOK_KW_NULL)) return alloc_expr(EXPR_LITERAL);
    if (t->kind == TOK_INT_LIT || t->kind == TOK_FLOAT_LIT || t->kind == TOK_STR_LIT) {
        next_tok(ts);
        Expr *e = alloc_expr(EXPR_LITERAL);
        if (e) e->lit = (t->kind == TOK_INT_LIT) ? val_int(t->i64) : (t->kind == TOK_FLOAT_LIT) ? val_float(t->f64) : val_text_copy(t->lexeme);
        return e;
    }
    if (t->kind == TOK_IDENT) {
        next_tok(ts);
        AggFunc agg_fn;
        if (peek_tok(ts)->kind == TOK_LPAREN && parse_agg_name(t->lexeme, &agg_fn)) {
            next_tok(ts);
            Expr *e = alloc_expr(EXPR_AGG);
            if (!e) return NULL;
            e->agg_fn = agg_fn;
            if (agg_fn == AGG_FN_COUNT && match_tok(ts, TOK_STAR)) e->agg_star = true;
            else {
                e->agg_distinct = match_tok(ts, TOK_KW_DISTINCT);
                if (!(e->left = parse_prec(ts, 1, err, err_cap))) { ast_expr_free(e); return NULL; }
            }
            if (expect_tok(ts, TOK_RPAREN, "')'", err, err_cap) != 0) { ast_expr_free(e); return NULL; }
            return e;
        }
        Expr *e = alloc_expr(EXPR_COLUMN);
        if (!e) return NULL;
        if (match_tok(ts, TOK_DOT)) {
            if (peek_tok(ts)->kind != TOK_IDENT) { snprintf(err, err_cap, "expected column after '.'"); ast_expr_free(e); return NULL; }
            strncpy(e->table_qual, t->lexeme, AGG_IDENT_MAX - 1);
            strncpy(e->col_name, next_tok(ts)->lexeme, AGG_IDENT_MAX - 1);
        } else strncpy(e->col_name, t->lexeme, AGG_IDENT_MAX - 1);
        return e;
    }
    snprintf(err, err_cap, "unexpected token '%s' at %d:%d", t->lexeme ? t->lexeme : "", t->line, t->col);
    return NULL;
}

static Expr *parse_prefix(TokenStream *ts, char *err, size_t err_cap) {
    if (match_tok(ts, TOK_KW_NOT)) {
        Expr *sub = parse_prec(ts, 3, err, err_cap);
        if (!sub) return NULL;
        Expr *u = alloc_expr(EXPR_UNARY);
        if (!u) { ast_expr_free(sub); return NULL; }
        u->uop = UOP_NOT; u->left = sub; return u;
    }
    if (match_tok(ts, TOK_MINUS)) {
        Expr *sub = parse_prefix(ts, err, err_cap);
        if (!sub) return NULL;
        if (sub->kind == EXPR_LITERAL && sub->lit.type == VAL_INT) { sub->lit.i64 = -sub->lit.i64; return sub; }
        if (sub->kind == EXPR_LITERAL && sub->lit.type == VAL_FLOAT) { sub->lit.f64 = -sub->lit.f64; return sub; }
        Expr *u = alloc_expr(EXPR_UNARY);
        if (!u) { ast_expr_free(sub); return NULL; }
        u->uop = UOP_NEG; u->left = sub; return u;
    }
    if (match_tok(ts, TOK_PLUS)) return parse_prefix(ts, err, err_cap);
    return parse_primary(ts, err, err_cap);
}

static int binop_info(TokKind k, BinOp *op, int *prec) {
    static const struct { TokKind tk; BinOp bop; int pr; } tbl[] = {
        {TOK_KW_OR, BOP_OR, 1}, {TOK_KW_AND, BOP_AND, 2}, {TOK_EQ, BOP_EQ, 4}, {TOK_NEQ, BOP_NEQ, 4},
        {TOK_LT, BOP_LT, 4}, {TOK_LE, BOP_LE, 4}, {TOK_GT, BOP_GT, 4}, {TOK_GE, BOP_GE, 4},
        {TOK_PLUS, BOP_ADD, 5}, {TOK_MINUS, BOP_SUB, 5}, {TOK_STAR, BOP_MUL, 6}, {TOK_SLASH, BOP_DIV, 6}, {TOK_PERCENT, BOP_MOD, 6}
    };
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (tbl[i].tk == k) { *op = tbl[i].bop; *prec = tbl[i].pr; return 1; }
    }
    return 0;
}

static Expr *parse_prec(TokenStream *ts, int min_prec, char *err, size_t err_cap) {
    Expr *lhs = parse_prefix(ts, err, err_cap);
    while (lhs) {
        if (min_prec <= 4 && match_tok(ts, TOK_KW_IS)) {
            bool neg = match_tok(ts, TOK_KW_NOT);
            if (expect_tok(ts, TOK_KW_NULL, "NULL", err, err_cap) != 0) { ast_expr_free(lhs); return NULL; }
            Expr *u = alloc_expr(EXPR_UNARY);
            if (!u) { ast_expr_free(lhs); return NULL; }
            u->uop = neg ? UOP_IS_NOT_NULL : UOP_IS_NULL; u->left = lhs; lhs = u;
            continue;
        }
        BinOp op; int prec = 0;
        if (!binop_info(peek_tok(ts)->kind, &op, &prec) || prec < min_prec) break;
        next_tok(ts);
        Expr *rhs = parse_prec(ts, prec + 1, err, err_cap);
        if (!rhs) { ast_expr_free(lhs); return NULL; }
        Expr *bin = alloc_expr(EXPR_BINARY);
        if (!bin) { ast_expr_free(lhs); ast_expr_free(rhs); return NULL; }
        bin->bop = op; bin->left = lhs; bin->right = rhs; lhs = bin;
    }
    return lhs;
}

static int parse_signed_int(TokenStream *ts, int64_t *out, char *err, size_t err_cap) {
    bool neg = match_tok(ts, TOK_MINUS);
    if (!neg) match_tok(ts, TOK_PLUS);
    if (peek_tok(ts)->kind != TOK_INT_LIT) { snprintf(err, err_cap, "expected integer literal"); return -1; }
    int64_t v = next_tok(ts)->i64;
    *out = neg ? -v : v;
    return 0;
}

static int parse_create(TokenStream *ts, AstStmt *out, char *err, size_t err_cap) {
    out->kind = STMT_CREATE;
    if (expect_tok(ts, TOK_KW_TABLE, "TABLE", err, err_cap) != 0 || peek_tok(ts)->kind != TOK_IDENT) return -1;
    strncpy(out->create_s.table_name, next_tok(ts)->lexeme, AGG_IDENT_MAX - 1);
    if (expect_tok(ts, TOK_LPAREN, "'('", err, err_cap) != 0) return -1;
    do {
        if (out->create_s.n_cols >= AGG_MAX_COLS || peek_tok(ts)->kind != TOK_IDENT) return -1;
        ColumnDef *cd = &out->create_s.cols[out->create_s.n_cols];
        strncpy(cd->name, next_tok(ts)->lexeme, AGG_IDENT_MAX - 1);
        TokKind ck = next_tok(ts)->kind;
        if (ck == TOK_KW_INT) cd->type = COL_INT;
        else if (ck == TOK_KW_FLOAT) cd->type = COL_FLOAT;
        else if (ck == TOK_KW_TEXT) cd->type = COL_TEXT;
        else { snprintf(err, err_cap, "unsupported column type"); return -1; }
        out->create_s.n_cols++;
    } while (match_tok(ts, TOK_COMMA));
    return expect_tok(ts, TOK_RPAREN, "')'", err, err_cap);
}

static int parse_literal_val(TokenStream *ts, Val *out_val, char *err, size_t err_cap) {
    if (match_tok(ts, TOK_KW_NULL)) { *out_val = val_null(); return 0; }
    if (peek_tok(ts)->kind == TOK_STR_LIT) { *out_val = val_text_copy(next_tok(ts)->lexeme); return 0; }
    bool neg = match_tok(ts, TOK_MINUS);
    if (!neg) match_tok(ts, TOK_PLUS);
    const Token *t = peek_tok(ts);
    if (t->kind == TOK_INT_LIT) { next_tok(ts); *out_val = val_int(neg ? -t->i64 : t->i64); return 0; }
    if (t->kind == TOK_FLOAT_LIT) { next_tok(ts); *out_val = val_float(neg ? -t->f64 : t->f64); return 0; }
    snprintf(err, err_cap, "expected literal value in INSERT");
    return -1;
}

static int parse_insert(TokenStream *ts, AstStmt *out, char *err, size_t err_cap) {
    out->kind = STMT_INSERT;
    if (expect_tok(ts, TOK_KW_INTO, "INTO", err, err_cap) != 0 || peek_tok(ts)->kind != TOK_IDENT) return -1;
    strncpy(out->insert_s.table_name, next_tok(ts)->lexeme, AGG_IDENT_MAX - 1);
    if (expect_tok(ts, TOK_KW_VALUES, "VALUES", err, err_cap) != 0) return -1;
    do {
        if (expect_tok(ts, TOK_LPAREN, "'('", err, err_cap) != 0) return -1;
        Val tmp[AGG_MAX_COLS]; size_t nv = 0;
        do {
            if (nv >= AGG_MAX_COLS || parse_literal_val(ts, &tmp[nv], err, err_cap) != 0) {
                for (size_t k = 0; k < nv; k++) val_free(&tmp[k]);
                return -1;
            }
            nv++;
        } while (match_tok(ts, TOK_COMMA));
        if (expect_tok(ts, TOK_RPAREN, "')'", err, err_cap) != 0) {
            for (size_t k = 0; k < nv; k++) val_free(&tmp[k]);
            return -1;
        }
        AstInsert *ins = &out->insert_s;
        if (ins->n_tuples == ins->cap_tuples) {
            size_t nc = ins->cap_tuples == 0 ? 8 : ins->cap_tuples * 2;
            InsertTuple *nt = (InsertTuple *)realloc(ins->tuples, nc * sizeof(InsertTuple));
            if (!nt) { for (size_t k = 0; k < nv; k++) val_free(&tmp[k]); return -1; }
            ins->tuples = nt; ins->cap_tuples = nc;
        }
        Val *copied = (Val *)malloc(nv * sizeof(Val));
        if (!copied) { for (size_t k = 0; k < nv; k++) val_free(&tmp[k]); return -1; }
        memcpy(copied, tmp, nv * sizeof(Val));
        ins->tuples[ins->n_tuples++] = (InsertTuple){.vals = copied, .n_vals = nv};
    } while (match_tok(ts, TOK_COMMA));
    return 0;
}

static int parse_select(TokenStream *ts, AstStmt *out, char *err, size_t err_cap) {
    out->kind = STMT_SELECT;
    AstSelect *s = &out->select_s;
    do {
        if (s->n_proj >= AGG_MAX_SELECT_ITEMS || !(s->proj_exprs[s->n_proj] = parse_prec(ts, 1, err, err_cap))) return -1;
        if (match_tok(ts, TOK_KW_AS)) {
            if (peek_tok(ts)->kind != TOK_IDENT) { snprintf(err, err_cap, "expected alias"); return -1; }
            strncpy(s->proj_aliases[s->n_proj], next_tok(ts)->lexeme, AGG_IDENT_MAX - 1);
        } else if (peek_tok(ts)->kind == TOK_IDENT) {
            strncpy(s->proj_aliases[s->n_proj], next_tok(ts)->lexeme, AGG_IDENT_MAX - 1);
        }
        s->n_proj++;
    } while (match_tok(ts, TOK_COMMA));

    if (expect_tok(ts, TOK_KW_FROM, "FROM", err, err_cap) != 0 || peek_tok(ts)->kind != TOK_IDENT) return -1;
    strncpy(s->table_name, next_tok(ts)->lexeme, AGG_IDENT_MAX - 1);
    if (match_tok(ts, TOK_KW_WHERE) && !(s->where_expr = parse_prec(ts, 1, err, err_cap))) return -1;
    if (match_tok(ts, TOK_KW_GROUP)) {
        if (expect_tok(ts, TOK_KW_BY, "BY", err, err_cap) != 0) return -1;
        do {
            if (s->n_group >= AGG_MAX_GROUP_KEYS || !(s->group_exprs[s->n_group] = parse_prec(ts, 1, err, err_cap))) return -1;
            s->n_group++;
        } while (match_tok(ts, TOK_COMMA));
    }
    if (match_tok(ts, TOK_KW_HAVING) && !(s->having_expr = parse_prec(ts, 1, err, err_cap))) return -1;
    if (match_tok(ts, TOK_KW_ORDER)) {
        if (expect_tok(ts, TOK_KW_BY, "BY", err, err_cap) != 0) return -1;
        do {
            if (s->n_order >= AGG_MAX_ORDER_ITEMS) return -1;
            Expr *oe = parse_prec(ts, 1, err, err_cap);
            if (!oe) return -1;
            bool desc = match_tok(ts, TOK_KW_DESC);
            if (!desc) match_tok(ts, TOK_KW_ASC);
            s->order_terms[s->n_order++] = (OrderTerm){.expr = oe, .desc = desc};
        } while (match_tok(ts, TOK_COMMA));
    }
    if (match_tok(ts, TOK_KW_LIMIT)) { s->has_limit = true; if (parse_signed_int(ts, &s->limit_val, err, err_cap) != 0) return -1; }
    if (match_tok(ts, TOK_KW_OFFSET)) { s->has_offset = true; if (parse_signed_int(ts, &s->offset_val, err, err_cap) != 0) return -1; }
    return 0;
}

int sql_parse_stmt(TokenStream *ts, AstStmt *out, char *err, size_t err_cap) {
    memset(out, 0, sizeof(*out));
    while (match_tok(ts, TOK_SEMI)) {}
    int rc = -1;
    if (match_tok(ts, TOK_KW_CREATE)) rc = parse_create(ts, out, err, err_cap);
    else if (match_tok(ts, TOK_KW_INSERT)) rc = parse_insert(ts, out, err, err_cap);
    else if (match_tok(ts, TOK_KW_SELECT)) rc = parse_select(ts, out, err, err_cap);
    else snprintf(err, err_cap, "unexpected token '%s'", peek_tok(ts)->lexeme ? peek_tok(ts)->lexeme : "");
    if (rc != 0) { ast_stmt_free(out); return -1; }
    if (!match_tok(ts, TOK_SEMI) && peek_tok(ts)->kind != TOK_EOF) {
        snprintf(err, err_cap, "unexpected trailing token '%s'", peek_tok(ts)->lexeme ? peek_tok(ts)->lexeme : "");
        ast_stmt_free(out);
        return -1;
    }
    while (match_tok(ts, TOK_SEMI)) {}
    return 0;
}
