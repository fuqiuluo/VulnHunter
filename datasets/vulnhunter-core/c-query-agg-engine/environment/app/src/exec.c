#include "engine.h"

#include <stdlib.h>
#include <string.h>

typedef struct { const Row *row; const Val *group_keys, *agg_vals, *proj_vals; } EvalCtx;
typedef struct { Val *cols, *sort_keys; size_t seq; } ResultRow;
typedef struct { ResultRow *rows; size_t n_rows, cap_rows, n_cols, n_sort; } ResultSet;
typedef enum { TRUTH_FALSE = 0, TRUTH_TRUE = 1, TRUTH_UNKNOWN = 2 } SqlTruth;

static SqlTruth val_to_truth(const Val *v) {
    if (!v || v->type == VAL_NULL) return TRUTH_UNKNOWN;
    if (v->type == VAL_INT) return v->i64 != 0 ? TRUTH_TRUE : TRUTH_FALSE;
    if (v->type == VAL_FLOAT) return v->f64 != 0.0 ? TRUTH_TRUE : TRUTH_FALSE;
    return (v->text && v->text[0] != '\0') ? TRUTH_TRUE : TRUTH_FALSE;
}

static void free_val_slice(Val *arr, size_t n) {
    if (!arr) return;
    for (size_t i = 0; i < n; i++) val_free(&arr[i]);
}

static int eval_expr(const EvalCtx *ctx, const Expr *e, Val *out, char *err, size_t err_cap) {
    if (!e) { *out = val_null(); return 0; }
    if (ctx->proj_vals && e->bound_proj >= 0) { *out = val_clone(&ctx->proj_vals[e->bound_proj]); return 0; }
    if (ctx->group_keys && e->bound_group >= 0) { *out = val_clone(&ctx->group_keys[e->bound_group]); return 0; }

    switch (e->kind) {
        case EXPR_LITERAL:
            *out = val_clone(&e->lit);
            return 0;
        case EXPR_COLUMN:
            if (!ctx->row || e->bound_col < 0 || (size_t)e->bound_col >= ctx->row->n_vals) {
                snprintf(err, err_cap, "unbound column '%s'", e->col_name);
                return -1;
            }
            *out = val_clone(&ctx->row->vals[e->bound_col]);
            return 0;
        case EXPR_AGG:
            if (!ctx->agg_vals || e->agg_slot < 0) { snprintf(err, err_cap, "unbound aggregate"); return -1; }
            *out = val_clone(&ctx->agg_vals[e->agg_slot]);
            return 0;
        case EXPR_UNARY: {
            Val sub = val_null();
            if (eval_expr(ctx, e->left, &sub, err, err_cap) != 0) return -1;
            if (e->uop == UOP_IS_NULL || e->uop == UOP_IS_NOT_NULL) {
                bool n = (sub.type == VAL_NULL);
                val_free(&sub);
                *out = val_int((e->uop == UOP_IS_NULL ? n : !n) ? 1 : 0);
                return 0;
            }
            if (e->uop == UOP_NOT) {
                SqlTruth tr = val_to_truth(&sub);
                val_free(&sub);
                *out = (tr == TRUTH_UNKNOWN) ? val_null() : val_int(tr == TRUTH_TRUE ? 0 : 1);
                return 0;
            }
            if (sub.type == VAL_NULL) { *out = val_null(); return 0; }
            if (e->uop == UOP_NEG) {
                if (sub.type == VAL_INT) { *out = val_int(-sub.i64); return 0; }
                if (sub.type == VAL_FLOAT) { *out = val_float(-sub.f64); return 0; }
                val_free(&sub);
                snprintf(err, err_cap, "unary '-' requires numeric operand");
                return -1;
            }
            *out = sub;
            return 0;
        }
        case EXPR_BINARY: {
            Val lv = val_null(), rv = val_null();
            if (eval_expr(ctx, e->left, &lv, err, err_cap) != 0) return -1;
            if (eval_expr(ctx, e->right, &rv, err, err_cap) != 0) { val_free(&lv); return -1; }

            if (e->bop == BOP_AND || e->bop == BOP_OR) {
                SqlTruth lt = val_to_truth(&lv), rt = val_to_truth(&rv);
                val_free(&lv); val_free(&rv);
                if (e->bop == BOP_AND) {
                    *out = (lt == TRUTH_FALSE || rt == TRUTH_FALSE) ? val_int(0)
                         : (lt == TRUTH_TRUE && rt == TRUTH_TRUE)   ? val_int(1) : val_null();
                } else {
                    *out = (lt == TRUTH_TRUE || rt == TRUTH_TRUE)   ? val_int(1)
                         : (lt == TRUTH_FALSE && rt == TRUTH_FALSE) ? val_int(0) : val_null();
                }
                return 0;
            }
            if (lv.type == VAL_NULL || rv.type == VAL_NULL) {
                val_free(&lv); val_free(&rv);
                *out = val_null();
                return 0;
            }
            if (e->bop >= BOP_EQ && e->bop <= BOP_GE) {
                bool ok_t = ((lv.type == VAL_INT || lv.type == VAL_FLOAT) &&
                             (rv.type == VAL_INT || rv.type == VAL_FLOAT)) ||
                            (lv.type == VAL_TEXT && rv.type == VAL_TEXT);
                if (!ok_t) { val_free(&lv); val_free(&rv); snprintf(err, err_cap, "incompatible comparison"); return -1; }
                int cmp = val_compare_sql(&lv, &rv);
                val_free(&lv); val_free(&rv);
                bool ok = (e->bop == BOP_EQ && cmp == 0) || (e->bop == BOP_NEQ && cmp != 0) ||
                          (e->bop == BOP_LT && cmp < 0)  || (e->bop == BOP_LE && cmp <= 0) ||
                          (e->bop == BOP_GT && cmp > 0)  || (e->bop == BOP_GE && cmp >= 0);
                *out = val_int(ok ? 1 : 0);
                return 0;
            }
            if ((lv.type != VAL_INT && lv.type != VAL_FLOAT) || (rv.type != VAL_INT && rv.type != VAL_FLOAT)) {
                val_free(&lv); val_free(&rv);
                snprintf(err, err_cap, "arithmetic requires numeric operands");
                return -1;
            }
            if (lv.type == VAL_FLOAT || rv.type == VAL_FLOAT) {
                if (e->bop == BOP_MOD) { snprintf(err, err_cap, "modulo requires integers"); return -1; }
                double a = (lv.type == VAL_INT) ? (double)lv.i64 : lv.f64;
                double b = (rv.type == VAL_INT) ? (double)rv.i64 : rv.f64;
                if (e->bop == BOP_DIV && b == 0.0) { snprintf(err, err_cap, "division by zero"); return -1; }
                *out = val_float(e->bop == BOP_ADD ? a + b : e->bop == BOP_SUB ? a - b : e->bop == BOP_MUL ? a * b : a / b);
                return 0;
            }
            int64_t a = lv.i64, b = rv.i64;
            if ((e->bop == BOP_DIV || e->bop == BOP_MOD) && b == 0) { snprintf(err, err_cap, "division by zero"); return -1; }
            switch (e->bop) {
                case BOP_ADD: *out = val_int(a + b); break;
                case BOP_SUB: *out = val_int(a - b); break;
                case BOP_MUL: *out = val_int(a * b); break;
                case BOP_DIV: *out = val_int(a / b); break;
                case BOP_MOD: *out = val_int(a % b); break;
                default: break;
            }
            return 0;
        }
    }
    return 0;
}

static void result_set_free(ResultSet *rs) {
    if (!rs) return;
    for (size_t r = 0; r < rs->n_rows; r++) {
        free_val_slice(rs->rows[r].cols, rs->n_cols); free(rs->rows[r].cols);
        free_val_slice(rs->rows[r].sort_keys, rs->n_sort); free(rs->rows[r].sort_keys);
    }
    free(rs->rows);
    memset(rs, 0, sizeof(*rs));
}

static const OrderTerm *g_active_order = NULL;
static size_t g_active_n_order = 0;

static int compare_result_rows(const void *pa, const void *pb) {
    const ResultRow *a = (const ResultRow *)pa, *b = (const ResultRow *)pb;
    for (size_t i = 0; i < g_active_n_order; i++) {
        int cmp = val_compare_sql(&a->sort_keys[i], &b->sort_keys[i]);
        if (cmp != 0) return g_active_order[i].desc ? -cmp : cmp;
    }
    return (a->seq > b->seq) - (a->seq < b->seq);
}

static void print_row_pipe(FILE *fp, const ResultRow *r, size_t n_cols) {
    for (size_t c = 0; c < n_cols; c++) {
        if (c > 0) fputc('|', fp);
        const Val *v = &r->cols[c];
        if (v->type == VAL_NULL) fputs("NULL", fp);
        else if (v->type == VAL_INT) fprintf(fp, "%lld", (long long)v->i64);
        else if (v->type == VAL_FLOAT) fprintf(fp, "%.2f", v->f64);
        else fputs(v->text ? v->text : "", fp);
    }
    fputc('\n', fp);
}

static int materialize_row(const QueryPlan *plan, const EvalCtx *base_ctx,
                           ResultSet *rs, size_t seq, char *err, size_t err_cap) {
    Val *cols = (Val *)calloc(plan->n_proj, sizeof(Val));
    if (!cols) return -1;
    for (size_t p = 0; p < plan->n_proj; p++) {
        if (eval_expr(base_ctx, plan->proj_exprs[p], &cols[p], err, err_cap) != 0) {
            free_val_slice(cols, p); free(cols); return -1;
        }
    }
    Val *skeys = NULL;
    if (plan->n_order > 0) {
        skeys = (Val *)calloc(plan->n_order, sizeof(Val));
        if (!skeys) { free_val_slice(cols, plan->n_proj); free(cols); return -1; }
        EvalCtx ord_ctx = *base_ctx;
        ord_ctx.proj_vals = cols;
        for (size_t o = 0; o < plan->n_order; o++) {
            if (eval_expr(&ord_ctx, plan->order_terms[o].expr, &skeys[o], err, err_cap) != 0) {
                free_val_slice(skeys, o); free(skeys);
                free_val_slice(cols, plan->n_proj); free(cols);
                return -1;
            }
        }
    }
    if (rs->n_rows == rs->cap_rows) {
        size_t nc = rs->cap_rows == 0 ? 16 : rs->cap_rows * 2;
        ResultRow *nr = (ResultRow *)realloc(rs->rows, nc * sizeof(ResultRow));
        if (!nr) {
            free_val_slice(cols, plan->n_proj); free(cols);
            free_val_slice(skeys, plan->n_order); free(skeys);
            return -1;
        }
        rs->rows = nr; rs->cap_rows = nc;
    }
    rs->rows[rs->n_rows++] = (ResultRow){.cols = cols, .sort_keys = skeys, .seq = seq};
    return 0;
}

static int eval_filter(const EvalCtx *ctx, const Expr *pred, bool *keep_out, char *err, size_t err_cap) {
    if (!pred) { *keep_out = true; return 0; }
    Val v = val_null();
    if (eval_expr(ctx, pred, &v, err, err_cap) != 0) return -1;
    *keep_out = (val_to_truth(&v) == TRUTH_TRUE);
    val_free(&v);
    return 0;
}

int execute_query_plan(const QueryPlan *plan, FILE *out_fp, char *err, size_t err_cap) {
    const Table *tbl = plan->table;
    ResultSet rs = {.n_cols = plan->n_proj, .n_sort = plan->n_order};

    if (!plan->is_aggregated) {
        size_t seq = 0;
        for (size_t r = 0; r < tbl->n_rows; r++) {
            EvalCtx rctx = {.row = &tbl->rows[r]};
            bool keep = true;
            if (eval_filter(&rctx, plan->where_expr, &keep, err, err_cap) != 0 ||
                (keep && materialize_row(plan, &rctx, &rs, seq++, err, err_cap) != 0)) {
                result_set_free(&rs);
                return -1;
            }
        }
    } else {
        HashGroupTable ht;
        if (hash_group_init(&ht, plan->n_group, plan->acc_stride) != 0) return -1;
        for (size_t r = 0; r < tbl->n_rows; r++) {
            EvalCtx rctx = {.row = &tbl->rows[r]};
            bool keep = true;
            if (eval_filter(&rctx, plan->where_expr, &keep, err, err_cap) != 0) { hash_group_free(&ht); return -1; }
            if (!keep) continue;

            Val key_buf[AGG_MAX_GROUP_KEYS] = {0};
            for (size_t g = 0; g < plan->n_group; g++) {
                if (eval_expr(&rctx, plan->group_exprs[g], &key_buf[g], err, err_cap) != 0) {
                    free_val_slice(key_buf, g); hash_group_free(&ht); return -1;
                }
            }
            GroupBucket *grp = hash_group_get_or_create(&ht, key_buf, err, err_cap);
            free_val_slice(key_buf, plan->n_group);
            if (!grp) { hash_group_free(&ht); return -1; }

            for (size_t a = 0; a < plan->n_aggs; a++) {
                const AggSpec *spec = &plan->aggs[a];
                Val arg_v = val_null();
                if (!spec->is_star && eval_expr(&rctx, spec->arg, &arg_v, err, err_cap) != 0) {
                    hash_group_free(&ht); return -1;
                }
                int step_rc = agg_accum_step(&grp->accs[a], spec, &arg_v, err, err_cap);
                val_free(&arg_v);
                if (step_rc != 0) { hash_group_free(&ht); return -1; }
            }
        }
        if (ht.count == 0 && plan->n_group == 0 && !hash_group_get_or_create(&ht, NULL, err, err_cap)) {
            hash_group_free(&ht);
            return -1;
        }
        Val empty_dummy = val_null();
        for (size_t gi = 0; gi < ht.count; gi++) {
            const GroupBucket *grp = hash_group_at(&ht, gi);
            Val agg_vals[AGG_MAX_SPECS] = {0};
            for (size_t a = 0; a < plan->n_aggs; a++) agg_vals[a] = agg_accum_finalize(&grp->accs[a], &plan->aggs[a]);
            EvalCtx gctx = {.group_keys = plan->n_group > 0 ? grp->keys : &empty_dummy, .agg_vals = agg_vals};
            bool keep = true;
            int rc = eval_filter(&gctx, plan->having_expr, &keep, err, err_cap);
            if (rc == 0 && keep) rc = materialize_row(plan, &gctx, &rs, gi, err, err_cap);
            free_val_slice(agg_vals, plan->n_aggs);
            if (rc != 0) { hash_group_free(&ht); result_set_free(&rs); return -1; }
        }
        hash_group_free(&ht);
    }

    if (plan->n_order > 0 && rs.n_rows > 1) {
        g_active_order = plan->order_terms;
        g_active_n_order = plan->n_order;
        qsort(rs.rows, rs.n_rows, sizeof(ResultRow), compare_result_rows);
    }

    int64_t start = plan->offset_val;
    int64_t end = plan->has_limit ? (plan->offset_val + plan->limit_val) : (int64_t)rs.n_rows;
    if (end > (int64_t)rs.n_rows) end = (int64_t)rs.n_rows;
    for (int64_t i = start; i < end; i++) print_row_pipe(out_fp, &rs.rows[i], rs.n_cols);

    result_set_free(&rs);
    return 0;
}

int engine_run_script(Catalog *cat, const char *sql, FILE *out_fp, char *err, size_t err_cap) {
    TokenStream ts;
    if (sql_tokenize(sql, &ts, err, err_cap) != 0) return -1;
    while (!token_stream_at_end(&ts)) {
        if (ts.items[ts.pos].kind == TOK_SEMI) { ts.pos++; continue; }
        AstStmt stmt;
        if (sql_parse_stmt(&ts, &stmt, err, err_cap) != 0) { token_stream_free(&ts); return -1; }
        int rc = 0;
        if (stmt.kind == STMT_CREATE) rc = catalog_exec_create(cat, &stmt.create_s, err, err_cap);
        else if (stmt.kind == STMT_INSERT) rc = catalog_exec_insert(cat, &stmt.insert_s, err, err_cap);
        else {
            QueryPlan plan;
            rc = build_query_plan(cat, &stmt.select_s, &plan, err, err_cap);
            if (rc == 0) rc = execute_query_plan(&plan, out_fp, err, err_cap);
        }
        ast_stmt_free(&stmt);
        if (rc != 0) { token_stream_free(&ts); return -1; }
    }
    token_stream_free(&ts);
    return 0;
}
