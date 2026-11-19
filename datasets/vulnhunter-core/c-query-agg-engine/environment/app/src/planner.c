#include "engine.h"

#include <string.h>

static bool expr_contains_agg(const Expr *e) {
    return e && (e->kind == EXPR_AGG || expr_contains_agg(e->left) || expr_contains_agg(e->right));
}

static bool expr_struct_equal(const Expr *a, const Expr *b) {
    if (!a || !b) return a == b;
    if (a->kind != b->kind) return false;
    switch (a->kind) {
        case EXPR_LITERAL: return val_key_equal(&a->lit, &b->lit);
        case EXPR_COLUMN:
            return (a->bound_col >= 0 && b->bound_col >= 0)
                 ? (a->bound_col == b->bound_col)
                 : (str_ieq(a->col_name, b->col_name) && str_ieq(a->table_qual, b->table_qual));
        case EXPR_UNARY:  return a->uop == b->uop && expr_struct_equal(a->left, b->left);
        case EXPR_BINARY: return a->bop == b->bop && expr_struct_equal(a->left, b->left) && expr_struct_equal(a->right, b->right);
        case EXPR_AGG:
            return a->agg_fn == b->agg_fn && a->agg_star == b->agg_star &&
                   a->agg_distinct == b->agg_distinct && expr_struct_equal(a->left, b->left);
    }
    return false;
}

static int resolve_columns(const Table *tbl, Expr *e, char *err, size_t err_cap) {
    if (!e) return 0;
    if (e->kind == EXPR_COLUMN) {
        if (e->table_qual[0] != '\0' && !str_ieq(e->table_qual, tbl->name)) {
            snprintf(err, err_cap, "unknown table qualifier '%s'", e->table_qual);
            return -1;
        }
        int idx = table_find_col(tbl, e->col_name);
        if (idx < 0) {
            snprintf(err, err_cap, "unknown column '%s' in table '%s'", e->col_name, tbl->name);
            return -1;
        }
        e->bound_col = idx;
        return 0;
    }
    return (resolve_columns(tbl, e->left, err, err_cap) == 0 &&
            resolve_columns(tbl, e->right, err, err_cap) == 0) ? 0 : -1;
}

static int register_agg_spec(QueryPlan *plan, Expr *agg_expr, char *err, size_t err_cap) {
    for (size_t i = 0; i < plan->n_aggs; i++) {
        const AggSpec *sp = &plan->aggs[i];
        if (sp->fn == agg_expr->agg_fn && sp->is_star == agg_expr->agg_star &&
            sp->is_distinct == agg_expr->agg_distinct && expr_struct_equal(sp->arg, agg_expr->left)) {
            agg_expr->agg_slot = (int)i;
            return 0;
        }
    }
    if (plan->n_aggs >= AGG_MAX_SPECS) {
        snprintf(err, err_cap, "too many distinct aggregate expressions in query");
        return -1;
    }
    size_t slot = plan->n_aggs++;
    plan->aggs[slot] = (AggSpec){.fn = agg_expr->agg_fn, .is_star = agg_expr->agg_star,
                                 .is_distinct = agg_expr->agg_distinct, .arg = agg_expr->left};
    agg_expr->agg_slot = (int)slot;
    return 0;
}

static int bind_expr(QueryPlan *plan, const Table *tbl, Expr *e,
                     bool allow_agg, bool require_grouped, bool in_agg_arg,
                     char *err, size_t err_cap) {
    if (!e) return 0;
    if (require_grouped && !in_agg_arg && e->kind != EXPR_AGG) {
        for (size_t g = 0; g < plan->n_group; g++) {
            if (expr_struct_equal(e, plan->group_exprs[g])) { e->bound_group = (int)g; return 0; }
        }
    }
    switch (e->kind) {
        case EXPR_LITERAL: return 0;
        case EXPR_COLUMN:
            if (require_grouped && !in_agg_arg) {
                snprintf(err, err_cap, "column '%s' must appear in GROUP BY or aggregate", e->col_name);
                return -1;
            }
            return 0;
        case EXPR_UNARY:
            return bind_expr(plan, tbl, e->left, allow_agg, require_grouped, in_agg_arg, err, err_cap);
        case EXPR_BINARY:
            return (bind_expr(plan, tbl, e->left, allow_agg, require_grouped, in_agg_arg, err, err_cap) == 0 &&
                    bind_expr(plan, tbl, e->right, allow_agg, require_grouped, in_agg_arg, err, err_cap) == 0) ? 0 : -1;
        case EXPR_AGG:
            if (!allow_agg || in_agg_arg) { snprintf(err, err_cap, "invalid aggregate placement"); return -1; }
            if (!e->agg_star && bind_expr(plan, tbl, e->left, true, false, true, err, err_cap) != 0) return -1;
            return register_agg_spec(plan, e, err, err_cap);
    }
    return 0;
}

int build_query_plan(Catalog *cat, AstSelect *stmt, QueryPlan *plan, char *err, size_t err_cap) {
    memset(plan, 0, sizeof(*plan));
    const Table *tbl = catalog_find_table(cat, stmt->table_name);
    if (!tbl) { snprintf(err, err_cap, "unknown table '%s'", stmt->table_name); return -1; }
    *plan = (QueryPlan){
        .table = tbl, .proj_exprs = stmt->proj_exprs, .n_proj = stmt->n_proj,
        .where_expr = stmt->where_expr, .group_exprs = stmt->group_exprs, .n_group = stmt->n_group,
        .having_expr = stmt->having_expr, .order_terms = stmt->order_terms, .n_order = stmt->n_order,
    };

    bool has_agg = (stmt->n_group > 0) || (stmt->having_expr != NULL);
    for (size_t i = 0; i < stmt->n_proj && !has_agg; i++) has_agg = expr_contains_agg(stmt->proj_exprs[i]);
    for (size_t i = 0; i < stmt->n_order && !has_agg; i++) has_agg = expr_contains_agg(stmt->order_terms[i].expr);
    plan->is_aggregated = has_agg;

    if (stmt->where_expr && (resolve_columns(tbl, stmt->where_expr, err, err_cap) != 0 ||
        bind_expr(plan, tbl, stmt->where_expr, false, false, false, err, err_cap) != 0)) return -1;

    for (size_t g = 0; g < stmt->n_group; g++) {
        if (resolve_columns(tbl, stmt->group_exprs[g], err, err_cap) != 0 ||
            bind_expr(plan, tbl, stmt->group_exprs[g], false, false, false, err, err_cap) != 0) return -1;
    }
    for (size_t i = 0; i < stmt->n_proj; i++) {
        if (resolve_columns(tbl, stmt->proj_exprs[i], err, err_cap) != 0 ||
            bind_expr(plan, tbl, stmt->proj_exprs[i], true, plan->is_aggregated, false, err, err_cap) != 0) return -1;
    }

    if (plan->is_aggregated) {
        size_t width_floor = tbl->n_cols > 0 ? tbl->n_cols : 1;
        plan->acc_stride = plan->n_aggs > width_floor ? plan->n_aggs : width_floor;
    }

    if (stmt->having_expr && (resolve_columns(tbl, stmt->having_expr, err, err_cap) != 0 ||
        bind_expr(plan, tbl, stmt->having_expr, true, plan->is_aggregated, false, err, err_cap) != 0)) return -1;

    for (size_t i = 0; i < stmt->n_order; i++) {
        Expr *oe = stmt->order_terms[i].expr;
        if (oe->kind == EXPR_COLUMN && oe->table_qual[0] == '\0') {
            int alias_idx = -1;
            for (size_t p = 0; p < stmt->n_proj; p++) {
                if (stmt->proj_aliases[p][0] != '\0' && str_ieq(oe->col_name, stmt->proj_aliases[p])) {
                    alias_idx = (int)p;
                    break;
                }
            }
            if (alias_idx >= 0) { oe->bound_proj = alias_idx; continue; }
        }
        if (resolve_columns(tbl, oe, err, err_cap) != 0 ||
            bind_expr(plan, tbl, oe, plan->is_aggregated, plan->is_aggregated, false, err, err_cap) != 0) return -1;
    }

    plan->has_limit = stmt->has_limit;
    plan->limit_val = stmt->limit_val;
    plan->offset_val = stmt->has_offset ? stmt->offset_val : 0;
    return 0;
}
