#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": [
    "src/planner.c",
    "src/hash_group.c",
    "src/exec.c"
  ],
  "findings": [
    {
      "file": "src/planner.c",
      "function": "build_query_plan",
      "issue": "plan->acc_stride was computed immediately after binding SELECT projections using max(n_aggs, n_cols), before HAVING and ORDER BY clauses registered implicit aggregate expressions, causing heap buffer out-of-bounds writes into per-group accumulator arrays when total distinct aggregates exceeded that pre-rewrite bound. Fixed by sizing acc_stride after all clauses are bound and rejecting negative LIMIT/OFFSET values."
    },
    {
      "file": "src/hash_group.c",
      "function": "hash_group_rehash",
      "issue": "Rehashing the open-addressed group bucket array freed ht->buckets without updating the GroupBucket pointers stored in ht->order, leaving dangling pointers read during post-aggregation group iteration when distinct groups exceeded initial load capacity. Also hardened agg_accum_step against signed 64-bit integer addition wrap in SUM/AVG."
    },
    {
      "file": "src/exec.c",
      "function": "execute_query_plan",
      "issue": "Pagination computed plan->offset_val + plan->limit_val in signed int64_t and allowed negative offsets/limits, triggering signed overflow UB and invalid slice bounds; eval_expr also lacked 64-bit signed overflow checks on unary negation, addition, subtraction, multiplication, and INT64_MIN / -1 division."
    }
  ],
  "summary": "Fixed implicit aggregate accumulator sizing in build_query_plan after HAVING/ORDER BY binding, updated group order pointers across hash_group_rehash, and hardened 64-bit arithmetic and pagination bounds across hash_group.c and exec.c."
}
EOF

cat > "$APP_DIR/src/planner.c" <<'EOF'
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
    if ((stmt->has_limit && stmt->limit_val < 0) || (stmt->has_offset && stmt->offset_val < 0)) {
        snprintf(err, err_cap, "LIMIT and OFFSET must be non-negative");
        return -1;
    }

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

    if (plan->is_aggregated) {
        plan->acc_stride = plan->n_aggs > 0 ? plan->n_aggs : 1;
    }

    plan->has_limit = stmt->has_limit;
    plan->limit_val = stmt->limit_val;
    plan->offset_val = stmt->has_offset ? stmt->offset_val : 0;
    return 0;
}
EOF

cat > "$APP_DIR/src/hash_group.c" <<'EOF'
#include "engine.h"

#include <stdlib.h>
#include <string.h>

#define INITIAL_GROUP_BUCKETS 64
#define INITIAL_DIST_SLOTS    16

static int distinct_rehash(DistinctSet *ds, size_t new_cap) {
    DistSlot *next = (DistSlot *)calloc(new_cap, sizeof(DistSlot));
    if (!next) return -1;
    size_t mask = new_cap - 1;
    for (size_t i = 0; i < ds->capacity; i++) {
        if (!ds->slots[i].occupied) continue;
        size_t pos = (size_t)(ds->slots[i].hash & mask);
        while (next[pos].occupied) pos = (pos + 1) & mask;
        next[pos] = ds->slots[i];
    }
    free(ds->slots);
    ds->slots = next;
    ds->capacity = new_cap;
    return 0;
}

static int distinct_insert(DistinctSet *ds, const Val *v, bool *inserted_out) {
    *inserted_out = false;
    if (ds->capacity == 0) {
        ds->slots = (DistSlot *)calloc(INITIAL_DIST_SLOTS, sizeof(DistSlot));
        if (!ds->slots) return -1;
        ds->capacity = INITIAL_DIST_SLOTS;
    } else if ((ds->count + 1) * 4 > ds->capacity * 3 && distinct_rehash(ds, ds->capacity * 2) != 0) {
        return -1;
    }
    uint64_t h = val_hash(v);
    size_t mask = ds->capacity - 1, pos = (size_t)(h & mask);
    while (ds->slots[pos].occupied) {
        if (ds->slots[pos].hash == h && val_key_equal(&ds->slots[pos].val, v)) return 0;
        pos = (pos + 1) & mask;
    }
    ds->slots[pos] = (DistSlot){.occupied = true, .hash = h, .val = val_clone(v)};
    ds->count++;
    *inserted_out = true;
    return 0;
}

static void distinct_free(DistinctSet *ds) {
    if (!ds || !ds->slots) return;
    for (size_t i = 0; i < ds->capacity; i++) {
        if (ds->slots[i].occupied) val_free(&ds->slots[i].val);
    }
    free(ds->slots);
    memset(ds, 0, sizeof(*ds));
}

void agg_accum_cleanup(AggAccum *acc) {
    if (!acc) return;
    val_free(&acc->min_val);
    val_free(&acc->max_val);
    distinct_free(&acc->distinct);
    memset(acc, 0, sizeof(*acc));
}

static uint64_t hash_group_keys(const Val *keys, size_t n_keys) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < n_keys; i++) h ^= val_hash(&keys[i]) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h;
}

static bool group_keys_match(const Val *a, const Val *b, size_t n_keys) {
    for (size_t i = 0; i < n_keys; i++) {
        if (!val_key_equal(&a[i], &b[i])) return false;
    }
    return true;
}

int hash_group_init(HashGroupTable *ht, size_t n_keys, size_t acc_stride) {
    memset(ht, 0, sizeof(*ht));
    ht->capacity = INITIAL_GROUP_BUCKETS;
    ht->n_keys = n_keys;
    ht->acc_stride = acc_stride > 0 ? acc_stride : 1;
    ht->order_cap = INITIAL_GROUP_BUCKETS;
    ht->buckets = (GroupBucket *)calloc(ht->capacity, sizeof(GroupBucket));
    ht->order = (GroupBucket **)calloc(ht->order_cap, sizeof(GroupBucket *));
    if (!ht->buckets || !ht->order) {
        free(ht->buckets); free(ht->order);
        memset(ht, 0, sizeof(*ht));
        return -1;
    }
    return 0;
}

void hash_group_free(HashGroupTable *ht) {
    if (!ht) return;
    if (ht->buckets) {
        for (size_t i = 0; i < ht->capacity; i++) {
            GroupBucket *b = &ht->buckets[i];
            if (!b->occupied) continue;
            for (size_t k = 0; k < ht->n_keys; k++) val_free(&b->keys[k]);
            free(b->keys);
            for (size_t a = 0; a < ht->acc_stride; a++) agg_accum_cleanup(&b->accs[a]);
            free(b->accs);
        }
        free(ht->buckets);
    }
    free(ht->order);
    memset(ht, 0, sizeof(*ht));
}

static int hash_group_rehash(HashGroupTable *ht, size_t new_cap) {
    GroupBucket *new_buckets = (GroupBucket *)calloc(new_cap, sizeof(GroupBucket));
    if (!new_buckets) return -1;
    size_t mask = new_cap - 1;
    for (size_t idx = 0; idx < ht->count; idx++) {
        GroupBucket *old = ht->order[idx];
        size_t pos = (size_t)(old->hash & mask);
        while (new_buckets[pos].occupied) pos = (pos + 1) & mask;
        new_buckets[pos] = *old;
        ht->order[idx] = &new_buckets[pos];
    }
    free(ht->buckets);
    ht->buckets = new_buckets;
    ht->capacity = new_cap;
    return 0;
}

GroupBucket *hash_group_get_or_create(HashGroupTable *ht, const Val *keys, char *err, size_t err_cap) {
    if ((ht->count + 1) * 4 > ht->capacity * 3 && hash_group_rehash(ht, ht->capacity * 2) != 0) {
        snprintf(err, err_cap, "out of memory expanding group hash table");
        return NULL;
    }
    uint64_t h = hash_group_keys(keys, ht->n_keys);
    size_t mask = ht->capacity - 1, pos = (size_t)(h & mask);
    while (ht->buckets[pos].occupied) {
        if (ht->buckets[pos].hash == h && group_keys_match(ht->buckets[pos].keys, keys, ht->n_keys)) {
            return &ht->buckets[pos];
        }
        pos = (pos + 1) & mask;
    }

    Val *kcopy = NULL;
    if (ht->n_keys > 0) {
        kcopy = (Val *)calloc(ht->n_keys, sizeof(Val));
        if (!kcopy) { snprintf(err, err_cap, "out of memory"); return NULL; }
        for (size_t i = 0; i < ht->n_keys; i++) kcopy[i] = val_clone(&keys[i]);
    }
    AggAccum *accs = (AggAccum *)calloc(ht->acc_stride, sizeof(AggAccum));
    if (!accs) {
        for (size_t i = 0; i < ht->n_keys; i++) val_free(&kcopy[i]);
        free(kcopy);
        snprintf(err, err_cap, "out of memory");
        return NULL;
    }
    if (ht->count == ht->order_cap) {
        size_t new_ocap = ht->order_cap * 2;
        GroupBucket **next_order = (GroupBucket **)realloc(ht->order, new_ocap * sizeof(GroupBucket *));
        if (!next_order) {
            for (size_t i = 0; i < ht->n_keys; i++) val_free(&kcopy[i]);
            free(kcopy); free(accs);
            snprintf(err, err_cap, "out of memory");
            return NULL;
        }
        ht->order = next_order;
        ht->order_cap = new_ocap;
    }

    GroupBucket *b = &ht->buckets[pos];
    *b = (GroupBucket){.occupied = true, .hash = h, .keys = kcopy, .accs = accs};
    ht->order[ht->count++] = b;
    return b;
}

const GroupBucket *hash_group_at(const HashGroupTable *ht, size_t index) {
    return (!ht || index >= ht->count) ? NULL : ht->order[index];
}

int agg_accum_step(AggAccum *acc, const AggSpec *spec, const Val *arg, char *err, size_t err_cap) {
    if (spec->is_star) {
        if (__builtin_add_overflow(acc->count, 1, &acc->count)) {
            snprintf(err, err_cap, "integer count limit exceeded");
            return -1;
        }
        acc->has_value = true;
        return 0;
    }
    if (!arg || arg->type == VAL_NULL) return 0;
    if (spec->is_distinct) {
        bool inserted = false;
        if (distinct_insert(&acc->distinct, arg, &inserted) != 0) {
            snprintf(err, err_cap, "out of memory updating DISTINCT state");
            return -1;
        }
        if (!inserted) return 0;
    }

    switch (spec->fn) {
        case AGG_FN_COUNT:
            if (__builtin_add_overflow(acc->count, 1, &acc->count)) {
                snprintf(err, err_cap, "integer count limit exceeded");
                return -1;
            }
            acc->has_value = true;
            return 0;
        case AGG_FN_AVG:
            if (arg->type != VAL_INT && arg->type != VAL_FLOAT) {
                snprintf(err, err_cap, "AVG requires numeric input");
                return -1;
            }
            acc->saw_float = true;
            acc->float_sum += (arg->type == VAL_FLOAT) ? arg->f64 : (double)arg->i64;
            if (__builtin_add_overflow(acc->count, 1, &acc->count)) {
                snprintf(err, err_cap, "integer count limit exceeded");
                return -1;
            }
            acc->has_value = true;
            return 0;
        case AGG_FN_SUM:
            if (arg->type != VAL_INT && arg->type != VAL_FLOAT) {
                snprintf(err, err_cap, "SUM requires numeric input");
                return -1;
            }
            if (arg->type == VAL_FLOAT) {
                if (!acc->saw_float) { acc->float_sum = (double)acc->int_sum; acc->saw_float = true; }
                acc->float_sum += arg->f64;
            } else if (acc->saw_float) {
                acc->float_sum += (double)arg->i64;
            } else if (__builtin_add_overflow(acc->int_sum, arg->i64, &acc->int_sum)) {
                snprintf(err, err_cap, "integer range exceeded in SUM");
                return -1;
            }
            if (__builtin_add_overflow(acc->count, 1, &acc->count)) {
                snprintf(err, err_cap, "integer count limit exceeded");
                return -1;
            }
            acc->has_value = true;
            return 0;
        case AGG_FN_MIN:
        case AGG_FN_MAX: {
            Val *slot = (spec->fn == AGG_FN_MIN) ? &acc->min_val : &acc->max_val;
            int want = (spec->fn == AGG_FN_MIN) ? -1 : 1;
            if (!acc->has_value || (val_compare_sql(arg, slot) == want)) {
                if (acc->has_value) val_free(slot);
                *slot = val_clone(arg);
                acc->has_value = true;
            }
            acc->count++;
            return 0;
        }
    }
    return 0;
}

Val agg_accum_finalize(const AggAccum *acc, const AggSpec *spec) {
    if (spec->fn == AGG_FN_COUNT) return val_int(acc->count);
    if (!acc->has_value || acc->count == 0) return val_null();
    if (spec->fn == AGG_FN_SUM) return acc->saw_float ? val_float(acc->float_sum) : val_int(acc->int_sum);
    if (spec->fn == AGG_FN_AVG) return val_float((acc->saw_float ? acc->float_sum : (double)acc->int_sum) / (double)acc->count);
    return val_clone(spec->fn == AGG_FN_MIN ? &acc->min_val : &acc->max_val);
}
EOF

cat > "$APP_DIR/src/exec.c" <<'EOF'
#include "engine.h"

#include <limits.h>
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
                if (sub.type == VAL_INT) {
                    int64_t neg_v = 0;
                    if (__builtin_sub_overflow((int64_t)0, sub.i64, &neg_v)) {
                        snprintf(err, err_cap, "integer negation out of range");
                        return -1;
                    }
                    *out = val_int(neg_v);
                    return 0;
                }
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
            int64_t a = lv.i64, b = rv.i64, res = 0;
            if ((e->bop == BOP_DIV || e->bop == BOP_MOD) && b == 0) { snprintf(err, err_cap, "division by zero"); return -1; }
            if ((e->bop == BOP_DIV || e->bop == BOP_MOD) && a == INT64_MIN && b == -1) {
                snprintf(err, err_cap, "integer division out of range");
                return -1;
            }
            bool bad = false;
            switch (e->bop) {
                case BOP_ADD: bad = __builtin_add_overflow(a, b, &res); break;
                case BOP_SUB: bad = __builtin_sub_overflow(a, b, &res); break;
                case BOP_MUL: bad = __builtin_mul_overflow(a, b, &res); break;
                case BOP_DIV: res = a / b; break;
                case BOP_MOD: res = a % b; break;
                default: break;
            }
            if (bad) {
                snprintf(err, err_cap, "integer arithmetic out of range");
                return -1;
            }
            *out = val_int(res);
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
    if (plan->offset_val < 0 || (plan->has_limit && plan->limit_val < 0)) {
        snprintf(err, err_cap, "LIMIT and OFFSET must be non-negative");
        return -1;
    }

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

    size_t start = (uint64_t)plan->offset_val > rs.n_rows ? rs.n_rows : (size_t)plan->offset_val;
    size_t avail = rs.n_rows - start;
    size_t take = (plan->has_limit && (uint64_t)plan->limit_val < avail) ? (size_t)plan->limit_val : avail;
    for (size_t i = 0; i < take; i++) {
        print_row_pipe(out_fp, &rs.rows[start + i], rs.n_cols);
    }

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
EOF

make -C "$APP_DIR" clean all
