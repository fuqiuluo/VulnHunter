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
    for (size_t i = 0; i < ht->capacity; i++) {
        if (!ht->buckets[i].occupied) continue;
        size_t pos = (size_t)(ht->buckets[i].hash & mask);
        while (new_buckets[pos].occupied) pos = (pos + 1) & mask;
        new_buckets[pos] = ht->buckets[i];
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
    if (spec->is_star) { acc->count++; acc->has_value = true; return 0; }
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
            acc->count++; acc->has_value = true;
            return 0;
        case AGG_FN_SUM:
        case AGG_FN_AVG:
            if (arg->type != VAL_INT && arg->type != VAL_FLOAT) {
                snprintf(err, err_cap, "SUM/AVG requires numeric input");
                return -1;
            }
            if (arg->type == VAL_FLOAT) {
                if (!acc->saw_float) { acc->float_sum = (double)acc->int_sum; acc->saw_float = true; }
                acc->float_sum += arg->f64;
            } else if (acc->saw_float) acc->float_sum += (double)arg->i64;
            else acc->int_sum += arg->i64;
            acc->count++; acc->has_value = true;
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
