#ifndef AGG_ENGINE_H
#define AGG_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define AGG_IDENT_MAX        64
#define AGG_MAX_COLS         32
#define AGG_MAX_TABLES       32
#define AGG_MAX_SELECT_ITEMS 32
#define AGG_MAX_GROUP_KEYS   16
#define AGG_MAX_ORDER_ITEMS  16
#define AGG_MAX_SPECS        32

typedef enum { COL_INT = 0, COL_FLOAT, COL_TEXT } ColType;
typedef enum { VAL_NULL = 0, VAL_INT, VAL_FLOAT, VAL_TEXT } ValType;

typedef struct { ValType type; int64_t i64; double f64; char *text; } Val;
typedef struct { char name[AGG_IDENT_MAX]; ColType type; } ColumnDef;
typedef struct { Val *vals; size_t n_vals; } Row;

typedef struct {
    char name[AGG_IDENT_MAX];
    ColumnDef cols[AGG_MAX_COLS];
    size_t n_cols;
    Row *rows;
    size_t n_rows, cap_rows;
} Table;

typedef struct { Table tables[AGG_MAX_TABLES]; size_t n_tables; } Catalog;

typedef enum {
    TOK_EOF = 0, TOK_IDENT, TOK_INT_LIT, TOK_FLOAT_LIT, TOK_STR_LIT,
    TOK_COMMA, TOK_SEMI, TOK_LPAREN, TOK_RPAREN, TOK_DOT,
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_EQ, TOK_NEQ, TOK_LT, TOK_LE, TOK_GT, TOK_GE,
    TOK_KW_CREATE, TOK_KW_TABLE, TOK_KW_INSERT, TOK_KW_INTO, TOK_KW_VALUES,
    TOK_KW_SELECT, TOK_KW_FROM, TOK_KW_WHERE, TOK_KW_GROUP, TOK_KW_BY,
    TOK_KW_HAVING, TOK_KW_ORDER, TOK_KW_ASC, TOK_KW_DESC,
    TOK_KW_LIMIT, TOK_KW_OFFSET, TOK_KW_AS, TOK_KW_DISTINCT,
    TOK_KW_AND, TOK_KW_OR, TOK_KW_NOT, TOK_KW_IS, TOK_KW_NULL,
    TOK_KW_INT, TOK_KW_FLOAT, TOK_KW_TEXT
} TokKind;

typedef struct { TokKind kind; char *lexeme; int64_t i64; double f64; int line, col; } Token;
typedef struct { Token *items; size_t count, cap, pos; } TokenStream;

typedef enum { AGG_FN_COUNT = 0, AGG_FN_SUM, AGG_FN_AVG, AGG_FN_MIN, AGG_FN_MAX } AggFunc;
typedef enum { UOP_NEG = 0, UOP_POS, UOP_NOT, UOP_IS_NULL, UOP_IS_NOT_NULL } UnaryOp;
typedef enum {
    BOP_ADD = 0, BOP_SUB, BOP_MUL, BOP_DIV, BOP_MOD,
    BOP_EQ, BOP_NEQ, BOP_LT, BOP_LE, BOP_GT, BOP_GE, BOP_AND, BOP_OR
} BinOp;
typedef enum { EXPR_LITERAL = 0, EXPR_COLUMN, EXPR_UNARY, EXPR_BINARY, EXPR_AGG } ExprKind;

typedef struct Expr {
    ExprKind kind;
    Val lit;
    char table_qual[AGG_IDENT_MAX], col_name[AGG_IDENT_MAX];
    int bound_col, bound_group, bound_proj;
    UnaryOp uop;
    BinOp bop;
    struct Expr *left, *right;
    AggFunc agg_fn;
    bool agg_star, agg_distinct;
    int agg_slot;
} Expr;

typedef struct { Expr *expr; bool desc; } OrderTerm;
typedef struct { char table_name[AGG_IDENT_MAX]; ColumnDef cols[AGG_MAX_COLS]; size_t n_cols; } AstCreate;
typedef struct { Val *vals; size_t n_vals; } InsertTuple;
typedef struct { char table_name[AGG_IDENT_MAX]; InsertTuple *tuples; size_t n_tuples, cap_tuples; } AstInsert;

typedef struct {
    char table_name[AGG_IDENT_MAX];
    Expr *proj_exprs[AGG_MAX_SELECT_ITEMS];
    char proj_aliases[AGG_MAX_SELECT_ITEMS][AGG_IDENT_MAX];
    size_t n_proj;
    Expr *where_expr, *having_expr;
    Expr *group_exprs[AGG_MAX_GROUP_KEYS];
    size_t n_group;
    OrderTerm order_terms[AGG_MAX_ORDER_ITEMS];
    size_t n_order;
    bool has_limit, has_offset;
    int64_t limit_val, offset_val;
} AstSelect;

typedef enum { STMT_CREATE = 0, STMT_INSERT, STMT_SELECT } StmtKind;
typedef struct { StmtKind kind; AstCreate create_s; AstInsert insert_s; AstSelect select_s; } AstStmt;
typedef struct { AggFunc fn; bool is_star, is_distinct; Expr *arg; } AggSpec;

typedef struct {
    const Table *table;
    bool is_aggregated, has_limit;
    Expr **proj_exprs, **group_exprs;
    Expr *where_expr, *having_expr;
    OrderTerm *order_terms;
    size_t n_proj, n_group, n_order, n_aggs, acc_stride;
    AggSpec aggs[AGG_MAX_SPECS];
    int64_t limit_val, offset_val;
} QueryPlan;

typedef struct { bool occupied; uint64_t hash; Val val; } DistSlot;
typedef struct { DistSlot *slots; size_t capacity, count; } DistinctSet;

typedef struct {
    int64_t count, int_sum;
    double float_sum;
    bool saw_float, has_value;
    Val min_val, max_val;
    DistinctSet distinct;
} AggAccum;

typedef struct { bool occupied; uint64_t hash; Val *keys; AggAccum *accs; } GroupBucket;
typedef struct {
    GroupBucket *buckets, **order;
    size_t capacity, count, n_keys, acc_stride, order_cap;
} HashGroupTable;

Val val_null(void);
Val val_int(int64_t v);
Val val_float(double v);
Val val_text_copy(const char *s);
Val val_clone(const Val *src);
void val_free(Val *v);
int val_compare_sql(const Val *a, const Val *b);
bool val_key_equal(const Val *a, const Val *b);
uint64_t val_hash(const Val *v);
int str_ieq(const char *a, const char *b);

void catalog_init(Catalog *cat);
void catalog_free(Catalog *cat);
Table *catalog_find_table(Catalog *cat, const char *name);
int table_find_col(const Table *tbl, const char *name);
int catalog_exec_create(Catalog *cat, const AstCreate *stmt, char *err, size_t err_cap);
int catalog_exec_insert(Catalog *cat, const AstInsert *stmt, char *err, size_t err_cap);

int sql_tokenize(const char *src, TokenStream *out, char *err, size_t err_cap);
void token_stream_free(TokenStream *ts);
bool token_stream_at_end(const TokenStream *ts);
int sql_parse_stmt(TokenStream *ts, AstStmt *out, char *err, size_t err_cap);
void ast_stmt_free(AstStmt *stmt);
void ast_expr_free(Expr *e);

int build_query_plan(Catalog *cat, AstSelect *stmt, QueryPlan *plan, char *err, size_t err_cap);

int hash_group_init(HashGroupTable *ht, size_t n_keys, size_t acc_stride);
void hash_group_free(HashGroupTable *ht);
GroupBucket *hash_group_get_or_create(HashGroupTable *ht, const Val *keys, char *err, size_t err_cap);
const GroupBucket *hash_group_at(const HashGroupTable *ht, size_t index);
int agg_accum_step(AggAccum *acc, const AggSpec *spec, const Val *arg, char *err, size_t err_cap);
Val agg_accum_finalize(const AggAccum *acc, const AggSpec *spec);
void agg_accum_cleanup(AggAccum *acc);

int execute_query_plan(const QueryPlan *plan, FILE *out_fp, char *err, size_t err_cap);
int engine_run_script(Catalog *cat, const char *sql, FILE *out_fp, char *err, size_t err_cap);

#endif
