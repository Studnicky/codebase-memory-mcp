/*
 * sql.h — the SQL trust boundary.
 *
 * `store` owns <sqlite3.h>. Every other module reaches the database through
 * the types published here, so sqlite's conventions stop at this edge:
 *
 *   - sqlite3_step returns a three-way result (ROW / DONE / an error code)
 *     that a caller must remember to distinguish. cbm_sql_step returns a
 *     named enum the compiler can check exhaustively.
 *   - sqlite3_column_text returns `const unsigned char *`, which every call
 *     site casts away. cbm_sql_column_text returns `const char *`.
 *   - sqlite3_bind_text needs a length and a destructor sentinel
 *     (-1, SQLITE_TRANSIENT) repeated at every site. cbm_sql_bind_text takes
 *     a string.
 *   - sqlite3_prepare_v2 signals failure through an int return AND an
 *     out-parameter. cbm_sql_prepare returns bool and leaves *out NULL.
 *   - sqlite's allocator hooks are sized in `int`. cbm_sql_bind_allocator
 *     takes size_t and does the narrowing once, here.
 *
 * The handles are opaque aliases for sqlite's own, not wrappers: crossing this
 * boundary costs nothing at runtime.
 */
#ifndef CBM_STORE_SQL_H
#define CBM_STORE_SQL_H

#include "store/store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct cbm_sql cbm_sql_t;
typedef struct cbm_sql_stmt cbm_sql_stmt_t;

/* Outcome of advancing a statement. A caller that handles ROW and DONE and
 * ignores ERROR is a compile-time-visible omission, not a silent one. */
typedef enum {
    CBM_SQL_ROW = 0,  /* a row is available; read it with cbm_sql_column_* */
    CBM_SQL_DONE,     /* the statement finished normally */
    CBM_SQL_ERROR,    /* the statement failed; see cbm_sql_errmsg */
} cbm_sql_step_t;

/* The connection behind a store. NULL when the store is not open. */
cbm_sql_t *cbm_store_sql(cbm_store_t *s);

/* Open a connection directly to a database file, read-write, for maintenance
 * that must run outside a store — compaction and VACUUM INTO, which the
 * store's authorizer refuses by design. On failure returns false and sets
 * *out to NULL, having released any partial connection sqlite handed back.
 * The caller owns the result and must cbm_sql_close it. */
bool cbm_sql_open(const char *path, cbm_sql_t **out);

/* Close a connection from cbm_sql_open. NULL-safe. Never call this on the
 * connection cbm_store_sql returns — the store owns that one. */
void cbm_sql_close(cbm_sql_t *db);

/* Compile `sql`. On failure returns false and sets *out to NULL, so a caller
 * cannot proceed with an uninitialised statement. */
bool cbm_sql_prepare(cbm_sql_t *db, const char *sql, cbm_sql_stmt_t **out);

/* Bind a parameter. Indices are 1-based, as sqlite's are. `value` is copied,
 * so it need not outlive the call. Binding NULL text binds SQL NULL. */
bool cbm_sql_bind_text(cbm_sql_stmt_t *st, int index, const char *value);
bool cbm_sql_bind_int(cbm_sql_stmt_t *st, int index, int value);
bool cbm_sql_bind_int64(cbm_sql_stmt_t *st, int index, int64_t value);
bool cbm_sql_bind_double(cbm_sql_stmt_t *st, int index, double value);
bool cbm_sql_bind_null(cbm_sql_stmt_t *st, int index);

/* Advance the statement one row. */
cbm_sql_step_t cbm_sql_step(cbm_sql_stmt_t *st);

/* Read a column of the current row. Columns are 0-based, as sqlite's are.
 *
 * cbm_sql_column_text NEVER returns NULL: a SQL NULL reads as "". Returning
 * NULL would make the pointer carry two meanings — "the text" and "there was
 * no text" — and every caller would have to remember which one it got. They
 * did not: of the call sites this boundary replaced, the large majority
 * dereferenced the result directly.
 *
 * A caller that genuinely needs to tell SQL NULL from an empty string asks for
 * that, with cbm_sql_column_is_null. The distinction is still available; it is
 * just no longer something you can miss by accident. */
const char *cbm_sql_column_text(cbm_sql_stmt_t *st, int col);

/* True when the column holds SQL NULL, as opposed to an empty string. */
bool cbm_sql_column_is_null(cbm_sql_stmt_t *st, int col);
int64_t cbm_sql_column_int64(cbm_sql_stmt_t *st, int col);
int cbm_sql_column_int(cbm_sql_stmt_t *st, int col);
double cbm_sql_column_double(cbm_sql_stmt_t *st, int col);

/* Rewind for re-execution. cbm_sql_reset keeps bindings; cbm_sql_clear_bindings
 * drops them. Both are NULL-safe. */
void cbm_sql_reset(cbm_sql_stmt_t *st);
void cbm_sql_clear_bindings(cbm_sql_stmt_t *st);

/* Release the statement. NULL-safe. Returns false if the statement ended in an
 * error — sqlite reports a failed step here as well as at the step itself, and
 * some errors (a deferred constraint, a failed commit) surface only on this
 * call, so a caller that cares about whether the statement really succeeded
 * must check. Ignoring the result is fine on a pure cleanup path. */
bool cbm_sql_finalize(cbm_sql_stmt_t *st);

/* Run one or more statements that return no rows. */
bool cbm_sql_exec(cbm_sql_t *db, const char *sql);

/* The last error on this connection. Never NULL; "" when there is none. */
const char *cbm_sql_errmsg(cbm_sql_t *db);

/* Total rows changed on this connection since it was opened. */
int cbm_sql_total_changes(cbm_sql_t *db);

/* Allocator sqlite should use. Sized in size_t; the narrowing to sqlite's
 * `int`-sized hooks happens behind this boundary. */
typedef struct {
    void *(*alloc)(size_t size);
    void *(*grow)(void *block, size_t size);
    void (*release)(void *block);
    size_t (*usable_size)(void *block);
} cbm_sql_allocator_t;

/* Bind `alloc` as sqlite's allocator. MUST run before the first connection is
 * opened — sqlite refuses the change once it has initialised, and this returns
 * false in that case rather than leaving the caller to read a status code. */
bool cbm_sql_bind_allocator(const cbm_sql_allocator_t *alloc);

#endif /* CBM_STORE_SQL_H */
