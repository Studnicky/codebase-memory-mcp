/*
 * sql.c — the only place outside store.c that speaks sqlite.
 *
 * The handles are aliases, not wrappers: cbm_sql_t IS sqlite3 and
 * cbm_sql_stmt_t IS sqlite3_stmt, reinterpreted through the opaque names the
 * header publishes. Nothing is allocated to cross this boundary.
 */
#include "store/sql.h"

#include "sqlite3.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

static sqlite3 *as_db(cbm_sql_t *db) {
    return (sqlite3 *)(void *)db;
}

static sqlite3_stmt *as_stmt(cbm_sql_stmt_t *st) {
    return (sqlite3_stmt *)(void *)st;
}

bool cbm_sql_open(const char *path, cbm_sql_t **out) {
    if (!out) {
        return false;
    }
    *out = NULL;
    if (!path) {
        return false;
    }
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        /* sqlite allocates a handle even for most failures, so that the error
         * message is readable; closing it here is what lets the caller treat
         * false as "nothing to clean up". */
        sqlite3_close(db);
        return false;
    }
    *out = (cbm_sql_t *)(void *)db;
    return true;
}

void cbm_sql_close(cbm_sql_t *db) {
    if (db) {
        (void)sqlite3_close(as_db(db));
    }
}

bool cbm_sql_prepare(cbm_sql_t *db, const char *sql, cbm_sql_stmt_t **out) {
    if (!out) {
        return false;
    }
    *out = NULL;
    if (!db || !sql) {
        return false;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(as_db(db), sql, -1, &st, NULL) != SQLITE_OK || !st) {
        /* sqlite may hand back a statement alongside a failure; releasing it
         * here is what lets the caller treat false as "nothing to clean up". */
        sqlite3_finalize(st);
        return false;
    }
    *out = (cbm_sql_stmt_t *)(void *)st;
    return true;
}

bool cbm_sql_bind_text(cbm_sql_stmt_t *st, int index, const char *value) {
    if (!st) {
        return false;
    }
    if (!value) {
        return sqlite3_bind_null(as_stmt(st), index) == SQLITE_OK;
    }
    /* SQLITE_TRANSIENT: sqlite copies the bytes, so the caller's buffer does
     * not have to outlive the statement. */
    return sqlite3_bind_text(as_stmt(st), index, value, -1, SQLITE_TRANSIENT) == SQLITE_OK;
}

bool cbm_sql_bind_int(cbm_sql_stmt_t *st, int index, int value) {
    return st && sqlite3_bind_int(as_stmt(st), index, value) == SQLITE_OK;
}

bool cbm_sql_bind_int64(cbm_sql_stmt_t *st, int index, int64_t value) {
    return st && sqlite3_bind_int64(as_stmt(st), index, (sqlite3_int64)value) == SQLITE_OK;
}

bool cbm_sql_bind_double(cbm_sql_stmt_t *st, int index, double value) {
    return st && sqlite3_bind_double(as_stmt(st), index, value) == SQLITE_OK;
}

bool cbm_sql_bind_null(cbm_sql_stmt_t *st, int index) {
    return st && sqlite3_bind_null(as_stmt(st), index) == SQLITE_OK;
}

cbm_sql_step_t cbm_sql_step(cbm_sql_stmt_t *st) {
    if (!st) {
        return CBM_SQL_ERROR;
    }
    switch (sqlite3_step(as_stmt(st))) {
    case SQLITE_ROW:
        return CBM_SQL_ROW;
    case SQLITE_DONE:
        return CBM_SQL_DONE;
    default:
        return CBM_SQL_ERROR;
    }
}

const char *cbm_sql_column_text(cbm_sql_stmt_t *st, int col) {
    if (!st) {
        return "";
    }
    /* sqlite returns unsigned char * for historical reasons; the bytes are the
     * UTF-8 the caller wants either way, so the cast belongs here rather than
     * at every call site. A SQL NULL reads as "" so the returned pointer is
     * always safe to dereference — ask cbm_sql_column_is_null to tell the two
     * apart. */
    const char *text = (const char *)sqlite3_column_text(as_stmt(st), col);
    return text ? text : "";
}

bool cbm_sql_column_is_null(cbm_sql_stmt_t *st, int col) {
    return !st || sqlite3_column_type(as_stmt(st), col) == SQLITE_NULL;
}

int64_t cbm_sql_column_int64(cbm_sql_stmt_t *st, int col) {
    return st ? (int64_t)sqlite3_column_int64(as_stmt(st), col) : 0;
}

int cbm_sql_column_int(cbm_sql_stmt_t *st, int col) {
    return st ? sqlite3_column_int(as_stmt(st), col) : 0;
}

double cbm_sql_column_double(cbm_sql_stmt_t *st, int col) {
    return st ? sqlite3_column_double(as_stmt(st), col) : 0.0;
}

void cbm_sql_reset(cbm_sql_stmt_t *st) {
    if (st) {
        (void)sqlite3_reset(as_stmt(st));
    }
}

void cbm_sql_clear_bindings(cbm_sql_stmt_t *st) {
    if (st) {
        (void)sqlite3_clear_bindings(as_stmt(st));
    }
}

bool cbm_sql_finalize(cbm_sql_stmt_t *st) {
    if (!st) {
        return true;
    }
    return sqlite3_finalize(as_stmt(st)) == SQLITE_OK;
}

bool cbm_sql_exec(cbm_sql_t *db, const char *sql) {
    if (!db || !sql) {
        return false;
    }
    /* The message sqlite allocates here is freed immediately: callers read the
     * connection's error text through cbm_sql_errmsg, so there is no second
     * ownership rule to remember. */
    char *err = NULL;
    int rc = sqlite3_exec(as_db(db), sql, NULL, NULL, &err);
    sqlite3_free(err);
    return rc == SQLITE_OK;
}

const char *cbm_sql_errmsg(cbm_sql_t *db) {
    if (!db) {
        return "";
    }
    const char *msg = sqlite3_errmsg(as_db(db));
    return msg ? msg : "";
}

int cbm_sql_total_changes(cbm_sql_t *db) {
    return db ? sqlite3_total_changes(as_db(db)) : 0;
}

/* ── Allocator binding ────────────────────────────────────────── */

/* sqlite's hooks are sized in int. The vtable this module publishes is sized
 * in size_t, so the narrowing happens once, here, instead of at whatever
 * module happened to own the allocator. */
static cbm_sql_allocator_t g_alloc;
static atomic_flag g_allocator_bind_lock = ATOMIC_FLAG_INIT;
static atomic_bool g_allocator_bound = ATOMIC_VAR_INIT(false);

static void *sql_alloc(int size) {
    return size > 0 && g_alloc.alloc ? g_alloc.alloc((size_t)size) : NULL;
}

static void sql_free(void *block) {
    if (g_alloc.release) {
        g_alloc.release(block);
    }
}

static void *sql_grow(void *block, int size) {
    return size > 0 && g_alloc.grow ? g_alloc.grow(block, (size_t)size) : NULL;
}

static int sql_size(void *block) {
    return g_alloc.usable_size ? (int)g_alloc.usable_size(block) : 0;
}

static int sql_roundup(int size) {
    enum { SQL_ALIGN = 8 }; /* sqlite requires an 8-byte-aligned roundup */
    return (size + (SQL_ALIGN - 1)) & ~(SQL_ALIGN - 1);
}

/* sqlite calls xInit and xShutdown unconditionally — it does not check them
 * for NULL — so both must be real functions even when there is nothing to set
 * up. There is not: the allocator behind them is already live by the time
 * sqlite initializes. */
static int sql_mem_init(void *app_data) {
    (void)app_data;
    return SQLITE_OK;
}

static void sql_mem_shutdown(void *app_data) {
    (void)app_data;
}

bool cbm_sql_bind_allocator(const cbm_sql_allocator_t *alloc) {
    if (!alloc || !alloc->alloc || !alloc->grow || !alloc->release || !alloc->usable_size) {
        return false;
    }

    while (atomic_flag_test_and_set_explicit(&g_allocator_bind_lock, memory_order_acquire)) {
        atomic_signal_fence(memory_order_seq_cst);
    }
    if (atomic_load_explicit(&g_allocator_bound, memory_order_relaxed)) {
        atomic_flag_clear_explicit(&g_allocator_bind_lock, memory_order_release);
        return false;
    }

    /* Field order matches struct sqlite3_mem_methods exactly:
     * xMalloc, xFree, xRealloc, xSize, xRoundup, xInit, xShutdown, pAppData. */
    const sqlite3_mem_methods methods = {sql_alloc,   sql_free,     sql_grow,         sql_size,
                                         sql_roundup, sql_mem_init, sql_mem_shutdown, NULL};
    /* SQLITE_CONFIG_MALLOC must precede sqlite3_initialize and the first
     * sqlite3_open*. Publish the callbacks only after SQLite accepts its local
     * copy, so a rejected late bind cannot redirect frees made by live stores. */
    bool configured = sqlite3_config(SQLITE_CONFIG_MALLOC, &methods) == SQLITE_OK;
    if (configured) {
        atomic_signal_fence(memory_order_seq_cst);
        g_alloc = *alloc;
        atomic_store_explicit(&g_allocator_bound, true, memory_order_release);
    }
    atomic_flag_clear_explicit(&g_allocator_bind_lock, memory_order_release);
    return configured;
}
