/*
 * pipeline_delta.c — delta-repair staging primitives (closure route only).
 *
 * The dedicated incremental subsystem: instead of loading the whole previous
 * graph into RAM and dumping a complete new generation, the closure route
 * CLONES the live database (copy-on-write where the filesystem offers it),
 * PATCHES exactly the repaired node/edge set into the clone inside one
 * transaction, and publishes through the same sealed-staging finalize leg as
 * the dump path. The general indexing pipeline is untouched; these
 * primitives exist only for the closure orchestration in
 * pipeline_incremental.c.
 *
 * Id discipline carries the design: node ids are AUTOINCREMENT and never
 * reused, the small in-RAM gbuf is pre-seeded with PROXY nodes carrying
 * their real database ids, and fresh nodes are numbered above the previous
 * generation's MAX(id) — so "id > max_db_id" is the complete, marker-free
 * definition of what the patch inserts, and every edge endpoint id is
 * database-valid by construction.
 *
 * FTS policy: the nodes_fts table is contentless, so purged rows cannot be
 * deleted individually on existing databases; their rowids can never alias
 * a live node again (AUTOINCREMENT), so dead entries simply drop out of the
 * rowid join at query time. The patch inserts rows for exactly the new
 * nodes, via the same cbm_camel_split SQL function the wholesale rebuild
 * uses.
 */
#include "foundation/constants.h"
#include "pipeline/pipeline_internal.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "foundation/compat_fs.h"
#include "foundation/log.h"
#include "store/sql.h"
#include "store/store.h"

enum {
    DELTA_IN_CHUNK = 200,
    DELTA_PLACEHOLDER_BYTES_PER_PATH = 2,
    DELTA_C_STRING_TERMINATOR_BYTES = 1,
    DELTA_SEQUENCE_NEXT_OFFSET = 1,
    DELTA_SQL_BIND_FIRST_PARAMETER = 1,
    DELTA_SQL_BIND_SECOND_PARAMETER = 2,
    DELTA_SQL_BIND_SECOND_PATH_OFFSET = DELTA_SQL_BIND_SECOND_PARAMETER,
    DELTA_SNAPSHOT_COLUMN_SOURCE_QN = 0,
    DELTA_SNAPSHOT_COLUMN_TARGET_QN = 1,
    DELTA_SNAPSHOT_COLUMN_TYPE = 2,
    DELTA_SNAPSHOT_COLUMN_PROPERTIES = 3,
    DELTA_CAPACITY_GROWTH_FACTOR = 2,
    DELTA_SNAPSHOT_INITIAL_CAPACITY = 64,
    DELTA_PRESEED_FAILED = -1,
    DELTA_PRESEED_COLUMN_ID = 0,
    DELTA_PRESEED_COLUMN_LABEL = 1,
    DELTA_PRESEED_COLUMN_NAME = 2,
    DELTA_PRESEED_COLUMN_QUALIFIED_NAME = 3,
    DELTA_PRESEED_COLUMN_FILE_PATH = 4,
    DELTA_NODE_ID_NEXT_INCREMENT = 1,
    DELTA_LOG_COUNT_BUFFER_SIZE = 32,
    DELTA_REMAP_INITIAL_CAPACITY = 256,
    DELTA_BINARY_SEARCH_DIVISOR = 2,
    DELTA_BINARY_SEARCH_STEP = 1,
    DELTA_QN_LOOKUP_COLUMN_ID = 0,
    DELTA_NODE_BIND_ID = 1,
    DELTA_NODE_BIND_PROJECT = 2,
    DELTA_NODE_BIND_LABEL = 3,
    DELTA_NODE_BIND_NAME = 4,
    DELTA_NODE_BIND_QUALIFIED_NAME = 5,
    DELTA_NODE_BIND_FILE_PATH = 6,
    DELTA_NODE_BIND_START_LINE = 7,
    DELTA_NODE_BIND_END_LINE = 8,
    DELTA_NODE_BIND_PROPERTIES = 9,
    DELTA_OWNER_COLUMN_LABEL = 0,
    DELTA_OWNER_COLUMN_QUALIFIED_NAME = 1,
    DELTA_EDGE_BIND_PROJECT = 1,
    DELTA_EDGE_BIND_SOURCE_ID = 2,
    DELTA_EDGE_BIND_TARGET_ID = 3,
    DELTA_EDGE_BIND_TYPE = 4,
    DELTA_EDGE_BIND_PROPERTIES = 5,
    DELTA_RELINK_BIND_PROJECT = 1,
    DELTA_RELINK_BIND_TYPE = 2,
    DELTA_RELINK_BIND_PROPERTIES = 3,
    DELTA_RELINK_BIND_SOURCE_QN = 4,
    DELTA_RELINK_BIND_TARGET_QN = 5,
    DELTA_FTS_BIND_PROJECT = 1,
    DELTA_FTS_BIND_MAX_DB_ID = 2,
};

/* Assemble "?,?,...,?" for a chunked IN list. buf must hold 2*count. */
static void delta_placeholders(char *buf, int count) {
    int pos = 0;
    for (int i = 0; i < count; i++) {
        buf[pos++] = '?';
        if (i + DELTA_SEQUENCE_NEXT_OFFSET < count) {
            buf[pos++] = ',';
        }
    }
    buf[pos] = '\0';
}

int cbm_delta_stage_clone(const char *final_db_path, char **out_stage_path) {
    *out_stage_path = NULL;
    char *stage = cbm_pipeline_create_staging_path(final_db_path);
    if (!stage) {
        return CBM_NOT_FOUND;
    }
    if (cbm_clone_or_copy_file(final_db_path, stage) != 0) {
        cbm_pipeline_discard_stage(stage);
        free(stage);
        return CBM_NOT_FOUND;
    }
    *out_stage_path = stage;
    return 0;
}

/* Snapshot inbound cross-file edges into the given files from OUTSIDE them,
 * keyed by endpoint qualified names — the same semantics as the gbuf-based
 * capture, expressed as one indexed query per chunk. Edge types a full
 * reindex recomputes wholesale are excluded for the same reasons recorded
 * there (restoring a stale copy could produce edges a full build would not). */
static bool delta_edge_type_is_recomputed(const char *type) {
    return type && (strcmp(type, "SIMILAR_TO") == 0 || strcmp(type, "SEMANTICALLY_RELATED") == 0 ||
                    strcmp(type, "FILE_CHANGES_WITH") == 0 || strcmp(type, "DATA_FLOWS") == 0);
}

typedef struct {
    cbm_delta_saved_edge_t *items;
    int count;
    int capacity;
} delta_snapshot_t;

static bool delta_snapshot_grow(delta_snapshot_t *snapshot) {
    if (snapshot->count < snapshot->capacity) {
        return true;
    }
    if (snapshot->capacity > INT_MAX / DELTA_CAPACITY_GROWTH_FACTOR) {
        return false;
    }
    int capacity = snapshot->capacity ? snapshot->capacity * DELTA_CAPACITY_GROWTH_FACTOR
                                      : DELTA_SNAPSHOT_INITIAL_CAPACITY;
    cbm_delta_saved_edge_t *items = realloc(snapshot->items, (size_t)capacity * sizeof(*items));
    if (!items) {
        return false;
    }
    snapshot->items = items;
    snapshot->capacity = capacity;
    return true;
}

static bool delta_snapshot_add(delta_snapshot_t *snapshot, cbm_sql_stmt_t *stmt, const char *type) {
    if (!delta_snapshot_grow(snapshot)) {
        return false;
    }
    const char *source = cbm_sql_column_text(stmt, DELTA_SNAPSHOT_COLUMN_SOURCE_QN);
    const char *target = cbm_sql_column_text(stmt, DELTA_SNAPSHOT_COLUMN_TARGET_QN);
    const char *properties = cbm_sql_column_is_null(stmt, DELTA_SNAPSHOT_COLUMN_PROPERTIES)
                                 ? NULL
                                 : cbm_sql_column_text(stmt, DELTA_SNAPSHOT_COLUMN_PROPERTIES);
    cbm_delta_saved_edge_t *edge = &snapshot->items[snapshot->count];
    edge->source_qn = strdup(source ? source : "");
    edge->target_qn = strdup(target ? target : "");
    edge->type = strdup(type);
    edge->props = strdup(properties ? properties : "{}");
    if (!edge->source_qn || !edge->target_qn || !edge->type || !edge->props) {
        free(edge->source_qn);
        free(edge->target_qn);
        free(edge->type);
        free(edge->props);
        return false;
    }
    snapshot->count++;
    return true;
}

static bool delta_snapshot_prepare(cbm_sql_t *db, const char *placeholders, cbm_sql_stmt_t **stmt) {
    char sql[CBM_SZ_4K];
    int length = snprintf(sql, sizeof(sql),
                          /* CROSS JOIN pins nodes-first: the planner otherwise walks
                           * EVERY project edge through the url_path index prefix
                           * (measured 14.6s vs 4ms at kernel scale). */
                          "SELECT src.qualified_name, tgt.qualified_name, e.type, e.properties"
                          " FROM nodes tgt"
                          " CROSS JOIN edges e ON e.target_id = tgt.id"
                          " CROSS JOIN nodes src ON e.source_id = src.id"
                          " WHERE tgt.project = ?1 AND tgt.file_path IN (%s)"
                          " AND src.file_path NOT IN (%s)"
                          " AND src.file_path <> '' AND src.file_path IS NOT NULL",
                          placeholders, placeholders);
    return length >= 0 && (size_t)length < sizeof(sql) && cbm_sql_prepare(db, sql, stmt);
}

static void delta_snapshot_bind_paths(cbm_sql_stmt_t *stmt, const char *project,
                                      const char *const *paths, int offset, int count) {
    cbm_sql_bind_text(stmt, DELTA_SQL_BIND_FIRST_PARAMETER, project);
    for (int index = 0; index < count; index++) {
        cbm_sql_bind_text(stmt, DELTA_SQL_BIND_SECOND_PARAMETER + index, paths[offset + index]);
        cbm_sql_bind_text(stmt, DELTA_SQL_BIND_SECOND_PATH_OFFSET + count + index,
                          paths[offset + index]);
    }
}

static bool delta_snapshot_chunk(cbm_sql_t *db, const char *project, const char *const *paths,
                                 int offset, int count, delta_snapshot_t *snapshot) {
    char placeholders[(DELTA_PLACEHOLDER_BYTES_PER_PATH * DELTA_IN_CHUNK) +
                      DELTA_C_STRING_TERMINATOR_BYTES];
    delta_placeholders(placeholders, count);
    cbm_sql_stmt_t *stmt = NULL;
    if (!delta_snapshot_prepare(db, placeholders, &stmt)) {
        return false;
    }
    delta_snapshot_bind_paths(stmt, project, paths, offset, count);
    cbm_sql_step_t step = CBM_SQL_DONE;
    while ((step = cbm_sql_step(stmt)) == CBM_SQL_ROW) {
        const char *type = cbm_sql_column_text(stmt, DELTA_SNAPSHOT_COLUMN_TYPE);
        if (!delta_edge_type_is_recomputed(type) && !delta_snapshot_add(snapshot, stmt, type)) {
            cbm_sql_finalize(stmt);
            return false;
        }
    }
    cbm_sql_finalize(stmt);
    return step == CBM_SQL_DONE;
}

int cbm_delta_snapshot_inbound(cbm_store_t *store, const char *project, const char *const *paths,
                               int path_count, cbm_delta_saved_edge_t **out, int *out_count) {
    *out = NULL;
    *out_count = 0;
    if (path_count <= 0) {
        return 0;
    }
    cbm_sql_t *db = cbm_store_sql(store);
    if (!db) {
        return CBM_NOT_FOUND;
    }
    delta_snapshot_t snapshot = {0};
    for (int off = 0; off < path_count; off += DELTA_IN_CHUNK) {
        int chunk = path_count - off;
        if (chunk > DELTA_IN_CHUNK) {
            chunk = DELTA_IN_CHUNK;
        }
        if (!delta_snapshot_chunk(db, project, paths, off, chunk, &snapshot)) {
            cbm_delta_free_snapshot(snapshot.items, snapshot.count);
            return CBM_NOT_FOUND;
        }
    }
    *out = snapshot.items;
    *out_count = snapshot.count;
    return 0;
}

void cbm_delta_free_snapshot(cbm_delta_saved_edge_t *items, int count) {
    if (!items) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(items[i].source_qn);
        free(items[i].target_qn);
        free(items[i].type);
        free(items[i].props);
    }
    free(items);
}

int cbm_delta_purge(cbm_store_t *store, const char *project, const char *const *paths,
                    int path_count) {
    if (path_count <= 0) {
        return 0;
    }
    cbm_sql_t *db = cbm_store_sql(store);
    if (!db) {
        return CBM_NOT_FOUND;
    }
    for (int off = 0; off < path_count; off += DELTA_IN_CHUNK) {
        int chunk = path_count - off;
        if (chunk > DELTA_IN_CHUNK) {
            chunk = DELTA_IN_CHUNK;
        }
        char ph[(DELTA_PLACEHOLDER_BYTES_PER_PATH * DELTA_IN_CHUNK) +
                DELTA_C_STRING_TERMINATOR_BYTES];
        delta_placeholders(ph, chunk);
        char sql[CBM_SZ_1K];
        int n = snprintf(sql, sizeof(sql),
                         "DELETE FROM nodes WHERE project = ?1 AND file_path IN (%s)", ph);
        if (n < 0 || (size_t)n >= sizeof(sql)) {
            return CBM_NOT_FOUND;
        }
        cbm_sql_stmt_t *stmt = NULL;
        if (!cbm_sql_prepare(db, sql, &stmt)) {
            return CBM_NOT_FOUND;
        }
        cbm_sql_bind_text(stmt, DELTA_SQL_BIND_FIRST_PARAMETER, project);
        for (int i = 0; i < chunk; i++) {
            cbm_sql_bind_text(stmt, DELTA_SQL_BIND_SECOND_PARAMETER + i, paths[off + i]);
        }
        cbm_sql_step_t rc = cbm_sql_step(stmt);
        cbm_sql_finalize(stmt);
        if (rc != CBM_SQL_DONE) {
            return CBM_NOT_FOUND;
        }
    }
    return 0;
}

/* Every project node becomes a proxy. The first cut filtered by label and
 * the fail-closed patch immediately found the counterexamples (synthetic
 * Decorator nodes on django; Macro is six of the kernel's 8.5M nodes) — any
 * node the resolvers or restricted post-passes can target as an edge
 * endpoint must carry its real id in RAM, and curating that set by label is
 * guessing. The proxy load stays edge-free and property-free, which is
 * where the old full load actually spent its time. */

int64_t cbm_delta_preseed(cbm_store_t *store, const char *project, cbm_gbuf_t *gbuf) {
    cbm_sql_t *db = cbm_store_sql(store);
    if (!db) {
        return DELTA_PRESEED_FAILED;
    }
    int64_t max_id = 0;
    {
        cbm_sql_stmt_t *stmt = NULL;
        /* Global MAX, not project-scoped: node ids are one keyspace for the
         * whole database, and the watermark must clear every row in it. */
        if (!cbm_sql_prepare(db, "SELECT COALESCE(MAX(id), 0) FROM nodes", &stmt)) {
            return DELTA_PRESEED_FAILED;
        }
        if (cbm_sql_step(stmt) == CBM_SQL_ROW) {
            max_id = cbm_sql_column_int64(stmt, 0);
        }
        cbm_sql_finalize(stmt);
    }

    /* Proxy only what resolution can reach by NAME or QN: the registry
     * symbols (cbm_label_is_type_like + Function/Method/Variable/Field, the
     * exact set incr_label_is_registry_symbol admits) plus the structural
     * nodes edges attach to. Everything else -- overwhelmingly Macro, six of
     * the kernel's 8.5M nodes -- is never a lookup target, and a proxy for it
     * would be pure load cost.
     *
     * Safety net for the labels this list does not anticipate: a resolver
     * that upserts an unproxied QN now produces a fresh node that the patch
     * maps back onto its existing row by qualified name, rather than the
     * UNIQUE violation the pre-remap patch would have raised. A resolver that
     * only LOOKS UP still needs its target resident, which is why the list
     * mirrors the registry's own membership rule instead of guessing. */
    cbm_sql_stmt_t *stmt = NULL;
    if (!cbm_sql_prepare(db,
                         "SELECT id, label, name, qualified_name, file_path FROM nodes"
                         " WHERE project = ?1 AND label NOT IN"
                         " ('Macro','Comment','Section','Branch','Commit','Tag')"
                         " ORDER BY id",
                         &stmt)) {
        return DELTA_PRESEED_FAILED;
    }
    cbm_sql_bind_text(stmt, DELTA_SQL_BIND_FIRST_PARAMETER, project);
    cbm_sql_step_t step_rc;
    int64_t seeded = 0;
    while ((step_rc = cbm_sql_step(stmt)) == CBM_SQL_ROW) {
        int64_t id = cbm_sql_column_int64(stmt, DELTA_PRESEED_COLUMN_ID);
        const char *label = cbm_sql_column_text(stmt, DELTA_PRESEED_COLUMN_LABEL);
        const char *name = cbm_sql_column_text(stmt, DELTA_PRESEED_COLUMN_NAME);
        const char *qn = cbm_sql_column_text(stmt, DELTA_PRESEED_COLUMN_QUALIFIED_NAME);
        const char *fp = cbm_sql_column_text(stmt, DELTA_PRESEED_COLUMN_FILE_PATH);
        /* Pin the gbuf id to the database id: proxies ARE their rows. */
        cbm_gbuf_set_next_id(gbuf, id);
        int64_t got = cbm_node_id_value(
            cbm_gbuf_upsert_node(gbuf, label, name, qn, fp ? fp : "", 0, 0, "{}"));
        if (got != id) {
            /* A QN collision inside the preseed set would silently split
             * identity between RAM and disk; the run cannot be trusted. */
            cbm_sql_finalize(stmt);
            cbm_log_error("delta.preseed_id_mismatch", "qn", qn ? qn : "");
            return DELTA_PRESEED_FAILED;
        }
        seeded++;
    }
    cbm_sql_finalize(stmt);
    if (step_rc != CBM_SQL_DONE) {
        return DELTA_PRESEED_FAILED;
    }
    cbm_gbuf_set_next_id(gbuf, max_id + DELTA_NODE_ID_NEXT_INCREMENT);
    char seeded_buf[DELTA_LOG_COUNT_BUFFER_SIZE];
    snprintf(seeded_buf, sizeof(seeded_buf), "%lld", (long long)seeded);
    cbm_log_info("delta.preseed", "proxies", seeded_buf);
    return max_id;
}

/* Patch visitor state: inserts everything above the id watermark. */
typedef struct {
    cbm_sql_t *db;
    const char *project;
    int64_t max_db_id;
    cbm_sql_stmt_t *node_stmt;
    cbm_sql_stmt_t *edge_stmt;
    cbm_sql_stmt_t *qn_lookup;
    /* gbuf id -> real database id for any fresh node whose qualified
     * name turns out to already exist on disk: a resolver referenced
     * a symbol the narrowed proxy set did not pre-load, so it upserted
     * a stand-in. Mapping it back keeps the existing row authoritative
     * and every edge endpoint database-valid. Appended in ascending
     * gbuf-id order (nodes are visited that way), so lookups binary
     * search -- CBMHashTable stores key POINTERS without copying,
     * which a stack-formatted integer key cannot satisfy. */
    struct {
        int64_t from;
        int64_t to;
    } *remap;
    int remap_count;
    int remap_cap;
    bool failed;
    int64_t nodes;
    int64_t edges;
    int64_t remapped;
} delta_patch_ctx_t;

static void delta_remap_put(delta_patch_ctx_t *ctx, int64_t from, int64_t to) {
    if (ctx->remap_count >= ctx->remap_cap) {
        /* Doubling an int overflows before the cast can widen it, so bound it
         * first and fail the same way this function already does when the
         * allocation fails. */
        if (ctx->remap_cap > INT_MAX / DELTA_CAPACITY_GROWTH_FACTOR) {
            ctx->failed = true;
            return;
        }
        int ncap = ctx->remap_cap ? ctx->remap_cap * DELTA_CAPACITY_GROWTH_FACTOR
                                  : DELTA_REMAP_INITIAL_CAPACITY;
        void *grown = realloc(ctx->remap, (size_t)ncap * sizeof(*ctx->remap));
        if (!grown) {
            ctx->failed = true;
            return;
        }
        ctx->remap = grown;
        ctx->remap_cap = ncap;
    }
    ctx->remap[ctx->remap_count].from = from;
    ctx->remap[ctx->remap_count].to = to;
    ctx->remap_count++;
}

static int64_t delta_remap_get(const delta_patch_ctx_t *ctx, int64_t id) {
    if (id <= ctx->max_db_id || ctx->remap_count == 0) {
        return id;
    }
    int lo = 0;
    int hi = ctx->remap_count - DELTA_BINARY_SEARCH_STEP;
    while (lo <= hi) {
        int mid = lo + ((hi - lo) / DELTA_BINARY_SEARCH_DIVISOR);
        if (ctx->remap[mid].from == id) {
            return ctx->remap[mid].to;
        }
        if (ctx->remap[mid].from < id) {
            lo = mid + DELTA_BINARY_SEARCH_STEP;
        } else {
            hi = mid - DELTA_BINARY_SEARCH_STEP;
        }
    }
    return id;
}

static void delta_patch_node(const cbm_gbuf_node_t *node, void *userdata) {
    delta_patch_ctx_t *ctx = (delta_patch_ctx_t *)userdata;
    if (ctx->failed || cbm_node_id_value(node->id) <= ctx->max_db_id) {
        return;
    }
    if (node->qualified_name) {
        cbm_sql_reset(ctx->qn_lookup);
        cbm_sql_bind_text(ctx->qn_lookup, DELTA_SQL_BIND_FIRST_PARAMETER, ctx->project);
        cbm_sql_bind_text(ctx->qn_lookup, DELTA_SQL_BIND_SECOND_PARAMETER, node->qualified_name);
        if (cbm_sql_step(ctx->qn_lookup) == CBM_SQL_ROW) {
            /* Already on disk: an unchanged file's symbol. A node from a
             * CHANGED file cannot appear here -- the purge removed it --
             * so repaired files still receive fresh rows. */
            delta_remap_put(ctx, cbm_node_id_value(node->id),
                            cbm_sql_column_int64(ctx->qn_lookup, DELTA_QN_LOOKUP_COLUMN_ID));
            ctx->remapped++;
            return;
        }
    }
    cbm_sql_reset(ctx->node_stmt);
    cbm_sql_bind_int64(ctx->node_stmt, DELTA_NODE_BIND_ID, cbm_node_id_value(node->id));
    cbm_sql_bind_text(ctx->node_stmt, DELTA_NODE_BIND_PROJECT, ctx->project);
    cbm_sql_bind_text(ctx->node_stmt, DELTA_NODE_BIND_LABEL, node->label);
    cbm_sql_bind_text(ctx->node_stmt, DELTA_NODE_BIND_NAME, node->name);
    cbm_sql_bind_text(ctx->node_stmt, DELTA_NODE_BIND_QUALIFIED_NAME, node->qualified_name);
    cbm_sql_bind_text(ctx->node_stmt, DELTA_NODE_BIND_FILE_PATH, node->file_path);
    cbm_sql_bind_int(ctx->node_stmt, DELTA_NODE_BIND_START_LINE, node->start_line);
    cbm_sql_bind_int(ctx->node_stmt, DELTA_NODE_BIND_END_LINE, node->end_line);
    cbm_sql_bind_text(ctx->node_stmt, DELTA_NODE_BIND_PROPERTIES, node->properties_json);
    if (cbm_sql_step(ctx->node_stmt) != CBM_SQL_DONE) {
        ctx->failed = true;
        char id_buf[DELTA_LOG_COUNT_BUFFER_SIZE];
        snprintf(id_buf, sizeof(id_buf), "%lld", (long long)cbm_node_id_value(node->id));
        cbm_log_error("delta.patch_node_failed", "qn", node->qualified_name, "err",
                      cbm_sql_errmsg(ctx->db));
        cbm_log_error("delta.patch_node_id", "id", id_buf);
        cbm_sql_stmt_t *who = NULL;
        if (cbm_sql_prepare(ctx->db, "SELECT label, qualified_name FROM nodes WHERE id = ?1",
                            &who)) {
            cbm_sql_bind_int64(who, DELTA_SQL_BIND_FIRST_PARAMETER, cbm_node_id_value(node->id));
            if (cbm_sql_step(who) == CBM_SQL_ROW) {
                cbm_log_error("delta.patch_id_owner", "label",
                              cbm_sql_column_text(who, DELTA_OWNER_COLUMN_LABEL), "qn",
                              cbm_sql_column_text(who, DELTA_OWNER_COLUMN_QUALIFIED_NAME));
            }
            cbm_sql_finalize(who);
        }
        return;
    }
    ctx->nodes++;
}

static void delta_patch_edge(const cbm_gbuf_edge_t *edge, void *userdata) {
    delta_patch_ctx_t *ctx = (delta_patch_ctx_t *)userdata;
    if (ctx->failed) {
        return;
    }
    int64_t src = delta_remap_get(ctx, cbm_node_id_value(edge->source_id));
    int64_t tgt = delta_remap_get(ctx, cbm_node_id_value(edge->target_id));
    if (src <= ctx->max_db_id && tgt <= ctx->max_db_id &&
        src == cbm_node_id_value(edge->source_id) && tgt == cbm_node_id_value(edge->target_id)) {
        return; /* both endpoints pre-existed unremapped: already recorded */
    }
    char *props_json = cbm_gbuf_edge_props_json_alloc(edge);
    if (!props_json) {
        ctx->failed = true;
        cbm_log_error("delta.patch_edge_props_alloc_failed", "type", edge->type);
        return;
    }

    cbm_sql_reset(ctx->edge_stmt);
    cbm_sql_bind_text(ctx->edge_stmt, DELTA_EDGE_BIND_PROJECT, ctx->project);
    cbm_sql_bind_int64(ctx->edge_stmt, DELTA_EDGE_BIND_SOURCE_ID, src);
    cbm_sql_bind_int64(ctx->edge_stmt, DELTA_EDGE_BIND_TARGET_ID, tgt);
    cbm_sql_bind_text(ctx->edge_stmt, DELTA_EDGE_BIND_TYPE, edge->type);
    cbm_sql_bind_text(ctx->edge_stmt, DELTA_EDGE_BIND_PROPERTIES, props_json);
    cbm_sql_step_t step_rc = cbm_sql_step(ctx->edge_stmt);
    free(props_json);
    if (step_rc != CBM_SQL_DONE) {
        ctx->failed = true;
        cbm_log_error("delta.patch_edge_failed", "type", edge->type);
        return;
    }
    ctx->edges++;
}

static bool delta_prepare_patch_statements(cbm_sql_t *db, delta_patch_ctx_t *ctx) {
    if (!cbm_sql_prepare(db,
                         "SELECT id FROM nodes WHERE project = ?1"
                         " AND qualified_name = ?2",
                         &ctx->qn_lookup)) {
        return false;
    }
    bool prepared =
        cbm_sql_prepare(db,
                        "INSERT INTO nodes (id, project, label, name, qualified_name,"
                        " file_path, start_line, end_line, properties)"
                        " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                        &ctx->node_stmt) &&
        cbm_sql_prepare(db,
                        "INSERT OR IGNORE INTO edges (project, source_id, target_id, type,"
                        " properties) VALUES (?1,?2,?3,?4,?5)",
                        &ctx->edge_stmt);
    if (!prepared) {
        cbm_sql_finalize(ctx->node_stmt);
        cbm_sql_finalize(ctx->edge_stmt);
        cbm_sql_finalize(ctx->qn_lookup);
    }
    return prepared;
}

static void delta_finalize_patch_statements(delta_patch_ctx_t *ctx) {
    cbm_sql_finalize(ctx->node_stmt);
    cbm_sql_finalize(ctx->edge_stmt);
    cbm_sql_finalize(ctx->qn_lookup);
}

static void delta_relink_snapshot(delta_patch_ctx_t *ctx, const cbm_delta_saved_edge_t *snapshot,
                                  int snapshot_count) {
    if (ctx->failed || snapshot_count <= 0) {
        return;
    }
    cbm_sql_stmt_t *relink = NULL;
    if (!cbm_sql_prepare(ctx->db,
                         "INSERT OR IGNORE INTO edges (project, source_id, target_id,"
                         " type, properties)"
                         " SELECT ?1, s.id, t.id, ?2, ?3 FROM nodes s, nodes t"
                         " WHERE s.project = ?1 AND s.qualified_name = ?4"
                         " AND t.project = ?1 AND t.qualified_name = ?5",
                         &relink)) {
        ctx->failed = true;
        return;
    }
    for (int index = 0; index < snapshot_count && !ctx->failed; index++) {
        cbm_sql_reset(relink);
        cbm_sql_bind_text(relink, DELTA_RELINK_BIND_PROJECT, ctx->project);
        cbm_sql_bind_text(relink, DELTA_RELINK_BIND_TYPE, snapshot[index].type);
        cbm_sql_bind_text(relink, DELTA_RELINK_BIND_PROPERTIES, snapshot[index].props);
        cbm_sql_bind_text(relink, DELTA_RELINK_BIND_SOURCE_QN, snapshot[index].source_qn);
        cbm_sql_bind_text(relink, DELTA_RELINK_BIND_TARGET_QN, snapshot[index].target_qn);
        if (cbm_sql_step(relink) != CBM_SQL_DONE) {
            ctx->failed = true;
        }
    }
    cbm_sql_finalize(relink);
}

static void delta_patch_fts(delta_patch_ctx_t *ctx) {
    if (ctx->failed) {
        return;
    }
    cbm_sql_stmt_t *fts = NULL;
    if (!cbm_sql_prepare(ctx->db,
                         "INSERT INTO nodes_fts (rowid, name, qualified_name, label,"
                         " file_path)"
                         " SELECT id, cbm_camel_split(name), qualified_name, label,"
                         " file_path FROM nodes WHERE project = ?1 AND id > ?2",
                         &fts)) {
        /* FTS5 may be compiled out; the table then never existed and
         * search runs without it — matching the dump path's behavior. */
        cbm_log_warn("delta.fts_insert_unavailable", "project", ctx->project);
        return;
    }
    cbm_sql_bind_text(fts, DELTA_FTS_BIND_PROJECT, ctx->project);
    cbm_sql_bind_int64(fts, DELTA_FTS_BIND_MAX_DB_ID, ctx->max_db_id);
    if (cbm_sql_step(fts) != CBM_SQL_DONE) {
        ctx->failed = true;
    }
    cbm_sql_finalize(fts);
}

static void delta_log_patch(const delta_patch_ctx_t *ctx) {
    char nodes[DELTA_LOG_COUNT_BUFFER_SIZE];
    char edges[DELTA_LOG_COUNT_BUFFER_SIZE];
    char remapped[DELTA_LOG_COUNT_BUFFER_SIZE];
    snprintf(nodes, sizeof(nodes), "%lld", (long long)ctx->nodes);
    snprintf(edges, sizeof(edges), "%lld", (long long)ctx->edges);
    snprintf(remapped, sizeof(remapped), "%lld", (long long)ctx->remapped);
    cbm_log_info("delta.patch", "nodes", nodes, "edges", edges, "remapped", remapped);
}

int cbm_delta_patch(cbm_store_t *store, const char *project, cbm_gbuf_t *gbuf, int64_t max_db_id,
                    const cbm_delta_saved_edge_t *snapshot, int snapshot_count) {
    cbm_sql_t *db = cbm_store_sql(store);
    if (!db) {
        return CBM_NOT_FOUND;
    }
    if (cbm_store_begin(store) != CBM_STORE_OK) {
        return CBM_NOT_FOUND;
    }
    delta_patch_ctx_t ctx = {.db = db, .project = project, .max_db_id = max_db_id};
    if (!delta_prepare_patch_statements(db, &ctx)) {
        cbm_store_rollback(store);
        return CBM_NOT_FOUND;
    }
    cbm_gbuf_foreach_node(gbuf, delta_patch_node, &ctx);
    if (!ctx.failed) {
        cbm_gbuf_foreach_edge(gbuf, delta_patch_edge, &ctx);
    }
    delta_finalize_patch_statements(&ctx);
    delta_relink_snapshot(&ctx, snapshot, snapshot_count);
    delta_patch_fts(&ctx);

    if (ctx.failed) {
        free(ctx.remap);
        cbm_store_rollback(store);
        return CBM_NOT_FOUND;
    }
    free(ctx.remap);
    if (cbm_store_commit(store) != CBM_STORE_OK) {
        return CBM_NOT_FOUND;
    }
    delta_log_patch(&ctx);
    return 0;
}
