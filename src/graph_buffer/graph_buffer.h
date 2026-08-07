/*
 * graph_buffer.h — In-memory graph buffer for pipeline indexing.
 *
 * Holds all nodes and edges in RAM during indexing, then dumps to SQLite.
 * Provides O(1) node lookup by qualified name and edge dedup by key.
 *
 * Depends on: foundation (hash_table, dyn_array), store (data structs)
 */
#ifndef CBM_GRAPH_BUFFER_H
#define CBM_GRAPH_BUFFER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

/* ── Opaque handle ──────────────────────────────────────────────── */

typedef struct cbm_gbuf cbm_gbuf_t;

/* Forward declare store for dump path */
typedef struct cbm_store cbm_store_t;

/* ── Nominal ID types ─────────────────────────────────────────────── */

/* Node and edge temp IDs are distinct single-field structs so the compiler
 * rejects mixing them. Passing a node id where an edge id is expected, or a
 * bare int64_t where either is expected, is a compile error.
 *
 * These types do NOT by themselves catch a transposed source_id/target_id at
 * a call site: both endpoints are node ids, so two bare cbm_node_id_t
 * arguments have the same type and swapping them would still compile, still
 * reversing the edge with no diagnostic. That hazard is closed by
 * cbm_edge_endpoints_t below, which requires the roles to be named at the
 * call site instead of inferred from argument order. */
typedef struct {
    int64_t v;
} cbm_node_id_t;

typedef struct {
    int64_t v;
} cbm_edge_id_t;

/* Edge endpoints, named rather than positional. cbm_gbuf_insert_edge and
 * cbm_gbuf_insert_edge_props take one of these instead of two bare
 * cbm_node_id_t parameters, so a transposition stops being a silent
 * positional slip and becomes a statement the caller must write on purpose:
 *
 *     cbm_gbuf_insert_edge(gb, (cbm_edge_endpoints_t){.source = caller,
 *                                                      .target = callee},
 *                          "CALLS", props);
 *
 * Always use the designated-initializer form (.source = ..., .target = ...)
 * at every call site. A positional initializer, (cbm_edge_endpoints_t){a, b},
 * reintroduces the exact hazard this type exists to remove and must never be
 * used. */
typedef struct {
    cbm_node_id_t source;
    cbm_node_id_t target;
} cbm_edge_endpoints_t;

/* Sentinel for "no id" / error, matching the buffer's existing convention
 * (temp ids are sequential from 1; 0 means not-found or allocation failure). */
#define CBM_NODE_ID_INVALID ((cbm_node_id_t){0})
#define CBM_EDGE_ID_INVALID ((cbm_edge_id_t){0})

static inline cbm_node_id_t cbm_node_id(int64_t v) {
    return (cbm_node_id_t){v};
}
static inline cbm_edge_id_t cbm_edge_id(int64_t v) {
    return (cbm_edge_id_t){v};
}

/* Unwrap to a plain int64_t — for serialization, SQL binding, printf, and
 * hash-table keys. Should not be used to feed logic that stays inside the
 * buffer; keep computations in the wrapped type. */
static inline int64_t cbm_node_id_value(cbm_node_id_t id) {
    return id.v;
}
static inline int64_t cbm_edge_id_value(cbm_edge_id_t id) {
    return id.v;
}

static inline bool cbm_node_id_eq(cbm_node_id_t a, cbm_node_id_t b) {
    return a.v == b.v;
}
static inline bool cbm_edge_id_eq(cbm_edge_id_t a, cbm_edge_id_t b) {
    return a.v == b.v;
}

static inline bool cbm_node_id_valid(cbm_node_id_t id) {
    return id.v != 0;
}
static inline bool cbm_edge_id_valid(cbm_edge_id_t id) {
    return id.v != 0;
}

/* ── Node / Edge structs (owned by the buffer) ───────────────────── */

typedef struct {
    cbm_node_id_t id;           /* temp ID (sequential from 1) */
    const char *label;          /* pool-owned (interned); freed once by the pool, not here */
    char *name;                 /* heap-owned */
    char *qualified_name;       /* heap-owned */
    const char *file_path;      /* pool-owned (interned); freed once by the pool, not here */
    int start_line;
    int end_line;
    char *properties_json; /* heap-owned JSON string, "{}" default */
} cbm_gbuf_node_t;

/* Typed edge property kinds. STRING also carries verbatim JSON literal text
 * for values the buffer cannot classify (arrays, objects) — see
 * cbm_gbuf_insert_edge's JSON-parsing shim. */
typedef enum {
    CBM_EDGE_PROP_STRING,
    CBM_EDGE_PROP_NUMBER,
    CBM_EDGE_PROP_BOOL,
} cbm_edge_prop_kind_t;

/* A single typed edge property. As an argument to cbm_gbuf_insert_edge_props,
 * key/text are borrowed (callers pass string literals or stack buffers that
 * outlive only the call); the buffer heap-copies them on store. */
typedef struct {
    const char *key; /* borrowed on input; heap-owned once stored on an edge */
    cbm_edge_prop_kind_t kind;
    const char *text; /* STRING only; NULL for NUMBER/BOOL */
    double number;    /* NUMBER only */
    bool flag;        /* BOOL only */
    int decimals;     /* NUMBER only: fixed decimals when serializing to JSON */
} cbm_gbuf_prop_t;

typedef struct {
    cbm_edge_id_t id;          /* temp ID */
    cbm_node_id_t source_id;   /* temp node ID */
    cbm_node_id_t target_id;   /* temp node ID */
    const char *type;          /* pool-owned (interned); freed once by the pool, not here */
    cbm_gbuf_prop_t *props;    /* heap-owned array; each key/text heap-owned */
    int prop_count;
} cbm_gbuf_edge_t;

/* ── Lifecycle ──────────────────────────────────────────────────── */

/* Create a new graph buffer for a project. */
cbm_gbuf_t *cbm_gbuf_new(const char *project, const char *root_path);

/* Create a graph buffer with a shared atomic ID source.
 * IDs are allocated via atomic_fetch_add on *id_source.
 * Used for parallel extraction where multiple gbufs need unique IDs.
 * If id_source is NULL, behaves like cbm_gbuf_new(). */
cbm_gbuf_t *cbm_gbuf_new_shared_ids(const char *project, const char *root_path,
                                    _Atomic int64_t *id_source);

/* Free the graph buffer and all owned data. NULL-safe. */
void cbm_gbuf_free(cbm_gbuf_t *gb);

/* Merge all nodes and edges from src into dst.
 * Nodes are merged by QN: on collision, src wins (updates dst node fields).
 * New nodes are inserted with their original IDs (from shared ID source).
 * Edges are remapped for any QN-colliding nodes, then inserted with dedup.
 * After merge, src can be safely freed (all data is copied).
 * Returns 0 on success, -1 on error. */
int cbm_gbuf_merge(cbm_gbuf_t *dst, cbm_gbuf_t *src);

/* ── Node operations ─────────────────────────────────────────────── */

/* Upsert a node by qualified name. Returns the temp ID.
 * All string fields are copied (buffer owns the copies).
 * Returns 0 on error. */
cbm_node_id_t cbm_gbuf_upsert_node(cbm_gbuf_t *gb, const char *label, const char *name,
                                   const char *qualified_name, const char *file_path,
                                   int start_line, int end_line, const char *properties_json);

/* Find a node by qualified name. Returns NULL if not found. */
const cbm_gbuf_node_t *cbm_gbuf_find_by_qn(const cbm_gbuf_t *gb, const char *qn);

/* Find a node by temp ID. Returns NULL if not found. */
const cbm_gbuf_node_t *cbm_gbuf_find_by_id(const cbm_gbuf_t *gb, cbm_node_id_t id);

/* Find nodes by label. Sets *out and *count. Caller does NOT free.
 * Returns 0 on success, -1 on error. */
int cbm_gbuf_find_by_label(const cbm_gbuf_t *gb, const char *label, const cbm_gbuf_node_t ***out,
                           int *count);

/* Find nodes by name (exact). Sets *out and *count. Caller does NOT free. */
int cbm_gbuf_find_by_name(const cbm_gbuf_t *gb, const char *name, const cbm_gbuf_node_t ***out,
                          int *count);

/* Count total nodes in buffer. */
int cbm_gbuf_node_count(const cbm_gbuf_t *gb);

/* Replace a node's properties JSON in place, keyed by id.
 *
 * The lookup API above hands out `const cbm_gbuf_node_t *`, so a pass that
 * enriches nodes it found has no typed way to write the result back. This is
 * that way. Node storage belongs to the buffer, so the buffer performs the
 * write and frees the string it replaces; a caller unwrapping the const off a
 * looked-up node and assigning the field itself is a const violation whether
 * or not the compiler is able to see it.
 *
 * Copies the string. Returns false if the id names no node. */
bool cbm_gbuf_set_node_properties_json(cbm_gbuf_t *gb, cbm_node_id_t id,
                                       const char *properties_json);

/* Get the next ID that would be assigned. Used to initialize shared atomic counters. */
int64_t cbm_gbuf_next_id(const cbm_gbuf_t *gb);

/* Set the next ID counter. Used after merging worker gbufs to sync the main counter. */
void cbm_gbuf_set_next_id(cbm_gbuf_t *gb, int64_t next_id);
/* next_id/set_next_id stay bare int64_t: they address the shared allocation
 * counter, not a specific node or edge, so neither nominal type applies. */

/* Delete all nodes with a label. Cascade-deletes referencing edges. */
int cbm_gbuf_delete_by_label(cbm_gbuf_t *gb, const char *label);

/* Delete all nodes for a given file path. Cascade-deletes referencing edges.
 * Used by incremental indexing to remove stale nodes before re-extraction. */
int cbm_gbuf_delete_by_file(cbm_gbuf_t *gb, const char *file_path);

/* Bulk-load all nodes and edges for a project from an existing SQLite DB
 * into this graph buffer. Returns 0 on success. */
int cbm_gbuf_load_from_db(cbm_gbuf_t *gb, const char *db_path, const char *project);

/* Iterate all live nodes (not deleted from QN index). */
typedef void (*cbm_gbuf_node_visitor_fn)(const cbm_gbuf_node_t *node, void *userdata);
void cbm_gbuf_foreach_node(const cbm_gbuf_t *gb, cbm_gbuf_node_visitor_fn fn, void *userdata);

/* Iterate all edges. */
typedef void (*cbm_gbuf_edge_visitor_fn)(const cbm_gbuf_edge_t *edge, void *userdata);
void cbm_gbuf_foreach_edge(const cbm_gbuf_t *gb, cbm_gbuf_edge_visitor_fn fn, void *userdata);

/* ── Edge operations ─────────────────────────────────────────────── */

/* Insert an edge. Deduplicates by (source_id, target_id, type).
 * On duplicate, merges properties (later wins). Returns edge temp ID.
 * Returns 0 on error. */
cbm_edge_id_t cbm_gbuf_insert_edge(cbm_gbuf_t *gb, cbm_edge_endpoints_t endpoints, const char *type,
                                   const char *properties_json);

/* Insert an edge with typed properties. Deduplicates by (source_id, target_id,
 * type) — IMPORTS edges also key on the "local_name" property (#768). On
 * duplicate, replaces the stored properties only when the incoming set wins
 * under edge_props_should_replace's rule (higher "confidence" wins; ties
 * break on a deterministic serialized-JSON order; an empty incoming set never
 * displaces stored properties). props/prop_count are borrowed for the call;
 * key/text are heap-copied into the edge. Returns edge temp ID, 0 on error. */
cbm_edge_id_t cbm_gbuf_insert_edge_props(cbm_gbuf_t *gb, cbm_edge_endpoints_t endpoints,
                                         const char *type, const cbm_gbuf_prop_t *props,
                                         int prop_count);

/* Typed property accessors. Return NULL/false when the edge has no property
 * with that key and kind. The returned string pointer is borrowed (edge-owned,
 * valid until the edge is freed or its properties are replaced). */
const char *cbm_gbuf_edge_prop_string(const cbm_gbuf_edge_t *edge, const char *key);
bool cbm_gbuf_edge_prop_number(const cbm_gbuf_edge_t *edge, const char *key, double *out);
bool cbm_gbuf_edge_prop_bool(const cbm_gbuf_edge_t *edge, const char *key, bool *out);

/* Serialize an edge's typed properties to a flat JSON object into `out`
 * (NUL-terminated, keys in insertion order, numbers at their fixed decimals,
 * strings JSON-escaped). Empty property list yields "{}". Returns true if the
 * JSON fit in out_size; on overflow or error, out holds an empty string. */
bool cbm_gbuf_edge_props_json(const cbm_gbuf_edge_t *edge, char *out, size_t out_size);

/* Serialize an edge's typed properties to a malloc'd flat JSON object string
 * (unbounded — for callers that cannot use a fixed-size buffer, e.g. an
 * incremental-index snapshot capturing CALLS edges' arg-expression props).
 * Caller frees. Returns NULL on OOM or a NULL edge — callers must treat NULL
 * as a failed capture, not silently substitute "{}". */
char *cbm_gbuf_edge_props_json_alloc(const cbm_gbuf_edge_t *edge);

/* Find edges from source_id with given type.
 * Sets *out and *count. Caller does NOT free. */
int cbm_gbuf_find_edges_by_source_type(const cbm_gbuf_t *gb, cbm_node_id_t source_id,
                                       const char *type, const cbm_gbuf_edge_t ***out, int *count);

/* Find edges to target_id with given type. */
int cbm_gbuf_find_edges_by_target_type(const cbm_gbuf_t *gb, cbm_node_id_t target_id,
                                       const char *type, const cbm_gbuf_edge_t ***out, int *count);

/* Find all edges of a given type. */
int cbm_gbuf_find_edges_by_type(const cbm_gbuf_t *gb, const char *type,
                                const cbm_gbuf_edge_t ***out, int *count);

/* Count total edges. */
int cbm_gbuf_edge_count(const cbm_gbuf_t *gb);

/* Count edges of a given type. */
int cbm_gbuf_edge_count_by_type(const cbm_gbuf_t *gb, const char *type);

/* Delete all edges of a type. */
int cbm_gbuf_delete_edges_by_type(cbm_gbuf_t *gb, const char *type);

/* ── Vector storage (for semantic embeddings) ───────────────────── */

/* Store an int8-quantized vector for a node. The vector data is copied.
 * Called by pass_semantic_edges after computing RI vectors.
 * Vectors are carried through to cbm_write_db during the dump phase. */
int cbm_gbuf_store_vector(cbm_gbuf_t *gb, cbm_node_id_t node_id, const uint8_t *vector,
                          int vector_len);

/* Store an enriched token vector for query-time lookup.
 * Called by pass_semantic_edges after corpus finalization.
 * Token string and vector data are copied. */
int cbm_gbuf_store_token_vector(cbm_gbuf_t *gb, const char *token, const uint8_t *vector,
                                int vector_len, float idf);

/* ── Dump to SQLite ──────────────────────────────────────────────── */

/* Dump the entire buffer to a SQLite file using the direct page writer.
 * Assigns sequential final IDs and remaps edge references.
 * Returns 0 on success, -1 on error. */
int cbm_gbuf_dump_to_sqlite(cbm_gbuf_t *gb, const char *path);

/* Flush the buffer to an existing store via the store API.
 * Deletes existing project data first. Returns 0 on success. */
int cbm_gbuf_flush_to_store(cbm_gbuf_t *gb, cbm_store_t *store);

/* Merge the buffer into an existing store WITHOUT deleting existing data.
 * Upserts nodes, inserts edges. Used for incremental indexing.
 * Returns 0 on success. */
int cbm_gbuf_merge_into_store(cbm_gbuf_t *gb, cbm_store_t *store);

#endif /* CBM_GRAPH_BUFFER_H */
