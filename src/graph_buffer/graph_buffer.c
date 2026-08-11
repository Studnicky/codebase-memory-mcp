/*
 * graph_buffer.c — In-memory graph buffer for pipeline indexing.
 *
 * Uses foundation hash tables for O(1) node lookup by QN and edge dedup.
 * Uses dynamic arrays for ordered iteration and secondary indexes.
 *
 * Memory ownership: each node/edge is individually heap-allocated so that
 * pointers stored in hash tables remain stable when the pointer-array grows.
 * The buffer frees everything in cbm_gbuf_free().
 */
#include "foundation/constants.h"

enum {
    GB_ERR = -1,
    GB_COL_2 = 2,
    GB_COL_3 = 3,
    GB_COL_4 = 4,
    GB_COL_5 = 5,
    GB_COL_6 = 6,
    GB_COL_7 = 7,
    GB_URL_PATH_PREFIX = 12,   /* strlen(""url_path":"") */
    GB_MIN_FOR_DEDUP = 2,      /* need at least 2 vectors to sort+dedup */
    GB_DEDUP_LOOKAHEAD = 1,    /* compare current with next element */
    GB_JSON_ESC_BUF = 8,       /* longest single-char JSON escape, e.g. "" + NUL */
    GB_JSON_INIT_CAP = 256,    /* initial growable-buffer capacity for JSON serialization */
    GB_JSON_GROW = 2,          /* growable-buffer doubling factor */
    GB_NUM_BUF = 64,           /* fixed-decimal number rendering buffer */
    GB_ASCII_PRINTABLE = 0x20, /* control characters below this need \u escaping */
    GB_NAME_ORDER_LESS = -1,
    GB_NAME_ORDER_GREATER = 1,
    GB_ID_INDEX_GROWTH_FACTOR = 2,
};
#include "graph_buffer/graph_buffer.h"
#include <yyjson/yyjson.h> // url_path extraction must match json_extract semantics
#include "store/store.h"
#include "sqlite_writer.h"
#include "foundation/hash_table.h"
#include "foundation/compat.h"
#include "foundation/log.h"
#include "foundation/dyn_array.h"
#include "foundation/profile.h"
#include "store/sql.h"

#include <stdatomic.h>
#include <stdint.h> // int64_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // strdup
#include <time.h>

static const uint64_t GB_FNV1A_OFFSET_BASIS = UINT64_C(14695981039346656037);
static const uint64_t GB_FNV1A_PRIME = UINT64_C(1099511628211);

static inline void *intptr_to_ptr(intptr_t v) {
    void *p;
    memcpy(&p, &v, sizeof(p));
    return p;
}

/* Free a const-qualified pointer this code owns and is releasing (e.g. a
 * hash-table key handed back as const char*). Reading the pointer value out
 * with memcpy transfers ownership without a qualifier-discarding cast, which
 * -Wcast-qual would otherwise report at every one of this file's release
 * sites rather than once here. Mirrors foundation/platform.h's safe_str_free. */
static inline void free_owned_const(const void *p) {
    void *owned;
    memcpy(&owned, &p, sizeof(owned));
    free(owned);
}

/* ── Internal types ──────────────────────────────────────────────── */

/* Edge key for dedup hash table — composite key as string "srcID:tgtID:type",
 * plus ":local_name" for IMPORTS edges (#768). 256 bytes fit two int64s, the
 * type and a ~200-char local_name verbatim; longer local_names are re-keyed
 * with a hash of the full name in make_edge_key (never silently truncated). */
#define EDGE_KEY_BUF CBM_SZ_256

/* Per-type or per-key edge list stored in hash tables as values */
typedef CBM_DYN_ARRAY(const cbm_gbuf_edge_t *) edge_ptr_array_t;

/* Per-label or per-name node list */
typedef CBM_DYN_ARRAY(const cbm_gbuf_node_t *) node_ptr_array_t;

struct cbm_gbuf {
    char *project;
    char *root_path;
    int64_t next_id;
    _Atomic int64_t *shared_ids; /* NULL = use next_id, non-NULL = atomic source */

    /* Node storage: array of pointers to individually heap-allocated nodes.
     * This ensures pointers stored in hash tables remain valid when the
     * pointer array reallocs (only the pointer array moves, not the nodes). */
    CBM_DYN_ARRAY(cbm_gbuf_node_t *) nodes;

    /* Primary index: QN → cbm_gbuf_node_t* */
    CBMHashTable *node_by_qn;
    /* Primary index: "id" string → cbm_gbuf_node_t* */
    /* Dense id → node array (ids are sequential from alloc_next_id, shared
     * with edges → holes where edges took ids). Replaces a hash table keyed
     * on STRDUP'D DECIMAL STRINGS of the id — ~0.44 GB of buckets + key
     * strings at kernel scale, plus a snprintf+strdup+hash on every one of
     * the ~18 hot find_by_id call sites. */
    cbm_gbuf_node_t **by_id;
    int64_t by_id_cap;

    /* Secondary node indexes */
    CBMHashTable *nodes_by_label; /* key: label, value: (node_ptr_array_t*) */
    CBMHashTable *nodes_by_name;  /* key: name, value: (node_ptr_array_t*) */

    /* Edge storage: array of pointers to individually heap-allocated edges */
    CBM_DYN_ARRAY(cbm_gbuf_edge_t *) edges;

    /* Edge dedup index: "srcID:tgtID:type" → cbm_gbuf_edge_t* */
    CBMHashTable *edge_by_key;

    /* Edge secondary indexes: composite keys → edge_ptr_array_t */
    CBMHashTable *edges_by_source_type; /* "srcID:type" → edge_ptr_array_t* */
    CBMHashTable *edges_by_target_type; /* "tgtID:type" → edge_ptr_array_t* */
    CBMHashTable *edges_by_type;        /* "type" → edge_ptr_array_t* */

    /* String intern pool for highly-repetitive fields (node label/file_path,
     * edge type). Maps string content → owned canonical copy, collapsing
     * O(nodes+edges) duplicate allocations to O(distinct). The pool owns the
     * copies; interned pointers are stable for the buffer lifetime and are NOT
     * freed by free_node_strings/free_edge_strings — only once in cbm_gbuf_free. */
    CBMHashTable *intern_pool;

    /* Vector storage for semantic embeddings (filled by pass_semantic_edges,
     * consumed by cbm_write_db during dump). */
    CBMDumpVector *dump_vectors;
    int dump_vector_count;
    int dump_vector_cap;

    /* Token vector storage for enriched RI vectors (query-time lookup). */
    CBMDumpTokenVec *dump_token_vecs;
    int dump_token_vec_count;
    int dump_token_vec_cap;
};

/* A narrow allocation seam covers dump/store preflight buffers only. Production
 * keeps using the standard allocator directly; tests can exercise every failure
 * boundary without affecting graph construction or the store adapter. */
#ifdef CBM_ENABLE_TEST_SEAMS
static atomic_int g_preflight_allocations_before_failure = ATOMIC_VAR_INIT(-1);

void cbm_gbuf_fail_allocation_after_for_test(int successful_allocations) {
    atomic_store_explicit(&g_preflight_allocations_before_failure, successful_allocations,
                          memory_order_relaxed);
}

static bool gb_preflight_allocation_fails(void) {
    int remaining =
        atomic_load_explicit(&g_preflight_allocations_before_failure, memory_order_relaxed);
    while (remaining >= 0) {
        if (remaining == 0) {
            return true;
        }
        if (atomic_compare_exchange_weak_explicit(&g_preflight_allocations_before_failure,
                                                  &remaining, remaining - 1, memory_order_relaxed,
                                                  memory_order_relaxed)) {
            return false;
        }
    }
    return false;
}
#else
static bool gb_preflight_allocation_fails(void) {
    return false;
}
#endif

static void *gb_preflight_malloc(size_t size) {
    return gb_preflight_allocation_fails() ? NULL : malloc(size);
}

static void *gb_preflight_calloc(size_t count, size_t size) {
    return gb_preflight_allocation_fails() ? NULL : calloc(count, size);
}

static void *gb_preflight_realloc(void *ptr, size_t size) {
    return gb_preflight_allocation_fails() ? NULL : realloc(ptr, size);
}

/* ── Helpers ─────────────────────────────────────────────────────── */

/* String fields whose caller intentionally omits a value retain that absence.
 * Callers that require a JSON object pass the "{}" default explicitly. */
static char *heap_strdup(const char *s) {
    return s ? strdup(s) : NULL;
}

/* Intern a repetitive structural string into the buffer's pool: identical
 * content collapses to a single heap copy owned by the pool. NULL maps to
 * "{}" for labels and paths; node names retain NULL separately. The returned
 * pointer is stable for the buffer's lifetime and must never be freed or
 * mutated by callers. Returns NULL only on OOM. */
static const char *gb_intern(cbm_gbuf_t *gb, const char *s) {
    const char *key = s ? s : "{}";
    const char *found = cbm_ht_get(gb->intern_pool, key);
    if (found) {
        return found;
    }
    char *copy = strdup(key);
    if (copy) {
        cbm_ht_set(gb->intern_pool, copy, copy); /* key == value == owned copy */
    }
    return copy;
}

/* Compare nullable names without normalizing absence into a source string. */
static int gb_name_compare(const char *left, const char *right) {
    if (!left) {
        return right ? GB_NAME_ORDER_LESS : 0;
    }
    return right ? strcmp(left, right) : GB_NAME_ORDER_GREATER;
}

static void make_id_key(char *buf, size_t bufsz, cbm_node_id_t id) {
    snprintf(buf, bufsz, "%lld", (long long)cbm_node_id_value(id));
}

/* FNV-1a 64-bit over a byte slice — for re-keying oversized local_names. */
static uint64_t fnv1a64(const char *s, size_t len) {
    uint64_t h = GB_FNV1A_OFFSET_BASIS;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= GB_FNV1A_PRIME;
    }
    return h;
}

/* Find a property by key in a typed property array (edge-owned or a raw
 * incoming array — both use cbm_gbuf_prop_t). Returns NULL if absent. */
static const cbm_gbuf_prop_t *find_prop(const cbm_gbuf_prop_t *props, int prop_count,
                                        const char *key) {
    for (int i = 0; i < prop_count; i++) {
        if (props[i].key && strcmp(props[i].key, key) == 0) {
            return &props[i];
        }
    }
    return NULL;
}

/* IMPORTS edges carry exactly one imported symbol's local_name (#768): two
 * named imports from the same specifier resolve to the same (source,
 * target) pair but are distinct symbols. Key on local_name too so the
 * second import doesn't dedup-collide with and overwrite the first —
 * every pass that walks IMPORTS edges (pass_calls.c, pass_usages.c,
 * pass_semantic.c, pass_lsp_cross.c) expects one local_name per edge, so
 * losing an edge here silently breaks cross-file call resolution for
 * whichever symbol got dropped, not just "who imports X" queries. Other
 * edge types keep the plain (source,target,type) key: collapsing repeat
 * edges of the same type between the same two nodes (e.g. multiple call
 * sites) into one is the existing, intended dedup behavior there.
 *
 * A local_name too long for the key buffer is re-keyed with an FNV-1a hash
 * of the FULL name instead of being truncated — a truncated key would
 * collide two long names sharing a prefix and silently drop an edge again.
 * The hash key is prefixed with byte 0x01, which cannot appear in the raw
 * JSON slice (control characters must be \u-escaped in JSON), so hash keys
 * can never collide with verbatim keys.
 *
 * local_name is read from the typed property list rather than by scanning
 * JSON text — the decoded value (not its escaped JSON encoding) is what's
 * hashed/keyed on now, which only differs from the prior strstr-based key
 * when local_name itself contains a JSON escape sequence (never true for the
 * identifier-like names this codebase emits). */
static void make_edge_key(char *buf, size_t bufsz, cbm_node_id_t src, cbm_node_id_t tgt,
                          const char *type, const cbm_gbuf_prop_t *props, int prop_count) {
    long long src_v = (long long)cbm_node_id_value(src);
    long long tgt_v = (long long)cbm_node_id_value(tgt);
    if (strcmp(type, "IMPORTS") == 0) {
        const cbm_gbuf_prop_t *ln = find_prop(props, prop_count, "local_name");
        if (ln && ln->kind == CBM_EDGE_PROP_STRING && ln->text) {
            size_t ln_len = strlen(ln->text);
            int n = snprintf(buf, bufsz, "%lld:%lld:%s:%.*s", src_v, tgt_v, type, (int)ln_len,
                             ln->text);
            if (n < 0 || (size_t)n >= bufsz) {
                snprintf(buf, bufsz, "%lld:%lld:%s:\x01%016llx", src_v, tgt_v, type,
                         (unsigned long long)fnv1a64(ln->text, ln_len));
            }
            return;
        }
    }
    snprintf(buf, bufsz, "%lld:%lld:%s", src_v, tgt_v, type);
}

static void make_src_type_key(char *buf, size_t bufsz, cbm_node_id_t src, const char *type) {
    snprintf(buf, bufsz, "%lld:%s", (long long)cbm_node_id_value(src), type);
}

/* Get or create a node_ptr_array_t in a hash table */
static node_ptr_array_t *get_or_create_node_array(CBMHashTable *ht, const char *key) {
    node_ptr_array_t *arr = cbm_ht_get(ht, key);
    if (!arr) {
        arr = calloc(CBM_ALLOC_ONE, sizeof(node_ptr_array_t));
        cbm_ht_set(ht, strdup(key), arr);
    }
    return arr;
}

/* Get or create an edge_ptr_array_t in a hash table */
static edge_ptr_array_t *get_or_create_edge_array(CBMHashTable *ht, const char *key) {
    edge_ptr_array_t *arr = cbm_ht_get(ht, key);
    if (!arr) {
        arr = calloc(CBM_ALLOC_ONE, sizeof(edge_ptr_array_t));
        cbm_ht_set(ht, strdup(key), arr);
    }
    return arr;
}

/* Free a node_ptr_array_t (callback for hash table iteration) */
static void free_node_array(const char *key, void *value, void *ud) {
    (void)ud;
    node_ptr_array_t *arr = value;
    if (arr) {
        cbm_da_free(arr);
        free(arr);
    }
    free_owned_const(key);
}

/* Free an edge_ptr_array_t (callback) */
static void free_edge_array(const char *key, void *value, void *ud) {
    (void)ud;
    edge_ptr_array_t *arr = value;
    if (arr) {
        cbm_da_free(arr);
        free(arr);
    }
    free_owned_const(key);
}

/* Free keys only (for edge_by_key, deleted_set) */
static void free_key_only(const char *key, void *value, void *ud) {
    (void)value;
    (void)ud;
    free_owned_const(key);
}

/* Free a single node's owned strings. label and file_path are interned
 * (pool-owned) — NOT freed here; the pool frees them once in cbm_gbuf_free. */
static void free_node_strings(cbm_gbuf_node_t *n) {
    free(n->name);
    free(n->qualified_name);
    free(n->properties_json);
}

/* Free a single edge's owned properties (each prop's key/text) and the props
 * array itself. type is interned (pool-owned) — NOT freed here; the pool
 * frees it once in cbm_gbuf_free. */
static void free_edge_props(cbm_gbuf_prop_t *props, int prop_count) {
    for (int i = 0; i < prop_count; i++) {
        free_owned_const(props[i].key);
        free_owned_const(props[i].text);
    }
    free(props);
}

static void free_edge_strings(cbm_gbuf_edge_t *e) {
    free_edge_props(e->props, e->prop_count);
    e->props = NULL;
    e->prop_count = 0;
}

/* Allocate the next buffer-local or shared-atomic ID. */
static int64_t alloc_next_id(cbm_gbuf_t *gb) {
    if (gb->shared_ids) {
        return atomic_fetch_add_explicit(gb->shared_ids, SKIP_ONE, memory_order_relaxed);
    }
    return gb->next_id++;
}

/* Swap-remove an edge from a pointer array by ID. */
static void remove_edge_from_ptr_array(edge_ptr_array_t *arr, cbm_edge_id_t edge_id) {
    if (!arr) {
        return;
    }
    for (int j = 0; j < arr->count; j++) {
        if (cbm_edge_id_eq(arr->items[j]->id, edge_id)) {
            arr->items[j] = arr->items[--arr->count];
            return;
        }
    }
}

/* Swap-remove a node from a node_ptr_array by ID. */
static void remove_node_from_ptr_array(node_ptr_array_t *arr, cbm_node_id_t node_id) {
    if (!arr) {
        return;
    }
    for (int j = 0; j < arr->count; j++) {
        if (cbm_node_id_eq(arr->items[j]->id, node_id)) {
            arr->items[j] = arr->items[--arr->count];
            return;
        }
    }
}

/* Remove an edge from all indexes (dedup + source_type + target_type + type). */
static void unindex_edge(cbm_gbuf_t *gb, const cbm_gbuf_edge_t *e) {
    char key[EDGE_KEY_BUF];

    make_edge_key(key, sizeof(key), e->source_id, e->target_id, e->type, e->props, e->prop_count);
    const char *ekey = cbm_ht_get_key(gb->edge_by_key, key);
    cbm_ht_delete(gb->edge_by_key, key);
    free_owned_const(ekey);

    make_src_type_key(key, sizeof(key), e->source_id, e->type);
    remove_edge_from_ptr_array(cbm_ht_get(gb->edges_by_source_type, key), e->id);

    make_src_type_key(key, sizeof(key), e->target_id, e->type);
    remove_edge_from_ptr_array(cbm_ht_get(gb->edges_by_target_type, key), e->id);

    remove_edge_from_ptr_array(cbm_ht_get(gb->edges_by_type, e->type), e->id);
}

/* Cascade-delete all edges touching nodes in deleted_set. */
static void cascade_delete_edges(cbm_gbuf_t *gb, CBMHashTable *deleted_set) {
    int write_idx = 0;
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        char src_id[CBM_SZ_32];
        char tgt_id[CBM_SZ_32];
        make_id_key(src_id, sizeof(src_id), e->source_id);
        make_id_key(tgt_id, sizeof(tgt_id), e->target_id);

        if (cbm_ht_get(deleted_set, src_id) || cbm_ht_get(deleted_set, tgt_id)) {
            unindex_edge(gb, e);
            free_edge_strings(e);
            free(e);
        } else {
            gb->edges.items[write_idx++] = gb->edges.items[i];
        }
    }
    gb->edges.count = write_idx;
}

/* Register a node in primary (QN, ID) and secondary (label, name) indexes. */
static void register_node_in_indexes(cbm_gbuf_t *gb, cbm_gbuf_node_t *node) {
    cbm_ht_set(gb->node_by_qn, node->qualified_name, node);

    int64_t node_id_v = cbm_node_id_value(node->id);
    if (node_id_v >= gb->by_id_cap) {
        int64_t nc = gb->by_id_cap > 0 ? gb->by_id_cap : CBM_SZ_1K;
        while (nc <= node_id_v) {
            nc *= GB_ID_INDEX_GROWTH_FACTOR;
        }
        cbm_gbuf_node_t **grown = realloc(gb->by_id, (size_t)nc * sizeof(*grown));
        if (grown) {
            memset(grown + gb->by_id_cap, 0, (size_t)(nc - gb->by_id_cap) * sizeof(*grown));
            gb->by_id = grown;
            gb->by_id_cap = nc;
        }
    }
    if (node_id_v >= 0 && node_id_v < gb->by_id_cap) {
        gb->by_id[node_id_v] = node;
    }

    node_ptr_array_t *by_label = get_or_create_node_array(gb->nodes_by_label, node->label);
    cbm_da_push(by_label, (const cbm_gbuf_node_t *)node);

    if (node->name) {
        node_ptr_array_t *by_name = get_or_create_node_array(gb->nodes_by_name, node->name);
        cbm_da_push(by_name, (const cbm_gbuf_node_t *)node);
    }
}

/* Push an edge pointer into a dynamic array (wraps macro to reduce CC contribution). */
static void edge_array_push(edge_ptr_array_t *arr, const cbm_gbuf_edge_t *edge) {
    cbm_da_push(arr, edge);
}

/* Index an edge by one key into a hash table bucket. */
static void index_edge_by_key(CBMHashTable *ht, const char *key, cbm_gbuf_edge_t *edge) {
    edge_ptr_array_t *arr = get_or_create_edge_array(ht, key);
    edge_array_push(arr, (const cbm_gbuf_edge_t *)edge);
}

/* Register an edge in secondary indexes (source_type, target_type, type). */
static void register_edge_in_indexes(cbm_gbuf_t *gb, cbm_gbuf_edge_t *edge) {
    char key[EDGE_KEY_BUF];

    make_src_type_key(key, sizeof(key), edge->source_id, edge->type);
    index_edge_by_key(gb->edges_by_source_type, key, edge);

    make_src_type_key(key, sizeof(key), edge->target_id, edge->type);
    index_edge_by_key(gb->edges_by_target_type, key, edge);

    index_edge_by_key(gb->edges_by_type, edge->type, edge);
}

/* Rebuild edge secondary indexes from scratch (after bulk deletion). */
static void rebuild_edge_secondary_indexes(cbm_gbuf_t *gb) {
    cbm_ht_foreach(gb->edges_by_source_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_source_type);
    cbm_ht_foreach(gb->edges_by_target_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_target_type);
    cbm_ht_foreach(gb->edges_by_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_type);

    gb->edges_by_source_type = cbm_ht_create(CBM_SZ_256);
    gb->edges_by_target_type = cbm_ht_create(CBM_SZ_256);
    gb->edges_by_type = cbm_ht_create(CBM_SZ_32);

    for (int i = 0; i < gb->edges.count; i++) {
        register_edge_in_indexes(gb, gb->edges.items[i]);
    }
}

/* Release all lookup hash tables (used by dump after building arrays). */
static void release_gbuf_indexes(cbm_gbuf_t *gb) {
    cbm_ht_free(gb->node_by_qn);
    gb->node_by_qn = NULL;
    free(gb->by_id);
    gb->by_id = NULL;
    gb->by_id_cap = 0;
    cbm_ht_foreach(gb->nodes_by_label, free_node_array, NULL);
    cbm_ht_free(gb->nodes_by_label);
    gb->nodes_by_label = NULL;
    cbm_ht_foreach(gb->nodes_by_name, free_node_array, NULL);
    cbm_ht_free(gb->nodes_by_name);
    gb->nodes_by_name = NULL;
    cbm_ht_foreach(gb->edge_by_key, free_key_only, NULL);
    cbm_ht_free(gb->edge_by_key);
    gb->edge_by_key = NULL;
    cbm_ht_foreach(gb->edges_by_source_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_source_type);
    gb->edges_by_source_type = NULL;
    cbm_ht_foreach(gb->edges_by_target_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_target_type);
    gb->edges_by_target_type = NULL;
    cbm_ht_foreach(gb->edges_by_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_type);
    gb->edges_by_type = NULL;
}

/* ── Lifecycle ──────────────────────────────────────────────────── */

cbm_gbuf_t *cbm_gbuf_new(const char *project, const char *root_path) {
    cbm_gbuf_t *gb = calloc(CBM_ALLOC_ONE, sizeof(cbm_gbuf_t));
    if (!gb) {
        return NULL;
    }

    gb->project = strdup(project ? project : "");
    gb->root_path = strdup(root_path ? root_path : "");
    gb->next_id = SKIP_ONE;
    gb->shared_ids = NULL;

    gb->node_by_qn = cbm_ht_create(CBM_SZ_256);
    gb->by_id = NULL;
    gb->by_id_cap = 0;
    gb->nodes_by_label = cbm_ht_create(CBM_SZ_32);
    gb->nodes_by_name = cbm_ht_create(CBM_SZ_256);

    gb->edge_by_key = cbm_ht_create(CBM_SZ_512);
    gb->edges_by_source_type = cbm_ht_create(CBM_SZ_256);
    gb->edges_by_target_type = cbm_ht_create(CBM_SZ_256);
    gb->edges_by_type = cbm_ht_create(CBM_SZ_32);

    gb->intern_pool = cbm_ht_create(CBM_SZ_1K);

    return gb;
}

cbm_gbuf_t *cbm_gbuf_new_shared_ids(const char *project, const char *root_path,
                                    _Atomic int64_t *id_source) {
    cbm_gbuf_t *gb = cbm_gbuf_new(project, root_path);
    if (gb && id_source) {
        gb->shared_ids = id_source;
    }
    return gb;
}

void cbm_gbuf_free(cbm_gbuf_t *gb) {
    if (!gb) {
        return;
    }

    /* Free each individually-allocated node */
    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];
        free_node_strings(n);
        free(n);
    }
    cbm_da_free(&gb->nodes);

    /* Free each individually-allocated edge */
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        free_edge_strings(e);
        free(e);
    }
    cbm_da_free(&gb->edges);

    /* Free hash tables — may be NULL if already released by dump_to_sqlite */
    if (gb->node_by_qn) {
        cbm_ht_free(gb->node_by_qn);
    }
    free(gb->by_id);
    if (gb->nodes_by_label) {
        cbm_ht_foreach(gb->nodes_by_label, free_node_array, NULL);
        cbm_ht_free(gb->nodes_by_label);
    }
    if (gb->nodes_by_name) {
        cbm_ht_foreach(gb->nodes_by_name, free_node_array, NULL);
        cbm_ht_free(gb->nodes_by_name);
    }
    if (gb->edge_by_key) {
        cbm_ht_foreach(gb->edge_by_key, free_key_only, NULL);
        cbm_ht_free(gb->edge_by_key);
    }
    if (gb->edges_by_source_type) {
        cbm_ht_foreach(gb->edges_by_source_type, free_edge_array, NULL);
        cbm_ht_free(gb->edges_by_source_type);
    }
    if (gb->edges_by_target_type) {
        cbm_ht_foreach(gb->edges_by_target_type, free_edge_array, NULL);
        cbm_ht_free(gb->edges_by_target_type);
    }
    if (gb->edges_by_type) {
        cbm_ht_foreach(gb->edges_by_type, free_edge_array, NULL);
        cbm_ht_free(gb->edges_by_type);
    }

    /* Free vector storage */
    for (int i = 0; i < gb->dump_vector_count; i++) {
        free_owned_const(gb->dump_vectors[i].vector);
    }
    free(gb->dump_vectors);

    /* Free token vector storage */
    for (int i = 0; i < gb->dump_token_vec_count; i++) {
        free_owned_const(gb->dump_token_vecs[i].token);
        free_owned_const(gb->dump_token_vecs[i].vector);
    }
    free(gb->dump_token_vecs);

    /* Free interned strings (node label/file_path, edge type) — pool owns one
     * copy each (key == value), freed exactly once via free_key_only. Done after
     * nodes/edges since they borrowed these pointers. */
    if (gb->intern_pool) {
        cbm_ht_foreach(gb->intern_pool, free_key_only, NULL);
        cbm_ht_free(gb->intern_pool);
    }

    free(gb->project);
    free(gb->root_path);
    free(gb);
}

/* ── Vector storage ──────────────────────────────────────────────── */

int cbm_gbuf_store_vector(cbm_gbuf_t *gb, cbm_node_id_t node_id, const uint8_t *vector,
                          int vector_len) {
    if (!gb || !vector || vector_len <= 0) {
        return GB_ERR;
    }
    enum { VEC_INIT_CAP = 1024, VEC_GROW = 2 };
    if (gb->dump_vector_count >= gb->dump_vector_cap) {
        int new_cap =
            gb->dump_vector_cap < VEC_INIT_CAP ? VEC_INIT_CAP : gb->dump_vector_cap * VEC_GROW;
        CBMDumpVector *grown = realloc(gb->dump_vectors, (size_t)new_cap * sizeof(CBMDumpVector));
        if (!grown) {
            return GB_ERR;
        }
        gb->dump_vectors = grown;
        gb->dump_vector_cap = new_cap;
    }
    /* Copy vector data */
    uint8_t *vec_copy = malloc((size_t)vector_len);
    if (!vec_copy) {
        return GB_ERR;
    }
    memcpy(vec_copy, vector, (size_t)vector_len);

    gb->dump_vectors[gb->dump_vector_count++] = (CBMDumpVector){
        .node_id = cbm_node_id_value(node_id),
        .project = gb->project, /* borrowed — valid until gbuf_free */
        .vector = vec_copy,
        .vector_len = vector_len,
    };
    return 0;
}

int cbm_gbuf_store_token_vector(cbm_gbuf_t *gb, const char *token, const uint8_t *vector,
                                int vector_len, float idf) {
    if (!gb || !token || !vector || vector_len <= 0) {
        return GB_ERR;
    }
    enum { TV_INIT_CAP = 256, TV_GROW = 2 };
    if (gb->dump_token_vec_count >= gb->dump_token_vec_cap) {
        int new_cap =
            gb->dump_token_vec_cap < TV_INIT_CAP ? TV_INIT_CAP : gb->dump_token_vec_cap * TV_GROW;
        CBMDumpTokenVec *grown =
            realloc(gb->dump_token_vecs, (size_t)new_cap * sizeof(CBMDumpTokenVec));
        if (!grown) {
            return GB_ERR;
        }
        gb->dump_token_vecs = grown;
        gb->dump_token_vec_cap = new_cap;
    }
    uint8_t *vec_copy = malloc((size_t)vector_len);
    if (!vec_copy) {
        return GB_ERR;
    }
    memcpy(vec_copy, vector, (size_t)vector_len);

    int idx = gb->dump_token_vec_count;
    gb->dump_token_vecs[idx] = (CBMDumpTokenVec){
        .id = idx + SKIP_ONE, /* 1-based sequential ID */
        .project = gb->project,
        .token = strdup(token),
        .vector = vec_copy,
        .vector_len = vector_len,
        .idf = idf,
    };
    gb->dump_token_vec_count++;
    return 0;
}

/* ── ID accessors ────────────────────────────────────────────────── */

int64_t cbm_gbuf_next_id(const cbm_gbuf_t *gb) {
    if (!gb) {
        return SKIP_ONE;
    }
    if (gb->shared_ids) {
        return atomic_load(gb->shared_ids);
    }
    return gb->next_id;
}

void cbm_gbuf_set_next_id(cbm_gbuf_t *gb, int64_t next_id) {
    if (!gb) {
        return;
    }
    gb->next_id = next_id;
}

/* ── Node operations ─────────────────────────────────────────────── */

cbm_node_id_t cbm_gbuf_upsert_node(cbm_gbuf_t *gb, const char *label, const char *name,
                                   const char *qualified_name, const char *file_path,
                                   int start_line, int end_line, const char *properties_json) {
    if (!gb || !qualified_name) {
        return CBM_NODE_ID_INVALID;
    }

    /* Check if node already exists */
    cbm_gbuf_node_t *existing = cbm_ht_get(gb->node_by_qn, qualified_name);
    if (existing) {
        /* Don't let a per-file "Module" def touch a structural directory node
         * ("Project" root or "Folder"). In a directory-based-module language
         * (Go/Java) a file's module_qn equals its directory QN: a root file →
         * the project name (== the "Project" node's QN); a file in pkg/ →
         * proj.pkg (== the "pkg/" Folder node's QN). Its always-emitted Module
         * def collides here; the directory node is the package/module container
         * and must keep its structural label AND its own name/file_path/range.
         * Updating those in place set the shared node's file_path to whichever
         * same-package file happened to be processed LAST (worker-order
         * dependent) — the nondeterministic file attribution behind #787 — and
         * left the Folder node exposed to delete-nodes-by-file on incremental
         * reindex of that file. Skip the update entirely. (Both the sequential
         * upsert and the parallel local-gbuf merge route through this function.) */
        if (existing->label && label && strcmp(label, "Module") == 0 &&
            (strcmp(existing->label, "Project") == 0 || strcmp(existing->label, "Folder") == 0)) {
            return existing->id;
        }
        /* Same-QN arrival: distinct source entities can share a QN (C: a
         * struct, a function and a macro with one name), and the same entity
         * can be re-upserted with fresh content. The old code let the LAST
         * arrival overwrite — under parallel extraction the merge order
         * varies run to run, so WHICH entity survived flickered (xfs:
         * Function-node count 4998 vs 5015 across two runs) and every
         * order-sensitive consumer downstream inherited it. Pick the
         * survivor by a canonical CONTENT rule instead, a pure function of
         * the two candidates: smallest file_path, then LARGEST start_line,
         * then largest name/label (a mixed-direction composite is still a
         * total order, so the pick is commutative and scheduling-free).
         * Line-descending within a file keeps the classic upsert contract —
         * a later definition in the same file (macro redefinition, refresh
         * of the same entity with new content) replaces the earlier one,
         * deterministically, because intra-file arrival order is fixed. A
         * full tie is the same entity re-upserted → refresh in place.
         * Kind-disambiguated QNs (the real cure) remain a follow-up. */
        int c = strcmp(file_path ? file_path : "", existing->file_path);
        if (c == 0) {
            c = existing->start_line - start_line;
        }
        if (c == 0) {
            c = gb_name_compare(existing->name, name);
        }
        if (c == 0) {
            c = strcmp(existing->label, label ? label : "");
        }
        if (c > 0) {
            return existing->id; /* existing entity is the canonical winner */
        }
        /* Update in-place. name/properties are strdup'd BEFORE freeing old ones
         * (callers may pass existing->name as an argument). label/file_path are
         * interned: gb_intern returns a stable pool pointer (idempotent even when
         * label == existing->label), so the old value is replaced, never freed.
         * When the surviving label/name changes, keep the secondary indexes
         * consistent (the old code left the node listed under its ORIGINAL
         * label/name — cbm_gbuf_find_by_label/name then missed or mis-listed it,
         * which is how the flickering Function set reached the semantic pass). */
        char *new_name = heap_strdup(name);
        /* "{}" is the empty property set, and it is what every reader already
         * substitutes for NULL — so store it once here rather than making each
         * of them remember. It also matches the column's own DEFAULT '{}'. */
        char *new_props = heap_strdup(properties_json ? properties_json : "{}");
        const char *new_label_interned = gb_intern(gb, label);
        bool label_changed = !existing->label || !new_label_interned ||
                             strcmp(existing->label, new_label_interned) != 0;
        bool name_changed = gb_name_compare(existing->name, new_name) != 0;
        if (label_changed) {
            remove_node_from_ptr_array(cbm_ht_get(gb->nodes_by_label, existing->label),
                                       existing->id);
        }
        if (name_changed) {
            if (existing->name) {
                remove_node_from_ptr_array(cbm_ht_get(gb->nodes_by_name, existing->name),
                                           existing->id);
            }
        }
        existing->label = new_label_interned;
        free(existing->name);
        existing->name = new_name;
        existing->file_path = gb_intern(gb, file_path);
        existing->start_line = start_line;
        existing->end_line = end_line;
        if (new_props) {
            free(existing->properties_json);
            existing->properties_json = new_props;
        }
        if (label_changed) {
            node_ptr_array_t *by_label =
                get_or_create_node_array(gb->nodes_by_label, existing->label);
            cbm_da_push(by_label, (const cbm_gbuf_node_t *)existing);
        }
        if (name_changed) {
            if (existing->name) {
                node_ptr_array_t *by_name =
                    get_or_create_node_array(gb->nodes_by_name, existing->name);
                cbm_da_push(by_name, (const cbm_gbuf_node_t *)existing);
            }
        }
        return existing->id;
    }

    /* Heap-allocate a new node (pointer stays stable across array growth) */
    cbm_gbuf_node_t *node = calloc(CBM_ALLOC_ONE, sizeof(cbm_gbuf_node_t));
    if (!node) {
        return CBM_NODE_ID_INVALID;
    }

    cbm_node_id_t id = cbm_node_id(alloc_next_id(gb));
    node->id = id;
    node->label = gb_intern(gb, label);
    node->name = heap_strdup(name);
    node->qualified_name = heap_strdup(qualified_name);
    node->file_path = gb_intern(gb, file_path);
    node->start_line = start_line;
    node->end_line = end_line;
    node->properties_json = heap_strdup(properties_json ? properties_json : "{}");

    /* Store pointer in array and register in all indexes */
    cbm_da_push(&gb->nodes, node);
    register_node_in_indexes(gb, node);

    return id;
}

const cbm_gbuf_node_t *cbm_gbuf_find_by_qn(const cbm_gbuf_t *gb, const char *qn) {
    if (!gb || !qn) {
        return NULL;
    }
    return cbm_ht_get(gb->node_by_qn, qn);
}

const cbm_gbuf_node_t *cbm_gbuf_find_by_id(const cbm_gbuf_t *gb, cbm_node_id_t id) {
    int64_t id_v = cbm_node_id_value(id);
    if (!gb || !gb->by_id || id_v < 0 || id_v >= gb->by_id_cap) {
        return NULL;
    }
    return gb->by_id[id_v];
}

bool cbm_gbuf_set_node_properties_json(cbm_gbuf_t *gb, cbm_node_id_t id,
                                       const char *properties_json) {
    int64_t id_v = cbm_node_id_value(id);
    if (!gb || !gb->by_id || id_v < 0 || id_v >= gb->by_id_cap) {
        return false;
    }
    cbm_gbuf_node_t *node = gb->by_id[id_v];
    if (!node) {
        return false;
    }
    char *copy = heap_strdup(properties_json ? properties_json : "{}");
    if (!copy) {
        return false;
    }
    free(node->properties_json);
    node->properties_json = copy;
    return true;
}

int cbm_gbuf_find_by_label(const cbm_gbuf_t *gb, const char *label, const cbm_gbuf_node_t ***out,
                           int *count) {
    if (!gb || !out || !count) {
        return CBM_NOT_FOUND;
    }
    node_ptr_array_t *arr = cbm_ht_get(gb->nodes_by_label, label ? label : "");
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_find_by_name(const cbm_gbuf_t *gb, const char *name, const cbm_gbuf_node_t ***out,
                          int *count) {
    if (!gb || !name || !out || !count) {
        return CBM_NOT_FOUND;
    }
    node_ptr_array_t *arr = cbm_ht_get(gb->nodes_by_name, name);
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_node_count(const cbm_gbuf_t *gb) {
    /* Use QN hash table count since it's authoritative (handles deletes) */
    return gb ? (int)cbm_ht_count(gb->node_by_qn) : 0;
}

int cbm_gbuf_delete_by_label(cbm_gbuf_t *gb, const char *label) {
    if (!gb || !label) {
        return CBM_NOT_FOUND;
    }

    node_ptr_array_t *arr = cbm_ht_get(gb->nodes_by_label, label);
    if (!arr || arr->count == 0) {
        return 0;
    }

    /* Build hash set of deleted node IDs for O(1) lookup */
    /* arr->count is never negative (it's a live element count). */
    CBMHashTable *deleted_set = cbm_ht_create((size_t)arr->count);
    for (int i = 0; i < arr->count; i++) {
        const cbm_gbuf_node_t *n = arr->items[i];

        char id_buf[CBM_SZ_32];
        make_id_key(id_buf, sizeof(id_buf), n->id);
        cbm_ht_set(deleted_set, strdup(id_buf), intptr_to_ptr(SKIP_ONE));

        /* Remove from primary indexes */
        cbm_ht_delete(gb->node_by_qn, n->qualified_name);
        int64_t n_id_v = cbm_node_id_value(n->id);
        if (n_id_v >= 0 && n_id_v < gb->by_id_cap) {
            gb->by_id[n_id_v] = NULL;
        }
    }

    /* Clear the label array */
    cbm_da_clear(arr);

    /* Cascade-delete edges referencing deleted nodes */
    cascade_delete_edges(gb, deleted_set);

    cbm_ht_foreach(deleted_set, free_key_only, NULL);
    cbm_ht_free(deleted_set);
    return 0;
}

int cbm_gbuf_delete_by_file(cbm_gbuf_t *gb, const char *file_path) {
    if (!gb || !file_path) {
        return CBM_NOT_FOUND;
    }

    /* Collect IDs of nodes in this file */
    CBMHashTable *deleted_set = cbm_ht_create(CBM_SZ_64);
    int deleted_count = 0;
    int scanned = 0;

    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];
        scanned++;
        if (!n->file_path || strcmp(n->file_path, file_path) != 0) {
            continue;
        }
        if (!n->qualified_name || !cbm_ht_get(gb->node_by_qn, n->qualified_name)) {
            continue;
        }

        char id_buf[CBM_SZ_32];
        make_id_key(id_buf, sizeof(id_buf), n->id);
        cbm_ht_set(deleted_set, strdup(id_buf), intptr_to_ptr(SKIP_ONE));

        /* Remove from secondary indexes */
        remove_node_from_ptr_array(cbm_ht_get(gb->nodes_by_label, n->label), n->id);
        if (n->name) {
            remove_node_from_ptr_array(cbm_ht_get(gb->nodes_by_name, n->name), n->id);
        }

        /* Remove from primary indexes */
        cbm_ht_delete(gb->node_by_qn, n->qualified_name);
        int64_t n_id_v = cbm_node_id_value(n->id);
        if (n_id_v >= 0 && n_id_v < gb->by_id_cap) {
            gb->by_id[n_id_v] = NULL;
        }

        /* NULL out QN so dump's liveness check (cbm_ht_get by QN) fails
         * even if a new node with the same QN is inserted later via merge. */
        free(n->qualified_name);
        n->qualified_name = NULL;
        deleted_count++;
    }

    if (deleted_count == 0) {
        cbm_ht_free(deleted_set);
        return 0;
    }

    /* Cascade-delete edges referencing deleted nodes */
    cascade_delete_edges(gb, deleted_set);

    cbm_ht_foreach(deleted_set, free_key_only, NULL);
    cbm_ht_free(deleted_set);
    {
        char s_buf[CBM_SZ_16];
        char d_buf[CBM_SZ_16];
        snprintf(s_buf, sizeof(s_buf), "%d", scanned);
        snprintf(d_buf, sizeof(d_buf), "%d", deleted_count);
        cbm_log_info("gbuf.delete_by_file", "file", file_path, "scanned", s_buf, "deleted", d_buf);
    }
    return deleted_count;
}

int cbm_gbuf_load_from_db(cbm_gbuf_t *gb, const char *db_path, const char *project) {
    if (!gb || !db_path || !project) {
        return CBM_NOT_FOUND;
    }

    cbm_store_t *store = cbm_store_open_path(db_path);
    if (!store) {
        return CBM_NOT_FOUND;
    }

    cbm_sql_t *db = cbm_store_sql(store);
    if (!db) {
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }

    /* First pass: find max node ID for mapping array */
    cbm_sql_stmt_t *stmt = NULL;
    if (!cbm_sql_prepare(db, "SELECT MAX(id) FROM nodes WHERE project = ?", &stmt)) {
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    cbm_sql_bind_text(stmt, SKIP_ONE, project);
    int64_t max_old_id = 0;
    if (cbm_sql_step(stmt) == CBM_SQL_ROW) {
        max_old_id = cbm_sql_column_int64(stmt, 0);
    }
    cbm_sql_finalize(stmt);

    int64_t *old_to_new = calloc((size_t)(max_old_id + SKIP_ONE), sizeof(int64_t));
    if (!old_to_new) {
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }

    /* Load all nodes */
    if (!cbm_sql_prepare(
            db,
            "SELECT id, label, name, qualified_name, file_path, start_line, end_line, properties "
            "FROM nodes WHERE project = ? ORDER BY id",
            &stmt)) {
        free(old_to_new);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    cbm_sql_bind_text(stmt, SKIP_ONE, project);

    while (cbm_sql_step(stmt) == CBM_SQL_ROW) {
        int64_t old_id = cbm_sql_column_int64(stmt, 0);
        const char *label = cbm_sql_column_text(stmt, SKIP_ONE);
        const char *name = cbm_sql_column_text(stmt, GB_COL_2);
        name = name && name[0] != '\0' ? name : NULL;
        const char *qn = cbm_sql_column_text(stmt, GB_COL_3);
        const char *fp = cbm_sql_column_text(stmt, GB_COL_4);
        int sl = cbm_sql_column_int(stmt, GB_COL_5);
        int el = cbm_sql_column_int(stmt, GB_COL_6);
        /* A node with no properties must stay NULL rather than becoming "":
         * consumers treat NULL as "{}" and reject "" as malformed JSON, so an
         * empty string here silently drops every property written later. */
        const char *props =
            cbm_sql_column_is_null(stmt, GB_COL_7) ? NULL : cbm_sql_column_text(stmt, GB_COL_7);

        int64_t new_id =
            cbm_node_id_value(cbm_gbuf_upsert_node(gb, label, name, qn, fp, sl, el, props));
        if (new_id > 0 && old_id <= max_old_id) {
            old_to_new[old_id] = new_id;
        }
    }
    cbm_sql_finalize(stmt);

    /* Load all edges, remap IDs */
    if (!cbm_sql_prepare(db,
                         "SELECT source_id, target_id, type, properties "
                         "FROM edges WHERE project = ?",
                         &stmt)) {
        free(old_to_new);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    cbm_sql_bind_text(stmt, SKIP_ONE, project);

    while (cbm_sql_step(stmt) == CBM_SQL_ROW) {
        int64_t old_src = cbm_sql_column_int64(stmt, 0);
        int64_t old_tgt = cbm_sql_column_int64(stmt, SKIP_ONE);
        const char *type = cbm_sql_column_text(stmt, GB_COL_2);
        /* Same reasoning as the node load: absent properties stay absent. */
        const char *props =
            cbm_sql_column_is_null(stmt, GB_COL_3) ? NULL : cbm_sql_column_text(stmt, GB_COL_3);

        int64_t new_src = (old_src <= max_old_id) ? old_to_new[old_src] : 0;
        int64_t new_tgt = (old_tgt <= max_old_id) ? old_to_new[old_tgt] : 0;
        if (new_src > 0 && new_tgt > 0) {
            cbm_gbuf_insert_edge(gb,
                                 (cbm_edge_endpoints_t){.source = cbm_node_id(new_src),
                                                        .target = cbm_node_id(new_tgt)},
                                 type, props);
        }
    }
    cbm_sql_finalize(stmt);

    free(old_to_new);
    cbm_store_close(store);
    return 0;
}

void cbm_gbuf_foreach_node(const cbm_gbuf_t *gb, cbm_gbuf_node_visitor_fn fn, void *userdata) {
    if (!gb || !fn) {
        return;
    }
    for (int i = 0; i < gb->nodes.count; i++) {
        const cbm_gbuf_node_t *n = gb->nodes.items[i];
        if (n->qualified_name && cbm_ht_get(gb->node_by_qn, n->qualified_name)) {
            fn(n, userdata);
        }
    }
}

void cbm_gbuf_foreach_edge(const cbm_gbuf_t *gb, cbm_gbuf_edge_visitor_fn fn, void *userdata) {
    if (!gb || !fn) {
        return;
    }
    for (int i = 0; i < gb->edges.count; i++) {
        fn(gb->edges.items[i], userdata);
    }
}

/* ── Edge properties: typed storage, JSON view, JSON shim ──────────── */

/* Append `s` to the growable buffer *out (NUL-terminated at *len), growing
 * via realloc as needed. Returns false (and leaves *out unmodified) on OOM. */
static bool gb_buf_append(char **out, size_t *len, size_t *cap, const char *s) {
    size_t n = strlen(s);
    if (*len + n + SKIP_ONE > *cap) {
        size_t new_cap = *cap > 0 ? *cap : GB_JSON_INIT_CAP;
        while (*len + n + SKIP_ONE > new_cap) {
            new_cap *= GB_JSON_GROW;
        }
        char *grown = gb_preflight_realloc(*out, new_cap);
        if (!grown) {
            return false;
        }
        *out = grown;
        *cap = new_cap;
    }
    memcpy(*out + *len, s, n);
    *len += n;
    (*out)[*len] = '\0';
    return true;
}

/* JSON-escape and append `s` (without surrounding quotes) to the growable
 * buffer. Returns false on OOM. */
/* Render one byte in its JSON-escaped form. Control characters that have no
 * short escape take the \uXXXX form, which keeps the output valid JSON for
 * arbitrary extracted text. */
static void gb_json_escape_byte(unsigned char ch, char esc[GB_JSON_ESC_BUF]) {
    switch (ch) {
    case '"':
        snprintf(esc, GB_JSON_ESC_BUF, "\\\"");
        return;
    case '\\':
        snprintf(esc, GB_JSON_ESC_BUF, "\\\\");
        return;
    case '\n':
        snprintf(esc, GB_JSON_ESC_BUF, "\\n");
        return;
    case '\r':
        snprintf(esc, GB_JSON_ESC_BUF, "\\r");
        return;
    case '\t':
        snprintf(esc, GB_JSON_ESC_BUF, "\\t");
        return;
    default:
        break;
    }
    if (ch < GB_ASCII_PRINTABLE) {
        snprintf(esc, GB_JSON_ESC_BUF, "\\u%04x", ch);
        return;
    }
    esc[0] = (char)ch;
    esc[SKIP_ONE] = '\0';
}

static bool gb_json_escape_append(char **out, size_t *len, size_t *cap, const char *s) {
    char esc[GB_JSON_ESC_BUF];
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        gb_json_escape_byte(*p, esc);
        if (!gb_buf_append(out, len, cap, esc)) {
            return false;
        }
    }
    return true;
}

/* True when `s` is itself a JSON array or object literal (leading '[' or
 * '{', ignoring whitespace) — the marker cbm_gbuf_insert_edge's JSON shim
 * uses to smuggle nested values through the STRING kind losslessly. */
static bool gb_is_raw_json_literal(const char *s) {
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    return *s == '[' || *s == '{';
}

/* Append one property's JSON value (no key) to the growable buffer. */
static bool gb_json_append_value(char **out, size_t *len, size_t *cap, const cbm_gbuf_prop_t *p) {
    switch (p->kind) {
    case CBM_EDGE_PROP_STRING: {
        const char *text = p->text ? p->text : "";
        if (gb_is_raw_json_literal(text)) {
            return gb_buf_append(out, len, cap, text);
        }
        return gb_buf_append(out, len, cap, "\"") && gb_json_escape_append(out, len, cap, text) &&
               gb_buf_append(out, len, cap, "\"");
    }
    case CBM_EDGE_PROP_NUMBER: {
        char nb[GB_NUM_BUF];
        snprintf(nb, sizeof(nb), "%.*f", p->decimals >= 0 ? p->decimals : 0, p->number);
        return gb_buf_append(out, len, cap, nb);
    }
    case CBM_EDGE_PROP_BOOL:
        return gb_buf_append(out, len, cap, p->flag ? "true" : "false");
    default:
        return gb_buf_append(out, len, cap, "null");
    }
}

/* Serialize a typed property array to a malloc'd flat JSON object string,
 * keys in insertion order. Returns NULL on OOM. */
static char *gb_serialize_props(const cbm_gbuf_prop_t *props, int prop_count) {
    char *out = NULL;
    size_t len = 0;
    size_t cap = 0;
    bool ok = gb_buf_append(&out, &len, &cap, "{");
    for (int i = 0; ok && i < prop_count; i++) {
        if (i > 0) {
            ok = gb_buf_append(&out, &len, &cap, ",");
        }
        ok = ok && gb_buf_append(&out, &len, &cap, "\"") &&
             gb_json_escape_append(&out, &len, &cap, props[i].key ? props[i].key : "") &&
             gb_buf_append(&out, &len, &cap, "\":") &&
             gb_json_append_value(&out, &len, &cap, &props[i]);
    }
    ok = ok && gb_buf_append(&out, &len, &cap, "}");
    if (!ok) {
        free(out);
        return NULL;
    }
    return out;
}

bool cbm_gbuf_edge_props_json(const cbm_gbuf_edge_t *edge, char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return false;
    }
    out[0] = '\0';
    if (!edge) {
        return false;
    }
    char *serialized = gb_serialize_props(edge->props, edge->prop_count);
    if (!serialized) {
        return false;
    }
    bool fits = strlen(serialized) < out_size;
    if (fits) {
        snprintf(out, out_size, "%s", serialized);
    }
    free(serialized);
    return fits;
}

char *cbm_gbuf_edge_props_json_alloc(const cbm_gbuf_edge_t *edge) {
    if (!edge) {
        return NULL;
    }
    return gb_serialize_props(edge->props, edge->prop_count);
}

const char *cbm_gbuf_edge_prop_string(const cbm_gbuf_edge_t *edge, const char *key) {
    if (!edge || !key) {
        return NULL;
    }
    const cbm_gbuf_prop_t *p = find_prop(edge->props, edge->prop_count, key);
    return (p && p->kind == CBM_EDGE_PROP_STRING) ? p->text : NULL;
}

bool cbm_gbuf_edge_prop_number(const cbm_gbuf_edge_t *edge, const char *key, double *out) {
    if (!edge || !key || !out) {
        return false;
    }
    const cbm_gbuf_prop_t *p = find_prop(edge->props, edge->prop_count, key);
    if (!p || p->kind != CBM_EDGE_PROP_NUMBER) {
        return false;
    }
    *out = p->number;
    return true;
}

bool cbm_gbuf_edge_prop_bool(const cbm_gbuf_edge_t *edge, const char *key, bool *out) {
    if (!edge || !key || !out) {
        return false;
    }
    const cbm_gbuf_prop_t *p = find_prop(edge->props, edge->prop_count, key);
    if (!p || p->kind != CBM_EDGE_PROP_BOOL) {
        return false;
    }
    *out = p->flag;
    return true;
}

/* Heap-copy a borrowed property array (key always dup'd; text dup'd for
 * STRING kind) into a freshly allocated, edge-owned array. count<=0 yields
 * NULL with *out_count set to 0, a valid "no properties" edge. On OOM
 * partway through, frees everything copied so far and returns NULL with
 * *out_count set to 0 rather than leaking or handing back a half-populated
 * array. */
static cbm_gbuf_prop_t *gb_copy_props(const cbm_gbuf_prop_t *props, int count, int *out_count) {
    *out_count = 0;
    if (count <= 0) {
        return NULL;
    }
    cbm_gbuf_prop_t *copy = calloc((size_t)count, sizeof(cbm_gbuf_prop_t));
    if (!copy) {
        return NULL;
    }
    for (int i = 0; i < count; i++) {
        copy[i].kind = props[i].kind;
        copy[i].number = props[i].number;
        copy[i].flag = props[i].flag;
        copy[i].decimals = props[i].decimals;
        copy[i].key = strdup(props[i].key ? props[i].key : "");
        copy[i].text = (props[i].kind == CBM_EDGE_PROP_STRING)
                           ? strdup(props[i].text ? props[i].text : "")
                           : NULL;
        bool text_ok = props[i].kind != CBM_EDGE_PROP_STRING || copy[i].text;
        if (!copy[i].key || !text_ok) {
            free_edge_props(copy, i + SKIP_ONE);
            return NULL;
        }
    }
    *out_count = count;
    return copy;
}

/* Decide whether incoming properties should replace an existing edge's
 * properties on a dedup collision. Rule: higher "confidence" wins; when
 * confidence is equal (or absent on both sides) a deterministic total order
 * over the serialized JSON form breaks the tie so the outcome never depends
 * on merge/arrival order; an empty/absent incoming property set never
 * displaces stored properties. */
static bool edge_props_should_replace(const cbm_gbuf_edge_t *existing, const cbm_gbuf_prop_t *props,
                                      int prop_count) {
    if (prop_count <= 0) {
        return false;
    }
    const cbm_gbuf_prop_t *incoming_conf_prop = find_prop(props, prop_count, "confidence");
    bool incoming_has = incoming_conf_prop && incoming_conf_prop->kind == CBM_EDGE_PROP_NUMBER;
    double incoming_conf = incoming_has ? incoming_conf_prop->number : 0.0;
    double existing_conf = 0.0;
    bool existing_has = cbm_gbuf_edge_prop_number(existing, "confidence", &existing_conf);

    if (incoming_has && existing_has && incoming_conf != existing_conf) {
        return incoming_conf > existing_conf;
    }
    if (incoming_has != existing_has) {
        return incoming_has;
    }

    char *incoming_json = gb_serialize_props(props, prop_count);
    char existing_json[CBM_SZ_2K];
    cbm_gbuf_edge_props_json(existing, existing_json, sizeof(existing_json));
    bool replace = incoming_json && strcmp(incoming_json, existing_json) > 0;
    free(incoming_json);
    return replace;
}

/* ── Edge operations ─────────────────────────────────────────────── */

cbm_edge_id_t cbm_gbuf_insert_edge_props(cbm_gbuf_t *gb, cbm_edge_endpoints_t endpoints,
                                         const char *type, const cbm_gbuf_prop_t *props,
                                         int prop_count) {
    if (!gb || !type) {
        return CBM_EDGE_ID_INVALID;
    }
    cbm_node_id_t source_id = endpoints.source;
    cbm_node_id_t target_id = endpoints.target;

    /* Check for dedup */
    char key[EDGE_KEY_BUF];
    make_edge_key(key, sizeof(key), source_id, target_id, type, props, prop_count);

    cbm_gbuf_edge_t *existing = cbm_ht_get(gb->edge_by_key, key);
    if (existing) {
        if (edge_props_should_replace(existing, props, prop_count)) {
            int new_count = 0;
            cbm_gbuf_prop_t *new_props = gb_copy_props(props, prop_count, &new_count);
            free_edge_props(existing->props, existing->prop_count);
            existing->props = new_props;
            existing->prop_count = new_count;
        }
        return existing->id;
    }

    /* Heap-allocate a new edge (pointer stays stable) */
    cbm_gbuf_edge_t *edge = calloc(CBM_ALLOC_ONE, sizeof(cbm_gbuf_edge_t));
    if (!edge) {
        return CBM_EDGE_ID_INVALID;
    }

    cbm_edge_id_t id = cbm_edge_id(alloc_next_id(gb));
    edge->id = id;
    edge->source_id = source_id;
    edge->target_id = target_id;
    edge->type = gb_intern(gb, type);
    edge->props = gb_copy_props(props, prop_count, &edge->prop_count);

    /* Store pointer in array */
    cbm_da_push(&gb->edges, edge);

    /* Dedup index */
    cbm_ht_set(gb->edge_by_key, strdup(key), edge);

    /* Secondary indexes */
    register_edge_in_indexes(gb, edge);

    return id;
}

/* True when `raw` (a yyjson raw-number token, YYJSON_READ_NUMBER_AS_RAW) is
 * plain fixed-point decimal notation ("-123.45", "0") with no exponent —
 * the only form gb_json_append_value can re-emit byte-for-byte via "%.*f".
 * On success, *decimals is the digit count after '.' (0 if none). */
static bool gb_raw_number_decimals(const char *raw, int *decimals) {
    if (strpbrk(raw, "eE")) {
        return false;
    }
    const char *dot = strchr(raw, '.');
    *decimals = dot ? (int)strlen(dot + SKIP_ONE) : 0;
    return true;
}

/* Classify one JSON object value into a borrowed cbm_gbuf_prop_t. key/text
 * are heap-allocated by this call (uniform ownership regardless of whether
 * the source was doc-borrowed text or a freshly rendered literal), so the
 * caller frees every prop the same way regardless of kind. */
static void gb_prop_from_json_val(cbm_gbuf_prop_t *out, const char *key, yyjson_val *val) {
    out->key = strdup(key ? key : "");
    out->text = NULL;
    out->decimals = 0;

    if (yyjson_is_str(val)) {
        out->kind = CBM_EDGE_PROP_STRING;
        const char *s = yyjson_get_str(val);
        out->text = strdup(s ? s : "");
        return;
    }
    if (yyjson_is_bool(val)) {
        out->kind = CBM_EDGE_PROP_BOOL;
        out->flag = yyjson_get_bool(val);
        return;
    }
    int decimals = 0;
    const char *raw = yyjson_is_raw(val) ? yyjson_get_raw(val) : NULL;
    if (raw && gb_raw_number_decimals(raw, &decimals)) {
        out->kind = CBM_EDGE_PROP_NUMBER;
        out->number = strtod(raw, NULL);
        out->decimals = decimals;
        return;
    }
    /* Array, object, null, or an exponent-notation number: none round-trip
     * through the fixed-decimal NUMBER slot or escaped STRING quoting
     * without loss (#requirement: lossless round-trip for nested values), so
     * keep the exact source text and re-emit it unescaped — gb_is_raw_json_literal
     * recognizes '['/'{' text on the way back out. A raw number here would
     * lose its distinguishing mark and get quoted as a string on re-emit,
     * which is an accepted trade-off: this codebase's emitters never produce
     * exponent notation for edge properties. */
    out->kind = CBM_EDGE_PROP_STRING;
    char *rendered = yyjson_val_write(val, YYJSON_WRITE_NOFLAG, NULL);
    out->text = rendered ? rendered : strdup("null");
}

/* Parse a flat JSON object ("{}"/NULL → zero props) into a heap-allocated,
 * caller-owned cbm_gbuf_prop_t array. Only handles what this codebase emits:
 * a flat object with string/number/bool values; nested arrays/objects are
 * preserved verbatim as STRING props rather than corrupted (see
 * gb_prop_from_json_val). Returns NULL (and *out_count=0) for "{}"/NULL/
 * malformed input/OOM — never partially parsed. */
static cbm_gbuf_prop_t *gb_parse_props_json(const char *json, int *out_count) {
    *out_count = 0;
    if (!json || strcmp(json, "{}") == 0) {
        return NULL;
    }
    yyjson_doc *doc = yyjson_read(json, strlen(json), YYJSON_READ_NUMBER_AS_RAW);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!root || !yyjson_is_obj(root) || yyjson_obj_size(root) == 0) {
        yyjson_doc_free(doc);
        return NULL;
    }

    int n = (int)yyjson_obj_size(root);
    cbm_gbuf_prop_t *props = calloc((size_t)n, sizeof(cbm_gbuf_prop_t));
    if (!props) {
        yyjson_doc_free(doc);
        return NULL;
    }

    yyjson_obj_iter iter;
    yyjson_obj_iter_init(root, &iter);
    yyjson_val *key_val;
    int idx = 0;
    while ((key_val = yyjson_obj_iter_next(&iter))) {
        gb_prop_from_json_val(&props[idx], yyjson_get_str(key_val),
                              yyjson_obj_iter_get_val(key_val));
        idx++;
    }
    yyjson_doc_free(doc);

    *out_count = idx;
    return props;
}

/* JSON shim: parses `properties_json` into typed props, delegates to
 * cbm_gbuf_insert_edge_props, then releases the temporary parse. Kept for
 * the call sites that build a JSON string directly. */
cbm_edge_id_t cbm_gbuf_insert_edge(cbm_gbuf_t *gb, cbm_edge_endpoints_t endpoints, const char *type,
                                   const char *properties_json) {
    int prop_count = 0;
    cbm_gbuf_prop_t *props = gb_parse_props_json(properties_json, &prop_count);

    cbm_edge_id_t id = cbm_gbuf_insert_edge_props(gb, endpoints, type, props, prop_count);

    free_edge_props(props, prop_count);
    return id;
}

int cbm_gbuf_find_edges_by_source_type(const cbm_gbuf_t *gb, cbm_node_id_t source_id,
                                       const char *type, const cbm_gbuf_edge_t ***out, int *count) {
    if (!gb || !out || !count) {
        return CBM_NOT_FOUND;
    }
    char key[EDGE_KEY_BUF];
    make_src_type_key(key, sizeof(key), source_id, type);
    edge_ptr_array_t *arr = cbm_ht_get(gb->edges_by_source_type, key);
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_find_edges_by_target_type(const cbm_gbuf_t *gb, cbm_node_id_t target_id,
                                       const char *type, const cbm_gbuf_edge_t ***out, int *count) {
    if (!gb || !out || !count) {
        return CBM_NOT_FOUND;
    }
    char key[EDGE_KEY_BUF];
    make_src_type_key(key, sizeof(key), target_id, type);
    edge_ptr_array_t *arr = cbm_ht_get(gb->edges_by_target_type, key);
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_find_edges_by_type(const cbm_gbuf_t *gb, const char *type,
                                const cbm_gbuf_edge_t ***out, int *count) {
    if (!gb || !out || !count) {
        return CBM_NOT_FOUND;
    }
    edge_ptr_array_t *arr = cbm_ht_get(gb->edges_by_type, type);
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_edge_count(const cbm_gbuf_t *gb) {
    return gb ? gb->edges.count : 0;
}

int cbm_gbuf_edge_count_by_type(const cbm_gbuf_t *gb, const char *type) {
    if (!gb || !type) {
        return 0;
    }
    edge_ptr_array_t *arr = cbm_ht_get(gb->edges_by_type, type);
    return arr ? arr->count : 0;
}

int cbm_gbuf_delete_edges_by_type(cbm_gbuf_t *gb, const char *type) {
    if (!gb || !type) {
        return CBM_NOT_FOUND;
    }

    /* Remove edges of the given type from array and dedup index */
    int write_idx = 0;
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        if (strcmp(e->type, type) == 0) {
            char key[EDGE_KEY_BUF];
            make_edge_key(key, sizeof(key), e->source_id, e->target_id, e->type, e->props,
                          e->prop_count);
            const char *ekey = cbm_ht_get_key(gb->edge_by_key, key);
            cbm_ht_delete(gb->edge_by_key, key);
            free_owned_const(ekey);
            free_edge_strings(e);
            free(e);
        } else {
            gb->edges.items[write_idx++] = gb->edges.items[i];
        }
    }
    gb->edges.count = write_idx;

    /* Rebuild edge secondary indexes */
    rebuild_edge_secondary_indexes(gb);

    return 0;
}

/* ── Merge ───────────────────────────────────────────────────────── */

/* Free remap hash table entries (key = heap string, value = heap int64_t*) */
static void free_remap_entry(const char *key, void *val, void *ud) {
    (void)ud;
    free_owned_const(key);
    free(val);
}

/* Handle QN collision: update dst node fields (src wins), record remap if IDs differ.
 * label/file_path are re-interned into dst's pool (sn's pointers belong to src). */
static void merge_update_existing(cbm_gbuf_t *dst, cbm_gbuf_node_t *existing,
                                  const cbm_gbuf_node_t *sn, CBMHashTable **remap) {
    /* Same guard as cbm_gbuf_upsert_node: a per-file "Module" def coming from a
     * worker-local gbuf must not touch the structural directory node ("Project"
     * root or "Folder") that shares its QN in a directory-based-module language
     * (Java/Go). pass_structure seeds Folder/Project nodes on the MAIN gbuf
     * before the parallel extract, so every worker's always-emitted Module def
     * for that package collides here; unconditional "src wins" relabelled the
     * directory node to Module and set its file_path to whichever worker merged
     * LAST — the nondeterministic USAGE-source misattribution of #787. Keep the
     * structural node intact; the ID remap below still redirects the worker's
     * edges onto the canonical node. */
    bool module_on_container =
        existing->label && sn->label && strcmp(sn->label, "Module") == 0 &&
        (strcmp(existing->label, "Project") == 0 || strcmp(existing->label, "Folder") == 0);
    if (!module_on_container) {
        /* Canonical collision winner (determinism) — mirrors
         * cbm_gbuf_upsert_node exactly. Distinct source entities can share a
         * QN (C: struct/function/macro with one name); unconditional "src
         * wins" made the survivor depend on worker merge order, flickering
         * the node set (and every downstream consumer) run to run. Winner =
         * smallest file_path, then LARGEST start_line, then largest
         * name/label — one total order, commutative, scheduling-free; a full
         * tie is the same entity → refresh from src. */
        int c = strcmp(sn->file_path, existing->file_path);
        if (c == 0) {
            c = existing->start_line - sn->start_line;
        }
        if (c == 0) {
            c = gb_name_compare(existing->name, sn->name);
        }
        if (c == 0) {
            c = strcmp(existing->label, sn->label);
        }
        bool sn_wins = c <= 0;
        if (sn_wins) {
            /* Keep the secondary indexes consistent when the surviving
             * label/name changes (the old code left the node listed under its
             * original label/name, so find_by_label/name mis-listed it). */
            const char *new_label = gb_intern(dst, sn->label);
            bool label_changed =
                !existing->label || !new_label || strcmp(existing->label, new_label) != 0;
            bool name_changed = gb_name_compare(existing->name, sn->name) != 0;
            if (label_changed) {
                remove_node_from_ptr_array(cbm_ht_get(dst->nodes_by_label, existing->label),
                                           existing->id);
            }
            if (name_changed) {
                if (existing->name) {
                    remove_node_from_ptr_array(cbm_ht_get(dst->nodes_by_name, existing->name),
                                               existing->id);
                }
            }
            existing->label = new_label;
            free(existing->name);
            existing->name = heap_strdup(sn->name);
            existing->file_path = gb_intern(dst, sn->file_path);
            existing->start_line = sn->start_line;
            existing->end_line = sn->end_line;
            if (sn->properties_json) {
                free(existing->properties_json);
                existing->properties_json =
                    heap_strdup(sn->properties_json ? sn->properties_json : "{}");
            }
            if (label_changed) {
                node_ptr_array_t *by_label =
                    get_or_create_node_array(dst->nodes_by_label, existing->label);
                cbm_da_push(by_label, (const cbm_gbuf_node_t *)existing);
            }
            if (name_changed) {
                if (existing->name) {
                    node_ptr_array_t *by_name =
                        get_or_create_node_array(dst->nodes_by_name, existing->name);
                    cbm_da_push(by_name, (const cbm_gbuf_node_t *)existing);
                }
            }
        }
    }

    if (!cbm_node_id_eq(sn->id, existing->id)) {
        if (!*remap) {
            *remap = cbm_ht_create(CBM_SZ_32);
        }
        char key[CBM_SZ_32];
        make_id_key(key, sizeof(key), sn->id);
        int64_t *val = malloc(sizeof(int64_t));
        *val = cbm_node_id_value(existing->id);
        cbm_ht_set(*remap, strdup(key), val);
    }
}

/* Copy a non-colliding src node into dst with its original ID. */
static void merge_copy_new_node(cbm_gbuf_t *dst, const cbm_gbuf_node_t *sn) {
    cbm_gbuf_node_t *node = calloc(CBM_ALLOC_ONE, sizeof(cbm_gbuf_node_t));
    if (!node) {
        return;
    }

    node->id = sn->id;
    node->label = gb_intern(dst, sn->label);
    node->name = heap_strdup(sn->name);
    node->qualified_name = heap_strdup(sn->qualified_name);
    node->file_path = gb_intern(dst, sn->file_path);
    node->start_line = sn->start_line;
    node->end_line = sn->end_line;
    node->properties_json = heap_strdup(sn->properties_json ? sn->properties_json : "{}");

    cbm_da_push(&dst->nodes, node);
    register_node_in_indexes(dst, node);

    int64_t node_id_v = cbm_node_id_value(node->id);
    if (node_id_v >= dst->next_id) {
        dst->next_id = node_id_v + SKIP_ONE;
    }
}

/* Remap edge IDs using the collision remap table and insert into dst. */
static void merge_remap_edges(cbm_gbuf_t *dst, cbm_gbuf_t *src, CBMHashTable *remap) {
    for (int i = 0; i < src->edges.count; i++) {
        cbm_gbuf_edge_t *se = src->edges.items[i];

        int64_t new_src = cbm_node_id_value(se->source_id);
        int64_t new_tgt = cbm_node_id_value(se->target_id);

        if (remap) {
            char key[CBM_SZ_32];
            make_id_key(key, sizeof(key), se->source_id);
            int64_t *remapped = cbm_ht_get(remap, key);
            if (remapped) {
                new_src = *remapped;
            }

            make_id_key(key, sizeof(key), se->target_id);
            remapped = cbm_ht_get(remap, key);
            if (remapped) {
                new_tgt = *remapped;
            }
        }

        cbm_gbuf_insert_edge_props(
            dst,
            (cbm_edge_endpoints_t){.source = cbm_node_id(new_src), .target = cbm_node_id(new_tgt)},
            se->type, se->props, se->prop_count);
    }
}

int cbm_gbuf_merge(cbm_gbuf_t *dst, cbm_gbuf_t *src) {
    if (!dst || !src) {
        return CBM_NOT_FOUND;
    }
    if (src->nodes.count == 0 && src->edges.count == 0) {
        return 0;
    }

    /* ID remap for QN-colliding nodes: "src_id" → (int64_t*) dst_id.
     * Only populated when a src node's QN already exists in dst. */
    CBMHashTable *remap = NULL;

    for (int i = 0; i < src->nodes.count; i++) {
        cbm_gbuf_node_t *sn = src->nodes.items[i];
        if (!sn->qualified_name) {
            continue;
        }

        /* Skip nodes deleted from QN index */
        if (!cbm_ht_get(src->node_by_qn, sn->qualified_name)) {
            continue;
        }

        cbm_gbuf_node_t *existing = cbm_ht_get(dst->node_by_qn, sn->qualified_name);
        if (existing) {
            merge_update_existing(dst, existing, sn, &remap);
        } else {
            merge_copy_new_node(dst, sn);
        }
    }

    /* Merge edges with optional ID remapping */
    merge_remap_edges(dst, src, remap);

    if (remap) {
        cbm_ht_foreach(remap, free_remap_entry, NULL);
        cbm_ht_free(remap);
    }

    return 0;
}

/* ── Dump / Flush ────────────────────────────────────────────────── */

/* Remap a temp edge ID to its final sequential ID, or 0 if out of range. */
static int64_t remap_id(const int64_t *temp_to_final, int64_t max_temp_id, int64_t temp_id) {
    return (temp_id < max_temp_id) ? temp_to_final[temp_id] : 0;
}

/* Build dump-ready node array with sequential IDs. Populates temp_to_final mapping. */
static int cmp_dump_vectors_by_id(const void *a, const void *b) {
    int64_t da = ((const CBMDumpVector *)a)->node_id;
    int64_t db = ((const CBMDumpVector *)b)->node_id;
    return (da > db) - (da < db);
}

static bool build_dump_nodes(cbm_gbuf_t *gb, int live_count, int64_t *temp_to_final,
                             int64_t max_temp_id, CBMDumpNode **out_nodes, int *out_count) {
    *out_nodes = NULL;
    *out_count = 0;
    size_t cap = (size_t)(live_count > 0 ? live_count : SKIP_ONE);
    CBMDumpNode *dump_nodes = gb_preflight_malloc(cap * sizeof(*dump_nodes));
    if (!dump_nodes) {
        free(dump_nodes);
        return false;
    }
    int idx = 0;

    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];
        if (!n->qualified_name || !cbm_ht_get(gb->node_by_qn, n->qualified_name)) {
            continue;
        }

        int64_t final_id = idx + SKIP_ONE; /* 1-based sequential */
        int64_t n_id_v = cbm_node_id_value(n->id);
        if (n_id_v < max_temp_id) {
            temp_to_final[n_id_v] = final_id;
        }

        dump_nodes[idx] = (CBMDumpNode){
            .id = final_id,
            .project = gb->project,
            .label = n->label,
            .name = n->name,
            .qualified_name = n->qualified_name,
            .file_path = n->file_path,
            .start_line = n->start_line,
            .end_line = n->end_line,
            .properties = n->properties_json,
        };
        idx++;
    }

    *out_nodes = dump_nodes;
    *out_count = idx;
    return true;
}

/* Build dump-ready edge array with remapped IDs. Returns url_paths,
 * local_names, and the serialized properties JSON (heap string arrays owned
 * by the caller) via out params — each parallel to dump_edges[0..*out_count). */
static void free_dump_resources(char **url_paths, char **local_names, char **props_json,
                                int edge_count, CBMDumpEdge *dump_edges, CBMDumpNode *dump_nodes,
                                int64_t *temp_to_final);

static bool build_dump_edges(cbm_gbuf_t *gb, const int64_t *temp_to_final, int64_t max_temp_id,
                             CBMDumpEdge **out_edges, int *out_count, char ***out_url_paths,
                             char ***out_local_names, char ***out_props_json) {
    *out_edges = NULL;
    *out_count = 0;
    *out_url_paths = NULL;
    *out_local_names = NULL;
    *out_props_json = NULL;
    /* Count valid edges (both endpoints resolved) */
    int valid_edges = 0;
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        if (remap_id(temp_to_final, max_temp_id, cbm_node_id_value(e->source_id)) > 0 &&
            remap_id(temp_to_final, max_temp_id, cbm_node_id_value(e->target_id)) > 0) {
            valid_edges++;
        }
    }

    size_t alloc_count = (size_t)(valid_edges > 0 ? valid_edges : SKIP_ONE);
    CBMDumpEdge *dump_edges = gb_preflight_malloc(alloc_count * sizeof(*dump_edges));
    char **url_paths = gb_preflight_calloc(alloc_count, sizeof(*url_paths));
    char **local_names = gb_preflight_calloc(alloc_count, sizeof(*local_names));
    char **props_json = gb_preflight_calloc(alloc_count, sizeof(*props_json));
    if (!dump_edges || !url_paths || !local_names || !props_json) {
        free(dump_edges);
        free(url_paths);
        free(local_names);
        free(props_json);
        return false;
    }
    int idx = 0;

    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        int64_t src = remap_id(temp_to_final, max_temp_id, cbm_node_id_value(e->source_id));
        int64_t tgt = remap_id(temp_to_final, max_temp_id, cbm_node_id_value(e->target_id));
        if (src == 0 || tgt == 0) {
            continue;
        }

        const char *url_path_value = cbm_gbuf_edge_prop_string(e, "url_path");
        char *url_path =
            url_path_value ? gb_preflight_malloc(strlen(url_path_value) + SKIP_ONE) : NULL;
        if (url_path) {
            memcpy(url_path, url_path_value, strlen(url_path_value) + SKIP_ONE);
        }
        if (url_path_value && !url_path) {
            free_dump_resources(url_paths, local_names, props_json, idx, dump_edges, NULL, NULL);
            return false;
        }
        url_paths[idx] = url_path;

        /* IMPORTS only — mirrors the local_name_gen CASE in the edges DDL. */
        const char *local_name_value = (e->type && strcmp(e->type, "IMPORTS") == 0)
                                           ? cbm_gbuf_edge_prop_string(e, "local_name")
                                           : NULL;
        char *local_name =
            local_name_value ? gb_preflight_malloc(strlen(local_name_value) + SKIP_ONE) : NULL;
        if (local_name) {
            memcpy(local_name, local_name_value, strlen(local_name_value) + SKIP_ONE);
        }
        if (local_name_value && !local_name) {
            free_dump_resources(url_paths, local_names, props_json, idx + SKIP_ONE, dump_edges,
                                NULL, NULL);
            return false;
        }
        local_names[idx] = local_name;

        char *serialized = gb_serialize_props(e->props, e->prop_count);
        if (!serialized) {
            free_dump_resources(url_paths, local_names, props_json, idx + SKIP_ONE, dump_edges,
                                NULL, NULL);
            return false;
        }
        props_json[idx] = serialized;

        dump_edges[idx] = (CBMDumpEdge){
            .id = idx + SKIP_ONE,
            .project = gb->project,
            .source_id = src,
            .target_id = tgt,
            .type = e->type,
            .properties = props_json[idx],
            .url_path = url_path ? url_path : "",
            .local_name = local_name ? local_name : "",
        };
        idx++;
    }

    *out_edges = dump_edges;
    *out_count = idx;
    *out_url_paths = url_paths;
    *out_local_names = local_names;
    *out_props_json = props_json;
    return true;
}

/* Remap vector node IDs through temp_to_final, sort by ID, deduplicate. */
static void remap_sort_dedup_vectors(CBMDumpVector *vectors, int *count,
                                     const int64_t *temp_to_final, int64_t max_temp_id) {
    int remapped = 0;
    int dropped = 0;
    for (int i = 0; i < *count; i++) {
        int64_t old_id = vectors[i].node_id;
        int64_t new_id = (old_id > 0 && old_id < max_temp_id) ? temp_to_final[old_id] : 0;
        if (new_id > 0) {
            vectors[remapped] = vectors[i];
            vectors[remapped].node_id = new_id;
            remapped++;
        } else {
            dropped++;
        }
    }
    if (dropped > 0) {
        char r_buf[CBM_SZ_16];
        char d_buf[CBM_SZ_16];
        snprintf(r_buf, sizeof(r_buf), "%d", remapped);
        snprintf(d_buf, sizeof(d_buf), "%d", dropped);
        cbm_log_info("dump.vectors.remap", "remapped", r_buf, "dropped", d_buf);
    }
    *count = remapped;

    if (*count >= GB_MIN_FOR_DEDUP) {
        qsort(vectors, (size_t)*count, sizeof(*vectors), cmp_dump_vectors_by_id);
        int deduped = 0;
        for (int i = 0; i < *count; i++) {
            if (i + GB_DEDUP_LOOKAHEAD < *count &&
                vectors[i].node_id == vectors[i + GB_DEDUP_LOOKAHEAD].node_id) {
                continue;
            }
            vectors[deduped++] = vectors[i];
        }
        *count = deduped;
    }
}

static bool build_dump_vectors(const cbm_gbuf_t *gb, const int64_t *temp_to_final,
                               int64_t max_temp_id, CBMDumpVector **out_vectors, int *out_count) {
    *out_vectors = NULL;
    *out_count = 0;
    if (gb->dump_vector_count == 0) {
        return true;
    }

    CBMDumpVector *vectors = gb_preflight_malloc((size_t)gb->dump_vector_count * sizeof(*vectors));
    if (!vectors) {
        return false;
    }
    memcpy(vectors, gb->dump_vectors, (size_t)gb->dump_vector_count * sizeof(*vectors));
    int count = gb->dump_vector_count;
    remap_sort_dedup_vectors(vectors, &count, temp_to_final, max_temp_id);
    *out_vectors = vectors;
    *out_count = count;
    return true;
}

static void log_dump_summary(int node_count, int edge_count) {
    char b1[CBM_SZ_16];
    char b2[CBM_SZ_16];
    snprintf(b1, sizeof(b1), "%d", node_count);
    snprintf(b2, sizeof(b2), "%d", edge_count);
    cbm_log_info("gbuf.dump", "nodes", b1, "edges", b2);
}

static void free_dump_resources(char **url_paths, char **local_names, char **props_json,
                                int edge_count, CBMDumpEdge *dump_edges, CBMDumpNode *dump_nodes,
                                int64_t *temp_to_final) {
    for (int i = 0; i < edge_count; i++) {
        if (url_paths) {
            free(url_paths[i]);
        }
        if (local_names) {
            free(local_names[i]);
        }
        if (props_json) {
            free(props_json[i]);
        }
    }
    free(url_paths);
    free(local_names);
    free(props_json);
    free(dump_edges);
    free(dump_nodes);
    free(temp_to_final);
}

static int count_live_nodes(cbm_gbuf_t *gb) {
    int count = 0;
    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];
        if (n->qualified_name && cbm_ht_get(gb->node_by_qn, n->qualified_name)) {
            count++;
        }
    }
    return count;
}

static void generate_iso_timestamp(char *buf, size_t buf_size) {
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_val = cbm_gmtime_r(&now, &tm_buf);
    if (strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%SZ", tm_val) == 0) {
        snprintf(buf, buf_size, "1970-01-01T00:00:00Z");
    }
}

int cbm_gbuf_dump_to_sqlite(cbm_gbuf_t *gb, const char *path) {
    if (!gb || !path) {
        return CBM_NOT_FOUND;
    }

    CBM_PROF_START(t_count);
    int live_count = count_live_nodes(gb);
    CBM_PROF_END_N("dump", "1_count_live_nodes", t_count, live_count);

    CBM_PROF_START(t_build_nodes);
    int64_t max_temp_id = gb->next_id;
    int64_t *temp_to_final = gb_preflight_calloc((size_t)max_temp_id, sizeof(*temp_to_final));
    if (!temp_to_final) {
        return CBM_NOT_FOUND;
    }

    int node_idx = 0;
    CBMDumpNode *dump_nodes = NULL;
    if (!build_dump_nodes(gb, live_count, temp_to_final, max_temp_id, &dump_nodes, &node_idx)) {
        free(temp_to_final);
        return CBM_NOT_FOUND;
    }
    CBM_PROF_END_N("dump", "2_build_dump_nodes", t_build_nodes, node_idx);

    int edge_idx = 0;
    char **url_paths = NULL;
    char **local_names = NULL;
    char **props_json = NULL;
    CBMDumpEdge *dump_edges = NULL;
    CBM_PROF_START(t_build_edges);
    if (!build_dump_edges(gb, temp_to_final, max_temp_id, &dump_edges, &edge_idx, &url_paths,
                          &local_names, &props_json)) {
        free_dump_resources(NULL, NULL, NULL, 0, NULL, dump_nodes, temp_to_final);
        return CBM_NOT_FOUND;
    }
    CBM_PROF_END_N("dump", "3_build_dump_edges", t_build_edges, edge_idx);

    CBMDumpVector *dump_vectors = NULL;
    int dump_vector_count = 0;
    CBM_PROF_START(t_vec_remap);
    if (!build_dump_vectors(gb, temp_to_final, max_temp_id, &dump_vectors, &dump_vector_count)) {
        CBM_PROF_END_N("dump", "5_vector_remap_sort", t_vec_remap, 0);
        free_dump_resources(url_paths, local_names, props_json, edge_idx, dump_edges, dump_nodes,
                            temp_to_final);
        return CBM_NOT_FOUND;
    }
    CBM_PROF_END_N("dump", "5_vector_remap_sort", t_vec_remap, dump_vector_count);

    char indexed_at[CBM_SZ_64];
    generate_iso_timestamp(indexed_at, sizeof(indexed_at));

    cbm_db_writer_t *w = cbm_writer_open(path);
    if (!w) {
        free(dump_vectors);
        free_dump_resources(url_paths, local_names, props_json, edge_idx, dump_edges, dump_nodes,
                            temp_to_final);
        return CBM_NOT_FOUND;
    }

    CBM_PROF_START(t_append);
    enum { DUMP_PARTITION_NODES = 1 << 16 };
    int rc = 0;
    for (int off = 0; off < node_idx; off += DUMP_PARTITION_NODES) {
        int chunk = node_idx - off;
        if (chunk > DUMP_PARTITION_NODES) {
            chunk = DUMP_PARTITION_NODES;
        }
        rc = cbm_writer_append_nodes(w, &dump_nodes[off], chunk);
        if (rc != 0) {
            break;
        }
    }
    CBM_PROF_END_N("dump", "2b_stream_append_nodes", t_append, node_idx);

    /* Finalize: nodes-table interior + edges/vectors/metadata/indexes/sqlite_master.
     * Frees w and closes the file; handles a prior append error cleanly. */
    CBM_PROF_START(t_finalize);
    int frc = cbm_writer_finalize(w, gb->project, gb->root_path, indexed_at, dump_nodes, node_idx,
                                  dump_edges, edge_idx, dump_vectors, dump_vector_count,
                                  gb->dump_token_vecs, gb->dump_token_vec_count);
    CBM_PROF_END_N("dump", "6_write_db_finalize", t_finalize, node_idx + edge_idx);
    if (rc == 0) {
        rc = frc;
    }

    if (rc == 0) {
        CBM_PROF_START(t_release_idx);
        release_gbuf_indexes(gb);
        CBM_PROF_END("dump", "4_release_gbuf_indexes", t_release_idx);
        free(gb->dump_vectors);
        gb->dump_vectors = dump_vectors;
        gb->dump_vector_count = dump_vector_count;
        gb->dump_vector_cap = dump_vector_count;
        dump_vectors = NULL;
        log_dump_summary(node_idx, edge_idx);
    }
    free(dump_vectors);
    free_dump_resources(url_paths, local_names, props_json, edge_idx, dump_edges, dump_nodes,
                        temp_to_final);
    return rc;
}

static bool preflight_serialized_edge_properties(const cbm_gbuf_t *gb, char ***out_properties) {
    *out_properties = NULL;
    if (gb->edges.count == 0) {
        return true;
    }
    char **properties = gb_preflight_calloc((size_t)gb->edges.count, sizeof(*properties));
    if (!properties) {
        return false;
    }
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *edge = gb->edges.items[i];
        properties[i] = gb_serialize_props(edge->props, edge->prop_count);
        if (!properties[i]) {
            for (int j = 0; j < i; j++) {
                free(properties[j]);
            }
            free(properties);
            return false;
        }
    }
    *out_properties = properties;
    return true;
}

static void free_serialized_edge_properties(char **properties, int count) {
    if (!properties) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(properties[i]);
    }
    free(properties);
}

static int write_gbuf_to_store(cbm_gbuf_t *gb, cbm_store_t *store, int64_t *temp_to_real,
                               int64_t max_temp_id, char *const *edge_properties) {
    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];
        if (!n->qualified_name || !cbm_ht_get(gb->node_by_qn, n->qualified_name)) {
            continue;
        }
        cbm_node_t sn = {
            .project = gb->project,
            .label = n->label,
            .name = n->name,
            .qualified_name = n->qualified_name,
            .file_path = n->file_path,
            .start_line = n->start_line,
            .end_line = n->end_line,
            .properties_json = n->properties_json,
        };
        int64_t real_id = cbm_store_upsert_node(store, &sn);
        int64_t n_id_v = cbm_node_id_value(n->id);
        if (real_id <= 0 || n_id_v <= 0 || n_id_v >= max_temp_id) {
            return CBM_NOT_FOUND;
        }
        temp_to_real[n_id_v] = real_id;
    }

    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        int64_t e_src_v = cbm_node_id_value(e->source_id);
        int64_t e_tgt_v = cbm_node_id_value(e->target_id);
        int64_t real_src = (e_src_v > 0 && e_src_v < max_temp_id) ? temp_to_real[e_src_v] : 0;
        int64_t real_tgt = (e_tgt_v > 0 && e_tgt_v < max_temp_id) ? temp_to_real[e_tgt_v] : 0;
        if (real_src == 0 || real_tgt == 0) {
            continue;
        }
        cbm_edge_t se = {
            .project = gb->project,
            .source_id = real_src,
            .target_id = real_tgt,
            .type = e->type,
            .properties_json = edge_properties[i],
        };
        if (cbm_store_insert_edge(store, &se) <= 0) {
            return CBM_NOT_FOUND;
        }
    }
    return CBM_STORE_OK;
}

int cbm_gbuf_flush_to_store(cbm_gbuf_t *gb, cbm_store_t *store) {
    if (!gb || !store) {
        return CBM_NOT_FOUND;
    }
    int64_t max_temp_id = gb->next_id;
    int64_t *temp_to_real = gb_preflight_calloc((size_t)max_temp_id, sizeof(*temp_to_real));
    char **edge_properties = NULL;
    if (!temp_to_real || !preflight_serialized_edge_properties(gb, &edge_properties)) {
        free(temp_to_real);
        free_serialized_edge_properties(edge_properties, gb->edges.count);
        return CBM_NOT_FOUND;
    }

    int rc = cbm_store_begin_bulk(store);
    bool bulk_started = rc == CBM_STORE_OK;
    bool transaction_started = false;
    if (bulk_started) {
        rc = cbm_store_begin(store);
        transaction_started = rc == CBM_STORE_OK;
    }
    if (rc == CBM_STORE_OK) {
        rc = cbm_store_upsert_project(store, gb->project, gb->root_path);
    }
    if (rc == CBM_STORE_OK) {
        rc = cbm_store_drop_indexes(store);
    }
    if (rc == CBM_STORE_OK) {
        rc = cbm_store_delete_edges_by_project(store, gb->project);
    }
    if (rc == CBM_STORE_OK) {
        rc = cbm_store_delete_nodes_by_project(store, gb->project);
    }
    if (rc == CBM_STORE_OK) {
        rc = write_gbuf_to_store(gb, store, temp_to_real, max_temp_id, edge_properties);
    }
    if (rc == CBM_STORE_OK) {
        rc = cbm_store_create_indexes(store);
    }
    if (rc == CBM_STORE_OK) {
        rc = cbm_store_commit(store);
    }
    if (rc != CBM_STORE_OK && transaction_started) {
        cbm_store_rollback(store);
    }
    if (bulk_started && cbm_store_end_bulk(store) != CBM_STORE_OK) {
        rc = CBM_NOT_FOUND;
    }

    free(temp_to_real);
    free_serialized_edge_properties(edge_properties, gb->edges.count);
    return rc == CBM_STORE_OK ? 0 : CBM_NOT_FOUND;
}

int cbm_gbuf_merge_into_store(cbm_gbuf_t *gb, cbm_store_t *store) {
    if (!gb || !store) {
        return CBM_NOT_FOUND;
    }
    int64_t max_temp_id = gb->next_id;
    int64_t *temp_to_real = gb_preflight_calloc((size_t)max_temp_id, sizeof(*temp_to_real));
    char **edge_properties = NULL;
    if (!temp_to_real || !preflight_serialized_edge_properties(gb, &edge_properties)) {
        free(temp_to_real);
        free_serialized_edge_properties(edge_properties, gb->edges.count);
        return CBM_NOT_FOUND;
    }

    int rc = cbm_store_begin(store);
    if (rc == CBM_STORE_OK) {
        rc = write_gbuf_to_store(gb, store, temp_to_real, max_temp_id, edge_properties);
    }
    if (rc == CBM_STORE_OK) {
        rc = cbm_store_commit(store);
    }
    if (rc != CBM_STORE_OK) {
        cbm_store_rollback(store);
    }

    free(temp_to_real);
    free_serialized_edge_properties(edge_properties, gb->edges.count);
    return rc == CBM_STORE_OK ? 0 : CBM_NOT_FOUND;
}
