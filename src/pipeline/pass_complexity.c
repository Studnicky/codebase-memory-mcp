/*
 * pass_complexity.c — Interprocedural complexity propagation (Tier B).
 *
 * Tier A (in the extraction walk) stamps each Function/Method node with local
 * structural metrics: complexity (cyclomatic), cognitive, loop_count, loop_depth.
 * This pass propagates loop_depth along CALLS edges to estimate a worst-case
 * *transitive* nested-loop degree: a function with a depth-1 loop that calls an
 * O(n) helper is effectively O(n^2). The estimate assumes calls may occur inside
 * loops (an upper bound) — it is a queryable bottleneck *candidate* signal, not a
 * proof (true big-O is undecidable; cf. SPEED / Loopus). Cycles in the call graph
 * are broken and flagged via a `recursive` property.
 *
 * Writes two extra node properties: transitive_loop_depth, recursive.
 */
#include "foundation/constants.h"
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/log.h"
#include "foundation/compat.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

enum {
    CBM_TLD_MAX_DEPTH = 256,
    CBM_TLD_FIRST_NODE_ID = 1,
    CBM_TLD_RING_CAPACITY = 2,
    CBM_TLD_RING_STEP = CBM_TLD_FIRST_NODE_ID,
    CBM_TLD_DEPTH_INCREMENT = CBM_TLD_FIRST_NODE_ID,
    CBM_TLD_RING_MASK = CBM_TLD_RING_CAPACITY - CBM_TLD_FIRST_NODE_ID,
    CBM_TLD_STRING_TERMINATOR_SIZE = sizeof(""),
    CBM_TLD_JSON_CLOSING_BRACE_LENGTH = sizeof("}") - CBM_TLD_STRING_TERMINATOR_SIZE,
    CBM_TLD_EMPTY_JSON_OBJECT_LENGTH = sizeof("{}") - CBM_TLD_STRING_TERMINATOR_SIZE,
    CBM_TLD_STATE_UNVISITED = 0,
    CBM_TLD_STATE_IN_PROGRESS = CBM_TLD_FIRST_NODE_ID,
    CBM_TLD_STATE_DONE = CBM_TLD_RING_CAPACITY,
}; /* recursion-depth cap (cycle/stack guard) */

/* Int → string for structured logging (thread-safe ring buffer). */
static const char *itoa_cx(int val) {
    static CBM_TLS char bufs[CBM_TLD_RING_CAPACITY][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + CBM_TLD_RING_STEP) & CBM_TLD_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* Parse an integer "key":N from a flat JSON object. Returns def if absent. */
static int json_get_int(const char *json, const char *key, int dflt) {
    if (!json) {
        return dflt;
    }
    char pat[CBM_SZ_64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) {
        return dflt;
    }
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return (int)strtol(p, NULL, CBM_DECIMAL_BASE);
}

/* Parse a boolean "key":true/false from a flat JSON object. */
static bool json_get_bool(const char *json, const char *key) {
    if (!json) {
        return false;
    }
    char pat[CBM_SZ_64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) {
        return false;
    }
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return *p == 't';
}

/* Append transitive_loop_depth + recursive to a node's properties JSON object.
 * The buffer owns node storage, so the rewritten object goes back through
 * cbm_gbuf_set_node_properties_json rather than being assigned into the node. */
static void append_complexity_props(cbm_gbuf_t *gb, const cbm_gbuf_node_t *node, int tld,
                                    bool recursive) {
    const char *old = node->properties_json;
    size_t olen = strlen(old);
    if (olen < CBM_TLD_EMPTY_JSON_OBJECT_LENGTH ||
        old[olen - CBM_TLD_JSON_CLOSING_BRACE_LENGTH] != '}') {
        return; /* not a JSON object — leave untouched */
    }
    bool empty = (olen == CBM_TLD_EMPTY_JSON_OBJECT_LENGTH); /* "{}" */
    char *neu = malloc(olen + CBM_SZ_64);
    if (!neu) {
        return;
    }
    memcpy(neu, old, olen - CBM_TLD_JSON_CLOSING_BRACE_LENGTH); /* copy without trailing '}' */
    int w = snprintf(neu + (olen - CBM_TLD_JSON_CLOSING_BRACE_LENGTH), CBM_SZ_64,
                     "%s\"transitive_loop_depth\":%d,\"recursive\":%s}", empty ? "" : ",", tld,
                     recursive ? "true" : "false");
    if (w < 0) {
        free(neu);
        return;
    }
    cbm_gbuf_set_node_properties_json(gb, node->id, neu);
    free(neu);
}

typedef struct {
    int64_t node_id;
    const cbm_gbuf_edge_t **edges;
    int depth;
    int edge_count;
    int next_edge;
    int best_child_depth;
} tld_work_item_t;

typedef struct {
    const cbm_gbuf_t *graph;
    const int *loop_depth;
    int *tld;
    char *state;
    bool *recursive;
    int64_t max_id;
    tld_work_item_t *worklist;
    int work_count;
} tld_worklist_context_t;

static void tld_work_item_start(tld_work_item_t *item, const cbm_gbuf_t *gb, int64_t node_id,
                                int depth) {
    *item = (tld_work_item_t){
        .node_id = node_id,
        .depth = depth,
    };
    cbm_gbuf_find_edges_by_source_type(gb, cbm_node_id(node_id), "CALLS", &item->edges,
                                       &item->edge_count);
}

static void tld_update_best(tld_work_item_t *item, int child_depth) {
    if (child_depth > item->best_child_depth) {
        item->best_child_depth = child_depth;
    }
}

static bool tld_active_item_complete(tld_worklist_context_t *context) {
    tld_work_item_t *item = &context->worklist[context->work_count - CBM_TLD_FIRST_NODE_ID];
    if (item->next_edge < item->edge_count) {
        return false;
    }
    int completed_depth = context->loop_depth[item->node_id] + item->best_child_depth;
    context->tld[item->node_id] = completed_depth;
    context->state[item->node_id] = CBM_TLD_STATE_DONE;
    context->work_count--;
    if (context->work_count > 0) {
        tld_work_item_t *parent = &context->worklist[context->work_count - CBM_TLD_FIRST_NODE_ID];
        tld_update_best(parent, completed_depth);
    }
    return true;
}

static bool tld_child_is_valid(const tld_worklist_context_t *context, int64_t child_id) {
    return child_id >= CBM_TLD_FIRST_NODE_ID && child_id <= context->max_id;
}

static void tld_process_active_child(tld_worklist_context_t *context) {
    tld_work_item_t *item = &context->worklist[context->work_count - CBM_TLD_FIRST_NODE_ID];
    int64_t child_id = cbm_node_id_value(item->edges[item->next_edge++]->target_id);
    if (child_id == item->node_id) {
        context->recursive[item->node_id] = true;
        return;
    }
    if (!tld_child_is_valid(context, child_id)) {
        return;
    }
    if (context->state[child_id] == CBM_TLD_STATE_DONE) {
        tld_update_best(item, context->tld[child_id]);
        return;
    }
    if (context->state[child_id] == CBM_TLD_STATE_IN_PROGRESS) {
        context->recursive[child_id] = true;
        return;
    }
    if (item->depth >= CBM_TLD_MAX_DEPTH) {
        tld_update_best(item, context->loop_depth[child_id]);
        return;
    }
    context->state[child_id] = CBM_TLD_STATE_IN_PROGRESS;
    tld_work_item_start(&context->worklist[context->work_count], context->graph, child_id,
                        item->depth + CBM_TLD_DEPTH_INCREMENT);
    context->work_count++;
}

/* Memoized DFS implemented with an explicit stack: tld(id) = loop_depth(id)
 * plus the maximum CALLS-callee depth. state tracks unvisited, in-progress,
 * and completed nodes; a back edge marks its target recursive. */
static int tld_worklist(const cbm_gbuf_t *gb, int64_t root_id, const int *loop_depth, int *tld,
                        char *state, bool *recursive, int64_t maxid) {
    if (root_id < CBM_TLD_FIRST_NODE_ID || root_id > maxid) {
        return 0;
    }
    if (state[root_id] == CBM_TLD_STATE_DONE) {
        return tld[root_id];
    }
    if (state[root_id] == CBM_TLD_STATE_IN_PROGRESS) {
        recursive[root_id] = true;
        return 0;
    }

    tld_work_item_t worklist[CBM_TLD_MAX_DEPTH + CBM_TLD_FIRST_NODE_ID];
    tld_worklist_context_t context = {
        .graph = gb,
        .loop_depth = loop_depth,
        .tld = tld,
        .state = state,
        .recursive = recursive,
        .max_id = maxid,
        .worklist = worklist,
        .work_count = CBM_TLD_FIRST_NODE_ID,
    };
    state[root_id] = CBM_TLD_STATE_IN_PROGRESS;
    tld_work_item_start(&context.worklist[0], gb, root_id, 0);
    while (context.work_count > 0) {
        if (!tld_active_item_complete(&context)) {
            tld_process_active_child(&context);
        }
    }
    return tld[root_id];
}

/* Seed each Function/Method node's loop_depth and self_recursive flag, and
 * remember the node pointer for write-back. The self_recursive seed (set at
 * extraction) feeds the final recursive flag; tld_dfs additionally ORs in
 * mutual recursion discovered as a call-graph cycle. */
static void seed_loop_depths(const cbm_gbuf_t *gb, const char *label, int *loop_depth,
                             bool *recursive, const cbm_gbuf_node_t **nptr, int64_t maxid) {
    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    if (cbm_gbuf_find_by_label(gb, label, &nodes, &count) != 0) {
        return;
    }
    for (int i = 0; i < count; i++) {
        const cbm_gbuf_node_t *n = nodes[i];
        int64_t n_id_v = cbm_node_id_value(n->id);
        if (n_id_v >= CBM_TLD_FIRST_NODE_ID && n_id_v <= maxid) {
            loop_depth[n_id_v] = json_get_int(n->properties_json, "loop_depth", 0);
            recursive[n_id_v] = json_get_bool(n->properties_json, "self_recursive");
            nptr[n_id_v] = n;
        }
    }
}

void cbm_pipeline_pass_complexity(cbm_pipeline_ctx_t *ctx) {
    cbm_gbuf_t *gb = ctx->gbuf;
    /* Node and edge IDs are drawn from one shared counter, so node IDs are NOT
     * contiguous 1..node_count — they interleave with edge IDs. Size the lookup
     * arrays by the id ceiling (next_id) so every node id is addressable. */
    int64_t maxid = cbm_gbuf_next_id(gb) - CBM_TLD_FIRST_NODE_ID;
    if (maxid < CBM_TLD_FIRST_NODE_ID) {
        return;
    }
    size_t sz = (size_t)maxid + CBM_TLD_FIRST_NODE_ID;
    int *loop_depth = calloc(sz, sizeof(int));
    int *tld = calloc(sz, sizeof(int));
    char *state = calloc(sz, sizeof(char));
    bool *recursive = calloc(sz, sizeof(bool));
    const cbm_gbuf_node_t **nptr = calloc(sz, sizeof(const cbm_gbuf_node_t *));
    if (!loop_depth || !tld || !state || !recursive || !nptr) {
        free(loop_depth);
        free(tld);
        free(state);
        free(recursive);
        free(nptr);
        return;
    }

    seed_loop_depths(gb, "Function", loop_depth, recursive, nptr, maxid);
    seed_loop_depths(gb, "Method", loop_depth, recursive, nptr, maxid);

    int updated = 0;
    for (int64_t id = CBM_TLD_FIRST_NODE_ID; id <= maxid; id++) {
        if (!nptr[id]) {
            continue; /* only Function/Method nodes */
        }
        if (state[id] != CBM_TLD_STATE_DONE) {
            tld_worklist(gb, id, loop_depth, tld, state, recursive, maxid);
        }
        append_complexity_props(gb, nptr[id], tld[id], recursive[id]);
        updated++;
    }

    cbm_log_info("pass.complexity", "functions", itoa_cx(updated));

    free(loop_depth);
    free(tld);
    free(state);
    free(recursive);
    free(nptr);
}
