/*
 * pass_calls.c — Resolve function/method calls into CALLS edges.
 *
 * For each discovered file:
 *   1. Re-extract calls (cbm_extract_file)
 *   2. Build per-file import map from IMPORTS edges in graph buffer
 *   3. Resolve each call via registry (import_map → same_module → unique → suffix)
 *   4. Create CALLS edges in graph buffer with confidence/strategy properties
 *
 * Depends on: pass_definitions having populated the registry and graph buffer
 */
#include "discover/discover.h"
#include "foundation/constants.h"

enum {
    PC_RING = 4,
    PC_RING_MASK = 3,
    PC_SIG_SCAN = 15,
    PC_REGEX_GRP = 2,
    PC_CONFIDENCE_DECIMALS = 2,
    PC_EXACT_CANDIDATE_COUNT = 1,
};
static const char PC_RETURN_TYPE_JSON_KEY[] = "\"return_type\":";
/* Confidence for a service-pattern HTTP/ASYNC edge emitted when registry
 * resolution is empty (external, unindexed client library) — see #523. */
#define PC_SVC_PATTERN_CONF 0.5
/* Confidence for a CALLS edge inferred from a FastAPI Depends() signature
 * reference. */
#define PC_DEPENDS_CONFIDENCE 0.95
#include "pipeline/pipeline.h"
#include <stdint.h>
#include "pipeline/pipeline_internal.h"
#include "pipeline/lsp_resolve.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/log.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/limits.h"
#include "foundation/platform.h"
#include "foundation/str_util.h"
#include "cbm.h"
#include "service_patterns.h"

#include "foundation/compat_regex.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* True for languages whose module QN derives from the CONTAINING DIRECTORY
 * (Java/Go package). MUST match cbm_lang_module_is_dir() (internal/cbm/helpers.c)
 * so same-module callee resolution keys against the directory-based def-node
 * QNs in the registry. */
static bool pc_module_is_dir(CBMLanguage lang) {
    return lang == CBM_LANG_JAVA || lang == CBM_LANG_GO;
}

/* Read entire file into heap-allocated buffer. Caller must free(). */
static char *read_file(const char *path, int *out_len) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    (void)fseek(f, 0, SEEK_END);
    long size = ftell(f);
    (void)fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > cbm_max_file_bytes()) { /* generous, env-configurable cap (B4) */
        (void)fclose(f);
        return NULL;
    }

    /* +pad: tree-sitter lexer lookahead reads past EOF; keep it in-bounds */
    enum { CBM_TS_LOOKAHEAD_PAD = 16 };
    char *buf = malloc((size_t)size + CBM_TS_LOOKAHEAD_PAD);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }

    size_t nread = fread(buf, SKIP_ONE, (size_t)size, f);
    (void)fclose(f);

    if (nread > (size_t)size) {
        nread = (size_t)size;
    }
    memset(buf + nread, 0, CBM_TS_LOOKAHEAD_PAD);
    *out_len = (int)nread;
    return buf;
}

/* Format int for logging. Thread-safe via TLS. */
static const char *itoa_log(int val) {
    static CBM_TLS char bufs[PC_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & PC_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* Build per-file import map from cached extraction result or graph buffer edges.
 * Returns parallel arrays of (local_name, module_qn) pairs. Caller frees. */
static int build_import_map(cbm_pipeline_ctx_t *ctx, const char *rel_path,
                            const CBMFileResult *result, const char ***out_keys,
                            const char ***out_vals, int *out_count) {
    *out_keys = NULL;
    *out_vals = NULL;
    *out_count = 0;

    /* Fast path: build from cached extraction result (no JSON parsing) */
    if (result && result->imports.count > 0) {
        const char **keys = calloc((size_t)result->imports.count, sizeof(const char *));
        const char **vals = calloc((size_t)result->imports.count, sizeof(const char *));
        int count = 0;

        for (int i = 0; i < result->imports.count; i++) {
            const CBMImport *imp = &result->imports.items[i];
            if (!imp->local_name || !imp->local_name[0] || !imp->module_path) {
                continue;
            }
            char *target_qn = cbm_pipeline_fqn_module(ctx->project_name, imp->module_path);
            const cbm_gbuf_node_t *target = cbm_gbuf_find_by_qn(ctx->gbuf, target_qn);
            free(target_qn);
            if (!target) {
                continue;
            }
            keys[count] = strdup(imp->local_name);
            vals[count] = target->qualified_name; /* borrowed from gbuf */
            count++;
        }

        *out_keys = keys;
        *out_vals = vals;
        *out_count = count;
        return 0;
    }

    /* Slow path: scan graph buffer IMPORTS edges + parse JSON properties */
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel_path, "__file__");
    const cbm_gbuf_node_t *file_node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
    free(file_qn);
    if (!file_node) {
        return 0;
    }

    const cbm_gbuf_edge_t **edges = NULL;
    int edge_count = 0;
    int rc = cbm_gbuf_find_edges_by_source_type(ctx->gbuf, file_node->id, "IMPORTS", &edges,
                                                &edge_count);
    if (rc != 0 || edge_count == 0) {
        return 0;
    }

    const char **keys = calloc((size_t)edge_count, sizeof(const char *));
    const char **vals = calloc((size_t)edge_count, sizeof(const char *));
    int count = 0;

    for (int i = 0; i < edge_count; i++) {
        const cbm_gbuf_edge_t *e = edges[i];
        const cbm_gbuf_node_t *target = cbm_gbuf_find_by_id(ctx->gbuf, e->target_id);
        if (!target) {
            continue;
        }
        const char *local_name = cbm_gbuf_edge_prop_string(e, "local_name");
        char *key = local_name ? strdup(local_name) : NULL;
        if (key) {
            keys[count] = key;
            vals[count] = target->qualified_name;
            count++;
        }
    }

    *out_keys = keys;
    *out_vals = vals;
    *out_count = count;
    return 0;
}

static void free_import_map(const char **keys, const char **vals, int count) {
    if (keys) {
        for (int i = 0; i < count; i++) {
            safe_str_free(&keys[i]);
        }
        free((void *)keys);
    }
    if (vals) {
        free((void *)vals);
    }
}

/* Handle a route registration call: create Route node + HANDLES edge. */
static void handle_route_registration(cbm_pipeline_ctx_t *ctx, const CBMCall *call,
                                      const cbm_gbuf_node_t *source_node, const char *module_qn,
                                      const char **imp_keys, const char **imp_vals, int imp_count) {
    const char *method = cbm_service_pattern_route_method(call->callee_name);
    char route_qn[CBM_ROUTE_QN_SIZE];
    char cpath[CBM_SZ_256];
    snprintf(route_qn, sizeof(route_qn), "__route__%s__%s", method ? method : "ANY",
             cbm_route_canon_path(call->first_string_arg, cpath, sizeof(cpath)));
    char route_props[CBM_SZ_256];
    snprintf(route_props, sizeof(route_props), "{\"method\":\"%s\"}", method ? method : "ANY");
    cbm_node_id_t route_id = cbm_gbuf_upsert_node(ctx->gbuf, "Route", call->first_string_arg,
                                                  route_qn, "", 0, 0, route_props);
    enum { ROUTE_CALLS_PROP_COUNT = 3 };
    cbm_gbuf_prop_t call_props[ROUTE_CALLS_PROP_COUNT] = {
        {.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name},
        {.key = "url_path", .kind = CBM_EDGE_PROP_STRING, .text = call->first_string_arg},
        {.key = "via", .kind = CBM_EDGE_PROP_STRING, .text = "route_registration"},
    };
    cbm_gbuf_insert_edge_props(
        ctx->gbuf, (cbm_edge_endpoints_t){.source = source_node->id, .target = route_id}, "CALLS",
        call_props, ROUTE_CALLS_PROP_COUNT);
    if (call->second_arg_name != NULL && call->second_arg_name[0] != '\0') {
        cbm_resolution_t hres = cbm_registry_resolve(ctx->registry, call->second_arg_name,
                                                     module_qn, imp_keys, imp_vals, imp_count);
        if (hres.qualified_name != NULL && hres.qualified_name[0] != '\0') {
            const cbm_gbuf_node_t *handler = cbm_gbuf_find_by_qn(ctx->gbuf, hres.qualified_name);
            if (handler != NULL) {
                enum { HANDLES_PROP_COUNT = 1 };
                cbm_gbuf_prop_t handles_props[HANDLES_PROP_COUNT] = {
                    {.key = "handler", .kind = CBM_EDGE_PROP_STRING, .text = hres.qualified_name},
                };
                cbm_gbuf_insert_edge_props(
                    ctx->gbuf, (cbm_edge_endpoints_t){.source = handler->id, .target = route_id},
                    "HANDLES", handles_props, HANDLES_PROP_COUNT);
            }
        }
    }
}

/* Emit an HTTP/async route edge for a service call. */
/* Build route QN and upsert Route node for HTTP/async edge. */
static cbm_node_id_t create_svc_route_node(cbm_pipeline_ctx_t *ctx, const char *url,
                                           cbm_svc_kind_t svc, const char *method,
                                           const char *broker) {
    char route_qn[CBM_ROUTE_QN_SIZE];
    const char *prefix;
    char cpath[CBM_SZ_256];
    const char *qpath = url;
    if (svc == CBM_SVC_HTTP) {
        prefix = method ? method : "ANY";
        qpath = cbm_route_canon_path(url, cpath, sizeof(cpath));
    } else {
        prefix = broker ? broker : "async";
    }
    snprintf(route_qn, sizeof(route_qn), "__route__%s__%s", prefix, qpath);
    /* Valid-JSON route properties, byte-identical to the parallel path's
     * build_service_route. The old code stored the RAW method/broker string
     * (literally `bullmq`), which broke json_extract, the edges generated
     * columns, and PRAGMA quick_check on every such cache (#898). */
    char route_props[CBM_SZ_256];
    if (method) {
        snprintf(route_props, sizeof(route_props), "{\"method\":\"%s\"}", method);
    } else if (broker) {
        snprintf(route_props, sizeof(route_props), "{\"broker\":\"%s\"}", broker);
    } else {
        snprintf(route_props, sizeof(route_props), "{}");
    }
    return cbm_gbuf_upsert_node(ctx->gbuf, "Route", url, route_qn, "", 0, 0, route_props);
}

/* Insert an edge, splicing the call-site line (,"line":N) in before the closing
 * brace when one was captured. Mirrors finalize_and_emit() on the parallel path
 * so CALLS edges carry their source line regardless of resolution path. Restricted
 * to CALLS: route/config edge props feed full-only predump passes
 * (create_route_nodes/create_data_flows), so altering them desyncs full vs
 * incremental indexing. */
/* Number of edge props calls_emit_edge may append on top of the caller-
 * supplied base props for a CALLS edge: "line" and "args". Callers must size
 * their prop array to their base field count plus this. */
enum { CALLS_EMIT_EXTRA_PROPS = 2 };

/* Build a "[{"i":0,"e":"<expr>","v":"<value>"},...]" literal into buf for a
 * CALLS edge's "args" prop. The sequential pass omitted this, so data_flow
 * mode had no argument expressions to surface for small (< 50 file) repos
 * that take the sequential path (#514). Mirrors the parallel path's
 * append_args_json shape so both pipelines agree. Returns false (buf
 * untouched) when the call captured no argument expressions. */
static bool calls_build_args_json(char *buf, size_t cap, const CBMCall *call) {
    if (!call || call->arg_count <= 0 || cap < PAIR_LEN) {
        return false;
    }
    size_t pos = 0;
    buf[pos++] = '[';
    for (int i = 0; i < call->arg_count; i++) {
        const CBMCallArg *a = &call->args[i];
        char esc_e[CBM_SZ_256];
        cbm_json_escape(esc_e, sizeof(esc_e), a->expr ? a->expr : "");
        char one[CBM_SZ_512];
        int n;
        if (a->value) {
            char esc_v[CBM_SZ_256];
            cbm_json_escape(esc_v, sizeof(esc_v), a->value);
            n = snprintf(one, sizeof(one), "%s{\"i\":%d,\"e\":\"%s\",\"v\":\"%s\"}",
                         i > 0 ? "," : "", a->index, esc_e, esc_v);
        } else {
            n = snprintf(one, sizeof(one), "%s{\"i\":%d,\"e\":\"%s\"}", i > 0 ? "," : "", a->index,
                         esc_e);
        }
        /* Add rather than subtract: pos is unsigned, so `cap - pos - PAIR_LEN`
         * wraps once pos reaches cap - PAIR_LEN and stops bounding the memcpy
         * below. The closing write at the end of this function already guards
         * additively; match it. */
        if (n <= 0 || pos + (size_t)n + PAIR_LEN >= cap) {
            break; /* not enough room — close the array with what fits */
        }
        memcpy(buf + pos, one, (size_t)n);
        pos += (size_t)n;
    }
    if (pos + SKIP_ONE < cap) {
        buf[pos++] = ']';
        buf[pos] = '\0';
    }
    return true;
}

/* Insert an edge from a caller-built base prop array, appending "line" and
 * "args" typed props for a CALLS edge when the call site provides them.
 * props must have room for prop_count + CALLS_EMIT_EXTRA_PROPS entries. */
static void calls_emit_edge(cbm_gbuf_t *gbuf, cbm_node_id_t src, cbm_node_id_t tgt,
                            const char *type, cbm_gbuf_prop_t *props, int prop_count,
                            const CBMCall *call) {
    char args_buf[CBM_SZ_1K];
    bool is_calls = call && strcmp(type, "CALLS") == 0;
    if (is_calls && call->start_line > 0) {
        props[prop_count++] = (cbm_gbuf_prop_t){
            .key = "line",
            .kind = CBM_EDGE_PROP_NUMBER,
            .number = (double)call->start_line,
            .decimals = 0,
        };
    }
    if (is_calls && calls_build_args_json(args_buf, sizeof(args_buf), call)) {
        props[prop_count++] =
            (cbm_gbuf_prop_t){.key = "args", .kind = CBM_EDGE_PROP_STRING, .text = args_buf};
    }
    cbm_gbuf_insert_edge_props(gbuf, (cbm_edge_endpoints_t){.source = src, .target = tgt}, type,
                               props, prop_count);
}

/* Number of base props built by calls_build_resolution_props: callee,
 * confidence, strategy, candidates. */
enum { CALLS_RESOLUTION_PROP_COUNT = 4 };

/* Build the "callee"/"confidence"/"strategy"/"candidates" props shared by
 * emit_http_async_edge's plain-CALLS fallback and emit_classified_edge's
 * default CALLS edge. props must have room for CALLS_RESOLUTION_PROP_COUNT
 * entries. */
static void calls_build_resolution_props(cbm_gbuf_prop_t *props, const char *callee,
                                         const cbm_resolution_t *res) {
    int n = 0;
    props[n++] = (cbm_gbuf_prop_t){.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = callee};
    props[n++] = (cbm_gbuf_prop_t){.key = "confidence",
                                   .kind = CBM_EDGE_PROP_NUMBER,
                                   .number = res->confidence,
                                   .decimals = PC_CONFIDENCE_DECIMALS};
    props[n++] = (cbm_gbuf_prop_t){.key = "strategy",
                                   .kind = CBM_EDGE_PROP_STRING,
                                   .text = res->strategy ? res->strategy : "unknown"};
    props[n++] = (cbm_gbuf_prop_t){.key = "candidates",
                                   .kind = CBM_EDGE_PROP_NUMBER,
                                   .number = (double)res->candidate_count,
                                   .decimals = 0};
}

static void emit_http_async_edge(cbm_pipeline_ctx_t *ctx, const CBMCall *call,
                                 const cbm_gbuf_node_t *source, const cbm_gbuf_node_t *target,
                                 const cbm_resolution_t *res, cbm_svc_kind_t svc,
                                 bool suppress_plain_calls) {
    const char *url_or_topic = call->first_string_arg;
    bool is_url = (url_or_topic && url_or_topic[0] != '\0' &&
                   (url_or_topic[0] == '/' || strstr(url_or_topic, "://") != NULL));
    bool is_topic = (url_or_topic && url_or_topic[0] != '\0' && svc == CBM_SVC_ASYNC &&
                     strlen(url_or_topic) > PAIR_LEN);
    if (!is_url && !is_topic) {
        /* No URL/topic → this is not a real service call; the svc kind was a
         * substring coincidence in the resolved QN (e.g. "SalesforceRestClient"
         * matches the "RestClient" HTTP lib). Emit a plain CALLS edge — unless a
         * weak TS/JS member-call match should be suppressed (#592/#606). */
        /* !target: the service-pattern call sites pass NULL (the route node is
         * synthesized below) behind a hand-duplicated copy of the is_url/
         * is_topic predicate above. While the copies agree this branch is
         * unreachable for them -- but a drift between the two would turn
         * target->id into a null dereference (clang-analyzer traced exactly
         * that), and with no callee node there is nothing to emit anyway. */
        if (suppress_plain_calls || !target) {
            return;
        }
        enum { PLAIN_CALLS_PROP_CAP = CALLS_RESOLUTION_PROP_COUNT + CALLS_EMIT_EXTRA_PROPS };
        cbm_gbuf_prop_t props[PLAIN_CALLS_PROP_CAP];
        calls_build_resolution_props(props, call->callee_name, res);
        calls_emit_edge(ctx->gbuf, source->id, target->id, "CALLS", props,
                        CALLS_RESOLUTION_PROP_COUNT, call);
        return;
    }
    const char *edge_type = (svc == CBM_SVC_HTTP) ? "HTTP_CALLS" : "ASYNC_CALLS";
    const char *method =
        (svc == CBM_SVC_HTTP) ? cbm_service_pattern_http_method(call->callee_name) : NULL;
    const char *broker =
        (svc == CBM_SVC_ASYNC) ? cbm_service_pattern_broker(res->qualified_name) : NULL;
    cbm_node_id_t route_id = create_svc_route_node(ctx, url_or_topic, svc, method, broker);
    /* Mirrors the parallel path's emit_http_async_service_edge field set:
     * callee + url_path always present, method/broker only for their
     * respective svc kind (#898). */
    enum { HTTP_ASYNC_PROP_CAP = CBM_SZ_4 + CALLS_EMIT_EXTRA_PROPS };
    cbm_gbuf_prop_t props[HTTP_ASYNC_PROP_CAP];
    int prop_count = 0;
    props[prop_count++] =
        (cbm_gbuf_prop_t){.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name};
    props[prop_count++] =
        (cbm_gbuf_prop_t){.key = "url_path", .kind = CBM_EDGE_PROP_STRING, .text = url_or_topic};
    if (method) {
        props[prop_count++] =
            (cbm_gbuf_prop_t){.key = "method", .kind = CBM_EDGE_PROP_STRING, .text = method};
    }
    if (broker) {
        props[prop_count++] =
            (cbm_gbuf_prop_t){.key = "broker", .kind = CBM_EDGE_PROP_STRING, .text = broker};
    }
    calls_emit_edge(ctx->gbuf, source->id, route_id, edge_type, props, prop_count, call);
}

/* Classify a resolved call and emit the appropriate edge. */
/* When suppress_plain_calls is true (a TS/JS/TSX weak short-name member-call
 * match, #592/#606), the route/HTTP/ASYNC/CONFIG service classifications below
 * still run — only the plain CALLS fall-through is skipped, so a fabricated
 * project edge is dropped while every service edge stays main-identical. */
static void emit_classified_edge(cbm_pipeline_ctx_t *ctx, const CBMCall *call,
                                 const cbm_gbuf_node_t *source, const cbm_gbuf_node_t *target,
                                 const cbm_resolution_t *res, const char *module_qn,
                                 const char **imp_keys, const char **imp_vals, int imp_count,
                                 bool suppress_plain_calls) {
    cbm_svc_kind_t svc = cbm_service_pattern_match(res->qualified_name);
    if (svc == CBM_SVC_ROUTE_REG && call->first_string_arg && call->first_string_arg[0] == '/') {
        handle_route_registration(ctx, call, source, module_qn, imp_keys, imp_vals, imp_count);
        return;
    }
    if (svc == CBM_SVC_HTTP || svc == CBM_SVC_ASYNC) {
        emit_http_async_edge(ctx, call, source, target, res, svc, suppress_plain_calls);
        return;
    }
    if (svc == CBM_SVC_CONFIG) {
        enum { CONFIGURES_PROP_COUNT = 3 };
        cbm_gbuf_prop_t props[CONFIGURES_PROP_COUNT] = {
            {.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name},
            {.key = "key",
             .kind = CBM_EDGE_PROP_STRING,
             .text = call->first_string_arg ? call->first_string_arg : ""},
            {.key = "confidence",
             .kind = CBM_EDGE_PROP_NUMBER,
             .number = res->confidence,
             .decimals = PC_CONFIDENCE_DECIMALS},
        };
        calls_emit_edge(ctx->gbuf, source->id, target->id, "CONFIGURES", props,
                        CONFIGURES_PROP_COUNT, call);
        return;
    }
    if (suppress_plain_calls) {
        return; /* weak TS/JS member-call match with an unresolved receiver (#606) */
    }
    enum { DEFAULT_CALLS_PROP_CAP = CALLS_RESOLUTION_PROP_COUNT + CALLS_EMIT_EXTRA_PROPS };
    cbm_gbuf_prop_t props[DEFAULT_CALLS_PROP_CAP];
    calls_build_resolution_props(props, call->callee_name, res);
    calls_emit_edge(ctx->gbuf, source->id, target->id, "CALLS", props, CALLS_RESOLUTION_PROP_COUNT,
                    call);
}

/* Find source node for a call: enclosing function or file node. */
static const cbm_gbuf_node_t *calls_find_source(cbm_pipeline_ctx_t *ctx, const char *rel,
                                                const char *enclosing_qn) {
    const cbm_gbuf_node_t *src = NULL;
    if (enclosing_qn) {
        src = cbm_gbuf_find_by_qn(ctx->gbuf, enclosing_qn);
        /* A class-level call in a directory-module language carries the
         * DIRECTORY module QN, which hits the shared Folder/Project node —
         * attribute to this file's File node instead (#787). */
        if (cbm_pipeline_node_is_dir_container(src)) {
            src = NULL;
        }
    }
    if (!src) {
        char *fqn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
        src = cbm_gbuf_find_by_qn(ctx->gbuf, fqn);
        free(fqn);
    }
    return src;
}

static bool calls_emit_lsp_resolution(cbm_pipeline_ctx_t *ctx, const CBMCall *call,
                                      const CBMResolvedCallArray *lsp_calls,
                                      const cbm_gbuf_node_t *source_node, const char *module_qn,
                                      const char **imp_keys, const char **imp_vals, int imp_count,
                                      CBMLanguage lang) {
    /* LSP-resolved calls take precedence over registry-textual matching.
     * Unique-tail fallbacks are JVM-only (see cbm_pipeline_lsp_allow_tail_match). */
    bool allow_tail = cbm_pipeline_lsp_allow_tail_match(lang);
    const CBMResolvedCall *lsp = cbm_pipeline_find_lsp_resolution_in_graph(
        lsp_calls, call, allow_tail, ctx->gbuf, ctx->project_name);
    if (lsp) {
        bool exact_external_target = call->requires_lsp_resolution &&
                                     cbm_pipeline_kotlin_external_target(lang, lsp->callee_qn);
        const cbm_gbuf_node_t *target_node =
            exact_external_target ? cbm_pipeline_lsp_target_node_strict(
                                        ctx->gbuf, ctx->project_name, lsp->callee_qn, allow_tail)
                                  : cbm_pipeline_lsp_target_node(ctx->gbuf, ctx->project_name,
                                                                 lsp->callee_qn, allow_tail);
        if (target_node && !cbm_node_id_eq(source_node->id, target_node->id)) {
            cbm_resolution_t res = {0};
            /* Use the gbuf node's QN so downstream edge props show the canonical
             * project-qualified form even when fallback prefixed the project. */
            res.qualified_name = target_node->qualified_name;
            res.confidence = (double)lsp->confidence;
            res.strategy = lsp->strategy;
            res.candidate_count = PC_EXACT_CANDIDATE_COUNT;
            emit_classified_edge(ctx, call, source_node, target_node, &res, module_qn, imp_keys,
                                 imp_vals, imp_count, false);
            return true;
        }
    }
    return false;
}

static bool calls_has_service_target(const CBMCall *call, cbm_svc_kind_t service) {
    const char *target = call->first_string_arg;
    return target && target[0] != '\0' &&
           (target[0] == '/' || strstr(target, "://") != NULL ||
            (service == CBM_SVC_ASYNC && strlen(target) > PAIR_LEN));
}

static cbm_resolution_t calls_service_resolution(const CBMCall *call) {
    return (cbm_resolution_t){.qualified_name = call->callee_name,
                              .confidence = PC_SVC_PATTERN_CONF,
                              .strategy = "service_pattern",
                              .candidate_count = 0};
}

static bool calls_emit_service_edge(cbm_pipeline_ctx_t *ctx, const CBMCall *call,
                                    const cbm_gbuf_node_t *source_node,
                                    const cbm_resolution_t *resolution, cbm_svc_kind_t service) {
    if (service != CBM_SVC_HTTP && service != CBM_SVC_ASYNC) {
        return false;
    }
    if (!calls_has_service_target(call, service)) {
        return false;
    }
    emit_http_async_edge(ctx, call, source_node, NULL, resolution, service, false);
    return true;
}

static bool calls_handle_unresolved_route(cbm_pipeline_ctx_t *ctx, const CBMCall *call,
                                          const cbm_gbuf_node_t *source_node, const char *module_qn,
                                          const char **imp_keys, const char **imp_vals,
                                          int imp_count) {
    if (cbm_service_pattern_route_method(call->callee_name) == NULL || !call->first_string_arg ||
        call->first_string_arg[0] != '/') {
        return false;
    }
    handle_route_registration(ctx, call, source_node, module_qn, imp_keys, imp_vals, imp_count);
    return true;
}

static cbm_svc_kind_t calls_unresolved_service_kind(const CBMCall *call) {
    cbm_svc_kind_t service = cbm_service_pattern_match(call->callee_name);
    if (service == CBM_SVC_NONE && cbm_service_pattern_is_global_fetch(call->callee_name)) {
        return CBM_SVC_HTTP;
    }
    return service;
}

/* Resolve one call and emit the appropriate edge. Returns 1 if resolved, 0 if not. */
static int resolve_single_call(cbm_pipeline_ctx_t *ctx, CBMCall *call,
                               const CBMResolvedCallArray *lsp_calls, const char *rel,
                               const char *module_qn, const char **imp_keys, const char **imp_vals,
                               int imp_count, CBMLanguage lang) {
    const cbm_gbuf_node_t *source_node = calls_find_source(ctx, rel, call->enclosing_func_qn);
    if (!source_node) {
        return 0;
    }

    if (calls_emit_lsp_resolution(ctx, call, lsp_calls, source_node, module_qn, imp_keys, imp_vals,
                                  imp_count, lang)) {
        return SKIP_ONE;
    }

    /* Synthetic semantic candidates (currently implicit C++ operators) are
     * valid calls only when the language resolver identifies a concrete
     * invocation target. Textual registry/service fallbacks would bind an
     * unresolved primitive expression such as `int + int` to an unrelated
     * project `operator+`, fabricating a CALLS edge. */
    if (call->requires_lsp_resolution) {
        return 0;
    }

    /* Service-pattern HTTP/ASYNC client call (`requests.get(url)`): the service
     * signal lives in the callee_name. The registry can mis-resolve such a call
     * to a spurious builtin short-name match (e.g. `requests.get` ->
     * `builtins.dict.get` via "get", strategy unique_name), which is non-empty
     * and not an HTTP pattern, so BOTH the empty-resolution and resolved-QN
     * service checks below miss it and the call is dropped. Detect it on the
     * callee_name FIRST so the HTTP_CALLS/ASYNC_CALLS edge is emitted regardless
     * (target is a synthesized route node, not the unindexed library). (#523) */
    cbm_svc_kind_t csvc = cbm_service_pattern_match(call->callee_name);
    cbm_resolution_t callee_service_resolution = calls_service_resolution(call);
    if (calls_emit_service_edge(ctx, call, source_node, &callee_service_resolution, csvc)) {
        return SKIP_ONE;
    }

    cbm_resolution_t res = cbm_registry_resolve(ctx->registry, call->callee_name, module_qn,
                                                imp_keys, imp_vals, imp_count);
    if (!res.qualified_name || res.qualified_name[0] == '\0') {
        /* Resolution is empty when the callee belongs to an EXTERNAL client
         * library whose source is not in the indexed tree (e.g. `requests.get`,
         * `httpx.post`) — the import map skips it (no node) and no project symbol
         * matches. The service-pattern signal lives in the RAW callee_name
         * ("requests.get" contains "requests"), so classify on that and emit the
         * HTTP_CALLS/ASYNC_CALLS edge directly (target is a synthesized route
         * node, not the absent library). Without this the call is dropped and
         * cross-repo matching finds no edge to match (#523). The parallel path
         * has the equivalent empty-resolution fallback in resolve_file_calls.
         *
         * Native `fetch()` (#856) belongs here too, not in the substring
         * tables above: it only counts as the global API once resolution has
         * already failed to find a local/imported `fetch` definition. */
        /* Route registration on an unresolvable callee (#952): facade-style
         * Laravel (`Route::get('/x', ...)`) — the facade class lives in
         * vendor/ and is never indexed, so resolution is ALWAYS empty in real
         * apps. Classify by callee suffix + path-shaped first arg, exactly
         * like the parallel path's callee_suffix fallback; without this the
         * sequential path minted zero Route nodes for such files. */
        if (calls_handle_unresolved_route(ctx, call, source_node, module_qn, imp_keys, imp_vals,
                                          imp_count)) {
            return SKIP_ONE;
        }
        cbm_svc_kind_t unresolved_service = calls_unresolved_service_kind(call);
        if (calls_emit_service_edge(ctx, call, source_node, &callee_service_resolution,
                                    unresolved_service)) {
            return SKIP_ONE;
        }
        return 0;
    }

    /* Perl call-graph noise guard (#476). Perl has no LSP resolver, so the
     * generic registry chain is the only resolver; for builtins (push/shift/
     * keys/...) and method calls ($obj->m with an unresolved receiver), a *weak*
     * cross-file short-name match to a project sub sharing the name is almost
     * always a false positive. Suppress only those weak matches; KEEP the
     * high-confidence same_module / import_map strategies so a genuine
     * same-file or imported call to a builtin-named sub still resolves. Gated
     * to Perl — other languages are unaffected. */
    if (cbm_perl_suppress_generic_match(lang == CBM_LANG_PERL, call->is_method, call->callee_name,
                                        res.strategy)) {
        return 0;
    }

    /* TS/JS/TSX weak-method suppression (#592/#606). A member call x.foo() only
     * reaches the registry when the TS-LSP could not resolve the receiver type
     * (the LSP block above already returned for type-resolved calls, including
     * the "resolved but target out of gbuf" fall-through). Binding such a call
     * by a weak short-name strategy fabricates an edge (`re.test()` -> a project
     * `test`). Rather than drop it here — which would also skip the service
     * bypasses below and emit_classified_edge's route/HTTP/CONFIG branches —
     * defer to emit_classified_edge and suppress ONLY the plain-CALLS
     * fall-through, so every service edge stays main-identical. res.strategy may
     * be lsp_* here; the helper's explicit drop-list leaves lsp_* untouched. */
    bool is_tsjs =
        lang == CBM_LANG_JAVASCRIPT || lang == CBM_LANG_TYPESCRIPT || lang == CBM_LANG_TSX;
    bool tsjs_drop_plain_call =
        cbm_tsjs_suppress_weak_method_match(is_tsjs, call->is_method, res.strategy);

    /* Service-pattern HTTP/ASYNC calls to an EXTERNAL client library (e.g.
     * `requests.get("/api/orders/{id}")`) resolve to a QN containing the library
     * name ("requests"), but that library is not in the indexed tree so
     * cbm_gbuf_find_by_qn returns NULL. The edge target for such calls is a
     * SYNTHESIZED route node (create_svc_route_node), not the library node, so
     * the missing target must NOT drop the call — otherwise no HTTP_CALLS edge
     * is written and cross-repo matching finds nothing (#523). Emit directly
     * when the call carries a URL/topic first argument. */
    cbm_svc_kind_t svc = cbm_service_pattern_match(res.qualified_name);
    if (calls_emit_service_edge(ctx, call, source_node, &res, svc)) {
        return SKIP_ONE;
    }

    const cbm_gbuf_node_t *target_node = cbm_gbuf_find_by_qn(ctx->gbuf, res.qualified_name);
    if (!target_node || cbm_node_id_eq(source_node->id, target_node->id)) {
        return 0;
    }
    emit_classified_edge(ctx, call, source_node, target_node, &res, module_qn, imp_keys, imp_vals,
                         imp_count, tsjs_drop_plain_call);
    return SKIP_ONE;
}

static bool calls_return_type_from_node(const cbm_gbuf_node_t *node, char return_type[CBM_SZ_256]) {
    if (!node->qualified_name || !node->properties_json) {
        return false;
    }
    const char *type_start = strstr(node->properties_json, PC_RETURN_TYPE_JSON_KEY);
    if (!type_start) {
        return false;
    }
    type_start += sizeof(PC_RETURN_TYPE_JSON_KEY) - SKIP_ONE;
    while (*type_start == ' ') {
        type_start++;
    }
    if (*type_start != '"') {
        return false;
    }
    type_start++;
    const char *type_end = strchr(type_start, '"');
    if (!type_end) {
        return false;
    }
    int length = (int)(type_end - type_start);
    if (length <= 0 || length >= CBM_SZ_256) {
        return false;
    }
    memcpy(return_type, type_start, (size_t)length);
    return_type[length] = '\0';
    return true;
}

static bool calls_return_type_is_scalar(const char *return_type) {
    static const char *scalar_types[] = {"%String",    "%Integer", "%Float", "%Boolean",
                                         "%Status",    "%Numeric", "%Date",  "%Time",
                                         "%TimeStamp", "%Binary",  NULL};
    for (int i = 0; scalar_types[i]; i++) {
        if (strcmp(return_type, scalar_types[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void calls_add_return_type(CBMReturnTypeTable *table, const cbm_gbuf_node_t *node) {
    char return_type[CBM_SZ_256];
    if (!calls_return_type_from_node(node, return_type) ||
        calls_return_type_is_scalar(return_type)) {
        return;
    }
    table->entries[table->count].method_qn = node->qualified_name;
    table->entries[table->count].return_type = strdup(return_type);
    table->count++;
}

/* ObjectScript: build a method-QN -> return-type table from the Method nodes
 * already in the graph buffer (definitions pass ran first). Scalar return types
 * (%String, %Integer, ...) are skipped since they cannot host method dispatch.
 * Returns NULL when no usable entries exist. Caller owns the heap table. */
static CBMReturnTypeTable *build_return_type_table(const cbm_gbuf_t *gbuf) {
    if (!gbuf) {
        return NULL;
    }
    const cbm_gbuf_node_t **method_nodes = NULL;
    int method_count = 0;
    if (cbm_gbuf_find_by_label(gbuf, "Method", &method_nodes, &method_count) != 0 ||
        method_count <= 0 || !method_nodes) {
        return NULL;
    }

    CBMReturnTypeTable *rtt =
        (CBMReturnTypeTable *)calloc(CBM_ALLOC_ONE, sizeof(CBMReturnTypeTable));
    if (!rtt) {
        return NULL;
    }
    for (int i = 0; i < method_count && rtt->count < CBM_RETURN_TYPE_TABLE_CAP; i++) {
        calls_add_return_type(rtt, method_nodes[i]);
    }
    if (rtt->count == 0) {
        free(rtt);
        return NULL;
    }
    return rtt;
}

static CBMFileResult *calls_get_or_extract(cbm_pipeline_ctx_t *ctx, int idx,
                                           const cbm_file_info_t *fi, bool *owned) {
    *owned = false;
    if (ctx->result_cache && ctx->result_cache[idx]) {
        return ctx->result_cache[idx];
    }
    int slen = 0;
    char *src = read_file(fi->path, &slen);
    if (!src) {
        return NULL;
    }
    CBMFileResult *r = cbm_extract_file_ex(src, slen, fi->language, ctx->project_name, fi->rel_path,
                                           CBM_EXTRACT_BUDGET, NULL, NULL, ctx->macro_table,
                                           ctx->return_type_table);
    free(src);
    if (r) {
        *owned = true;
    }
    return r;
}

int cbm_pipeline_pass_calls(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count) {
    cbm_log_info("pass.start", "pass", "calls", "files", itoa_log(file_count));

    /* ObjectScript: build the method-return-type table from the definitions
     * already in the graph buffer so `Set x = obj.Method()` can resolve x's
     * class for subsequent x.Method() dispatch. NULL if no Method nodes. */
    if (!ctx->return_type_table) {
        CBMReturnTypeTable *rtt = build_return_type_table(ctx->gbuf);
        if (rtt) {
            ctx->return_type_table = rtt;
        }
    }

    int total_calls = 0;
    int resolved = 0;
    int unresolved = 0;
    int errors = 0;

    for (int i = 0; i < file_count; i++) {
        if (cbm_pipeline_check_cancel(ctx)) {
            return CBM_NOT_FOUND;
        }

        const char *rel = files[i].rel_path;
        bool result_owned = false;
        CBMFileResult *result = calls_get_or_extract(ctx, i, &files[i], &result_owned);
        if (!result) {
            errors++;
            continue;
        }

        if (result->calls.count == 0) {
            if (result_owned) {
                cbm_free_result(result);
            }
            continue;
        }

        /* Build import map for this file */
        const char **imp_keys = NULL;
        const char **imp_vals = NULL;
        int imp_count = 0;
        build_import_map(ctx, rel, result, &imp_keys, &imp_vals, &imp_count);

        /* Compute module QN for same-module resolution (directory-based for
         * Java/Go so it matches their def-node QNs in the registry). */
        char *module_qn = cbm_pipeline_fqn_module_dir(ctx->project_name, rel,
                                                      pc_module_is_dir(files[i].language));

        /* Resolve each call */
        for (int c = 0; c < result->calls.count; c++) {
            CBMCall *call = &result->calls.items[c];
            if (!call->callee_name) {
                continue;
            }
            total_calls++;
            if (resolve_single_call(ctx, call, &result->resolved_calls, rel, module_qn, imp_keys,
                                    imp_vals, imp_count, files[i].language)) {
                resolved++;
            } else {
                unresolved++;
            }
        }

        free(module_qn);
        free_import_map(imp_keys, imp_vals, imp_count);
        if (result_owned) {
            cbm_free_result(result);
        }
    }

    cbm_log_info("pass.done", "pass", "calls", "total", itoa_log(total_calls), "resolved",
                 itoa_log(resolved), "unresolved", itoa_log(unresolved), "errors",
                 itoa_log(errors));

    /* Additional pattern-based edge passes run after normal call resolution */
    cbm_pipeline_pass_fastapi_depends(ctx, files, file_count);

    return 0;
}

/* ── FastAPI Depends() tracking ──────────────────────────────────── */
/* Scans Python function signatures for Depends(func_ref) patterns and
 * creates CALLS edges from the endpoint to the dependency function.
 * Without this, FastAPI auth/DI functions appear as dead code (in_degree=0). */

/* Extract Python function signature text from source starting at given line. Caller frees. */
static char *extract_py_signature(const char *source, int start_line, int end_line) {
    int sig_end = start_line + PC_SIG_SCAN;
    if (end_line > 0 && sig_end > end_line) {
        sig_end = end_line;
    }
    const char *p = source;
    int line = SKIP_ONE;
    while (*p && line < start_line) {
        if (*p == '\n') {
            line++;
        }
        p++;
    }
    const char *sig_start = p;
    while (*p && line < sig_end) {
        if (*p == '\n') {
            line++;
        }
        p++;
        if (p > sig_start + SKIP_ONE && p[-SKIP_ONE] == ':' && p[-PAIR_LEN] == ')') {
            break;
        }
    }
    size_t sig_len = (size_t)(p - sig_start);
    char *sig = malloc(sig_len + SKIP_ONE);
    if (!sig) {
        return NULL;
    }
    memcpy(sig, sig_start, sig_len);
    sig[sig_len] = '\0';
    return sig;
}

/* Scan one function's signature for Depends(func_ref) and create CALLS edges. */
static int scan_depends_in_sig(cbm_pipeline_ctx_t *ctx, const cbm_regex_t *re, const char *sig,
                               const CBMDefinition *def, const char *module_qn, const char **ik,
                               const char **iv, int ic) {
    int count = 0;
    cbm_regmatch_t match[PC_REGEX_GRP];
    const char *scan = sig;
    while (cbm_regexec(re, scan, PC_REGEX_GRP, match, 0) == 0) {
        int ref_len = match[SKIP_ONE].rm_eo - match[SKIP_ONE].rm_so;
        char func_ref[CBM_SZ_256];
        if (ref_len >= (int)sizeof(func_ref)) {
            ref_len = (int)sizeof(func_ref) - SKIP_ONE;
        }
        memcpy(func_ref, scan + match[SKIP_ONE].rm_so, (size_t)ref_len);
        func_ref[ref_len] = '\0';
        cbm_resolution_t res = cbm_registry_resolve(ctx->registry, func_ref, module_qn, ik, iv, ic);
        if (res.qualified_name && res.qualified_name[0] != '\0') {
            const cbm_gbuf_node_t *sn = cbm_gbuf_find_by_qn(ctx->gbuf, def->qualified_name);
            const cbm_gbuf_node_t *tn = cbm_gbuf_find_by_qn(ctx->gbuf, res.qualified_name);
            if (sn && tn && !cbm_node_id_eq(sn->id, tn->id)) {
                enum { DEPENDS_PROP_COUNT = 2 };
                cbm_gbuf_prop_t depends_props[DEPENDS_PROP_COUNT] = {
                    {.key = "confidence",
                     .kind = CBM_EDGE_PROP_NUMBER,
                     .number = PC_DEPENDS_CONFIDENCE,
                     .decimals = PC_CONFIDENCE_DECIMALS},
                    {.key = "strategy", .kind = CBM_EDGE_PROP_STRING, .text = "fastapi_depends"},
                };
                cbm_gbuf_insert_edge_props(
                    ctx->gbuf, (cbm_edge_endpoints_t){.source = sn->id, .target = tn->id}, "CALLS",
                    depends_props, DEPENDS_PROP_COUNT);
                count++;
            }
        }
        scan += match[0].rm_eo;
    }
    return count;
}

static bool is_callable_def(const CBMDefinition *def) {
    return def->qualified_name && def->start_line > 0 && def->label &&
           (strcmp(def->label, "Function") == 0 || strcmp(def->label, "Method") == 0);
}

static bool file_has_depends_call(const CBMFileResult *result) {
    for (int c = 0; c < result->calls.count; c++) {
        if (result->calls.items[c].callee_name &&
            strcmp(result->calls.items[c].callee_name, "Depends") == 0) {
            return true;
        }
    }
    return false;
}

void cbm_pipeline_pass_fastapi_depends(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                       int file_count) {
    cbm_regex_t depends_re;
    if (cbm_regcomp(&depends_re, "Depends\\(([A-Za-z_][A-Za-z0-9_.]*)", CBM_REG_EXTENDED) != 0) {
        return;
    }

    int edge_count = 0;
    for (int i = 0; i < file_count; i++) {
        if (files[i].language != CBM_LANG_PYTHON) {
            continue;
        }
        if (cbm_pipeline_check_cancel(ctx)) {
            break;
        }

        CBMFileResult *result = ctx->result_cache ? ctx->result_cache[i] : NULL;
        if (!result || !file_has_depends_call(result)) {
            continue;
        }

        /* Read source and scan for Depends(func_ref) in function signatures */
        int source_len = 0;
        char *source = read_file(files[i].path, &source_len);
        if (!source) {
            continue;
        }

        char *module_qn = cbm_pipeline_fqn_module_dir(ctx->project_name, files[i].rel_path,
                                                      pc_module_is_dir(files[i].language));

        /* Build import map for alias resolution */
        const char **imp_keys = NULL;
        const char **imp_vals = NULL;
        int imp_count = 0;
        build_import_map(ctx, files[i].rel_path, result, &imp_keys, &imp_vals, &imp_count);

        for (int d = 0; d < result->defs.count; d++) {
            CBMDefinition *def = &result->defs.items[d];
            if (!is_callable_def(def)) {
                continue;
            }

            char *sig = extract_py_signature(source, (int)def->start_line, (int)def->end_line);
            if (!sig) {
                continue;
            }

            edge_count += scan_depends_in_sig(ctx, &depends_re, sig, def, module_qn, imp_keys,
                                              imp_vals, imp_count);
            free(sig);
        }

        free(module_qn);
        free_import_map(imp_keys, imp_vals, imp_count);
        free(source);
    }

    cbm_regfree(&depends_re);
    if (edge_count > 0) {
        cbm_log_info("pass.fastapi_depends", "edges", itoa_log(edge_count));
    }
}

/* DLL resolve tracking removed — triggered Windows Defender false positive.
 * See issue #89. */
