/*
 * pass_k8s.c — Pipeline pass for Kubernetes manifest and Kustomize overlay processing.
 *
 * For each discovered YAML file:
 *   1. Check if it is a kustomize overlay (kustomization.yaml / kustomization.yml)
 *      → emit a Module node and IMPORTS edges for each resources/bases/patches entry
 *   2. Else if it is a generic k8s manifest (apiVersion: detected)
 *      → emit one Resource node per file (first document only — multi-document YAML is not yet
 * supported)
 *
 * Depends on: pass_infrascan.c (cbm_is_kustomize_file, cbm_is_k8s_manifest, cbm_infra_qn),
 *             extraction layer (cbm.h), graph_buffer, pipeline internals.
 */
#include "foundation/constants.h"
#include "pipeline/pipeline.h"
#include <stdint.h>
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "discover/discover.h"
#include "foundation/log.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/limits.h"
#include "cbm.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Internal helpers ────────────────────────────────────────────── */

/* Read entire file into heap-allocated buffer. Returns NULL on error.
 * Caller must free(). Sets *out_len to byte count. */
static char *k8s_read_file(const char *path, int *out_len) {
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

/* Format int to string for logging. Thread-safe via TLS. */
static const char *itoa_k8s(int val) {
    enum { RING_BUF_COUNT = 4, RING_BUF_MASK = 3 };
    static CBM_TLS char bufs[RING_BUF_COUNT][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & RING_BUF_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* Extract the basename of a path (pointer into the string; no allocation). */
static const char *k8s_basename(const char *path) {
    const char *p = strrchr(path, '/');
    return p ? p + SKIP_ONE : path;
}

/* ── Kustomize handler ───────────────────────────────────────────── */

static void handle_kustomize(cbm_pipeline_ctx_t *ctx, const char *path, const char *rel_path,
                             CBMFileResult *result) {
    /* Emit Module node for this kustomize overlay file */
    char *mod_qn = cbm_infra_qn(ctx->project_name, rel_path, "kustomize", NULL);
    if (!mod_qn) {
        return;
    }

    cbm_node_id_t mod_id =
        cbm_gbuf_upsert_node(ctx->gbuf, "Module", k8s_basename(rel_path), mod_qn, rel_path,
                             SKIP_ONE, 0, "{\"source\":\"kustomize\"}");
    free(mod_qn);

    if (!cbm_node_id_valid(mod_id)) {
        return;
    }

    /* If we have a cached extraction result, emit IMPORTS edges for
     * resources/bases/patches/components entries */
    int import_count = 0;
    CBMFileResult *res = result;
    bool allocated = false;

    if (!res) {
        /* Fall back to re-extraction */
        int src_len = 0;
        char *source = k8s_read_file(path, &src_len);
        if (source) {
            res = cbm_extract_file(source, src_len, CBM_LANG_KUSTOMIZE, ctx->project_name, rel_path,
                                   CBM_EXTRACT_BUDGET, NULL, NULL);
            free(source);
            allocated = true;
        }
    }

    if (res) {
        for (int j = 0; j < res->imports.count; j++) {
            CBMImport *imp = &res->imports.items[j];
            if (!imp->module_path) {
                continue;
            }

            /* Compute target file QN */
            char *target_qn =
                cbm_pipeline_fqn_compute(ctx->project_name, imp->module_path, "__file__");
            if (!target_qn) {
                continue;
            }

            const cbm_gbuf_node_t *target = cbm_gbuf_find_by_qn(ctx->gbuf, target_qn);
            free(target_qn);

            if (target) {
                const cbm_gbuf_prop_t kustomize_props[] = {
                    {.key = "via", .kind = CBM_EDGE_PROP_STRING, .text = "kustomize"},
                };
                cbm_gbuf_insert_edge_props(
                    ctx->gbuf, (cbm_edge_endpoints_t){.source = mod_id, .target = target->id},
                    "IMPORTS", kustomize_props,
                    (int)(sizeof(kustomize_props) / sizeof(kustomize_props[0])));
                import_count++;
            }
        }

        if (allocated) {
            cbm_free_result(res);
        }
    }

    cbm_log_info("pass.k8s.kustomize", "file", rel_path, "imports", itoa_k8s(import_count));
}

/* ── K8s cross-manifest label-selector matching ──────────────────────
 * A Service routes traffic to the workload Pods whose labels match the
 * Service's spec.selector.  We record, per manifest, the Resource node id plus
 * its selector label-values (Services) and pod label-values (workloads), then
 * after all manifests are processed connect each Service to the workload(s) it
 * targets via an INFRA_MAPS edge.  This models the runtime traffic path the same
 * way k8s itself resolves Service → Endpoints by label.
 *
 * Matching is by label *value*: a Service selector `app: frontend` matches a
 * workload that either carries the pod label value "frontend" OR is named
 * "frontend" (the ubiquitous app==name convention, used when the pod template
 * omits explicit labels). */
enum { K8S_MAX_LABELS = 16, K8S_MAX_RECORDS = 512, K8S_LABEL_LEN = 128 };

typedef struct {
    cbm_node_id_t node_id;
    char name[K8S_LABEL_LEN];
    bool is_service;
    bool is_workload;
    char selector_vals[K8S_MAX_LABELS][K8S_LABEL_LEN]; /* Service spec.selector values */
    int n_selector;
    char label_vals[K8S_MAX_LABELS][K8S_LABEL_LEN]; /* workload pod-template label values */
    int n_label;
} k8s_record_t;

typedef struct {
    k8s_record_t *items;
    int count;
    int cap;
} k8s_record_array_t;

typedef struct {
    int kustomize;
    int manifest;
    int helm;
} k8s_pass_counts_t;

enum {
    K8S_PATH_DEPTH = 12,
    K8S_PATH_KEY_LEN = 64,
    K8S_LINE_TERMINATOR_RESERVE = 1,
    K8S_YAML_DOCUMENT_SEPARATOR_LEN = 3,
    K8S_PATH_PARENT_DEPTH = 1,
};

typedef struct {
    int indent;
    char key[K8S_PATH_KEY_LEN];
} k8s_path_entry_t;

/* Count leading-space indentation of a line (tabs are invalid YAML indent). */
static int k8s_indent(const char *line) {
    int n = 0;
    while (line[n] == ' ') {
        n++;
    }
    return n;
}

/* Split `key: value` (already de-indented). Returns 1 if a key was found; fills
 * key/val (val empty when the key opens a nested block). */
static int k8s_split_kv(const char *t, char *key, size_t key_sz, char *val, size_t val_sz) {
    enum {
        K8S_VALUE_TERMINATOR_RESERVE = 1,
        K8S_QUOTED_VALUE_DELIMITERS = 2,
        K8S_PARSE_KEY_VALUE_FOUND = 1,
    };
    key[0] = '\0';
    val[0] = '\0';
    if (t[0] == '#' || t[0] == '-' || t[0] == '\0') {
        return 0;
    }
    const char *colon = strchr(t, ':');
    if (!colon) {
        return 0;
    }
    size_t klen = (size_t)(colon - t);
    if (klen == 0 || klen >= key_sz) {
        return 0;
    }
    memcpy(key, t, klen);
    key[klen] = '\0';
    const char *v = colon + SKIP_ONE;
    while (*v == ' ' || *v == '\t') {
        v++;
    }
    size_t vn = 0;
    while (v[vn] && v[vn] != '\r' && v[vn] != '\n' && v[vn] != '#' &&
           vn + K8S_VALUE_TERMINATOR_RESERVE < val_sz) {
        val[vn] = v[vn];
        vn++;
    }
    /* trim trailing space */
    while (vn > 0 && (val[vn - K8S_VALUE_TERMINATOR_RESERVE] == ' ' ||
                      val[vn - K8S_VALUE_TERMINATOR_RESERVE] == '\t')) {
        vn--;
    }
    val[vn] = '\0';
    /* strip surrounding quotes */
    if (vn >= K8S_QUOTED_VALUE_DELIMITERS && (val[0] == '"' || val[0] == '\'') &&
        val[vn - K8S_VALUE_TERMINATOR_RESERVE] == val[0]) {
        memmove(val, val + SKIP_ONE, vn - K8S_QUOTED_VALUE_DELIMITERS);
        val[vn - K8S_QUOTED_VALUE_DELIMITERS] = '\0';
    }
    return K8S_PARSE_KEY_VALUE_FOUND;
}

static void k8s_add_val(char dst[][K8S_LABEL_LEN], int *n, const char *v) {
    if (*n >= K8S_MAX_LABELS || !v || !v[0]) {
        return;
    }
    snprintf(dst[*n], K8S_LABEL_LEN, "%s", v);
    (*n)++;
}

static bool k8s_next_line(const char **cursor, char *line, size_t line_size) {
    if (!*cursor || !**cursor || line_size <= K8S_LINE_TERMINATOR_RESERVE) {
        return false;
    }
    const char *start = *cursor;
    const char *eol = strchr(start, '\n');
    size_t length = eol ? (size_t)(eol - start) : strlen(start);
    size_t copied = length < line_size - K8S_LINE_TERMINATOR_RESERVE
                        ? length
                        : line_size - K8S_LINE_TERMINATOR_RESERVE;
    memcpy(line, start, copied);
    line[copied] = '\0';
    *cursor = eol ? eol + SKIP_ONE : NULL;
    return true;
}

static const char *k8s_trim_indent(const char *line) {
    while (*line == ' ') {
        line++;
    }
    return line;
}

static const char *k8s_trim_whitespace(const char *line) {
    while (*line == ' ' || *line == '\t') {
        line++;
    }
    return line;
}

static bool k8s_is_document_separator(const char *line, const char *trimmed) {
    return line == trimmed && strncmp(trimmed, "---", K8S_YAML_DOCUMENT_SEPARATOR_LEN) == 0;
}

static void k8s_pop_path(k8s_path_entry_t *stack, int *depth, int indent) {
    while (*depth > 0 && stack[*depth - SKIP_ONE].indent >= indent) {
        (*depth)--;
    }
}

static bool k8s_under_path(const k8s_path_entry_t *stack, int depth, const char *key) {
    return depth >= K8S_PATH_PARENT_DEPTH && strcmp(stack[depth - SKIP_ONE].key, key) == 0;
}

static void k8s_push_path(k8s_path_entry_t *stack, int *depth, int indent, const char *key) {
    if (*depth >= K8S_PATH_DEPTH) {
        return;
    }
    stack[*depth].indent = indent;
    snprintf(stack[*depth].key, sizeof(stack[*depth].key), "%s", key);
    (*depth)++;
}

static void k8s_set_resource_kind(k8s_record_t *rec, const char *value) {
    rec->is_service = strcmp(value, "Service") == 0;
    rec->is_workload = strcmp(value, "Deployment") == 0 || strcmp(value, "StatefulSet") == 0 ||
                       strcmp(value, "DaemonSet") == 0 || strcmp(value, "ReplicaSet") == 0 ||
                       strcmp(value, "ReplicationController") == 0 || strcmp(value, "Pod") == 0 ||
                       strcmp(value, "Job") == 0 || strcmp(value, "CronJob") == 0;
}

static void k8s_scan_leaf(k8s_record_t *rec, const char *key, const char *value,
                          bool under_metadata, bool under_selector, bool under_labels,
                          bool *got_name, int indent) {
    if (indent == 0 && strcmp(key, "kind") == 0) {
        k8s_set_resource_kind(rec, value);
        return;
    }
    if (!*got_name && under_metadata && strcmp(key, "name") == 0) {
        snprintf(rec->name, sizeof(rec->name), "%s", value);
        *got_name = true;
        return;
    }
    if (under_selector) {
        k8s_add_val(rec->selector_vals, &rec->n_selector, value);
        return;
    }
    if (under_labels) {
        k8s_add_val(rec->label_vals, &rec->n_label, value);
    }
}

static void k8s_scan_label_line(const char *line, const char *trimmed, k8s_path_entry_t *stack,
                                int *depth, k8s_record_t *rec, bool *got_name) {
    if (!trimmed[0] || trimmed[0] == '#') {
        return;
    }
    int indent = k8s_indent(line);
    k8s_pop_path(stack, depth, indent);
    char key[K8S_PATH_KEY_LEN];
    char value[K8S_LABEL_LEN];
    if (!k8s_split_kv(trimmed, key, sizeof(key), value, sizeof(value))) {
        return;
    }
    if (!value[0]) {
        k8s_push_path(stack, depth, indent, key);
        return;
    }
    bool under_selector = k8s_under_path(stack, *depth, "selector");
    bool under_labels = k8s_under_path(stack, *depth, "labels");
    bool under_metadata = k8s_under_path(stack, *depth, "metadata");
    k8s_scan_leaf(rec, key, value, under_metadata, under_selector, under_labels, got_name, indent);
}

/* Scan a single-document k8s manifest's text for the resource name, selector
 * label-values (Service) and pod-template label-values (workload).  A small
 * indentation path-stack distinguishes spec.selector from
 * spec.template.metadata.labels and from top-level metadata.name. */
static void k8s_scan_labels(const char *source, k8s_record_t *rec) {
    k8s_path_entry_t stack[K8S_PATH_DEPTH];
    int depth = 0;
    bool got_name = false;
    const char *cursor = source;
    char line[CBM_SZ_512];
    while (k8s_next_line(&cursor, line, sizeof(line))) {
        const char *trimmed = k8s_trim_indent(line);
        if (k8s_is_document_separator(line, trimmed)) {
            break;
        }
        k8s_scan_label_line(line, trimmed, stack, &depth, rec, &got_name);
    }
}

/* True if any of the service's selector values matches the workload. */
static bool k8s_selector_matches(const k8s_record_t *svc, const k8s_record_t *wl) {
    for (int s = 0; s < svc->n_selector; s++) {
        const char *sv = svc->selector_vals[s];
        if (!sv[0]) {
            continue;
        }
        if (wl->name[0] && strcmp(sv, wl->name) == 0) {
            return true;
        }
        for (int l = 0; l < wl->n_label; l++) {
            if (strcmp(sv, wl->label_vals[l]) == 0) {
                return true;
            }
        }
    }
    return false;
}

/* After all manifests are recorded, connect each Service to the workload(s) its
 * selector targets via an INFRA_MAPS edge (Service Resource → workload Resource). */
static void k8s_link_selectors(cbm_pipeline_ctx_t *ctx, const k8s_record_array_t *recs) {
    int edges = 0;
    for (int i = 0; i < recs->count; i++) {
        const k8s_record_t *svc = &recs->items[i];
        if (!svc->is_service || svc->n_selector == 0 || !cbm_node_id_valid(svc->node_id)) {
            continue;
        }
        for (int j = 0; j < recs->count; j++) {
            const k8s_record_t *wl = &recs->items[j];
            if (i == j || !wl->is_workload || !cbm_node_id_valid(wl->node_id)) {
                continue;
            }
            if (k8s_selector_matches(svc, wl)) {
                const cbm_gbuf_prop_t selector_props[] = {
                    {.key = "kind", .kind = CBM_EDGE_PROP_STRING, .text = "selector"},
                    {.key = "service", .kind = CBM_EDGE_PROP_STRING, .text = svc->name},
                    {.key = "workload", .kind = CBM_EDGE_PROP_STRING, .text = wl->name},
                };
                cbm_gbuf_insert_edge_props(
                    ctx->gbuf,
                    (cbm_edge_endpoints_t){.source = svc->node_id, .target = wl->node_id},
                    "INFRA_MAPS", selector_props,
                    (int)(sizeof(selector_props) / sizeof(selector_props[0])));
                edges++;
            }
        }
    }
    if (edges > 0) {
        cbm_log_info("pass.k8s.selectors", "linked", itoa_k8s(edges));
    }
}

/* ── K8s manifest handler ────────────────────────────────────────── */

/* source/src_len are the already-read file bytes (caller retains ownership and
 * must free after this call returns).  When `rec` is non-NULL it is populated
 * with the first Resource's node id, name and label/selector values for later
 * cross-manifest selector matching. */
static void handle_k8s_manifest(cbm_pipeline_ctx_t *ctx, const char *path, const char *rel_path,
                                const char *source, int src_len, k8s_record_t *rec) {
    (void)path; /* retained for symmetry; source is always provided now */
    int resource_count = 0;

    CBMFileResult *res = cbm_extract_file(source, src_len, CBM_LANG_K8S, ctx->project_name,
                                          rel_path, CBM_EXTRACT_BUDGET, NULL, NULL);
    if (!res) {
        return;
    }

    /* Compute file node QN for DEFINES edges */
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel_path, "__file__");
    const cbm_gbuf_node_t *file_node = file_qn ? cbm_gbuf_find_by_qn(ctx->gbuf, file_qn) : NULL;
    free(file_qn);

    for (int d = 0; d < res->defs.count; d++) {
        CBMDefinition *def = &res->defs.items[d];
        if (!def->label || strcmp(def->label, "Resource") != 0) {
            continue;
        }
        if (!def->name || !def->qualified_name) {
            continue;
        }

        cbm_node_id_t node_id =
            cbm_gbuf_upsert_node(ctx->gbuf, "Resource", def->name, def->qualified_name, rel_path,
                                 (int)def->start_line, (int)def->end_line, "{\"source\":\"k8s\"}");

        /* DEFINES edge: File → Resource */
        if (file_node && cbm_node_id_valid(node_id)) {
            cbm_gbuf_insert_edge_props(
                ctx->gbuf, (cbm_edge_endpoints_t){.source = file_node->id, .target = node_id},
                "DEFINES", NULL, 0);
        }

        /* Capture the first Resource for cross-manifest selector matching. */
        if (rec && !cbm_node_id_valid(rec->node_id) && cbm_node_id_valid(node_id)) {
            rec->node_id = node_id;
        }

        resource_count++;
    }

    cbm_free_result(res);

    /* Record selector / pod-label values for later Service → workload linking. */
    if (rec && cbm_node_id_valid(rec->node_id)) {
        k8s_scan_labels(source, rec);
    }

    cbm_log_info("pass.k8s.manifest", "file", rel_path, "resources", itoa_k8s(resource_count));
}

/* ── Helm chart handler ──────────────────────────────────────────── */

static bool is_helm_chart_file(const char *base) {
    return strcmp(base, "Chart.yaml") == 0 || strcmp(base, "Chart.yml") == 0;
}

/* Emit a Chart node for a Chart.yaml and a DEPENDS_ON edge to a (shared,
 * deduplicated) Chart node per declared dependency (#338). */
static void handle_helm_chart(cbm_pipeline_ctx_t *ctx, const char *rel_path, const char *source) {
    cbm_helm_chart_t hc;
    if (cbm_parse_helm_chart(source, &hc) != 0) {
        return;
    }

    const char *cname = hc.chart_name[0] ? hc.chart_name : k8s_basename(rel_path);
    char *chart_qn = cbm_infra_qn(ctx->project_name, rel_path, "helm-chart", NULL);
    if (!chart_qn) {
        return;
    }
    cbm_node_id_t chart_id = cbm_gbuf_upsert_node(ctx->gbuf, "Chart", cname, chart_qn, rel_path,
                                                  SKIP_ONE, 0, "{\"source\":\"helm\"}");
    free(chart_qn);

    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel_path, "__file__");
    const cbm_gbuf_node_t *file_node = file_qn ? cbm_gbuf_find_by_qn(ctx->gbuf, file_qn) : NULL;
    if (file_node && cbm_node_id_valid(chart_id)) {
        cbm_gbuf_insert_edge_props(
            ctx->gbuf, (cbm_edge_endpoints_t){.source = file_node->id, .target = chart_id},
            "DEFINES", NULL, 0);
    }
    free(file_qn);

    int dep_edges = 0;
    for (int i = 0; i < hc.dep_count && cbm_node_id_valid(chart_id); i++) {
        /* Stable per-project QN so multiple charts depending on the same chart
         * link to one shared dependency node. */
        char dep_qn[CBM_SZ_512];
        snprintf(dep_qn, sizeof(dep_qn), "%s.__helm_dep__.%s", ctx->project_name, hc.deps[i]);
        cbm_node_id_t dep_id =
            cbm_gbuf_upsert_node(ctx->gbuf, "Chart", hc.deps[i], dep_qn, rel_path, SKIP_ONE, 0,
                                 "{\"source\":\"helm\",\"external\":true}");
        if (cbm_node_id_valid(dep_id)) {
            cbm_gbuf_insert_edge_props(ctx->gbuf,
                                       (cbm_edge_endpoints_t){.source = chart_id, .target = dep_id},
                                       "DEPENDS_ON", NULL, 0);
            dep_edges++;
        }
    }
    cbm_log_info("pass.k8s.helm", "file", rel_path, "deps", itoa_k8s(dep_edges));
}

/* ── Dependency-manifest handler (go.mod / requirements.txt) ──────── */

static bool is_gomod_file(const char *base) {
    return strcmp(base, "go.mod") == 0;
}

static bool is_requirements_file(const char *base) {
    return strcmp(base, "requirements.txt") == 0;
}

/* Emit a DEPENDS_ON edge from the manifest file node to a (shared, per-project)
 * external Package node.  Mirrors the Helm Chart.yaml DEPENDS_ON shape. */
static int emit_dep_edge(cbm_pipeline_ctx_t *ctx, const cbm_gbuf_node_t *src, const char *rel_path,
                         const char *ecosystem, const char *name) {
    enum { K8S_DEPENDENCY_EDGE_CREATED = 1 };
    if (!name || !name[0]) {
        return 0;
    }
    char dep_qn[CBM_SZ_512];
    snprintf(dep_qn, sizeof(dep_qn), "%s.__%s_dep__.%s", ctx->project_name, ecosystem, name);
    char dep_props[CBM_SZ_256];
    snprintf(dep_props, sizeof(dep_props), "{\"source\":\"%s\",\"external\":true}", ecosystem);
    cbm_node_id_t dep_id =
        cbm_gbuf_upsert_node(ctx->gbuf, "Package", name, dep_qn, rel_path, SKIP_ONE, 0, dep_props);
    if (cbm_node_id_valid(dep_id) && !cbm_node_id_eq(dep_id, src->id)) {
        cbm_gbuf_insert_edge_props(ctx->gbuf,
                                   (cbm_edge_endpoints_t){.source = src->id, .target = dep_id},
                                   "DEPENDS_ON", NULL, 0);
        return K8S_DEPENDENCY_EDGE_CREATED;
    }
    return 0;
}

/* Copy the first whitespace-delimited token of `line` into `out`. */
static void first_token(const char *line, char *out, size_t out_sz) {
    enum { K8S_TOKEN_TERMINATOR_RESERVE = 1 };
    out[0] = '\0';
    while (*line == ' ' || *line == '\t') {
        line++;
    }
    size_t n = 0;
    while (line[n] && line[n] != ' ' && line[n] != '\t' && line[n] != '\r' && line[n] != '\n' &&
           n + K8S_TOKEN_TERMINATOR_RESERVE < out_sz) {
        out[n] = line[n];
        n++;
    }
    out[n] = '\0';
}

static const char *k8s_gomod_require_payload(const char *line) {
    enum { K8S_GOMOD_REQUIRE_KEYWORD_LEN = 7 };
    if (strncmp(line, "require", K8S_GOMOD_REQUIRE_KEYWORD_LEN) != 0) {
        return NULL;
    }
    char delimiter = line[K8S_GOMOD_REQUIRE_KEYWORD_LEN];
    if (delimiter != ' ' && delimiter != '\t' && delimiter != '(') {
        return NULL;
    }
    const char *payload = line + K8S_GOMOD_REQUIRE_KEYWORD_LEN;
    return k8s_trim_whitespace(payload);
}

static int k8s_emit_gomod_dependency(cbm_pipeline_ctx_t *ctx, const cbm_gbuf_node_t *src,
                                     const char *rel_path, const char *line) {
    char name[CBM_SZ_256];
    first_token(line, name, sizeof(name));
    return emit_dep_edge(ctx, src, rel_path, "gomod", name);
}

static int k8s_parse_gomod_line(cbm_pipeline_ctx_t *ctx, const cbm_gbuf_node_t *src,
                                const char *rel_path, const char *line, bool *in_block) {
    const char *trimmed = k8s_trim_whitespace(line);
    if (*in_block) {
        if (trimmed[0] == ')') {
            *in_block = false;
            return 0;
        }
        return trimmed[0] && trimmed[0] != '/'
                   ? k8s_emit_gomod_dependency(ctx, src, rel_path, trimmed)
                   : 0;
    }
    const char *payload = k8s_gomod_require_payload(trimmed);
    if (!payload) {
        return 0;
    }
    if (*payload == '(') {
        *in_block = true;
        return 0;
    }
    return *payload ? k8s_emit_gomod_dependency(ctx, src, rel_path, payload) : 0;
}

/* Parse go.mod `require` directives (single-line and block forms) and emit a
 * DEPENDS_ON edge per dependency.  go.mod requires are not surfaced as imports
 * by the extraction layer, so we parse the manifest text directly here. */
static int parse_gomod_deps(cbm_pipeline_ctx_t *ctx, const cbm_gbuf_node_t *src,
                            const char *rel_path, const char *source) {
    int edges = 0;
    bool in_block = false;
    const char *cursor = source;
    char line[CBM_SZ_512];
    while (k8s_next_line(&cursor, line, sizeof(line))) {
        edges += k8s_parse_gomod_line(ctx, src, rel_path, line, &in_block);
    }
    return edges;
}

/* Parse requirements.txt entries (one package spec per line) and emit a
 * DEPENDS_ON edge per dependency.  The package name is the leading token up to
 * the first version/extras/comment delimiter. */
static int parse_requirements_deps(cbm_pipeline_ctx_t *ctx, const cbm_gbuf_node_t *src,
                                   const char *rel_path, const char *source) {
    int edges = 0;
    const char *p = source;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[CBM_SZ_512];
        size_t cp = len < sizeof(line) - K8S_LINE_TERMINATOR_RESERVE
                        ? len
                        : sizeof(line) - K8S_LINE_TERMINATOR_RESERVE;
        memcpy(line, p, cp);
        line[cp] = '\0';
        const char *t = line;
        while (*t == ' ' || *t == '\t') {
            t++;
        }
        /* Skip blanks, comments, options (-r, --hash), and URLs. */
        if (t[0] && t[0] != '#' && t[0] != '-' && strstr(t, "://") == NULL) {
            char name[CBM_SZ_256];
            size_t n = 0;
            while (t[n] && t[n] != '=' && t[n] != '<' && t[n] != '>' && t[n] != '!' &&
                   t[n] != '~' && t[n] != '[' && t[n] != ';' && t[n] != ' ' && t[n] != '\t' &&
                   t[n] != '\r' && n + K8S_LINE_TERMINATOR_RESERVE < sizeof(name)) {
                name[n] = t[n];
                n++;
            }
            name[n] = '\0';
            edges += emit_dep_edge(ctx, src, rel_path, "pypi", name);
        }
        if (!eol) {
            break;
        }
        p = eol + SKIP_ONE;
    }
    return edges;
}

static void handle_dep_manifest(cbm_pipeline_ctx_t *ctx, const char *rel_path, const char *source,
                                const char *ecosystem) {
    if (!source) {
        return;
    }
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel_path, "__file__");
    const cbm_gbuf_node_t *src = file_qn ? cbm_gbuf_find_by_qn(ctx->gbuf, file_qn) : NULL;
    free(file_qn);
    if (!src) {
        return;
    }
    int dep_edges = strcmp(ecosystem, "gomod") == 0
                        ? parse_gomod_deps(ctx, src, rel_path, source)
                        : parse_requirements_deps(ctx, src, rel_path, source);
    cbm_log_info("pass.k8s.depmanifest", "file", rel_path, "deps", itoa_k8s(dep_edges));
}

/* ── Pass entry point ────────────────────────────────────────────── */

static k8s_record_t *k8s_next_record(k8s_record_array_t *records) {
    return records->count < records->cap ? &records->items[records->count] : NULL;
}

static CBMFileResult *k8s_cached_result(cbm_pipeline_ctx_t *ctx, int index) {
    return ctx->result_cache ? ctx->result_cache[index] : NULL;
}

static void k8s_process_dependency_file(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *file,
                                        const char *base) {
    int source_length = 0;
    char *source = k8s_read_file(file->path, &source_length);
    if (!source) {
        return;
    }
    const char *ecosystem = is_requirements_file(base) ? "pypi" : "gomod";
    handle_dep_manifest(ctx, file->rel_path, source, ecosystem);
    free(source);
}

static void k8s_process_yaml_file(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *file,
                                  const char *base, k8s_record_array_t *records,
                                  k8s_pass_counts_t *counts) {
    int source_length = 0;
    char *source = k8s_read_file(file->path, &source_length);
    if (!source) {
        return;
    }
    if (is_helm_chart_file(base)) {
        handle_helm_chart(ctx, file->rel_path, source);
        counts->helm++;
    } else if (cbm_is_k8s_manifest(base, source)) {
        k8s_record_t *record = k8s_next_record(records);
        handle_k8s_manifest(ctx, file->path, file->rel_path, source, source_length, record);
        if (record && cbm_node_id_valid(record->node_id)) {
            records->count++;
        }
        counts->manifest++;
    }
    free(source);
}

static void k8s_process_file(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *file, int index,
                             k8s_record_array_t *records, k8s_pass_counts_t *counts) {
    const char *base = k8s_basename(file->rel_path);
    if (is_gomod_file(base) || file->language == CBM_LANG_GOMOD || is_requirements_file(base)) {
        k8s_process_dependency_file(ctx, file, base);
        return;
    }
    if (cbm_is_kustomize_file(base)) {
        handle_kustomize(ctx, file->path, file->rel_path, k8s_cached_result(ctx, index));
        counts->kustomize++;
        return;
    }
    if (file->language == CBM_LANG_YAML || file->language == CBM_LANG_K8S) {
        k8s_process_yaml_file(ctx, file, base, records, counts);
    }
}

int cbm_pipeline_pass_k8s(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count) {
    cbm_log_info("pass.start", "pass", "k8s", "files", itoa_k8s(file_count));

    cbm_init();
    k8s_record_array_t recs = {0};
    recs.items = calloc(K8S_MAX_RECORDS, sizeof(*recs.items));
    recs.cap = recs.items ? K8S_MAX_RECORDS : 0;
    k8s_pass_counts_t counts = {0};

    for (int i = 0; i < file_count; i++) {
        if (cbm_pipeline_check_cancel(ctx)) {
            free(recs.items);
            return CBM_NOT_FOUND;
        }
        k8s_process_file(ctx, &files[i], i, &recs, &counts);
    }

    /* Connect Services to the workloads their selectors target (INFRA_MAPS). */
    k8s_link_selectors(ctx, &recs);
    free(recs.items);

    cbm_log_info("pass.done", "pass", "k8s", "kustomize", itoa_k8s(counts.kustomize), "manifests",
                 itoa_k8s(counts.manifest));
    (void)counts.helm;
    return 0;
}
