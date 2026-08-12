/*
 * pass_githistory.c — Analyze git log to find change coupling.
 *
 * Runs `git log --name-only --since=6 months ago` and computes
 * file pairs that change together frequently. Creates FILE_CHANGES_WITH
 * edges between File nodes with coupling_score properties.
 *
 * Skips commits with >20 files (refactoring/merge noise).
 * Requires minimum 3 co-changes for an edge.
 *
 * Depends on: pass_structure having created File nodes
 */
#include "foundation/constants.h"

enum {
    GH_RING = 4,
    GH_RING_MASK = 3,
    GH_INIT_CAP = 16,
    GH_MIN_COMMITS = 3,
    GH_MAX_FILES = 20,
    GITHISTORY_DECIMAL_BASE = 10,
};
/* Serialized decimal precision for a FILE_CHANGES_WITH edge's "coupling_score" prop. */
enum { GH_COUPLING_SCORE_DECIMALS = 2 };

#define SLEN(s) (sizeof(s) - 1)
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/hash_table.h"
#include "foundation/log.h"
#include "foundation/platform.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/str_util.h"

/* Minimum coupling score to create an edge */
#define MIN_COUPLING_SCORE 0.3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *itoa_log(int val) {
    static CBM_TLS char bufs[GH_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & GH_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

static bool ends_with(const char *s, size_t slen, const char *suffix) {
    size_t sflen = strlen(suffix);
    return slen >= sflen && strcmp(s + slen - sflen, suffix) == 0;
}

bool cbm_is_trackable_file(const char *path) {
    if (!path) {
        return false;
    }
    /* Skip directory prefixes */
#define LEN_NODE_MODULES_SLASH 13 /* strlen("node_modules/") */
    if (strncmp(path, ".git/", SLEN(".git/")) == 0 ||
        strncmp(path, "node_modules/", LEN_NODE_MODULES_SLASH) == 0 ||
        strncmp(path, "vendor/", SLEN("vendor/")) == 0 ||
        strncmp(path, "__pycache__/", SLEN("__pycache__/")) == 0 ||
        strncmp(path, ".cache/", SLEN(".cache/")) == 0) {
        return false;
    }
    /* Skip lock/generated file names */
    const char *base = strrchr(path, '/');
    base = base ? base + SKIP_ONE : path;
    if (strcmp(base, "package-lock.json") == 0 || strcmp(base, "yarn.lock") == 0 ||
        strcmp(base, "pnpm-lock.yaml") == 0 || strcmp(base, "Cargo.lock") == 0 ||
        strcmp(base, "poetry.lock") == 0 || strcmp(base, "composer.lock") == 0 ||
        strcmp(base, "Gemfile.lock") == 0 || strcmp(base, "Pipfile.lock") == 0) {
        return false;
    }
    /* Skip non-source file extensions */
    size_t len = strlen(path);
    if (ends_with(path, len, ".lock") || ends_with(path, len, ".sum") ||
        ends_with(path, len, ".min.js") || ends_with(path, len, ".min.css") ||
        ends_with(path, len, ".map") || ends_with(path, len, ".wasm") ||
        ends_with(path, len, ".png") || ends_with(path, len, ".jpg") ||
        ends_with(path, len, ".gif") || ends_with(path, len, ".ico") ||
        ends_with(path, len, ".svg")) {
        return false;
    }
    return true;
}

/* ── Commit parsing ───────────────────────────────────────────────── */

typedef struct {
    char **files;
    size_t count;
    size_t cap;
    long long timestamp; /* unix epoch of this commit; 0 when unknown */
} commit_t;

static void commit_add_file(commit_t *c, const char *file) {
    if (c->count >= c->cap) {
        c->cap = c->cap ? c->cap * PAIR_LEN : GH_INIT_CAP;
        c->files = cbm_realloc_or_abort(c->files, c->cap * sizeof(char *));
    }
    c->files[c->count++] = strdup(file);
}

static void commit_free(commit_t *c) {
    for (size_t i = 0; i < c->count; i++) {
        free(c->files[i]);
    }
    free(c->files);
}

typedef struct {
    commit_t *commits;
    size_t count;
    size_t cap;
    commit_t current;
} git_log_parser_t;

static void git_log_trim_line(char *line) {
    size_t length = strlen(line);
    while (length > 0 && (line[length - SKIP_ONE] == '\n' || line[length - SKIP_ONE] == '\r')) {
        line[--length] = '\0';
    }
}

static void git_log_append_current(git_log_parser_t *parser) {
    if (parser->current.count == 0) {
        return;
    }
    if (parser->count >= parser->cap) {
        parser->cap *= PAIR_LEN;
        parser->commits = cbm_realloc_or_abort(parser->commits, parser->cap * sizeof(commit_t));
    }
    parser->commits[parser->count++] = parser->current;
    memset(&parser->current, 0, sizeof(parser->current));
}

static void git_log_start_commit(git_log_parser_t *parser, const char *line) {
    git_log_append_current(parser);
    const char *hash_end = strchr(line + SLEN("COMMIT:"), ':');
    if (hash_end) {
        parser->current.timestamp = strtoll(hash_end + SKIP_ONE, NULL, GITHISTORY_DECIMAL_BASE);
    }
}

static void git_log_process_line(git_log_parser_t *parser, char *line) {
    git_log_trim_line(line);
    if (line[0] == '\0') {
        return;
    }
    if (strncmp(line, "COMMIT:", SLEN("COMMIT:")) == 0) {
        git_log_start_commit(parser, line);
        return;
    }
    if (cbm_is_trackable_file(line)) {
        commit_add_file(&parser->current, line);
    }
}

static void git_log_parser_finish(git_log_parser_t *parser) {
    git_log_append_current(parser);
}

/* ── git log parsing (popen "git log") ────────────────────────────── */

static int parse_git_log(const char *repo_path, commit_t **out, int *out_count) {
    *out = NULL;
    *out_count = 0;

    if (!cbm_validate_shell_path_arg(repo_path)) {
        return CBM_NOT_FOUND;
    }

    char cmd[CBM_SZ_1K];
#ifdef _WIN32
    /* cmd.exe does not recognize single quotes, and '/dev/null' is a POSIX path. */
    const char *null_dev = "NUL";
#else
    const char *null_dev = "/dev/null";
#endif
    /* git -C "<path>" works on both cmd.exe and POSIX shells. Double quotes are
     * safe here because cbm_validate_shell_arg (above) rejects ", $, `, \ and the
     * other shell metacharacters that would otherwise be active inside them. */
    snprintf(cmd, sizeof(cmd),
             "git -C \"%s\" log --name-only --pretty=format:COMMIT:%%H:%%ct "
             "--since=\"1 year ago\" --max-count=10000 2>%s",
             repo_path, null_dev);

    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
        return CBM_NOT_FOUND;
    }

    git_log_parser_t parser = {
        .commits = malloc(CBM_SZ_64 * sizeof(commit_t)),
        .count = 0,
        .cap = CBM_SZ_64,
        .current = {0},
    };

    char line[CBM_SZ_1K];
    while (fgets(line, sizeof(line), fp)) {
        git_log_process_line(&parser, line);
    }
    git_log_parser_finish(&parser);

    cbm_pclose(fp);
    *out = parser.commits;
    /* git log is capped at --max-count=10000 above, so count always fits the
     * int out_count contract (matched by cbm_compute_change_coupling's int
     * commit_count parameter, fixed by its header signature). */
    *out_count = (int)parser.count;
    return 0;
}

/* Callback to free hash table entries. */
static void free_counter(const char *key, void *val, void *ud) {
    (void)ud;
    safe_str_free(&key);
    free(val);
}

/* ── Standalone coupling computation (testable) ──────────────────── */

/* Context for collect_coupling_result callback. */
typedef struct {
    CBMHashTable *file_counts;
    CBMHashTable *pair_timestamps; /* pair_key → long long*: max commit ts */
    cbm_change_coupling_t *out;
    int out_count;
    int max_out;
} collect_coupling_ctx_t;

static void collect_coupling_cb(const char *pair_key, void *val, void *ud) {
    collect_coupling_ctx_t *cctx = ud;
    int co_count = *(int *)val;
    if (co_count < GH_MIN_COMMITS) {
        return;
    }
    if (cctx->out_count >= cctx->max_out) {
        return;
    }

    const char *sep = strchr(pair_key, '\x01');
    if (!sep) {
        return;
    }
    /* sep is a forward strchr() hit within pair_key, so sep >= pair_key always. */
    size_t la = (size_t)(sep - pair_key);
    const char *file_b = sep + SKIP_ONE;

    char file_a_buf[CBM_SZ_512];
    if (la >= sizeof(file_a_buf)) {
        return;
    }
    memcpy(file_a_buf, pair_key, la);
    file_a_buf[la] = '\0';

    int *count_a = cbm_ht_get(cctx->file_counts, file_a_buf);
    int *count_b = cbm_ht_get(cctx->file_counts, file_b);
    if (!count_a || !count_b) {
        return;
    }

    int min_total = *count_a < *count_b ? *count_a : *count_b;
    if (min_total == 0) {
        return;
    }

    double score = (double)co_count / (double)min_total;
    if (score < MIN_COUPLING_SCORE) {
        return;
    }

    cbm_change_coupling_t *cc = &cctx->out[cctx->out_count++];
    snprintf(cc->file_a, sizeof(cc->file_a), "%s", file_a_buf);
    snprintf(cc->file_b, sizeof(cc->file_b), "%s", file_b);
    cc->co_change_count = co_count;
    cc->coupling_score = score;
    long long *ts = cbm_ht_get(cctx->pair_timestamps, pair_key);
    cc->last_co_change = ts ? *ts : 0;
}

typedef struct {
    CBMHashTable *file_counts;
    CBMHashTable *pair_counts;
    CBMHashTable *pair_timestamps;
} coupling_counts_t;

static void coupling_increment_file_count(CBMHashTable *file_counts, const char *file) {
    int *count = cbm_ht_get(file_counts, file);
    if (count) {
        (*count)++;
        return;
    }
    int *new_count = malloc(sizeof(*new_count));
    *new_count = SKIP_ONE;
    cbm_ht_set(file_counts, strdup(file), new_count);
}

static char *coupling_pair_key(const char *first, const char *second, size_t *length_out) {
    const char *file_a = first;
    const char *file_b = second;
    if (strcmp(file_a, file_b) > 0) {
        file_a = second;
        file_b = first;
    }
    size_t length_a = strlen(file_a);
    size_t length_b = strlen(file_b);
    size_t pair_length = length_a + SKIP_ONE + length_b + SKIP_ONE;
    char *pair_key = malloc(pair_length);
    memcpy(pair_key, file_a, length_a);
    pair_key[length_a] = '\x01';
    memcpy(pair_key + length_a + SKIP_ONE, file_b, length_b + SKIP_ONE);
    *length_out = pair_length;
    return pair_key;
}

static void coupling_increment_pair_count(const coupling_counts_t *counts, const char *first,
                                          const char *second, long long timestamp) {
    size_t pair_length = 0;
    char *pair_key = coupling_pair_key(first, second, &pair_length);
    int *count = cbm_ht_get(counts->pair_counts, pair_key);
    if (count) {
        (*count)++;
        long long *last_changed = cbm_ht_get(counts->pair_timestamps, pair_key);
        if (last_changed && timestamp > *last_changed) {
            *last_changed = timestamp;
        }
        free(pair_key);
        return;
    }
    int *new_count = malloc(sizeof(*new_count));
    char *timestamp_key = malloc(pair_length);
    long long *last_changed = malloc(sizeof(*last_changed));
    *new_count = SKIP_ONE;
    *last_changed = timestamp;
    memcpy(timestamp_key, pair_key, pair_length);
    cbm_ht_set(counts->pair_counts, pair_key, new_count);
    cbm_ht_set(counts->pair_timestamps, timestamp_key, last_changed);
}

static void coupling_count_commit_files(const cbm_commit_files_t *commit,
                                        const coupling_counts_t *counts) {
    for (int file_index = 0; file_index < commit->count; file_index++) {
        coupling_increment_file_count(counts->file_counts, commit->files[file_index]);
    }
}

static void coupling_count_commit_pairs(const cbm_commit_files_t *commit,
                                        const coupling_counts_t *counts) {
    for (int first = 0; first < commit->count; first++) {
        for (int second = first + SKIP_ONE; second < commit->count; second++) {
            coupling_increment_pair_count(counts, commit->files[first], commit->files[second],
                                          commit->timestamp);
        }
    }
}

static void coupling_count_commits(const cbm_commit_files_t *commits, int commit_count,
                                   const coupling_counts_t *counts) {
    for (int commit_index = 0; commit_index < commit_count; commit_index++) {
        const cbm_commit_files_t *commit = &commits[commit_index];
        if (commit->count <= GH_MAX_FILES) {
            coupling_count_commit_files(commit, counts);
            coupling_count_commit_pairs(commit, counts);
        }
    }
}

int cbm_compute_change_coupling(const cbm_commit_files_t *commits, int commit_count,
                                cbm_change_coupling_t *out, int max_out) {
    CBMHashTable *file_counts = cbm_ht_create(CBM_SZ_1K);
    CBMHashTable *pair_counts = cbm_ht_create(CBM_SZ_2K);
    /* Parallel table mapping pair_key → max commit timestamp seen for that
     * pair, so the resulting edge can carry last_co_change. The pair_counts
     * table consumes its key on insert; pair_timestamps gets its own copy. */
    CBMHashTable *pair_timestamps = cbm_ht_create(CBM_SZ_2K);

    coupling_counts_t counts = {
        .file_counts = file_counts,
        .pair_counts = pair_counts,
        .pair_timestamps = pair_timestamps,
    };
    coupling_count_commits(commits, commit_count, &counts);

    collect_coupling_ctx_t cctx = {
        .file_counts = file_counts,
        .pair_timestamps = pair_timestamps,
        .out = out,
        .out_count = 0,
        .max_out = max_out,
    };
    cbm_ht_foreach(pair_counts, collect_coupling_cb, &cctx);

    cbm_ht_foreach(pair_counts, free_counter, NULL);
    cbm_ht_free(pair_counts);
    cbm_ht_foreach(pair_timestamps, free_counter, NULL);
    cbm_ht_free(pair_timestamps);
    cbm_ht_foreach(file_counts, free_counter, NULL);
    cbm_ht_free(file_counts);

    return cctx.out_count;
}

/* ── Split pass: compute (I/O-bound) + apply (gbuf writes) ───────── */

/* Pre-computed coupling result buffer for fused post-pass parallelism. */
#define MAX_COUPLINGS 8192
#define MAX_FILE_TEMPORAL 16384

static void githistory_free_commits(commit_t *commits, int commit_count) {
    for (int commit_index = 0; commit_index < commit_count; commit_index++) {
        commit_free(&commits[commit_index]);
    }
    free(commits);
}

static cbm_commit_files_t *githistory_commit_views(const commit_t *commits, int commit_count) {
    cbm_commit_files_t *views = calloc((size_t)commit_count, sizeof(*views));
    if (!views) {
        return NULL;
    }
    for (int commit_index = 0; commit_index < commit_count; commit_index++) {
        views[commit_index].files = commits[commit_index].files;
        views[commit_index].count = (int)commits[commit_index].count;
        views[commit_index].timestamp = commits[commit_index].timestamp;
    }
    return views;
}

static void githistory_update_temporal(cbm_file_temporal_t *files, int *count,
                                       CBMHashTable *indices, const char *file_path,
                                       long long timestamp) {
    int *existing_index = cbm_ht_get(indices, file_path);
    if (existing_index) {
        cbm_file_temporal_t *file = &files[*existing_index];
        file->change_count++;
        if (timestamp > file->last_modified) {
            file->last_modified = timestamp;
        }
        return;
    }
    if (*count >= MAX_FILE_TEMPORAL) {
        return;
    }
    int *new_index = malloc(sizeof(*new_index));
    char *key = new_index ? strdup(file_path) : NULL;
    if (!new_index || !key) {
        free(new_index);
        return;
    }
    cbm_file_temporal_t *file = &files[*count];
    snprintf(file->file_path, sizeof(file->file_path), "%s", file_path);
    file->change_count = SKIP_ONE;
    file->last_modified = timestamp;
    *new_index = *count;
    (*count)++;
    cbm_ht_set(indices, key, new_index);
}

static cbm_file_temporal_t *githistory_compute_file_temporal(const cbm_commit_files_t *commits,
                                                             int commit_count, int *count_out) {
    *count_out = 0;
    cbm_file_temporal_t *files = calloc(MAX_FILE_TEMPORAL, sizeof(*files));
    if (!files) {
        return NULL;
    }
    CBMHashTable *indices = cbm_ht_create(CBM_SZ_1K);
    for (int commit_index = 0; commit_index < commit_count; commit_index++) {
        const cbm_commit_files_t *commit = &commits[commit_index];
        if (commit->count > GH_MAX_FILES) {
            continue;
        }
        for (int file_index = 0; file_index < commit->count; file_index++) {
            githistory_update_temporal(files, count_out, indices, commit->files[file_index],
                                       commit->timestamp);
        }
    }
    cbm_ht_foreach(indices, free_counter, NULL);
    cbm_ht_free(indices);
    return files;
}

/* Compute change couplings without touching the graph buffer.
 * Can run on a separate thread while other passes use the gbuf. */
int cbm_pipeline_githistory_compute(const char *repo_path, cbm_githistory_result_t *result) {
    result->couplings = NULL;
    result->count = 0;
    result->commit_count = 0;
    result->file_temporal = NULL;
    result->file_temporal_count = 0;

    commit_t *commits = NULL;
    int commit_count = 0;
    int rc = parse_git_log(repo_path, &commits, &commit_count);
    if (rc != 0 || commit_count == 0) {
        free(commits);
        return 0;
    }

    result->commit_count = commit_count;

    cbm_commit_files_t *cf = githistory_commit_views(commits, commit_count);
    if (!cf) {
        githistory_free_commits(commits, commit_count);
        return 0;
    }

    cbm_change_coupling_t *couplings = malloc(MAX_COUPLINGS * sizeof(cbm_change_coupling_t));
    int coupling_count = cbm_compute_change_coupling(cf, commit_count, couplings, MAX_COUPLINGS);

    result->file_temporal =
        githistory_compute_file_temporal(cf, commit_count, &result->file_temporal_count);

    free(cf);
    githistory_free_commits(commits, commit_count);

    result->couplings = couplings;
    result->count = coupling_count;
    return 0;
}

/* Apply pre-computed couplings to the graph buffer (must be on main thread). */
int cbm_pipeline_githistory_apply(cbm_pipeline_ctx_t *ctx, const cbm_githistory_result_t *result) {
    int edge_count = 0;

    for (int i = 0; i < result->count; i++) {
        const cbm_change_coupling_t *cc = &result->couplings[i];

        char *qn_a = cbm_pipeline_fqn_compute(ctx->project_name, cc->file_a, "__file__");
        char *qn_b = cbm_pipeline_fqn_compute(ctx->project_name, cc->file_b, "__file__");

        const cbm_gbuf_node_t *node_a = cbm_gbuf_find_by_qn(ctx->gbuf, qn_a);
        const cbm_gbuf_node_t *node_b = cbm_gbuf_find_by_qn(ctx->gbuf, qn_b);

        free(qn_a);
        free(qn_b);

        if (!node_a || !node_b || cbm_node_id_eq(node_a->id, node_b->id)) {
            continue;
        }

        cbm_gbuf_prop_t props[] = {
            {.key = "co_changes",
             .kind = CBM_EDGE_PROP_NUMBER,
             .number = (double)cc->co_change_count,
             .decimals = 0},
            {.key = "coupling_score",
             .kind = CBM_EDGE_PROP_NUMBER,
             .number = cc->coupling_score,
             .decimals = GH_COUPLING_SCORE_DECIMALS},
            {.key = "last_co_change",
             .kind = CBM_EDGE_PROP_NUMBER,
             .number = (double)cc->last_co_change,
             .decimals = 0},
        };
        cbm_gbuf_insert_edge_props(
            ctx->gbuf, (cbm_edge_endpoints_t){.source = node_a->id, .target = node_b->id},
            "FILE_CHANGES_WITH", props, (int)(sizeof(props) / sizeof(props[0])));
        edge_count++;
    }

    /* Apply per-file temporal metadata to existing File nodes so callers
     * can query change_count / last_modified for hotspot analysis. The
     * extension is re-derived and JSON-escaped to keep the props blob
     * well-formed even for paths with quotes or backslashes. */
    for (int i = 0; i < result->file_temporal_count; i++) {
        const cbm_file_temporal_t *ft = &result->file_temporal[i];
        char *qn = cbm_pipeline_fqn_compute(ctx->project_name, ft->file_path, "__file__");
        const cbm_gbuf_node_t *node = cbm_gbuf_find_by_qn(ctx->gbuf, qn);
        free(qn);
        if (!node) {
            continue;
        }

        const char *base = strrchr(ft->file_path, '/');
        base = base ? base + SKIP_ONE : ft->file_path;
        const char *ext = strrchr(base, '.');
        char ext_escaped[CBM_SZ_64];
        cbm_json_escape(ext_escaped, (int)sizeof(ext_escaped), ext ? ext : "");

        char props[CBM_SZ_256];
        snprintf(props, sizeof(props),
                 "{\"extension\":\"%s\",\"last_modified\":%lld,\"change_count\":%d}", ext_escaped,
                 ft->last_modified, ft->change_count);

        cbm_gbuf_upsert_node(ctx->gbuf, node->label, node->name, node->qualified_name,
                             node->file_path, node->start_line, node->end_line, props);
    }

    return edge_count;
}

/* ── Main pass (original serial interface) ───────────────────────── */

int cbm_pipeline_pass_githistory(cbm_pipeline_ctx_t *ctx) {
    cbm_log_info("pass.start", "pass", "githistory");

    cbm_githistory_result_t result = {0};
    cbm_pipeline_githistory_compute(ctx->repo_path, &result);

    int edge_count = 0;
    if (result.count > 0 || result.file_temporal_count > 0) {
        edge_count = cbm_pipeline_githistory_apply(ctx, &result);
    }

    free(result.couplings);
    free(result.file_temporal);

    cbm_log_info("pass.done", "pass", "githistory", "commits", itoa_log(result.commit_count),
                 "edges", itoa_log(edge_count));
    return 0;
}
