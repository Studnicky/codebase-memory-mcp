/*
 * pass_parallel.c — Three-phase parallel pipeline.
 *
 * Phase 3A: Parallel extract + create definition nodes (per-worker gbufs)
 * Phase 3B: Serial registry build + edge creation from cached results
 * Phase 4:  Parallel call/usage/semantic resolution (per-worker edge bufs)
 *
 * Each file is read and parsed ONCE (Phase 3A). The CBMFileResult is cached
 * and reused for resolution (Phase 4), eliminating 3x redundant I/O + parsing.
 *
 * Depends on: worker_pool, graph_buffer (shared IDs + merge), extraction (cbm.h)
 */
#include "discover/discover.h"
#include "foundation/constants.h"

enum {
    PP_DECIMAL_BASE = 10,
    PP_RETAIN_BUDGET_DIVISOR = 8,
    PP_BYTES_PER_MB = CBM_SZ_1K * CBM_SZ_1K,
    PP_RING = 4,
    PP_RING_MASK = 3,
    PP_JSON_MARGIN = 10,
    PP_ESC_MARGIN = 3,
    PP_ESC_SPACE = 2,
    /* Fixed bytes around a serialized JSON field: ,"key":"value" / ,"key":[...]
     * -> comma + 2 key quotes + colon + 2 value quotes (resp. brackets). */
    PP_JSON_FIELD_OVERHEAD = 6,
    PP_ARGS_MARGIN = 20,
    /* Max typed edge props a single call site builds before finalize_and_emit
     * appends "args" and "line" — widest caller (emit_normal_calls_edge) uses
     * 4, leaving headroom for both. */
    PP_EDGE_PROPS_CAP = CBM_SZ_8,
    /* Fixed decimal places for a "confidence" edge prop serialized to JSON. */
    PP_CONFIDENCE_DECIMALS = 2,
    PP_LOG_THRESH = 24,
    PP_LOG_INTERVAL = 10,
    PP_TIMER_THRESH = 1000,
    /* Extraction memory back-pressure: when the process is over its RSS budget,
     * a worker reclaims + naps before pulling another file so peers can finish
     * and return pages. Bounded spins avoid deadlock when the resident graph
     * itself is near budget (then proceed with a soft overshoot). */
    PP_BACKPRESSURE_MAX_SPINS = 40,
    PP_BACKPRESSURE_NAP_NS = 3000000, /* 3 ms */
    PP_ERROR_LIST_INITIAL_CAPACITY = 8,
    PP_ERROR_LIST_GROWTH_FACTOR = 2,
    PP_JSON_CONTROL_CHAR_LIMIT = 0x20,
    PP_OVERSIZED_REASON_CAPACITY = 96,
    PP_LSP_INDEX_EXACT_SUFFIX_CAPACITY = 48,
    PP_LSP_INDEX_LEGACY_SUFFIX_CAPACITY = 16,
    PP_LSP_INDEX_DELIMITER_AND_TERMINATOR_BYTES = 2,
    PP_LSP_INDEX_CAPACITY_MULTIPLIER = 2,
    PP_LSP_INDEX_CAPACITY_OVERHEAD = 16,
    PP_REGISTRY_RESOLVE_CACHE_MIN_CAPACITY = 64,
    PP_RUST_REGISTRY_SCALE_CAPACITY = 96,
};
#define PP_NSEC_PER_SEC 1000000000ULL
#define PP_USEC_PER_MS 1000000ULL
#define PP_HALF_CONF 0.5
#define PP_FIELD_HINT_CONF 0.85
enum { PP_CSHARP_M_PREFIX_LEN = 2 };

/* Absolute source-retention ceilings for the parallel extract pipeline.
 *
 * The extract worker copies each file's source bytes into result->arena so
 * the fused cross-file LSP step in resolve_worker can re-parse without
 * re-opening the file. That retention is TRANSIENT (freed at run end) but it
 * is a PEAK-RSS driver: every retained byte is resident at once across the
 * extract→resolve handoff.
 *
 * A cap here is a FLOOR as much as a ceiling: whatever total we allow, we
 * WILL hold that much resident at peak on a large repo. rust-analyzer bounds
 * retained file *text* to a small fixed budget and re-reads source on a miss
 * rather than scaling the retained set with host RAM — because the re-read is
 * cheap relative to holding tens of GB resident. We follow the same model:
 *   - derive the total budget from the process memory budget (budget/8),
 *   - BUT clamp the RAM-derived DEFAULT to a small absolute ceiling (1 GiB)
 *     so a 512 GiB host does not retain 64 GiB of source it would re-read
 *     cheaply anyway, and keep the per-file cap modest (32 MiB) so one
 *     pathological generated blob cannot monopolise the budget.
 * A file dropped from retention is NOT lost to cross-file resolution:
 * resolve_worker re-reads it on demand, bounded and freed immediately
 * (source_reread fallback). Both caps are env-overridable — CBM_RETAIN_TOTAL_MB
 * / CBM_RETAIN_PER_FILE_MB raise or lower the auto-derived defaults directly
 * (the hard ceilings bound only the RAM-derived default, never a deliberate
 * operator/caller choice). */
#define PP_RETAIN_TOTAL_HARD_MAX_BYTES (1024ULL * 1024 * 1024)  /* 1 GiB default ceiling */
#define PP_RETAIN_PER_FILE_HARD_MAX_BYTES (32ULL * 1024 * 1024) /* 32 MiB per file */
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "pipeline/pass_lsp_cross.h" /* cbm_pxc_* helpers for fused cross-file LSP */
#include "pipeline/lsp_resolve.h"
#include "helpers.h" /* cbm_kind_in_set_free_cache — per-worker-thread cache teardown */
#include "foundation/worker_pool.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/compat_thread.h"
#include "graph_buffer/graph_buffer.h"
#include "service_patterns.h"
#include "foundation/platform.h"
#include "foundation/hash_table.h"
#include "foundation/log.h"
#include "foundation/slab_alloc.h"
#include "foundation/mem.h"
#include "foundation/str_util.h"
#include "foundation/profile.h"
#include "foundation/compat_regex.h"
#include "foundation/limits.h"
#include "cbm.h"
#include "arena.h"
#include "macro_table.h"
#include "simhash/minhash.h"
#include "semantic/ast_profile.h"

#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Back-pressure nap-cycle counter (test observability): each execution of the
 * over-budget collect+nap gate counts one cycle. Lets tests assert the gate does
 * not re-pay the full nap tax on every file pull when napping cannot reclaim
 * memory (the resident floor, not in-flight transients, holds the budget). */
static _Atomic long g_bp_nap_cycles = 0;
static _Atomic uint64_t g_lsp_linear_fallback_rows = 0;

long cbm_pp_bp_nap_cycles(void) {
    return atomic_load_explicit(&g_bp_nap_cycles, memory_order_relaxed);
}

void cbm_pp_bp_nap_cycles_reset(void) {
    atomic_store_explicit(&g_bp_nap_cycles, 0, memory_order_relaxed);
}

uint64_t cbm_pp_lsp_linear_fallback_rows(void) {
    return atomic_load_explicit(&g_lsp_linear_fallback_rows, memory_order_relaxed);
}

void cbm_pp_lsp_linear_fallback_rows_reset(void) {
    atomic_store_explicit(&g_lsp_linear_fallback_rows, 0, memory_order_relaxed);
}

/* Parse a positive MB-valued retention env knob (CBM_RETAIN_*_MB) into bytes.
 * Follows the limits.c strtol convention: unset / unparseable / non-positive
 * → return 0 so the caller keeps its derived default. */
static size_t cbm_retain_env_bytes(const char *name) {
    const char *raw = getenv(name);
    if (!raw || !raw[0]) {
        return 0;
    }
    errno = 0;
    char *end = NULL;
    long v = strtol(raw, &end, PP_DECIMAL_BASE);
    if (errno != 0 || end == raw || *end != '\0' || v <= 0) {
        return 0;
    }
    return (size_t)v * PP_BYTES_PER_MB;
}

/* Auto-derived TOTAL retention budget: a fraction of the process memory
 * budget, clamped to the absolute ceiling. The clamp bounds ONLY this
 * RAM-derived default — a huge-RAM host must not retain tens of GB it would
 * re-read cheaply. When the budget is unset (tests / no cgroup) fall back to
 * the ceiling. */
static size_t cbm_parallel_extract_default_total_cap(void) {
    size_t cap = cbm_mem_budget();
    if (cap > 0) {
        cap /= PP_RETAIN_BUDGET_DIVISOR;
    } else {
        cap = PP_RETAIN_TOTAL_HARD_MAX_BYTES;
    }
    if (cap > PP_RETAIN_TOTAL_HARD_MAX_BYTES) {
        cap = PP_RETAIN_TOTAL_HARD_MAX_BYTES;
    }
    return cap;
}

/* Auto-derived PER-FILE cap: modest absolute ceiling, never above the total. */
static size_t cbm_parallel_extract_default_per_file_cap(size_t total_cap) {
    size_t cap = PP_RETAIN_PER_FILE_HARD_MAX_BYTES;
    if (cap > total_cap) {
        cap = total_cap;
    }
    return cap;
}

/* Resolve the effective retention options from (in precedence order):
 * explicit caller opts > CBM_RETAIN_*_MB env knobs > RAM-derived defaults.
 * The absolute hard ceilings apply only to the RAM-derived defaults; an
 * operator/caller that sets a value explicitly is trusted. The only invariant
 * enforced unconditionally is per-file ≤ total. */
static cbm_parallel_extract_opts_t cbm_parallel_extract_resolve_opts(
    const cbm_parallel_extract_opts_t *opts) {
    cbm_parallel_extract_opts_t resolved = {
        .retain_sources = true,
        .retain_sources_set = true,
        .retain_total_budget_bytes = cbm_parallel_extract_default_total_cap(),
        .retain_per_file_max_bytes = 0,
    };

    size_t env_total = cbm_retain_env_bytes("CBM_RETAIN_TOTAL_MB");
    if (env_total > 0) {
        resolved.retain_total_budget_bytes = env_total;
    }

    resolved.retain_per_file_max_bytes =
        cbm_parallel_extract_default_per_file_cap(resolved.retain_total_budget_bytes);
    size_t env_per_file = cbm_retain_env_bytes("CBM_RETAIN_PER_FILE_MB");
    if (env_per_file > 0) {
        resolved.retain_per_file_max_bytes = env_per_file;
    }

    if (opts) {
        if (opts->retain_sources_set) {
            resolved.retain_sources = opts->retain_sources;
        }
        if (opts->retain_total_budget_bytes > 0) {
            resolved.retain_total_budget_bytes = opts->retain_total_budget_bytes;
        }
        if (opts->retain_per_file_max_bytes > 0) {
            resolved.retain_per_file_max_bytes = opts->retain_per_file_max_bytes;
        }
    }

    /* Correctness invariant: a single file can never exceed the total budget. */
    if (resolved.retain_per_file_max_bytes > resolved.retain_total_budget_bytes) {
        resolved.retain_per_file_max_bytes = resolved.retain_total_budget_bytes;
    }
    return resolved;
}

static uint64_t extract_now_ns(void) {
    struct timespec ts;
    cbm_clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * PP_NSEC_PER_SEC) + (uint64_t)ts.tv_nsec;
}

/* ── Helpers (duplicated from pass files — kept static for isolation) ── */

/* Read file into a malloc'd buffer (= mimalloc in production).
 * *out_size receives the on-disk size and *out_status the failure reason so the
 * caller can attribute a skip to the right phase (read vs oversized) instead of
 * a silent drop. Both out params may be NULL. */
static char *read_file(const char *path, int *out_len, long *out_size,
                       cbm_read_status_t *out_status) {
    if (out_size) {
        *out_size = 0;
    }
    if (out_status) {
        *out_status = CBM_READ_OK;
    }
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        if (out_status) {
            *out_status = CBM_READ_OPEN_FAIL;
        }
        return NULL;
    }
    (void)fseek(f, 0, SEEK_END);
    long size = ftell(f);
    (void)fseek(f, 0, SEEK_SET);
    if (out_size) {
        *out_size = size;
    }
    if (size <= 0) {
        (void)fclose(f);
        if (out_status) {
            *out_status = CBM_READ_EMPTY;
        }
        return NULL;
    }
    if (size > cbm_max_file_bytes()) { /* generous, env-configurable cap (B4) */
        (void)fclose(f);
        if (out_status) {
            *out_status = CBM_READ_OVERSIZED;
        }
        return NULL;
    }
    char *buf = (char *)malloc((size_t)size + SKIP_ONE);
    if (!buf) {
        (void)fclose(f);
        if (out_status) {
            *out_status = CBM_READ_OOM;
        }
        return NULL;
    }
    size_t nread = fread(buf, SKIP_ONE, (size_t)size, f);
    (void)fclose(f);
    buf[nread] = '\0';
    *out_len = (int)nread;
    return buf;
}

/* ── Per-worker skip list (Stage 2 / Track B) ───────────────────────
 * Each extract worker appends read/extract/oversized skips into its OWN list
 * (no lock on the hot path); the lists are merged into the pipeline's
 * cbm_file_error_t array in the existing sequential merge loop. */
typedef struct {
    cbm_file_error_t *items;
    int count;
    int cap;
} pp_err_list_t;

/* NULL-safe heap strdup. */
static char *pp_err_dup(const char *s) {
    if (!s) {
        return NULL;
    }
    size_t n = strlen(s) + SKIP_ONE;
    char *d = (char *)malloc(n);
    if (d) {
        memcpy(d, s, n);
    }
    return d;
}

static void pp_err_add(pp_err_list_t *list, const char *path, const char *reason,
                       const char *phase) {
    if (!list) {
        return;
    }
    if (list->count >= list->cap) {
        /* Doubling an int overflows before the cast can widen it, so bound it
         * first and drop the record as this function already does when the
         * allocation fails. */
        if (list->cap > INT_MAX / PP_ERROR_LIST_GROWTH_FACTOR) {
            return;
        }
        int ncap =
            list->cap ? list->cap * PP_ERROR_LIST_GROWTH_FACTOR : PP_ERROR_LIST_INITIAL_CAPACITY;
        cbm_file_error_t *grown =
            (cbm_file_error_t *)realloc(list->items, (size_t)ncap * sizeof(*grown));
        if (!grown) {
            return; /* drop on OOM — never fail extraction to record a skip */
        }
        list->items = grown;
        list->cap = ncap;
    }
    list->items[list->count].path = pp_err_dup(path);
    list->items[list->count].reason = pp_err_dup(reason);
    list->items[list->count].phase = pp_err_dup(phase);
    list->count++;
}

/* Free source buffer. */
static void free_source(char *buf) {
    free(buf);
}

static const char *itoa_log(int val) {
    static CBM_TLS char bufs[PP_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & PP_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* Append a JSON-escaped string value to buf at position *pos. */
/* Escape one character for JSON. Returns bytes written (1 or 2). */
static int json_escape_char(char *buf, size_t avail, char ch) {
    char esc = 0;
    switch (ch) {
    case '"':
        esc = '"';
        break;
    case '\\':
        esc = '\\';
        break;
    case '\n':
        esc = 'n';
        break;
    case '\r':
        esc = 'r';
        break;
    case '\t':
        esc = 't';
        break;
    default:
        if (avail >= SKIP_ONE) {
            /* Any other raw control byte (e.g. form feed) is invalid inside a
             * JSON string — degrade to a space. */
            buf[0] = ((unsigned char)ch < PP_JSON_CONTROL_CHAR_LIMIT) ? ' ' : ch;
        }
        return SKIP_ONE;
    }
    if (avail >= PP_ESC_SPACE) {
        buf[0] = '\\';
        buf[SKIP_ONE] = esc;
    }
    return PP_ESC_SPACE;
}

/* Escaped length of a string under json_escape_char's rules: escaped
 * characters expand to 2 bytes, everything else stays 1. */
static size_t pp_json_escaped_len(const char *s) {
    size_t n = 0;
    for (; *s; s++) {
        switch (*s) {
        case '"':
        case '\\':
        case '\n':
        case '\r':
        case '\t':
            n += PP_ESC_SPACE;
            break;
        default:
            n += SKIP_ONE;
        }
    }
    return n;
}

/* Appends are ATOMIC: a field is emitted only if the WHOLE serialized form
 * fits (with PP_ESC_SPACE bytes reserved for the closing '}' + NUL). Cutting a
 * field mid-value produced unterminated strings/arrays — malformed properties
 * JSON that aborts every json_extract()-based consumer downstream (seen on the
 * Linux kernel: 50-param functions truncated at the 2 KB cap). Dropping an
 * oversized optional field whole keeps the JSON valid. Twin of
 * pass_definitions.c — keep both in sync. */
static void append_json_string(char *buf, size_t bufsize, size_t *pos, const char *key,
                               const char *val) {
    if (!val || val[0] == '\0') {
        return;
    }
    size_t required = strlen(key) + pp_json_escaped_len(val) + PP_JSON_FIELD_OVERHEAD;
    if (*pos + required + PP_ESC_SPACE > bufsize) {
        return; /* whole field would not fit — skip it atomically */
    }
    size_t p = *pos;
    int w = snprintf(buf + p, bufsize - p, ",\"%s\":\"", key);
    if (w <= 0 || (size_t)w >= bufsize - p) {
        return;
    }
    p += (size_t)w;
    for (const char *s = val; *s && p < bufsize - PP_ESC_MARGIN; s++) {
        int n = json_escape_char(buf + p, bufsize - p - PP_ESC_SPACE, *s);
        p += (size_t)n;
    }
    if (p < bufsize - SKIP_ONE) {
        buf[p++] = '"';
    }
    buf[p] = '\0';
    *pos = p;
}

/* Append a JSON array of strings: ,"key":["a","b","c"]. Atomic like
 * append_json_string: emitted only if the whole array fits. */
static void append_json_str_array(char *buf, size_t bufsize, size_t *pos, const char *key,
                                  const char **arr) {
    if (!arr || !arr[0] || *pos >= bufsize - PP_JSON_MARGIN) {
        return;
    }
    /* ,"key":[ + per item "<escaped>" + separating commas + ] */
    size_t required = strlen(key) + PP_JSON_FIELD_OVERHEAD;
    for (int i = 0; arr[i]; i++) {
        required += pp_json_escaped_len(arr[i]) + PP_ESC_SPACE + (i > 0 ? SKIP_ONE : 0);
    }
    if (*pos + required + PP_ESC_SPACE > bufsize) {
        return; /* whole array would not fit — skip it atomically */
    }
    size_t p = *pos;
    int n = snprintf(buf + p, bufsize - p, ",\"%s\":[", key);
    if (n <= 0 || p + (size_t)n >= bufsize - PP_ESC_SPACE) {
        return;
    }
    p += (size_t)n;
    for (int i = 0; arr[i]; i++) {
        if (i > 0 && p < bufsize - SKIP_ONE) {
            buf[p++] = ',';
        }
        if (p < bufsize - SKIP_ONE) {
            buf[p++] = '"';
        }
        /* Full escaping (not just quote/backslash): items like C param types
         * sliced from multi-line declarations carry raw \n/\t bytes, which are
         * invalid inside JSON strings. */
        for (const char *s = arr[i]; *s && p < bufsize - PP_ESC_SPACE; s++) {
            p += (size_t)json_escape_char(buf + p, bufsize - p - PP_ESC_SPACE, *s);
        }
        if (p < bufsize - SKIP_ONE) {
            buf[p++] = '"';
        }
    }
    if (p < bufsize - SKIP_ONE) {
        buf[p++] = ']';
    }
    buf[p] = '\0';
    *pos = p;
}

static int build_function_def_props_prefix(char *buf, size_t bufsize, const CBMDefinition *def) {
    return snprintf(buf, bufsize,
                    "{\"complexity\":%d,\"cognitive\":%d,\"loop_count\":%d,\"loop_depth\":%d,"
                    "\"self_recursive\":%s,\"param_count\":%d,\"max_access_depth\":%d,"
                    "\"linear_scan_in_loop\":%d,\"alloc_in_loop\":%d,\"recursion_in_loop\":%s,"
                    "\"unguarded_recursion\":%s,"
                    "\"lines\":%d,\"is_exported\":%s,\"is_test\":%s,\"is_entry_point\":%s",
                    def->complexity, def->cognitive, def->loop_count, def->loop_depth,
                    def->is_recursive ? "true" : "false", def->param_count, def->max_access_depth,
                    def->linear_scan_in_loop, def->alloc_in_loop,
                    def->recursion_in_loop ? "true" : "false",
                    def->unguarded_recursion ? "true" : "false", def->lines,
                    def->is_exported ? "true" : "false", def->is_test ? "true" : "false",
                    def->is_entry_point ? "true" : "false");
}

static int build_nonfunction_def_props_prefix(char *buf, size_t bufsize, const CBMDefinition *def) {
    return snprintf(buf, bufsize,
                    "{\"complexity\":%d,\"lines\":%d,\"is_exported\":%s,\"is_test\":%s,"
                    "\"is_entry_point\":%s",
                    def->complexity, def->lines, def->is_exported ? "true" : "false",
                    def->is_test ? "true" : "false", def->is_entry_point ? "true" : "false");
}

static int build_def_props_prefix(char *buf, size_t bufsize, const CBMDefinition *def) {
    /* Complexity/loop/recursion metrics are meaningful only for Function/Method.
     * Gate the block so the millions of Macro/Field/Variable/Class/Enum nodes
     * keep a lean properties blob (lossless — those fields are always zero for
     * non-functions). Cuts RAM, gbuf-merge copy and dump volume. Mirrors
     * pass_definitions.c::build_def_props — keep both in sync. */
    const bool is_fn =
        def->label && (strcmp(def->label, "Function") == 0 || strcmp(def->label, "Method") == 0);
    int n = is_fn ? build_function_def_props_prefix(buf, bufsize, def)
                  : build_nonfunction_def_props_prefix(buf, bufsize, def);
    return n > 0 && (size_t)n < bufsize ? n : 0;
}

static void build_def_props_optional_fields(char *buf, size_t bufsize, size_t *pos,
                                            const CBMDefinition *def) {
    append_json_string(buf, bufsize, pos, "docstring", def->docstring);
    append_json_string(buf, bufsize, pos, "signature", def->signature);
    append_json_string(buf, bufsize, pos, "return_type", def->return_type);
    append_json_string(buf, bufsize, pos, "parent_class", def->parent_class);
    append_json_str_array(buf, bufsize, pos, "decorators", def->decorators);
    append_json_str_array(buf, bufsize, pos, "base_classes", def->base_classes);
    append_json_str_array(buf, bufsize, pos, "param_names", def->param_names);
    append_json_str_array(buf, bufsize, pos, "param_types", def->param_types);
    append_json_string(buf, bufsize, pos, "route_path", def->route_path);
    append_json_string(buf, bufsize, pos, "route_method", def->route_method);
}

static void build_def_props_derived_fields(char *buf, size_t bufsize, size_t *pos,
                                           const CBMDefinition *def) {
    if (def->fingerprint && def->fingerprint_k > 0 &&
        *pos + CBM_MINHASH_HEX_LEN + CBM_MINHASH_JSON_OVERHEAD < bufsize) {
        char fp_hex[CBM_MINHASH_HEX_BUF];
        cbm_minhash_to_hex((const cbm_minhash_t *)def->fingerprint, fp_hex, sizeof(fp_hex));
        append_json_string(buf, bufsize, pos, "fp", fp_hex);
    }
    if (def->structural_profile && *pos + CBM_AST_PROFILE_BUF < bufsize) {
        append_json_string(buf, bufsize, pos, "sp", def->structural_profile);
    }
    if (def->body_tokens && *pos + CBM_SZ_512 < bufsize) {
        append_json_string(buf, bufsize, pos, "bt", def->body_tokens);
    }
}

static void build_def_props(char *buf, size_t bufsize, const CBMDefinition *def) {
    int n = build_def_props_prefix(buf, bufsize, def);
    if (n == 0) {
        buf[0] = '\0';
        return;
    }
    size_t pos = (size_t)n;
    build_def_props_optional_fields(buf, bufsize, &pos, def);
    build_def_props_derived_fields(buf, bufsize, &pos, def);

    if (pos < bufsize - SKIP_ONE) {
        buf[pos] = '}';
        buf[pos + SKIP_ONE] = '\0';
    }
}

/* True for languages whose module QN derives from the CONTAINING DIRECTORY
 * (Java/Go package). MUST match cbm_lang_module_is_dir() (internal/cbm/helpers.c)
 * and pxc_module_is_dir() (pass_lsp_cross.c) so same-module callee resolution
 * keys against the directory-based def-node QNs in the registry. */
static bool pp_module_is_dir(CBMLanguage lang) {
    return lang == CBM_LANG_JAVA || lang == CBM_LANG_GO;
}

static bool is_checked_exception(const char *name) {
    if (!name) {
        return false;
    }
    if (strstr(name, "Error") || strstr(name, "Panic") || strstr(name, "error") ||
        strstr(name, "panic")) {
        return false;
    }
    return true;
}

static const char *resolve_as_class(const cbm_registry_t *reg, const char *name,
                                    const char *module_qn, const char **imp_keys,
                                    const char **imp_vals, int imp_count) {
    cbm_resolution_t res =
        cbm_registry_resolve(reg, name, module_qn, imp_keys, imp_vals, imp_count);
    if (!res.qualified_name || res.qualified_name[0] == '\0') {
        return NULL;
    }
    /* Accept any type-like container (Class/Struct/Interface/Enum/Type/Trait):
     * base classes, Rust `impl Trait for S` struct receivers, and Go struct
     * embedding all resolve through here. Struct included so the struct receiver
     * of an IMPLEMENTS edge is not dropped. */
    const char *label = cbm_registry_label_of(reg, res.qualified_name);
    if (!cbm_label_is_type_like(label)) {
        return NULL;
    }
    return res.qualified_name;
}

static void extract_decorator_func(const char *dec, char *out, size_t outsz) {
    out[0] = '\0';
    if (!dec) {
        return;
    }
    const char *start = dec;
    while (*start == '@' || *start == '#' || *start == '[' || *start == ' ') {
        start++;
    }
    size_t len = 0;
    while (start[len] && start[len] != '(' && start[len] != '[' && start[len] != ']' &&
           start[len] != ' ' && start[len] != ',') {
        len++;
    }
    if (len == 0 || len >= outsz) {
        return;
    }
    memcpy(out, start, len);
    out[len] = '\0';
}

/* ── File sort for tail-latency reduction ────────────────────────── */

typedef struct {
    int idx;
    int64_t size;
} file_sort_entry_t;

static int compare_by_size_desc(const void *a, const void *b) {
    const file_sort_entry_t *fa = a;
    const file_sort_entry_t *fb = b;
    if (fb->size > fa->size) {
        return SKIP_ONE;
    }
    if (fb->size < fa->size) {
        return CBM_NOT_FOUND;
    }
    return 0;
}

/* ── Phase 3A: Parallel Extract ──────────────────────────────────── */

#define CBM_CACHE_LINE CBM_SZ_128

typedef struct __attribute__((aligned(CBM_CACHE_LINE))) {
    cbm_gbuf_t *local_gbuf;
    int nodes_created;
    int errors;
    char _pad[CBM_CACHE_LINE - sizeof(cbm_gbuf_t *) - (PP_ESC_SPACE * sizeof(int))];
} extract_worker_state_t;

typedef struct {
    const cbm_file_info_t *files;
    file_sort_entry_t *sorted;
    int file_count;
    const char *project_name;
    const char *repo_path;

    extract_worker_state_t *workers;
    int max_workers;
    _Atomic int next_worker_id;

    CBMFileResult **result_cache;
    _Atomic int64_t *shared_ids;
    _Atomic int *cancelled;
    _Atomic int next_file_idx;

    cbm_pkg_entries_t *pkg_entries; /* per-worker manifest arrays (separate allocation) */

    bool retain_sources;              /* copy source into result->arena for cross-file LSP */
    size_t retain_total_budget_bytes; /* project-wide retention cap (peak-RSS bound) */
    size_t retain_per_file_max_bytes; /* per-file retention cap */
    _Atomic int64_t retained_bytes;   /* total source bytes copied into result arenas */
    _Atomic int retain_cap_warned;    /* WARN index.retain_capped emitted once per run */

    /* Per-worker skip lists (separate allocation, indexed by worker_id — no hot-
     * path lock). Merged into the pipeline in the sequential merge loop. */
    pp_err_list_t *err_lists;
    _Atomic int oversized_warned; /* throttle for the index.file_oversized WARN */

    /* Back-pressure futility latch: set when a full collect+nap cycle ended
     * still over budget — the resident floor (graph + retained sources), not
     * in-flight transients, holds the memory, so napping cannot reclaim it.
     * While set, pulls skip the nap (the designed soft overshoot); the cheap
     * over-budget probe re-arms the gate once RSS drains under budget. */
    _Atomic int bp_futile;

    const CBMMacroTable *macro_table;            /* ObjectScript $$$macros (NULL if none) */
    const CBMReturnTypeTable *return_type_table; /* ObjectScript return types (NULL if none) */
} extract_ctx_t;

/* Cap on the number of index.file_oversized WARN lines (the full list still goes
 * to the response/logfile — this only throttles the stderr noise). */
enum { PP_OVERSIZED_WARN_MAX = 32 };

/* Insert one definition node (and its route if present) into the local gbuf. */
static void insert_def_into_gbuf(extract_worker_state_t *ws, const cbm_file_info_t *fi,
                                 CBMDefinition *def) {
    char props[CBM_SZ_2K];
    build_def_props(props, sizeof(props), def);
    cbm_node_id_t func_id =
        cbm_gbuf_upsert_node(ws->local_gbuf, def->label ? def->label : "Function", def->name,
                             def->qualified_name, def->file_path ? def->file_path : fi->rel_path,
                             (int)def->start_line, (int)def->end_line, props);
    ws->nodes_created++;
    if (def->route_path && def->route_path[0] != '\0') {
        const char *rm = def->route_method ? def->route_method : "ANY";
        char route_qn[CBM_ROUTE_QN_SIZE];
        char cpath[CBM_SZ_256];
        snprintf(route_qn, sizeof(route_qn), "__route__%s__%s", rm,
                 cbm_route_canon_path(def->route_path, cpath, sizeof(cpath)));
        char rprops[CBM_SZ_256];
        snprintf(rprops, sizeof(rprops), "{\"method\":\"%s\",\"source\":\"decorator\"}", rm);
        cbm_node_id_t route_id =
            cbm_gbuf_upsert_node(ws->local_gbuf, "Route", def->route_path, route_qn,
                                 def->file_path ? def->file_path : fi->rel_path, 0, 0, rprops);
        cbm_gbuf_prop_t hprops[] = {
            {.key = "handler", .kind = CBM_EDGE_PROP_STRING, .text = def->qualified_name},
        };
        cbm_gbuf_insert_edge_props(ws->local_gbuf,
                                   (cbm_edge_endpoints_t){.source = func_id, .target = route_id},
                                   "HANDLES", hprops, (int)(sizeof(hprops) / sizeof(hprops[0])));
    }
}

static void log_extract_fail(int pos, uint64_t ms, const char *path) {
    if (pos < PP_LOG_THRESH) {
        cbm_log_warn("parallel.extract.file.fail", "pos", itoa_log(pos), "elapsed_ms",
                     itoa_log((int)ms), "path", path);
    }
}

static void log_extract_done(int pos, uint64_t ms, int defs, const char *path) {
    if (pos < PP_LOG_THRESH || ms > PP_TIMER_THRESH) {
        cbm_log_info("parallel.extract.file.done", "pos", itoa_log(pos), "elapsed_ms",
                     itoa_log((int)ms), "defs", itoa_log(defs), "path", path);
    }
}

static void extract_worker_apply_backpressure(extract_ctx_t *ec) {
    if (cbm_mem_budget() == 0) {
        return;
    }
    bool over = cbm_mem_over_budget();
    bool futile = atomic_load_explicit(&ec->bp_futile, memory_order_relaxed) != 0;
    if (over && !futile) {
        cbm_mem_collect();
        atomic_fetch_add_explicit(&g_bp_nap_cycles, SKIP_ONE, memory_order_relaxed);
        int spins = 0;
        for (; spins < PP_BACKPRESSURE_MAX_SPINS && cbm_mem_over_budget() &&
               !atomic_load_explicit(ec->cancelled, memory_order_relaxed);
             ++spins) {
            struct timespec nap = {0, PP_BACKPRESSURE_NAP_NS};
            cbm_nanosleep(&nap, NULL);
        }
        if (spins == PP_BACKPRESSURE_MAX_SPINS && cbm_mem_over_budget() &&
            atomic_exchange_explicit(&ec->bp_futile, SKIP_ONE, memory_order_relaxed) == 0) {
            cbm_log_warn("mem.backpressure.futile", "action", "soft_overshoot");
        }
    } else if (!over && futile) {
        atomic_store_explicit(&ec->bp_futile, 0, memory_order_relaxed);
    }
}

static void extract_record_read_failure(extract_ctx_t *ec, extract_worker_state_t *ws,
                                        pp_err_list_t *errs, const cbm_file_info_t *fi,
                                        long file_size, cbm_read_status_t status) {
    ++ws->errors;
    if (status == CBM_READ_OVERSIZED) {
        long cap = cbm_max_file_bytes();
        const long bytes_per_mb = (long)PP_BYTES_PER_MB;
        char reason[PP_OVERSIZED_REASON_CAPACITY];
        snprintf(reason, sizeof(reason), "oversized (%lld MB > %lld MB)",
                 (long long)(file_size / bytes_per_mb), (long long)(cap / bytes_per_mb));
        pp_err_add(errs, fi->rel_path, reason, "oversized");
        if (atomic_fetch_add_explicit(&ec->oversized_warned, SKIP_ONE, memory_order_relaxed) <
            PP_OVERSIZED_WARN_MAX) {
            cbm_log_warn("index.file_oversized", "path", fi->rel_path, "size_mb",
                         itoa_log((int)(file_size / bytes_per_mb)), "cap_mb",
                         itoa_log((int)(cap / bytes_per_mb)));
        }
    } else if (status == CBM_READ_OPEN_FAIL || status == CBM_READ_OOM) {
        pp_err_add(errs, fi->rel_path, "read failed", "read");
    }
}

static CBMFileResult *extract_file_result(const extract_ctx_t *ec, const cbm_file_info_t *fi,
                                          const char *source, int source_len) {
    return fi->language == CBM_LANG_OBJECTSCRIPT_EXPORT
               ? cbm_pipeline_extract_objectscript_export(source, source_len, ec->project_name,
                                                          fi->rel_path, ec->macro_table,
                                                          ec->return_type_table)
               : cbm_extract_file_ex(source, source_len, fi->language, ec->project_name,
                                     fi->rel_path, CBM_EXTRACT_BUDGET, NULL, NULL, ec->macro_table,
                                     ec->return_type_table);
}

static void extract_record_result_status(extract_worker_state_t *ws, pp_err_list_t *errs,
                                         const cbm_file_info_t *fi, const CBMFileResult *result) {
    if (result->has_error) {
        pp_err_add(errs, fi->rel_path, result->error_msg ? result->error_msg : "extract failed",
                   "extract");
        ++ws->errors;
    } else if (result->parse_incomplete) {
        pp_err_add(errs, fi->rel_path, result->error_ranges ? result->error_ranges : "unknown",
                   "parse_partial");
    }
}

static void extract_insert_definitions(extract_worker_state_t *ws, const cbm_file_info_t *fi,
                                       CBMFileResult *result) {
    for (int index = 0; index < result->defs.count; ++index) {
        CBMDefinition *definition = &result->defs.items[index];
        if (definition->qualified_name && definition->name) {
            insert_def_into_gbuf(ws, fi, definition);
        }
    }
}

static void extract_retain_source(extract_ctx_t *ec, const cbm_file_info_t *fi,
                                  CBMFileResult *result, const char *source, int source_len) {
    if (!ec->retain_sources || source_len <= 0) {
        return;
    }
    bool dropped = (size_t)source_len > ec->retain_per_file_max_bytes;
    if (!dropped) {
        int64_t prior = atomic_fetch_add_explicit(&ec->retained_bytes, (int64_t)source_len,
                                                  memory_order_relaxed);
        if ((size_t)(prior + (int64_t)source_len) <= ec->retain_total_budget_bytes) {
            char *copy = (char *)cbm_arena_alloc(&result->arena, (size_t)source_len + SKIP_ONE);
            if (copy) {
                memcpy(copy, source, (size_t)source_len);
                copy[source_len] = '\0';
                result->source = copy;
                result->source_len = source_len;
            } else {
                atomic_fetch_sub_explicit(&ec->retained_bytes, (int64_t)source_len,
                                          memory_order_relaxed);
            }
        } else {
            atomic_fetch_sub_explicit(&ec->retained_bytes, (int64_t)source_len,
                                      memory_order_relaxed);
            dropped = true;
        }
    }
    if (dropped &&
        atomic_exchange_explicit(&ec->retain_cap_warned, SKIP_ONE, memory_order_relaxed) == 0) {
        cbm_log_warn("index.retain_capped", "path", fi->rel_path ? fi->rel_path : "?", "bytes",
                     itoa_log(source_len));
    }
}

static void extract_worker_process_file(extract_ctx_t *ec, extract_worker_state_t *ws,
                                        int worker_id, int sort_pos) {
    int file_idx = ec->sorted[sort_pos].idx;
    const cbm_file_info_t *fi = &ec->files[file_idx];
    pp_err_list_t *errs = ec->err_lists ? &ec->err_lists[worker_id] : NULL;
    if (cbm_index_is_quarantined(fi->rel_path)) {
        const char *phase = cbm_index_quarantine_phase(fi->rel_path);
        phase = phase ? phase : "crash";
        pp_err_add(errs, fi->rel_path,
                   strcmp(phase, "hang") == 0 ? "quarantined after hang"
                                              : "quarantined after crash",
                   phase);
        ++ws->errors;
        return;
    }
    int source_len = 0;
    long file_size = 0;
    cbm_read_status_t status = CBM_READ_OK;
    char *source = read_file(fi->path, &source_len, &file_size, &status);
    if (!source) {
        extract_record_read_failure(ec, ws, errs, fi, file_size, status);
        return;
    }
    if (sort_pos < PP_LOG_THRESH) {
        cbm_log_info("parallel.extract.file.start", "pos", itoa_log(sort_pos), "size_kb",
                     itoa_log(source_len / CBM_SZ_1K), "path", fi->rel_path);
    }
    uint64_t started = extract_now_ns();
    CBMFileResult *result = extract_file_result(ec, fi, source, source_len);
    uint64_t elapsed_ms = (extract_now_ns() - started) / PP_USEC_PER_MS;
    if (!result) {
        log_extract_fail(sort_pos, elapsed_ms, fi->rel_path);
        free_source(source);
        ++ws->errors;
        pp_err_add(errs, fi->rel_path, "extract failed", "extract");
        return;
    }
    log_extract_done(sort_pos, elapsed_ms, result->defs.count, fi->rel_path);
    extract_record_result_status(ws, errs, fi, result);
    extract_insert_definitions(ws, fi, result);
    cbm_free_tree(result);
    const char *basename = strrchr(fi->rel_path, '/');
    cbm_pkgmap_try_parse(basename ? basename + SKIP_ONE : fi->rel_path, fi->rel_path, source,
                         source_len, &ec->pkg_entries[worker_id]);
    extract_retain_source(ec, fi, result, source, source_len);
    free_source(source);
    ec->result_cache[file_idx] = result;
    if ((sort_pos + SKIP_ONE) % PP_LOG_INTERVAL == 0 || sort_pos + SKIP_ONE == ec->file_count) {
        cbm_log_info("parallel.extract.progress", "done", itoa_log(sort_pos + SKIP_ONE), "total",
                     itoa_log(ec->file_count));
    }
    cbm_destroy_thread_parser();
    cbm_slab_reclaim();
    cbm_mem_collect();
}

static void extract_worker(int worker_id, void *ctx_ptr) {
    extract_ctx_t *ec = ctx_ptr;
    extract_worker_state_t *ws = &ec->workers[worker_id];
    if (!ws->local_gbuf) {
        ws->local_gbuf = cbm_gbuf_new_shared_ids(ec->project_name, ec->repo_path, ec->shared_ids);
    }
    while (SKIP_ONE) {
        int sort_pos =
            atomic_fetch_add_explicit(&ec->next_file_idx, SKIP_ONE, memory_order_relaxed);
        if (sort_pos >= ec->file_count ||
            atomic_load_explicit(ec->cancelled, memory_order_relaxed)) {
            break;
        }
        extract_worker_apply_backpressure(ec);
        extract_worker_process_file(ec, ws, worker_id, sort_pos);
    }
    cbm_slab_destroy_thread();
    cbm_kind_in_set_free_cache();
}

static void merge_pkg_entries(cbm_pipeline_ctx_t *ctx, cbm_pkg_entries_t *pkg_entries,
                              int worker_count) {
    if (!pkg_entries) {
        return;
    }
    /* Supplement with a repo-wide filesystem walk so manifests filtered
     * by the main discoverer (package.json, composer.json — in
     * IGNORED_JSON_FILES) still feed pkgmap. Append into worker 0's
     * array so the existing merge below sees them. */
    cbm_pkgmap_scan_repo(ctx->repo_path, &pkg_entries[0], ctx->excluded_dirs, ctx->excluded_count);
    cbm_pipeline_set_pkgmap(cbm_pkgmap_build(pkg_entries, worker_count, ctx->project_name));
    for (int i = 0; i < worker_count; i++) {
        cbm_pkg_entries_free(&pkg_entries[i]);
    }
    free(pkg_entries);
}

static void log_extract_mem_stats(int worker_count) {
    if (cbm_mem_budget() > 0) {
        size_t mb = (size_t)CBM_SZ_1K * CBM_SZ_1K;
        cbm_log_info("parallel.extract.mem", "rss_mb", itoa_log((int)(cbm_mem_rss() / mb)),
                     "peak_mb", itoa_log((int)(cbm_mem_peak_rss() / mb)), "budget_mb",
                     itoa_log((int)(cbm_mem_budget() / mb)), "per_worker_mb",
                     itoa_log((int)(cbm_mem_worker_budget(worker_count) / mb)));
    }
}

typedef struct {
    extract_ctx_t context;
    file_sort_entry_t *sorted;
    extract_worker_state_t *workers;
    cbm_pkg_entries_t *pkg_entries;
    pp_err_list_t *err_lists;
    CBMMacroTable *macro_table;
} pp_extract_run_t;

typedef struct {
    int nodes;
    int errors;
} pp_extract_totals_t;

static void pp_extract_log_start(int file_count, int worker_count,
                                 const cbm_parallel_extract_opts_t *options) {
    size_t megabyte = (size_t)CBM_SZ_1K * CBM_SZ_1K;
    cbm_log_info("parallel.extract.start", "files", itoa_log(file_count), "workers",
                 itoa_log(worker_count));
    cbm_log_info("parallel.extract.retention", "retain_sources",
                 options->retain_sources ? "true" : "false", "total_mb",
                 itoa_log((int)(options->retain_total_budget_bytes / megabyte)), "per_file_mb",
                 itoa_log((int)(options->retain_per_file_max_bytes / megabyte)));
    if (cbm_mem_budget() > 0) {
        cbm_log_info("parallel.mem.budget", "total_mb",
                     itoa_log((int)(cbm_mem_budget() / megabyte)), "per_worker_mb",
                     itoa_log((int)(cbm_mem_worker_budget(worker_count) / megabyte)));
    }
}

static void pp_extract_init_runtime(void) {
    CBM_PROF_START(initialized);
    cbm_init();
    cbm_destroy_thread_parser();
    cbm_slab_install();
    CBM_PROF_END("parallel_extract", "1_init_libs", initialized);
}

static file_sort_entry_t *pp_extract_sorted_files(const cbm_file_info_t *files, int file_count) {
    CBM_PROF_START(sorted);
    file_sort_entry_t *entries = malloc((size_t)file_count * sizeof(*entries));
    if (!entries) {
        return NULL;
    }
    for (int index = 0; index < file_count; ++index) {
        entries[index] = (file_sort_entry_t){.idx = index, .size = files[index].size};
    }
    qsort(entries, (size_t)file_count, sizeof(*entries), compare_by_size_desc);
    CBM_PROF_END_N("parallel_extract", "2_sort_files", sorted, file_count);
    return entries;
}

static bool pp_extract_run_prepare(pp_extract_run_t *run, cbm_pipeline_ctx_t *pipeline,
                                   const cbm_file_info_t *files, int file_count,
                                   CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                                   int worker_count, const cbm_parallel_extract_opts_t *options) {
    pp_extract_init_runtime();
    run->sorted = pp_extract_sorted_files(files, file_count);
    if (!run->sorted) {
        return false;
    }
    if (cbm_aligned_alloc((void **)&run->workers, CBM_CACHE_LINE,
                          (size_t)worker_count * sizeof(*run->workers)) != 0) {
        free(run->sorted);
        return false;
    }
    memset(run->workers, 0, (size_t)worker_count * sizeof(*run->workers));
    run->pkg_entries = calloc((size_t)worker_count, sizeof(*run->pkg_entries));
    if (!run->pkg_entries) {
        cbm_aligned_free(run->workers);
        free(run->sorted);
        return false;
    }
    run->err_lists = calloc((size_t)worker_count, sizeof(*run->err_lists));
    run->macro_table = cbm_build_macro_table_from_files(files, file_count, pipeline->repo_path);
    run->context = (extract_ctx_t){
        .files = files,
        .sorted = run->sorted,
        .file_count = file_count,
        .project_name = pipeline->project_name,
        .repo_path = pipeline->repo_path,
        .workers = run->workers,
        .max_workers = worker_count,
        .result_cache = result_cache,
        .shared_ids = shared_ids,
        .cancelled = pipeline->cancelled,
        .pkg_entries = run->pkg_entries,
        .err_lists = run->err_lists,
        .retain_sources = options->retain_sources,
        .retain_total_budget_bytes = options->retain_total_budget_bytes,
        .retain_per_file_max_bytes = options->retain_per_file_max_bytes,
        .macro_table = run->macro_table,
        .return_type_table = pipeline->return_type_table,
    };
    atomic_init(&run->context.next_worker_id, 0);
    atomic_init(&run->context.next_file_idx, 0);
    atomic_init(&run->context.retained_bytes, 0);
    atomic_init(&run->context.retain_cap_warned, 0);
    atomic_init(&run->context.oversized_warned, 0);
    atomic_init(&run->context.bp_futile, 0);
    return true;
}

static void pp_extract_dispatch(pp_extract_run_t *run, int file_count, int worker_count) {
    CBM_PROF_START(dispatched);
    cbm_parallel_for_opts_t options = {.max_workers = worker_count, .force_pthreads = false};
    cbm_parallel_for(worker_count, extract_worker, &run->context, options);
    CBM_PROF_END_N("parallel_extract", "3_dispatch_workers_parallel", dispatched, file_count);
}

static pp_extract_totals_t pp_extract_merge_workers(cbm_pipeline_ctx_t *pipeline,
                                                    pp_extract_run_t *run, int worker_count) {
    CBM_PROF_START(merged);
    pp_extract_totals_t totals = {0};
    for (int index = 0; index < worker_count; ++index) {
        extract_worker_state_t *worker = &run->workers[index];
        if (!worker->local_gbuf) {
            continue;
        }
        cbm_gbuf_merge(pipeline->gbuf, worker->local_gbuf);
        totals.nodes += worker->nodes_created;
        totals.errors += worker->errors;
        cbm_gbuf_free(worker->local_gbuf);
    }
    CBM_PROF_END_N("parallel_extract", "4_merge_gbufs_seq", merged, totals.nodes);
    return totals;
}

static void pp_extract_merge_errors(cbm_pipeline_ctx_t *pipeline, pp_err_list_t *error_lists,
                                    int worker_count) {
    if (!error_lists) {
        return;
    }
    for (int worker_index = 0; worker_index < worker_count; ++worker_index) {
        pp_err_list_t *errors = &error_lists[worker_index];
        for (int error_index = 0; error_index < errors->count; ++error_index) {
            cbm_file_error_t *error = &errors->items[error_index];
            cbm_pipeline_add_file_error(pipeline->pipeline, error->path, error->reason,
                                        error->phase);
            free(error->path);
            free(error->reason);
            free(error->phase);
        }
        free(errors->items);
    }
    free(error_lists);
}

static void pp_extract_run_free(cbm_pipeline_ctx_t *pipeline, pp_extract_run_t *run,
                                int worker_count) {
    merge_pkg_entries(pipeline, run->pkg_entries, worker_count);
    cbm_aligned_free(run->workers);
    free(run->sorted);
    cbm_macro_table_free(run->macro_table);
}

int cbm_parallel_extract_ex(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count,
                            CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                            int worker_count, const cbm_parallel_extract_opts_t *opts) {
    cbm_parallel_extract_opts_t resolved_opts = cbm_parallel_extract_resolve_opts(opts);
    if (file_count == 0) {
        return 0;
    }
    pp_extract_log_start(file_count, worker_count, &resolved_opts);
    pp_extract_run_t run = {0};
    if (!pp_extract_run_prepare(&run, ctx, files, file_count, result_cache, shared_ids,
                                worker_count, &resolved_opts)) {
        return CBM_NOT_FOUND;
    }
    pp_extract_dispatch(&run, file_count, worker_count);
    pp_extract_totals_t totals = pp_extract_merge_workers(ctx, &run, worker_count);
    pp_extract_merge_errors(ctx, run.err_lists, worker_count);
    pp_extract_run_free(ctx, &run, worker_count);
    if (atomic_load(ctx->cancelled)) {
        return CBM_NOT_FOUND;
    }
    log_extract_mem_stats(worker_count);
    cbm_log_info("parallel.extract.done", "nodes", itoa_log(totals.nodes), "errors",
                 itoa_log(totals.errors));
    return 0;
}

int cbm_parallel_extract(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count,
                         CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                         int worker_count) {
    return cbm_parallel_extract_ex(ctx, files, file_count, result_cache, shared_ids, worker_count,
                                   NULL);
}

/* ── Phase 3B: Serial Registry Build ─────────────────────────────── */

/* Register one definition and create DEFINES + DEFINES_METHOD edges. Returns edge count. */
static int register_and_link_def(cbm_pipeline_ctx_t *ctx, const CBMDefinition *def, const char *rel,
                                 int *reg_entries) {
    int edges = 0;
    if (!def->name || !def->qualified_name || !def->label) {
        return 0;
    }
    /* Register callable symbols + every type-like container (Class/Struct/
     * Interface/Enum/Type/Trait) — see pass_definitions.c for rationale. Struct
     * included so Rust/Go/Swift/D structs resolve as type targets. Variable/Field
     * defs are registered too so READS/WRITES can resolve.
     * KEEP IN SYNC with pass_definitions.c and pipeline_incremental.c. */
    if (strcmp(def->label, "Function") == 0 || strcmp(def->label, "Method") == 0 ||
        cbm_label_is_type_like(def->label) || strcmp(def->label, "Variable") == 0 ||
        strcmp(def->label, "Field") == 0) {
        cbm_registry_add(ctx->registry, def->name, def->qualified_name, def->label);
        (*reg_entries)++;
    }
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
    const cbm_gbuf_node_t *file_node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
    const cbm_gbuf_node_t *def_node = cbm_gbuf_find_by_qn(ctx->gbuf, def->qualified_name);
    if (file_node && def_node) {
        cbm_gbuf_insert_edge_props(
            ctx->gbuf, (cbm_edge_endpoints_t){.source = file_node->id, .target = def_node->id},
            "DEFINES", NULL, 0);
        edges++;
    }
    free(file_qn);
    if (def->parent_class && strcmp(def->label, "Method") == 0) {
        const cbm_gbuf_node_t *parent = cbm_gbuf_find_by_qn(ctx->gbuf, def->parent_class);
        if (parent && def_node) {
            cbm_gbuf_insert_edge_props(
                ctx->gbuf, (cbm_edge_endpoints_t){.source = parent->id, .target = def_node->id},
                "DEFINES_METHOD", NULL, 0);
        }
    }
    return edges;
}

/* Create IMPORTS edges for one file's imports (parallel path). */
static int create_imports_edges(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result,
                                const char *rel, CBMHashTable *namespace_map) {
    int count = 0;
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
    const cbm_gbuf_node_t *source_node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
    if (!source_node) {
        free(file_qn);
        return 0;
    }
    for (int j = 0; j < result->imports.count; j++) {
        CBMImport *imp = &result->imports.items[j];
        if (!imp->module_path) {
            continue;
        }
        const cbm_gbuf_node_t *target =
            cbm_pipeline_resolve_import_node(ctx, rel, file_qn, imp, namespace_map);
        if (target && !cbm_node_id_eq(target->id, source_node->id)) {
            cbm_gbuf_prop_t imp_props[] = {
                {.key = "local_name",
                 .kind = CBM_EDGE_PROP_STRING,
                 .text = imp->local_name ? imp->local_name : ""},
            };
            cbm_gbuf_insert_edge_props(
                ctx->gbuf, (cbm_edge_endpoints_t){.source = source_node->id, .target = target->id},
                "IMPORTS", imp_props, (int)(sizeof(imp_props) / sizeof(imp_props[0])));
            count++;
        }
    }
    free(file_qn);
    return count;
}

/* Find channel source node (enclosing function or file). */
static const cbm_gbuf_node_t *find_channel_src(cbm_pipeline_ctx_t *ctx, const CBMChannel *ch,
                                               const char *rel) {
    const cbm_gbuf_node_t *node = NULL;
    if (ch->enclosing_func_qn && ch->enclosing_func_qn[0]) {
        node = cbm_gbuf_find_by_qn(ctx->gbuf, ch->enclosing_func_qn);
    }
    if (!node) {
        char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
        node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
        free(file_qn);
    }
    return node;
}

/* Create Channel nodes + EMITS/LISTENS_ON edges for one file. */
static void create_channel_edges(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result,
                                 const char *rel) {
    for (int j = 0; j < result->channels.count; j++) {
        CBMChannel *ch = &result->channels.items[j];
        if (!ch->channel_name || !ch->channel_name[0]) {
            continue;
        }
        char channel_qn[CBM_SZ_512];
        snprintf(channel_qn, sizeof(channel_qn), "__channel__%s__%s",
                 ch->transport ? ch->transport : "unknown", ch->channel_name);
        char esc_cn[CBM_SZ_256];
        cbm_json_escape(esc_cn, sizeof(esc_cn), ch->channel_name);
        char channel_props[CBM_SZ_512];
        snprintf(channel_props, sizeof(channel_props), "{\"transport\":\"%s\",\"name\":\"%s\"}",
                 ch->transport ? ch->transport : "unknown", esc_cn);
        cbm_node_id_t channel_id = cbm_gbuf_upsert_node(ctx->gbuf, "Channel", ch->channel_name,
                                                        channel_qn, "", 0, 0, channel_props);
        const cbm_gbuf_node_t *src_node = find_channel_src(ctx, ch, rel);
        if (src_node && cbm_node_id_valid(channel_id)) {
            const char *edge_type = ch->direction == CBM_CHANNEL_EMIT ? "EMITS" : "LISTENS_ON";
            cbm_gbuf_prop_t edge_props[] = {
                {.key = "transport",
                 .kind = CBM_EDGE_PROP_STRING,
                 .text = ch->transport ? ch->transport : "unknown"},
            };
            cbm_gbuf_insert_edge_props(
                ctx->gbuf, (cbm_edge_endpoints_t){.source = src_node->id, .target = channel_id},
                edge_type, edge_props, (int)(sizeof(edge_props) / sizeof(edge_props[0])));
        }
    }
}

int cbm_build_registry_from_cache(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                  int file_count, CBMFileResult **result_cache) {
    cbm_log_info("parallel.registry.start", "files", itoa_log(file_count));

    int reg_entries = 0;
    int defines_edges = 0;
    int imports_edges = 0;

    /* Namespace/package → File-QN map for namespace imports (C# `using`,
     * Java/Kotlin `import`, PHP `use`). Built from the full result cache so
     * every declaring file is visible regardless of loop order. */
    const char **rels = (const char **)calloc((size_t)file_count, sizeof(char *));
    if (rels) {
        for (int i = 0; i < file_count; i++) {
            rels[i] = files[i].rel_path;
        }
    }
    CBMHashTable *namespace_map =
        cbm_pipeline_namespace_map_build(ctx->project_name, result_cache, rels, file_count);
    free(rels);

    for (int i = 0; i < file_count; i++) {
        if (cbm_pipeline_check_cancel(ctx)) {
            cbm_pipeline_namespace_map_free(namespace_map);
            return CBM_NOT_FOUND;
        }

        CBMFileResult *result = result_cache[i];
        if (!result) {
            continue;
        }

        const char *rel = files[i].rel_path;

        /* Register callable symbols + DEFINES/DEFINES_METHOD edges */
        for (int d = 0; d < result->defs.count; d++) {
            defines_edges += register_and_link_def(ctx, &result->defs.items[d], rel, &reg_entries);
        }

        imports_edges += create_imports_edges(ctx, result, rel, namespace_map);
        create_channel_edges(ctx, result, rel);
        cbm_pipeline_create_env_configures_for_file(ctx, result, rel);
    }

    cbm_pipeline_namespace_map_free(namespace_map);

    cbm_log_info("parallel.registry.done", "entries", itoa_log(reg_entries), "defines",
                 itoa_log(defines_edges), "imports", itoa_log(imports_edges));
    return 0;
}

/* ── Phase 4: Parallel Resolution ────────────────────────────────── */

typedef struct __attribute__((aligned(CBM_CACHE_LINE))) {
    cbm_gbuf_t *local_edge_buf;
    int calls_resolved;
    int usages_resolved;
    int semantic_resolved;
    int errors;
    /* Subset of calls_resolved that were attributed via the LSP-override
     * path (cbm_pipeline_find_lsp_resolution hit) rather than the
     * registry's textual matcher. Surfaced in the parallel.resolve.done
     * log line so divergence between pipelines becomes observable. */
    int lsp_overrides;
    char _pad[CBM_CACHE_LINE - sizeof(cbm_gbuf_t *) - ((PP_RING + SKIP_ONE) * sizeof(int))];
} resolve_worker_state_t;

typedef struct {
    const cbm_file_info_t *files;
    int file_count;
    const char *project_name;
    const char *repo_path;

    resolve_worker_state_t *workers;
    int max_workers;

    CBMFileResult **result_cache;
    const cbm_gbuf_t *main_gbuf;    /* READ-ONLY during Phase 4 */
    const cbm_registry_t *registry; /* READ-ONLY during Phase 4 */
    _Atomic int64_t *shared_ids;
    _Atomic int *cancelled;
    _Atomic int next_file_idx;

    /* Cross-file LSP inputs — pre-built once by the caller in pipeline.c
     * and shared read-only by usage across workers (typed non-const to
     * match the existing cbm_run_X_lsp_cross callee signatures the
     * worker forwards them to). NULL/0 → cross-LSP no-ops. */
    CBMLSPDef *all_defs;
    int def_count;
    char *const *def_modules; /* per-file module QN; def_modules[i] for files[i] */
    /* Optional inverted index for per-file def filtering (gopls pattern).
     * When non-NULL, the fused worker calls cbm_pxc_filter_defs_for_file
     * to shrink the def array passed to the LSP from O(all_defs) to
     * O(relevant_defs). NULL → each file sees the full all_defs[]. */
    struct CBMModuleDefIndex *module_def_index;
    /* Tier 2 full: pre-built per-language registries (project-wide,
     * finalized, READ-ONLY). When non-NULL for a lang, the worker uses
     * cbm_run_X_lsp_cross_with_registry — skip per-file build entirely.
     * Stored as CBMCrossLspRegistries* (typedef from pass_lsp_cross.h). */
    CBMCrossLspRegistries *cross_registries;

    /* F4: LAZILY-built shared Rust registry (built ONCE, on the first NULL-filter
     * rust file — the ~all_defs amplifier files). Not eager: repos whose rust files
     * all filter to subsets never pay the O(all_defs) build + multi-GB RSS. Built
     * under rust_shared_mu into rust_shared_arena, published via rust_shared_reg;
     * torn down after the worker dispatch. */
    _Atomic(CBMTypeRegistry *) rust_shared_reg;
    cbm_mutex_t rust_shared_mu;
    CBMArena rust_shared_arena;
    bool rust_shared_arena_live;

    /* Counters for parallel.resolve.lsp_cross_done summary. */
    _Atomic int lsp_cross_processed;
    _Atomic int lsp_cross_skipped_no_source;

    /* Per-sub-phase timing (ns aggregated across workers) — surfaces
     * exactly where parallel_resolve's wall time is spent so we stop
     * guessing about hot paths. Logged once at the end of
     * cbm_parallel_resolve. */
    _Atomic uint64_t time_ns_import_map;
    _Atomic uint64_t time_ns_cross_lsp;
    _Atomic uint64_t time_ns_calls;
    _Atomic uint64_t time_ns_usages;
    _Atomic uint64_t time_ns_throws;
    _Atomic uint64_t time_ns_rw;
    _Atomic uint64_t time_ns_semantic;
    /* Whole-iteration timer — captures everything from atomic file_idx
     * pickup through cleanup. If this >> sum of sub-phases, the
     * unmeasured cost is either in skip-eligibility checks, gbuf
     * setup, or — most likely — workers waiting on the
     * cbm_parallel_for synchronization barrier at the end. */
    _Atomic uint64_t time_ns_total_loop;
    _Atomic int total_files_visited;
    /* Sub-breakdowns inside resolve_file_calls — finds the 553µs-per-
     * iteration hot path that the high-level resolve_calls counter
     * doesn't pinpoint. */
    _Atomic uint64_t time_ns_rc_lsp_lookup; /* lsp_idx + fallback scan */
    _Atomic uint64_t time_ns_rc_resolve;    /* lsp_target_node OR registry_resolve */
    _Atomic uint64_t time_ns_rc_hint;       /* try_field_type_hint */
    _Atomic uint64_t time_ns_rc_target;     /* gbuf_find_by_qn for target */
    _Atomic uint64_t time_ns_rc_emit;       /* emit_service_edge */
    _Atomic uint64_t time_ns_rc_source;     /* find_source_node */
} resolve_ctx_t;

/* Minimum buffer space needed per arg JSON object */
#define CBM_ARG_JSON_GUARD CBM_SZ_32

/* Append arg data as JSON to edge properties: ,"args":[{"i":0,"e":"x","v":"val"},...]
 * Returns new position in buffer. */
/* Sanitize expression string for JSON (in-place). */
static void sanitize_expr(char *expr_buf, const char *expr) {
    if (expr) {
        snprintf(expr_buf, 128, "%.*s", 120, expr);
        for (char *p = expr_buf; *p; p++) {
            if (*p == '"') {
                *p = '\'';
            }
            if (*p == '\n' || *p == '\r') {
                *p = ' ';
            }
        }
    } else {
        expr_buf[0] = '\0';
    }
}

/* Format one call arg as JSON. Returns snprintf result. */
static int format_call_arg(char *buf, size_t bufsize, const CBMCallArg *a, const char *expr) {
    char esc_k[CBM_SZ_128];
    char esc_e[CBM_SZ_128];
    char esc_v[CBM_SZ_128];
    cbm_json_escape(esc_e, sizeof(esc_e), expr);
    if (a->keyword && a->value) {
        cbm_json_escape(esc_k, sizeof(esc_k), a->keyword);
        cbm_json_escape(esc_v, sizeof(esc_v), a->value);
        return snprintf(buf, bufsize, "{\"i\":%d,\"k\":\"%s\",\"e\":\"%s\",\"v\":\"%s\"}", a->index,
                        esc_k, esc_e, esc_v);
    }
    if (a->keyword) {
        cbm_json_escape(esc_k, sizeof(esc_k), a->keyword);
        return snprintf(buf, bufsize, "{\"i\":%d,\"k\":\"%s\",\"e\":\"%s\"}", a->index, esc_k,
                        esc_e);
    }
    if (a->value) {
        cbm_json_escape(esc_v, sizeof(esc_v), a->value);
        return snprintf(buf, bufsize, "{\"i\":%d,\"e\":\"%s\",\"v\":\"%s\"}", a->index, esc_e,
                        esc_v);
    }
    return snprintf(buf, bufsize, "{\"i\":%d,\"e\":\"%s\"}", a->index, esc_e);
}

/* Build the call args as a standalone JSON array literal (e.g.
 * [{"i":0,"e":"x","v":"val"},...]) into buf. The literal is carried as a
 * CBM_EDGE_PROP_STRING whose leading '[' tells the serializer to emit it
 * verbatim instead of JSON-string-escaping it. Returns the literal's length,
 * or 0 when the call has no args (no "args" prop should be emitted). */
static size_t build_args_json(char *buf, size_t bufsize, const CBMCall *call) {
    if (call->arg_count == 0 || bufsize < PP_ARGS_MARGIN) {
        return 0;
    }
    size_t pos = 0;
    buf[pos++] = '[';
    for (int i = 0; i < call->arg_count && pos < bufsize - CBM_ARG_JSON_GUARD; i++) {
        const CBMCallArg *a = &call->args[i];
        size_t mark = pos; /* rollback point (before the separator) */
        if (i > 0 && pos < bufsize - SKIP_ONE) {
            buf[pos++] = ',';
        }
        char expr_buf[CBM_SZ_128];
        sanitize_expr(expr_buf, a->expr);
        int n = format_call_arg(buf + pos, bufsize - pos, a, expr_buf);
        /* snprintf returns the UNtruncated length: if the arg did not fully
         * fit, advancing pos by n would push it past buf and the buf[pos]
         * writes below would overflow. Drop the arg whole (atomic field —
         * keeps the array valid) and stop appending. */
        if (n <= 0 || (size_t)n >= bufsize - pos) {
            pos = mark;
            break;
        }
        pos += (size_t)n;
    }
    if (pos < bufsize - SKIP_ONE) {
        buf[pos++] = ']';
    }
    buf[pos] = '\0';
    return pos;
}

/* Scan call args for a URL-like route path and handler reference. */
static bool is_path_keyword(const char *keyword) {
    static const char *path_keywords[] = {"prefix",     "path",     "route", "pattern",
                                          "url",        "endpoint", "rule",  "mount_path",
                                          "route_path", "url_path", NULL};
    for (const char **kw = path_keywords; *kw; kw++) {
        if (strcmp(keyword, *kw) == 0) {
            return true;
        }
    }
    return false;
}

static const char *find_route_path_in_args(const CBMCall *call, const char **out_handler) {
    *out_handler = NULL;
    /* 1. First string arg starting with / */
    if (call->first_string_arg && call->first_string_arg[0] == '/') {
        *out_handler = call->second_arg_name;
        return call->first_string_arg;
    }
    /* 2. Keyword args (prefix=, path=, route=, etc.) */
    const char *found = NULL;
    for (int ai = 0; ai < call->arg_count && !found; ai++) {
        const CBMCallArg *ca = &call->args[ai];
        const char *val = ca->value ? ca->value : ca->expr;
        if (!val || val[0] != '/') {
            continue;
        }
        if ((ca->keyword && is_path_keyword(ca->keyword)) || (!ca->keyword && ca->index == 0)) {
            found = val;
        }
    }
    if (!found) {
        return NULL;
    }
    /* 3. Handler: first identifier arg that's not a path/keyword */
    for (int ai = 0; ai < call->arg_count; ai++) {
        const CBMCallArg *ca = &call->args[ai];
        if (!ca->expr || ca->expr[0] == '/' || ca->expr[0] == '"' || ca->expr[0] == '\'') {
            continue;
        }
        if (ca->keyword && (strcmp(ca->keyword, "prefix") == 0 ||
                            strcmp(ca->keyword, "name") == 0 || strcmp(ca->keyword, "tags") == 0)) {
            continue;
        }
        *out_handler = ca->expr;
        break;
    }
    return found;
}

/* Append the "args" and (CALLS-only) "line" props to a caller-built typed
 * prop array, then emit the edge. props must have room for prop_count + 2
 * (callers size their arrays to PP_EDGE_PROPS_CAP). */
static void finalize_and_emit(cbm_gbuf_t *gbuf, cbm_node_id_t src_id, cbm_node_id_t tgt_id,
                              const char *edge_type, cbm_gbuf_prop_t *props, int prop_count,
                              const CBMCall *call) {
    char args_buf[CBM_SZ_2K];
    size_t args_len = build_args_json(args_buf, sizeof(args_buf), call);
    if (args_len > 0) {
        props[prop_count++] =
            (cbm_gbuf_prop_t){.key = "args", .kind = CBM_EDGE_PROP_STRING, .text = args_buf};
    }
    if (call->start_line > 0 && strcmp(edge_type, "CALLS") == 0) {
        props[prop_count++] = (cbm_gbuf_prop_t){
            .key = "line", .kind = CBM_EDGE_PROP_NUMBER, .number = call->start_line, .decimals = 0};
    }
    cbm_gbuf_insert_edge_props(gbuf, (cbm_edge_endpoints_t){.source = src_id, .target = tgt_id},
                               edge_type, props, prop_count);
}

/* Build Route node QN and properties for HTTP/async service edges. */
static cbm_node_id_t build_service_route(cbm_gbuf_t *gbuf, const char *arg, const char *method,
                                         const char *broker, cbm_svc_kind_t svc) {
    char route_qn[CBM_ROUTE_QN_SIZE];
    const char *prefix;
    char cpath[CBM_SZ_256];
    const char *qpath = arg;
    if (svc == CBM_SVC_HTTP) {
        prefix = method ? method : "ANY";
        qpath = cbm_route_canon_path(arg, cpath, sizeof(cpath));
    } else {
        prefix = broker ? broker : "async";
    }
    snprintf(route_qn, sizeof(route_qn), "__route__%s__%s", prefix, qpath);
    char route_props[CBM_SZ_256];
    if (method) {
        snprintf(route_props, sizeof(route_props), "{\"method\":\"%s\"}", method);
    } else if (broker) {
        snprintf(route_props, sizeof(route_props), "{\"broker\":\"%s\"}", broker);
    } else {
        snprintf(route_props, sizeof(route_props), "{}");
    }
    return cbm_gbuf_upsert_node(gbuf, "Route", arg, route_qn, "", 0, 0, route_props);
}

/* Emit HTTP_CALLS or ASYNC_CALLS edge via Route node. */
static void emit_http_async_service_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                                         const CBMCall *call, const cbm_resolution_t *res,
                                         cbm_svc_kind_t svc, const char *arg) {
    const char *edge_type = (svc == CBM_SVC_HTTP) ? "HTTP_CALLS" : "ASYNC_CALLS";
    const char *method =
        (svc == CBM_SVC_HTTP) ? cbm_service_pattern_http_method(call->callee_name) : NULL;
    const char *broker =
        (svc == CBM_SVC_ASYNC) ? cbm_service_pattern_broker(res->qualified_name) : NULL;

    cbm_node_id_t route_id = build_service_route(gbuf, arg, method, broker, svc);

    cbm_gbuf_prop_t props[PP_EDGE_PROPS_CAP];
    int pc = 0;
    props[pc++] =
        (cbm_gbuf_prop_t){.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name};
    props[pc++] = (cbm_gbuf_prop_t){.key = "url_path", .kind = CBM_EDGE_PROP_STRING, .text = arg};
    if (method) {
        props[pc++] =
            (cbm_gbuf_prop_t){.key = "method", .kind = CBM_EDGE_PROP_STRING, .text = method};
    }
    if (broker) {
        props[pc++] =
            (cbm_gbuf_prop_t){.key = "broker", .kind = CBM_EDGE_PROP_STRING, .text = broker};
    }
    finalize_and_emit(gbuf, source->id, route_id, edge_type, props, pc, call);
}

/* Emit CONFIGURES edge. */
static void emit_config_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                             const cbm_gbuf_node_t *target, const CBMCall *call,
                             const cbm_resolution_t *res, const char *arg) {
    /* emit_service_edge may be reached with target==NULL on the HTTP/ASYNC
     * external-client bypass (#523); a CONFIGURES edge needs a real target, so
     * never deref a NULL target here. */
    if (!target) {
        return;
    }
    cbm_gbuf_prop_t props[PP_EDGE_PROPS_CAP];
    int pc = 0;
    props[pc++] =
        (cbm_gbuf_prop_t){.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name};
    props[pc++] =
        (cbm_gbuf_prop_t){.key = "key", .kind = CBM_EDGE_PROP_STRING, .text = arg ? arg : ""};
    props[pc++] = (cbm_gbuf_prop_t){.key = "confidence",
                                    .kind = CBM_EDGE_PROP_NUMBER,
                                    .number = res->confidence,
                                    .decimals = PP_CONFIDENCE_DECIMALS};
    finalize_and_emit(gbuf, source->id, target->id, "CONFIGURES", props, pc, call);
}

/* Emit normal CALLS edge. */
static void emit_normal_calls_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                                   const cbm_gbuf_node_t *target, const CBMCall *call,
                                   const cbm_resolution_t *res) {
    /* A CALLS edge needs a real target; the HTTP/ASYNC external-client bypass
     * (#523) can reach emit_service_edge with target==NULL, so guard the deref. */
    if (!target) {
        return;
    }
    cbm_gbuf_prop_t props[PP_EDGE_PROPS_CAP];
    int pc = 0;
    props[pc++] =
        (cbm_gbuf_prop_t){.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name};
    props[pc++] = (cbm_gbuf_prop_t){.key = "confidence",
                                    .kind = CBM_EDGE_PROP_NUMBER,
                                    .number = res->confidence,
                                    .decimals = PP_CONFIDENCE_DECIMALS};
    props[pc++] = (cbm_gbuf_prop_t){.key = "strategy",
                                    .kind = CBM_EDGE_PROP_STRING,
                                    .text = res->strategy ? res->strategy : "unknown"};
    props[pc++] = (cbm_gbuf_prop_t){.key = "candidates",
                                    .kind = CBM_EDGE_PROP_NUMBER,
                                    .number = res->candidate_count,
                                    .decimals = 0};
    finalize_and_emit(gbuf, source->id, target->id, "CALLS", props, pc, call);
}

/* Classify a resolved call by library identity and emit the appropriate edge. */
/* Create Route node + CALLS + HANDLES edges for a route registration call. */
static void emit_route_registration(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                                    const CBMCall *call, const char *route_path,
                                    const char *handler_ref, const char *module_qn,
                                    const cbm_registry_t *registry, const cbm_gbuf_t *main_gbuf,
                                    const char **ik, const char **iv, int ic) {
    const char *method = cbm_service_pattern_route_method(call->callee_name);
    char rqn[CBM_ROUTE_QN_SIZE];
    char cpath[CBM_SZ_256];
    snprintf(rqn, sizeof(rqn), "__route__%s__%s", method ? method : "ANY",
             cbm_route_canon_path(route_path, cpath, sizeof(cpath)));
    char rp[CBM_SZ_256];
    snprintf(rp, sizeof(rp), "{\"method\":\"%s\"}", method ? method : "ANY");
    cbm_node_id_t rid = cbm_gbuf_upsert_node(gbuf, "Route", route_path, rqn, "", 0, 0, rp);
    cbm_gbuf_prop_t props[] = {
        {.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name},
        {.key = "url_path", .kind = CBM_EDGE_PROP_STRING, .text = route_path},
        {.key = "via", .kind = CBM_EDGE_PROP_STRING, .text = "route_registration"},
    };
    cbm_gbuf_insert_edge_props(gbuf, (cbm_edge_endpoints_t){.source = source->id, .target = rid},
                               "CALLS", props, (int)(sizeof(props) / sizeof(props[0])));
    if (handler_ref && handler_ref[0] != '\0') {
        cbm_resolution_t hres = cbm_registry_resolve(registry, handler_ref, module_qn, ik, iv, ic);
        if (hres.qualified_name && hres.qualified_name[0] != '\0') {
            const cbm_gbuf_node_t *h = cbm_gbuf_find_by_qn(main_gbuf, hres.qualified_name);
            if (h) {
                cbm_gbuf_prop_t hp[] = {
                    {.key = "handler", .kind = CBM_EDGE_PROP_STRING, .text = hres.qualified_name},
                };
                cbm_gbuf_insert_edge_props(gbuf,
                                           (cbm_edge_endpoints_t){.source = h->id, .target = rid},
                                           "HANDLES", hp, (int)(sizeof(hp) / sizeof(hp[0])));
            }
        }
    }
}

/* Reject regex metacharacters, spaces, double-slashes in URL candidates. */
static bool is_junk_url(const char *s) {
    for (int i = 0; s[i]; i++) {
        char ch = s[i];
        if (ch == '\\' || ch == '^' || ch == '$' || ch == '*' || ch == '+' || ch == '(' ||
            ch == ')' || ch == '[' || ch == ']' || ch == '|' || ch == ' ') {
            return true;
        }
        if (ch == '/' && i > 0 && s[i - SKIP_ONE] == '/') {
            return true;
        }
    }
    return false;
}

/* Normalize a template literal URL and reject junk patterns.
 * Returns true if norm contains a valid API path. */
static bool normalize_url_arg(const char *url, char *norm, int norm_sz) {
    int ni = 0;
    const char *p = url;
    if (*p == '`' || *p == '"' || *p == '\'') {
        p++;
    }
    if (*p != '/') {
        return false;
    }
    while (*p && ni < norm_sz - PAIR_LEN) {
        if (*p == '$' && *(p + SKIP_ONE) == '{') {
            norm[ni++] = ':';
            p += PAIR_LEN;
            while (*p && *p != '}' && ni < norm_sz - PAIR_LEN) {
                norm[ni++] = *p++;
            }
            if (*p == '}') {
                p++;
            }
        } else if (*p == '`' || *p == '"' || *p == '\'' || *p == '?') {
            break;
        } else {
            norm[ni++] = *p++;
        }
    }
    norm[ni] = '\0';
    enum { MIN_URL_LEN = 4 };
    if (ni < MIN_URL_LEN || !strchr(norm + SKIP_ONE, '/')) {
        return false;
    }
    return !is_junk_url(norm);
}

/* Detect API paths in call arguments and create HTTP_CALLS edges. */
static void detect_url_in_args(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                               const CBMCall *call) {
    for (int ai = 0; ai < call->arg_count; ai++) {
        const CBMCallArg *ca = &call->args[ai];
        const char *url = ca->value ? ca->value : ca->expr;
        if (!url || (url[0] != '/' && url[0] != '`')) {
            continue;
        }
        char norm[CBM_SZ_256];
        if (!normalize_url_arg(url, norm, (int)sizeof(norm))) {
            continue;
        }
        char route_qn[CBM_ROUTE_QN_SIZE];
        char cpath[CBM_SZ_256];
        snprintf(route_qn, sizeof(route_qn), "__route__ANY__%s",
                 cbm_route_canon_path(norm, cpath, sizeof(cpath)));
        cbm_node_id_t route_id = cbm_gbuf_upsert_node(gbuf, "Route", norm, route_qn, "", 0, 0,
                                                      "{\"source\":\"arg_url\"}");
        cbm_gbuf_prop_t eprops[] = {
            {.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name},
            {.key = "url_path", .kind = CBM_EDGE_PROP_STRING, .text = norm},
            {.key = "via", .kind = CBM_EDGE_PROP_STRING, .text = "arg_url"},
        };
        cbm_gbuf_insert_edge_props(gbuf,
                                   (cbm_edge_endpoints_t){.source = source->id, .target = route_id},
                                   "HTTP_CALLS", eprops, (int)(sizeof(eprops) / sizeof(eprops[0])));
        break;
    }
}

/* Extract gRPC service and method from a callee name.
 * Handles patterns like: pb.NewFooServiceClient(conn).GetBar → Foo/GetBar
 * Also: FooServiceGrpc.newBlockingStub(ch).getBar → FooService/getBar */
bool extract_grpc_service_method(const char *callee, char *service, size_t srv_sz, char *method,
                                 size_t meth_sz) {
    service[0] = '\0';
    method[0] = '\0';
    if (!callee) {
        return false;
    }
    /* Find last dot to split service.Method */
    const char *last_dot = strrchr(callee, '.');
    if (!last_dot || !last_dot[SKIP_ONE]) {
        return false;
    }
    snprintf(method, meth_sz, "%s", last_dot + SKIP_ONE);

    /* Extract service name: everything before the last dot, stripped of prefixes/suffixes */
    size_t prefix_len = (size_t)(last_dot - callee);
    char raw[CBM_SZ_256];
    if (prefix_len >= sizeof(raw)) {
        prefix_len = sizeof(raw) - SKIP_ONE;
    }
    memcpy(raw, callee, prefix_len);
    raw[prefix_len] = '\0';

    /* Strip common prefixes: pb.New, New, pb. */
    const char *s = raw;
    if (strncmp(s, "pb.New", CBM_SZ_6) == 0) {
        s += CBM_SZ_6;
    } else if (strncmp(s, "pb.", CBM_SZ_3) == 0 || strncmp(s, "New", CBM_SZ_3) == 0) {
        s += CBM_SZ_3;
    }

    /* Strip the generated-stub/client suffix, preserving the canonical
     * proto-declared service name. The proto service is `<X>Service`; the
     * generated client is `<X>ServiceClient` / `<X>ServiceGrpc`, so we strip
     * only the trailing stub/client token (Client/Stub/Grpc/…), NOT "Service"
     * itself — stripping "ServiceClient" yielded `<X>` and broke cross-repo
     * matching against the `<X>Service` declared name (#294). Longest tokens
     * first so e.g. BlockingStub wins over Stub.
     *
     * A match also serves as the gRPC stub-type signal: we ONLY emit a Route
     * when a recognized suffix is actually present. Without this gate the
     * fallback turned ordinary receiver vars (`_provider.GetGroup`,
     * `_builder.AddSomeService`) into phantom `__grpc__provider/...` Routes
     * that correspond to no .proto anywhere (#294). */
    snprintf(service, srv_sz, "%s", s);
    size_t slen = strlen(service);
    static const char *const suffixes[] = {"BlockingStub", "FutureStub", "AsyncStub",
                                           "AsyncClient",  "Servicer",   "Client",
                                           "Stub",         "Grpc",       NULL};
    bool stripped = false;
    for (const char *const *sfx = suffixes; *sfx; sfx++) {
        size_t flen = strlen(*sfx);
        if (slen > flen && strcmp(service + slen - flen, *sfx) == 0) {
            service[slen - flen] = '\0';
            stripped = true;
            break;
        }
    }

    return stripped && service[0] && method[0];
}

/* Emit GRPC_CALLS edge via gRPC Route node. */
static void emit_grpc_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source, const CBMCall *call,
                           const cbm_resolution_t *res) {
    char service[CBM_SZ_256];
    char method[CBM_SZ_256];
    /* Try callee_name first (e.g., "pb.NewCartServiceClient.GetCart") */
    if (!extract_grpc_service_method(call->callee_name, service, sizeof(service), method,
                                     sizeof(method))) {
        /* Fallback: try the resolved QN for Go chained calls.
         * Go pattern: pb.NewCartServiceClient(conn).GetCart(ctx, req)
         * callee_name = "GetCart", QN = "...CartServiceClient.GetCart"
         * The QN contains the full ServiceClient.Method pattern. */
        if (!res->qualified_name ||
            !extract_grpc_service_method(res->qualified_name, service, sizeof(service), method,
                                         sizeof(method))) {
            return;
        }
    }

    char route_qn[CBM_SZ_512];
    snprintf(route_qn, sizeof(route_qn), "__grpc__%s/%s", service, method);

    char route_name[CBM_SZ_256];
    snprintf(route_name, sizeof(route_name), "%s/%s", service, method);

    cbm_node_id_t route_id = cbm_gbuf_upsert_node(gbuf, "Route", route_name, route_qn, "", 0, 0,
                                                  "{\"source\":\"grpc\"}");

    cbm_gbuf_prop_t props[] = {
        {.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name},
        {.key = "service", .kind = CBM_EDGE_PROP_STRING, .text = service},
        {.key = "method", .kind = CBM_EDGE_PROP_STRING, .text = method},
        {.key = "confidence",
         .kind = CBM_EDGE_PROP_NUMBER,
         .number = res->confidence,
         .decimals = PP_CONFIDENCE_DECIMALS},
    };
    cbm_gbuf_insert_edge_props(gbuf,
                               (cbm_edge_endpoints_t){.source = source->id, .target = route_id},
                               "GRPC_CALLS", props, (int)(sizeof(props) / sizeof(props[0])));
}

/* Emit GRAPHQL_CALLS edge. Extract operation from first string arg if available. */
static void emit_graphql_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source, const CBMCall *call,
                              const cbm_resolution_t *res) {
    const char *op = call->first_string_arg;
    if (!op || !op[0]) {
        op = call->callee_name;
    }
    /* Try to extract a query/mutation name from the operation string */
    char op_name[CBM_SZ_256];
    snprintf(op_name, sizeof(op_name), "%s", op);
    /* Trim leading whitespace and "query "/"mutation " prefix */
    const char *p = op_name;
    while (*p == ' ' || *p == '\t' || *p == '\n') {
        p++;
    }
    if (strncmp(p, "query ", CBM_SZ_6) == 0) {
        p += CBM_SZ_6;
    } else if (strncmp(p, "mutation ", CBM_SZ_8) == 0) {
        p += CBM_SZ_8;
    }

    char route_qn[CBM_SZ_512];
    snprintf(route_qn, sizeof(route_qn), "__graphql__%s", p);

    cbm_node_id_t route_id =
        cbm_gbuf_upsert_node(gbuf, "Route", p, route_qn, "", 0, 0, "{\"source\":\"graphql\"}");

    cbm_gbuf_prop_t props[] = {
        {.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name},
        {.key = "operation", .kind = CBM_EDGE_PROP_STRING, .text = p},
        {.key = "confidence",
         .kind = CBM_EDGE_PROP_NUMBER,
         .number = res->confidence,
         .decimals = PP_CONFIDENCE_DECIMALS},
    };
    cbm_gbuf_insert_edge_props(gbuf,
                               (cbm_edge_endpoints_t){.source = source->id, .target = route_id},
                               "GRAPHQL_CALLS", props, (int)(sizeof(props) / sizeof(props[0])));
}

/* Emit TRPC_CALLS edge. Extract procedure path from callee chain. */
static void emit_trpc_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source, const CBMCall *call,
                           const cbm_resolution_t *res) {
    /* tRPC calls: trpc.user.getById.query() → extract "user.getById" */
    const char *callee = call->callee_name;
    if (!callee) {
        return;
    }
    /* Strip trailing .query/.mutate/.subscribe */
    char proc[CBM_SZ_256];
    snprintf(proc, sizeof(proc), "%s", callee);
    char *last_dot = strrchr(proc, '.');
    if (last_dot && (strcmp(last_dot, ".query") == 0 || strcmp(last_dot, ".mutate") == 0 ||
                     strcmp(last_dot, ".subscribe") == 0 || strcmp(last_dot, ".useQuery") == 0 ||
                     strcmp(last_dot, ".useMutation") == 0)) {
        *last_dot = '\0';
    }
    /* Strip leading trpc. */
    const char *p = proc;
    if (strncmp(p, "trpc.", CBM_SZ_5) == 0) {
        p += CBM_SZ_5;
    }

    char route_qn[CBM_SZ_512];
    snprintf(route_qn, sizeof(route_qn), "__trpc__%s", p);

    cbm_node_id_t route_id =
        cbm_gbuf_upsert_node(gbuf, "Route", p, route_qn, "", 0, 0, "{\"source\":\"trpc\"}");

    cbm_gbuf_prop_t props[] = {
        {.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = call->callee_name},
        {.key = "procedure", .kind = CBM_EDGE_PROP_STRING, .text = p},
        {.key = "confidence",
         .kind = CBM_EDGE_PROP_NUMBER,
         .number = res->confidence,
         .decimals = PP_CONFIDENCE_DECIMALS},
    };
    cbm_gbuf_insert_edge_props(gbuf,
                               (cbm_edge_endpoints_t){.source = source->id, .target = route_id},
                               "TRPC_CALLS", props, (int)(sizeof(props) / sizeof(props[0])));
}

/* When suppress_plain_calls is true (a TS/JS/TSX weak short-name member-call
 * match, #592/#606), every service classification below still runs — only the
 * plain CALLS fall-through (emit_normal_calls_edge) is skipped. detect_url_in_args
 * and the HTTP/ASYNC/gRPC/GraphQL/tRPC/CONFIG/route branches are unaffected, so
 * a verb-suffix HTTP client (api.patch('/x')), broker, or route registration
 * keeps its edge; only the fabricated project CALLS edge is dropped. */
static void emit_service_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                              const cbm_gbuf_node_t *target, const CBMCall *call,
                              const cbm_resolution_t *res, const char *module_qn,
                              const cbm_registry_t *registry, const cbm_gbuf_t *main_gbuf,
                              const char **imp_keys, const char **imp_vals, int imp_count,
                              bool suppress_plain_calls) {
    cbm_svc_kind_t svc = cbm_service_pattern_match(res->qualified_name);
    const char *arg = call->first_string_arg;

    /* Also detect route registration by callee name suffix alone (handles unresolved
     * local variables like app.include_router where QN resolution fails). */
    if (svc == CBM_SVC_NONE && cbm_service_pattern_route_method(call->callee_name) != NULL) {
        svc = CBM_SVC_ROUTE_REG;
    }

    /* Detect gRPC stub method calls by resolved QN.
     * Go pattern: pb.NewCartServiceClient(conn).GetCart(ctx, req)
     * Tree-sitter extracts GetCart as the callee, which resolves to the
     * generated pb interface method (QN contains "ServiceClient"). */
    if (svc == CBM_SVC_NONE && res->qualified_name) {
        if (strstr(res->qualified_name, "ServiceClient") != NULL ||
            strstr(res->qualified_name, "ServiceGrpc") != NULL ||
            strstr(res->qualified_name, "Servicer") != NULL) {
            svc = CBM_SVC_GRPC;
        }
    }

    if (svc == CBM_SVC_ROUTE_REG) {
        const char *handler_ref = NULL;
        const char *route_path = find_route_path_in_args(call, &handler_ref);
        if (route_path) {
            emit_route_registration(gbuf, source, call, route_path, handler_ref, module_qn,
                                    registry, main_gbuf, imp_keys, imp_vals, imp_count);
            return;
        }
        /* No path found — fall through to normal CALLS edge */
    }

    bool has_url = (arg && arg[0] != '\0' && (arg[0] == '/' || strstr(arg, "://") != NULL));
    bool has_topic = (arg && arg[0] != '\0' && svc == CBM_SVC_ASYNC && strlen(arg) > PP_ESC_SPACE);

    if ((svc == CBM_SVC_HTTP || svc == CBM_SVC_ASYNC) && (has_url || has_topic)) {
        emit_http_async_service_edge(gbuf, source, call, res, svc, arg);
    } else if (svc == CBM_SVC_GRPC) {
        emit_grpc_edge(gbuf, source, call, res);
    } else if (svc == CBM_SVC_GRAPHQL) {
        emit_graphql_edge(gbuf, source, call, res);
    } else if (svc == CBM_SVC_TRPC) {
        emit_trpc_edge(gbuf, source, call, res);
    } else if (svc == CBM_SVC_CONFIG) {
        emit_config_edge(gbuf, source, target, call, res, arg);
    } else if (!suppress_plain_calls) {
        emit_normal_calls_edge(gbuf, source, target, call, res);
    }

    detect_url_in_args(gbuf, source, call);
}

/* Find the source node for an edge: enclosing function or file node. */
static const cbm_gbuf_node_t *find_source_node(const cbm_gbuf_t *gbuf, const char *project,
                                               const char *rel, const char *enclosing_qn) {
    const cbm_gbuf_node_t *src = NULL;
    if (enclosing_qn) {
        src = cbm_gbuf_find_by_qn(gbuf, enclosing_qn);
        /* A class-level reference in a directory-module language carries the
         * DIRECTORY module QN, which hits the shared Folder/Project node —
         * attribute to this file's File node instead (#787). */
        if (cbm_pipeline_node_is_dir_container(src)) {
            src = NULL;
        }
    }
    if (!src) {
        char *file_qn = cbm_pipeline_fqn_compute(project, rel, "__file__");
        src = cbm_gbuf_find_by_qn(gbuf, file_qn);
        free(file_qn);
    }
    return src;
}

/* Field type hint resolution for obj.Method() with multiple candidates.
 * Strips C# field prefixes (_ / m_), capitalizes to get type name, and
 * checks if TypeName.Method or ITypeName.Method exists among candidates. */
static void try_field_type_hint(resolve_ctx_t *rc, cbm_resolution_t *res, const char *callee_name,
                                cbm_node_id_t source_id) {
    if (!res->qualified_name || res->candidate_count <= SKIP_ONE) {
        return;
    }
    const char *dot = strchr(callee_name, '.');
    if (!dot) {
        return;
    }
    size_t plen = (size_t)(dot - callee_name);
    char obj_name[CBM_SZ_256];
    if (plen >= sizeof(obj_name)) {
        return;
    }
    memcpy(obj_name, callee_name, plen);
    obj_name[plen] = '\0';

    const char *type_hint = obj_name;
    if (type_hint[0] == '_') {
        type_hint++;
    }
    if (type_hint[0] == 'm' && type_hint[SKIP_ONE] == '_') {
        type_hint += PP_CSHARP_M_PREFIX_LEN;
    }

    char type_name[CBM_SZ_256];
    snprintf(type_name, sizeof(type_name), "%s", type_hint);
    if (type_name[0] >= 'a' && type_name[0] <= 'z') {
        type_name[0] -= ('a' - 'A');
    }

    char iface_name[CBM_SZ_256];
    snprintf(iface_name, sizeof(iface_name), "I%s", type_name);

    const char *method = dot + SKIP_ONE;
    char *const *cands = NULL;
    int cand_count = 0;
    cbm_registry_find_by_name(rc->registry, method, &cands, &cand_count);
    for (int ci = 0; ci < cand_count; ci++) {
        if (strstr(cands[ci], type_name) || strstr(cands[ci], iface_name)) {
            const cbm_gbuf_node_t *better = cbm_gbuf_find_by_qn(rc->main_gbuf, cands[ci]);
            if (better && !cbm_node_id_eq(better->id, source_id)) {
                res->qualified_name = cands[ci];
                res->confidence = PP_FIELD_HINT_CONF;
                res->strategy = "field_type_hint";
                return;
            }
        }
    }
}

/* Free a strdup'd key stored in the per-file lsp_idx hash table. */
static void lsp_idx_free_key(const char *key, void *value, void *ud) {
    (void)value;
    (void)ud;
    safe_str_free(&key);
}

/* A hash key may have multiple semantic rows. Keep a permanent tombstone for
 * distinct targets so O(1) lookup cannot turn ambiguity into a confidence
 * contest; duplicate rows for the same target may still keep the best score. */
static CBMResolvedCall lsp_idx_ambiguous_record;
static CBMResolvedCall *const LSP_IDX_AMBIGUOUS = &lsp_idx_ambiguous_record;

static bool lsp_idx_keep_best(CBMHashTable *index, const char *key, CBMResolvedCall *candidate,
                              const cbm_gbuf_t *gbuf, const char *project_name,
                              bool allow_tail_match) {
    if (!index || !key || !candidate) {
        return false;
    }
    CBMResolvedCall *existing = (CBMResolvedCall *)cbm_ht_get(index, key);
    if (!existing) {
        char *owned_key = strdup(key);
        if (owned_key) {
            cbm_ht_set(index, owned_key, candidate);
            if (cbm_ht_get(index, key) == candidate) {
                return true;
            }
            free(owned_key);
        }
        return false;
    }
    if (existing == LSP_IDX_AMBIGUOUS) {
        return true;
    }
    if (!cbm_pipeline_invocation_targets_equal(existing->callee_qn, candidate->callee_qn, gbuf,
                                               project_name, allow_tail_match)) {
        const char *stored_key = cbm_ht_get_key(index, key);
        if (stored_key) {
            cbm_ht_set(index, stored_key, LSP_IDX_AMBIGUOUS);
        }
        return cbm_ht_get(index, key) != NULL;
    }
    if (candidate->confidence > existing->confidence) {
        const char *stored_key = cbm_ht_get_key(index, key);
        if (stored_key) {
            cbm_ht_set(index, stored_key, candidate);
        }
    }
    return cbm_ht_get(index, key) != NULL;
}

/* Caller QNs are user-controlled graph identifiers and can legitimately exceed
 * the old 1 KiB stack buffer. Build occurrence keys at their exact length so an
 * exact semantic row can never disappear merely because its caller is long. */
static char *lsp_idx_key(const char *caller_qn, const char *leaf, bool exact_site,
                         uint32_t site_start_byte, uint32_t site_end_byte,
                         CBMSourceOrigin source_origin) {
    if (!caller_qn || !leaf) {
        return NULL;
    }
    size_t caller_len = strlen(caller_qn);
    size_t leaf_len = strlen(leaf);
    size_t suffix_len =
        exact_site ? PP_LSP_INDEX_EXACT_SUFFIX_CAPACITY : PP_LSP_INDEX_LEGACY_SUFFIX_CAPACITY;
    if (caller_len >
        SIZE_MAX - leaf_len - suffix_len - PP_LSP_INDEX_DELIMITER_AND_TERMINATOR_BYTES) {
        return NULL;
    }
    size_t cap = caller_len + SKIP_ONE + leaf_len + suffix_len + SKIP_ONE;
    char *key = (char *)malloc(cap);
    if (!key) {
        return NULL;
    }
    int written = exact_site
                      ? snprintf(key, cap, "%s|%s|%u:%u|%u", caller_qn, leaf, site_start_byte,
                                 site_end_byte, (unsigned)source_origin)
                      : snprintf(key, cap, "%s|%s|%u", caller_qn, leaf, (unsigned)source_origin);
    if (written <= 0 || (size_t)written >= cap) {
        free(key);
        return NULL;
    }
    return key;
}

static bool lsp_idx_insert_leaf(CBMHashTable *index, CBMResolvedCall *candidate, const char *leaf,
                                bool exact_site, const cbm_gbuf_t *gbuf, const char *project_name,
                                bool allow_tail_match) {
    if (!index || !candidate || !candidate->caller_qn || !leaf || !leaf[0]) {
        return false;
    }
    char *key = lsp_idx_key(candidate->caller_qn, leaf, exact_site, candidate->site_start_byte,
                            candidate->site_end_byte, candidate->source_origin);
    if (!key) {
        return false;
    }
    bool inserted = lsp_idx_keep_best(index, key, candidate, gbuf, project_name, allow_tail_match);
    free(key);
    return inserted;
}

static const CBMResolvedCall *lsp_idx_lookup(const CBMHashTable *index, const CBMCall *call,
                                             bool exact_site, bool *key_built, bool *ambiguous) {
    if (key_built) {
        *key_built = false;
    }
    if (ambiguous) {
        *ambiguous = false;
    }
    if (!index || !call || !call->enclosing_func_qn || !call->callee_name) {
        return NULL;
    }
    const char *leaf = cbm_pipeline_call_callee_leaf(call->callee_name);
    if (!leaf || !leaf[0]) {
        return NULL;
    }
    char *key = lsp_idx_key(call->enclosing_func_qn, leaf, exact_site, call->site_start_byte,
                            call->site_end_byte, call->source_origin);
    if (!key) {
        return NULL;
    }
    if (key_built) {
        *key_built = true;
    }
    const CBMResolvedCall *candidate = (const CBMResolvedCall *)cbm_ht_get(index, key);
    free(key);
    if (candidate == LSP_IDX_AMBIGUOUS) {
        if (ambiguous) {
            *ambiguous = true;
        }
        return NULL;
    }
    if (!candidate || candidate->kind != CBM_RESOLVED_INVOCATION || !candidate->caller_qn ||
        strcmp(candidate->caller_qn, call->enclosing_func_qn) != 0 ||
        candidate->confidence < CBM_LSP_CONFIDENCE_FLOOR) {
        return NULL;
    }
    int site_rank = cbm_pipeline_invocation_site_rank(candidate, call);
    int expected_rank = exact_site ? CBM_LSP_SITE_RANK_EXACT : CBM_LSP_SITE_RANK_LEGACY;
    return site_rank == expected_rank &&
                   cbm_pipeline_invocation_leaf_matches(candidate, call, site_rank)
               ? candidate
               : NULL;
}

/* Resolve calls for one file and emit CALLS/HTTP_CALLS/ASYNC_CALLS edges. */
typedef struct {
    CBMHashTable *exact;
    CBMHashTable *legacy;
    bool exact_complete;
    bool legacy_complete;
    bool allow_tail;
} pp_lsp_call_indexes_t;

typedef struct {
    resolve_ctx_t *resolve;
    resolve_worker_state_t *worker;
    CBMFileResult *result;
    const char *relative_path;
    const char *module_qn;
    const char **import_keys;
    const char **import_values;
    int import_count;
    CBMLanguage language;
    const pp_lsp_call_indexes_t *lsp_indexes;
} pp_call_resolution_ctx_t;

typedef struct {
    cbm_resolution_t resolution;
    const cbm_gbuf_node_t *lsp_target;
    bool requires_lsp_target;
} pp_lsp_call_match_t;

typedef struct {
    const cbm_gbuf_node_t *source;
    const cbm_gbuf_node_t *lsp_target;
    cbm_resolution_t resolution;
    bool tsjs_drop_plain_call;
} pp_prepared_call_t;

static void pp_lsp_call_indexes_free(pp_lsp_call_indexes_t *indexes) {
    CBMHashTable *tables[] = {indexes->exact, indexes->legacy};
    for (size_t index = 0U; index < sizeof(tables) / sizeof(tables[0]); ++index) {
        if (tables[index]) {
            cbm_ht_foreach(tables[index], lsp_idx_free_key, NULL);
            cbm_ht_free(tables[index]);
        }
    }
}

static void pp_lsp_call_index_mark_incomplete(pp_lsp_call_indexes_t *indexes, bool exact_site) {
    if (exact_site) {
        indexes->exact_complete = false;
    } else {
        indexes->legacy_complete = false;
    }
}

static void pp_lsp_call_index_add(pp_lsp_call_indexes_t *indexes, CBMResolvedCall *candidate,
                                  const char *leaf, bool exact_site, const resolve_ctx_t *rc) {
    CBMHashTable *index = exact_site ? indexes->exact : indexes->legacy;
    if (!lsp_idx_insert_leaf(index, candidate, leaf, exact_site, rc->main_gbuf, rc->project_name,
                             indexes->allow_tail)) {
        pp_lsp_call_index_mark_incomplete(indexes, exact_site);
    }
}

static void pp_lsp_call_indexes_add_resolution(pp_lsp_call_indexes_t *indexes,
                                               CBMResolvedCall *candidate,
                                               const resolve_ctx_t *rc) {
    if (candidate->kind != CBM_RESOLVED_INVOCATION || !candidate->caller_qn ||
        !candidate->callee_qn || candidate->confidence < CBM_LSP_CONFIDENCE_FLOOR) {
        return;
    }
    bool exact_site =
        cbm_pipeline_source_site_present(candidate->site_start_byte, candidate->site_end_byte);
    if (!exact_site &&
        !cbm_pipeline_source_site_legacy(candidate->site_start_byte, candidate->site_end_byte)) {
        return;
    }
    pp_lsp_call_index_add(indexes, candidate, cbm_lsp_bare_segment(candidate->callee_qn),
                          exact_site, rc);
    if (candidate->reason && cbm_pipeline_invocation_reason_join_strategy(candidate->strategy)) {
        pp_lsp_call_index_add(indexes, candidate, cbm_lsp_bare_segment(candidate->reason),
                              exact_site, rc);
    }
    if (exact_site && candidate->strategy && strcmp(candidate->strategy, "lsp_destructor") == 0) {
        pp_lsp_call_index_add(indexes, candidate, "~", true, rc);
    }
}

static pp_lsp_call_indexes_t pp_lsp_call_indexes_build(const CBMFileResult *result,
                                                       const resolve_ctx_t *rc, CBMLanguage lang) {
    pp_lsp_call_indexes_t indexes = {.exact_complete = true,
                                     .legacy_complete = true,
                                     .allow_tail = cbm_pipeline_lsp_allow_tail_match(lang)};
    if (result->calls.count == 0 || result->resolved_calls.count == 0) {
        return indexes;
    }
    uint32_t capacity =
        ((uint32_t)result->resolved_calls.count * PP_LSP_INDEX_CAPACITY_MULTIPLIER) +
        PP_LSP_INDEX_CAPACITY_OVERHEAD;
    indexes.exact = cbm_ht_create(capacity);
    indexes.legacy = cbm_ht_create(capacity);
    indexes.exact_complete = indexes.exact != NULL;
    indexes.legacy_complete = indexes.legacy != NULL;
    for (int index = 0; (indexes.exact || indexes.legacy) && index < result->resolved_calls.count;
         ++index) {
        pp_lsp_call_indexes_add_resolution(&indexes, &result->resolved_calls.items[index], rc);
    }
    return indexes;
}

static const CBMResolvedCall *pp_find_lsp_call(const pp_call_resolution_ctx_t *context,
                                               const CBMCall *call) {
    const pp_lsp_call_indexes_t *indexes = context->lsp_indexes;
    bool exact_key_built = true;
    bool exact_key_ambiguous = false;
    bool legacy_key_built = true;
    const CBMResolvedCall *match = NULL;
    if (cbm_pipeline_source_site_present(call->site_start_byte, call->site_end_byte)) {
        match = lsp_idx_lookup(indexes->exact, call, true, &exact_key_built, &exact_key_ambiguous);
    }
    bool exact_authoritative = indexes->exact_complete && exact_key_built;
    if (!match && !exact_authoritative) {
        atomic_fetch_add_explicit(&g_lsp_linear_fallback_rows,
                                  (uint64_t)context->result->resolved_calls.count,
                                  memory_order_relaxed);
        match = cbm_pipeline_find_lsp_resolution_in_graph(
            &context->result->resolved_calls, call, indexes->allow_tail,
            context->resolve->main_gbuf, context->resolve->project_name);
    }
    if (!match && !call->requires_lsp_resolution && exact_authoritative && !exact_key_ambiguous) {
        match = lsp_idx_lookup(indexes->legacy, call, false, &legacy_key_built, NULL);
    }
    if (!match && (!indexes->legacy_complete || !legacy_key_built || indexes->allow_tail ||
                   call->requires_lsp_resolution)) {
        atomic_fetch_add_explicit(&g_lsp_linear_fallback_rows,
                                  (uint64_t)context->result->resolved_calls.count,
                                  memory_order_relaxed);
        match = cbm_pipeline_find_lsp_resolution_in_graph(
            &context->result->resolved_calls, call, indexes->allow_tail,
            context->resolve->main_gbuf, context->resolve->project_name);
    }
    return match;
}

static pp_lsp_call_match_t pp_match_lsp_call(const pp_call_resolution_ctx_t *context,
                                             const CBMCall *call) {
    pp_lsp_call_match_t match = {.requires_lsp_target = call->requires_lsp_resolution};
    uint64_t started = extract_now_ns();
    const CBMResolvedCall *resolved = pp_find_lsp_call(context, call);
    atomic_fetch_add_explicit(&context->resolve->time_ns_rc_lsp_lookup, extract_now_ns() - started,
                              memory_order_relaxed);
    if (!resolved) {
        return match;
    }
    bool strict_target =
        call->requires_lsp_resolution &&
        cbm_pipeline_kotlin_external_target(context->language, resolved->callee_qn);
    match.lsp_target = strict_target
                           ? cbm_pipeline_lsp_target_node_strict(
                                 context->resolve->main_gbuf, context->resolve->project_name,
                                 resolved->callee_qn, context->lsp_indexes->allow_tail)
                           : cbm_pipeline_lsp_target_node(
                                 context->resolve->main_gbuf, context->resolve->project_name,
                                 resolved->callee_qn, context->lsp_indexes->allow_tail);
    if (match.lsp_target) {
        match.resolution.qualified_name = match.lsp_target->qualified_name;
        match.resolution.strategy = resolved->strategy ? resolved->strategy : "lsp_override";
        match.resolution.confidence = (double)resolved->confidence;
        match.resolution.candidate_count = SKIP_ONE;
        ++context->worker->lsp_overrides;
    }
    return match;
}

static bool pp_prepare_call(const pp_call_resolution_ctx_t *context, const CBMCall *call,
                            pp_prepared_call_t *prepared) {
    if (!call->callee_name) {
        return false;
    }
    uint64_t started = extract_now_ns();
    prepared->source = find_source_node(context->resolve->main_gbuf, context->resolve->project_name,
                                        context->relative_path, call->enclosing_func_qn);
    atomic_fetch_add_explicit(&context->resolve->time_ns_rc_source, extract_now_ns() - started,
                              memory_order_relaxed);
    if (!prepared->source) {
        return false;
    }
    pp_lsp_call_match_t lsp_match = pp_match_lsp_call(context, call);
    prepared->resolution = lsp_match.resolution;
    prepared->lsp_target = lsp_match.lsp_target;
    started = extract_now_ns();
    if ((!prepared->resolution.qualified_name || !prepared->resolution.qualified_name[0]) &&
        !call->requires_lsp_resolution) {
        prepared->resolution = cbm_registry_resolve(context->resolve->registry, call->callee_name,
                                                    context->module_qn, context->import_keys,
                                                    context->import_values, context->import_count);
    }
    atomic_fetch_add_explicit(&context->resolve->time_ns_rc_resolve, extract_now_ns() - started,
                              memory_order_relaxed);
    if (lsp_match.requires_lsp_target && !prepared->lsp_target) {
        return false;
    }
    started = extract_now_ns();
    try_field_type_hint(context->resolve, &prepared->resolution, call->callee_name,
                        prepared->source->id);
    atomic_fetch_add_explicit(&context->resolve->time_ns_rc_hint, extract_now_ns() - started,
                              memory_order_relaxed);
    if (cbm_perl_suppress_generic_match(context->language == CBM_LANG_PERL, call->is_method,
                                        call->callee_name, prepared->resolution.strategy)) {
        return false;
    }
    bool is_tsjs = context->language == CBM_LANG_JAVASCRIPT ||
                   context->language == CBM_LANG_TYPESCRIPT || context->language == CBM_LANG_TSX;
    prepared->tsjs_drop_plain_call = cbm_tsjs_suppress_weak_method_match(
        is_tsjs, call->is_method, prepared->resolution.strategy);
    return true;
}

static bool pp_string_is_service_url(const char *value, cbm_svc_kind_t service) {
    return value && value[0] != '\0' &&
           (value[0] == '/' || strstr(value, "://") != NULL ||
            (service == CBM_SVC_ASYNC && strlen(value) > PP_ESC_SPACE));
}

static bool pp_emit_callee_service(const pp_call_resolution_ctx_t *context,
                                   const pp_prepared_call_t *prepared, const CBMCall *call) {
    cbm_svc_kind_t service = cbm_service_pattern_match(call->callee_name);
    if ((service != CBM_SVC_HTTP && service != CBM_SVC_ASYNC) ||
        !pp_string_is_service_url(call->first_string_arg, service)) {
        return false;
    }
    cbm_resolution_t resolution = {.qualified_name = call->callee_name,
                                   .confidence = PP_HALF_CONF,
                                   .strategy = "service_pattern"};
    emit_service_edge(context->worker->local_edge_buf, prepared->source, prepared->source, call,
                      &resolution, context->module_qn, context->resolve->registry,
                      context->resolve->main_gbuf, context->import_keys, context->import_values,
                      context->import_count, false);
    return true;
}

static void pp_emit_unresolved_service(const pp_call_resolution_ctx_t *context,
                                       const pp_prepared_call_t *prepared, const CBMCall *call) {
    if (cbm_service_pattern_route_method(call->callee_name) != NULL) {
        cbm_resolution_t resolution = {.qualified_name = call->callee_name,
                                       .confidence = PP_HALF_CONF,
                                       .strategy = "callee_suffix"};
        emit_service_edge(context->worker->local_edge_buf, prepared->source, prepared->source, call,
                          &resolution, context->module_qn, context->resolve->registry,
                          context->resolve->main_gbuf, context->import_keys, context->import_values,
                          context->import_count, false);
        return;
    }
    const char *url = call->first_string_arg;
    if (cbm_service_pattern_is_global_fetch(call->callee_name) &&
        pp_string_is_service_url(url, CBM_SVC_HTTP)) {
        cbm_resolution_t resolution = {.qualified_name = call->callee_name,
                                       .confidence = PP_HALF_CONF,
                                       .strategy = "service_pattern"};
        emit_http_async_service_edge(context->worker->local_edge_buf, prepared->source, call,
                                     &resolution, CBM_SVC_HTTP, url);
    }
}

static void pp_emit_external_service(const pp_call_resolution_ctx_t *context,
                                     const pp_prepared_call_t *prepared, const CBMCall *call) {
    cbm_svc_kind_t service = cbm_service_pattern_match(prepared->resolution.qualified_name);
    if ((service != CBM_SVC_HTTP && service != CBM_SVC_ASYNC) ||
        !pp_string_is_service_url(call->first_string_arg, service)) {
        return;
    }
    emit_service_edge(context->worker->local_edge_buf, prepared->source, NULL, call,
                      &prepared->resolution, context->module_qn, context->resolve->registry,
                      context->resolve->main_gbuf, context->import_keys, context->import_values,
                      context->import_count, false);
    ++context->worker->calls_resolved;
}

static void pp_emit_resolved_call(const pp_call_resolution_ctx_t *context,
                                  const pp_prepared_call_t *prepared, const CBMCall *call) {
    uint64_t started = extract_now_ns();
    const cbm_gbuf_node_t *target = prepared->lsp_target;
    if (!target || prepared->resolution.qualified_name != target->qualified_name) {
        target =
            cbm_gbuf_find_by_qn(context->resolve->main_gbuf, prepared->resolution.qualified_name);
    }
    atomic_fetch_add_explicit(&context->resolve->time_ns_rc_target, extract_now_ns() - started,
                              memory_order_relaxed);
    if (!target || cbm_node_id_eq(prepared->source->id, target->id)) {
        if (!target) {
            pp_emit_external_service(context, prepared, call);
        }
        return;
    }
    started = extract_now_ns();
    emit_service_edge(context->worker->local_edge_buf, prepared->source, target, call,
                      &prepared->resolution, context->module_qn, context->resolve->registry,
                      context->resolve->main_gbuf, context->import_keys, context->import_values,
                      context->import_count, prepared->tsjs_drop_plain_call);
    atomic_fetch_add_explicit(&context->resolve->time_ns_rc_emit, extract_now_ns() - started,
                              memory_order_relaxed);
    ++context->worker->calls_resolved;
}

static void resolve_file_calls(resolve_ctx_t *rc, resolve_worker_state_t *ws, CBMFileResult *result,
                               const char *rel, const char *module_qn, const char **imp_keys,
                               const char **imp_vals, int imp_count, CBMLanguage lang) {
    pp_lsp_call_indexes_t indexes = pp_lsp_call_indexes_build(result, rc, lang);
    pp_call_resolution_ctx_t call_context = {.resolve = rc,
                                             .worker = ws,
                                             .result = result,
                                             .relative_path = rel,
                                             .module_qn = module_qn,
                                             .import_keys = imp_keys,
                                             .import_values = imp_vals,
                                             .import_count = imp_count,
                                             .language = lang,
                                             .lsp_indexes = &indexes};

    for (int c = 0; c < result->calls.count; c++) {
        CBMCall *call = &result->calls.items[c];
        pp_prepared_call_t prepared = {0};
        if (!pp_prepare_call(&call_context, call, &prepared)) {
            continue;
        }
        if (pp_emit_callee_service(&call_context, &prepared, call)) {
            continue;
        }
        if (!prepared.resolution.qualified_name || !prepared.resolution.qualified_name[0]) {
            pp_emit_unresolved_service(&call_context, &prepared, call);
            continue;
        }
        pp_emit_resolved_call(&call_context, &prepared, call);
    }
    pp_lsp_call_indexes_free(&indexes);
}

static const cbm_gbuf_node_t *resolve_usage_target(
    resolve_ctx_t *rc, const CBMFileResult *result,
    const cbm_pipeline_lsp_reference_index_t *reference_index, bool reference_index_ready,
    const CBMUsage *usage, const char *module_qn, const char **imp_keys, const char **imp_vals,
    int imp_count, CBMLanguage lang, bool *precise_call_reference) {
    *precise_call_reference = false;
    const CBMResolvedCall *semantic_reference = NULL;
    const cbm_gbuf_node_t *target = NULL;
    if (cbm_pipeline_usage_semantic_reference_candidate(usage)) {
        bool allow_tail = cbm_pipeline_lsp_allow_tail_match(lang);
        semantic_reference = cbm_pipeline_find_lsp_reference_indexed_in_graph(
            &result->resolved_calls, reference_index_ready ? reference_index : NULL, usage,
            allow_tail, rc->main_gbuf, rc->project_name);
        if (semantic_reference &&
            !cbm_pipeline_usage_allows_semantic_reference(usage, semantic_reference)) {
            semantic_reference = NULL;
        }
        if (semantic_reference) {
            target = cbm_pipeline_lsp_target_node(rc->main_gbuf, rc->project_name,
                                                  semantic_reference->callee_qn, allow_tail);
            *precise_call_reference = cbm_pipeline_node_is_callable_target(target);
        }
    }
    if (target || semantic_reference) {
        return target;
    }
    cbm_resolution_t resolution = cbm_registry_resolve(rc->registry, usage->ref_name, module_qn,
                                                       imp_keys, imp_vals, imp_count);
    if (!resolution.qualified_name || resolution.qualified_name[0] == '\0' ||
        !cbm_pipeline_reference_candidate_fallback_allowed(lang, usage, resolution.strategy,
                                                           imp_keys, imp_count)) {
        return NULL;
    }
    target = cbm_gbuf_find_by_qn(rc->main_gbuf, resolution.qualified_name);
    return usage->semantic_reference_blocked && (usage->semantic_reference_local_shadow ||
                                                 cbm_pipeline_node_is_callable_target(target))
               ? NULL
               : target;
}

static void emit_usage_edge(resolve_worker_state_t *ws, const cbm_gbuf_node_t *source,
                            const cbm_gbuf_node_t *target, const CBMUsage *usage,
                            bool precise_call_reference) {
    cbm_gbuf_prop_t props[] = {
        {.key = "callee", .kind = CBM_EDGE_PROP_STRING, .text = usage->ref_name},
    };
    cbm_gbuf_insert_edge_props(ws->local_edge_buf,
                               (cbm_edge_endpoints_t){.source = source->id, .target = target->id},
                               precise_call_reference ? "CALL_REFERENCE" : "USAGE", props,
                               (int)(sizeof(props) / sizeof(props[0])));
    ++ws->usages_resolved;
}

/* Resolve usages for one file. */
static void resolve_file_usages(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                CBMFileResult *result, const char *rel, const char *module_qn,
                                const char **imp_keys, const char **imp_vals, int imp_count,
                                CBMLanguage lang) {
    cbm_pipeline_lsp_reference_index_t reference_index = {0};
    bool reference_index_ready =
        cbm_pipeline_lsp_reference_index_build(&result->resolved_calls, &reference_index);
    for (int u = 0; u < result->usages.count; u++) {
        CBMUsage *usage = &result->usages.items[u];
        if (!usage->ref_name) {
            continue;
        }
        const cbm_gbuf_node_t *src =
            find_source_node(rc->main_gbuf, rc->project_name, rel, usage->enclosing_func_qn);
        if (!src) {
            continue;
        }
        bool precise_call_reference = false;
        const cbm_gbuf_node_t *tgt = resolve_usage_target(
            rc, result, &reference_index, reference_index_ready, usage, module_qn, imp_keys,
            imp_vals, imp_count, lang, &precise_call_reference);
        if (!tgt || cbm_node_id_eq(src->id, tgt->id)) {
            continue;
        }
        emit_usage_edge(ws, src, tgt, usage, precise_call_reference);
    }
    cbm_pipeline_lsp_reference_index_free(&reference_index);
}

/* Resolve throws/raises for one file. */
static void resolve_file_throws(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                CBMFileResult *result, const char *rel, const char *module_qn,
                                const char **imp_keys, const char **imp_vals, int imp_count) {
    for (int t = 0; t < result->throws.count; t++) {
        CBMThrow *thr = &result->throws.items[t];
        if (!thr->exception_name || !thr->enclosing_func_qn) {
            continue;
        }
        /* find_source_node falls back to the per-file File node when the
         * lookup lands on a shared Folder/Project node (#787, #842) — same
         * guard resolve_file_calls/usages/rw already use. */
        const cbm_gbuf_node_t *src =
            find_source_node(rc->main_gbuf, rc->project_name, rel, thr->enclosing_func_qn);
        if (!src) {
            continue;
        }
        const char *edge_type = is_checked_exception(thr->exception_name) ? "THROWS" : "RAISES";
        cbm_resolution_t res = cbm_registry_resolve(rc->registry, thr->exception_name, module_qn,
                                                    imp_keys, imp_vals, imp_count);
        if (!res.qualified_name || res.qualified_name[0] == '\0') {
            continue;
        }
        const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_qn(rc->main_gbuf, res.qualified_name);
        if (!tgt || cbm_node_id_eq(src->id, tgt->id)) {
            continue;
        }
        cbm_gbuf_insert_edge_props(ws->local_edge_buf,
                                   (cbm_edge_endpoints_t){.source = src->id, .target = tgt->id},
                                   edge_type, NULL, 0);
    }
}

/* Resolve reads/writes for one file. */
static void resolve_file_rw(resolve_ctx_t *rc, resolve_worker_state_t *ws, CBMFileResult *result,
                            const char *rel, const char *module_qn, const char **imp_keys,
                            const char **imp_vals, int imp_count) {
    for (int r = 0; r < result->rw.count; r++) {
        CBMReadWrite *rw = &result->rw.items[r];
        if (!rw->var_name) {
            continue;
        }
        const cbm_gbuf_node_t *src =
            find_source_node(rc->main_gbuf, rc->project_name, rel, rw->enclosing_func_qn);
        if (!src) {
            continue;
        }
        cbm_resolution_t res = cbm_registry_resolve(rc->registry, rw->var_name, module_qn, imp_keys,
                                                    imp_vals, imp_count);
        if (!res.qualified_name || res.qualified_name[0] == '\0') {
            continue;
        }
        const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_qn(rc->main_gbuf, res.qualified_name);
        if (!tgt || cbm_node_id_eq(src->id, tgt->id)) {
            continue;
        }
        const char *etype = rw->is_write ? "WRITES" : "READS";
        cbm_gbuf_insert_edge_props(ws->local_edge_buf,
                                   (cbm_edge_endpoints_t){.source = src->id, .target = tgt->id},
                                   etype, NULL, 0);
    }
}

/* Resolve base_classes → INHERITS edges for one definition. */
static void resolve_def_inherits(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                 const CBMDefinition *def, const cbm_gbuf_node_t *node,
                                 const char *mq, const char **ik, const char **iv, int ic) {
    if (!def->base_classes) {
        return;
    }
    for (int b = 0; def->base_classes[b]; b++) {
        const char *bqn = resolve_as_class(rc->registry, def->base_classes[b], mq, ik, iv, ic);
        if (!bqn) {
            continue;
        }
        const cbm_gbuf_node_t *bn = cbm_gbuf_find_by_qn(rc->main_gbuf, bqn);
        if (bn && !cbm_node_id_eq(node->id, bn->id)) {
            /* Same Interface-label split as the sequential semantic pass —
             * hardcoding INHERITS here demoted every explicit `implements`
             * on large (parallel-path) corpora. */
            cbm_gbuf_insert_edge_props(ws->local_edge_buf,
                                       (cbm_edge_endpoints_t){.source = node->id, .target = bn->id},
                                       cbm_semantic_base_edge_type(bn), NULL, 0);
            ws->semantic_resolved++;
        }
    }
}

/* Resolve decorators → DECORATES edges for one definition. */
static const cbm_gbuf_node_t *resolve_decorator_node(resolve_ctx_t *rc, const char *fn,
                                                     const char *mq, const char **ik,
                                                     const char **iv, int ic) {
    cbm_resolution_t res = cbm_registry_resolve(rc->registry, fn, mq, ik, iv, ic);
    if ((!res.qualified_name || res.qualified_name[0] == '\0') && !strchr(fn, '.')) {
        char with_suffix[CBM_SZ_256];
        int written = snprintf(with_suffix, sizeof(with_suffix), "%sAttribute", fn);
        if (written > 0 && (size_t)written < sizeof(with_suffix)) {
            res = cbm_registry_resolve(rc->registry, with_suffix, mq, ik, iv, ic);
        }
    }
    return res.qualified_name && res.qualified_name[0] != '\0'
               ? cbm_gbuf_find_by_qn(rc->main_gbuf, res.qualified_name)
               : NULL;
}

static void resolve_def_decorators(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                   const CBMDefinition *def, const cbm_gbuf_node_t *node,
                                   const char *mq, const char **ik, const char **iv, int ic) {
    if (!def->decorators) {
        return;
    }
    for (int dc = 0; def->decorators[dc]; dc++) {
        char fn[CBM_SZ_256];
        extract_decorator_func(def->decorators[dc], fn, sizeof(fn));
        if (fn[0] == '\0') {
            continue;
        }
        const cbm_gbuf_node_t *dn = resolve_decorator_node(rc, fn, mq, ik, iv, ic);
        /* Qualified Rust proc-macro paths must not degrade to the decorated
         * function itself through the registry's same-module suffix fallback
         * (`#[tokio::main]` on local `main`).  Preserve the full external path
         * through the synthetic Decorator node instead. */
        if (dn && cbm_node_id_eq(dn->id, node->id) && def->decorators[dc][0] == '#' &&
            def->decorators[dc][SKIP_ONE] == '[' && strstr(fn, "::")) {
            dn = NULL;
        }
        cbm_node_id_t dn_id = CBM_NODE_ID_INVALID;
        if (dn) {
            dn_id = dn->id;
        } else {
            /* External/stdlib decorator (Rust `#[derive(Debug)]`, Swift
             * `@discardableResult`, Scala `@deprecated`, Python `@cache`,
             * Java `@Override`, ...): no local symbol resolves.  Materialise a
             * synthetic "Decorator" node so the DECORATES relation is recorded.
             * The node is created in the per-worker local_edge_buf (shared-ID
             * gbuf); the sequential merge dedupes by QN across workers, so all
             * uses of the same decorator name collapse to one node project-wide
             * and the edge target IDs are remapped consistently. */
            char syn_qn[CBM_SZ_512];
            snprintf(syn_qn, sizeof(syn_qn), "<decorator:%s>", fn);
            dn_id =
                cbm_gbuf_upsert_node(ws->local_edge_buf, "Decorator", fn, syn_qn, "", 0, 0, "{}");
        }
        if (cbm_node_id_valid(dn_id) && !cbm_node_id_eq(node->id, dn_id)) {
            /* Decorator SOURCE TEXT can contain quotes and raw newlines
             * (e.g. @register.tag("block"), multi-line @override_settings);
             * the typed STRING prop is JSON-escaped by the graph buffer on
             * serialization, so the raw text is safe to pass through here. */
            cbm_gbuf_prop_t dp[] = {
                {.key = "decorator", .kind = CBM_EDGE_PROP_STRING, .text = def->decorators[dc]},
            };
            cbm_gbuf_insert_edge_props(ws->local_edge_buf,
                                       (cbm_edge_endpoints_t){.source = node->id, .target = dn_id},
                                       "DECORATES", dp, (int)(sizeof(dp) / sizeof(dp[0])));
            /* Ensure a reference-style edge exists so the decorator appears in queries
             * without being misclassified as a real call by downstream passes. */
            cbm_gbuf_insert_edge_props(ws->local_edge_buf,
                                       (cbm_edge_endpoints_t){.source = node->id, .target = dn_id},
                                       "USAGE", NULL, 0);
            ws->semantic_resolved++;
        }
    }
}

/* Resolve INHERITS + DECORATES + IMPLEMENTS for one file. */
static void resolve_file_semantic(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                  CBMFileResult *result, const char *module_qn,
                                  const char **imp_keys, const char **imp_vals, int imp_count) {
    for (int d = 0; d < result->defs.count; d++) {
        CBMDefinition *def = &result->defs.items[d];
        if (!def->qualified_name) {
            continue;
        }
        const cbm_gbuf_node_t *node = cbm_gbuf_find_by_qn(rc->main_gbuf, def->qualified_name);
        if (!node) {
            continue;
        }
        resolve_def_inherits(rc, ws, def, node, module_qn, imp_keys, imp_vals, imp_count);
        resolve_def_decorators(rc, ws, def, node, module_qn, imp_keys, imp_vals, imp_count);
    }
    for (int t = 0; t < result->impl_traits.count; t++) {
        CBMImplTrait *it = &result->impl_traits.items[t];
        if (!it->trait_name || !it->struct_name) {
            continue;
        }
        const char *tqn = resolve_as_class(rc->registry, it->trait_name, module_qn, imp_keys,
                                           imp_vals, imp_count);
        const char *sqn = resolve_as_class(rc->registry, it->struct_name, module_qn, imp_keys,
                                           imp_vals, imp_count);
        if (!tqn || !sqn) {
            continue;
        }
        const cbm_gbuf_node_t *tn = cbm_gbuf_find_by_qn(rc->main_gbuf, tqn);
        const cbm_gbuf_node_t *sn = cbm_gbuf_find_by_qn(rc->main_gbuf, sqn);
        if (tn && sn && !cbm_node_id_eq(tn->id, sn->id)) {
            cbm_gbuf_insert_edge_props(ws->local_edge_buf,
                                       (cbm_edge_endpoints_t){.source = sn->id, .target = tn->id},
                                       "IMPLEMENTS", NULL, 0);
            ws->semantic_resolved++;
        }
    }
}

/* F4: get (or lazily build ONCE) the shared all_defs Rust registry. Called by the
 * first worker that hits a NULL-filter rust file; later null-files reuse it. Fast
 * path is a lock-free atomic load; the build happens under rust_shared_mu into the
 * dedicated rust_shared_arena (never a shared pipeline arena from a worker thread).
 * Returns NULL if there are no defs (caller falls back to the per-file build). */
static CBMTypeRegistry *pp_rust_shared_registry(resolve_ctx_t *rc) {
    CBMTypeRegistry *p = atomic_load_explicit(&rc->rust_shared_reg, memory_order_acquire);
    if (p) {
        return p;
    }
    if (!rc->all_defs || rc->def_count <= 0) {
        return NULL;
    }
    cbm_mutex_lock(&rc->rust_shared_mu);
    p = atomic_load_explicit(&rc->rust_shared_reg, memory_order_relaxed);
    if (!p) {
        cbm_arena_init(&rc->rust_shared_arena);
        rc->rust_shared_arena_live = true;
        p = cbm_rust_build_cross_registry(&rc->rust_shared_arena, rc->all_defs, rc->def_count);
        if (p) {
            char sb[PP_RUST_REGISTRY_SCALE_CAPACITY];
            snprintf(sb, sizeof(sb), "types=%d funcs=%d", p->type_count, p->func_count);
            cbm_log_info("cross_lsp.rust_registry", "scale", sb);
        }
        atomic_store_explicit(&rc->rust_shared_reg, p, memory_order_release);
    }
    cbm_mutex_unlock(&rc->rust_shared_mu);
    return p;
}

/* void*-typed adapter so the shared dispatch helper (pass_lsp_cross.c) can
 * borrow the lazily-built shared Rust registry without knowing resolve_ctx_t. */
static CBMTypeRegistry *pp_rust_shared_registry_get(void *ctx) {
    return pp_rust_shared_registry((resolve_ctx_t *)ctx);
}

static int pp_call_reference_site_count(const CBMFileResult *result) {
    int count = 0;
    for (int i = 0; i < result->usages.count; i++) {
        if (cbm_pipeline_usage_semantic_reference_candidate(&result->usages.items[i])) {
            count++;
        }
    }
    return count;
}

static int pp_qualified_lsp_site_count(const CBMFileResult *result) {
    int count = 0;
    for (int i = 0; i < result->resolved_calls.count; i++) {
        const CBMResolvedCall *resolved = &result->resolved_calls.items[i];
        if ((resolved->kind == CBM_RESOLVED_INVOCATION ||
             resolved->kind == CBM_RESOLVED_CALL_REFERENCE) &&
            resolved->caller_qn && resolved->callee_qn &&
            resolved->confidence >= CBM_LSP_CONFIDENCE_FLOOR) {
            count++;
        }
    }
    return count;
}

/* A per-file semantic walk can discover a faithful source occurrence that the
 * syntax extractor cannot represent as a CBMCall yet: Python operators and
 * calls hidden in Rust built-in macro token trees are the canonical examples.
 * An exact unresolved/low-confidence record is therefore an explicit request
 * for the project-registry pass, even when the parser-backed site count is
 * zero or already fully qualified. Zero-span generated semantics are excluded:
 * without source provenance they cannot safely join a graph carrier. */
static bool pp_has_pending_lsp_site(const CBMFileResult *result) {
    for (int i = 0; i < result->resolved_calls.count; i++) {
        const CBMResolvedCall *resolved = &result->resolved_calls.items[i];
        if (resolved->kind != CBM_RESOLVED_INVOCATION &&
            resolved->kind != CBM_RESOLVED_CALL_REFERENCE) {
            continue;
        }
        if (!resolved->caller_qn || !resolved->callee_qn ||
            resolved->site_end_byte <= resolved->site_start_byte) {
            continue;
        }
        if (resolved->reason || resolved->confidence < CBM_LSP_CONFIDENCE_FLOOR) {
            return true;
        }
    }
    return false;
}

typedef struct {
    int index;
    CBMFileResult *result;
    CBMLanguage language;
    const char *relative_path;
    const char **import_keys;
    const char **import_values;
    int import_count;
    char *module_qn;
} pp_resolve_file_t;

typedef struct {
    const char *text;
    char *owned;
    int length;
} pp_lsp_source_t;

static bool pp_resolve_is_generated_file(const char *relative_path) {
    static const char *const markers[] = {
        ".pb.go",  "zz_generated", "_generated.go", ".gen.go", "/applyconfigurations/",
        "_pb2.py", "_pb2_grpc.py", ".pb.cc",        ".pb.h",   ".pb-c.c",
        ".pb-c.h",
    };
    if (!relative_path) {
        return false;
    }
    for (size_t index = 0; index < sizeof(markers) / sizeof(markers[0]); ++index) {
        if (strstr(relative_path, markers[index]) != NULL) {
            return true;
        }
    }
    return false;
}

static bool pp_resolve_cross_lsp_eligible(const resolve_ctx_t *context,
                                          const pp_resolve_file_t *file) {
    int reference_sites = pp_call_reference_site_count(file->result);
    int semantic_sites = file->result->calls.count + reference_sites;
    int qualified_sites = pp_qualified_lsp_site_count(file->result);
    bool pending_site = pp_has_pending_lsp_site(file->result);
    bool is_jvm = file->language == CBM_LANG_JAVA || file->language == CBM_LANG_KOTLIN;
    return context->all_defs && context->def_count > 0 && cbm_pxc_has_cross_lsp(file->language) &&
           (semantic_sites > 0 || pending_site) &&
           (is_jvm || pending_site || qualified_sites < semantic_sites) &&
           !pp_resolve_is_generated_file(file->relative_path);
}

static bool pp_resolve_file_has_work(const pp_resolve_file_t *file, bool cross_lsp_eligible) {
    const CBMFileResult *result = file->result;
    return result->calls.count != 0 || result->usages.count != 0 || result->throws.count != 0 ||
           result->rw.count != 0 || result->defs.count != 0 || result->impl_traits.count != 0 ||
           cross_lsp_eligible;
}

static void pp_resolve_file_prepare(resolve_ctx_t *context, pp_resolve_file_t *file) {
    uint64_t started = extract_now_ns();
    cbm_pxc_build_import_map(context->main_gbuf, context->project_name, file->relative_path,
                             file->language, file->result, &file->import_keys, &file->import_values,
                             &file->import_count);
    atomic_fetch_add_explicit(&context->time_ns_import_map, extract_now_ns() - started,
                              memory_order_relaxed);
    int cache_capacity = file->result->calls.count + file->result->usages.count +
                         PP_REGISTRY_RESOLVE_CACHE_MIN_CAPACITY;
    cbm_registry_reach_cache_begin(cache_capacity);
    cbm_registry_import_map_cache_begin(file->import_keys, file->import_values, file->import_count);
    cbm_registry_resolve_cache_begin(cache_capacity);
    file->module_qn = cbm_pipeline_fqn_module_dir(context->project_name, file->relative_path,
                                                  pp_module_is_dir(file->language));
}

static void pp_resolve_file_release(pp_resolve_file_t *file) {
    cbm_registry_reach_cache_end();
    cbm_registry_import_map_cache_end();
    cbm_registry_resolve_cache_end();
    free(file->module_qn);
    cbm_pxc_free_import_map(file->import_keys, file->import_values, file->import_count);
}

static pp_lsp_source_t pp_resolve_lsp_source(const resolve_ctx_t *context,
                                             const pp_resolve_file_t *file) {
    pp_lsp_source_t source = {.text = file->result->source, .length = file->result->source_len};
    if ((!source.text || source.length <= 0) && context->files[file->index].path) {
        source.owned = read_file(context->files[file->index].path, &source.length, NULL, NULL);
        source.text = source.owned;
    }
    return source;
}

static void pp_resolve_cross_lsp(resolve_ctx_t *context, pp_resolve_file_t *file,
                                 bool cross_lsp_eligible) {
    if (!cross_lsp_eligible) {
        return;
    }
    pp_lsp_source_t source = pp_resolve_lsp_source(context, file);
    if (!source.text || source.length <= 0) {
        atomic_fetch_add_explicit(&context->lsp_cross_skipped_no_source, SKIP_ONE,
                                  memory_order_relaxed);
        return;
    }
    const char *module = context->def_modules ? context->def_modules[file->index] : file->module_qn;
    uint64_t started = extract_now_ns();
    cbm_index_mark_start(file->relative_path);
    cbm_pxc_dispatch_file(file->language, file->result, source.text, source.length,
                          file->relative_path, module, context->cross_registries,
                          context->module_def_index, context->all_defs, context->def_count,
                          file->import_keys, file->import_values, file->import_count,
                          pp_rust_shared_registry_get, context);
    cbm_index_mark_done(file->relative_path);
    free_source(source.owned);
    cbm_destroy_thread_parser();
    cbm_slab_reclaim();
    uint64_t elapsed_ns = extract_now_ns() - started;
    atomic_fetch_add_explicit(&context->time_ns_cross_lsp, elapsed_ns, memory_order_relaxed);
    uint64_t elapsed_ms = elapsed_ns / PP_USEC_PER_MS;
    if (elapsed_ms > PP_TIMER_THRESH) {
        cbm_log_info("parallel.resolve.lsp_cross.slow", "elapsed_ms", itoa_log((int)elapsed_ms),
                     "path", file->relative_path);
    }
    atomic_fetch_add_explicit(&context->lsp_cross_processed, SKIP_ONE, memory_order_relaxed);
}

static void pp_resolve_file_subphases(resolve_ctx_t *context, resolve_worker_state_t *worker,
                                      pp_resolve_file_t *file) {
    uint64_t started = extract_now_ns();
    resolve_file_calls(context, worker, file->result, file->relative_path, file->module_qn,
                       file->import_keys, file->import_values, file->import_count, file->language);
    atomic_fetch_add_explicit(&context->time_ns_calls, extract_now_ns() - started,
                              memory_order_relaxed);
    started = extract_now_ns();
    resolve_file_usages(context, worker, file->result, file->relative_path, file->module_qn,
                        file->import_keys, file->import_values, file->import_count, file->language);
    atomic_fetch_add_explicit(&context->time_ns_usages, extract_now_ns() - started,
                              memory_order_relaxed);
    started = extract_now_ns();
    resolve_file_throws(context, worker, file->result, file->relative_path, file->module_qn,
                        file->import_keys, file->import_values, file->import_count);
    atomic_fetch_add_explicit(&context->time_ns_throws, extract_now_ns() - started,
                              memory_order_relaxed);
    started = extract_now_ns();
    resolve_file_rw(context, worker, file->result, file->relative_path, file->module_qn,
                    file->import_keys, file->import_values, file->import_count);
    atomic_fetch_add_explicit(&context->time_ns_rw, extract_now_ns() - started,
                              memory_order_relaxed);
    started = extract_now_ns();
    resolve_file_semantic(context, worker, file->result, file->module_qn, file->import_keys,
                          file->import_values, file->import_count);
    atomic_fetch_add_explicit(&context->time_ns_semantic, extract_now_ns() - started,
                              memory_order_relaxed);
}

static void pp_resolve_worker_file(resolve_ctx_t *context, resolve_worker_state_t *worker,
                                   int file_index) {
    uint64_t started = extract_now_ns();
    CBMFileResult *result = context->result_cache[file_index];
    if (!result) {
        atomic_fetch_add_explicit(&context->time_ns_total_loop, extract_now_ns() - started,
                                  memory_order_relaxed);
        return;
    }
    atomic_fetch_add_explicit(&context->total_files_visited, SKIP_ONE, memory_order_relaxed);
    pp_resolve_file_t file = {.index = file_index,
                              .result = result,
                              .language = context->files[file_index].language,
                              .relative_path = context->files[file_index].rel_path};
    bool cross_lsp_eligible = pp_resolve_cross_lsp_eligible(context, &file);
    if (!pp_resolve_file_has_work(&file, cross_lsp_eligible)) {
        return;
    }
    pp_resolve_file_prepare(context, &file);
    pp_resolve_cross_lsp(context, &file, cross_lsp_eligible);
    pp_resolve_file_subphases(context, worker, &file);
    pp_resolve_file_release(&file);
    atomic_fetch_add_explicit(&context->time_ns_total_loop, extract_now_ns() - started,
                              memory_order_relaxed);
}

static void resolve_worker(int worker_id, void *ctx_ptr) {
    resolve_ctx_t *rc = ctx_ptr;
    resolve_worker_state_t *ws = &rc->workers[worker_id];

    if (!ws->local_edge_buf) {
        ws->local_edge_buf =
            cbm_gbuf_new_shared_ids(rc->project_name, rc->repo_path, rc->shared_ids);
    }

    /* Per-worker service-pattern result cache. The same resolved QN
     * (e.g. "fmt.Errorf", "context.Context.Done") appears in many
     * call edges across many files within a project — caching turns
     * cbm_service_pattern_match's 6 × 30 × strstr scan into one hash
     * lookup after the first miss for each QN. Scoped to the worker's
     * lifetime in the parallel_resolve phase. */
    cbm_service_pattern_cache_begin();

    while (SKIP_ONE) {
        int file_idx =
            atomic_fetch_add_explicit(&rc->next_file_idx, SKIP_ONE, memory_order_relaxed);
        if (file_idx >= rc->file_count) {
            break;
        }
        if (atomic_load_explicit(rc->cancelled, memory_order_relaxed)) {
            break;
        }

        pp_resolve_worker_file(rc, ws, file_idx);
    }

    cbm_destroy_thread_parser();
    cbm_slab_destroy_thread();
    cbm_service_pattern_cache_end();
}

typedef struct {
    int calls;
    int usages;
    int semantic;
    int lsp_overrides;
} pp_resolve_totals_t;

typedef struct {
    resolve_ctx_t context;
    resolve_worker_state_t *workers;
} pp_resolve_run_t;

static bool pp_resolve_run_prepare(pp_resolve_run_t *run, cbm_pipeline_ctx_t *pipeline,
                                   const cbm_file_info_t *files, int file_count,
                                   CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                                   int worker_count, CBMLSPDef *all_defs, int def_count,
                                   char *const *def_modules,
                                   struct CBMModuleDefIndex *module_def_index,
                                   CBMCrossLspRegistries *cross_registries) {
    if (cbm_aligned_alloc((void **)&run->workers, CBM_CACHE_LINE,
                          (size_t)worker_count * sizeof(*run->workers)) != 0) {
        return false;
    }
    memset(run->workers, 0, (size_t)worker_count * sizeof(*run->workers));
    run->context = (resolve_ctx_t){
        .files = files,
        .file_count = file_count,
        .project_name = pipeline->project_name,
        .repo_path = pipeline->repo_path,
        .workers = run->workers,
        .max_workers = worker_count,
        .result_cache = result_cache,
        .main_gbuf = pipeline->gbuf,
        .registry = pipeline->registry,
        .shared_ids = shared_ids,
        .cancelled = pipeline->cancelled,
        .all_defs = all_defs,
        .def_count = def_count,
        .def_modules = def_modules,
        .module_def_index = module_def_index,
        .cross_registries = cross_registries,
    };
    atomic_init(&run->context.next_file_idx, 0);
    atomic_init(&run->context.lsp_cross_processed, 0);
    atomic_init(&run->context.lsp_cross_skipped_no_source, 0);
    atomic_init(&run->context.rust_shared_reg, NULL);
    cbm_mutex_init(&run->context.rust_shared_mu);
    run->context.rust_shared_arena_live = false;
    return true;
}

static void pp_resolve_run_dispatch(pp_resolve_run_t *run, int file_count, int worker_count) {
    CBM_PROF_START(dispatched);
    cbm_parallel_for_opts_t options = {.max_workers = worker_count, .force_pthreads = false};
    cbm_parallel_for(worker_count, resolve_worker, &run->context, options);
    CBM_PROF_END_N("parallel_resolve", "1_dispatch_workers_parallel", dispatched, file_count);
    if (run->context.rust_shared_arena_live) {
        cbm_arena_destroy(&run->context.rust_shared_arena);
        run->context.rust_shared_arena_live = false;
    }
    cbm_mutex_destroy(&run->context.rust_shared_mu);
}

static pp_resolve_totals_t pp_resolve_run_merge(cbm_pipeline_ctx_t *pipeline, pp_resolve_run_t *run,
                                                int worker_count) {
    CBM_PROF_START(merged);
    pp_resolve_totals_t totals = {0};
    for (int index = 0; index < worker_count; ++index) {
        resolve_worker_state_t *worker = &run->workers[index];
        if (!worker->local_edge_buf) {
            continue;
        }
        cbm_gbuf_merge(pipeline->gbuf, worker->local_edge_buf);
        totals.calls += worker->calls_resolved;
        totals.usages += worker->usages_resolved;
        totals.semantic += worker->semantic_resolved;
        totals.lsp_overrides += worker->lsp_overrides;
        cbm_gbuf_free(worker->local_edge_buf);
    }
    CBM_PROF_END_N("parallel_resolve", "2_merge_edge_bufs_seq", merged,
                   totals.calls + totals.usages);
    return totals;
}

static void pp_resolve_log_duration(char *buffer, size_t capacity, const _Atomic uint64_t *value) {
    snprintf(
        buffer, capacity, "%llu",
        (unsigned long long)(atomic_load_explicit(value, memory_order_relaxed) / PP_USEC_PER_MS));
}

static void pp_resolve_log_summary(const resolve_ctx_t *context, const pp_resolve_totals_t *totals,
                                   int go_implementations, int definition_count) {
    cbm_log_info(
        "parallel.resolve.lsp_cross_done", "files_processed",
        itoa_log(atomic_load_explicit(&context->lsp_cross_processed, memory_order_relaxed)),
        "files_skipped_no_source",
        itoa_log(atomic_load_explicit(&context->lsp_cross_skipped_no_source, memory_order_relaxed)),
        "defs_total", itoa_log(definition_count));
    cbm_log_info("parallel.resolve.done", "calls", itoa_log(totals->calls), "usages",
                 itoa_log(totals->usages), "semantic",
                 itoa_log(totals->semantic + go_implementations), "lsp_overrides",
                 itoa_log(totals->lsp_overrides));
}

static void pp_resolve_log_timings(const resolve_ctx_t *context) {
    char total_loop[CBM_SZ_32];
    char files_visited[CBM_SZ_32];
    snprintf(files_visited, sizeof(files_visited), "%d",
             atomic_load_explicit(&context->total_files_visited, memory_order_relaxed));
    pp_resolve_log_duration(total_loop, sizeof(total_loop), &context->time_ns_total_loop);
    cbm_log_info("parallel.resolve.phase_summary", "total_loop_cpu_ms", total_loop, "files_visited",
                 files_visited);

    char import_map[CBM_SZ_32];
    char cross_lsp[CBM_SZ_32];
    char calls[CBM_SZ_32];
    pp_resolve_log_duration(import_map, sizeof(import_map), &context->time_ns_import_map);
    pp_resolve_log_duration(cross_lsp, sizeof(cross_lsp), &context->time_ns_cross_lsp);
    pp_resolve_log_duration(calls, sizeof(calls), &context->time_ns_calls);
    cbm_log_info("parallel.resolve.phase_ms_a", "import_map", import_map, "cross_lsp", cross_lsp,
                 "resolve_calls", calls);

    char usages[CBM_SZ_32];
    char throws[CBM_SZ_32];
    char reads_writes[CBM_SZ_32];
    char semantic[CBM_SZ_32];
    pp_resolve_log_duration(usages, sizeof(usages), &context->time_ns_usages);
    pp_resolve_log_duration(throws, sizeof(throws), &context->time_ns_throws);
    pp_resolve_log_duration(reads_writes, sizeof(reads_writes), &context->time_ns_rw);
    pp_resolve_log_duration(semantic, sizeof(semantic), &context->time_ns_semantic);
    cbm_log_info("parallel.resolve.phase_ms_b", "resolve_usages", usages, "resolve_throws", throws,
                 "resolve_rw", reads_writes, "resolve_semantic", semantic);

    char source[CBM_SZ_32];
    char lsp_lookup[CBM_SZ_32];
    char resolve[CBM_SZ_32];
    char hint[CBM_SZ_32];
    char target[CBM_SZ_32];
    char emit[CBM_SZ_32];
    pp_resolve_log_duration(source, sizeof(source), &context->time_ns_rc_source);
    pp_resolve_log_duration(lsp_lookup, sizeof(lsp_lookup), &context->time_ns_rc_lsp_lookup);
    pp_resolve_log_duration(resolve, sizeof(resolve), &context->time_ns_rc_resolve);
    pp_resolve_log_duration(hint, sizeof(hint), &context->time_ns_rc_hint);
    pp_resolve_log_duration(target, sizeof(target), &context->time_ns_rc_target);
    pp_resolve_log_duration(emit, sizeof(emit), &context->time_ns_rc_emit);
    cbm_log_info("parallel.resolve.calls_breakdown", "find_source", source, "lsp_lookup",
                 lsp_lookup, "resolve", resolve);
    cbm_log_info("parallel.resolve.calls_breakdown2", "field_hint", hint, "find_target", target,
                 "emit_edge", emit);
}

int cbm_parallel_resolve(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count,
                         CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                         int worker_count, CBMLSPDef *all_defs, int def_count,
                         char *const *def_modules, struct CBMModuleDefIndex *module_def_index,
                         void *cross_registries_v) {
    if (file_count == 0) {
        return 0;
    }
    CBMCrossLspRegistries *cross_registries = (CBMCrossLspRegistries *)cross_registries_v;
    cbm_log_info("parallel.resolve.start", "files", itoa_log(file_count), "workers",
                 itoa_log(worker_count));
    pp_resolve_run_t run = {0};
    if (!pp_resolve_run_prepare(&run, ctx, files, file_count, result_cache, shared_ids,
                                worker_count, all_defs, def_count, def_modules, module_def_index,
                                cross_registries)) {
        return CBM_NOT_FOUND;
    }
    pp_resolve_run_dispatch(&run, file_count, worker_count);
    pp_resolve_totals_t totals = pp_resolve_run_merge(ctx, &run, worker_count);
    cbm_aligned_free(run.workers);
    int go_implementations = cbm_pipeline_implements_go(ctx);
    totals.lsp_overrides += cbm_pipeline_override_explicit(ctx);
    if (atomic_load(ctx->cancelled)) {
        return CBM_NOT_FOUND;
    }
    pp_resolve_log_summary(&run.context, &totals, go_implementations, def_count);
    pp_resolve_log_timings(&run.context);
    return 0;
}
