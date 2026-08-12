/*
 * pipeline_incremental.c — Disk-based incremental re-indexing.
 *
 * Operates on the existing SQLite DB directly (not RAM-first graph buffer).
 * Compares file mtime+size against stored hashes to classify changed/unchanged.
 * Deletes changed files' nodes (edges cascade via ON DELETE CASCADE),
 * re-parses only changed files through passes into a temp graph buffer,
 * then merges new nodes/edges into the disk DB. Persists updated hashes.
 *
 * Called from pipeline.c when a DB with stored hashes already exists.
 */
#include "discover/userconfig.h"
#include "cbm.h"
#include "arena.h"
#include "foundation/constants.h"

enum {
    INCR_RING_BUF = 4,
    INCR_RING_MASK = 3,
    INCR_TS_BUF = 24,
    INCR_C_STRING_TERMINATOR_BYTES = 1,
    INCR_MANIFEST_HASH_ATTEMPTS = 2,
    INCR_FILE_READ_ITEMS = 1,
    INCR_SHA256_HEX_CHARS_PER_BYTE = 2,
    INCR_SHA256_HEX_SHIFT_BITS = 4,
    INCR_SHA256_HEX_LOW_NIBBLE_MASK = 0x0F,
    INCR_SECOND_HEX_CHAR_OFFSET = 1,
    INCR_MANIFEST_GROWTH_FACTOR = 2,
    INCR_EXPECTED_NEW_PATH_COUNT = 1U,
    INCR_GEMSPEC_SUFFIX_BYTES = 8,
    INCR_MANIFEST_RECURSION_DEPTH_STEP = 1,
    INCR_SKIPPED_MANIFEST_STATUS = 1,
    INCR_CLOSURE_PLAN_READY_STATUS = 1,
    INCR_HASH_TABLE_CAPACITY_FACTOR = 2U,
    INCR_NAME_SURFACE_ARRAY_COUNT = 2,
    INCR_FAILURE_STATUS = -1,
    INCR_LSP_DEF_START_TERMINAL_SLOT = 1,
    INCR_REL_PATH_SEPARATOR_BYTES = 1,
    INCR_MIN_ALLOCATION_ITEMS = 1,
    INCR_CLOSURE_BUDGET_PERCENT_SCALE = 100,
    INCR_MIN_WORKER_COUNT = 1,
    INCR_SQL_PROJECT_PARAMETER = 1,
    INCR_SQL_REL_PATH_PARAMETER = 2,
    INCR_NOT_INDEXED_PREFIX_BYTES = 11,
};
#include "pipeline/pipeline.h"
#include <stdio.h>
#include <time.h>
#include "pipeline/artifact.h"
#include "pipeline/lsp_surface.h"
#include "pipeline/pass_lsp_cross.h"
#include "store/sql.h"
#include "yyjson/yyjson.h"
#include "pipeline/pipeline_internal.h"
#include "store/store.h"
#include "graph_buffer/graph_buffer.h"
#include "discover/discover.h"
#include "foundation/log.h"
#include "foundation/hash_table.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/compat_thread.h"
#include "foundation/platform.h"
#include "foundation/sha256.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdatomic.h>
#include <stdint.h>

/* ── Constants ───────────────────────────────────────────────────── */

#define CBM_MS_PER_SEC 1000.0
#define CBM_NS_PER_MS 1000000.0
#define CBM_NS_PER_SEC 1000000000LL

#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
/* One-shot fault injection for the parallel incremental result cache. The
 * production build has no hook or branch at this allocation site. */
static atomic_bool g_incr_test_fail_result_cache_alloc = false;
static atomic_bool g_incr_test_force_legacy_partial = false;
static atomic_int g_incr_test_last_route = CBM_INCREMENTAL_ROUTE_NONE;

void cbm_pipeline_incremental_test_fail_result_cache_alloc_once(void) {
    atomic_store(&g_incr_test_fail_result_cache_alloc, true);
}

void cbm_pipeline_incremental_test_force_legacy_partial_once(void) {
    atomic_store(&g_incr_test_force_legacy_partial, true);
}

cbm_incremental_route_t cbm_pipeline_incremental_test_last_route(void) {
    return (cbm_incremental_route_t)atomic_load(&g_incr_test_last_route);
}

void cbm_pipeline_incremental_test_reset_faults(void) {
    atomic_store(&g_incr_test_fail_result_cache_alloc, false);
    atomic_store(&g_incr_test_force_legacy_partial, false);
    atomic_store(&g_incr_test_last_route, CBM_INCREMENTAL_ROUTE_NONE);
    cbm_pipeline_persist_test_reset_faults();
}

static bool incr_test_take_result_cache_alloc_failure(void) {
    return atomic_exchange(&g_incr_test_fail_result_cache_alloc, false);
}

static bool incr_test_take_force_legacy_partial(void) {
    return atomic_exchange(&g_incr_test_force_legacy_partial, false);
}

static void incr_test_set_last_route(cbm_incremental_route_t route) {
    atomic_store(&g_incr_test_last_route, route);
}
#endif

/* ── Timing helper (same as pipeline.c) ──────────────────────────── */

static double elapsed_ms(struct timespec start) {
    struct timespec now;
    cbm_clock_gettime(CLOCK_MONOTONIC, &now);
    double s = (double)(now.tv_sec - start.tv_sec);
    double ns = (double)(now.tv_nsec - start.tv_nsec);
    return (s * CBM_MS_PER_SEC) + (ns / CBM_NS_PER_MS);
}

/* itoa into static buffer — matches pipeline.c helper */
static const char *itoa_buf(int v) {
    static _Thread_local char buf[INCR_RING_BUF][INCR_TS_BUF];
    static _Thread_local int idx = 0;
    idx = (idx + SKIP_ONE) & INCR_RING_MASK;
    snprintf(buf[idx], sizeof(buf[idx]), "%d", v);
    return buf[idx];
}

/* ── Platform-portable mtime_ns ──────────────────────────────────── */

static int64_t stat_mtime_ns(const struct stat *st) {
#ifdef __APPLE__
    return ((int64_t)st->st_mtimespec.tv_sec * CBM_NS_PER_SEC) + (int64_t)st->st_mtimespec.tv_nsec;
#elif defined(_WIN32)
    return (int64_t)st->st_mtime * CBM_NS_PER_SEC;
#else
    return ((int64_t)st->st_mtim.tv_sec * CBM_NS_PER_SEC) + (int64_t)st->st_mtim.tv_nsec;
#endif
}

static const char *incr_mode_name(int mode) {
    switch (mode) {
    case CBM_MODE_FULL:
        return "full";
    case CBM_MODE_MODERATE:
        return "moderate";
    case CBM_MODE_FAST:
        return "fast";
    default:
        return "unknown";
    }
}

static const char *incr_coverage_recording_status(bool rows_available, int ignored_total,
                                                  int ignored_stored) {
    if (!rows_available) {
        return "unavailable";
    }
    if (ignored_total > ignored_stored) {
        return "truncated";
    }
    return "complete";
}

/* Free a const-qualified pointer this function owns. Captures the pointer's
 * bytes via memcpy into a local unqualified void* instead of casting away
 * const, matching safe_str_free's pattern (foundation/platform.h). */
static void free_owned(const void *p) {
    void *owned;
    memcpy(&owned, &p, sizeof(owned));
    free(owned);
}

/* Copy a const-qualified pointer's bytes into a plain void* for storage in a
 * generic container (e.g. cbm_ht_set's value parameter). The container never
 * writes through the pointer; this is not an ownership transfer. */
static void *nonowning_ptr(const void *p) {
    void *v;
    memcpy(&v, &p, sizeof(v));
    return v;
}

/* ── Exact semantic manifest ───────────────────────────────────── */

typedef struct {
    cbm_file_hash_t *items;
    int count;
    size_t cap;
    CBMHashTable *seen_paths;
} semantic_manifest_builder_t;

static int semantic_manifest_cmp(const void *a, const void *b) {
    const cbm_file_hash_t *ma = a;
    const cbm_file_hash_t *mb = b;
    return strcmp(ma->rel_path, mb->rel_path);
}

static bool semantic_manifest_is_virtual_path(const char *rel_path) {
    return rel_path &&
           strncmp(rel_path, CBM_SEMANTIC_INPUT_PREFIX, strlen(CBM_SEMANTIC_INPUT_PREFIX)) == 0;
}

void cbm_pipeline_free_semantic_manifest(cbm_file_hash_t *manifest, int count) {
    if (!manifest) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free_owned(manifest[i].project);
        free_owned(manifest[i].rel_path);
        free_owned(manifest[i].sha256);
    }
    free(manifest);
}

/* Hash a stable file generation. A concurrent edit is retried once; a second
 * race fails closed so a mixed-generation manifest can never be published. */
static int semantic_manifest_hash_file(
    const char *abs_path, char out[CBM_SHA256_HEX_LEN + INCR_C_STRING_TERMINATOR_BYTES],
    int64_t *mtime_ns, int64_t *size) {
    for (int attempt = 0; attempt < INCR_MANIFEST_HASH_ATTEMPTS; attempt++) {
        cbm_path_info_t before;
        if (cbm_path_info_utf8(abs_path, &before) != 0 || !before.is_regular || before.is_symlink) {
            return CBM_NOT_FOUND;
        }
        FILE *f = cbm_fopen(abs_path, "rb");
        if (!f) {
            return CBM_NOT_FOUND;
        }
        cbm_sha256_ctx sha;
        cbm_sha256_init(&sha);
        unsigned char buf[CBM_SZ_64K];
        size_t n;
        while ((n = fread(buf, INCR_FILE_READ_ITEMS, sizeof(buf), f)) > 0) {
            cbm_sha256_update(&sha, buf, n);
        }
        bool read_ok = !ferror(f);
        if (fclose(f) != 0) {
            read_ok = false;
        }
        cbm_path_info_t after;
        if (!read_ok || cbm_path_info_utf8(abs_path, &after) != 0 || !after.is_regular ||
            after.is_symlink) {
            return CBM_NOT_FOUND;
        }
        if (before.size != after.size || before.mtime_ns != after.mtime_ns) {
            continue;
        }
        uint8_t digest[CBM_SHA256_DIGEST_LEN];
        cbm_sha256_final(&sha, digest);
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
            out[i * INCR_SHA256_HEX_CHARS_PER_BYTE] = hex[digest[i] >> INCR_SHA256_HEX_SHIFT_BITS];
            out[(i * INCR_SHA256_HEX_CHARS_PER_BYTE) + INCR_SECOND_HEX_CHAR_OFFSET] =
                hex[digest[i] & INCR_SHA256_HEX_LOW_NIBBLE_MASK];
        }
        out[CBM_SHA256_HEX_LEN] = '\0';
        *mtime_ns = after.mtime_ns;
        *size = after.size;
        return 0;
    }
    cbm_log_warn("semantic_manifest.raced", "path", abs_path);
    return CBM_NOT_FOUND;
}

static int semantic_manifest_add_digest(semantic_manifest_builder_t *builder, const char *project,
                                        const char *rel_path, const char *sha, int64_t mtime_ns,
                                        int64_t size) {
    if (!builder || !project || !rel_path || !rel_path[0] || !sha ||
        strlen(sha) != CBM_SHA256_HEX_LEN || cbm_ht_has(builder->seen_paths, rel_path)) {
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < CBM_SHA256_HEX_LEN; i++) {
        if (!((sha[i] >= '0' && sha[i] <= '9') || (sha[i] >= 'a' && sha[i] <= 'f'))) {
            return CBM_NOT_FOUND;
        }
    }
    if ((size_t)builder->count == builder->cap) {
        size_t new_cap =
            builder->cap > 0 ? builder->cap * INCR_MANIFEST_GROWTH_FACTOR : (size_t)CBM_SZ_64;
        cbm_file_hash_t *grown = realloc(builder->items, new_cap * sizeof(*builder->items));
        if (!grown) {
            return CBM_NOT_FOUND;
        }
        builder->items = grown;
        builder->cap = new_cap;
    }
    char *project_copy = strdup(project);
    char *path_copy = strdup(rel_path);
    char *sha_copy = strdup(sha);
    if (!project_copy || !path_copy || !sha_copy) {
        free(project_copy);
        free(path_copy);
        free(sha_copy);
        return CBM_NOT_FOUND;
    }
    uint32_t before_count = cbm_ht_count(builder->seen_paths);
    cbm_ht_set(builder->seen_paths, path_copy, path_copy);
    if (cbm_ht_count(builder->seen_paths) != before_count + INCR_EXPECTED_NEW_PATH_COUNT) {
        free(project_copy);
        free(path_copy);
        free(sha_copy);
        return CBM_NOT_FOUND;
    }
    builder->items[builder->count++] = (cbm_file_hash_t){
        .project = project_copy,
        .rel_path = path_copy,
        .sha256 = sha_copy,
        .mtime_ns = mtime_ns,
        .size = size,
    };
    return 0;
}

static int semantic_manifest_add(semantic_manifest_builder_t *builder, const char *project,
                                 const char *rel_path, const char *abs_path) {
    if (!rel_path || !rel_path[0]) {
        return 0;
    }
    /* Reserved rows are synthetic and can never be supplied by discovery. */
    if (semantic_manifest_is_virtual_path(rel_path)) {
        return CBM_NOT_FOUND;
    }
    if (cbm_ht_has(builder->seen_paths, rel_path)) {
        return 0;
    }
    char sha[CBM_SHA256_HEX_LEN + INCR_C_STRING_TERMINATOR_BYTES];
    int64_t mtime_ns = 0;
    int64_t size = 0;
    if (semantic_manifest_hash_file(abs_path, sha, &mtime_ns, &size) != 0) {
        cbm_log_error("semantic_manifest.err", "path", abs_path);
        return CBM_NOT_FOUND;
    }
    return semantic_manifest_add_digest(builder, project, rel_path, sha, mtime_ns, size);
}

static void semantic_manifest_hash_bool(cbm_sha256_ctx *sha, const char *name, bool value) {
    const char encoded = value ? '1' : '0';
    cbm_sha256_update(sha, name, strlen(name) + INCR_C_STRING_TERMINATOR_BYTES);
    cbm_sha256_update(sha, &encoded, sizeof(encoded));
}

static void semantic_manifest_hash_string(cbm_sha256_ctx *sha, const char *name,
                                          const char *value) {
    cbm_sha256_update(sha, name, strlen(name) + INCR_C_STRING_TERMINATOR_BYTES);
    cbm_sha256_update(sha, value ? value : "",
                      strlen(value ? value : "") + INCR_C_STRING_TERMINATOR_BYTES);
}

static void semantic_manifest_git_digest(
    const cbm_git_context_t *git_ctx,
    char out[CBM_SHA256_HEX_LEN + INCR_C_STRING_TERMINATOR_BYTES]) {
    static const char domain[] = "cbm-semantic-git-context-v1";
    cbm_sha256_ctx sha;
    cbm_sha256_init(&sha);
    cbm_sha256_update(&sha, domain, sizeof(domain));
    semantic_manifest_hash_bool(&sha, "is_git", git_ctx && git_ctx->is_git);
    semantic_manifest_hash_bool(&sha, "is_worktree", git_ctx && git_ctx->is_worktree);
    semantic_manifest_hash_bool(&sha, "is_detached", git_ctx && git_ctx->is_detached);
    semantic_manifest_hash_bool(&sha, "root_exists", git_ctx && git_ctx->root_exists);
    semantic_manifest_hash_string(&sha, "branch", git_ctx ? git_ctx->branch : NULL);
    semantic_manifest_hash_string(&sha, "branch_slug", git_ctx ? git_ctx->branch_slug : NULL);
    semantic_manifest_hash_string(&sha, "head_sha", git_ctx ? git_ctx->head_sha : NULL);
    semantic_manifest_hash_string(&sha, "base_sha", git_ctx ? git_ctx->base_sha : NULL);
    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_final(&sha, digest);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
        out[i * INCR_SHA256_HEX_CHARS_PER_BYTE] = hex[digest[i] >> INCR_SHA256_HEX_SHIFT_BITS];
        out[(i * INCR_SHA256_HEX_CHARS_PER_BYTE) + INCR_SECOND_HEX_CHAR_OFFSET] =
            hex[digest[i] & INCR_SHA256_HEX_LOW_NIBBLE_MASK];
    }
    out[CBM_SHA256_HEX_LEN] = '\0';
}

static bool semantic_manifest_package_control(const char *name) {
    if (!name) {
        return false;
    }
    size_t len = strlen(name);
    return strcmp(name, "package.json") == 0 || strcmp(name, "go.mod") == 0 ||
           strcmp(name, "Cargo.toml") == 0 || strcmp(name, "pyproject.toml") == 0 ||
           strcmp(name, "composer.json") == 0 || strcmp(name, "pubspec.yaml") == 0 ||
           strcmp(name, "pom.xml") == 0 || strcmp(name, "build.gradle") == 0 ||
           strcmp(name, "build.gradle.kts") == 0 || strcmp(name, "mix.exs") == 0 ||
           (len >= INCR_GEMSPEC_SUFFIX_BYTES &&
            strcmp(name + len - INCR_GEMSPEC_SUFFIX_BYTES, ".gemspec") == 0);
}

typedef struct {
    char abs_dir[CBM_SZ_4K];
    char rel_dir[CBM_SZ_4K];
    int depth;
} semantic_manifest_dir_t;

static int semantic_manifest_push_dir(semantic_manifest_dir_t **dirs, size_t *count,
                                      size_t *capacity, const char *abs_dir, const char *rel_dir,
                                      int depth) {
    if (*count == *capacity) {
        size_t next_capacity = *capacity * PAIR_LEN;
        semantic_manifest_dir_t *grown = realloc(*dirs, next_capacity * sizeof(**dirs));
        if (!grown) {
            return CBM_NOT_FOUND;
        }
        *dirs = grown;
        *capacity = next_capacity;
    }
    semantic_manifest_dir_t *next = &(*dirs)[(*count)++];
    int abs_n = snprintf(next->abs_dir, sizeof(next->abs_dir), "%s", abs_dir);
    int rel_n = snprintf(next->rel_dir, sizeof(next->rel_dir), "%s", rel_dir ? rel_dir : "");
    if (abs_n < 0 || abs_n >= (int)sizeof(next->abs_dir) || rel_n < 0 ||
        rel_n >= (int)sizeof(next->rel_dir)) {
        return CBM_NOT_FOUND;
    }
    next->depth = depth;
    return 0;
}

static int semantic_manifest_control_entry(semantic_manifest_builder_t *builder,
                                           const char *project, const char *abs_dir,
                                           const char *rel_dir, const char *name,
                                           char **excluded_dirs, int excluded_count,
                                           semantic_manifest_dir_t **dirs, size_t *dir_count,
                                           size_t *dir_capacity, int depth) {
    char abs_path[CBM_SZ_4K];
    char rel_path[CBM_SZ_4K];
    int abs_n = snprintf(abs_path, sizeof(abs_path), "%s/%s", abs_dir, name);
    int rel_n = rel_dir[0] ? snprintf(rel_path, sizeof(rel_path), "%s/%s", rel_dir, name)
                           : snprintf(rel_path, sizeof(rel_path), "%s", name);
    if (abs_n < 0 || abs_n >= (int)sizeof(abs_path) || rel_n < 0 ||
        rel_n >= (int)sizeof(rel_path)) {
        return CBM_NOT_FOUND;
    }
    cbm_path_info_t info;
    if (cbm_path_info_utf8(abs_path, &info) != 0) {
        return CBM_NOT_FOUND;
    }
    if (info.is_symlink) {
        return 0;
    }
    if (info.is_directory) {
        if (cbm_should_skip_dir(name, CBM_MODE_FULL) ||
            cbm_pipeline_relpath_is_excluded(rel_path, excluded_dirs, excluded_count)) {
            return 0;
        }
        return semantic_manifest_push_dir(dirs, dir_count, dir_capacity, abs_path, rel_path,
                                          depth + INCR_MANIFEST_RECURSION_DEPTH_STEP);
    }
    bool root_control = !rel_dir[0] && (strcmp(name, ".cbmignore") == 0 ||
                                        strcmp(name, ".codebase-memory.json") == 0);
    return info.is_regular && (strcmp(name, ".gitignore") == 0 || root_control ||
                               semantic_manifest_package_control(name))
               ? semantic_manifest_add(builder, project, rel_path, abs_path)
               : 0;
}

static int semantic_manifest_walk_controls(semantic_manifest_builder_t *builder,
                                           const char *project, const char *abs_dir,
                                           const char *rel_dir, int depth, char **excluded_dirs,
                                           int excluded_count) {
    enum { MANIFEST_WALK_MAX_DEPTH = 64 };
    size_t dir_capacity = CBM_SZ_16;
    size_t dir_count = 0;
    semantic_manifest_dir_t *dirs = calloc(dir_capacity, sizeof(*dirs));
    if (!dirs || semantic_manifest_push_dir(&dirs, &dir_count, &dir_capacity, abs_dir, rel_dir,
                                            depth) != 0) {
        free(dirs);
        return CBM_NOT_FOUND;
    }
    int rc = 0;
    while (rc == 0 && dir_count > 0) {
        semantic_manifest_dir_t current = dirs[--dir_count];
        if (current.depth >= MANIFEST_WALK_MAX_DEPTH) {
            continue;
        }
        cbm_dir_t *dir = cbm_opendir(current.abs_dir);
        if (!dir) {
            rc = CBM_NOT_FOUND;
            break;
        }
        cbm_dirent_t *entry;
        while (rc == 0 && (entry = cbm_readdir(dir)) != NULL) {
            const char *name = entry->name;
            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                rc = semantic_manifest_control_entry(
                    builder, project, current.abs_dir, current.rel_dir, name, excluded_dirs,
                    excluded_count, &dirs, &dir_count, &dir_capacity, current.depth);
            }
        }
        cbm_closedir(dir);
    }
    free(dirs);
    return rc;
}

/* Parallel pre-hash of the discovery list. Hashing dominates manifest cost
 * (tens of thousands of file reads; single-threaded it was the second-
 * largest block of a kernel-scale incremental run after publication), and
 * semantic_manifest_hash_file is pure per-file work, so the files fan out
 * across workers while ASSEMBLY stays serial and in discovery order — the
 * manifest bytes are identical to the serial build's, only sooner. */
typedef struct {
    const cbm_file_info_t *files;
    int file_count;
    int worker_id;
    int worker_count;
    char (*shas)[CBM_SHA256_HEX_LEN + INCR_C_STRING_TERMINATOR_BYTES];
    int64_t *mtimes;
    int64_t *sizes;
    int8_t *rcs;
} manifest_hash_worker_t;

static void *manifest_hash_worker(void *arg) {
    manifest_hash_worker_t *w = (manifest_hash_worker_t *)arg;
    for (int i = w->worker_id; i < w->file_count; i += w->worker_count) {
        if (!w->files[i].rel_path || !w->files[i].rel_path[0]) {
            w->rcs[i] =
                INCR_SKIPPED_MANIFEST_STATUS; /* assembly skips exactly as the serial path did */
            continue;
        }
        w->rcs[i] = semantic_manifest_hash_file(w->files[i].path, w->shas[i], &w->mtimes[i],
                                                &w->sizes[i]) == 0
                        ? 0
                        : INCR_FAILURE_STATUS;
    }
    return NULL;
}

enum { MANIFEST_PARALLEL_MIN_FILES = 64 };

static int semantic_manifest_add_files_serial(semantic_manifest_builder_t *builder,
                                              const char *project, const cbm_file_info_t *files,
                                              int file_count) {
    int rc = 0;
    for (int i = 0; rc == 0 && i < file_count; i++) {
        rc = semantic_manifest_add(builder, project, files[i].rel_path, files[i].path);
    }
    return rc;
}

static int semantic_manifest_add_hashed_files(
    semantic_manifest_builder_t *builder, const char *project, const cbm_file_info_t *files,
    int file_count, char (*shas)[CBM_SHA256_HEX_LEN + INCR_C_STRING_TERMINATOR_BYTES],
    const int64_t *mtimes, const int64_t *sizes, const int8_t *rcs) {
    for (int i = 0; i < file_count; i++) {
        if (rcs[i] == INCR_SKIPPED_MANIFEST_STATUS ||
            cbm_ht_has(builder->seen_paths, files[i].rel_path)) {
            continue;
        }
        if (rcs[i] != 0) {
            cbm_log_error("semantic_manifest.err", "path", files[i].path);
            return CBM_NOT_FOUND;
        }
        int rc = semantic_manifest_add_digest(builder, project, files[i].rel_path, shas[i],
                                              mtimes[i], sizes[i]);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

static int semantic_manifest_add_files_parallel(semantic_manifest_builder_t *builder,
                                                const char *project, const cbm_file_info_t *files,
                                                int file_count, int hash_workers) {
    char (*shas)[CBM_SHA256_HEX_LEN + INCR_C_STRING_TERMINATOR_BYTES] =
        malloc((size_t)file_count * sizeof(*shas));
    int64_t *mtimes = calloc((size_t)file_count, sizeof(*mtimes));
    int64_t *sizes = calloc((size_t)file_count, sizeof(*sizes));
    int8_t *rcs = calloc((size_t)file_count, sizeof(*rcs));
    cbm_thread_t *threads = calloc((size_t)hash_workers, sizeof(*threads));
    manifest_hash_worker_t *workers = calloc((size_t)hash_workers, sizeof(*workers));
    int rc = 0;
    if (!shas || !mtimes || !sizes || !rcs || !threads || !workers) {
        rc = semantic_manifest_add_files_serial(builder, project, files, file_count);
    } else {
        int spawned = 0;
        for (int w = 0; w < hash_workers; w++) {
            workers[w] = (manifest_hash_worker_t){.files = files,
                                                  .file_count = file_count,
                                                  .worker_id = w,
                                                  .worker_count = hash_workers,
                                                  .shas = shas,
                                                  .mtimes = mtimes,
                                                  .sizes = sizes,
                                                  .rcs = rcs};
            if (cbm_thread_create(&threads[w], 0, manifest_hash_worker, &workers[w]) != 0) {
                break;
            }
            spawned++;
        }
        for (int w = spawned; w < hash_workers; w++) {
            workers[w] = (manifest_hash_worker_t){.files = files,
                                                  .file_count = file_count,
                                                  .worker_id = w,
                                                  .worker_count = hash_workers,
                                                  .shas = shas,
                                                  .mtimes = mtimes,
                                                  .sizes = sizes,
                                                  .rcs = rcs};
            (void)manifest_hash_worker(&workers[w]);
        }
        for (int w = 0; w < spawned; w++) {
            cbm_thread_join(&threads[w]);
        }
        rc = semantic_manifest_add_hashed_files(builder, project, files, file_count, shas, mtimes,
                                                sizes, rcs);
    }
    free(shas);
    free(mtimes);
    free(sizes);
    free(rcs);
    free(threads);
    free(workers);
    return rc;
}

static int semantic_manifest_add_context(semantic_manifest_builder_t *builder, const char *project,
                                         const cbm_git_context_t *git_ctx,
                                         const cbm_userconfig_t *userconfig) {
    char git_digest[CBM_SHA256_HEX_LEN + INCR_C_STRING_TERMINATOR_BYTES];
    char unavailable_digest[CBM_SHA256_HEX_LEN + INCR_C_STRING_TERMINATOR_BYTES];
    semantic_manifest_git_digest(git_ctx, git_digest);
    cbm_sha256_hex("cbm-userconfig-unavailable-v1", strlen("cbm-userconfig-unavailable-v1"),
                   unavailable_digest);
    const char *global = userconfig ? userconfig->global_source_sha256 : unavailable_digest;
    const char *project_config =
        userconfig ? userconfig->project_source_sha256 : unavailable_digest;
    int rc = semantic_manifest_add_digest(builder, project, CBM_SEMANTIC_INPUT_GIT_CONTEXT,
                                          git_digest, 0, 0);
    if (rc == 0) {
        rc = semantic_manifest_add_digest(builder, project, CBM_SEMANTIC_INPUT_GLOBAL_CONFIG,
                                          global, 0, 0);
    }
    return rc == 0 ? semantic_manifest_add_digest(
                         builder, project, CBM_SEMANTIC_INPUT_PROJECT_CONFIG, project_config, 0, 0)
                   : rc;
}

static int semantic_manifest_add_aliases(semantic_manifest_builder_t *builder, const char *project,
                                         const char *repo_path, char **excluded_dirs,
                                         int excluded_count) {
    cbm_path_alias_collection_t *aliases =
        cbm_load_path_aliases_excluded(repo_path, excluded_dirs, excluded_count);
    if (!aliases) {
        return 0;
    }
    int rc = 0;
    for (int i = 0; rc == 0 && i < aliases->count; i++) {
        const char *rel = aliases->scopes[i].source_rel_path;
        if (!rel) {
            continue;
        }
        char abs_path[CBM_SZ_4K];
        int count = snprintf(abs_path, sizeof(abs_path), "%s/%s", repo_path, rel);
        rc = count < 0 || count >= (int)sizeof(abs_path)
                 ? CBM_NOT_FOUND
                 : semantic_manifest_add(builder, project, rel, abs_path);
    }
    cbm_path_alias_collection_free(aliases);
    return rc;
}

int cbm_pipeline_build_semantic_manifest(const char *project, const char *repo_path,
                                         const cbm_file_info_t *files, int file_count,
                                         char **excluded_dirs, int excluded_count,
                                         const cbm_git_context_t *git_ctx,
                                         const cbm_userconfig_t *userconfig, cbm_file_hash_t **out,
                                         int *out_count) {
    if (!project || !repo_path || !out || !out_count || file_count < 0 ||
        (file_count > 0 && !files)) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    *out_count = 0;
    semantic_manifest_builder_t builder = {0};
    uint64_t reserve =
        ((uint64_t)(file_count > 0 ? file_count : 0) * INCR_HASH_TABLE_CAPACITY_FACTOR) + CBM_SZ_64;
    if (reserve > UINT32_MAX) {
        reserve = UINT32_MAX;
    }
    builder.seen_paths = cbm_ht_create((uint32_t)reserve);
    if (!builder.seen_paths) {
        return CBM_NOT_FOUND;
    }
    int rc = semantic_manifest_add_context(&builder, project, git_ctx, userconfig);
    struct timespec t_hash;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t_hash);
    int hash_workers = cbm_default_worker_count(true);
    if (rc == 0) {
        bool can_parallelize = file_count >= MANIFEST_PARALLEL_MIN_FILES && hash_workers > SKIP_ONE;
        rc = can_parallelize
                 ? semantic_manifest_add_files_parallel(&builder, project, files, file_count,
                                                        hash_workers)
                 : semantic_manifest_add_files_serial(&builder, project, files, file_count);
    }
    cbm_log_info("pass.timing", "pass", "semantic_manifest_hash", "files", itoa_buf(file_count),
                 "workers", itoa_buf(hash_workers), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t_hash)));
    if (rc == 0) {
        rc = semantic_manifest_walk_controls(&builder, project, repo_path, "", 0, excluded_dirs,
                                             excluded_count);
    }
    if (rc == 0) {
        rc = semantic_manifest_add_aliases(&builder, project, repo_path, excluded_dirs,
                                           excluded_count);
    }
    if (rc != 0) {
        cbm_ht_free(builder.seen_paths);
        cbm_pipeline_free_semantic_manifest(builder.items, builder.count);
        return rc;
    }
    cbm_ht_free(builder.seen_paths);
    qsort(builder.items, (size_t)builder.count, sizeof(*builder.items), semantic_manifest_cmp);
    *out = builder.items;
    *out_count = builder.count;
    return 0;
}

bool cbm_pipeline_semantic_manifests_equal(const cbm_file_hash_t *left, int left_count,
                                           const cbm_file_hash_t *right, int right_count) {
    if (left_count < 0 || right_count < 0 || left_count != right_count ||
        (left_count > 0 && (!left || !right))) {
        return false;
    }
    uint64_t reserve =
        ((uint64_t)(right_count > 0 ? right_count : 0) * INCR_HASH_TABLE_CAPACITY_FACTOR) +
        CBM_SZ_64;
    if (reserve > UINT32_MAX) {
        reserve = UINT32_MAX;
    }
    CBMHashTable *by_path = cbm_ht_create((uint32_t)reserve);
    if (!by_path) {
        return false;
    }
    bool equal = true;
    for (int i = 0; equal && i < right_count; i++) {
        if (!right[i].rel_path || !right[i].sha256 || cbm_ht_has(by_path, right[i].rel_path)) {
            equal = false;
            break;
        }
        uint32_t before = cbm_ht_count(by_path);
        cbm_ht_set(by_path, right[i].rel_path, nonowning_ptr(right[i].sha256));
        equal = cbm_ht_count(by_path) == before + INCR_EXPECTED_NEW_PATH_COUNT;
    }
    for (int i = 0; equal && i < left_count; i++) {
        if (!left[i].rel_path || !left[i].sha256) {
            equal = false;
            break;
        }
        const char *sha = cbm_ht_get(by_path, left[i].rel_path);
        equal = sha && strcmp(sha, left[i].sha256) == 0;
    }
    cbm_ht_free(by_path);
    return equal;
}

int cbm_pipeline_build_fresh_semantic_manifest(const char *project, const char *repo_path, int mode,
                                               cbm_file_hash_t **out, int *out_count) {
    if (!project || !repo_path || !out || !out_count) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    *out_count = 0;
    cbm_discover_opts_t opts = {
        .mode = (cbm_index_mode_t)mode,
        .ignore_file = NULL,
        .max_file_size = 0,
    };
    cbm_file_info_t *fresh_files = NULL;
    int fresh_file_count = 0;
    char **fresh_excluded = NULL;
    int fresh_excluded_count = 0;
    cbm_ignored_file_t *fresh_ignored = NULL;
    int fresh_ignored_count = 0;
    int fresh_ignored_total = 0;
    cbm_userconfig_t *fresh_userconfig = cbm_userconfig_load(repo_path);
    cbm_git_context_t fresh_git_ctx = {0};
    const cbm_userconfig_t *previous_userconfig = cbm_get_user_lang_config();
    int rc = fresh_userconfig ? cbm_git_context_resolve(repo_path, &fresh_git_ctx) : CBM_NOT_FOUND;
    if (rc == 0) {
        cbm_set_user_lang_config(fresh_userconfig);
        rc = cbm_discover_ex2(repo_path, &opts, &fresh_files, &fresh_file_count, &fresh_excluded,
                              &fresh_excluded_count, &fresh_ignored, &fresh_ignored_count,
                              &fresh_ignored_total);
    }
    if (rc == 0) {
        rc = cbm_pipeline_build_semantic_manifest(project, repo_path, fresh_files, fresh_file_count,
                                                  fresh_excluded, fresh_excluded_count,
                                                  &fresh_git_ctx, fresh_userconfig, out, out_count);
    }
    cbm_set_user_lang_config(previous_userconfig);
    cbm_git_context_free(&fresh_git_ctx);
    cbm_userconfig_free(fresh_userconfig);
    cbm_discover_free(fresh_files, fresh_file_count);
    cbm_discover_free_excluded(fresh_excluded, fresh_excluded_count);
    cbm_discover_free_ignored(fresh_ignored, fresh_ignored_count);
    return rc;
}

/* ── File classification ─────────────────────────────────────────── */

/* Classify discovered files against stored hashes using mtime+size.
 * Returns a boolean array: changed[i] = true if files[i] needs re-parsing.
 * Caller must free the returned array. */
static bool *classify_files(cbm_file_info_t *files, int file_count, cbm_file_hash_t *stored,
                            int stored_count, int *out_changed, int *out_unchanged) {
    bool *changed = calloc((size_t)file_count, sizeof(bool));
    if (!changed) {
        return NULL;
    }

    int n_changed = 0;
    int n_unchanged = 0;

    /* Build lookup: rel_path -> stored hash */
    CBMHashTable *ht =
        cbm_ht_create(stored_count > 0 ? (size_t)stored_count * PAIR_LEN : CBM_SZ_64);
    for (int i = 0; i < stored_count; i++) {
        cbm_ht_set(ht, stored[i].rel_path, &stored[i]);
    }

    for (int i = 0; i < file_count; i++) {
        cbm_file_hash_t *h = cbm_ht_get(ht, files[i].rel_path);
        if (!h) {
            /* New file */
            changed[i] = true;
            n_changed++;
            continue;
        }

        struct stat st;
        if (stat(files[i].path, &st) != 0) {
            changed[i] = true;
            n_changed++;
            continue;
        }

        if (stat_mtime_ns(&st) != h->mtime_ns || st.st_size != h->size) {
            changed[i] = true;
            n_changed++;
        } else {
            n_unchanged++;
        }
    }

    cbm_ht_free(ht);
    *out_changed = n_changed;
    *out_unchanged = n_unchanged;
    return changed;
}

/* Classify stored files that are absent from current discovery. Returns the
 * count of truly-deleted files (output via out_deleted) and ALSO collects
 * mode-skipped files into out_mode_skipped (caller frees both).
 *
 * A stored file is classified as:
 *   - "deleted"      — `stat()` returns ENOENT or ENOTDIR. Its nodes will
 *                       be purged and its hash row dropped.
 *   - "mode-skipped" — `stat()` succeeds. The file exists on disk but the
 *                       current discovery pass didn't visit it (e.g. excluded
 *                       by FAST_SKIP_DIRS in fast/moderate mode). Its nodes
 *                       must be preserved AND its hash row must be carried
 *                       forward into the new DB so subsequent reindexes can
 *                       still see it as "known" rather than treating it as
 *                       new-or-deleted.
 *
 * Without this distinction, a fast-mode reindex after a full-mode index
 * would silently purge every file under `tools/`, `scripts/`, `bin/`,
 * `build/`, `docs/`, `__tests__/`, etc. — see task
 * claude-connectors/codebase-memory-index-repository-is-destructive-...
 * and the 2026-04-13 Skyline incident (packages/mcp/src/tools/ vanished
 * from a live graph mid-session).
 *
 * Mode-skipped hash preservation is the second half of the additive-merge
 * contract: dump_and_persist re-upserts these hash rows so the next reindex
 * can correctly detect a real on-disk deletion of a mode-skipped file (as
 * opposed to seeing it as "never existed" → noop → orphaned graph nodes).
 *
 * Fail-safe rules (preserve nodes on uncertainty):
 *   - repo_path NULL → log error and preserve everything (return 0
 *     deletions, empty mode_skipped). The caller contract is that
 *     repo_path is required; a NULL means a misconfigured pipeline,
 *     not a deletion signal.
 *   - snprintf truncation (combined path ≥ CBM_SZ_4K) → preserve. We can't
 *     reliably stat a truncated path. Treat as mode-skipped.
 *   - stat() errno != ENOENT/ENOTDIR (EACCES, EIO, ELOOP, transient NFS,
 *     etc.) → preserve. The file may exist; we just can't see it right now.
 *     Treat as mode-skipped.
 *
 * Note: we use stat() (not lstat()) on purpose. A symlink whose target was
 * deleted should be classified as deleted from the indexer's perspective
 * because the indexer follows symlinks during discovery — a stale symlink
 * has no source to parse. */
static bool deleted_file_must_be_preserved(const char *repo_path, const char *rel_path) {
    char abs_path[CBM_SZ_4K];
    int n = snprintf(abs_path, sizeof(abs_path), "%s/%s", repo_path, rel_path);
    if (n < 0 || n >= (int)sizeof(abs_path)) {
        cbm_log_warn("incremental.path_truncated", "rel_path", rel_path);
        return true;
    }
    struct stat st;
    if (stat(abs_path, &st) == 0) {
        return true;
    }
    if (errno == ENOENT || errno == ENOTDIR) {
        return false;
    }
    cbm_log_warn("incremental.stat_uncertain", "rel_path", rel_path, "errno", itoa_buf(errno));
    return true;
}

static bool append_mode_skipped_file(cbm_file_hash_t **items, int *count, size_t *capacity,
                                     const cbm_file_hash_t *stored) {
    if ((size_t)*count >= *capacity) {
        *capacity *= PAIR_LEN;
        cbm_file_hash_t *grown = realloc(*items, *capacity * sizeof(**items));
        if (!grown) {
            cbm_log_error("incremental.err", "msg", "find_deleted_files_realloc_oom_ms");
            return false;
        }
        *items = grown;
    }
    char *rel_path = strdup(stored->rel_path);
    char *sha256 = stored->sha256 ? strdup(stored->sha256) : NULL;
    if (!rel_path || (stored->sha256 && !sha256)) {
        cbm_log_error("incremental.err", "msg", "find_deleted_files_strdup_oom", "rel_path",
                      stored->rel_path);
        free(rel_path);
        free(sha256);
        return false;
    }
    (*items)[*count] = (cbm_file_hash_t){
        .project = NULL,
        .rel_path = rel_path,
        .sha256 = sha256,
        .mtime_ns = stored->mtime_ns,
        .size = stored->size,
    };
    (*count)++;
    return true;
}

static bool append_deleted_path(char ***items, int *count, size_t *capacity, const char *rel_path) {
    if ((size_t)*count >= *capacity) {
        *capacity *= PAIR_LEN;
        char **grown = realloc(*items, *capacity * sizeof(**items));
        if (!grown) {
            cbm_log_error("incremental.err", "msg", "find_deleted_files_realloc_oom");
            return false;
        }
        *items = grown;
    }
    (*items)[*count] = strdup(rel_path);
    (*count)++;
    return true;
}

static int find_deleted_files(const char *repo_path, cbm_file_info_t *files, int file_count,
                              cbm_file_hash_t *stored, int stored_count, char ***out_deleted,
                              cbm_file_hash_t **out_mode_skipped, int *out_mode_skipped_count) {
    *out_deleted = NULL;
    *out_mode_skipped = NULL;
    *out_mode_skipped_count = 0;

    if (!repo_path) {
        /* Misconfigured pipeline. Preserve everything rather than risk
         * silently re-introducing the destructive overwrite this function
         * was rewritten to prevent. */
        cbm_log_error("incremental.err", "msg", "find_deleted_files_null_repo_path");
        return 0;
    }

    CBMHashTable *current = cbm_ht_create((size_t)file_count * PAIR_LEN);
    for (int i = 0; i < file_count; i++) {
        cbm_ht_set(current, files[i].rel_path, &files[i]);
    }

    int del_count = 0;
    size_t del_cap = (size_t)CBM_SZ_64;
    char **deleted = malloc(del_cap * sizeof(char *));
    if (!deleted) {
        cbm_log_error("incremental.err", "msg", "find_deleted_files_oom");
        cbm_ht_free(current);
        return 0;
    }

    int ms_count = 0;
    size_t ms_cap = (size_t)CBM_SZ_64;
    cbm_file_hash_t *mode_skipped = malloc(ms_cap * sizeof(cbm_file_hash_t));
    if (!mode_skipped) {
        cbm_log_error("incremental.err", "msg", "find_deleted_files_oom_ms");
        free(deleted);
        cbm_ht_free(current);
        return 0;
    }

    for (int i = 0; i < stored_count; i++) {
        if (semantic_manifest_is_virtual_path(stored[i].rel_path)) {
            continue; /* synthetic semantic inputs are not repository files */
        }
        if (cbm_ht_get(current, stored[i].rel_path)) {
            continue; /* still visited by current pass */
        }
        if (deleted_file_must_be_preserved(repo_path, stored[i].rel_path)) {
            if (!append_mode_skipped_file(&mode_skipped, &ms_count, &ms_cap, &stored[i])) {
                break;
            }
        } else if (!append_deleted_path(&deleted, &del_count, &del_cap, stored[i].rel_path)) {
            break;
        }
    }

    cbm_ht_free(current);
    *out_deleted = deleted;
    *out_mode_skipped = mode_skipped;
    *out_mode_skipped_count = ms_count;
    return del_count;
}

/* Free a mode_skipped array allocated by find_deleted_files. */
static void free_mode_skipped(cbm_file_hash_t *ms, int count) {
    if (!ms) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free_owned(ms[i].rel_path);
        free_owned(ms[i].sha256);
    }
    free(ms);
}

/* ── Inbound cross-file edge preservation (incremental correctness) ──
 *
 * The purge step (cbm_gbuf_delete_by_file) removes a changed file's nodes,
 * and the cascade then drops every edge referencing them — INCLUDING inbound
 * edges whose source lives in an UNCHANGED file (e.g. StudyService.grade ->
 * SM2.review, or a Folder -> File containment edge). Because incremental only
 * re-parses the changed files, the resolution passes never regenerate those
 * inbound edges, so the graph silently loses cross-file CALLS / CALL_REFERENCE / USAGE /
 * CONTAINS_FILE / INHERITS / ... edges on every edit and diverges from a
 * clean full reindex (which resolves every file).
 *
 * Fix: snapshot the inbound cross-file edges into changed files BEFORE the
 * purge, keyed by endpoint qualified_name (stable across re-parse), then
 * re-link them AFTER re-resolution + post-passes. Notes:
 *   - Only edges whose target is in a changed file and whose source is NOT
 *     are snapshotted; edges out of a changed file are regenerated when that
 *     file is re-resolved.
 *   - Edge types recomputed wholesale by post-passes (SIMILAR_TO,
 *     SEMANTICALLY_RELATED) are skipped — re-linking a stale snapshot could
 *     add edges a full reindex would not produce.
 *   - cbm_gbuf_insert_edge dedups, so re-linking an edge the resolver already
 *     recreated is a harmless no-op.
 *   - A target whose qualified_name no longer exists (symbol deleted or
 *     renamed by the edit) is dropped — matching full-reindex semantics. */

typedef struct {
    char *source_qn;
    char *target_qn;
    char *type;
    cbm_gbuf_prop_t *props; /* heap-owned array; each key/text (STRING) heap-owned */
    int prop_count;
} cbm_saved_edge_t;

typedef struct {
    cbm_gbuf_t *gbuf;
    CBMHashTable *changed_paths; /* rel_path -> non-NULL sentinel (membership set) */
    cbm_saved_edge_t *items;
    int count;
    size_t cap;
} cbm_edge_capture_t;

/* Edge types that must NOT be re-linked from the pre-purge snapshot, because a
 * full reindex (re)computes them via a pass whose result can differ from the
 * snapshot — restoring a stale copy could leave wrong properties or even an
 * edge a full reindex would not produce:
 *   - SIMILAR_TO / SEMANTICALLY_RELATED: rebuilt wholesale by the incremental
 *     post-passes (similarity / semantic_edges) over a drifting corpus.
 *   - FILE_CHANGES_WITH (git-history coupling) and DATA_FLOWS (route data flow):
 *     produced only by full-pipeline post-passes (githistory / route_nodes)
 *     that do NOT run during incremental; they remain a known incremental
 *     limitation rather than something to restore stale.
 * Every other edge type IS safe to re-link, by one of two routes that both
 * match a full reindex: edges re-emitted by the per-file resolution passes that
 * run incrementally (CALLS, CALL_REFERENCE, USAGE, DEFINES, DEFINES_METHOD, INHERITS,
 * IMPLEMENTS) are deduped on re-link, while structural containment edges
 * (CONTAINS_FILE, CONTAINS_FOLDER) — which the full-only structure pass does
 * NOT regenerate incrementally — are preserved precisely by this snapshot. */
static bool incr_edge_type_is_recomputed(const char *type) {
    return type && (strcmp(type, "SIMILAR_TO") == 0 || strcmp(type, "SEMANTICALLY_RELATED") == 0 ||
                    strcmp(type, "FILE_CHANGES_WITH") == 0 || strcmp(type, "DATA_FLOWS") == 0);
}

/* Frees a deep-copied prop array as produced by incr_dup_edge_props, for
 * `n` populated entries (used both on full success-then-later-failure paths
 * and on final teardown). */
/* Releases a heap buffer reached through a const pointer. The prop fields are
 * const because readers must not mutate them; the snapshot owns these copies
 * and is responsible for freeing them. memcpy moves the value without a
 * qualifier-dropping cast. */
static void incr_free_const(const void *owned) {
    void *raw = NULL;
    memcpy(&raw, &owned, sizeof(raw));
    free(raw);
}

static void incr_free_dup_props(cbm_gbuf_prop_t *props, int n) {
    for (int i = 0; i < n; i++) {
        incr_free_const(props[i].key);
        if (props[i].kind == CBM_EDGE_PROP_STRING) {
            incr_free_const(props[i].text);
        }
    }
    free(props);
}

/* Deep-copies an edge's typed property array so the snapshot survives the
 * node purge that follows capture (the source edge and its nodes are freed
 * before restore runs). Every entry's key is heap-owned by the copy; STRING
 * entries also heap-own their text. A zero-prop edge is a valid capture
 * (*out_props = NULL, *out_count = 0), not a failure. Returns false only on
 * allocation failure, leaving *out_props untouched. */
static bool incr_dup_edge_props(const cbm_gbuf_edge_t *edge, cbm_gbuf_prop_t **out_props,
                                int *out_count) {
    if (edge->prop_count <= 0) {
        *out_props = NULL;
        *out_count = 0;
        return true;
    }
    cbm_gbuf_prop_t *copy = calloc((size_t)edge->prop_count, sizeof(*copy));
    if (!copy) {
        return false;
    }
    for (int i = 0; i < edge->prop_count; i++) {
        const cbm_gbuf_prop_t *src = &edge->props[i];
        copy[i] = *src;
        copy[i].key = strdup(src->key);
        copy[i].text = (src->kind == CBM_EDGE_PROP_STRING && src->text) ? strdup(src->text) : NULL;
        bool text_ok = !(src->kind == CBM_EDGE_PROP_STRING && src->text) || copy[i].text;
        if (!copy[i].key || !text_ok) {
            incr_free_dup_props(copy, i + SKIP_ONE);
            return false;
        }
    }
    *out_props = copy;
    *out_count = edge->prop_count;
    return true;
}

/* cbm_gbuf_foreach_edge visitor: snapshot inbound cross-file edges into
 * changed files so they survive the purge and can be re-linked afterward. */
static void incr_capture_inbound_edge(const cbm_gbuf_edge_t *edge, void *userdata) {
    cbm_edge_capture_t *cap = (cbm_edge_capture_t *)userdata;
    if (incr_edge_type_is_recomputed(edge->type)) {
        return;
    }
    const cbm_gbuf_node_t *src = cbm_gbuf_find_by_id(cap->gbuf, edge->source_id);
    const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_id(cap->gbuf, edge->target_id);
    if (!src || !tgt || !src->qualified_name || !tgt->qualified_name || !src->file_path ||
        !tgt->file_path) {
        return;
    }
    /* Keep only edges that the purge would orphan permanently: target is in a
     * changed file (its node is deleted + re-created), source is NOT (its file
     * is never re-parsed, so the resolver won't regenerate the edge). */
    if (!cbm_ht_get(cap->changed_paths, tgt->file_path) ||
        cbm_ht_get(cap->changed_paths, src->file_path)) {
        return;
    }
    if ((size_t)cap->count >= cap->cap) {
        size_t ncap = (cap->cap > 0) ? cap->cap * PAIR_LEN : (size_t)CBM_SZ_64;
        cbm_saved_edge_t *tmp = realloc(cap->items, ncap * sizeof(*tmp));
        if (!tmp) {
            cbm_log_warn("incremental.edge_snapshot_oom", "captured", itoa_buf(cap->count));
            return; /* best-effort: stop capturing, keep what we have */
        }
        cap->items = tmp;
        cap->cap = ncap;
    }
    cbm_saved_edge_t *s = &cap->items[cap->count];
    s->source_qn = strdup(src->qualified_name);
    s->target_qn = strdup(tgt->qualified_name);
    s->type = strdup(edge->type);
    if (!s->source_qn || !s->target_qn || !s->type) {
        free(s->source_qn);
        free(s->target_qn);
        free(s->type);
        return;
    }
    if (!incr_dup_edge_props(edge, &s->props, &s->prop_count)) {
        free(s->source_qn);
        free(s->target_qn);
        free(s->type);
        return;
    }
    cap->count++;
}

/* Re-link snapshotted inbound edges to the freshly re-created target nodes.
 * Returns the number of edges re-linked. */
static int incr_restore_inbound_edges(cbm_gbuf_t *gbuf, cbm_edge_capture_t *cap) {
    int restored = 0;
    for (int i = 0; i < cap->count; i++) {
        cbm_saved_edge_t *s = &cap->items[i];
        const cbm_gbuf_node_t *src = cbm_gbuf_find_by_qn(gbuf, s->source_qn);
        const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_qn(gbuf, s->target_qn);
        if (src && tgt) {
            cbm_gbuf_insert_edge_props(gbuf,
                                       (cbm_edge_endpoints_t){.source = src->id, .target = tgt->id},
                                       s->type, s->props, s->prop_count);
            restored++;
        }
    }
    return restored;
}

static void incr_free_edge_capture(cbm_edge_capture_t *cap) {
    for (int i = 0; i < cap->count; i++) {
        free(cap->items[i].source_qn);
        free(cap->items[i].target_qn);
        free(cap->items[i].type);
        incr_free_dup_props(cap->items[i].props, cap->items[i].prop_count);
    }
    free(cap->items);
    cap->items = NULL;
    cap->count = 0;
    cap->cap = 0;
}

/* ── Persist file hashes ─────────────────────────────────────────── */

/* ── Registry seed visitor ────────────────────────────────────────── */

/* Labels the full-index definition pass seeds into the registry
 * (pass_definitions.c — KEEP IN SYNC). Incremental re-resolution must see the
 * SAME symbol set, or it diverges from a clean full reindex: seeding extra
 * container nodes (File / Module / Folder / ...) lets a type usage like `Word`
 * resolve to the same-named Module node instead of the Class node. Only
 * callable / declared symbols belong in the registry. */
static bool incr_label_is_registry_symbol(const char *label) {
    /* Mirror pass_definitions.c / pass_parallel.c registry seeding EXACTLY:
     * callables + every type-like container (Class/Struct/Interface/Enum/Type/
     * Trait) + Variable/Field. Struct included so an incremental re-resolve seeds
     * the same struct type nodes a full reindex would. */
    return label && (strcmp(label, "Function") == 0 || strcmp(label, "Method") == 0 ||
                     cbm_label_is_type_like(label) || strcmp(label, "Variable") == 0 ||
                     strcmp(label, "Field") == 0);
}

/* Callback for cbm_gbuf_foreach_node: seed the registry with the existing
 * project's definition symbols so the resolver can match cross-file symbols
 * during incremental. Mirrors the full-index registry contents exactly so an
 * incremental re-resolve picks the same nodes a full reindex would. */
static void registry_visitor(const cbm_gbuf_node_t *node, void *userdata) {
    cbm_registry_t *r = (cbm_registry_t *)userdata;
    if (!incr_label_is_registry_symbol(node->label)) {
        return;
    }
    cbm_registry_add(r, node->name, node->qualified_name, node->label);
}

static void free_incremental_result_cache(CBMFileResult **cache, int count) {
    if (!cache) {
        return;
    }
    for (int i = 0; i < count; i++) {
        cbm_free_result(cache[i]);
    }
    free(cache);
}

/* ── Closure repair (reverse-dependency incremental) ─────────────
 *
 * Routing model: the semantic manifest names WHAT changed; the previous
 * generation's graph names WHO consumed it. A body edit leaves a file's
 * persisted LSP surface byte-identical, so only the file itself is
 * recomputed; a surface change pulls in exactly the files with edges into
 * it. Per-file extraction is a pure function of file content, so an
 * unchanged dependent can never be surface-changed in turn — the closure is
 * structurally depth-1 and needs no fixpoint. Every uncertain case declines
 * to a FULL rebuild: new files, added definition names (yesterday's graph
 * cannot know tomorrow's referencers), virtual/config manifest entries,
 * missing or unreadable surface rows, dependents outside discovery, or a
 * closure above the budget. Declining is never wrong — it is exactly
 * today's behaviour. */

enum {
    CLOSURE_BUDGET_PERCENT = 30,
    /* A percentage-only budget starves small repositories (1 changed file in
     * a 3-file project is 33%). Closures at or under this absolute size are
     * always worth attempting; the percentage governs at scale, where it is
     * the honest signal that a rebuild costs less than a repair. */
    CLOSURE_BUDGET_FLOOR_FILES = 8,
};

typedef struct {
    /* Deserialized surfaces of the files NOT being re-parsed, registered
     * into the cross registries exactly as a full build would register
     * their fresh parses. Strings live in `arena`. */
    CBMLSPDef *base_defs;
    int base_def_count;
    CBMArena arena;
    /* Filled by run_extract_resolve: the re-parsed files' new surface rows
     * (heap; ownership passes to the publish merge) and the module strings
     * resolve borrowed (freed after publish). */
    cbm_lsp_surface_row_t *fresh_rows;
    int fresh_count;
    char **def_modules;
    int def_module_count;
    /* Parallel rehydration: per-worker arenas owning the deserialized
     * def strings. The resolvers and the patch borrow those strings, so
     * the arenas live exactly as long as cr.arena itself. */
    CBMArena *rehydrate_arenas;
    int rehydrate_arena_count;
} closure_resolve_t;

typedef struct {
    cbm_file_info_t *files; /* heap array; entries borrow strings from the
                             * caller's discovery array */
    int count;
    int n_changed;
    int n_dependents;
    cbm_lsp_surface_row_t *stored_rows; /* whole previous generation */
    int stored_count;
} closure_plan_t;

static void closure_plan_free(closure_plan_t *plan) {
    free(plan->files);
    cbm_store_free_lsp_surfaces(plan->stored_rows, plan->stored_count);
    memset(plan, 0, sizeof(*plan));
}

/* Short names a surface JSON defines ("lsp"[].sn plus "reg"[].n), as a
 * heap-keyed set. Returns NULL on parse failure — callers decline to FULL. */
static CBMHashTable *surface_name_set(const char *defs_json) {
    yyjson_doc *doc = yyjson_read(defs_json, strlen(defs_json), 0);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *lsp = root ? yyjson_obj_get(root, "lsp") : NULL;
    yyjson_val *reg = root ? yyjson_obj_get(root, "reg") : NULL;
    CBMHashTable *set = cbm_ht_create(CBM_SZ_64);
    if (!set) {
        yyjson_doc_free(doc);
        return NULL;
    }
    const char *arr_keys[] = {"sn", "n"};
    yyjson_val *arrs[] = {lsp, reg};
    for (int a = 0; a < INCR_NAME_SURFACE_ARRAY_COUNT; a++) {
        if (!arrs[a] || !yyjson_is_arr(arrs[a])) {
            continue;
        }
        size_t idx;
        size_t max;
        yyjson_val *item;
        yyjson_arr_foreach(arrs[a], idx, max, item) {
            const char *name = yyjson_get_str(yyjson_obj_get(item, arr_keys[a]));
            if (name && name[0] && !cbm_ht_get(set, name)) {
                char *copy = strdup(name);
                if (copy) {
                    cbm_ht_set(set, copy, copy);
                }
            }
        }
    }
    yyjson_doc_free(doc);
    return set;
}

static void surface_name_free_visitor(const char *key, void *value, void *userdata) {
    (void)key;
    (void)userdata;
    free(value); /* value IS the heap key copy */
}

static void surface_name_set_free(CBMHashTable *set) {
    if (!set) {
        return;
    }
    cbm_ht_foreach(set, surface_name_free_visitor, NULL);
    cbm_ht_free(set);
}

typedef struct {
    CBMHashTable *stored_set;
    bool added;
} surface_added_check_t;

static void surface_added_visitor(const char *key, void *value, void *userdata) {
    (void)value;
    surface_added_check_t *check = (surface_added_check_t *)userdata;
    if (!check->added && !cbm_ht_get(check->stored_set, key)) {
        check->added = true;
    }
}

/* Does `fresh_json` define any short name absent from `stored_json`? An
 * added name can re-route references in files that have NO edge into this
 * file yet (call-the-helper-you-just-wrote, shadowing), which the
 * edge-derived dependent set cannot see — those cases go to FULL. */
static int surface_added_names(const char *stored_json, const char *fresh_json, bool *out_added) {
    *out_added = true; /* fail closed */
    CBMHashTable *stored_set = surface_name_set(stored_json);
    CBMHashTable *fresh_set = surface_name_set(fresh_json);
    int rc = (stored_set && fresh_set) ? 0 : INCR_FAILURE_STATUS;
    if (rc == 0) {
        surface_added_check_t check = {.stored_set = stored_set, .added = false};
        cbm_ht_foreach(fresh_set, surface_added_visitor, &check);
        *out_added = check.added;
    }
    surface_name_set_free(stored_set);
    surface_name_set_free(fresh_set);
    return rc;
}

static int run_extract_resolve_sequential(cbm_pipeline_ctx_t *ctx, cbm_file_info_t *changed_files,
                                          int ci) {
    cbm_log_info("incremental.mode", "mode", "sequential", "changed", itoa_buf(ci));
    CBMFileResult **prior_cache = ctx->result_cache;
    CBMFileResult **cache = prior_cache;
    bool owns_cache = false;
    if (!cache && ci > 0) {
        cache = (CBMFileResult **)calloc((size_t)ci, sizeof(*cache));
        if (!cache) {
            cbm_log_error("incremental.err", "phase", "result_cache_alloc");
            return CBM_NOT_FOUND;
        }
        ctx->result_cache = cache;
        owns_cache = true;
    }
    int rc = cbm_pipeline_pass_definitions(ctx, changed_files, ci);
    if (rc == 0) {
        rc = cbm_pipeline_check_cancel(ctx);
    }
    if (rc == 0) {
        rc = cbm_pipeline_pass_calls(ctx, changed_files, ci);
    }
    if (rc == 0) {
        rc = cbm_pipeline_check_cancel(ctx);
    }
    if (rc == 0) {
        rc = cbm_pipeline_pass_usages(ctx, changed_files, ci);
    }
    if (rc == 0) {
        rc = cbm_pipeline_check_cancel(ctx);
    }
    if (rc == 0) {
        rc = cbm_pipeline_pass_semantic(ctx, changed_files, ci);
    }
    if (rc == 0) {
        rc = cbm_pipeline_check_cancel(ctx);
    }
    if (owns_cache) {
        free_incremental_result_cache(cache, ci);
        ctx->result_cache = prior_cache;
    }
    return rc;
}

static CBMFileResult **incremental_result_cache_create(int ci) {
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
    if (incr_test_take_result_cache_alloc_failure()) {
        return NULL;
    }
#endif
    size_t capacity = ci > 0 ? (size_t)ci : INCR_MIN_ALLOCATION_ITEMS;
    return (CBMFileResult **)calloc(capacity, sizeof(CBMFileResult *));
}

static int run_parallel_extract_phase(cbm_pipeline_ctx_t *ctx, cbm_file_info_t *changed_files,
                                      int ci, CBMFileResult **cache, _Atomic int64_t *shared_ids,
                                      int worker_count) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    int rc = cbm_parallel_extract(ctx, changed_files, ci, cache, shared_ids, worker_count);
    if (rc == 0) {
        rc = cbm_pipeline_check_cancel(ctx);
    }
    cbm_log_info("pass.timing", "pass", "incr_extract", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    if (rc == 0) {
        cbm_gbuf_set_next_id(ctx->gbuf, atomic_load(shared_ids));
    }
    return rc;
}

static int run_parallel_registry_phase(cbm_pipeline_ctx_t *ctx, cbm_file_info_t *changed_files,
                                       int ci, CBMFileResult **cache) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    int rc = cbm_build_registry_from_cache(ctx, changed_files, ci, cache);
    if (rc == 0) {
        rc = cbm_pipeline_check_cancel(ctx);
    }
    cbm_log_info("pass.timing", "pass", "incr_registry", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));
    return rc;
}

typedef struct {
    CBMLSPDef *all_defs;
    int all_def_count;
    CBMModuleDefIndex *module_def_index;
    CBMCrossLspRegistries cross_registries;
    CBMCrossLspRegistries *registries;
} parallel_resolve_inputs_t;

static void closure_prepare_parallel_resolution(cbm_pipeline_ctx_t *ctx,
                                                cbm_file_info_t *changed_files, int ci,
                                                CBMFileResult **cache, closure_resolve_t *closure,
                                                parallel_resolve_inputs_t *inputs) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    size_t changed_capacity = ci > 0 ? (size_t)ci : INCR_MIN_ALLOCATION_ITEMS;
    char **def_modules = calloc(changed_capacity, sizeof(*def_modules));
    int *def_starts =
        calloc(changed_capacity + INCR_LSP_DEF_START_TERMINAL_SLOT, sizeof(*def_starts));
    int fresh_count = 0;
    CBMLSPDef *fresh_defs = NULL;
    if (def_modules && def_starts) {
        fresh_defs = cbm_pxc_collect_all_defs(cache, changed_files, ci, ctx->project_name,
                                              def_modules, &fresh_count, def_starts);
    }
    if ((fresh_defs || fresh_count == 0) && def_starts &&
        cbm_lsp_surface_build_rows(ctx->project_name, cache, changed_files, ci, fresh_defs,
                                   def_starts, &closure->fresh_rows, &closure->fresh_count) != 0) {
        closure->fresh_rows = NULL;
        closure->fresh_count = 0;
    }
    free(def_starts);
    inputs->all_def_count = closure->base_def_count + fresh_count;
    if (inputs->all_def_count > 0) {
        inputs->all_defs = (CBMLSPDef *)cbm_arena_alloc(
            &closure->arena, (size_t)inputs->all_def_count * sizeof(*inputs->all_defs));
    }
    if (inputs->all_defs) {
        if (closure->base_def_count > 0) {
            memcpy(inputs->all_defs, closure->base_defs,
                   (size_t)closure->base_def_count * sizeof(*inputs->all_defs));
        }
        if (fresh_defs && fresh_count > 0) {
            memcpy(inputs->all_defs + closure->base_def_count, fresh_defs,
                   (size_t)fresh_count * sizeof(*inputs->all_defs));
        }
        inputs->module_def_index =
            cbm_pxc_build_module_def_index(inputs->all_defs, inputs->all_def_count);
        if (ci > CLOSURE_BUDGET_FLOOR_FILES) {
            CBMArena *arena = &closure->arena;
            inputs->cross_registries.go =
                cbm_go_build_cross_registry(arena, inputs->all_defs, inputs->all_def_count);
            inputs->cross_registries.python =
                cbm_py_build_cross_registry(arena, inputs->all_defs, inputs->all_def_count);
            inputs->cross_registries.c =
                cbm_c_build_cross_registry(arena, inputs->all_defs, inputs->all_def_count);
            inputs->cross_registries.cs =
                cbm_cs_build_cross_registry(arena, inputs->all_defs, inputs->all_def_count);
            inputs->cross_registries.ts =
                cbm_ts_build_cross_registry(arena, inputs->all_defs, inputs->all_def_count);
            inputs->registries = &inputs->cross_registries;
        }
    } else {
        inputs->all_def_count = 0;
    }
    free(fresh_defs);
    closure->def_modules = def_modules;
    closure->def_module_count = ci;
    cbm_log_info("incremental.closure_registries", "base", itoa_buf(closure->base_def_count),
                 "fresh", itoa_buf(fresh_count), "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
}

static int run_parallel_resolve_phase(cbm_pipeline_ctx_t *ctx, cbm_file_info_t *changed_files,
                                      int ci, CBMFileResult **cache, _Atomic int64_t *shared_ids,
                                      int worker_count, closure_resolve_t *closure,
                                      parallel_resolve_inputs_t *inputs) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    int rc = cbm_parallel_resolve(ctx, changed_files, ci, cache, shared_ids, worker_count,
                                  inputs->all_defs, inputs->all_def_count,
                                  closure ? closure->def_modules : NULL, inputs->module_def_index,
                                  inputs->registries);
    cbm_pxc_free_module_def_index(inputs->module_def_index);
    if (rc == 0) {
        rc = cbm_pipeline_check_cancel(ctx);
    }
    cbm_log_info("pass.timing", "pass", "incr_resolve", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    cbm_gbuf_set_next_id(ctx->gbuf, atomic_load(shared_ids));
    return rc;
}

/* Run parallel or sequential extract+resolve for changed files. Any failure
 * aborts before persistence: the caller discards this in-memory graph and
 * preserves the old on-disk database and its retryable hashes. */
static int run_extract_resolve(cbm_pipeline_ctx_t *ctx, cbm_file_info_t *changed_files, int ci,
                               closure_resolve_t *closure) {
    /* Per-file LSP always runs (every mode). Cross-file LSP: the legacy
     * partial route still skips it (NULL cross_registries below); the
     * closure-repair route rebuilds the registries from persisted surfaces +
     * this run's fresh parses and resolves with them — the same Tier-2 path
     * a full build takes, which is what makes its output converge. */

#define MIN_FILES_FOR_PARALLEL_INCR 50
    int worker_count = cbm_default_worker_count(true);
    bool use_parallel =
        closure != NULL || (worker_count > SKIP_ONE && ci > MIN_FILES_FOR_PARALLEL_INCR);

    if (use_parallel) {
        cbm_log_info("incremental.mode", "mode", "parallel", "workers", itoa_buf(worker_count),
                     "changed", itoa_buf(ci));

        _Atomic int64_t shared_ids;
        atomic_init(&shared_ids, cbm_gbuf_next_id(ctx->gbuf));

        CBMFileResult **cache = incremental_result_cache_create(ci);
        if (!cache) {
            cbm_log_error("incremental.err", "phase", "result_cache_alloc");
            return CBM_NOT_FOUND;
        }

        int rc =
            run_parallel_extract_phase(ctx, changed_files, ci, cache, &shared_ids, worker_count);
        if (rc != 0) {
            free_incremental_result_cache(cache, ci);
            return rc;
        }
        rc = run_parallel_registry_phase(ctx, changed_files, ci, cache);
        if (rc != 0) {
            free_incremental_result_cache(cache, ci);
            return rc;
        }

        /* Registry construction can materialize serial resource nodes after
         * extraction established the workers' shared allocator. Hand the main
         * buffer's monotonic watermark back to the workers before resolve-time
         * synthetic nodes are created. */
        int64_t registry_next_id = cbm_gbuf_next_id(ctx->gbuf);
        if (registry_next_id > atomic_load(&shared_ids)) {
            atomic_store(&shared_ids, registry_next_id);
        }

        parallel_resolve_inputs_t inputs = {0};
        if (closure) {
            closure_prepare_parallel_resolution(ctx, changed_files, ci, cache, closure, &inputs);
        }
        rc = run_parallel_resolve_phase(ctx, changed_files, ci, cache, &shared_ids, worker_count,
                                        closure, &inputs);
        free_incremental_result_cache(cache, ci);
        return rc;
    }
    return run_extract_resolve_sequential(ctx, changed_files, ci);
}

/* Run post-extraction passes (tests, decorator tags, configlink). */
static int run_postpasses(cbm_pipeline_ctx_t *ctx, cbm_file_info_t *changed_files, int ci,
                          const char *project) {
    struct timespec t;

    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    int rc = cbm_pipeline_pass_tests(ctx, changed_files, ci);
    cbm_log_info("pass.timing", "pass", "incr_tests", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    if (rc != 0 || cbm_pipeline_check_cancel(ctx)) {
        return rc != 0 ? rc : CBM_NOT_FOUND;
    }

    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    rc = cbm_pipeline_pass_decorator_tags(ctx->gbuf, project);
    cbm_log_info("pass.timing", "pass", "incr_decorator_tags", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));
    if (rc < 0 || cbm_pipeline_check_cancel(ctx)) {
        return rc < 0 ? rc : CBM_NOT_FOUND;
    }

    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    rc = cbm_pipeline_pass_configlink(ctx);
    cbm_log_info("pass.timing", "pass", "incr_configlink", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));
    if (rc < 0 || cbm_pipeline_check_cancel(ctx)) {
        return rc < 0 ? rc : CBM_NOT_FOUND;
    }

    /* SIMILAR_TO + SEMANTICALLY_RELATED edges only in moderate/full modes */
    if (ctx->mode <= CBM_MODE_MODERATE) {
        cbm_clock_gettime(CLOCK_MONOTONIC, &t);
        rc = cbm_pipeline_pass_similarity(ctx);
        cbm_log_info("pass.timing", "pass", "incr_similarity", "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t)));
        if (rc < 0 || cbm_pipeline_check_cancel(ctx)) {
            return rc < 0 ? rc : CBM_NOT_FOUND;
        }

        cbm_clock_gettime(CLOCK_MONOTONIC, &t);
        rc = cbm_pipeline_pass_semantic_edges(ctx);
        cbm_log_info("pass.timing", "pass", "incr_semantic_edges", "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t)));
        if (rc < 0 || cbm_pipeline_check_cancel(ctx)) {
            return rc < 0 ? rc : CBM_NOT_FOUND;
        }
    }
    return 0;
}
/* Publish the test-only legacy partial result through the same atomic
 * generation boundary as full indexing. */
static int dump_and_persist(cbm_gbuf_t *gbuf, const char *db_path, const char *project,
                            atomic_int *cancelled, const cbm_file_hash_t *manifest,
                            int manifest_count, const char *adr_content, const char *repo_path,
                            const cbm_coverage_row_t *cov, int cov_count,
                            const cbm_coverage_meta_t *meta_template,
                            const cbm_lsp_surface_row_t *surface_rows, int surface_row_count) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_pipeline_generation_t generation = {
        .gbuf = gbuf,
        .final_db_path = db_path,
        .project = project,
        .cancelled = cancelled,
        .manifest = manifest,
        .manifest_count = manifest_count,
        .adr_content = adr_content,
        .coverage = cov,
        .coverage_count = cov_count,
        .coverage_meta = meta_template ? *meta_template : (cbm_coverage_meta_t){0},
        .surface_rows = surface_rows,
        .surface_row_count = surface_row_count,
    };
    int rc = cbm_pipeline_publish_generation(&generation);
    cbm_log_info("incremental.dump", "rc", itoa_buf(rc), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));
    if (rc != 0) {
        return rc;
    }

    /* Auto-update artifact if one already exists (persistence was enabled previously) */
    if (repo_path && cbm_artifact_exists(repo_path)) {
        cbm_artifact_export(db_path, repo_path, project, CBM_ARTIFACT_FAST);
    }
    return 0;
}

/* Parallel base-def rehydration: rows are independent, so the JSON decode
 * fans out across workers on a stride; assembly back into one array stays
 * in ROW ORDER, so the registration input is byte-for-byte the sequence
 * the serial loop produced. Measured 35s serial at kernel scale (2.37M
 * defs) -- the single largest delta block after the query-plan fixes. */
typedef struct {
    const cbm_lsp_surface_row_t *const *rows;
    int row_count;
    int worker_id;
    int worker_count;
    CBMArena *arena;      /* this worker's arena (owned by cr) */
    CBMLSPDef **row_defs; /* per-row result pointers */
    int *row_counts;      /* per-row def counts; -1 = decode failure */
} rehydrate_worker_t;

static void *rehydrate_worker(void *arg) {
    rehydrate_worker_t *w = (rehydrate_worker_t *)arg;
    for (int i = w->worker_id; i < w->row_count; i += w->worker_count) {
        CBMLSPDef *defs = NULL;
        int count = cbm_lsp_surface_defs_from_json(w->arena, w->rows[i]->defs_json, &defs);
        w->row_defs[i] = defs;
        w->row_counts[i] = count;
    }
    return NULL;
}

/* Probe-extract a set of files into a throwaway graph to compute their
 * FRESH surfaces without touching the real state. Parses the changed files
 * once more than strictly necessary (the executor re-extracts them into the
 * real graph after the purge); the changed set is small by construction and
 * correctness stays trivially reasoned. Returns heap rows via out. */
static int closure_probe_surfaces(cbm_pipeline_t *p, const char *project,
                                  cbm_file_info_t *probe_files, int probe_count,
                                  cbm_lsp_surface_row_t **out_rows, int *out_count) {
    *out_rows = NULL;
    *out_count = 0;
    cbm_gbuf_t *probe_gbuf = cbm_gbuf_new(project, cbm_pipeline_repo_path(p));
    if (!probe_gbuf) {
        return INCR_FAILURE_STATUS;
    }
    char **excluded_dirs = NULL;
    int excluded_count = 0;
    cbm_pipeline_get_excluded(p, &excluded_dirs, &excluded_count);
    cbm_path_alias_collection_t *aliases =
        cbm_load_path_aliases_excluded(cbm_pipeline_repo_path(p), excluded_dirs, excluded_count);
    cbm_pipeline_ctx_t probe_ctx = {
        .project_name = project,
        .repo_path = cbm_pipeline_repo_path(p),
        .gbuf = probe_gbuf,
        .registry = NULL,
        .cancelled = cbm_pipeline_cancelled_ptr(p),
        .pipeline = NULL, /* probe must not record file errors twice */
        .mode = cbm_pipeline_get_mode(p),
        .path_aliases = aliases,
        .excluded_dirs = excluded_dirs,
        .excluded_count = excluded_count,
    };
    CBMFileResult **cache = (CBMFileResult **)calloc((size_t)probe_count, sizeof(CBMFileResult *));
    int rc = cache ? 0 : INCR_FAILURE_STATUS;
    if (rc == 0) {
        _Atomic int64_t probe_ids;
        atomic_init(&probe_ids, cbm_gbuf_next_id(probe_gbuf));
        rc = cbm_parallel_extract(&probe_ctx, probe_files, probe_count, cache, &probe_ids,
                                  cbm_default_worker_count(true));
    }
    if (rc == 0) {
        char **def_modules = (char **)calloc((size_t)probe_count, sizeof(char *));
        int *def_starts =
            (int *)calloc((size_t)probe_count + INCR_LSP_DEF_START_TERMINAL_SLOT, sizeof(int));
        int def_count = 0;
        CBMLSPDef *defs = NULL;
        if (def_modules && def_starts) {
            defs = cbm_pxc_collect_all_defs(cache, probe_files, probe_count, project, def_modules,
                                            &def_count, def_starts);
            rc = cbm_lsp_surface_build_rows(project, cache, probe_files, probe_count, defs,
                                            def_starts, out_rows, out_count);
        } else {
            rc = INCR_FAILURE_STATUS;
        }
        free(defs);
        free(def_starts);
        if (def_modules) {
            for (int i = 0; i < probe_count; i++) {
                free(def_modules[i]);
            }
            free(def_modules);
        }
    }
    if (cache) {
        free_incremental_result_cache(cache, probe_count);
    }
    /* Parallel extraction builds the process-global package map; the probe
     * owns it exactly as the real extraction paths do. Leaving it behind
     * leaked one map per probed run (LSan, macOS CI). */
    cbm_pkgmap_free(cbm_pipeline_get_pkgmap());
    cbm_pipeline_set_pkgmap(NULL);
    cbm_path_alias_collection_free(aliases);
    cbm_gbuf_free(probe_gbuf);
    return rc;
}

/* Is this manifest row a path-alias config (tsconfig/jsconfig class)? Exact
 * match against the loaded alias collection's config paths, plus a basename
 * fallback so a REMOVED config (absent from the fresh collection) still
 * classifies. Alias configs are the one config class whose effect is
 * per-scope rather than global, which is what makes governed-closure repair
 * sound for them and for nothing else. */
static bool closure_is_alias_config(const cbm_path_alias_collection_t *aliases,
                                    const char *rel_path) {
    if (!rel_path) {
        return false;
    }
    if (aliases) {
        for (int i = 0; i < aliases->count; i++) {
            if (aliases->scopes[i].source_rel_path &&
                strcmp(aliases->scopes[i].source_rel_path, rel_path) == 0) {
                return true;
            }
        }
    }
    const char *slash = strrchr(rel_path, '/');
    const char *base = slash ? slash + INCR_REL_PATH_SEPARATOR_BYTES : rel_path;
    return strcmp(base, "tsconfig.json") == 0 || strcmp(base, "jsconfig.json") == 0;
}

/* Every discovered file under the config's directory joins the closure:
 * their RESOLUTION consumed the config even though their bytes (and thus
 * surfaces) are unchanged, so they re-extract and re-resolve but never
 * propagate further. Over-inclusion (nested scopes) is safe; the budget
 * still bounds the total. */
static void closure_seed_governed(CBMHashTable *closure_set, const cbm_file_info_t *files,
                                  int file_count, const char *config_rel_path) {
    const char *slash = strrchr(config_rel_path, '/');
    size_t dir_len = slash ? (size_t)(slash - config_rel_path + INCR_REL_PATH_SEPARATOR_BYTES) : 0;
    for (int i = 0; i < file_count; i++) {
        if (dir_len > 0 && strncmp(files[i].rel_path, config_rel_path, dir_len) != 0) {
            continue;
        }
        if (!cbm_ht_get(closure_set, files[i].rel_path)) {
            cbm_ht_set(closure_set, files[i].rel_path, (void *)files[i].rel_path);
        }
    }
}

typedef struct {
    CBMHashTable *fresh_by_path;
    CBMHashTable *files_by_path;
    CBMHashTable *stored_by_path;
    CBMHashTable *closure_set;
    const char **changed_paths;
    char **dependents;
    int dependent_count;
    cbm_lsp_surface_row_t *probe_rows;
    int probe_count;
    cbm_file_info_t *probe_files;
    cbm_path_alias_collection_t *aliases;
    int n_changed;
    int n_deleted;
    int n_surface_changed;
} closure_plan_state_t;

static void closure_plan_state_destroy(closure_plan_state_t *state) {
    cbm_path_alias_collection_free(state->aliases);
    free(state->probe_files);
    cbm_store_free_lsp_surfaces(state->probe_rows, state->probe_count);
    cbm_store_free_dependent_files(state->dependents, state->dependent_count);
    free(state->changed_paths);
    cbm_ht_free(state->fresh_by_path);
    cbm_ht_free(state->files_by_path);
    cbm_ht_free(state->stored_by_path);
    cbm_ht_free(state->closure_set);
}

static bool closure_plan_state_index_manifests(closure_plan_state_t *state, cbm_file_info_t *files,
                                               int file_count, const cbm_file_hash_t *stored,
                                               int stored_count, const cbm_file_hash_t *fresh,
                                               int fresh_count) {
    state->fresh_by_path = cbm_ht_create(((size_t)fresh_count * PAIR_LEN) + CBM_SZ_64);
    state->files_by_path = cbm_ht_create(((size_t)file_count * PAIR_LEN) + CBM_SZ_64);
    state->stored_by_path = cbm_ht_create(((size_t)stored_count * PAIR_LEN) + CBM_SZ_64);
    state->closure_set = cbm_ht_create(CBM_SZ_64);
    if (!state->fresh_by_path || !state->files_by_path || !state->stored_by_path ||
        !state->closure_set) {
        return false;
    }
    for (int i = 0; i < file_count; i++) {
        cbm_ht_set(state->files_by_path, files[i].rel_path, &files[i]);
    }
    for (int i = 0; i < fresh_count; i++) {
        cbm_ht_set(state->fresh_by_path, fresh[i].rel_path, nonowning_ptr(&fresh[i]));
    }
    for (int i = 0; i < stored_count; i++) {
        cbm_ht_set(state->stored_by_path, stored[i].rel_path, nonowning_ptr(&stored[i]));
    }
    return true;
}

static const char *closure_plan_classify_fresh(const closure_plan_state_t *state,
                                               const cbm_file_hash_t *fresh_row,
                                               cbm_file_info_t *files, int file_count,
                                               cbm_path_alias_collection_t *aliases,
                                               bool *governed_seeded,
                                               closure_plan_state_t *mutable_state) {
    const cbm_file_hash_t *old_row = cbm_ht_get(state->stored_by_path, fresh_row->rel_path);
    if (old_row && strcmp(old_row->sha256, fresh_row->sha256) == 0) {
        return NULL;
    }
    if (semantic_manifest_is_virtual_path(fresh_row->rel_path)) {
        return "semantic_input_changed";
    }
    if (cbm_ht_get(state->files_by_path, fresh_row->rel_path)) {
        if (!old_row) {
            return "new_file";
        }
        mutable_state->changed_paths[mutable_state->n_changed++] = fresh_row->rel_path;
        return NULL;
    }
    if (!closure_is_alias_config(aliases, fresh_row->rel_path)) {
        return "control_file_changed";
    }
    closure_seed_governed(state->closure_set, files, file_count, fresh_row->rel_path);
    *governed_seeded = true;
    return NULL;
}

static const char *closure_plan_classify_manifest(closure_plan_state_t *state,
                                                  cbm_pipeline_t *pipeline, cbm_file_info_t *files,
                                                  int file_count, const cbm_file_hash_t *stored,
                                                  int stored_count, const cbm_file_hash_t *fresh,
                                                  int fresh_count) {
    size_t path_count = (size_t)fresh_count + (size_t)stored_count;
    state->changed_paths = calloc(path_count > 0 ? path_count : INCR_MIN_ALLOCATION_ITEMS,
                                  sizeof(*state->changed_paths));
    if (!state->changed_paths) {
        return "alloc";
    }
    state->aliases = cbm_load_path_aliases_excluded(cbm_pipeline_repo_path(pipeline), NULL, 0);
    bool governed_seeded = false;
    for (int i = 0; i < fresh_count; i++) {
        const char *decline = closure_plan_classify_fresh(state, &fresh[i], files, file_count,
                                                          state->aliases, &governed_seeded, state);
        if (decline) {
            return decline;
        }
    }
    for (int i = 0; i < stored_count; i++) {
        if (cbm_ht_get(state->fresh_by_path, stored[i].rel_path)) {
            continue;
        }
        bool removed_alias = !cbm_ht_get(state->files_by_path, stored[i].rel_path) &&
                             closure_is_alias_config(state->aliases, stored[i].rel_path);
        if (removed_alias) {
            closure_seed_governed(state->closure_set, files, file_count, stored[i].rel_path);
            governed_seeded = true;
        } else {
            state->changed_paths[state->n_changed + state->n_deleted++] = stored[i].rel_path;
        }
    }
    return state->n_changed == 0 && state->n_deleted == 0 && !governed_seeded ? "no_file_delta"
                                                                              : NULL;
}

static const cbm_lsp_surface_row_t *closure_probe_row(const closure_plan_state_t *state,
                                                      const char *rel_path) {
    for (int i = 0; i < state->probe_count; i++) {
        if (strcmp(state->probe_rows[i].rel_path, rel_path) == 0) {
            return &state->probe_rows[i];
        }
    }
    return NULL;
}

static const char *closure_plan_probe_changed(cbm_pipeline_t *pipeline, const char *project,
                                              closure_plan_state_t *state) {
    size_t capacity = state->n_changed > 0 ? (size_t)state->n_changed : INCR_MIN_ALLOCATION_ITEMS;
    cbm_file_info_t *probe_files = calloc(capacity, sizeof(*probe_files));
    if (!probe_files) {
        return "alloc";
    }
    for (int i = 0; i < state->n_changed; i++) {
        cbm_file_info_t *file = cbm_ht_get(state->files_by_path, state->changed_paths[i]);
        if (!file) {
            free(probe_files);
            return "changed_not_discovered";
        }
        probe_files[i] = *file;
    }
    if (state->n_changed > 0 &&
        closure_probe_surfaces(pipeline, project, probe_files, state->n_changed, &state->probe_rows,
                               &state->probe_count) != 0) {
        free(probe_files);
        return "probe_failed";
    }
    state->probe_files = probe_files;
    return NULL;
}

static const char *closure_plan_finalize_files(cbm_file_info_t *files, int file_count,
                                               closure_plan_t *plan, closure_plan_state_t *state) {
    for (int i = 0; i < state->n_changed; i++) {
        cbm_ht_set(state->closure_set, state->changed_paths[i],
                   nonowning_ptr(state->changed_paths[i]));
    }
    for (int i = 0; i < state->dependent_count; i++) {
        if (!cbm_ht_get(state->files_by_path, state->dependents[i])) {
            return "dependent_not_discovered";
        }
        cbm_ht_set(state->closure_set, state->dependents[i], state->dependents[i]);
    }
    int closure_count = (int)cbm_ht_count(state->closure_set);
    if (closure_count > CLOSURE_BUDGET_FLOOR_FILES &&
        closure_count * INCR_CLOSURE_BUDGET_PERCENT_SCALE > file_count * CLOSURE_BUDGET_PERCENT) {
        return "budget_exceeded";
    }
    plan->files = calloc((size_t)(closure_count ? closure_count : INCR_MIN_ALLOCATION_ITEMS),
                         sizeof(*plan->files));
    if (!plan->files) {
        return "alloc";
    }
    for (int i = 0; i < file_count; i++) {
        if (cbm_ht_get(state->closure_set, files[i].rel_path)) {
            plan->files[plan->count++] = files[i];
        }
    }
    plan->n_changed = state->n_changed;
    plan->n_dependents = state->dependent_count;
    return NULL;
}

static const char *closure_plan_load_surfaces(cbm_pipeline_t *pipeline, cbm_store_t *store,
                                              const char *project, cbm_file_info_t *files,
                                              int file_count, closure_plan_t *plan,
                                              closure_plan_state_t *state) {
    if (cbm_store_get_lsp_surfaces(store, project, &plan->stored_rows, &plan->stored_count) !=
            CBM_STORE_OK ||
        plan->stored_count == 0) {
        return "no_surface_rows";
    }
    CBMHashTable *rows_by_path = cbm_ht_create((size_t)plan->stored_count * PAIR_LEN);
    if (!rows_by_path) {
        return "alloc";
    }
    for (int i = 0; i < plan->stored_count; i++) {
        cbm_ht_set(rows_by_path, plan->stored_rows[i].rel_path, &plan->stored_rows[i]);
    }
    const char *decline = closure_plan_probe_changed(pipeline, project, state);
    if (decline) {
        cbm_ht_free(rows_by_path);
        return decline;
    }
    int target_total = state->n_changed + state->n_deleted;
    size_t target_capacity = target_total > 0 ? (size_t)target_total : INCR_MIN_ALLOCATION_ITEMS;
    const char **targets = calloc(target_capacity, sizeof(*targets));
    if (!targets) {
        cbm_ht_free(rows_by_path);
        return "alloc";
    }
    int target_count = 0;
    for (int i = 0; !decline && i < state->n_changed; i++) {
        const cbm_lsp_surface_row_t *stored_row = cbm_ht_get(rows_by_path, state->changed_paths[i]);
        const cbm_lsp_surface_row_t *fresh_row = closure_probe_row(state, state->changed_paths[i]);
        if (!stored_row || !fresh_row) {
            decline = "missing_surface_row";
        } else if (strcmp(stored_row->surface_sha, fresh_row->surface_sha) != 0) {
            bool added = false;
            if (surface_added_names(stored_row->defs_json, fresh_row->defs_json, &added) != 0 ||
                added) {
                decline = "added_definition_names";
            } else {
                state->n_surface_changed++;
                targets[target_count++] = state->changed_paths[i];
            }
        }
    }
    for (int i = 0; i < state->n_deleted; i++) {
        targets[target_count++] = state->changed_paths[state->n_changed + i];
    }
    cbm_ht_free(rows_by_path);
    if (!decline && target_count > 0 &&
        cbm_store_get_dependent_files(store, project, targets, target_count, &state->dependents,
                                      &state->dependent_count) != CBM_STORE_OK) {
        decline = "dependent_query_failed";
    }
    free(targets);
    if (decline) {
        return decline;
    }
    return closure_plan_finalize_files(files, file_count, plan, state);
}

/* Decide whether this manifest delta is closure-repairable, and if so build
 * the plan. Returns 1 with *plan filled, or 0 (decline → FULL) with the
 * reason logged. Every early exit declines; nothing here mutates state. */
static int closure_try_plan(cbm_pipeline_t *p, cbm_store_t *store, const char *project,
                            cbm_file_info_t *files, int file_count, const cbm_file_hash_t *stored,
                            int stored_count, const cbm_file_hash_t *fresh, int fresh_count,
                            closure_plan_t *plan) {
    memset(plan, 0, sizeof(*plan));
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    const char *decline = NULL;

    /* Index the fresh manifest and discovery list by rel_path. */
    closure_plan_state_t state = {0};
    if (!closure_plan_state_index_manifests(&state, files, file_count, stored, stored_count, fresh,
                                            fresh_count)) {
        decline = "alloc";
        goto done;
    }

    /* Delta classification straight from the semantic manifests (content
     * hashes, not mtimes). Virtual entries are config/lockfile digests —
     * their effect on resolution is not file-local, so any delta there
     * declines. New files decline: yesterday's graph cannot know who would
     * reference a file that did not exist. */
    decline = closure_plan_classify_manifest(&state, p, files, file_count, stored, stored_count,
                                             fresh, fresh_count);
    if (decline) {
        goto done;
    }

    decline = closure_plan_load_surfaces(p, store, project, files, file_count, plan, &state);
    if (decline) {
        goto done;
    }
    /* Two calls, not one: itoa_buf recycles a four-slot ring, so six
     * conversions in a single call print two corrupted fields (observed:
     * surface_changed reporting the elapsed-ms value at kernel scale). */
    cbm_log_info("incremental.closure_plan", "changed", itoa_buf(state.n_changed),
                 "surface_changed", itoa_buf(state.n_surface_changed), "deleted",
                 itoa_buf(state.n_deleted), "dependents", itoa_buf(state.dependent_count));
    cbm_log_info("incremental.closure_plan_done", "closure", itoa_buf(plan->count), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));

done:
    closure_plan_state_destroy(&state);
    if (decline) {
        cbm_log_info("incremental.closure_decline", "reason", decline, "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t)));
        cbm_store_free_lsp_surfaces(plan->stored_rows, plan->stored_count);
        memset(plan, 0, sizeof(*plan));
        return 0;
    }
    return INCR_CLOSURE_PLAN_READY_STATUS;
}

/* ── Delta-repair orchestration (closure route) ──────────────────
 *
 * The closure route's executor: clone the live generation, repair the
 * closure against proxy nodes carrying real database ids, patch the clone
 * transactionally, publish through the shared staged tail. No full graph
 * load, no full dump. EVERY failure discards the stage and returns
 * CBM_PIPELINE_FORCE_FULL_REINDEX: the live database is never touched, so
 * a full rebuild always self-heals whatever the delta could not do.
 *
 * Takes ownership of changed_files/deleted/mode_skipped/old_cov/plan and
 * closes `store` (the routing read connection). */
static int closure_delta_open_stage(const char *db_path, char **stage, cbm_store_t **staging) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    if (cbm_delta_stage_clone(db_path, stage) != 0) {
        return CBM_NOT_FOUND;
    }
    cbm_log_info("delta.clone", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    *staging = cbm_store_open_path(*stage);
    if (!*staging) {
        return CBM_NOT_FOUND;
    }
    cbm_log_info("delta.staging_open", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    return 0;
}

static int closure_delta_prepare_purge(cbm_store_t *staging, const char *project,
                                       cbm_file_info_t *changed_files, int ci, char **deleted,
                                       int deleted_count, const char ***purge_paths,
                                       cbm_delta_saved_edge_t **snapshot, int *snapshot_count) {
    int purge_count = ci + deleted_count;
    const char **paths =
        calloc((size_t)(purge_count ? purge_count : INCR_MIN_ALLOCATION_ITEMS), sizeof(*paths));
    if (!paths) {
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < ci; i++) {
        paths[i] = changed_files[i].rel_path;
    }
    for (int i = 0; i < deleted_count; i++) {
        paths[ci + i] = deleted[i];
    }
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    int rc =
        cbm_delta_snapshot_inbound(staging, project, paths, purge_count, snapshot, snapshot_count);
    if (rc == 0) {
        rc = cbm_delta_purge(staging, project, paths, purge_count);
    }
    cbm_log_info("delta.snapshot_purge", "captured", itoa_buf(*snapshot_count), "purged_files",
                 itoa_buf(purge_count), "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    if (rc != 0) {
        free(paths);
        return rc;
    }
    *purge_paths = paths;
    return 0;
}

static void closure_delta_release_rehydrate(closure_resolve_t *resolve) {
    cbm_store_free_lsp_surfaces(resolve->fresh_rows, resolve->fresh_count);
    for (int i = 0; i < resolve->def_module_count; i++) {
        free(resolve->def_modules[i]);
    }
    free(resolve->def_modules);
    for (int i = 0; i < resolve->rehydrate_arena_count; i++) {
        cbm_arena_destroy(&resolve->rehydrate_arenas[i]);
    }
    free(resolve->rehydrate_arenas);
    cbm_arena_destroy(&resolve->arena);
}

static void closure_delta_cleanup(
    cbm_store_t *staging, char *stage, cbm_delta_saved_edge_t *snapshot, int snapshot_count,
    CBMHashTable *stale_surface_set, closure_resolve_t *resolve, bool resolve_live,
    cbm_file_hash_t *manifest, int manifest_count, cbm_coverage_row_t *cov,
    const char **purge_paths, cbm_registry_t *registry, cbm_path_alias_collection_t *path_aliases,
    cbm_gbuf_t *gbuf, closure_plan_t *plan, cbm_file_info_t *changed_files, char **deleted,
    int deleted_count, cbm_file_hash_t *mode_skipped, int mode_skipped_count,
    cbm_coverage_row_t *old_cov, int old_cov_count) {
    if (staging) {
        cbm_store_close(staging);
    }
    if (stage) {
        cbm_pipeline_discard_stage(stage);
        free(stage);
    }
    cbm_delta_free_snapshot(snapshot, snapshot_count);
    surface_name_set_free(stale_surface_set);
    if (resolve_live) {
        closure_delta_release_rehydrate(resolve);
    }
    cbm_pipeline_free_semantic_manifest(manifest, manifest_count);
    free(cov);
    free(purge_paths);
    cbm_registry_free(registry);
    cbm_path_alias_collection_free(path_aliases);
    cbm_gbuf_free(gbuf);
    closure_plan_free(plan);
    free(changed_files);
    for (int i = 0; i < deleted_count; i++) {
        free(deleted[i]);
    }
    free(deleted);
    free_mode_skipped(mode_skipped, mode_skipped_count);
    cbm_store_free_coverage(old_cov, old_cov_count);
}

static int closure_delta_prepare_graph(cbm_pipeline_t *pipeline, cbm_store_t *staging,
                                       const char *project, cbm_gbuf_t **gbuf_out,
                                       cbm_registry_t **registry_out, int64_t *max_db_id_out) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_gbuf_t *gbuf = cbm_gbuf_new(project, cbm_pipeline_repo_path(pipeline));
    if (!gbuf) {
        return CBM_NOT_FOUND;
    }
    int64_t max_db_id = cbm_delta_preseed(staging, project, gbuf);
    cbm_registry_t *registry = max_db_id < 0 ? NULL : cbm_registry_new();
    if (!registry) {
        cbm_gbuf_free(gbuf);
        return CBM_NOT_FOUND;
    }
    cbm_gbuf_foreach_node(gbuf, registry_visitor, registry);
    cbm_log_info("delta.preseed_done", "registry", itoa_buf(cbm_registry_size(registry)),
                 "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    *gbuf_out = gbuf;
    *registry_out = registry;
    *max_db_id_out = max_db_id;
    return 0;
}

static CBMHashTable *closure_delta_stale_surface_set(const char *const *purge_paths,
                                                     int purge_count) {
    CBMHashTable *set = cbm_ht_create(((size_t)purge_count * PAIR_LEN) + CBM_SZ_64);
    if (!set) {
        return NULL;
    }
    for (int i = 0; i < purge_count; i++) {
        char *key = strdup(purge_paths[i]);
        if (!key) {
            surface_name_set_free(set);
            return NULL;
        }
        cbm_ht_set(set, key, key);
    }
    return set;
}

static void closure_delta_add_file_nodes(cbm_gbuf_t *gbuf, const char *project,
                                         const cbm_file_info_t *files, int file_count) {
    for (int i = 0; i < file_count; i++) {
        char *file_qn = cbm_pipeline_fqn_compute(project, files[i].rel_path, "__file__");
        if (!file_qn) {
            continue;
        }
        const char *rel = files[i].rel_path;
        const char *slash = strrchr(rel, '/');
        const char *basename = slash ? slash + SKIP_ONE : rel;
        const char *ext = strrchr(basename, '.');
        char props[CBM_SZ_256];
        snprintf(props, sizeof(props), "{\"extension\":\"%s\"}", ext ? ext : "");
        const char *qualified_name = file_qn;
        const char *file_path = rel;
        cbm_gbuf_upsert_node(gbuf, "File", basename, qualified_name, file_path, 0, 0, props);
        free(file_qn);
    }
}

static void closure_delta_release_context(cbm_pipeline_ctx_t *ctx) {
    if (ctx->return_type_table) {
        for (int i = 0; i < ctx->return_type_table->count; i++) {
            free_owned(ctx->return_type_table->entries[i].return_type);
        }
        free_owned(ctx->return_type_table);
    }
    free_owned(ctx->macro_table);
    cbm_pkgmap_free(cbm_pipeline_get_pkgmap());
    cbm_pipeline_set_pkgmap(NULL);
}

static int closure_delta_run_repair(cbm_pipeline_t *pipeline, const char *project, cbm_gbuf_t *gbuf,
                                    cbm_registry_t *registry,
                                    cbm_path_alias_collection_t **aliases_out,
                                    cbm_file_info_t *changed_files, int ci,
                                    closure_resolve_t *resolve) {
    char **excluded_dirs = NULL;
    int excluded_count = 0;
    cbm_pipeline_get_excluded(pipeline, &excluded_dirs, &excluded_count);
    *aliases_out = cbm_load_path_aliases_excluded(cbm_pipeline_repo_path(pipeline), excluded_dirs,
                                                  excluded_count);
    cbm_pipeline_ctx_t ctx = {
        .project_name = project,
        .repo_path = cbm_pipeline_repo_path(pipeline),
        .gbuf = gbuf,
        .registry = registry,
        .cancelled = cbm_pipeline_cancelled_ptr(pipeline),
        .pipeline = pipeline,
        .mode = cbm_pipeline_get_mode(pipeline),
        .path_aliases = *aliases_out,
        .excluded_dirs = excluded_dirs,
        .excluded_count = excluded_count,
    };
    closure_delta_add_file_nodes(gbuf, project, changed_files, ci);
    int rc = run_extract_resolve(&ctx, changed_files, ci, resolve);
    if (rc == 0) {
        rc = cbm_pipeline_pass_k8s(&ctx, changed_files, ci);
    }
    if (rc == 0) {
        rc = cbm_pipeline_check_cancel(&ctx);
    }
    if (rc == 0) {
        rc = run_postpasses(&ctx, changed_files, ci, project);
    }
    closure_delta_release_context(&ctx);
    return rc;
}

typedef struct {
    cbm_coverage_row_t *rows;
    int count;
    bool available;
    int ignored_count;
    int ignored_total;
} closure_coverage_t;

static closure_coverage_t closure_delta_collect_coverage(cbm_pipeline_t *pipeline,
                                                         const cbm_coverage_row_t *old_cov,
                                                         int old_cov_count,
                                                         const CBMHashTable *stale_surface_set) {
    cbm_file_error_t *errors = NULL;
    int error_count = 0;
    cbm_pipeline_get_file_errors(pipeline, &errors, &error_count);
    char **excluded = NULL;
    int excluded_count = 0;
    cbm_pipeline_get_excluded(pipeline, &excluded, &excluded_count);
    cbm_ignored_file_t *ignored = NULL;
    closure_coverage_t coverage = {0};
    cbm_pipeline_get_ignored(pipeline, &ignored, &coverage.ignored_count, &coverage.ignored_total);
    int capacity = old_cov_count + error_count + excluded_count + coverage.ignored_count;
    coverage.available = capacity == 0;
    coverage.rows = capacity > 0 ? malloc((size_t)capacity * sizeof(*coverage.rows)) : NULL;
    coverage.available = coverage.available || coverage.rows != NULL;
    if (!coverage.rows) {
        return coverage;
    }
    for (int i = 0; i < old_cov_count; i++) {
        bool by_design = old_cov[i].kind && strncmp(old_cov[i].kind, "not_indexed",
                                                    INCR_NOT_INDEXED_PREFIX_BYTES) == 0;
        if (!by_design && old_cov[i].rel_path &&
            !cbm_ht_get(stale_surface_set, old_cov[i].rel_path)) {
            coverage.rows[coverage.count++] = old_cov[i];
        }
    }
    for (int i = 0; i < error_count; i++) {
        coverage.rows[coverage.count++] = (cbm_coverage_row_t){
            .rel_path = errors[i].path, .kind = errors[i].phase, .detail = errors[i].reason};
    }
    for (int i = 0; i < excluded_count; i++) {
        coverage.rows[coverage.count++] = (cbm_coverage_row_t){
            .rel_path = excluded[i], .kind = "not_indexed_dir", .detail = "excluded subtree"};
    }
    for (int i = 0; i < coverage.ignored_count; i++) {
        coverage.rows[coverage.count++] = (cbm_coverage_row_t){.rel_path = ignored[i].rel_path,
                                                               .kind = "not_indexed_file",
                                                               .detail = ignored[i].reason};
    }
    return coverage;
}

static int closure_delta_verify_manifest(cbm_pipeline_t *pipeline, const char *project,
                                         const cbm_file_hash_t *baseline, int baseline_count,
                                         cbm_file_hash_t **manifest, int *manifest_count) {
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
    cbm_pipeline_persist_test_run_before_final_manifest();
#endif
    if (cbm_pipeline_build_fresh_semantic_manifest(project, cbm_pipeline_repo_path(pipeline),
                                                   cbm_pipeline_get_mode(pipeline), manifest,
                                                   manifest_count) != 0 ||
        !cbm_pipeline_semantic_manifests_equal(baseline, baseline_count, *manifest,
                                               *manifest_count)) {
        cbm_log_warn("delta.abort", "reason", "semantic_inputs_changed");
        return CBM_PIPELINE_ABORT_PRESERVE_DB;
    }
    return 0;
}

static int closure_delta_update_surfaces(cbm_store_t *staging, const char *project,
                                         const char *const *purge_paths, int purge_count,
                                         const closure_resolve_t *resolve) {
    cbm_sql_t *db = cbm_store_sql(staging);
    cbm_sql_stmt_t *statement = NULL;
    bool ok = db != NULL && cbm_sql_prepare(db,
                                            "DELETE FROM lsp_surface WHERE project = ?1"
                                            " AND rel_path = ?2",
                                            &statement);
    for (int i = 0; ok && i < purge_count; i++) {
        cbm_sql_reset(statement);
        cbm_sql_bind_text(statement, INCR_SQL_PROJECT_PARAMETER, project);
        cbm_sql_bind_text(statement, INCR_SQL_REL_PATH_PARAMETER, purge_paths[i]);
        ok = cbm_sql_step(statement) == CBM_SQL_DONE;
    }
    cbm_sql_finalize(statement);
    return ok && cbm_store_upsert_lsp_surface_batch(staging, resolve->fresh_rows,
                                                    resolve->fresh_count) == CBM_STORE_OK
               ? 0
               : CBM_NOT_FOUND;
}

static const cbm_lsp_surface_row_t **closure_delta_eligible_rows(
    const closure_plan_t *plan, const CBMHashTable *stale_surface_set, int *count) {
    size_t capacity =
        plan->stored_count > 0 ? (size_t)plan->stored_count : INCR_MIN_ALLOCATION_ITEMS;
    const cbm_lsp_surface_row_t **rows = calloc(capacity, sizeof(*rows));
    if (!rows) {
        return NULL;
    }
    for (int i = 0; i < plan->stored_count; i++) {
        const cbm_lsp_surface_row_t *row = &plan->stored_rows[i];
        if (!cbm_ht_get(stale_surface_set, row->rel_path)) {
            rows[(*count)++] = row;
        }
    }
    return rows;
}

static int closure_delta_rehydrate_rows(const cbm_lsp_surface_row_t *const *rows, int row_count,
                                        closure_resolve_t *resolve, CBMLSPDef ***defs_out,
                                        int **counts_out) {
    int workers = cbm_default_worker_count(true);
    workers = workers < INCR_MIN_WORKER_COUNT ? INCR_MIN_WORKER_COUNT : workers;
    if (workers > row_count) {
        workers = row_count > 0 ? row_count : INCR_MIN_WORKER_COUNT;
    }
    size_t capacity = row_count > 0 ? (size_t)row_count : INCR_MIN_ALLOCATION_ITEMS;
    CBMLSPDef **defs = calloc(capacity, sizeof(*defs));
    int *counts = calloc(capacity, sizeof(*counts));
    resolve->rehydrate_arenas = calloc((size_t)workers, sizeof(*resolve->rehydrate_arenas));
    cbm_thread_t *threads = calloc((size_t)workers, sizeof(*threads));
    rehydrate_worker_t *worker_args = calloc((size_t)workers, sizeof(*worker_args));
    if (!defs || !counts || !resolve->rehydrate_arenas || !threads || !worker_args) {
        free(defs);
        free(counts);
        free(threads);
        free(worker_args);
        return CBM_NOT_FOUND;
    }
    resolve->rehydrate_arena_count = workers;
    for (int worker = 0; worker < workers; worker++) {
        cbm_arena_init(&resolve->rehydrate_arenas[worker]);
        worker_args[worker] = (rehydrate_worker_t){
            .rows = rows,
            .row_count = row_count,
            .worker_id = worker,
            .worker_count = workers,
            .arena = &resolve->rehydrate_arenas[worker],
            .row_defs = defs,
            .row_counts = counts,
        };
    }
    int spawned = 0;
    for (; spawned < workers; spawned++) {
        if (cbm_thread_create(&threads[spawned], 0, rehydrate_worker, &worker_args[spawned]) != 0) {
            break;
        }
    }
    for (int worker = spawned; worker < workers; worker++) {
        (void)rehydrate_worker(&worker_args[worker]);
    }
    for (int worker = 0; worker < spawned; worker++) {
        cbm_thread_join(&threads[worker]);
    }
    free(threads);
    free(worker_args);
    *defs_out = defs;
    *counts_out = counts;
    return 0;
}

static int closure_delta_merge_rehydrated(closure_resolve_t *resolve,
                                          const cbm_lsp_surface_row_t *const *rows, int row_count,
                                          CBMLSPDef *const *row_defs, const int *row_counts) {
    int64_t total = 0;
    for (int i = 0; i < row_count; i++) {
        if (row_counts[i] < 0) {
            cbm_log_error("delta.rehydrate_failed", "path", rows[i]->rel_path);
            return CBM_NOT_FOUND;
        }
        total += row_counts[i];
    }
    if (total == 0) {
        return 0;
    }
    resolve->base_defs =
        cbm_arena_alloc(&resolve->arena, (size_t)total * sizeof(*resolve->base_defs));
    if (!resolve->base_defs) {
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < row_count; i++) {
        if (row_counts[i] > 0) {
            memcpy(resolve->base_defs + resolve->base_def_count, row_defs[i],
                   (size_t)row_counts[i] * sizeof(*resolve->base_defs));
            resolve->base_def_count += row_counts[i];
        }
    }
    return 0;
}

static int closure_delta_rehydrate(const closure_plan_t *plan,
                                   const CBMHashTable *stale_surface_set,
                                   closure_resolve_t *resolve) {
    int row_count = 0;
    const cbm_lsp_surface_row_t **rows =
        closure_delta_eligible_rows(plan, stale_surface_set, &row_count);
    CBMLSPDef **row_defs = NULL;
    int *row_counts = NULL;
    int rc = rows ? closure_delta_rehydrate_rows(rows, row_count, resolve, &row_defs, &row_counts)
                  : CBM_NOT_FOUND;
    if (rc == 0) {
        rc = closure_delta_merge_rehydrated(resolve, rows, row_count, row_defs, row_counts);
    }
    free(rows);
    free(row_defs);
    free(row_counts);
    return rc;
}

static int run_closure_delta(cbm_pipeline_t *p, const char *db_path, const char *project,
                             const cbm_file_hash_t *baseline_manifest, int baseline_count,
                             closure_plan_t *plan, cbm_file_info_t *changed_files, int ci,
                             char **deleted, int deleted_count, cbm_file_hash_t *mode_skipped,
                             int mode_skipped_count, cbm_coverage_row_t *old_cov, int old_cov_count,
                             cbm_store_t *route_store, struct timespec t0) {
    struct timespec t;
    cbm_store_close(route_store);

    int result = CBM_PIPELINE_FORCE_FULL_REINDEX;
    char *stage = NULL;
    cbm_store_t *staging = NULL;
    cbm_delta_saved_edge_t *snapshot = NULL;
    int snapshot_count = 0;
    cbm_gbuf_t *gbuf = NULL;
    cbm_registry_t *registry = NULL;
    cbm_path_alias_collection_t *path_aliases = NULL;
    CBMHashTable *stale_surface_set = NULL;
    closure_resolve_t cr = {0};
    bool cr_arena_live = false;
    const char **purge_paths = NULL;
    cbm_file_hash_t *manifest = NULL;
    int manifest_count = 0;
    cbm_coverage_row_t *cov = NULL;
    int cov_n = 0;

    int purge_count = ci + deleted_count;
    if (closure_delta_open_stage(db_path, &stage, &staging) != 0 ||
        closure_delta_prepare_purge(staging, project, changed_files, ci, deleted, deleted_count,
                                    &purge_paths, &snapshot, &snapshot_count) != 0) {
        goto out;
    }

    int64_t max_db_id = 0;
    if (closure_delta_prepare_graph(p, staging, project, &gbuf, &registry, &max_db_id) != 0) {
        goto out;
    }
    stale_surface_set = closure_delta_stale_surface_set(purge_paths, purge_count);
    if (!stale_surface_set) {
        goto out;
    }
    cbm_arena_init(&cr.arena);
    cr_arena_live = true;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    if (closure_delta_rehydrate(plan, stale_surface_set, &cr) != 0) {
        goto out;
    }
    cbm_log_info("delta.rehydrate", "defs", itoa_buf(cr.base_def_count), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));

    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    int phase_rc =
        closure_delta_run_repair(p, project, gbuf, registry, &path_aliases, changed_files, ci, &cr);
    if (phase_rc != 0) {
        cbm_log_error("delta.err", "phase", "extract_resolve", "rc", itoa_buf(phase_rc));
        goto out;
    }
    cbm_log_info("delta.repair", "files", itoa_buf(ci), "elapsed_ms", itoa_buf((int)elapsed_ms(t)));

    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    if (cbm_delta_patch(staging, project, gbuf, max_db_id, snapshot, snapshot_count) != 0) {
        goto out;
    }
    cbm_log_info("delta.patch_done", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));

    closure_coverage_t coverage =
        closure_delta_collect_coverage(p, old_cov, old_cov_count, stale_surface_set);
    cov = coverage.rows;
    cov_n = coverage.count;

    if (closure_delta_verify_manifest(p, project, baseline_manifest, baseline_count, &manifest,
                                      &manifest_count) != 0) {
        result = CBM_PIPELINE_ABORT_PRESERVE_DB;
        goto out;
    }

    if (closure_delta_update_surfaces(staging, project, purge_paths, purge_count, &cr) != 0) {
        goto out;
    }

    /* Committed counts for the #334 plausibility gate. */
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_pipeline_set_committed_counts(p, cbm_store_count_nodes(staging, project),
                                      cbm_store_count_edges(staging, project));
    cbm_log_info("delta.committed_counts", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));

    {
        int index_mode = cbm_pipeline_get_mode(p);
        cbm_pipeline_generation_t generation = {
            .gbuf = NULL,
            .final_db_path = db_path,
            .project = project,
            .cancelled = cbm_pipeline_cancelled_ptr(p),
            .manifest = manifest,
            .manifest_count = manifest_count,
            .adr_content = NULL, /* the clone already carries the ADR rows */
            .coverage = cov,
            .coverage_count = cov_n,
            .coverage_meta =
                {
                    .index_mode = incr_mode_name(index_mode),
                    .recording_status = incr_coverage_recording_status(
                        coverage.available, coverage.ignored_total, coverage.ignored_count),
                    .ignored_files_stored = coverage.ignored_count,
                    .ignored_files_total = coverage.ignored_total,
                    .coverage_version = CBM_SEMANTIC_INDEX_VERSION,
                    .hash_records_complete = true,
                },
            .surface_rows = NULL,
            .surface_row_count = 0,
            .surfaces_in_place = true,
        };
        cbm_store_close(staging);
        staging = NULL;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t);
        result = cbm_pipeline_publish_staged(stage, &generation, false, true);
        cbm_log_info("delta.publish_total", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
        stage = NULL; /* publish_staged owns and frees it on every path */
    }
    cbm_log_info("incremental.done_delta", "elapsed_ms", itoa_buf((int)elapsed_ms(t0)));

out:
    if (result == CBM_PIPELINE_FORCE_FULL_REINDEX) {
        cbm_log_warn("delta.fallback", "reason", "delta_failed_full_rebuild");
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
        incr_test_set_last_route(CBM_INCREMENTAL_ROUTE_FORCED_FULL);
#endif
    }
    closure_delta_cleanup(staging, stage, snapshot, snapshot_count, stale_surface_set, &cr,
                          cr_arena_live, manifest, manifest_count, cov, purge_paths, registry,
                          path_aliases, gbuf, plan, changed_files, deleted, deleted_count,
                          mode_skipped, mode_skipped_count, old_cov, old_cov_count);
    return result;
}

/* ── Incremental pipeline entry point ────────────────────────────── */

static cbm_file_info_t *incremental_changed_files(const cbm_file_info_t *files, int file_count,
                                                  const bool *is_changed,
                                                  const closure_plan_t *closure_plan,
                                                  bool closure_active, int n_changed,
                                                  int *changed_count) {
    cbm_file_info_t *changed = n_changed > 0 ? malloc((size_t)n_changed * sizeof(*changed)) : NULL;
    for (int i = 0; closure_active && i < closure_plan->count; i++) {
        changed[(*changed_count)++] = closure_plan->files[i];
    }
    for (int i = 0; !closure_active && i < file_count; i++) {
        if (is_changed[i]) {
            changed[(*changed_count)++] = files[i];
        }
    }
    return changed;
}

static int incremental_load_graph(const char *db_path, const char *project, const char *repo_path,
                                  cbm_gbuf_t **out) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_gbuf_t *graph = cbm_gbuf_new(project, repo_path);
    int rc = graph ? cbm_gbuf_load_from_db(graph, db_path, project) : CBM_NOT_FOUND;
    cbm_log_info("incremental.load_db", "rc", itoa_buf(rc), "nodes",
                 itoa_buf(graph ? cbm_gbuf_node_count(graph) : 0), "edges",
                 itoa_buf(graph ? cbm_gbuf_edge_count(graph) : 0), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));
    if (rc != 0) {
        cbm_gbuf_free(graph);
        return rc;
    }
    *out = graph;
    return 0;
}

static int incremental_load_adr(cbm_store_t *store, const char *project, char **saved_adr) {
    cbm_adr_t adr = {0};
    int rc = cbm_store_adr_get(store, project, &adr);
    bool had_content = rc == CBM_STORE_OK && adr.content != NULL;
    if (had_content) {
        *saved_adr = strdup(adr.content);
    }
    cbm_store_adr_free(&adr);
    return rc == CBM_STORE_NOT_FOUND || (rc == CBM_STORE_OK && (!had_content || *saved_adr))
               ? 0
               : CBM_NOT_FOUND;
}

static void incremental_capture_inbound(cbm_gbuf_t *graph, cbm_file_info_t *changed_files, int ci,
                                        cbm_edge_capture_t *capture) {
    CBMHashTable *changed_paths = cbm_ht_create(ci > 0 ? (size_t)ci * PAIR_LEN : CBM_SZ_64);
    for (int i = 0; i < ci; i++) {
        cbm_ht_set(changed_paths, changed_files[i].rel_path, &changed_files[i]);
    }
    capture->gbuf = graph;
    capture->changed_paths = changed_paths;
    cbm_gbuf_foreach_edge(graph, incr_capture_inbound_edge, capture);
    capture->changed_paths = NULL;
    cbm_ht_free(changed_paths);
}

static void incremental_purge_files(cbm_gbuf_t *graph, cbm_file_info_t *changed_files, int ci,
                                    char **deleted, int deleted_count) {
    for (int i = 0; i < ci; i++) {
        cbm_gbuf_delete_by_file(graph, changed_files[i].rel_path);
    }
    for (int i = 0; i < deleted_count; i++) {
        cbm_gbuf_delete_by_file(graph, deleted[i]);
        free(deleted[i]);
    }
    free(deleted);
}

static void incremental_free_deleted_paths(char **deleted, int deleted_count) {
    for (int i = 0; i < deleted_count; i++) {
        free(deleted[i]);
    }
    free(deleted);
}

static int incremental_run_repair(cbm_pipeline_t *pipeline, const char *project, cbm_gbuf_t *graph,
                                  cbm_registry_t *registry,
                                  cbm_path_alias_collection_t **aliases_out,
                                  cbm_file_info_t *changed_files, int ci) {
    char **excluded_dirs = NULL;
    int excluded_count = 0;
    cbm_pipeline_get_excluded(pipeline, &excluded_dirs, &excluded_count);
    *aliases_out = cbm_load_path_aliases_excluded(cbm_pipeline_repo_path(pipeline), excluded_dirs,
                                                  excluded_count);
    cbm_pipeline_ctx_t ctx = {
        .project_name = project,
        .repo_path = cbm_pipeline_repo_path(pipeline),
        .gbuf = graph,
        .registry = registry,
        .cancelled = cbm_pipeline_cancelled_ptr(pipeline),
        .pipeline = pipeline,
        .mode = cbm_pipeline_get_mode(pipeline),
        .path_aliases = *aliases_out,
        .excluded_dirs = excluded_dirs,
        .excluded_count = excluded_count,
    };
    closure_delta_add_file_nodes(graph, project, changed_files, ci);
    int rc = run_extract_resolve(&ctx, changed_files, ci, NULL);
    if (rc == 0) {
        rc = cbm_pipeline_pass_k8s(&ctx, changed_files, ci);
    }
    if (rc == 0) {
        rc = cbm_pipeline_check_cancel(&ctx);
    }
    if (rc == 0) {
        rc = run_postpasses(&ctx, changed_files, ci, project);
    }
    closure_delta_release_context(&ctx);
    return rc;
}

static closure_coverage_t incremental_collect_coverage(cbm_pipeline_t *pipeline,
                                                       const cbm_coverage_row_t *old_cov,
                                                       int old_cov_count,
                                                       const cbm_file_info_t *changed_files,
                                                       int changed_count) {
    CBMHashTable *changed_set =
        cbm_ht_create(changed_count > 0 ? (size_t)changed_count * PAIR_LEN : CBM_SZ_64);
    for (int i = 0; i < changed_count; i++) {
        cbm_ht_set(changed_set, changed_files[i].rel_path, nonowning_ptr(&changed_files[i]));
    }
    cbm_file_error_t *errors = NULL;
    int error_count = 0;
    cbm_pipeline_get_file_errors(pipeline, &errors, &error_count);
    char **excluded = NULL;
    int excluded_count = 0;
    cbm_pipeline_get_excluded(pipeline, &excluded, &excluded_count);
    cbm_ignored_file_t *ignored = NULL;
    closure_coverage_t coverage = {0};
    cbm_pipeline_get_ignored(pipeline, &ignored, &coverage.ignored_count, &coverage.ignored_total);
    int capacity = old_cov_count + error_count + excluded_count + coverage.ignored_count;
    coverage.available = capacity == 0;
    coverage.rows = capacity > 0 ? malloc((size_t)capacity * sizeof(*coverage.rows)) : NULL;
    coverage.available = coverage.available || coverage.rows != NULL;
    if (coverage.rows) {
        for (int i = 0; i < old_cov_count; i++) {
            bool by_design = old_cov[i].kind && strncmp(old_cov[i].kind, "not_indexed",
                                                        INCR_NOT_INDEXED_PREFIX_BYTES) == 0;
            if (!by_design && old_cov[i].rel_path &&
                !cbm_ht_get(changed_set, old_cov[i].rel_path)) {
                coverage.rows[coverage.count++] = old_cov[i];
            }
        }
        for (int i = 0; i < error_count; i++) {
            coverage.rows[coverage.count++] = (cbm_coverage_row_t){
                .rel_path = errors[i].path, .kind = errors[i].phase, .detail = errors[i].reason};
        }
        for (int i = 0; i < excluded_count; i++) {
            coverage.rows[coverage.count++] = (cbm_coverage_row_t){
                .rel_path = excluded[i], .kind = "not_indexed_dir", .detail = "excluded subtree"};
        }
        for (int i = 0; i < coverage.ignored_count; i++) {
            coverage.rows[coverage.count++] = (cbm_coverage_row_t){.rel_path = ignored[i].rel_path,
                                                                   .kind = "not_indexed_file",
                                                                   .detail = ignored[i].reason};
        }
    }
    cbm_ht_free(changed_set);
    return coverage;
}

int cbm_pipeline_run_incremental(cbm_pipeline_t *p, const char *db_path, cbm_file_info_t *files,
                                 int file_count, const cbm_file_hash_t *baseline_manifest,
                                 int baseline_count) {
    struct timespec t0;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t0);
    closure_plan_t closure_plan = {0};
    bool closure_active = false;

    const char *project = cbm_pipeline_project_name(p);

    bool force_legacy_partial = false;
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
    force_legacy_partial = incr_test_take_force_legacy_partial();
    incr_test_set_last_route(CBM_INCREMENTAL_ROUTE_NONE);
#endif

    /* Exact semantic-manifest routing is read-only. Do not reopen a sealed
     * generation in WAL mode merely to prove that it is already current.
     * Only the legacy partial TEST route needs a writable connection, so the
     * writable branch exists only in test-API builds. */
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
    cbm_store_t *store =
        force_legacy_partial ? cbm_store_open_path(db_path) : cbm_store_open_path_query(db_path);
#else
    cbm_store_t *store = cbm_store_open_path_query(db_path);
#endif
    if (!store) {
        cbm_log_error("incremental.err", "msg", "open_db_failed", "path", db_path);
        return CBM_NOT_FOUND;
    }

    /* Load stored file hashes */
    cbm_file_hash_t *stored = NULL;
    int stored_count = 0;
    if (cbm_store_get_file_hashes(store, project, &stored, &stored_count) != CBM_STORE_OK) {
        cbm_log_error("incremental.err", "msg", "manifest_read_failed", "project", project);
        cbm_store_close(store);
        return CBM_PIPELINE_ABORT_PRESERVE_DB;
    }

    /* Production incremental routing is deliberately binary: an exact
     * semantic-manifest match is a no-op; any byte/set/mode/migration delta
     * rebuilds the complete graph. This avoids partial LSP/package/config
     * convergence gaps while retaining the common unchanged-repo fast path. */
    if (!force_legacy_partial) {
        cbm_coverage_meta_t meta = {0};
        int meta_rc = cbm_store_coverage_meta_get(store, project, &meta);
        const char *mode_name = incr_mode_name(cbm_pipeline_get_mode(p));
        bool metadata_current = meta_rc == CBM_STORE_OK &&
                                meta.coverage_version == CBM_SEMANTIC_INDEX_VERSION &&
                                meta.hash_records_complete && meta.index_mode &&
                                strcmp(meta.index_mode, mode_name) == 0;
        bool exact = metadata_current &&
                     cbm_pipeline_semantic_manifests_equal(stored, stored_count, baseline_manifest,
                                                           baseline_count);
        cbm_store_coverage_meta_clear(&meta);
        if (exact) {
            cbm_store_free_file_hashes(stored, stored_count);
            cbm_store_close(store);
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
            incr_test_set_last_route(CBM_INCREMENTAL_ROUTE_NOOP);
#endif
            cbm_log_info("incremental.noop", "reason", "semantic_manifest_equal");
            return cbm_pipeline_refresh_artifact(p, db_path);
        }
        /* Manifest delta. Closure repair recomputes exactly the changed
         * files plus the recorded consumers of any changed SURFACE; every
         * uncertain case declines inside the planner, making the pre-plan
         * behaviour (full rebuild) the unconditional fallback. */
        if (metadata_current &&
            closure_try_plan(p, store, project, files, file_count, stored, stored_count,
                             baseline_manifest, baseline_count, &closure_plan)) {
            closure_active = true;
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
            incr_test_set_last_route(CBM_INCREMENTAL_ROUTE_CLOSURE_REPAIR);
#endif
            cbm_log_info("incremental.route", "route", "closure_repair", "files",
                         itoa_buf(closure_plan.count));
            /* Fall through into the shared repair tail below. */
        } else {
            cbm_store_free_file_hashes(stored, stored_count);
            cbm_store_close(store);
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
            incr_test_set_last_route(CBM_INCREMENTAL_ROUTE_FORCED_FULL);
#endif
            cbm_log_info("incremental.force_full", "reason", "semantic_manifest_changed");
            return CBM_PIPELINE_FORCE_FULL_REINDEX;
        }
    }

    /* Classify files. The closure route already knows its re-parse set (the
     * plan); the legacy test route keeps its historical mtime+size classify. */
    int n_changed = 0;
    int n_unchanged = 0;
    bool *is_changed = NULL;
    if (closure_active) {
        n_changed = closure_plan.count;
    } else {
        is_changed =
            classify_files(files, file_count, stored, stored_count, &n_changed, &n_unchanged);
    }

    /* Classify stored files absent from current discovery: truly-deleted
     * (purge) vs mode-skipped (preserve nodes AND hash rows). */
    char **deleted = NULL;
    cbm_file_hash_t *mode_skipped = NULL;
    int mode_skipped_count = 0;
    int deleted_count =
        find_deleted_files(cbm_pipeline_repo_path(p), files, file_count, stored, stored_count,
                           &deleted, &mode_skipped, &mode_skipped_count);

    cbm_log_info("incremental.classify", "changed", itoa_buf(n_changed), "unchanged",
                 itoa_buf(n_unchanged), "deleted", itoa_buf(deleted_count), "mode_skipped",
                 itoa_buf(mode_skipped_count));

    /* Fast path: nothing changed → skip. The on-disk DB is left untouched,
     * which means existing hash rows (including for any mode-skipped files
     * that were already preserved by an earlier run) remain intact. */
    if (!closure_active && n_changed == 0 && deleted_count == 0) {
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
        incr_test_set_last_route(CBM_INCREMENTAL_ROUTE_NOOP);
#endif
        cbm_log_info("incremental.noop", "reason", "no_changes");
        free(is_changed);
        free(deleted);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        cbm_store_free_file_hashes(stored, stored_count);
        cbm_store_close(store);
        return 0;
    }

#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
    if (!closure_active) {
        incr_test_set_last_route(CBM_INCREMENTAL_ROUTE_LEGACY_PARTIAL);
    }
#endif

    cbm_store_free_file_hashes(stored, stored_count);

    /* Coverage rows (#963): the dump below rebuilds the DB file, wiping the
     * separate index_coverage table — capture the previous rows now (store
     * still open) so entries for files NOT re-extracted this run survive. */
    cbm_coverage_row_t *old_cov = NULL;
    int old_cov_count = 0;
    if (cbm_store_coverage_get(store, project, &old_cov, &old_cov_count) != CBM_STORE_OK) {
        cbm_log_error("incremental.err", "msg", "coverage_read_failed", "project", project);
        cbm_store_free_coverage(old_cov, old_cov_count);
        free(is_changed);
        incremental_free_deleted_paths(deleted, deleted_count);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        cbm_store_close(store);
        closure_plan_free(&closure_plan);
        return CBM_PIPELINE_ABORT_PRESERVE_DB;
    }

    int ci = 0;
    cbm_file_info_t *changed_files = incremental_changed_files(
        files, file_count, is_changed, &closure_plan, closure_active, n_changed, &ci);
    free(is_changed);

    cbm_log_info("incremental.reparse", "files", itoa_buf(ci));

    if (closure_active) {
        /* The delta executor owns everything passed and never touches the
         * live database; its every failure falls back to a full rebuild. */
        return run_closure_delta(p, db_path, project, baseline_manifest, baseline_count,
                                 &closure_plan, changed_files, ci, deleted, deleted_count,
                                 mode_skipped, mode_skipped_count, old_cov, old_cov_count, store,
                                 t0);
    }

    struct timespec t;

    cbm_gbuf_t *existing = NULL;
    if (incremental_load_graph(db_path, project, cbm_pipeline_repo_path(p), &existing) != 0) {
        cbm_log_error("incremental.err", "msg", "load_db_failed");
        cbm_gbuf_free(existing);
        free(changed_files);
        incremental_free_deleted_paths(deleted, deleted_count);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        cbm_store_free_coverage(old_cov, old_cov_count);
        cbm_store_close(store);
        closure_plan_free(&closure_plan);
        return CBM_NOT_FOUND;
    }

    char *saved_adr = NULL;
    if (incremental_load_adr(store, project, &saved_adr) != 0) {
        cbm_gbuf_free(existing);
        free(changed_files);
        incremental_free_deleted_paths(deleted, deleted_count);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        cbm_store_free_coverage(old_cov, old_cov_count);
        cbm_store_close(store);
        closure_plan_free(&closure_plan);
        return CBM_PIPELINE_ABORT_PRESERVE_DB;
    }

    cbm_store_close(store);

    /* Snapshot inbound cross-file edges into changed files BEFORE purging, so
     * the cascade delete doesn't permanently drop edges whose source lives in
     * an unchanged (never-re-parsed) file. Re-linked after re-resolution. */
    cbm_edge_capture_t edge_cap = {0};
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    incremental_capture_inbound(existing, changed_files, ci, &edge_cap);
    cbm_log_info("incremental.edge_snapshot", "captured", itoa_buf(edge_cap.count), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t)));

    /* Step 2: Purge stale nodes */
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    incremental_purge_files(existing, changed_files, ci, deleted, deleted_count);
    cbm_log_info("incremental.purge", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));

    /* Step 3-5: Registry + extract + resolve */
    cbm_registry_t *registry = cbm_registry_new();
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    cbm_gbuf_foreach_node(existing, registry_visitor, registry);
    cbm_log_info("incremental.registry_seed", "symbols", itoa_buf(cbm_registry_size(registry)),
                 "elapsed_ms", itoa_buf((int)elapsed_ms(t)));

    cbm_path_alias_collection_t *path_aliases = NULL;
    int phase_rc =
        incremental_run_repair(p, project, existing, registry, &path_aliases, changed_files, ci);

    if (phase_rc != 0) {
        cbm_log_error("incremental.err", "phase", "extract_resolve", "rc", itoa_buf(phase_rc));
        free(changed_files);
        cbm_registry_free(registry);
        cbm_path_alias_collection_free(path_aliases);
        incr_free_edge_capture(&edge_cap);
        cbm_store_free_coverage(old_cov, old_cov_count);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        free(saved_adr);
        cbm_gbuf_free(existing);
        return CBM_PIPELINE_ABORT_PRESERVE_DB;
    }

    closure_coverage_t coverage =
        incremental_collect_coverage(p, old_cov, old_cov_count, changed_files, ci);
    cbm_coverage_row_t *cov = coverage.rows;
    int cov_n = coverage.count;

    free(changed_files);
    cbm_registry_free(registry);
    cbm_path_alias_collection_free(path_aliases);

    /* Re-link inbound cross-file edges that the purge orphaned. Runs after
     * re-resolution AND post-passes so the freshly re-created target nodes
     * exist and nothing downstream clobbers the restored edges; insert_edge
     * dedups, so any edge the resolver already recreated is a no-op. */
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    int relinked = incr_restore_inbound_edges(existing, &edge_cap);
    cbm_log_info("incremental.edge_relink", "relinked", itoa_buf(relinked), "captured",
                 itoa_buf(edge_cap.count), "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    incr_free_edge_capture(&edge_cap);

    cbm_file_hash_t *manifest = NULL;
    int manifest_count = 0;
#if defined(CBM_INCREMENTAL_TEST_API) && CBM_INCREMENTAL_TEST_API
    cbm_pipeline_persist_test_run_before_final_manifest();
#endif
    int manifest_rc = cbm_pipeline_build_fresh_semantic_manifest(
        project, cbm_pipeline_repo_path(p), cbm_pipeline_get_mode(p), &manifest, &manifest_count);
    if (manifest_rc != 0 || !cbm_pipeline_semantic_manifests_equal(
                                baseline_manifest, baseline_count, manifest, manifest_count)) {
        cbm_log_warn("incremental.abort", "reason", "semantic_inputs_changed");
        cbm_pipeline_free_semantic_manifest(manifest, manifest_count);
        free(cov);
        cbm_store_free_coverage(old_cov, old_cov_count);
        free_mode_skipped(mode_skipped, mode_skipped_count);
        free(saved_adr);
        cbm_gbuf_free(existing);
        return CBM_PIPELINE_ABORT_PRESERVE_DB;
    }

    /* Step 7: atomically publish the complete staged generation. */
    /* Record committed counts before dump_and_persist (whose dump frees the
     * gbuf node index, zeroing the count) so the #334 plausibility gate also
     * covers incremental reindexes, not just full ones. */
    cbm_pipeline_set_committed_counts(p, cbm_gbuf_node_count(existing),
                                      cbm_gbuf_edge_count(existing));
    int index_mode = cbm_pipeline_get_mode(p);
    cbm_coverage_meta_t coverage_meta = {
        .index_mode = incr_mode_name(index_mode),
        .recording_status = incr_coverage_recording_status(
            coverage.available, coverage.ignored_total, coverage.ignored_count),
        .ignored_files_stored = coverage.ignored_count,
        .ignored_files_total = coverage.ignored_total,
        .coverage_version = CBM_SEMANTIC_INDEX_VERSION,
        .hash_records_complete = true,
    };
    /* Publish surfaces: the surviving previous rows plus this run's fresh
     * ones (closure route). The legacy test route publishes none — its
     * re-parsed files have no codec output, and publishing a stale row
     * would satisfy a future closure plan with yesterday's surface; an
     * empty table just routes the next incremental to a full rebuild. */
    int persist_rc = dump_and_persist(
        existing, db_path, project, cbm_pipeline_cancelled_ptr(p), manifest, manifest_count,
        saved_adr, cbm_pipeline_repo_path(p), cov, cov_n, &coverage_meta, NULL, 0);
    cbm_pipeline_free_semantic_manifest(manifest, manifest_count);
    free(saved_adr);
    free(cov);
    cbm_store_free_coverage(old_cov, old_cov_count);
    free_mode_skipped(mode_skipped, mode_skipped_count);
    cbm_gbuf_free(existing);

    cbm_log_info("incremental.done", "elapsed_ms", itoa_buf((int)elapsed_ms(t0)));
    return persist_rc;
}
