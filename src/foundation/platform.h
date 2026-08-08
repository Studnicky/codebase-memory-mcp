/*
 * platform.h — OS abstractions.
 *
 * Provides cross-platform wrappers for:
 *   - Memory-mapped files (mmap / VirtualAlloc)
 *   - High-resolution monotonic clock
 *   - CPU core count
 *   - File existence check
 */
#ifndef CBM_PLATFORM_H
#define CBM_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ── Safe memory ──────────────────────────────────────────────── */

/* Grow an allocation, or die trying. NEVER returns NULL, so the growth idiom
 * `arr = cbm_realloc_or_abort(arr, n * sizeof *arr); arr[i] = x;` is correct
 * without a check at every site.
 *
 * There is no global OOM handler here: mimalloc runs with default options and
 * nothing registers a fallback, so a failed growth has no recovery — the
 * caller has already lost the old buffer and every one of these call sites
 * writes through the result immediately. Aborting names the failure at the
 * point it happens; the alternative is a NULL dereference several frames
 * later, attributed to nothing. Same reasoning as mem_setup_fatal: fatal here
 * beats a slow death later.
 *
 * Where a failed growth IS genuinely recoverable, call cbm_realloc_or_free
 * and handle the NULL. */
void *cbm_realloc_or_abort(void *ptr, size_t size);

/* Make the next cbm_realloc_or_abort take its failure branch, so the abort
 * path is reachable from a test without depending on a real allocator refusal
 * (which the sanitizers intercept before it reaches us). Consumed by that one
 * call; the caller does not return. */
void cbm_realloc_fail_next_growth_for_test(void);

/* Grow an allocation, freeing the old block on failure instead of leaking it.
 * Returns NULL on failure — the old pointer is already freed, so the caller
 * must not touch it again. Only for call sites that genuinely recover; the
 * default is cbm_realloc_or_abort. */
static inline void *cbm_realloc_or_free(void *ptr, size_t size) {
    enum { REALLOC_MIN = 1 };
    if (size == 0) {
        size = REALLOC_MIN;
    }
    void *tmp = realloc(ptr, size);
    if (!tmp) {
        free(ptr);
    }
    return tmp;
}

/* Safe free: frees and NULLs a pointer to prevent double-free / use-after-free.
 * Use via the safe_free() macro so the caller's pointer is actually cleared. */
static inline void safe_free_impl(void **pp) {
    if (pp && *pp) {
        free(*pp);
        *pp = NULL;
    }
}
#define safe_free(ptr) safe_free_impl((void **)(void *)&(ptr))

/* Safe const string free: frees a const char* and NULLs it.
 *
 * The `const` here describes what callers may do with the string, not who owns
 * it: this function IS the owner's release point. Reading the pointer value out
 * with memcpy transfers ownership without a qualifier-discarding cast, which
 * -Wcast-qual would otherwise report at every one of this function's call
 * sites rather than once here. */
static inline void safe_str_free(const char **sp) {
    if (sp && *sp) {
        void *owned;
        memcpy(&owned, sp, sizeof(owned));
        free(owned);
        *sp = NULL;
    }
}

/* Safe buffer free: frees a heap array and zeros its element count.
 * Use for dynamic arrays paired with a size_t count. */
static inline void safe_buf_free_impl(void **buf, size_t *count) {
    if (buf && *buf) {
        free(*buf);
        *buf = NULL;
    }
    if (count) {
        *count = 0;
    }
}
#define safe_buf_free(buf, countp) safe_buf_free_impl((void **)(void *)&(buf), (countp))

/* Safe grow: multiplies capacity and reallocs when count reaches cap.
 * `cap` must be an unsigned type — the multiplication below is the growth step,
 * and on a signed capacity it would be overflow, i.e. undefined.
 * Only appropriate for arrays whose elements don't own additional heap memory;
 * for arrays of heap-allocated pointers, prefer a manual realloc+cleanup.
 * Usage: safe_grow(arr, count, cap, growth_factor)
 * After the call, arr is the new buffer — never NULL, see
 * cbm_realloc_or_abort. */
#define safe_grow(arr, n, cap, factor)                                          \
    do {                                                                        \
        if ((size_t)(n) >= (size_t)(cap)) {                                     \
            (cap) *= (factor);                                                  \
            (arr) = cbm_realloc_or_abort((arr), (size_t)(cap) * sizeof(*(arr))); \
        }                                                                       \
    } while (0)

/* ── Memory mapping ────────────────────────────────────────────── */

/* Map a file read-only into memory. Returns NULL on error.
 * *out_size is set to the file size. */
void *cbm_mmap_read(const char *path, size_t *out_size);

/* Unmap a previously mapped region. */
void cbm_munmap(void *addr, size_t size);

/* ── Timing ────────────────────────────────────────────────────── */

/* Monotonic nanosecond timestamp (for elapsed time measurement). */
uint64_t cbm_now_ns(void);

/* Monotonic millisecond timestamp. */
uint64_t cbm_now_ms(void);

/* ── System info ───────────────────────────────────────────────── */

/* Number of available CPU cores. */
int cbm_nprocs(void);

/* System topology: core types and RAM (only fields with production consumers). */
typedef struct {
    int total_cores;  /* hw.ncpu (all cores) */
    int perf_cores;   /* P-cores (Apple) or total_cores (others) */
    size_t total_ram; /* total physical RAM in bytes */
} cbm_system_info_t;

/* Query system information. Results are cached after first call. */
cbm_system_info_t cbm_system_info(void);

/* Recommended worker count for parallel indexing.
 * initial=true:  all cores (user is waiting for initial index)
 * initial=false: max(1, perf_cores-1) (leave headroom for user apps) */
int cbm_default_worker_count(bool initial);

/* ── Environment variables ──────────────────────────────────────── */

/* Thread-safe getenv: copies the value into a caller-provided buffer.
 * Returns buf on success, or fallback if the variable is unset.
 * Returns NULL when the variable is unset and fallback is NULL. */
const char *cbm_safe_getenv(const char *name, char *buf, size_t buf_sz, const char *fallback);

/* ── Home directory ─────────────────────────────────────────────── */

/* Cross-platform home directory: tries HOME first, then USERPROFILE (Windows).
 * Returns NULL when neither is set. */
const char *cbm_get_home_dir(void);

/* ── App config directories ────────────────────────────────────── */

/* Cross-platform app config directory (static buffer, not thread-safe).
 * Windows: %APPDATA% (e.g. C:/Users/.../AppData/Roaming)
 * macOS:   $HOME (callers append Library/Application Support/...)
 * Linux:   $XDG_CONFIG_HOME or ~/.config */
const char *cbm_app_config_dir(void);

/* Windows: %LOCALAPPDATA% (e.g. C:/Users/.../AppData/Local)
 * macOS/Linux: same as cbm_app_config_dir(). */
const char *cbm_app_local_dir(void);

/* ── Cache directory ────────────────────────────────────────────── */

/* Resolve the database cache directory. All project indexes are stored here.
 * Priority: CBM_CACHE_DIR env var > ~/.cache/codebase-memory-mcp (default).
 * Returns static buffer or NULL if home is unavailable. */
const char *cbm_resolve_cache_dir(void);

/* ── File system ───────────────────────────────────────────────── */

/* Check if a path exists. */
bool cbm_file_exists(const char *path);

/* Check if path is a directory. */
bool cbm_is_dir(const char *path);

/* Get file size. Returns -1 on error. */
int64_t cbm_file_size(const char *path);

/* Normalize path separators to forward slashes (in-place).
 * On Windows, converts backslashes to forward slashes.
 * On POSIX, this is a no-op. Returns the input pointer. */
char *cbm_normalize_path_sep(char *path);

#endif /* CBM_PLATFORM_H */
