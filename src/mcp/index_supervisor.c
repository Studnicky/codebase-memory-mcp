/*
 * index_supervisor.c — see index_supervisor.h.
 */
#include "index_supervisor.h"

#include "daemon/runtime.h"
#include "daemon/service.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h" /* cbm_mkdir_p, cbm_fopen, cbm_resolve_executable_path */
#include "foundation/constants.h"
#include "foundation/log.h"
#include "foundation/platform.h" /* cbm_safe_getenv, path normalization */
#include "foundation/profile.h"  /* cbm_profile_active (keep worker log under CBM_PROFILE) */
#include "foundation/subprocess.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>

#ifdef _WIN32
#include <io.h>
#include <process.h>
#define worker_close _close
#define worker_getpid _getpid
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#define worker_close close
#define worker_getpid getpid
#endif

_Static_assert(CBM_INDEX_WORKER_BUILD_FINGERPRINT_SIZE == CBM_DAEMON_BUILD_FINGERPRINT_SIZE,
               "worker and daemon build fingerprint sizes must match");

/* ── Worker-role state ────────────────────────────────────────────── */

static bool g_worker_active = false;
static char g_worker_response_out[CBM_SZ_4K] = {0};
static size_t g_worker_memory_budget_bytes = 0;
static bool g_build_fingerprint_capture_attempted = false;
static char g_build_fingerprint[CBM_INDEX_WORKER_BUILD_FINGERPRINT_SIZE] = {0};

enum {
    INDEX_WORKER_ENV_REPLACE_EXISTING = 1,
    INDEX_WORKER_DECIMAL_BASE = 10,
    INDEX_WORKER_ARGV_EXECUTABLE = 0,
    INDEX_WORKER_ARGV_MODE = 1,
    INDEX_WORKER_ARGV_ROLE = 2,
    INDEX_WORKER_ARGV_BUILD_FLAG = 3,
    INDEX_WORKER_ARGV_BUILD_FINGERPRINT = 4,
    INDEX_WORKER_ARGV_METHOD = 5,
    INDEX_WORKER_ARGV_ARGUMENTS = 6,
    INDEX_WORKER_ARGV_RESPONSE_FLAG = 7,
    INDEX_WORKER_ARGV_RESPONSE_PATH = 8,
    INDEX_WORKER_ARGV_REQUIRED_COUNT = 9,
    INDEX_WORKER_OPTION_VALUE_OFFSET = 1,
    INDEX_WORKER_OPTION_PAIR_WIDTH = 2,
    INDEX_WORKER_MILLISECONDS_PER_SECOND = 1000,
    INDEX_WORKER_STRING_TERMINATOR_BYTES = 1,
    INDEX_WORKER_FILE_READ_ITEM_BYTES = 1,
    INDEX_WORKER_RELAY_LINE_CAP = 1024,
    INDEX_WORKER_TEMP_LOCK_PAUSE_US = 1000,
    INDEX_WORKER_CACHE_DIRECTORY_MODE = 0700,
    INDEX_WORKER_STATUS_TEXT_CAP = 16,
    INDEX_WORKER_COUNTER_INCREMENT = 1,
    INDEX_WORKER_HANDLE_COUNT = 1,
    INDEX_WORKER_FAILURE_EXIT_CODE = -1,
};

void cbm_index_set_worker_role(bool is_worker, const char *response_out) {
    g_worker_active = is_worker;
    if (response_out && response_out[0]) {
        snprintf(g_worker_response_out, sizeof(g_worker_response_out), "%s", response_out);
    } else {
        g_worker_response_out[0] = '\0';
    }
}

static void worker_set_local_env(const char *name, const char *value) {
    if (value && value[0]) {
        (void)cbm_setenv(name, value, INDEX_WORKER_ENV_REPLACE_EXISTING);
    } else {
        (void)cbm_unsetenv(name);
    }
}

void cbm_index_set_worker_role_options(bool is_worker, const char *response_out, bool single_thread,
                                       const char *marker_file, const char *quarantine_file,
                                       size_t memory_budget_bytes) {
    cbm_index_set_worker_role(is_worker, response_out);
    g_worker_memory_budget_bytes = is_worker ? memory_budget_bytes : 0;
    if (!is_worker) {
        return;
    }
    worker_set_local_env("CBM_INDEX_SINGLE_THREAD", single_thread ? "1" : NULL);
    worker_set_local_env("CBM_INDEX_MARKER_FILE", marker_file);
    worker_set_local_env("CBM_INDEX_QUARANTINE_FILE", quarantine_file);
}

bool cbm_index_worker_active(void) {
    return g_worker_active;
}

const char *cbm_index_worker_response_out(void) {
    return g_worker_response_out[0] ? g_worker_response_out : NULL;
}

size_t cbm_index_worker_memory_budget_bytes(void) {
    return g_worker_memory_budget_bytes;
}

static bool worker_fingerprint_valid(const char *fingerprint);

bool cbm_index_supervisor_capture_build_fingerprint(void) {
    if (g_build_fingerprint_capture_attempted) {
        return g_build_fingerprint[0] != '\0';
    }
    g_build_fingerprint_capture_attempted = true;
#ifdef CBM_CLI_ENABLE_TEST_API
    /* Test-only seam: computing the real fingerprint hashes the ENTIRE
     * executable image, which for the ASan test-runner (hundreds of MB) takes
     * tens of seconds per spawned worker/daemon on constrained CI runners and
     * is the sole cause of the daemon-family readiness-timeout flakes. When a
     * valid stub is provided the hash is skipped; every process in the test
     * (parent, forked children, re-exec'd workers) inherits the same stub via
     * the environment, so exact-build match/mismatch behaviour is preserved
     * while startup becomes instant. Never compiled into production. */
    char test_fingerprint[CBM_INDEX_WORKER_BUILD_FINGERPRINT_SIZE];
    const char *test_value = cbm_safe_getenv("CBM_TEST_BUILD_FINGERPRINT", test_fingerprint,
                                             sizeof(test_fingerprint), NULL);
    if (test_value && worker_fingerprint_valid(test_value)) {
        (void)snprintf(g_build_fingerprint, sizeof(g_build_fingerprint), "%s", test_value);
        return true;
    }
#endif
    char captured[CBM_INDEX_WORKER_BUILD_FINGERPRINT_SIZE] = {0};
    if (!cbm_daemon_runtime_process_build_fingerprint((uint64_t)worker_getpid(), captured)) {
        return false;
    }
    (void)snprintf(g_build_fingerprint, sizeof(g_build_fingerprint), "%s", captured);
    return true;
}

const char *cbm_index_supervisor_build_fingerprint(void) {
    return g_build_fingerprint[0] ? g_build_fingerprint : NULL;
}

static bool worker_fingerprint_valid(const char *fingerprint) {
    if (!fingerprint || strlen(fingerprint) != CBM_INDEX_WORKER_BUILD_FINGERPRINT_LENGTH) {
        return false;
    }
    for (size_t i = 0; i < CBM_INDEX_WORKER_BUILD_FINGERPRINT_LENGTH; i++) {
        char ch = fingerprint[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool worker_parse_positive_size(const char *text, size_t *value_out) {
    if (!text || !text[0] || !value_out) {
        return false;
    }
    size_t value = 0;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; cursor++) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        size_t digit = (size_t)(*cursor - '0');
        if (value > (SIZE_MAX - digit) / INDEX_WORKER_DECIMAL_BASE) {
            return false;
        }
        value = (value * INDEX_WORKER_DECIMAL_BASE) + digit;
    }
    if (value == 0) {
        return false;
    }
    *value_out = value;
    return true;
}

static bool worker_argv_required_valid(int argc, char *const argv[]) {
    return argc >= INDEX_WORKER_ARGV_REQUIRED_COUNT && argv && argv[INDEX_WORKER_ARGV_EXECUTABLE] &&
           argv[INDEX_WORKER_ARGV_EXECUTABLE][0] && argv[INDEX_WORKER_ARGV_MODE] &&
           strcmp(argv[INDEX_WORKER_ARGV_MODE], "cli") == 0 && argv[INDEX_WORKER_ARGV_ROLE] &&
           strcmp(argv[INDEX_WORKER_ARGV_ROLE], "--index-worker") == 0 &&
           argv[INDEX_WORKER_ARGV_BUILD_FLAG] &&
           strcmp(argv[INDEX_WORKER_ARGV_BUILD_FLAG], CBM_INDEX_WORKER_BUILD_ARG) == 0 &&
           worker_fingerprint_valid(argv[INDEX_WORKER_ARGV_BUILD_FINGERPRINT]) &&
           argv[INDEX_WORKER_ARGV_METHOD] &&
           strcmp(argv[INDEX_WORKER_ARGV_METHOD], "index_repository") == 0 &&
           argv[INDEX_WORKER_ARGV_ARGUMENTS] && argv[INDEX_WORKER_ARGV_ARGUMENTS][0] &&
           argv[INDEX_WORKER_ARGV_RESPONSE_FLAG] &&
           strcmp(argv[INDEX_WORKER_ARGV_RESPONSE_FLAG], "--response-out") == 0 &&
           argv[INDEX_WORKER_ARGV_RESPONSE_PATH] && argv[INDEX_WORKER_ARGV_RESPONSE_PATH][0];
}

static bool worker_argument_matches_option(const char *argument, const char *option) {
    return argument && strcmp(argument, option) == 0;
}

static bool worker_parse_optional_memory(int argc, char *const argv[], int *next,
                                         cbm_index_worker_invocation_t *invocation) {
    if (*next >= argc ||
        !worker_argument_matches_option(argv[*next], CBM_INDEX_WORKER_MEMORY_BUDGET_ARG)) {
        return true;
    }
    int value_index = *next + INDEX_WORKER_OPTION_VALUE_OFFSET;
    if (value_index >= argc ||
        !worker_parse_positive_size(argv[value_index], &invocation->memory_budget_bytes)) {
        return false;
    }
    *next += INDEX_WORKER_OPTION_PAIR_WIDTH;
    return true;
}

static void worker_parse_optional_single_thread(int argc, char *const argv[], int *next,
                                                cbm_index_worker_invocation_t *invocation) {
    if (*next < argc &&
        worker_argument_matches_option(argv[*next], CBM_INDEX_WORKER_SINGLE_THREAD_ARG)) {
        invocation->single_thread = true;
        (*next)++;
    }
}

static bool worker_parse_optional_path(int argc, char *const argv[], int *next, const char *option,
                                       const char **path_out) {
    if (*next >= argc || !worker_argument_matches_option(argv[*next], option)) {
        return true;
    }
    int value_index = *next + INDEX_WORKER_OPTION_VALUE_OFFSET;
    if (value_index >= argc || !argv[value_index] || !argv[value_index][0]) {
        return false;
    }
    *path_out = argv[value_index];
    *next += INDEX_WORKER_OPTION_PAIR_WIDTH;
    return true;
}

static bool worker_parse_optional_arguments(int argc, char *const argv[], int *next,
                                            cbm_index_worker_invocation_t *invocation) {
    if (!worker_parse_optional_memory(argc, argv, next, invocation)) {
        return false;
    }
    worker_parse_optional_single_thread(argc, argv, next, invocation);
    return worker_parse_optional_path(argc, argv, next, CBM_INDEX_WORKER_MARKER_ARG,
                                      &invocation->marker_file) &&
           worker_parse_optional_path(argc, argv, next, CBM_INDEX_WORKER_QUARANTINE_ARG,
                                      &invocation->quarantine_file);
}

cbm_index_worker_argv_status_t cbm_index_worker_parse_process_argv(
    int argc, char *const argv[], cbm_index_worker_invocation_t *invocation_out) {
    if (invocation_out) {
        memset(invocation_out, 0, sizeof(*invocation_out));
    }
    bool has_worker_role = false;
    for (int index = INDEX_WORKER_ARGV_MODE; index < argc; index++) {
        if (worker_argument_matches_option(argv[index], "--index-worker")) {
            has_worker_role = true;
            break;
        }
    }
    if (!has_worker_role) {
        return CBM_INDEX_WORKER_ARGV_NOT_WORKER;
    }
    if (!invocation_out || !worker_argv_required_valid(argc, argv)) {
        return CBM_INDEX_WORKER_ARGV_INVALID;
    }

    cbm_index_worker_invocation_t parsed = {
        .expected_build_fingerprint = argv[INDEX_WORKER_ARGV_BUILD_FINGERPRINT],
        .args_json = argv[INDEX_WORKER_ARGV_ARGUMENTS],
        .response_out = argv[INDEX_WORKER_ARGV_RESPONSE_PATH],
    };
    int next = INDEX_WORKER_ARGV_REQUIRED_COUNT;
    if (!worker_parse_optional_arguments(argc, argv, &next, &parsed) || next != argc) {
        return CBM_INDEX_WORKER_ARGV_INVALID;
    }
    if (!g_build_fingerprint[0]) {
        return CBM_INDEX_WORKER_ARGV_BUILD_UNAVAILABLE;
    }
    if (strcmp(parsed.expected_build_fingerprint, g_build_fingerprint) != 0) {
        return CBM_INDEX_WORKER_ARGV_BUILD_MISMATCH;
    }
    *invocation_out = parsed;
    return CBM_INDEX_WORKER_ARGV_VALID;
}

const char *cbm_index_worker_argv_status_message(cbm_index_worker_argv_status_t status) {
    switch (status) {
    case CBM_INDEX_WORKER_ARGV_VALID:
        return "worker invocation accepted";
    case CBM_INDEX_WORKER_ARGV_INVALID:
        return "invalid internal worker arguments";
    case CBM_INDEX_WORKER_ARGV_BUILD_UNAVAILABLE:
        return "worker executable fingerprint could not be verified";
    case CBM_INDEX_WORKER_ARGV_BUILD_MISMATCH:
        return "worker executable build conflicts with its supervisor; close all CBM sessions "
               "and retry";
    case CBM_INDEX_WORKER_ARGV_NOT_WORKER:
    default:
        return "not an internal worker invocation";
    }
}

/* Test hook (#845): counts worker-start ATTEMPTS, including ones that fail to
 * resolve the self binary — an embedder must never even try to spawn. */
static atomic_int g_spawn_count = 0;

int cbm_index_supervisor_spawn_count(void) {
    return atomic_load_explicit(&g_spawn_count, memory_order_relaxed);
}

/* Test hook: counts SINGLE-THREADED spawns. Production recovery is parallel-
 * only (there are no sequential production runs); this must stay ZERO on
 * every supervised path — any nonzero count means a recovery/probe regressed
 * to the sequential crawl that ground an 81k-file TS corpus for hours. */
static atomic_int g_spawn_st_count = 0;

int cbm_index_supervisor_spawn_st_count(void) {
    return atomic_load_explicit(&g_spawn_st_count, memory_order_relaxed);
}

/* #845: opt-in host mark — see the header. Set once from the real binary's
 * main(); embedders never set it, so should_wrap() stays false for them. */
static bool g_host_marked = false;

void cbm_index_supervisor_mark_host(void) {
    g_host_marked = true;
}

bool cbm_index_supervisor_should_wrap(void) {
    if (!g_host_marked) {
        return false; /* embedder (#845): never spawn `<self> cli --index-worker` */
    }
    if (g_worker_active) {
        return false; /* I am the worker — run in-process, never re-supervise */
    }
    /* Supervision is a safety boundary for the physical CBM host. An ambient
     * variable must never turn a long-lived MCP/CLI parent into the indexer. */
    return true;
}

static bool supervisor_disable_requested(void) {
    char supervisor_setting[CBM_SZ_32] = {0};
    return cbm_safe_getenv("CBM_INDEX_SUPERVISOR", supervisor_setting, sizeof(supervisor_setting),
                           NULL) &&
           strcmp(supervisor_setting, "0") == 0;
}

static bool worker_parse_timeout_ms(const char *text, int *timeout_out) {
    if (!text || !text[0]) {
        return false;
    }
    errno = 0;
    char *end = NULL;
    long seconds = strtol(text, &end, INDEX_WORKER_DECIMAL_BASE);
    if (errno == ERANGE || end == text || *end != '\0' || seconds <= 0 ||
        seconds > INT_MAX / INDEX_WORKER_MILLISECONDS_PER_SECOND) {
        return false;
    }
    *timeout_out = (int)(seconds * INDEX_WORKER_MILLISECONDS_PER_SECOND);
    return true;
}

/* Quiet-timeout (ms) for a supervised worker: killed + reported as a hang if it
 * emits no NEW log line within the window. This is a NO-PROGRESS timeout — every
 * completed log line the worker tails (per-batch parallel.extract.progress every
 * 10 files, plus each pass boundary) resets it — NOT a total-time cap, so a large
 * repo that keeps making progress is never falsely killed. Default: 15 min (a
 * genuinely stuck file emits nothing, so this fires only on a real hang). The
 * CBM_INDEX_WORKER_TIMEOUT_S override (seconds → ms) tightens it for tests. */
static int worker_quiet_timeout_ms(void) {
    enum { DEFAULT_QUIET_TIMEOUT_MS = 900000 }; /* 15 min with no progress */
    char timeout_seconds[CBM_SZ_32] = {0};
    int timeout_seconds_ms = 0;
    if (cbm_safe_getenv("CBM_INDEX_WORKER_TIMEOUT_S", timeout_seconds, sizeof(timeout_seconds),
                        NULL) &&
        worker_parse_timeout_ms(timeout_seconds, &timeout_seconds_ms)) {
        return timeout_seconds_ms;
    }
    return DEFAULT_QUIET_TIMEOUT_MS;
}

typedef enum {
    WORKER_RESPONSE_READ_OK = 0,
    WORKER_RESPONSE_READ_ERROR,
    WORKER_RESPONSE_READ_TOO_LARGE,
} worker_response_read_status_t;

/* Read at most one daemon-application payload. The worker is already reaped,
 * but the byte count remains an explicit allocation/read boundary even if an
 * escaped process still has the response file open. */
static char *slurp_worker_response(const char *path, worker_response_read_status_t *status_out) {
    *status_out = WORKER_RESPONSE_READ_ERROR;
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        (void)fclose(f);
        return NULL;
    }
    long n = ftell(f);
    if (n < 0) {
        (void)fclose(f);
        return NULL;
    }
    if ((uint64_t)n > (uint64_t)CBM_DAEMON_RUNTIME_APPLICATION_PAYLOAD_MAX) {
        *status_out = WORKER_RESPONSE_READ_TOO_LARGE;
        (void)fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)n + INDEX_WORKER_STRING_TERMINATOR_BYTES);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t rd = fread(buf, INDEX_WORKER_FILE_READ_ITEM_BYTES, (size_t)n, f);
    bool complete = rd == (size_t)n && !ferror(f);
    (void)fclose(f);
    if (!complete) {
        free(buf);
        return NULL;
    }
    buf[rd] = '\0';
    *status_out = WORKER_RESPONSE_READ_OK;
    return buf;
}

enum {
    INDEX_WORKER_PATH_CAP = CBM_SZ_4K,
    INDEX_WORKER_ARGV_CAP = 17,
    INDEX_WORKER_SYNC_POLL_NS = 10000000,
    INDEX_WORKER_RELAY_LINES_PER_POLL = 64,
    INDEX_WORKER_RELAY_BYTES_PER_POLL = 64 * 1024,
};

struct cbm_index_worker_handle {
    cbm_subprocess_t *process;
    char response_path[INDEX_WORKER_PATH_CAP];
    char log_path[INDEX_WORKER_PATH_CAP];
    cbm_proc_log_cb log_callback;
    void *log_context;
    long relay_tail_pos;
    bool process_terminal;
    cbm_proc_result_t process_result;
    atomic_bool terminal;
    cbm_index_worker_result_t result;
};

/* The generic subprocess supervisor tails logs in bounded batches to preserve
 * its nonblocking poll contract. A short-lived worker can therefore become
 * terminal with more completed lines still on disk. Keep the request callback
 * at this layer and delay the index-worker terminal result until its independent
 * bounded cursor has caught up. This also keeps callback state request-scoped:
 * no process-global sink is installed and concurrent workers never share a
 * cursor or context.
 *
 * Returns true when the relay cursor is at EOF (or no callback was requested),
 * false when another bounded poll is needed. A partial final line is deliberately
 * left undelivered, matching cbm_proc_log_cb's completed-line contract. */
static FILE *worker_relay_open(const cbm_index_worker_handle_t *handle) {
#ifdef _WIN32
    return cbm_fopen(handle->log_path, "rb");
#else
    int flags = O_RDONLY | O_NONBLOCK;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int descriptor = open(handle->log_path, flags);
    if (descriptor < 0) {
        return NULL;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode)) {
        (void)close(descriptor);
        return NULL;
    }
    FILE *log = fdopen(descriptor, "r");
    if (!log) {
        (void)close(descriptor);
    }
    return log;
#endif
}

static bool worker_relay_line(cbm_index_worker_handle_t *handle, FILE *log, size_t *delivered_lines,
                              size_t *delivered_bytes) {
    char line[INDEX_WORKER_RELAY_LINE_CAP];
    long before = ftell(log);
    if (!fgets(line, sizeof(line), log)) {
        return false;
    }
    size_t length = strlen(line);
    *delivered_bytes += length;
    bool complete = length > 0 && line[length - INDEX_WORKER_STRING_TERMINATOR_BYTES] == '\n';
    if (complete) {
        line[length - INDEX_WORKER_STRING_TERMINATOR_BYTES] = '\0';
        handle->relay_tail_pos = ftell(log);
        (*delivered_lines)++;
        if (line[0]) {
            handle->log_callback(line, handle->log_context);
        }
        return true;
    }
    if (length == sizeof(line) - INDEX_WORKER_STRING_TERMINATOR_BYTES) {
        /* Consume an oversized line in bounded chunks so it cannot pin the
         * cursor forever. This mirrors the subprocess tailer. */
        handle->relay_tail_pos = ftell(log);
        (*delivered_lines)++;
        handle->log_callback(line, handle->log_context);
        return true;
    }
    /* The worker may append the rest before a later running poll. Once its
     * process tree is quiescent this remains intentionally undelivered because
     * callbacks are for complete lines only. */
    handle->relay_tail_pos = before;
    return false;
}

static bool worker_relay_drain(cbm_index_worker_handle_t *handle, FILE *log) {
    if (fseek(log, handle->relay_tail_pos, SEEK_SET) != 0) {
        return true;
    }
    size_t delivered_lines = 0;
    size_t delivered_bytes = 0;
    while (delivered_lines < INDEX_WORKER_RELAY_LINES_PER_POLL &&
           delivered_bytes < INDEX_WORKER_RELAY_BYTES_PER_POLL &&
           worker_relay_line(handle, log, &delivered_lines, &delivered_bytes)) {}
    if (delivered_lines != INDEX_WORKER_RELAY_LINES_PER_POLL &&
        delivered_bytes < INDEX_WORKER_RELAY_BYTES_PER_POLL) {
        return true;
    }
    /* Probe without advancing the durable cursor. The FILE is closed
     * immediately, so consuming this byte only answers whether another bounded
     * owner-thread poll is required. */
    return fgetc(log) == EOF;
}

static bool worker_relay_log(cbm_index_worker_handle_t *handle) {
    if (!handle || !handle->log_callback) {
        return true;
    }
    FILE *log = worker_relay_open(handle);
    if (!log) {
        return true;
    }

    bool caught_up = worker_relay_drain(handle, log);
    (void)fclose(log);
    return caught_up;
}

/* cbm_mkstemp's Windows compatibility implementation uses an internal buffer.
 * Serialize just the name creation so concurrent daemon jobs remain safe; the
 * spawned workers themselves are fully concurrent. */
static atomic_flag g_worker_tmp_lock = ATOMIC_FLAG_INIT;

static void worker_tmp_lock(void) {
    while (atomic_flag_test_and_set_explicit(&g_worker_tmp_lock, memory_order_acquire)) {
        cbm_usleep(INDEX_WORKER_TEMP_LOCK_PAUSE_US);
    }
}

static void worker_tmp_unlock(void) {
    atomic_flag_clear_explicit(&g_worker_tmp_lock, memory_order_release);
}

static void worker_result_init(cbm_index_worker_result_t *result) {
    memset(result, 0, sizeof(*result));
    result->outcome = CBM_PROC_SPAWN_FAILED;
    result->exit_code = INDEX_WORKER_FAILURE_EXIT_CODE;
}

/* Resolve into caller-owned storage. The generic resolver returns a shared
 * static buffer, which is unsuitable for concurrent daemon starts. */
static bool worker_cache_dir(char out[INDEX_WORKER_PATH_CAP]) {
    char configured[INDEX_WORKER_PATH_CAP] = {0};
    if (cbm_safe_getenv("CBM_CACHE_DIR", configured, sizeof(configured), NULL) && configured[0]) {
        int written = snprintf(out, INDEX_WORKER_PATH_CAP, "%s", configured);
        if (written <= 0 || written >= INDEX_WORKER_PATH_CAP) {
            return false;
        }
        cbm_normalize_path_sep(out);
        return true;
    }
    char home[INDEX_WORKER_PATH_CAP] = {0};
    if (!cbm_safe_getenv("HOME", home, sizeof(home), NULL) || !home[0]) {
        (void)cbm_safe_getenv("USERPROFILE", home, sizeof(home), NULL);
    }
    if (!home[0]) {
        return false;
    }
    int written = snprintf(out, INDEX_WORKER_PATH_CAP, "%s/.cache/codebase-memory-mcp", home);
    if (written <= 0 || written >= INDEX_WORKER_PATH_CAP) {
        return false;
    }
    cbm_normalize_path_sep(out);
    return true;
}

static bool worker_unique_file(char *out, size_t out_size, const char *kind) {
    if (!out || out_size == 0 || !kind || !kind[0]) {
        return false;
    }
    char cache_copy[INDEX_WORKER_PATH_CAP] = {0};
    bool have_cache = worker_cache_dir(cache_copy);
    int written;
    if (have_cache) {
        char directory[INDEX_WORKER_PATH_CAP];
        written = snprintf(directory, sizeof(directory), "%s/logs", cache_copy);
        if (written <= 0 || written >= (int)sizeof(directory) ||
            !cbm_mkdir_p(directory, INDEX_WORKER_CACHE_DIRECTORY_MODE)) {
            return false;
        }
        written = snprintf(out, out_size, "%s/.worker-%s-XXXXXX", directory, kind);
    } else {
        written = snprintf(out, out_size, ".worker-%s-XXXXXX", kind);
    }
    if (written <= 0 || written >= (int)out_size) {
        out[0] = '\0';
        return false;
    }
    worker_tmp_lock();
    int descriptor = cbm_mkstemp(out);
    worker_tmp_unlock();
    if (descriptor < 0) {
        out[0] = '\0';
        return false;
    }
    (void)worker_close(descriptor);
    return true;
}

static bool worker_result_succeeded(const cbm_index_worker_result_t *result) {
    return result && result->outcome == CBM_PROC_CLEAN && !result->cancellation_requested &&
           result->tree_quiesced && !result->supervision_failed;
}

static void worker_terminal_log(cbm_index_worker_handle_t *handle) {
    char signal_text[INDEX_WORKER_STATUS_TEXT_CAP];
    char exit_text[INDEX_WORKER_STATUS_TEXT_CAP];
    (void)snprintf(signal_text, sizeof(signal_text), "%d", handle->result.term_signal);
    (void)snprintf(exit_text, sizeof(exit_text), "%d", handle->result.exit_code);
    cbm_log_info("index.supervisor.reap", "outcome", cbm_proc_outcome_str(handle->result.outcome),
                 "exit_code", exit_text, "signal", signal_text);
    if (handle->result.response_rejected) {
        cbm_log_error("index.supervisor.response_rejected", "reason", "payload_too_large", "log",
                      handle->log_path);
    } else if (handle->result.supervision_failed || !handle->result.tree_quiesced) {
        cbm_log_error("index.supervisor.containment_failed", "outcome",
                      cbm_proc_outcome_str(handle->result.outcome), "log", handle->log_path);
    } else if (handle->result.cancellation_requested) {
        cbm_log_warn("index.supervisor.worker_cancelled", "outcome",
                     cbm_proc_outcome_str(handle->result.outcome), "log", handle->log_path);
    } else if (handle->result.outcome == CBM_PROC_CLEAN && !cbm_profile_active) {
        (void)cbm_unlink(handle->log_path);
    } else if (handle->result.outcome == CBM_PROC_CLEAN) {
        cbm_log_info("index.supervisor.profile_log", "log", handle->log_path);
    } else {
        cbm_log_warn("index.supervisor.worker_failed", "outcome",
                     cbm_proc_outcome_str(handle->result.outcome), "exit_code", exit_text, "log",
                     handle->log_path);
    }
}

int cbm_index_worker_start_with_log(const char *args_json, size_t memory_budget_bytes,
                                    bool single_thread, const char *marker_file,
                                    const char *quarantine_file, cbm_proc_log_cb log_callback,
                                    void *log_context, cbm_index_worker_handle_t **handle_out) {
    if (handle_out) {
        *handle_out = NULL;
    }
    atomic_fetch_add_explicit(&g_spawn_count, INDEX_WORKER_COUNTER_INCREMENT, memory_order_relaxed);
    if (single_thread) {
        atomic_fetch_add_explicit(&g_spawn_st_count, INDEX_WORKER_COUNTER_INCREMENT,
                                  memory_order_relaxed);
    }
    if (!handle_out || !args_json || !args_json[0]) {
        return INDEX_WORKER_FAILURE_EXIT_CODE;
    }
    if (g_host_marked && !g_worker_active && supervisor_disable_requested()) {
        /* Keep the old variable as a deterministic refusal seam, but never as
         * a production escape hatch into unsafe in-process indexing. */
        cbm_log_error("index.supervisor.disable_refused", "action", "fail_closed");
        return INDEX_WORKER_FAILURE_EXIT_CODE;
    }
    const char *build_fingerprint = cbm_index_supervisor_build_fingerprint();
    if (!build_fingerprint) {
        cbm_log_error("index.supervisor.build_fingerprint_unavailable", "action", "refuse_spawn");
        return INDEX_WORKER_FAILURE_EXIT_CODE;
    }

    char self[INDEX_WORKER_PATH_CAP] = {0};
    if (!cbm_resolve_executable_path(NULL, self, sizeof(self)) || !self[0]) {
        cbm_log_error("index.supervisor.no_self_path", "action", "fail_closed");
        return INDEX_WORKER_FAILURE_EXIT_CODE;
    }
    cbm_index_worker_handle_t *handle = calloc(INDEX_WORKER_HANDLE_COUNT, sizeof(*handle));
    if (!handle) {
        return INDEX_WORKER_FAILURE_EXIT_CODE;
    }
    atomic_init(&handle->terminal, false);
    handle->log_callback = log_callback;
    handle->log_context = log_context;
    worker_result_init(&handle->result);
    if (!worker_unique_file(handle->response_path, sizeof(handle->response_path), "response") ||
        !worker_unique_file(handle->log_path, sizeof(handle->log_path), "log")) {
        (void)cbm_unlink(handle->response_path);
        (void)cbm_unlink(handle->log_path);
        free(handle);
        return INDEX_WORKER_FAILURE_EXIT_CODE;
    }

    const char *argv[INDEX_WORKER_ARGV_CAP];
    size_t argc = 0;
    argv[argc++] = self;
    argv[argc++] = "cli";
    argv[argc++] = "--index-worker";
    argv[argc++] = CBM_INDEX_WORKER_BUILD_ARG;
    argv[argc++] = build_fingerprint;
    argv[argc++] = "index_repository";
    argv[argc++] = args_json;
    argv[argc++] = "--response-out";
    argv[argc++] = handle->response_path;
    char memory_budget_text[CBM_SZ_32];
    if (memory_budget_bytes > 0) {
        (void)snprintf(memory_budget_text, sizeof(memory_budget_text), "%zu", memory_budget_bytes);
        argv[argc++] = CBM_INDEX_WORKER_MEMORY_BUDGET_ARG;
        argv[argc++] = memory_budget_text;
    }
    if (single_thread) {
        argv[argc++] = CBM_INDEX_WORKER_SINGLE_THREAD_ARG;
    }
    if (marker_file && marker_file[0]) {
        argv[argc++] = CBM_INDEX_WORKER_MARKER_ARG;
        argv[argc++] = marker_file;
    }
    if (quarantine_file && quarantine_file[0]) {
        argv[argc++] = CBM_INDEX_WORKER_QUARANTINE_ARG;
        argv[argc++] = quarantine_file;
    }
    argv[argc] = NULL;

    cbm_proc_opts_t options = {0};
    options.bin = self;
    options.argv = argv;
    options.log_file = handle->log_path;
    /* The subprocess tail remains authoritative for quiet-timeout activity.
     * Request callbacks use the supervisor's independent cursor so a terminal
     * child cannot strand a bounded tail backlog. */
    options.on_log_line = NULL;
    options.log_ud = NULL;
    options.quiet_timeout_ms = worker_quiet_timeout_ms();
    options.delete_log_on_exit = false;
    if (cbm_subprocess_spawn(&options, &handle->process) != 0) {
        (void)cbm_unlink(handle->response_path);
        (void)cbm_unlink(handle->log_path);
        free(handle);
        cbm_log_error("index.supervisor.spawn_failed", "action", "fail_closed");
        return INDEX_WORKER_FAILURE_EXIT_CODE;
    }
    *handle_out = handle;
    return 0;
}

int cbm_index_worker_start(const char *args_json, size_t memory_budget_bytes, bool single_thread,
                           const char *marker_file, const char *quarantine_file,
                           cbm_index_worker_handle_t **handle_out) {
    return cbm_index_worker_start_with_log(args_json, memory_budget_bytes, single_thread,
                                           marker_file, quarantine_file, NULL, NULL, handle_out);
}

cbm_index_worker_poll_t cbm_index_worker_poll(cbm_index_worker_handle_t *handle,
                                              const cbm_index_worker_result_t **result_out) {
    if (result_out) {
        *result_out = NULL;
    }
    if (!handle || !result_out || !handle->process) {
        return CBM_INDEX_WORKER_POLL_ERROR;
    }
    if (atomic_load_explicit(&handle->terminal, memory_order_acquire)) {
        *result_out = &handle->result;
        return CBM_INDEX_WORKER_POLL_TERMINAL;
    }
    bool relay_caught_up = true;
    if (!handle->process_terminal) {
        cbm_proc_result_t process_result;
        cbm_proc_poll_t state = cbm_subprocess_poll(handle->process, &process_result);
        relay_caught_up = worker_relay_log(handle);
        if (state == CBM_PROC_POLL_RUNNING) {
            return CBM_INDEX_WORKER_POLL_RUNNING;
        }
        if (state != CBM_PROC_POLL_TERMINAL) {
            return CBM_INDEX_WORKER_POLL_ERROR;
        }
        handle->process_result = process_result;
        handle->process_terminal = true;
    } else {
        relay_caught_up = worker_relay_log(handle);
    }
    if (!relay_caught_up) {
        /* The process tree is already quiescent, but one bounded callback batch
         * remains. Keep the public poll nonblocking and report terminal only
         * after every completed worker log line has reached its request sink. */
        return CBM_INDEX_WORKER_POLL_RUNNING;
    }
    const cbm_proc_result_t *process_result = &handle->process_result;
    handle->result.outcome = process_result->outcome;
    handle->result.exit_code = process_result->exit_code;
    handle->result.term_signal = process_result->term_signal;
    handle->result.cancellation_requested = process_result->cancellation_requested;
    handle->result.forced = process_result->forced;
    handle->result.tree_quiesced = process_result->tree_quiesced;
    handle->result.supervision_failed = process_result->supervision_failed;
    if (worker_result_succeeded(&handle->result)) {
        worker_response_read_status_t response_status;
        handle->result.response = slurp_worker_response(handle->response_path, &response_status);
        if (response_status == WORKER_RESPONSE_READ_TOO_LARGE) {
            /* A clean exit with an out-of-contract response is a contained
             * worker failure, not a fallback to in-process indexing. */
            handle->result.response_rejected = true;
            handle->result.outcome = CBM_PROC_EXIT_NONZERO;
            handle->result.exit_code = INDEX_WORKER_FAILURE_EXIT_CODE;
        }
    }
    (void)cbm_unlink(handle->response_path);
    worker_terminal_log(handle);
    atomic_store_explicit(&handle->terminal, true, memory_order_release);
    *result_out = &handle->result;
    return CBM_INDEX_WORKER_POLL_TERMINAL;
}

bool cbm_index_worker_request_cancel(cbm_index_worker_handle_t *handle) {
    return handle && !atomic_load_explicit(&handle->terminal, memory_order_acquire) &&
           cbm_subprocess_request_cancel(handle->process);
}

const char *cbm_index_worker_response_path(const cbm_index_worker_handle_t *handle) {
    return handle ? handle->response_path : NULL;
}

const char *cbm_index_worker_log_path(const cbm_index_worker_handle_t *handle) {
    return handle ? handle->log_path : NULL;
}

void cbm_index_worker_destroy(cbm_index_worker_handle_t *handle) {
    if (!handle) {
        return;
    }
    if (!atomic_load_explicit(&handle->terminal, memory_order_acquire)) {
        cbm_log_error("index.supervisor.destroy_running", "action", "ignored");
        return;
    }
    cbm_subprocess_destroy(handle->process);
    free(handle->result.response);
    handle->result.response = NULL;
    free(handle);
}

int cbm_index_spawn_worker_with_log_cancel(const char *args_json, bool single_thread,
                                           const char *marker_file, const char *quarantine_file,
                                           cbm_proc_log_cb log_callback, void *log_context,
                                           const atomic_int *cancel_requested,
                                           cbm_index_worker_result_t *result) {
    if (!result) {
        return INDEX_WORKER_FAILURE_EXIT_CODE;
    }
    worker_result_init(result);
    cbm_index_worker_handle_t *handle = NULL;
    if (cbm_index_worker_start_with_log(args_json, 0, single_thread, marker_file, quarantine_file,
                                        log_callback, log_context, &handle) != 0) {
        return INDEX_WORKER_FAILURE_EXIT_CODE;
    }
    const cbm_index_worker_result_t *cached = NULL;
    bool cancellation_forwarded = false;
    for (;;) {
        if (!cancellation_forwarded && cancel_requested &&
            atomic_load_explicit(cancel_requested, memory_order_acquire) != 0) {
            cancellation_forwarded = cbm_index_worker_request_cancel(handle);
        }
        cbm_index_worker_poll_t state = cbm_index_worker_poll(handle, &cached);
        if (state == CBM_INDEX_WORKER_POLL_TERMINAL) {
            break;
        }
        if (state == CBM_INDEX_WORKER_POLL_ERROR) {
            (void)cbm_index_worker_request_cancel(handle);
        }
        const struct timespec pause = {0, INDEX_WORKER_SYNC_POLL_NS};
        (void)cbm_nanosleep(&pause, NULL);
    }
    *result = *cached;
    result->response = cached->response ? cbm_strdup(cached->response) : NULL;
    cbm_index_worker_destroy(handle);
    return 0;
}

int cbm_index_spawn_worker_with_log(const char *args_json, bool single_thread,
                                    const char *marker_file, const char *quarantine_file,
                                    cbm_proc_log_cb log_callback, void *log_context,
                                    cbm_index_worker_result_t *result) {
    return cbm_index_spawn_worker_with_log_cancel(args_json, single_thread, marker_file,
                                                  quarantine_file, log_callback, log_context, NULL,
                                                  result);
}

int cbm_index_spawn_worker(const char *args_json, bool single_thread, const char *marker_file,
                           const char *quarantine_file, cbm_index_worker_result_t *result) {
    return cbm_index_spawn_worker_with_log(args_json, single_thread, marker_file, quarantine_file,
                                           NULL, NULL, result);
}

void cbm_index_worker_result_free(cbm_index_worker_result_t *result) {
    if (result) {
        free(result->response);
        result->response = NULL;
    }
}
