/*
 * application.c — Daemon-owned CBM application sessions and thin-client wire.
 */
#include "host/application.h"
#include "daemon/daemon.h"
#include "daemon/runtime.h"
#include "foundation/constants.h"
#include "host/application_internal.h"

#include "cli/cli.h"
#include "foundation/build_version.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/compat_thread.h"
#include "foundation/log.h"
#include "foundation/mem.h"
#include "foundation/platform.h"
#include "foundation/subprocess.h"
#include "mcp/index_supervisor.h"
#include "mcp/mcp.h"
#include "mcp/mcp_internal.h"
#include "pipeline/pipeline.h"
#include "store/store.h"
#include "ui/config.h"
#include "watcher/watcher.h"

#include <yyjson/yyjson.h>

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <windows.h>
#define application_close _close
#else
#include <unistd.h>
#define application_close close
#endif

enum {
    APPLICATION_BYTE_INDEX_FIRST = 0,
    APPLICATION_BYTE_INDEX_SECOND = 1,
    APPLICATION_BYTE_INDEX_THIRD = 2,
    APPLICATION_BYTE_INDEX_FOURTH = 3,
    APPLICATION_U32_SHIFT_MOST_SIGNIFICANT = 24,
    APPLICATION_U32_SHIFT_SECOND = 16,
    APPLICATION_U32_SHIFT_THIRD = 8,
    APPLICATION_TEXT_TERMINATOR_BYTES = 1,
    APPLICATION_ALLOCATION_ELEMENTS_ONE = 1,
    APPLICATION_COUNT_ONE = 1,
    APPLICATION_PROTOCOL_TRUE = 1,
    APPLICATION_RESULT_FAILURE = -1,
    APPLICATION_RESULT_SUCCESS = 0,
    APPLICATION_RESULT_SKIPPED = 1,
    APPLICATION_CONTEXT_HEADER_SIZE = 19,
    APPLICATION_CONTEXT_ROOT_LENGTH_OFFSET = 1,
    APPLICATION_CONTEXT_ALLOWED_PRESENT_OFFSET = 5,
    APPLICATION_CONTEXT_ALLOWED_LENGTH_OFFSET = 6,
    APPLICATION_CONTEXT_PROFILE_OFFSET = 10,
    APPLICATION_CONTEXT_EVENT_LENGTH_OFFSET = 11,
    APPLICATION_CONTEXT_DIALECT_LENGTH_OFFSET = 15,
    APPLICATION_TOOL_HEADER_SIZE = 5,
    APPLICATION_TOOL_NAME_LENGTH_OFFSET = 1,
    APPLICATION_UI_CONFIG_REQUEST_SIZE = 7,
    APPLICATION_UI_CONFIG_MASK_OFFSET = 1,
    APPLICATION_UI_CONFIG_ENABLED_OFFSET = 2,
    APPLICATION_UI_CONFIG_PORT_OFFSET = 3,
    APPLICATION_UI_CONFIG_PORT_SECOND_BYTE_OFFSET = 4,
    APPLICATION_PATH_CAP = 4096,
    APPLICATION_NUMERIC_TEXT_CAP = 32,
    APPLICATION_ERROR_MESSAGE_CAP = 1024,
    APPLICATION_JOB_THREAD_STACK = 256 * 1024,
    APPLICATION_JOB_POLL_US = 10000,
    APPLICATION_COORDINATION_CLEANUP_MS = 500,
    APPLICATION_DEFAULT_PHYSICAL_JOB_LIMIT = 4,
    APPLICATION_DEFAULT_MAX_RESTARTS = 100,
    APPLICATION_MARKER_MAX_BYTES = 64 * 1024 * 1024,
    APPLICATION_MAX_SUSPECTS = 65536,
    APPLICATION_UPDATE_POLL_US = 10000,
    APPLICATION_BACKGROUND_REAP_MS = 10000,
    APPLICATION_UPDATE_VERSION_CAP = 128,
    APPLICATION_UPDATE_NOTICE_CAP = 1024,
    APPLICATION_FILE_MODE_OWNER_ONLY = 0700,
    APPLICATION_CANCEL_CHECK_INTERVAL_MASK = 255,
    APPLICATION_STATUS_LINE_MIN_LENGTH = 3,
    APPLICATION_STATUS_LINE_RELATIVE_OFFSET = 2,
    APPLICATION_OPEN_PATH_CAPACITY_INITIAL = 16,
    APPLICATION_OPEN_PATH_CAPACITY_GROWTH = 2,
    APPLICATION_DECIMAL_RADIX = 10,
    APPLICATION_COORDINATION_RETRY_MS = 100,
    APPLICATION_SHUTDOWN_TIMEOUT_MS = 3000,
    APPLICATION_NETWORK_PORT_MAX = 65535,
    APPLICATION_JSONRPC_INTERNAL_ERROR_CODE = -32603,
};

/* There is deliberately NO production update-check provider. The daemon used to
 * spawn `curl` against the GitHub releases API on the first eligible session of
 * every run, purely to print "a newer version exists". That put a release URL
 * and an outbound request into every shipped binary, and made a developer tool
 * phone home from every agent session, to deliver something the install scripts
 * and package managers already report.
 *
 * The SEAM below survives: `update_ops` remains injectable, and the notice,
 * ownership, cancellation and generation-replay logic is still exercised by the
 * fakes in tests/test_daemon_application.c. With no provider installed the whole
 * machinery simply never starts a generation (see
 * application_update_subscribe_locked), so a build that ships no provider makes
 * no network request by default -- the property, not just the absence of a call.
 */

typedef struct cbm_daemon_application_watch cbm_daemon_application_watch_t;
typedef struct cbm_daemon_application_session cbm_daemon_application_session_t;
typedef struct cbm_daemon_application_job cbm_daemon_application_job_t;
typedef struct cbm_daemon_application_mutation cbm_daemon_application_mutation_t;
typedef struct cbm_daemon_application_watch_job_subscription
    cbm_daemon_application_watch_job_subscription_t;

typedef enum {
    APPLICATION_JOB_SUBSCRIBE_OK = 0,
    APPLICATION_JOB_SUBSCRIBE_OPTIONS_CONFLICT,
    APPLICATION_JOB_SUBSCRIBE_BUSY,
    APPLICATION_JOB_SUBSCRIBE_CANCELLING,
    APPLICATION_JOB_SUBSCRIBE_UNAVAILABLE,
    APPLICATION_JOB_SUBSCRIBE_ALLOCATION_FAILED,
} application_job_subscribe_status_t;

struct cbm_daemon_application_watch {
    char *project;
    char *root;
    size_t subscribers;
    cbm_daemon_application_watch_t *next;
};

struct cbm_daemon_application_session {
    cbm_daemon_application_t *application;
    cbm_mcp_server_t *mcp;
    cbm_daemon_client_id_t client_id;
    uint64_t authenticated_process_id;
    bool context_set;
    cbm_mcp_tool_profile_t tool_profile;
    char *hook_event;
    char *hook_dialect;
    bool session_cancelled;
    bool request_active;
    cbm_daemon_runtime_application_token_t active_request_token;
    cbm_daemon_runtime_application_token_t request_cancel_token;
    cbm_daemon_application_watch_t *watch;
    cbm_daemon_application_job_t *active_job;
    bool active_job_subscribed;
    cbm_daemon_application_job_t *auto_index_job;
    bool auto_index_subscribed;
    bool auto_index_evaluated;
    bool auto_index_retry_pending;
    bool background_eligible;
    bool update_owner;
    bool update_notice_delivered;
    bool pending_background_initialize;
    bool pending_update_notice;
    cbm_daemon_application_session_t *next;
};

struct cbm_daemon_application_job {
    cbm_daemon_application_t *application;
    char *project_key;
    char *root_path;
    char *args_json;
    char *response;
    cbm_daemon_application_worker_t worker;
    cbm_thread_t thread;
    size_t subscribers;
    size_t watcher_waiters;
    bool thread_started;
    bool thread_done;
    bool terminal;
    bool successful;
    bool cancelled;
    bool cancel_requested;
    bool supervision_failed;
    cbm_daemon_application_job_t *next;
};

/* A watcher-triggered physical job is owned by the exact live sessions that
 * currently subscribe to its project/root watch. The callback waiting for the
 * job is only a storage waiter; it is deliberately not an ownership
 * subscription, so the worker is cancelled when the last matching session
 * disconnects even while unrelated daemon sessions remain alive. */
struct cbm_daemon_application_watch_job_subscription {
    cbm_daemon_application_session_t *session;
    cbm_daemon_application_job_t *job;
    cbm_daemon_application_watch_job_subscription_t *next;
};

struct cbm_daemon_application_mutation {
    char *project_key;
    cbm_project_lock_lease_t *project_lock_lease;
    bool releasing;
    cbm_daemon_application_mutation_t *next;
};

struct cbm_daemon_application {
    cbm_mutex_t mutex;
    struct cbm_watcher *watcher;
    struct cbm_config *config;
    cbm_daemon_application_session_t *sessions;
    cbm_daemon_application_watch_t *watches;
    cbm_daemon_application_job_t *jobs;
    cbm_daemon_application_watch_job_subscription_t *watch_job_subscriptions;
    cbm_daemon_application_mutation_t *mutations;
    cbm_daemon_application_worker_ops_t worker_ops;
    cbm_daemon_application_update_ops_t update_ops;
    cbm_project_lock_manager_t *project_locks;
    size_t physical_job_limit;
    size_t worker_memory_budget_bytes;
    size_t active_mutations;
    size_t update_owners;
    cbm_daemon_application_update_worker_t update_worker;
    cbm_thread_t update_thread;
    char update_notice[APPLICATION_UPDATE_NOTICE_CAP];
    bool update_generation_started;
    bool update_cancel_requested;
    bool update_thread_started;
    bool update_thread_done;
    bool update_thread_joining;
    bool stopping;
    /* See cbm_daemon_application_set_permanent. */
    bool permanent;
};

static void application_job_unsubscribe_locked(cbm_daemon_application_job_t *job);
static void application_watch_job_unsubscribe_session_locked(
    cbm_daemon_application_session_t *session);
static bool application_watch_job_subscribe_late_session_locked(
    cbm_daemon_application_session_t *session, cbm_daemon_application_watch_t *watch);
static bool application_unique_recovery_file(char out[APPLICATION_PATH_CAP], const char *kind);
static bool application_update_reap(cbm_daemon_application_t *application, bool wait,
                                    uint32_t timeout_ms);
static void *application_job_thread(void *opaque);
static char *application_auto_index_args(const char *root_path);
static cbm_daemon_application_job_t *application_job_subscribe_locked(
    cbm_daemon_application_t *application, const char *project_key, const char *root_path,
    const char *args_json, application_job_subscribe_status_t *status_out);

static atomic_bool g_application_fail_next_job_thread_start_for_test = ATOMIC_VAR_INIT(false);

void cbm_daemon_application_fail_next_job_thread_start_for_test(void) {
    atomic_store_explicit(&g_application_fail_next_job_thread_start_for_test, true,
                          memory_order_release);
}

static atomic_bool g_application_hold_job_before_start_for_test = ATOMIC_VAR_INIT(false);

/* Counts completed background-initialize passes (the request-handler tail
 * that evaluates auto-index admission). The client can observe its
 * initialize RESPONSE before this tail finishes, so a test asserting the
 * tail's NEGATIVE outcome ("no job was admitted") needs this positive
 * completion signal — a fixed sleep is a lottery in both directions. */
static atomic_int g_application_background_initializes_for_test = ATOMIC_VAR_INIT(0);

int cbm_daemon_application_background_initializes_for_test(void) {
    return atomic_load_explicit(&g_application_background_initializes_for_test,
                                memory_order_acquire);
}

/* Counts iterations of the explicit-index busy-queue wait loop. A test that
 * needs "the request is parked behind the physical job limit" waits for a
 * DELTA here — the positive signal that queueing (not an error return)
 * happened — before releasing the slot. */
static atomic_int g_application_busy_queue_waits_for_test = ATOMIC_VAR_INIT(0);

int cbm_daemon_application_busy_queue_waits_for_test(void) {
    return atomic_load_explicit(&g_application_busy_queue_waits_for_test, memory_order_acquire);
}

void cbm_daemon_application_hold_job_before_start_for_test(bool hold) {
    atomic_store_explicit(&g_application_hold_job_before_start_for_test, hold,
                          memory_order_release);
}

static int application_job_thread_create(cbm_thread_t *thread, void *context) {
    if (atomic_exchange_explicit(&g_application_fail_next_job_thread_start_for_test, false,
                                 memory_order_acq_rel)) {
        return APPLICATION_RESULT_FAILURE;
    }
    return cbm_thread_create(thread, APPLICATION_JOB_THREAD_STACK, application_job_thread, context);
}

static bool application_request_cancelled_locked(const cbm_daemon_application_session_t *session) {
    return session &&
           (session->session_cancelled ||
            (session->request_active &&
             session->active_request_token != CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID &&
             session->request_cancel_token == session->active_request_token));
}

static uint64_t application_deadline_after(uint32_t timeout_ms) {
    uint64_t now = cbm_now_ms();
    return now > UINT64_MAX - timeout_ms ? UINT64_MAX : now + timeout_ms;
}

static _Noreturn void application_cleanup_force_terminate(const char *component) {
    /* In production this module is daemon-owned and the host log sink flushes
     * every record synchronously. Continuing would either lose the only retry
     * handle or falsely make a project mutation appear released. */
    cbm_log_error("daemon.forced_shutdown", "component", component);
    (void)fflush(stdout);
    (void)fflush(stderr);
#ifdef _WIN32
    (void)TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
    abort();
#else
    _exit(EXIT_FAILURE);
#endif
}

static void application_project_lock_release_fully(cbm_project_lock_lease_t **lease) {
    uint64_t deadline = application_deadline_after(APPLICATION_COORDINATION_CLEANUP_MS);
    while (lease && *lease) {
        (void)cbm_project_lock_lease_release(lease);
        if (!*lease) {
            return;
        }
        if (cbm_now_ms() >= deadline) {
            application_cleanup_force_terminate("project_lock_cleanup");
        }
        cbm_usleep(1000);
    }
}

static int application_worker_start_default(void *context, const char *args_json,
                                            size_t memory_budget_bytes, const char *marker_file,
                                            const char *quarantine_file,
                                            cbm_daemon_application_worker_t *worker_out) {
    (void)context;
    cbm_index_worker_handle_t *worker = NULL;
    int result = cbm_index_worker_start(args_json, memory_budget_bytes, false, marker_file,
                                        quarantine_file, &worker);
    *worker_out = worker;
    return result;
}

static cbm_index_worker_poll_t application_worker_poll_default(
    void *context, cbm_daemon_application_worker_t worker,
    const cbm_index_worker_result_t **result_out) {
    (void)context;
    return cbm_index_worker_poll((cbm_index_worker_handle_t *)worker, result_out);
}

static bool application_worker_cancel_default(void *context,
                                              cbm_daemon_application_worker_t worker) {
    (void)context;
    return cbm_index_worker_request_cancel((cbm_index_worker_handle_t *)worker);
}

static const char *application_worker_log_path_default(void *context,
                                                       cbm_daemon_application_worker_t worker) {
    (void)context;
    return cbm_index_worker_log_path((cbm_index_worker_handle_t *)worker);
}

static void application_worker_destroy_default(void *context,
                                               cbm_daemon_application_worker_t worker) {
    (void)context;
    cbm_index_worker_destroy((cbm_index_worker_handle_t *)worker);
}

static uint32_t application_get_u32(const uint8_t *bytes) {
    return ((uint32_t)bytes[APPLICATION_BYTE_INDEX_FIRST]
            << APPLICATION_U32_SHIFT_MOST_SIGNIFICANT) |
           ((uint32_t)bytes[APPLICATION_BYTE_INDEX_SECOND] << APPLICATION_U32_SHIFT_SECOND) |
           ((uint32_t)bytes[APPLICATION_BYTE_INDEX_THIRD] << APPLICATION_U32_SHIFT_THIRD) |
           (uint32_t)bytes[APPLICATION_BYTE_INDEX_FOURTH];
}

static void application_put_u32(uint8_t *bytes, uint32_t value) {
    bytes[APPLICATION_BYTE_INDEX_FIRST] =
        (uint8_t)(value >> APPLICATION_U32_SHIFT_MOST_SIGNIFICANT);
    bytes[APPLICATION_BYTE_INDEX_SECOND] = (uint8_t)(value >> APPLICATION_U32_SHIFT_SECOND);
    bytes[APPLICATION_BYTE_INDEX_THIRD] = (uint8_t)(value >> APPLICATION_U32_SHIFT_THIRD);
    bytes[APPLICATION_BYTE_INDEX_FOURTH] = (uint8_t)value;
}

static char *application_text_copy(const uint8_t *bytes, uint32_t length) {
    if (!bytes || length == 0 || memchr(bytes, '\0', length) != NULL) {
        return NULL;
    }
    char *copy = malloc((size_t)length + APPLICATION_TEXT_TERMINATOR_BYTES);
    if (copy) {
        memcpy(copy, bytes, length);
        copy[length] = '\0';
    }
    return copy;
}

static bool application_regular_db_exists(const char *project) {
    const char *cache = cbm_resolve_cache_dir();
    if (!cache || !project || !project[0]) {
        return false;
    }
    char path[APPLICATION_PATH_CAP];
    int written = snprintf(path, sizeof(path), "%s/%s.db", cache, project);
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return false;
    }
    struct stat status;
    return stat(path, &status) == 0 && S_ISREG(status.st_mode);
}

static cbm_daemon_application_watch_t *application_find_watch_locked(
    cbm_daemon_application_t *application, const char *project) {
    for (cbm_daemon_application_watch_t *watch = application->watches; watch; watch = watch->next) {
        if (strcmp(watch->project, project) == 0) {
            return watch;
        }
    }
    return NULL;
}

static void application_remove_watch_entry_locked(cbm_daemon_application_t *application,
                                                  cbm_daemon_application_watch_t *watch,
                                                  bool unregister_physical_watch) {
    cbm_daemon_application_watch_t **cursor = &application->watches;
    while (*cursor && *cursor != watch) {
        cursor = &(*cursor)->next;
    }
    if (*cursor != watch) {
        return;
    }
    *cursor = watch->next;
    for (cbm_daemon_application_session_t *session = application->sessions; session;
         session = session->next) {
        if (session->watch == watch) {
            application_watch_job_unsubscribe_session_locked(session);
            session->watch = NULL;
        }
    }
    if (unregister_physical_watch && application->watcher) {
        cbm_watcher_unwatch(application->watcher, watch->project);
    }
    free(watch->project);
    free(watch->root);
    free(watch);
}

static void application_remove_watch_locked(cbm_daemon_application_t *application,
                                            cbm_daemon_application_watch_t *watch) {
    application_remove_watch_entry_locked(application, watch, true);
}

static void application_release_session_watch_locked(cbm_daemon_application_session_t *session) {
    cbm_daemon_application_watch_t *watch = session->watch;
    if (!watch) {
        return;
    }
    application_watch_job_unsubscribe_session_locked(session);
    session->watch = NULL;
    if (watch->subscribers > 0) {
        watch->subscribers--;
    }
    if (watch->subscribers == 0) {
        application_remove_watch_locked(session->application, watch);
    }
}

/* Caller holds application->mutex. */
static void application_refresh_watch_locked(cbm_daemon_application_session_t *session) {
    cbm_daemon_application_t *application = session->application;
    if (!application->watcher || !session->context_set ||
        session->tool_profile != CBM_MCP_TOOL_PROFILE_ALL || session->hook_event ||
        session->hook_dialect || session->auto_index_subscribed) {
        return;
    }
    const char *project = cbm_mcp_server_session_project(session->mcp);
    const char *root = cbm_mcp_server_session_root(session->mcp);
    if (!project || !project[0] || !root || !root[0]) {
        return;
    }
    bool enabled = !application->config ||
                   cbm_config_get_bool(application->config, CBM_CONFIG_AUTO_WATCH, true);
    bool db_exists = application_regular_db_exists(project);

    /* Disconnect cancellation is the logical ownership boundary. An
     * in-flight request may reach this refresh after cancel returned but
     * before runtime can join it and call session_close; it must never
     * recreate that session's watch. */
    if (application->stopping || application_request_cancelled_locked(session)) {
        return;
    }
    cbm_daemon_application_watch_t *watch = application_find_watch_locked(application, project);
    if (!enabled || !db_exists) {
        /* A delete/config transition is global for this project. Remove the
         * physical watch and clear every logical subscriber in one step. */
        if (watch) {
            application_remove_watch_locked(application, watch);
        }
        return;
    }
    if (session->watch) {
        return;
    }
    if (watch) {
        if (strcmp(watch->root, root) == 0) {
            if (!application_watch_job_subscribe_late_session_locked(session, watch)) {
                cbm_log_warn("daemon.watch.late_owner_allocation_failed", "project", project,
                             "action", "retry");
                return;
            }
            watch->subscribers++;
            session->watch = watch;
        } else {
            cbm_log_warn("daemon.watch.project_collision", "project", project, "existing_root",
                         watch->root, "requested_root", root);
        }
        return;
    }

    watch = calloc(APPLICATION_ALLOCATION_ELEMENTS_ONE, sizeof(*watch));
    if (watch) {
        watch->project = strdup(project);
        watch->root = strdup(root);
    }
    if (!watch || !watch->project || !watch->root) {
        if (watch) {
            free(watch->project);
            free(watch->root);
            free(watch);
        }
        return;
    }
    /* Physical registration is the commit point. Never publish a logical
     * subscription that the shared watcher failed to install. */
    if (!cbm_watcher_watch(application->watcher, project, root)) {
        cbm_log_warn("daemon.watch.registration_failed", "project", project, "action", "retry");
        free(watch->project);
        free(watch->root);
        free(watch);
        return;
    }
    watch->subscribers = APPLICATION_COUNT_ONE;
    watch->next = application->watches;
    application->watches = watch;
    session->watch = watch;
}

static void application_refresh_watch(cbm_daemon_application_session_t *session) {
    if (!session || !session->application) {
        return;
    }
    cbm_mutex_lock(&session->application->mutex);
    application_refresh_watch_locked(session);
    cbm_mutex_unlock(&session->application->mutex);
}

static void application_job_free(cbm_daemon_application_job_t *job) {
    if (!job) {
        return;
    }
    free(job->project_key);
    free(job->root_path);
    free(job->args_json);
    free(job->response);
    free(job);
}

/* Reap completed job threads only after every logical demand subscription and
 * watcher callback storage waiter has released the job. Exactly one caller
 * removes a job under the mutex. */
static void application_jobs_reap_completed(cbm_daemon_application_t *application) {
    for (;;) {
        cbm_daemon_application_job_t *reap = NULL;
        cbm_mutex_lock(&application->mutex);
        cbm_daemon_application_job_t **cursor = &application->jobs;
        while (*cursor) {
            if ((*cursor)->thread_done && (*cursor)->subscribers == 0 &&
                (*cursor)->watcher_waiters == 0) {
                reap = *cursor;
                *cursor = reap->next;
                reap->next = NULL;
                break;
            }
            cursor = &(*cursor)->next;
        }
        cbm_mutex_unlock(&application->mutex);
        if (!reap) {
            return;
        }
        if (reap->thread_started) {
            (void)cbm_thread_join(&reap->thread);
        }
        application_job_free(reap);
    }
}

typedef enum {
    APPLICATION_ATTEMPT_TERMINAL = 0,
    APPLICATION_ATTEMPT_START_FAILED,
    APPLICATION_ATTEMPT_CANCELLED,
} application_attempt_status_t;

typedef struct {
    cbm_index_worker_result_t result;
    bool has_result;
    char log_path[APPLICATION_PATH_CAP];
} application_attempt_t;

static atomic_flag g_application_tmp_lock = ATOMIC_FLAG_INIT;

static void application_tmp_lock(void) {
    while (atomic_flag_test_and_set_explicit(&g_application_tmp_lock, memory_order_acquire)) {
        cbm_usleep(1000);
    }
}

static void application_tmp_unlock(void) {
    atomic_flag_clear_explicit(&g_application_tmp_lock, memory_order_release);
}

static bool application_cache_dir(char out[APPLICATION_PATH_CAP]) {
    char configured[APPLICATION_PATH_CAP] = {0};
    if (cbm_safe_getenv("CBM_CACHE_DIR", configured, sizeof(configured), NULL) && configured[0]) {
        int written = snprintf(out, APPLICATION_PATH_CAP, "%s", configured);
        if (written <= 0 || written >= APPLICATION_PATH_CAP) {
            return false;
        }
        cbm_normalize_path_sep(out);
        return true;
    }
    char home[APPLICATION_PATH_CAP] = {0};
    if (!cbm_safe_getenv("HOME", home, sizeof(home), NULL) || !home[0]) {
        (void)cbm_safe_getenv("USERPROFILE", home, sizeof(home), NULL);
    }
    if (!home[0]) {
        return false;
    }
    int written = snprintf(out, APPLICATION_PATH_CAP, "%s/.cache/codebase-memory-mcp", home);
    if (written <= 0 || written >= APPLICATION_PATH_CAP) {
        return false;
    }
    cbm_normalize_path_sep(out);
    return true;
}

static bool application_unique_recovery_file(char out[APPLICATION_PATH_CAP], const char *kind) {
    char cache[APPLICATION_PATH_CAP] = {0};
    char directory[APPLICATION_PATH_CAP] = {0};
    int written;
    if (application_cache_dir(cache)) {
        written = snprintf(directory, sizeof(directory), "%s/logs", cache);
        if (written <= 0 || written >= (int)sizeof(directory) ||
            !cbm_mkdir_p(directory, APPLICATION_FILE_MODE_OWNER_ONLY)) {
            return false;
        }
    } else {
        written = snprintf(directory, sizeof(directory), "%s", cbm_tmpdir());
        if (written <= 0 || written >= (int)sizeof(directory)) {
            return false;
        }
    }
    written = snprintf(out, APPLICATION_PATH_CAP, "%s/.daemon-index-%s-XXXXXX", directory, kind);
    if (written <= 0 || written >= APPLICATION_PATH_CAP) {
        out[0] = '\0';
        return false;
    }
    application_tmp_lock();
    int descriptor = cbm_mkstemp(out);
    application_tmp_unlock();
    if (descriptor < 0) {
        out[0] = '\0';
        return false;
    }
    (void)application_close(descriptor);
    return true;
}

static bool application_recovery_files_create(char marker_path[APPLICATION_PATH_CAP],
                                              char quarantine_path[APPLICATION_PATH_CAP]) {
    if (!application_unique_recovery_file(marker_path, "marker")) {
        return false;
    }
    if (!application_unique_recovery_file(quarantine_path, "quarantine")) {
        (void)cbm_unlink(marker_path);
        marker_path[0] = '\0';
        return false;
    }
    return true;
}

static void application_recovery_files_remove(const char *marker_path,
                                              const char *quarantine_path) {
    if (marker_path && marker_path[0]) {
        (void)cbm_unlink(marker_path);
    }
    if (quarantine_path && quarantine_path[0]) {
        (void)cbm_unlink(quarantine_path);
    }
}

static bool application_truncate_file(const char *path) {
    FILE *file = cbm_fopen(path, "wb");
    return file && fclose(file) == 0;
}

static bool application_job_cancel_requested(cbm_daemon_application_job_t *job);
static bool application_suspect_contains(char **suspects, int count, const char *relative);

static bool application_suspect_line_is_valid(char *line, size_t *length_out) {
    size_t length = strlen(line);
    if (length == 0 || line[length - APPLICATION_TEXT_TERMINATOR_BYTES] != '\n') {
        return false;
    }
    line[--length] = '\0';
    if (length > 0 && line[length - APPLICATION_TEXT_TERMINATOR_BYTES] == '\r') {
        line[--length] = '\0';
    }
    *length_out = length;
    return length >= APPLICATION_STATUS_LINE_MIN_LENGTH &&
           (line[APPLICATION_BYTE_INDEX_FIRST] == 'S' ||
            line[APPLICATION_BYTE_INDEX_FIRST] == 'D') &&
           line[APPLICATION_BYTE_INDEX_SECOND] == ' ';
}

static bool application_suspect_add(char ***paths, int *count, size_t *capacity,
                                    const char *relative) {
    if (application_suspect_contains(*paths, *count, relative)) {
        return true;
    }
    if (*count >= APPLICATION_MAX_SUSPECTS) {
        return false;
    }
    if ((size_t)*count == *capacity) {
        size_t next_capacity = *capacity ? *capacity * APPLICATION_OPEN_PATH_CAPACITY_GROWTH
                                         : APPLICATION_OPEN_PATH_CAPACITY_INITIAL;
        char **next = realloc(*paths, next_capacity * sizeof(*next));
        if (!next) {
            return false;
        }
        *paths = next;
        *capacity = next_capacity;
    }
    char *copy = cbm_strdup(relative);
    if (!copy) {
        return false;
    }
    (*paths)[(*count)++] = copy;
    return true;
}

static void application_suspect_remove(char **paths, int *count, const char *relative) {
    for (int i = 0; i < *count; i++) {
        if (strcmp(paths[i], relative) == 0) {
            free(paths[i]);
            memmove(&paths[i], &paths[i + 1], (size_t)(*count - i - 1) * sizeof(*paths));
            (*count)--;
            return;
        }
    }
}

static char **application_read_suspects(cbm_daemon_application_job_t *job, const char *path,
                                        int *count_out, bool *cancelled_out) {
    *count_out = 0;
    *cancelled_out = false;
    int64_t marker_size = cbm_file_size(path);
    if (marker_size < 0 || marker_size > APPLICATION_MARKER_MAX_BYTES) {
        return NULL;
    }
    FILE *file = cbm_fopen(path, "rb");
    if (!file) {
        return NULL;
    }
    char **open_paths = NULL;
    int open_count = 0;
    size_t open_capacity = 0;
    bool allocation_failed = false;
    size_t lines_read = 0;
    char line[APPLICATION_PATH_CAP];
    while (fgets(line, sizeof(line), file)) {
        if ((lines_read++ & APPLICATION_CANCEL_CHECK_INTERVAL_MASK) == 0U &&
            application_job_cancel_requested(job)) {
            *cancelled_out = true;
            allocation_failed = true;
            break;
        }
        size_t length = 0;
        size_t raw_length = strlen(line);
        if (!application_suspect_line_is_valid(line, &length)) {
            if (raw_length == 0 || line[raw_length - APPLICATION_TEXT_TERMINATOR_BYTES] != '\n') {
                break;
            }
            continue;
        }
        const char *relative = line + APPLICATION_STATUS_LINE_RELATIVE_OFFSET;
        if (line[APPLICATION_BYTE_INDEX_FIRST] == 'S') {
            if (!application_suspect_add(&open_paths, &open_count, &open_capacity, relative)) {
                allocation_failed = true;
                break;
            }
        } else {
            application_suspect_remove(open_paths, &open_count, relative);
        }
    }
    (void)fclose(file);
    if (allocation_failed) {
        for (int i = 0; i < open_count; i++) {
            free(open_paths[i]);
        }
        free(open_paths);
        return NULL;
    }
    if (open_count == 0) {
        free(open_paths);
        return NULL;
    }
    *count_out = open_count;
    return open_paths;
}

static void application_free_suspects(char **suspects, int count) {
    if (!suspects) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(suspects[i]);
    }
    free(suspects);
}

static bool application_suspect_contains(char **suspects, int count, const char *relative) {
    for (int i = 0; i < count; i++) {
        if (strcmp(suspects[i], relative) == 0) {
            return true;
        }
    }
    return false;
}

static bool application_append_quarantine(const char *path, const char *relative,
                                          const char *phase) {
    if (!relative || !relative[0] || strpbrk(relative, "\r\n\t")) {
        return false;
    }
    FILE *file = cbm_fopen(path, "ab");
    if (!file) {
        return false;
    }
    bool written = fprintf(file, "%s\t%s\n", relative, phase) >= 0;
    return fclose(file) == 0 && written;
}

static int application_max_restarts(void) {
    char value[APPLICATION_NUMERIC_TEXT_CAP] = {0};
    if (!cbm_safe_getenv("CBM_INDEX_MAX_RESTARTS", value, sizeof(value), NULL) || !value[0]) {
        return APPLICATION_DEFAULT_MAX_RESTARTS;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, APPLICATION_DECIMAL_RADIX);
    return end && *end == '\0' && parsed > 0 && parsed <= INT_MAX
               ? (int)parsed
               : APPLICATION_DEFAULT_MAX_RESTARTS;
}

static void application_attempt_init(application_attempt_t *attempt) {
    memset(attempt, 0, sizeof(*attempt));
    attempt->result.outcome = CBM_PROC_SPAWN_FAILED;
    attempt->result.exit_code = APPLICATION_RESULT_FAILURE;
}

static void application_attempt_free(application_attempt_t *attempt) {
    free(attempt->result.response);
    attempt->result.response = NULL;
}

static bool application_job_cancel_requested(cbm_daemon_application_job_t *job) {
    cbm_daemon_application_t *application = job->application;
    cbm_mutex_lock(&application->mutex);
    bool cancelled = job->cancel_requested || application->stopping;
    cbm_mutex_unlock(&application->mutex);
    return cancelled;
}

static bool application_project_keys_conflict(const char *left, const char *right) {
    return left && right &&
           (strcmp(left, right) == 0 || strcmp(left, "*") == 0 || strcmp(right, "*") == 0);
}

static bool application_mutation_conflicts_locked(cbm_daemon_application_t *application,
                                                  const char *project_key) {
    for (cbm_daemon_application_mutation_t *mutation = application->mutations; mutation;
         mutation = mutation->next) {
        if (application_project_keys_conflict(mutation->project_key, project_key)) {
            return true;
        }
    }
    return false;
}

static bool application_job_reserves_project_locked(cbm_daemon_application_t *application,
                                                    const char *project_key) {
    for (cbm_daemon_application_job_t *job = application->jobs; job; job = job->next) {
        if (!job->terminal && application_project_keys_conflict(job->project_key, project_key)) {
            return true;
        }
    }
    return false;
}

static bool application_mutation_cancelled_locked(cbm_daemon_application_t *application,
                                                  cbm_daemon_application_session_t *session) {
    return application->stopping || (session && application_request_cancelled_locked(session));
}

static cbm_daemon_application_mutation_t *application_mutation_reserve_locked(
    cbm_daemon_application_t *application, const char *project_key) {
    cbm_daemon_application_mutation_t *mutation =
        calloc(APPLICATION_ALLOCATION_ELEMENTS_ONE, sizeof(*mutation));
    if (!mutation) {
        return NULL;
    }
    mutation->project_key = cbm_strdup(project_key);
    if (!mutation->project_key) {
        free(mutation);
        return NULL;
    }
    mutation->next = application->mutations;
    application->mutations = mutation;
    application->active_mutations++;
    return mutation;
}

static void application_mutation_release_reservation(cbm_daemon_application_t *application,
                                                     cbm_daemon_application_mutation_t *reserved) {
    cbm_mutex_lock(&application->mutex);
    cbm_daemon_application_mutation_t **cursor = &application->mutations;
    while (*cursor && *cursor != reserved) {
        cursor = &(*cursor)->next;
    }
    if (*cursor == reserved) {
        *cursor = reserved->next;
        if (application->active_mutations > 0) {
            application->active_mutations--;
        }
    }
    cbm_mutex_unlock(&application->mutex);
    free(reserved->project_key);
    free(reserved);
}

static cbm_daemon_application_mutation_t *application_wait_for_mutation_reservation(
    cbm_daemon_application_t *application, cbm_daemon_application_session_t *session,
    const char *project_key, bool wait) {
    for (;;) {
        cbm_mutex_lock(&application->mutex);
        bool cancelled = application_mutation_cancelled_locked(application, session);
        bool busy = application_mutation_conflicts_locked(application, project_key) ||
                    application_job_reserves_project_locked(application, project_key);
        cbm_daemon_application_mutation_t *reserved =
            !cancelled && !busy ? application_mutation_reserve_locked(application, project_key)
                                : NULL;
        cbm_mutex_unlock(&application->mutex);
        if (reserved || cancelled || !wait) {
            return reserved;
        }
        cbm_usleep(APPLICATION_JOB_POLL_US);
    }
}

static bool application_mutation_acquire_project_lock(cbm_daemon_application_t *application,
                                                      cbm_daemon_application_session_t *session,
                                                      cbm_daemon_application_mutation_t *reserved,
                                                      const char *project_key, bool wait) {
    if (!application->project_locks) {
        return true;
    }
    for (;;) {
        uint64_t now = cbm_now_ms();
        uint64_t deadline = now > UINT64_MAX - APPLICATION_COORDINATION_RETRY_MS
                                ? UINT64_MAX
                                : now + APPLICATION_COORDINATION_RETRY_MS;
        cbm_project_lock_lease_t *lease = NULL;
        cbm_private_file_lock_status_t status =
            wait ? cbm_project_lock_acquire(application->project_locks, project_key, deadline, NULL,
                                            &lease)
                 : cbm_project_lock_try_acquire(application->project_locks, project_key, &lease);
        cbm_mutex_lock(&application->mutex);
        bool cancelled = application_mutation_cancelled_locked(application, session);
        cbm_mutex_unlock(&application->mutex);
        if (status == CBM_PRIVATE_FILE_LOCK_OK && lease && !cancelled) {
            reserved->project_lock_lease = lease;
            return true;
        }
        application_project_lock_release_fully(&lease);
        if (status != CBM_PRIVATE_FILE_LOCK_BUSY || cancelled || !wait) {
            if (status != CBM_PRIVATE_FILE_LOCK_BUSY) {
                cbm_log_error("daemon.project_lock_failed", "project", project_key, "action",
                              "refuse_mutation");
            }
            return false;
        }
    }
}

static bool application_mutation_begin_internal(cbm_daemon_application_t *application,
                                                cbm_daemon_application_session_t *session,
                                                const char *project_key, bool wait) {
    if (!application || !project_key || !project_key[0]) {
        return false;
    }
    cbm_daemon_application_mutation_t *reserved =
        application_wait_for_mutation_reservation(application, session, project_key, wait);
    if (!reserved) {
        return false;
    }
    if (application_mutation_acquire_project_lock(application, session, reserved, project_key,
                                                  wait)) {
        return true;
    }
    application_mutation_release_reservation(application, reserved);
    return false;
}

bool cbm_daemon_application_project_mutation_try_begin(cbm_daemon_application_t *application,
                                                       const char *project) {
    return application_mutation_begin_internal(application, NULL, project, false);
}

void cbm_daemon_application_project_mutation_end(cbm_daemon_application_t *application,
                                                 const char *project) {
    if (!application || !project || !project[0]) {
        return;
    }
    cbm_mutex_lock(&application->mutex);
    cbm_daemon_application_mutation_t *mutation = application->mutations;
    while (mutation && strcmp(mutation->project_key, project) != 0) {
        mutation = mutation->next;
    }
    if (!mutation || mutation->releasing) {
        cbm_mutex_unlock(&application->mutex);
        return;
    }
    mutation->releasing = true;
    cbm_mutex_unlock(&application->mutex);

    /* Keep the logical reservation visible until the native lease is gone.
     * Otherwise another in-daemon operation can observe an apparently free
     * project and enter the OS-lock wait during the release handoff. */
    application_project_lock_release_fully(&mutation->project_lock_lease);

    cbm_mutex_lock(&application->mutex);
    cbm_daemon_application_mutation_t **cursor = &application->mutations;
    while (*cursor && *cursor != mutation) {
        cursor = &(*cursor)->next;
    }
    if (*cursor == mutation) {
        *cursor = mutation->next;
        if (application->active_mutations > 0) {
            application->active_mutations--;
        }
    }
    cbm_mutex_unlock(&application->mutex);
    free(mutation->project_key);
    free(mutation);
}

static bool application_watcher_mutation_begin(void *context, const char *project) {
    return cbm_daemon_application_project_mutation_try_begin(context, project);
}

static void application_watcher_mutation_end(void *context, const char *project) {
    cbm_daemon_application_project_mutation_end(context, project);
}

static void application_watcher_project_pruned(void *context, const char *project) {
    cbm_daemon_application_t *application = context;
    if (!application || !project) {
        return;
    }
    cbm_mutex_lock(&application->mutex);
    cbm_daemon_application_watch_t *watch = application_find_watch_locked(application, project);
    if (watch) {
        /* The watcher already removed its physical entry. Invalidate every
         * logical subscriber so a later successful index can re-register it. */
        application_remove_watch_entry_locked(application, watch, false);
    }
    cbm_mutex_unlock(&application->mutex);
}

static bool application_session_mutation_begin(void *context, const char *project) {
    cbm_daemon_application_session_t *session = context;
    return session &&
           application_mutation_begin_internal(session->application, session, project, true);
}

static bool application_session_mutation_try_begin(void *context, const char *project) {
    cbm_daemon_application_session_t *session = context;
    return session &&
           application_mutation_begin_internal(session->application, session, project, false);
}

static void application_session_mutation_end(void *context, const char *project) {
    cbm_daemon_application_session_t *session = context;
    if (session) {
        cbm_daemon_application_project_mutation_end(session->application, project);
    }
}

static bool application_job_wait_for_mutations(cbm_daemon_application_job_t *job) {
    cbm_daemon_application_t *application = job->application;
    for (;;) {
        cbm_mutex_lock(&application->mutex);
        bool cancelled = job->cancel_requested || application->stopping;
        bool busy = application_mutation_conflicts_locked(application, job->project_key);
        cbm_mutex_unlock(&application->mutex);
        if (cancelled) {
            return false;
        }
        if (!busy) {
            return true;
        }
        cbm_usleep(APPLICATION_JOB_POLL_US);
    }
}

static void application_cancelled_result(cbm_index_worker_result_t *result) {
    memset(result, 0, sizeof(*result));
    result->outcome = CBM_PROC_KILLED;
    result->exit_code = APPLICATION_RESULT_FAILURE;
    result->cancellation_requested = true;
    result->tree_quiesced = true;
}

static const cbm_index_worker_result_t *application_wait_for_worker(
    cbm_daemon_application_job_t *job, cbm_daemon_application_worker_t worker) {
    cbm_daemon_application_t *application = job->application;
    const cbm_index_worker_result_t *result = NULL;
    for (;;) {
        cbm_index_worker_poll_t state =
            application->worker_ops.poll(application->worker_ops.context, worker, &result);
        if (state == CBM_INDEX_WORKER_POLL_TERMINAL) {
            return result;
        }
        cbm_mutex_lock(&application->mutex);
        bool cancel_pending =
            (job->cancel_requested || application->stopping) && job->worker == worker;
        cbm_mutex_unlock(&application->mutex);
        if (cancel_pending || state == CBM_INDEX_WORKER_POLL_ERROR) {
            (void)application->worker_ops.cancel(application->worker_ops.context, worker);
        }
        cbm_usleep(APPLICATION_JOB_POLL_US);
    }
}

static application_attempt_status_t application_job_run_attempt(cbm_daemon_application_job_t *job,
                                                                const char *marker_path,
                                                                const char *quarantine_path,
                                                                application_attempt_t *attempt) {
    application_attempt_init(attempt);
    cbm_daemon_application_t *application = job->application;
    if (application_job_cancel_requested(job)) {
        return APPLICATION_ATTEMPT_CANCELLED;
    }

    cbm_daemon_application_worker_t worker = NULL;
    application_tmp_lock();
    int start_result = application->worker_ops.start(
        application->worker_ops.context, job->args_json, application->worker_memory_budget_bytes,
        marker_path, quarantine_path, &worker);
    application_tmp_unlock();
    if (start_result != 0 || !worker) {
        return application_job_cancel_requested(job) ? APPLICATION_ATTEMPT_CANCELLED
                                                     : APPLICATION_ATTEMPT_START_FAILED;
    }

    cbm_mutex_lock(&application->mutex);
    job->worker = worker;
    bool cancel_now = job->cancel_requested || application->stopping;
    cbm_mutex_unlock(&application->mutex);
    if (cancel_now) {
        /* The worker thread owns this handle until destroy below. Invoke the
         * external supervisor without the application mutex held. */
        (void)application->worker_ops.cancel(application->worker_ops.context, worker);
    }

    const cbm_index_worker_result_t *borrowed = application_wait_for_worker(job, worker);

    if (borrowed) {
        attempt->result = *borrowed;
        attempt->result.response = borrowed->response ? cbm_strdup(borrowed->response) : NULL;
        attempt->has_result = true;
    }
    const char *worker_log =
        application->worker_ops.log_path(application->worker_ops.context, worker);
    if (worker_log) {
        (void)snprintf(attempt->log_path, sizeof(attempt->log_path), "%s", worker_log);
    }

    cbm_mutex_lock(&application->mutex);
    if (job->worker == worker) {
        job->worker = NULL;
    }
    bool cancelled = job->cancel_requested || application->stopping;
    cbm_mutex_unlock(&application->mutex);
    application->worker_ops.destroy(application->worker_ops.context, worker);

    if (cancelled) {
        if (!attempt->has_result) {
            application_cancelled_result(&attempt->result);
            attempt->has_result = true;
        } else {
            attempt->result.cancellation_requested = true;
        }
    }
    return APPLICATION_ATTEMPT_TERMINAL;
}

static char *application_job_failure_response(const cbm_index_worker_result_t *result,
                                              const char *log_path) {
    char message[APPLICATION_ERROR_MESSAGE_CAP];
    if (result && result->cancellation_requested) {
        (void)snprintf(message, sizeof(message),
                       "index operation cancelled after its final owning session disconnected");
    } else if (result && (result->supervision_failed || !result->tree_quiesced)) {
        (void)snprintf(message, sizeof(message),
                       "index worker containment failed (%s); inspect log: %s",
                       cbm_proc_outcome_str(result->outcome), log_path ? log_path : "unavailable");
    } else if (result) {
        (void)snprintf(message, sizeof(message),
                       "index worker ended with %s (exit=%d, signal=%d); inspect log: %s",
                       cbm_proc_outcome_str(result->outcome), result->exit_code,
                       result->term_signal, log_path ? log_path : "unavailable");
    } else {
        (void)snprintf(message, sizeof(message), "index worker could not be started");
    }
    return cbm_mcp_text_result(message, true);
}

static cbm_mcp_supervised_result_disposition_t application_attempt_disposition(
    cbm_daemon_application_job_t *job, application_attempt_t *attempt) {
    if (application_job_cancel_requested(job)) {
        if (!attempt->has_result) {
            application_cancelled_result(&attempt->result);
            attempt->has_result = true;
        } else {
            attempt->result.cancellation_requested = true;
        }
    }
    return cbm_mcp_supervised_result_disposition(0, attempt->has_result ? &attempt->result : NULL);
}

static void application_record_attempt(const application_attempt_t *attempt,
                                       cbm_index_worker_result_t *last_result,
                                       bool *have_last_result,
                                       char last_log[APPLICATION_PATH_CAP]) {
    *last_result = attempt->result;
    last_result->response = NULL;
    *have_last_result = attempt->has_result;
    last_log[0] = '\0';
    if (attempt->log_path[0]) {
        (void)snprintf(last_log, APPLICATION_PATH_CAP, "%s", attempt->log_path);
    }
}

static void application_record_cancelled(cbm_index_worker_result_t *last_result,
                                         bool *have_last_result,
                                         char last_log[APPLICATION_PATH_CAP]) {
    application_cancelled_result(last_result);
    *have_last_result = true;
    last_log[0] = '\0';
}

static bool application_result_is_attributable_failure(
    const application_attempt_t *attempt, cbm_mcp_supervised_result_disposition_t disposition) {
    return disposition == CBM_MCP_SUPERVISED_RESULT_CONTAINED_FAILURE && attempt->has_result &&
           (attempt->result.outcome == CBM_PROC_CRASH || attempt->result.outcome == CBM_PROC_HANG);
}

typedef enum {
    APPLICATION_ATTEMPT_DECISION_STOP = 0,
    APPLICATION_ATTEMPT_DECISION_SUCCESS,
    APPLICATION_ATTEMPT_DECISION_RECOVERABLE,
} application_attempt_decision_t;

typedef struct {
    char *response;
    bool successful;
    bool unsafe_terminal;
    bool supervision_failed;
    cbm_index_worker_result_t last_result;
    bool have_last_result;
    char last_log[APPLICATION_PATH_CAP];
} application_job_execution_t;

static void application_job_execution_init(application_job_execution_t *execution) {
    memset(execution, 0, sizeof(*execution));
    application_cancelled_result(&execution->last_result);
}

static void application_job_execution_cancel(application_job_execution_t *execution) {
    application_record_cancelled(&execution->last_result, &execution->have_last_result,
                                 execution->last_log);
    execution->unsafe_terminal = true;
}

static application_attempt_decision_t application_consume_attempt(
    cbm_daemon_application_job_t *job, application_attempt_t *attempt,
    application_job_execution_t *execution, cbm_proc_outcome_t *failure_outcome) {
    cbm_mcp_supervised_result_disposition_t disposition =
        application_attempt_disposition(job, attempt);
    application_record_attempt(attempt, &execution->last_result, &execution->have_last_result,
                               execution->last_log);
    if (disposition == CBM_MCP_SUPERVISED_RESULT_SUCCESS) {
        execution->response = attempt->result.response;
        attempt->result.response = NULL;
        execution->successful = execution->response != NULL;
        application_attempt_free(attempt);
        return APPLICATION_ATTEMPT_DECISION_SUCCESS;
    }
    if (disposition == CBM_MCP_SUPERVISED_RESULT_UNSAFE_TERMINAL) {
        execution->unsafe_terminal = true;
        execution->supervision_failed =
            attempt->has_result && !attempt->result.cancellation_requested &&
            (attempt->result.supervision_failed || !attempt->result.tree_quiesced);
        application_attempt_free(attempt);
        return APPLICATION_ATTEMPT_DECISION_STOP;
    }
    if (application_result_is_attributable_failure(attempt, disposition)) {
        *failure_outcome = attempt->result.outcome;
        application_attempt_free(attempt);
        return APPLICATION_ATTEMPT_DECISION_RECOVERABLE;
    }
    application_attempt_free(attempt);
    return APPLICATION_ATTEMPT_DECISION_STOP;
}

static bool application_recovery_record_suspects(
    cbm_daemon_application_job_t *job, const char *marker_path, const char *quarantine_path,
    cbm_proc_outcome_t outcome, int recovery_index, char ***previous_suspects, int *previous_count,
    int *quarantined, application_job_execution_t *execution) {
    int suspect_count = 0;
    bool cancelled = false;
    char **suspects = application_read_suspects(job, marker_path, &suspect_count, &cancelled);
    if (cancelled || application_job_cancel_requested(job)) {
        application_free_suspects(suspects, suspect_count);
        application_job_execution_cancel(execution);
        return false;
    }
    if (!suspects || suspect_count == 0) {
        application_free_suspects(suspects, suspect_count);
        cbm_log_warn("daemon.index.recovery_unattributable", "action", "stop");
        return false;
    }
    if (*previous_suspects) {
        const char *pick = NULL;
        for (int i = 0; i < suspect_count && !pick; i++) {
            if (application_suspect_contains(*previous_suspects, *previous_count, suspects[i])) {
                pick = suspects[i];
            }
        }
        if (!pick) {
            application_free_suspects(suspects, suspect_count);
            cbm_log_warn("daemon.index.recovery_unattributable", "action", "stop");
            return false;
        }
        const char *phase = outcome == CBM_PROC_HANG ? "hang" : "crash";
        if (!application_append_quarantine(quarantine_path, pick, phase)) {
            cbm_log_warn("daemon.index.quarantine_write_fail", "path", pick);
            application_free_suspects(suspects, suspect_count);
            return false;
        }
        (*quarantined)++;
        char attempt_text[APPLICATION_NUMERIC_TEXT_CAP];
        (void)snprintf(attempt_text, sizeof(attempt_text), "%d", recovery_index + 1);
        cbm_log_warn("daemon.index.file_quarantined", "path", pick, "outcome", phase, "attempt",
                     attempt_text);
    }
    application_free_suspects(*previous_suspects, *previous_count);
    *previous_suspects = suspects;
    *previous_count = suspect_count;
    return true;
}

static void application_job_try_partial(cbm_daemon_application_job_t *job,
                                        const char *quarantine_path, int quarantined,
                                        application_job_execution_t *execution) {
    if (application_job_cancel_requested(job)) {
        application_job_execution_cancel(execution);
        return;
    }
    application_attempt_t attempt;
    application_attempt_status_t status =
        application_job_run_attempt(job, NULL, quarantine_path, &attempt);
    if (status == APPLICATION_ATTEMPT_CANCELLED) {
        application_job_execution_cancel(execution);
        return;
    }
    if (status != APPLICATION_ATTEMPT_TERMINAL) {
        return;
    }
    cbm_proc_outcome_t failure_outcome = CBM_PROC_SPAWN_FAILED;
    application_attempt_decision_t decision =
        application_consume_attempt(job, &attempt, execution, &failure_outcome);
    if (decision == APPLICATION_ATTEMPT_DECISION_SUCCESS) {
        char quarantined_text[APPLICATION_NUMERIC_TEXT_CAP];
        (void)snprintf(quarantined_text, sizeof(quarantined_text), "%d", quarantined);
        cbm_log_warn("daemon.index.recovery_partial", "quarantined", quarantined_text);
    }
}

static void application_job_recover(cbm_daemon_application_job_t *job,
                                    application_job_execution_t *execution) {
    if (application_job_cancel_requested(job)) {
        application_job_execution_cancel(execution);
        return;
    }
    char marker_path[APPLICATION_PATH_CAP] = {0};
    char quarantine_path[APPLICATION_PATH_CAP] = {0};
    if (!application_recovery_files_create(marker_path, quarantine_path)) {
        return;
    }

    int quarantined = 0;
    char **previous_suspects = NULL;
    int previous_count = 0;
    int recovery_cap = application_max_restarts();
    for (int recovery_index = 0; recovery_index < recovery_cap; recovery_index++) {
        if (application_job_cancel_requested(job)) {
            application_job_execution_cancel(execution);
            break;
        }
        if (!application_truncate_file(marker_path)) {
            break;
        }
        application_attempt_t attempt;
        application_attempt_status_t status =
            application_job_run_attempt(job, marker_path, quarantine_path, &attempt);
        if (status == APPLICATION_ATTEMPT_CANCELLED) {
            application_job_execution_cancel(execution);
            break;
        }
        if (status != APPLICATION_ATTEMPT_TERMINAL) {
            break;
        }
        cbm_proc_outcome_t failure_outcome = CBM_PROC_SPAWN_FAILED;
        application_attempt_decision_t decision =
            application_consume_attempt(job, &attempt, execution, &failure_outcome);
        if (decision != APPLICATION_ATTEMPT_DECISION_RECOVERABLE ||
            !application_recovery_record_suspects(
                job, marker_path, quarantine_path, failure_outcome, recovery_index,
                &previous_suspects, &previous_count, &quarantined, execution)) {
            break;
        }
    }
    application_free_suspects(previous_suspects, previous_count);
    if (!execution->response && !execution->unsafe_terminal && quarantined > 0) {
        application_job_try_partial(job, quarantine_path, quarantined, execution);
    }
    application_recovery_files_remove(marker_path, quarantine_path);
}

/* A capacity/cancellation conflict is resolved by the terminal publication
 * that freed the project or global slot. Admit waiting session auto-index work
 * at that same boundary so an otherwise-idle MCP session does not need to send
 * another request merely to make background progress. Caller holds mutex. */
static void application_auto_index_retry_pending_locked(cbm_daemon_application_t *application) {
    if (application->stopping) {
        return;
    }
    for (cbm_daemon_application_session_t *session = application->sessions; session;
         session = session->next) {
        if (!session->auto_index_retry_pending || session->auto_index_subscribed ||
            session->session_cancelled || !session->context_set) {
            continue;
        }
        const char *project = cbm_mcp_server_session_project(session->mcp);
        const char *root_path = cbm_mcp_server_session_root(session->mcp);
        if (!project || !project[0] || !root_path || !root_path[0]) {
            session->auto_index_retry_pending = false;
            continue;
        }
        if (application_regular_db_exists(project)) {
            session->auto_index_retry_pending = false;
            application_refresh_watch_locked(session);
            continue;
        }
        char *args = application_auto_index_args(root_path);
        if (!args) {
            continue;
        }
        application_job_subscribe_status_t subscribe_status = APPLICATION_JOB_SUBSCRIBE_UNAVAILABLE;
        cbm_daemon_application_job_t *retry = application_job_subscribe_locked(
            application, project, root_path, args, &subscribe_status);
        free(args);
        if (retry) {
            session->auto_index_job = retry;
            session->auto_index_subscribed = true;
            session->auto_index_retry_pending = false;
            cbm_log_info("daemon.autoindex.admission_retried", "project", project);
            continue;
        }
        if (subscribe_status == APPLICATION_JOB_SUBSCRIBE_BUSY) {
            /* No further distinct job can fit until another terminal publish. */
            break;
        }
    }
}

static void application_job_publish(cbm_daemon_application_job_t *job,
                                    application_job_execution_t *execution) {
    if (!execution->response) {
        execution->response = application_job_failure_response(
            execution->have_last_result ? &execution->last_result : NULL,
            execution->last_log[0] ? execution->last_log : NULL);
    }
    cbm_daemon_application_t *application = job->application;
    cbm_mutex_lock(&application->mutex);
    job->response = execution->response;
    job->successful = execution->successful;
    job->cancelled = execution->have_last_result && execution->last_result.cancellation_requested;
    job->supervision_failed = execution->supervision_failed ||
                              (execution->unsafe_terminal && execution->have_last_result &&
                               !execution->last_result.cancellation_requested);
    job->terminal = true;
    job->thread_done = true;
    for (cbm_daemon_application_session_t *session = application->sessions; session;
         session = session->next) {
        if (session->auto_index_job != job || !session->auto_index_subscribed) {
            continue;
        }
        session->auto_index_job = NULL;
        session->auto_index_subscribed = false;
        application_job_unsubscribe_locked(job);
        if (job->successful) {
            application_refresh_watch_locked(session);
        }
    }
    application_auto_index_retry_pending_locked(application);
    cbm_mutex_unlock(&application->mutex);
}

static void *application_job_thread(void *opaque) {
    cbm_daemon_application_job_t *job = opaque;
    application_job_execution_t execution;
    application_job_execution_init(&execution);
    /* Deterministic-interleaving seam: a held gate parks this thread before
     * its first pre-start cancel check, so tests can force the
     * cancel-wins-before-worker-start ordering that otherwise needs a
     * descheduled thread on a loaded runner (CI is never a lottery: the
     * interleaving must be reproducible by construction). */
    while (
        atomic_load_explicit(&g_application_hold_job_before_start_for_test, memory_order_acquire)) {
        cbm_usleep(1000);
    }

    /* The linked non-terminal job is the daemon-internal reservation: it
     * coalesces identical requests and blocks same-project daemon mutations.
     * The physical worker is the sole owner of the cross-process project lock,
     * so the daemon must not pre-acquire that same native lease here. */
    if (!application_job_wait_for_mutations(job)) {
        application_job_execution_cancel(&execution);
    } else {
        application_attempt_t attempt;
        application_attempt_status_t status =
            application_job_run_attempt(job, NULL, NULL, &attempt);
        if (status == APPLICATION_ATTEMPT_CANCELLED) {
            application_job_execution_cancel(&execution);
        } else if (status == APPLICATION_ATTEMPT_TERMINAL) {
            cbm_proc_outcome_t failure_outcome = CBM_PROC_SPAWN_FAILED;
            application_attempt_decision_t decision =
                application_consume_attempt(job, &attempt, &execution, &failure_outcome);
            if (decision == APPLICATION_ATTEMPT_DECISION_RECOVERABLE) {
                application_job_recover(job, &execution);
            }
        }
    }
    application_job_publish(job, &execution);
    return NULL;
}

static cbm_daemon_application_job_t *application_find_job_locked(
    cbm_daemon_application_t *application, const char *project_key) {
    for (cbm_daemon_application_job_t *job = application->jobs; job; job = job->next) {
        if (strcmp(job->project_key, project_key) == 0) {
            return job;
        }
    }
    return NULL;
}

/* Terminal jobs may remain linked while their original waiters copy the
 * published response. They are immutable history, not coalescing targets for
 * a later request of the same project. */
static cbm_daemon_application_job_t *application_find_active_job_locked(
    cbm_daemon_application_t *application, const char *project_key) {
    for (cbm_daemon_application_job_t *job = application->jobs; job; job = job->next) {
        if (!job->terminal && strcmp(job->project_key, project_key) == 0) {
            return job;
        }
    }
    return NULL;
}

static char *application_index_project_key(const char *root_path, const char *args_json) {
    char *override = cbm_mcp_get_string_arg(args_json, "name");
    char *key = cbm_project_name_from_path(override && override[0] ? override : root_path);
    free(override);
    return key;
}

static size_t application_active_job_count_locked(cbm_daemon_application_t *application) {
    size_t count = 0;
    for (cbm_daemon_application_job_t *job = application->jobs; job; job = job->next) {
        if (!job->terminal) {
            count++;
        }
    }
    return count;
}

/* Compare the effective index request, not its JSON spelling. yyjson's deep
 * equality treats object member order as insignificant, while the small
 * normalization below removes values that the index handler interprets as
 * its defaults. Arrays remain order-sensitive and all non-default options are
 * preserved. */
static bool application_index_args_normalize_defaults(yyjson_mut_val *root) {
    if (!root || !yyjson_mut_is_obj(root)) {
        return false;
    }
    yyjson_mut_val *mode = yyjson_mut_obj_get(root, "mode");
    if (mode && (!yyjson_mut_is_str(mode) || yyjson_mut_equals_str(mode, "full"))) {
        (void)yyjson_mut_obj_remove_key(root, "mode");
    }
    yyjson_mut_val *persistence = yyjson_mut_obj_get(root, "persistence");
    if (persistence && (!yyjson_mut_is_bool(persistence) || !yyjson_mut_get_bool(persistence))) {
        (void)yyjson_mut_obj_remove_key(root, "persistence");
    }
    yyjson_mut_val *name = yyjson_mut_obj_get(root, "name");
    if (name && (!yyjson_mut_is_str(name) || yyjson_mut_get_len(name) == 0)) {
        (void)yyjson_mut_obj_remove_key(root, "name");
    }
    return true;
}

static bool application_index_args_equal(const char *left, const char *right) {
    if (!left || !right) {
        return false;
    }
    yyjson_doc *left_source = yyjson_read(left, strlen(left), 0);
    yyjson_doc *right_source = yyjson_read(right, strlen(right), 0);
    yyjson_mut_doc *left_copy = left_source ? yyjson_doc_mut_copy(left_source, NULL) : NULL;
    yyjson_mut_doc *right_copy = right_source ? yyjson_doc_mut_copy(right_source, NULL) : NULL;
    yyjson_mut_val *left_root = left_copy ? yyjson_mut_doc_get_root(left_copy) : NULL;
    yyjson_mut_val *right_root = right_copy ? yyjson_mut_doc_get_root(right_copy) : NULL;
    bool equal = application_index_args_normalize_defaults(left_root) &&
                 application_index_args_normalize_defaults(right_root) &&
                 yyjson_mut_equals(left_root, right_root);
    yyjson_mut_doc_free(left_copy);
    yyjson_mut_doc_free(right_copy);
    yyjson_doc_free(left_source);
    yyjson_doc_free(right_source);
    return equal;
}

/* Caller holds application->mutex. Keeping watcher ownership validation and
 * this admission in the same critical section closes the unwatch race. */
static cbm_daemon_application_job_t *application_job_subscribe_locked(
    cbm_daemon_application_t *application, const char *project_key, const char *root_path,
    const char *args_json, application_job_subscribe_status_t *status_out) {
    *status_out = APPLICATION_JOB_SUBSCRIBE_UNAVAILABLE;
    if (application->stopping) {
        return NULL;
    }
    cbm_daemon_application_job_t *job =
        application_find_active_job_locked(application, project_key);
    if (job) {
        if (job->cancel_requested) {
            *status_out = APPLICATION_JOB_SUBSCRIBE_CANCELLING;
            return NULL;
        }
        if (!application_index_args_equal(job->args_json, args_json)) {
            *status_out = APPLICATION_JOB_SUBSCRIBE_OPTIONS_CONFLICT;
            return NULL;
        }
        job->subscribers++;
        *status_out = APPLICATION_JOB_SUBSCRIBE_OK;
        return job;
    }

    if (application_active_job_count_locked(application) >= application->physical_job_limit) {
        char limit[APPLICATION_NUMERIC_TEXT_CAP];
        (void)snprintf(limit, sizeof(limit), "%zu", application->physical_job_limit);
        cbm_log_warn("daemon.index.admission_busy", "limit", limit, "project", project_key);
        *status_out = APPLICATION_JOB_SUBSCRIBE_BUSY;
        return NULL;
    }

    job = calloc(APPLICATION_ALLOCATION_ELEMENTS_ONE, sizeof(*job));
    if (job) {
        job->project_key = strdup(project_key);
        job->root_path = strdup(root_path);
        job->args_json = strdup(args_json);
    }
    if (!job || !job->project_key || !job->root_path || !job->args_json) {
        application_job_free(job);
        *status_out = APPLICATION_JOB_SUBSCRIBE_ALLOCATION_FAILED;
        return NULL;
    }
    job->application = application;
    job->subscribers = APPLICATION_COUNT_ONE;
    job->next = application->jobs;
    application->jobs = job;
    if (application_job_thread_create(&job->thread, job) == 0) {
        job->thread_started = true;
    } else {
        /* The job was linked only so a concurrently started thread could
         * observe its reservation. No thread exists on this path, so roll the
         * reservation back synchronously and let background callers retry. */
        application->jobs = job->next;
        job->next = NULL;
        application_job_free(job);
        *status_out = APPLICATION_JOB_SUBSCRIBE_UNAVAILABLE;
        cbm_log_warn("daemon.index.thread_start_failed", "action", "retry");
        return NULL;
    }
    *status_out = APPLICATION_JOB_SUBSCRIBE_OK;
    return job;
}

static cbm_daemon_application_job_t *application_job_subscribe(
    cbm_daemon_application_t *application, const char *project_key, const char *root_path,
    const char *args_json, application_job_subscribe_status_t *status_out) {
    application_jobs_reap_completed(application);
    cbm_mutex_lock(&application->mutex);
    cbm_daemon_application_job_t *job = application_job_subscribe_locked(
        application, project_key, root_path, args_json, status_out);
    cbm_mutex_unlock(&application->mutex);
    return job;
}

static void application_job_unsubscribe_locked(cbm_daemon_application_job_t *job) {
    if (!job || job->subscribers == 0) {
        return;
    }
    job->subscribers--;
    if (job->subscribers == 0 && !job->terminal) {
        job->cancel_requested = true;
    }
}

/* Transfer a final session's subscription to the disconnect cleanup path so
 * the job cannot be reaped before that path has observed terminal containment.
 * Non-final subscriptions detach immediately and leave the shared worker live. */
static cbm_daemon_application_job_t *application_auto_index_release_locked(
    cbm_daemon_application_session_t *session) {
    if (!session || !session->auto_index_job || !session->auto_index_subscribed) {
        return NULL;
    }
    cbm_daemon_application_job_t *job = session->auto_index_job;
    session->auto_index_job = NULL;
    session->auto_index_subscribed = false;
    if (!job->terminal && job->subscribers == APPLICATION_COUNT_ONE) {
        job->cancel_requested = true;
        return job;
    }
    application_job_unsubscribe_locked(job);
    return NULL;
}

static void application_auto_index_cancel_join(cbm_daemon_application_t *application,
                                               cbm_daemon_application_job_t *job) {
    if (!application || !job) {
        return;
    }
    uint64_t deadline = application_deadline_after(APPLICATION_BACKGROUND_REAP_MS);
    for (;;) {
        cbm_mutex_lock(&application->mutex);
        bool terminal = job->terminal && job->thread_done;
        if (terminal) {
            application_job_unsubscribe_locked(job);
        }
        cbm_mutex_unlock(&application->mutex);
        if (terminal) {
            application_jobs_reap_completed(application);
            return;
        }
        if (cbm_now_ms() >= deadline) {
            application_cleanup_force_terminate("auto_index_cleanup");
        }
        cbm_usleep(APPLICATION_JOB_POLL_US);
    }
}

static void application_update_cancel_locked(cbm_daemon_application_t *application) {
    if (!application->update_generation_started || application->update_thread_done) {
        return;
    }
    application->update_cancel_requested = true;
    if (application->update_worker) {
        (void)application->update_ops.cancel(application->update_ops.context,
                                             application->update_worker);
    }
}

static bool application_update_owner_release_locked(cbm_daemon_application_session_t *session) {
    if (!session || !session->update_owner) {
        return false;
    }
    cbm_daemon_application_t *application = session->application;
    session->update_owner = false;
    if (application->update_owners > 0) {
        application->update_owners--;
    }
    if (application->update_owners == 0) {
        application_update_cancel_locked(application);
        return application->update_thread_started;
    }
    return false;
}

static bool application_update_version_valid(const char *version) {
    if (!version || !version[0] || strlen(version) >= APPLICATION_UPDATE_VERSION_CAP) {
        return false;
    }
    for (const unsigned char *cursor = (const unsigned char *)version; *cursor; cursor++) {
        if (!(isalnum(*cursor) || *cursor == '.' || *cursor == '-' || *cursor == '_' ||
              *cursor == '+')) {
            return false;
        }
    }
    return true;
}

static void application_update_publish_terminal_locked(cbm_daemon_application_t *application,
                                                       const char *latest_version,
                                                       bool completed_generation) {
    if (!application->update_cancel_requested && application_update_version_valid(latest_version) &&
        cbm_compare_versions(latest_version, cbm_build_version_get()) > 0) {
        (void)snprintf(application->update_notice, sizeof(application->update_notice),
                       "Update available: %s -> %s -- run: codebase-memory-mcp update  |  "
                       "Enjoying codebase-memory-mcp? Please leave a star: "
                       "https://github.com/DeusData/codebase-memory-mcp",
                       cbm_build_version_get(), latest_version);
        cbm_log_info("update.available", "current", cbm_build_version_get(), "latest",
                     latest_version);
    }
    for (cbm_daemon_application_session_t *session = application->sessions; session;
         session = session->next) {
        session->update_owner = false;
    }
    application->update_owners = 0;
    application->update_worker = NULL;
    /* A clean/poll-terminal generation is immutable daemon history and is
     * replayed to late sessions. Cancellation and worker-start failure did
     * not perform a check, so they release the generation slot for retry once
     * this thread has been joined. */
    application->update_generation_started = completed_generation;
    application->update_thread_done = true;
    application_auto_index_retry_pending_locked(application);
}

static void *application_update_thread(void *opaque) {
    cbm_daemon_application_t *application = opaque;
    cbm_daemon_application_update_worker_t worker = NULL;
    if (application->update_ops.start(application->update_ops.context, &worker) != 0 || !worker) {
        cbm_mutex_lock(&application->mutex);
        application_update_publish_terminal_locked(application, NULL, false);
        cbm_mutex_unlock(&application->mutex);
        return NULL;
    }

    cbm_mutex_lock(&application->mutex);
    application->update_worker = worker;
    if (application->update_cancel_requested || application->stopping ||
        application->update_owners == 0) {
        application_update_cancel_locked(application);
    }
    cbm_mutex_unlock(&application->mutex);

    const char *latest_version = NULL;
    for (;;) {
        cbm_daemon_application_update_poll_t status =
            application->update_ops.poll(application->update_ops.context, worker, &latest_version);
        if (status != CBM_DAEMON_APPLICATION_UPDATE_POLL_RUNNING) {
            if (status == CBM_DAEMON_APPLICATION_UPDATE_POLL_ERROR) {
                latest_version = NULL;
            }
            break;
        }
        cbm_mutex_lock(&application->mutex);
        if (application->update_cancel_requested || application->stopping ||
            application->update_owners == 0) {
            application_update_cancel_locked(application);
        }
        cbm_mutex_unlock(&application->mutex);
        cbm_usleep(APPLICATION_UPDATE_POLL_US);
    }

    char version[APPLICATION_UPDATE_VERSION_CAP] = {0};
    if (latest_version && strlen(latest_version) < sizeof(version)) {
        (void)snprintf(version, sizeof(version), "%s", latest_version);
    }
    cbm_mutex_lock(&application->mutex);
    bool completed_generation = !application->update_cancel_requested && !application->stopping &&
                                application->update_owners > 0;
    application_update_publish_terminal_locked(application, version[0] ? version : NULL,
                                               completed_generation);
    cbm_mutex_unlock(&application->mutex);
    application->update_ops.destroy(application->update_ops.context, worker);
    return NULL;
}

static void application_update_subscribe_locked(cbm_daemon_application_session_t *session) {
    cbm_daemon_application_t *application = session->application;
    /* No provider, no generation. This is what makes "the daemon performs no
     * network request by default" a structural property rather than a promise:
     * with update_ops empty nothing is ever started, so no session can observe
     * a generation, become its owner, or wait on it. */
    if (!application->update_ops.start) {
        return;
    }
    if (application->update_generation_started) {
        if (application->update_thread_started && !application->update_thread_done &&
            !application->update_cancel_requested && !session->update_owner) {
            session->update_owner = true;
            application->update_owners++;
        }
        return;
    }
    /* A retryable generation may already be terminal but not yet joined. The
     * owning thread handle cannot be overwritten; the next request retries
     * after application_update_reap() clears it. */
    if (application->update_thread_started) {
        return;
    }
    application->update_generation_started = true;
    application->update_thread_done = false;
    application->update_cancel_requested = false;
    session->update_owner = true;
    application->update_owners = APPLICATION_COUNT_ONE;
    if (cbm_thread_create(&application->update_thread, APPLICATION_JOB_THREAD_STACK,
                          application_update_thread, application) == 0) {
        application->update_thread_started = true;
        return;
    }
    session->update_owner = false;
    application->update_owners = 0;
    application->update_generation_started = false;
    application->update_thread_done = false;
    cbm_log_warn("daemon.update.thread_start_failed", "action", "retry");
}

static bool application_update_reap(cbm_daemon_application_t *application, bool wait,
                                    uint32_t timeout_ms) {
    if (!application) {
        return false;
    }
    uint64_t deadline = application_deadline_after(timeout_ms);
    for (;;) {
        bool join = false;
        cbm_mutex_lock(&application->mutex);
        if (!application->update_thread_started) {
            cbm_mutex_unlock(&application->mutex);
            return true;
        }
        if (application->update_thread_done && !application->update_thread_joining) {
            application->update_thread_joining = true;
            join = true;
        }
        cbm_mutex_unlock(&application->mutex);
        if (join) {
            bool joined = cbm_thread_join(&application->update_thread) == 0;
            cbm_mutex_lock(&application->mutex);
            if (joined) {
                application->update_thread_started = false;
            }
            application->update_thread_joining = false;
            cbm_mutex_unlock(&application->mutex);
            return joined;
        }
        if (!wait || cbm_now_ms() >= deadline) {
            return false;
        }
        cbm_usleep(APPLICATION_UPDATE_POLL_US);
    }
}

static char *application_auto_index_args(const char *root_path) {
    yyjson_mut_doc *document = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = document ? yyjson_mut_obj(document) : NULL;
    if (!document || !root) {
        yyjson_mut_doc_free(document);
        return NULL;
    }
    yyjson_mut_doc_set_root(document, root);
    char *args = yyjson_mut_obj_add_strcpy(document, root, "repo_path", root_path)
                     ? yyjson_mut_write(document, 0, NULL)
                     : NULL;
    yyjson_mut_doc_free(document);
    return args;
}

static char *application_auto_index_prepare(cbm_daemon_application_t *application,
                                            const char *project, const char *root_path,
                                            bool *args_required) {
    bool database_exists = application_regular_db_exists(project);
    bool enabled = application->config &&
                   cbm_config_get_bool(application->config, CBM_CONFIG_AUTO_INDEX, false);
    int limit = application->config
                    ? cbm_config_get_int(application->config, CBM_CONFIG_AUTO_INDEX_LIMIT,
                                         CBM_MCP_DEFAULT_AUTO_INDEX_LIMIT)
                    : CBM_MCP_DEFAULT_AUTO_INDEX_LIMIT;
    bool candidate = enabled && !database_exists;
    int tracked_files = APPLICATION_RESULT_FAILURE;
    bool within_limit =
        !candidate || cbm_mcp_auto_index_within_file_limit(root_path, limit, &tracked_files);
    if (candidate && !within_limit) {
        char files[APPLICATION_NUMERIC_TEXT_CAP];
        (void)snprintf(files, sizeof(files), "%d", tracked_files);
        cbm_log_warn("daemon.autoindex.skipped", "project", project, "reason",
                     tracked_files >= 0 ? "too_many_files" : "unsafe_or_unavailable_path", "files",
                     files);
    }
    *args_required = candidate && within_limit;
    return *args_required ? application_auto_index_args(root_path) : NULL;
}

static void application_background_initialize_impl(cbm_daemon_application_session_t *session) {
    if (!session || !session->application || !session->context_set ||
        session->tool_profile != CBM_MCP_TOOL_PROFILE_ALL || session->hook_event ||
        session->hook_dialect) {
        return;
    }
    cbm_daemon_application_t *application = session->application;
    const char *project = cbm_mcp_server_session_project(session->mcp);
    const char *root_path = cbm_mcp_server_session_root(session->mcp);
    if (!project || !project[0] || !root_path || !root_path[0]) {
        return;
    }
    /* Join a terminal retryable update generation before reusing its single
     * thread slot. This is non-blocking unless the thread already published
     * terminal state. */
    (void)application_update_reap(application, false, 0);
    bool args_required = false;
    char *args = application_auto_index_prepare(application, project, root_path, &args_required);
    application_jobs_reap_completed(application);
    cbm_mutex_lock(&application->mutex);
    if (application->stopping || application_request_cancelled_locked(session)) {
        cbm_mutex_unlock(&application->mutex);
        free(args);
        return;
    }
    session->background_eligible = true;
    application_update_subscribe_locked(session);
    bool attempt_auto_index = !session->auto_index_subscribed &&
                              (!session->auto_index_evaluated || session->auto_index_retry_pending);
    if (attempt_auto_index) {
        session->auto_index_evaluated = true;
        session->auto_index_retry_pending = false;
    }
    if (attempt_auto_index && args) {
        application_job_subscribe_status_t subscribe_status = APPLICATION_JOB_SUBSCRIBE_UNAVAILABLE;
        cbm_daemon_application_job_t *job = application_job_subscribe_locked(
            application, project, root_path, args, &subscribe_status);
        if (job) {
            session->auto_index_job = job;
            session->auto_index_subscribed = true;
        } else {
            session->auto_index_retry_pending =
                subscribe_status == APPLICATION_JOB_SUBSCRIBE_BUSY ||
                subscribe_status == APPLICATION_JOB_SUBSCRIBE_CANCELLING ||
                subscribe_status == APPLICATION_JOB_SUBSCRIBE_OPTIONS_CONFLICT ||
                subscribe_status == APPLICATION_JOB_SUBSCRIBE_UNAVAILABLE ||
                subscribe_status == APPLICATION_JOB_SUBSCRIBE_ALLOCATION_FAILED;
            cbm_log_warn("daemon.autoindex.admission_failed", "project", project, "action",
                         session->auto_index_retry_pending ? "retry" : "skip");
        }
    } else if (attempt_auto_index && args_required && !args) {
        /* JSON allocation is a transient resource failure, not a permanent
         * policy decision. Retry at the next coordinator opportunity. */
        session->auto_index_retry_pending = true;
    }
    cbm_mutex_unlock(&application->mutex);
    free(args);
    application_refresh_watch(session);
}

static void application_background_initialize(cbm_daemon_application_session_t *session) {
    application_background_initialize_impl(session);
    atomic_fetch_add_explicit(&g_application_background_initializes_for_test, APPLICATION_COUNT_ONE,
                              memory_order_release);
}

static bool application_jsonrpc_success(const char *response) {
    yyjson_doc *document = response ? yyjson_read(response, strlen(response), 0) : NULL;
    yyjson_val *root = document ? yyjson_doc_get_root(document) : NULL;
    bool success = yyjson_is_obj(root) && yyjson_obj_get(root, "result") != NULL &&
                   yyjson_obj_get(root, "error") == NULL;
    yyjson_doc_free(document);
    return success;
}

static void application_update_notice_inject(cbm_daemon_application_session_t *session,
                                             char **response_io) {
    cbm_daemon_application_t *application = session->application;
    cbm_mutex_lock(&application->mutex);
    if (session->background_eligible && !session->update_notice_delivered &&
        !session->pending_update_notice && application->update_thread_done &&
        application->update_notice[0] &&
        cbm_mcp_jsonrpc_response_prepend_notice(response_io, application->update_notice)) {
        session->pending_update_notice = true;
    }
    cbm_mutex_unlock(&application->mutex);
}

static bool application_watch_job_subscription_exists_locked(
    cbm_daemon_application_t *application, cbm_daemon_application_session_t *session,
    cbm_daemon_application_job_t *job) {
    for (cbm_daemon_application_watch_job_subscription_t *subscription =
             application->watch_job_subscriptions;
         subscription; subscription = subscription->next) {
        if (subscription->session == session && subscription->job == job) {
            return true;
        }
    }
    return false;
}

/* Attach a newly registered logical watch to a watcher callback that was
 * already admitted for the same project/root. Without this step, closing the
 * pre-existing owners can cancel the physical worker while this late session
 * still expects the shared watch to remain live. Caller holds the mutex. */
static bool application_watch_job_subscribe_late_session_locked(
    cbm_daemon_application_session_t *session, cbm_daemon_application_watch_t *watch) {
    if (!session || !watch || !session->application) {
        return false;
    }
    cbm_daemon_application_t *application = session->application;
    cbm_daemon_application_job_t *job =
        application_find_active_job_locked(application, watch->project);
    if (!job || job->watcher_waiters == 0 || strcmp(job->root_path, watch->root) != 0 ||
        application_watch_job_subscription_exists_locked(application, session, job)) {
        return true;
    }
    cbm_daemon_application_watch_job_subscription_t *subscription =
        calloc(APPLICATION_ALLOCATION_ELEMENTS_ONE, sizeof(*subscription));
    if (!subscription) {
        return false;
    }
    subscription->session = session;
    subscription->job = job;
    subscription->next = application->watch_job_subscriptions;
    application->watch_job_subscriptions = subscription;
    job->subscribers++;
    return true;
}

/* Caller holds application->mutex. Allocate the complete change before
 * publishing any node so an allocation failure never leaves only a subset of
 * the exact live watch owners subscribed. */
static bool application_watch_job_subscribe_sessions_locked(cbm_daemon_application_t *application,
                                                            cbm_daemon_application_watch_t *watch,
                                                            cbm_daemon_application_job_t *job,
                                                            size_t *matched_out) {
    *matched_out = 0;
    if (!watch || !job || strcmp(watch->project, job->project_key) != 0 ||
        strcmp(watch->root, job->root_path) != 0) {
        return true;
    }

    cbm_daemon_application_watch_job_subscription_t *pending = NULL;
    for (cbm_daemon_application_session_t *session = application->sessions; session;
         session = session->next) {
        if (session->session_cancelled || !session->context_set || session->watch != watch) {
            continue;
        }
        (*matched_out)++;
        if (application_watch_job_subscription_exists_locked(application, session, job)) {
            continue;
        }
        cbm_daemon_application_watch_job_subscription_t *subscription =
            calloc(APPLICATION_ALLOCATION_ELEMENTS_ONE, sizeof(*subscription));
        if (!subscription) {
            while (pending) {
                cbm_daemon_application_watch_job_subscription_t *next = pending->next;
                free(pending);
                pending = next;
            }
            return false;
        }
        subscription->session = session;
        subscription->job = job;
        subscription->next = pending;
        pending = subscription;
    }

    while (pending) {
        cbm_daemon_application_watch_job_subscription_t *subscription = pending;
        pending = pending->next;
        subscription->next = application->watch_job_subscriptions;
        application->watch_job_subscriptions = subscription;
        job->subscribers++;
    }
    return true;
}

static void application_watch_job_unsubscribe_session_locked(
    cbm_daemon_application_session_t *session) {
    if (!session || !session->application) {
        return;
    }
    cbm_daemon_application_watch_job_subscription_t **cursor =
        &session->application->watch_job_subscriptions;
    while (*cursor) {
        cbm_daemon_application_watch_job_subscription_t *subscription = *cursor;
        if (subscription->session != session) {
            cursor = &subscription->next;
            continue;
        }
        *cursor = subscription->next;
        application_job_unsubscribe_locked(subscription->job);
        free(subscription);
    }
}

static void application_watch_job_unsubscribe_job_locked(cbm_daemon_application_t *application,
                                                         cbm_daemon_application_job_t *job) {
    cbm_daemon_application_watch_job_subscription_t **cursor =
        &application->watch_job_subscriptions;
    while (*cursor) {
        cbm_daemon_application_watch_job_subscription_t *subscription = *cursor;
        if (subscription->job != job) {
            cursor = &subscription->next;
            continue;
        }
        *cursor = subscription->next;
        application_job_unsubscribe_locked(job);
        free(subscription);
    }
}

static char *application_job_wait_for_session(cbm_daemon_application_session_t *session,
                                              cbm_daemon_application_job_t *job) {
    cbm_daemon_application_t *application = session->application;
    for (;;) {
        cbm_mutex_lock(&application->mutex);
        if (session->active_job != job || !session->active_job_subscribed) {
            cbm_mutex_unlock(&application->mutex);
            return cbm_mcp_text_result("index operation cancelled for this session", true);
        }
        if (job->terminal) {
            char *response = job->response ? strdup(job->response) : NULL;
            session->active_job = NULL;
            session->active_job_subscribed = false;
            application_job_unsubscribe_locked(job);
            cbm_mutex_unlock(&application->mutex);
            application_jobs_reap_completed(application);
            return response ? response
                            : cbm_mcp_text_result("index coordinator lost its result", true);
        }
        cbm_mutex_unlock(&application->mutex);
        cbm_usleep(APPLICATION_JOB_POLL_US);
    }
}

static char *application_index_execute(void *context, const char *root_path,
                                       const char *args_json) {
    cbm_daemon_application_session_t *session = context;
    if (!session || !root_path || !args_json) {
        return NULL;
    }
    char *project_key = application_index_project_key(root_path, args_json);
    if (!project_key) {
        return cbm_mcp_text_result("failed to derive index project identity", true);
    }
    application_job_subscribe_status_t subscribe_status = APPLICATION_JOB_SUBSCRIBE_UNAVAILABLE;
    cbm_daemon_application_job_t *job = NULL;
    for (;;) {
        job = application_job_subscribe(session->application, project_key, root_path, args_json,
                                        &subscribe_status);
        if (job || (subscribe_status != APPLICATION_JOB_SUBSCRIBE_BUSY &&
                    subscribe_status != APPLICATION_JOB_SUBSCRIBE_CANCELLING)) {
            break;
        }
        /* Physical job limit reached (or a same-project cancel still
         * draining): QUEUE instead of surfacing a raw busy error. The
         * request thread blocks for the whole index anyway, so waiting for
         * a slot is the same contract — and the wait stays cancellable and
         * shutdown-aware (a stopping coordinator answers UNAVAILABLE, which
         * exits this loop with the error below). */
        atomic_fetch_add_explicit(&g_application_busy_queue_waits_for_test, APPLICATION_COUNT_ONE,
                                  memory_order_release);
        cbm_mutex_lock(&session->application->mutex);
        bool queued_cancelled = application_request_cancelled_locked(session);
        cbm_mutex_unlock(&session->application->mutex);
        if (queued_cancelled) {
            free(project_key);
            return cbm_mcp_text_result("index operation cancelled for this session", true);
        }
        cbm_usleep(APPLICATION_JOB_POLL_US);
    }
    free(project_key);
    if (!job) {
        const char *message = "daemon index coordinator is stopping or unavailable";
        if (subscribe_status == APPLICATION_JOB_SUBSCRIBE_OPTIONS_CONFLICT) {
            message = "another index operation for this project is active with different options";
        } else if (subscribe_status == APPLICATION_JOB_SUBSCRIBE_ALLOCATION_FAILED) {
            message = "daemon index coordinator could not allocate an index job";
        }
        return cbm_mcp_text_result(message, true);
    }
    cbm_mutex_lock(&session->application->mutex);
    if (application_request_cancelled_locked(session)) {
        application_job_unsubscribe_locked(job);
        cbm_mutex_unlock(&session->application->mutex);
        return cbm_mcp_text_result("index operation cancelled for this session", true);
    }
    if (session->active_job) {
        application_job_unsubscribe_locked(job);
        cbm_mutex_unlock(&session->application->mutex);
        return cbm_mcp_text_result("this session already has an active index operation", true);
    }
    session->active_job = job;
    session->active_job_subscribed = true;
    cbm_mutex_unlock(&session->application->mutex);
    return application_job_wait_for_session(session, job);
}

static cbm_daemon_runtime_application_session_t *application_session_open(
    void *context, cbm_daemon_client_id_t client_id, uint64_t authenticated_process_id) {
    cbm_daemon_application_t *application = context;
    if (!application || client_id == CBM_DAEMON_CLIENT_ID_INVALID ||
        authenticated_process_id == 0) {
        return NULL;
    }
    cbm_daemon_application_session_t *session =
        calloc(APPLICATION_ALLOCATION_ELEMENTS_ONE, sizeof(*session));
    if (!session) {
        return NULL;
    }
    session->mcp = cbm_mcp_server_new(NULL);
    if (!session->mcp || !cbm_mcp_server_release_pristine_memory_store(session->mcp)) {
        cbm_mcp_server_free(session->mcp);
        free(session);
        return NULL;
    }
    cbm_mcp_server_set_background_tasks(session->mcp, false);
    cbm_mcp_server_set_config(session->mcp, application->config);
    cbm_mcp_server_set_index_executor(session->mcp, application_index_execute, session);
    cbm_mcp_server_set_project_mutation_guard(session->mcp, application_session_mutation_begin,
                                              application_session_mutation_end, session);
    cbm_mcp_server_set_project_mutation_try_guard(session->mcp,
                                                  application_session_mutation_try_begin);
    session->tool_profile = CBM_MCP_TOOL_PROFILE_ALL;
    session->application = application;
    session->client_id = client_id;
    session->authenticated_process_id = authenticated_process_id;

    cbm_mutex_lock(&application->mutex);
    if (application->stopping) {
        cbm_mutex_unlock(&application->mutex);
        cbm_mcp_server_free(session->mcp);
        free(session);
        return NULL;
    }
    session->next = application->sessions;
    application->sessions = session;
    cbm_mutex_unlock(&application->mutex);
    return (cbm_daemon_runtime_application_session_t *)session;
}

static cbm_daemon_runtime_application_status_t application_set_context(
    cbm_daemon_application_session_t *session, const uint8_t *request, uint32_t request_length) {
    if (session->context_set || request_length < APPLICATION_CONTEXT_HEADER_SIZE) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    uint32_t root_length = application_get_u32(request + APPLICATION_CONTEXT_ROOT_LENGTH_OFFSET);
    bool allowed_present =
        request[APPLICATION_CONTEXT_ALLOWED_PRESENT_OFFSET] == APPLICATION_PROTOCOL_TRUE;
    uint32_t allowed_length =
        application_get_u32(request + APPLICATION_CONTEXT_ALLOWED_LENGTH_OFFSET);
    uint8_t profile_value = request[APPLICATION_CONTEXT_PROFILE_OFFSET];
    uint32_t event_length = application_get_u32(request + APPLICATION_CONTEXT_EVENT_LENGTH_OFFSET);
    uint32_t dialect_length =
        application_get_u32(request + APPLICATION_CONTEXT_DIALECT_LENGTH_OFFSET);
    uint64_t expected = (uint64_t)APPLICATION_CONTEXT_HEADER_SIZE + root_length + allowed_length +
                        event_length + dialect_length;
    if (request[APPLICATION_CONTEXT_ALLOWED_PRESENT_OFFSET] > APPLICATION_PROTOCOL_TRUE ||
        root_length == 0 || expected != request_length ||
        (!allowed_present && allowed_length != 0) ||
        profile_value > (uint8_t)CBM_MCP_TOOL_PROFILE_SCOUT ||
        (profile_value != (uint8_t)CBM_MCP_TOOL_PROFILE_ALL &&
         (event_length != 0 || dialect_length != 0))) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    cbm_mcp_tool_profile_t tool_profile = (cbm_mcp_tool_profile_t)profile_value;
    const uint8_t *payload = request + APPLICATION_CONTEXT_HEADER_SIZE;
    char *root = application_text_copy(request + APPLICATION_CONTEXT_HEADER_SIZE, root_length);
    char *allowed =
        allowed_present ? application_text_copy(payload + root_length, allowed_length) : NULL;
    char *hook_event =
        event_length ? application_text_copy(payload + root_length + allowed_length, event_length)
                     : NULL;
    char *hook_dialect =
        dialect_length ? application_text_copy(
                             payload + root_length + allowed_length + event_length, dialect_length)
                       : NULL;
    if (!root || (allowed_present && !allowed) || (event_length && !hook_event) ||
        (dialect_length && !hook_dialect) ||
        !cbm_hook_augment_invocation_supported(hook_event, hook_dialect)) {
        free(root);
        free(allowed);
        free(hook_event);
        free(hook_dialect);
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    char canonical_root[APPLICATION_PATH_CAP] = {0};
    char canonical_allowed[APPLICATION_PATH_CAP] = {0};
    bool canonical = cbm_canonical_path(root, canonical_root, sizeof(canonical_root));
    if (canonical && allowed_present) {
        canonical = cbm_canonical_path(allowed, canonical_allowed, sizeof(canonical_allowed));
    }
    struct stat root_status;
    canonical =
        canonical && stat(canonical_root, &root_status) == 0 && S_ISDIR(root_status.st_mode);
    bool set =
        canonical && cbm_mcp_server_set_session_context(session->mcp, canonical_root,
                                                        allowed_present ? canonical_allowed : NULL);
    free(root);
    free(allowed);
    if (!set) {
        free(hook_event);
        free(hook_dialect);
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    cbm_mcp_server_set_tool_profile(session->mcp, tool_profile);
    session->tool_profile = tool_profile;
    session->hook_event = hook_event;
    session->hook_dialect = hook_dialect;
    session->context_set = true;
    return CBM_DAEMON_RUNTIME_APPLICATION_OK;
}

/* Build the JSON-RPC error that replaces a reply too large to frame.
 *
 * Says the two numbers a caller needs to act — what the reply measured and what
 * fits — because the alternative the reporter lived through was a silent exit
 * with nothing to go on. The advice is concrete for the same reason: "narrow the
 * projection or add LIMIT" is actionable, "internal error" is not.
 *
 * `request` may be NULL when the message did not parse; the response then omits
 * the id, which is what JSON-RPC requires for an unidentifiable request. */
static char *application_oversized_response_error(const cbm_jsonrpc_request_t *request,
                                                  size_t response_length) {
    char message[CBM_SZ_256];
    (void)snprintf(message, sizeof(message),
                   "response too large: %zu bytes exceeds the %u byte transport limit; "
                   "narrow the projection, add LIMIT, or paginate",
                   response_length, (unsigned)CBM_DAEMON_RUNTIME_APPLICATION_PAYLOAD_MAX);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return NULL;
    }
    yyjson_mut_val *err = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, err);
    /* -32603 (internal error) is the closest standard code: the request was
     * well-formed and the failure is server-side. */
    yyjson_mut_obj_add_int(doc, err, "code", APPLICATION_JSONRPC_INTERNAL_ERROR_CODE);
    yyjson_mut_obj_add_str(doc, err, "message", message);
    char *error_json = yyjson_mut_write(doc, 0, NULL);
    yyjson_mut_doc_free(doc);
    if (!error_json) {
        return NULL;
    }

    cbm_jsonrpc_response_t response = {
        .id = request && request->has_id ? request->id : 0,
        .id_str = request ? request->id_str : NULL,
        .error_json = error_json,
        .error_code = APPLICATION_JSONRPC_INTERNAL_ERROR_CODE,
    };
    char *encoded = cbm_jsonrpc_format_response(&response);
    free(error_json);
    return encoded;
}

/* Decide whether `response` can be framed, substituting the error when it
 * cannot. Owns `response` either way and returns the reply to send, or NULL
 * only on allocation failure. This is ONE function on purpose: the bug was the
 * DECISION (an oversized reply travelling on as if it were fine), so the
 * decision and the substitution have to be testable together — a test that
 * only builds the error passes even with the size check removed. */
static char *application_framable_response(char *response, const cbm_jsonrpc_request_t *request) {
    if (!response || strlen(response) <= CBM_DAEMON_RUNTIME_APPLICATION_PAYLOAD_MAX) {
        return response;
    }
    char *replacement = application_oversized_response_error(request, strlen(response));
    free(response);
    return replacement;
}

char *cbm_daemon_application_framable_response_for_test(char *response,
                                                        const cbm_jsonrpc_request_t *request) {
    return application_framable_response(response, request);
}

static cbm_daemon_runtime_application_status_t application_mcp_request(
    cbm_daemon_application_session_t *session, const uint8_t *request, uint32_t request_length,
    uint8_t **response_out, uint32_t *response_length_out) {
    if (!session->context_set || request_length <= APPLICATION_TEXT_TERMINATOR_BYTES) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    char *message = application_text_copy(request + APPLICATION_TEXT_TERMINATOR_BYTES,
                                          request_length - APPLICATION_TEXT_TERMINATOR_BYTES);
    if (!message) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    cbm_jsonrpc_request_t parsed = {0};
    bool parsed_ok = cbm_jsonrpc_parse(message, &parsed) == 0;
    bool initialize_request =
        parsed_ok && parsed.has_id && parsed.method && strcmp(parsed.method, "initialize") == 0;
    bool tool_request =
        parsed_ok && parsed.has_id && parsed.method && strcmp(parsed.method, "tools/call") == 0;
    char *response = cbm_mcp_server_handle(session->mcp, message);
    free(message);
    if (initialize_request && application_jsonrpc_success(response)) {
        cbm_mutex_lock(&session->application->mutex);
        session->pending_background_initialize = true;
        cbm_mutex_unlock(&session->application->mutex);
    } else if (tool_request && response) {
        application_update_notice_inject(session, &response);
    }
    if (response) {
        size_t response_length = strlen(response);
        if (response_length > UINT32_MAX) {
            if (parsed_ok) {
                cbm_jsonrpc_request_free(&parsed);
            }
            free(response);
            return CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
        }
        /* A reply larger than one frame has to become a JSON-RPC error HERE,
         * while the request id is still in hand. Handing it to the transport
         * instead is indistinguishable from a dead socket at the frontend
         * worker, which responds by _Exit()ing the process — right for a broken
         * transport, a fatal over-reaction to a large answer. Under an MCP host
         * that does not respawn the server, that took every tool on it out for
         * the rest of the session, leaving exit=1 and an empty stderr to debug
         * from (#1375). */
        response = application_framable_response(response, parsed_ok ? &parsed : NULL);
        if (!response) {
            if (parsed_ok) {
                cbm_jsonrpc_request_free(&parsed);
            }
            return CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
        }
        response_length = strlen(response);
        *response_out = (uint8_t *)response;
        *response_length_out = (uint32_t)response_length;
    }
    if (parsed_ok) {
        cbm_jsonrpc_request_free(&parsed);
    }
    application_refresh_watch(session);
    return CBM_DAEMON_RUNTIME_APPLICATION_OK;
}

static cbm_daemon_runtime_application_status_t application_tool_request(
    cbm_daemon_application_session_t *session, const uint8_t *request, uint32_t request_length,
    uint8_t **response_out, uint32_t *response_length_out) {
    if (!session->context_set || request_length <= APPLICATION_TOOL_HEADER_SIZE) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    uint32_t tool_length = application_get_u32(request + APPLICATION_TOOL_NAME_LENGTH_OFFSET);
    if (tool_length == 0 || tool_length >= request_length - APPLICATION_TOOL_HEADER_SIZE) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    char *tool = application_text_copy(request + APPLICATION_TOOL_HEADER_SIZE, tool_length);
    uint32_t args_length = request_length - APPLICATION_TOOL_HEADER_SIZE - tool_length;
    char *args =
        application_text_copy(request + APPLICATION_TOOL_HEADER_SIZE + tool_length, args_length);
    if (!tool || !args) {
        free(tool);
        free(args);
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    char *response = cbm_mcp_handle_tool(session->mcp, tool, args);
    free(tool);
    free(args);
    if (!response) {
        return CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
    }
    size_t response_length = strlen(response);
    if (response_length > UINT32_MAX) {
        free(response);
        return CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
    }
    *response_out = (uint8_t *)response;
    *response_length_out = (uint32_t)response_length;
    application_refresh_watch(session);
    return CBM_DAEMON_RUNTIME_APPLICATION_OK;
}

static cbm_daemon_runtime_application_status_t application_set_ui_config(
    cbm_daemon_application_t *application, cbm_daemon_application_session_t *session,
    const uint8_t *request, uint32_t request_length) {
    const uint8_t valid_mask =
        CBM_DAEMON_APPLICATION_UI_CONFIG_ENABLED | CBM_DAEMON_APPLICATION_UI_CONFIG_PORT;
    if (!session || !session->context_set || session->tool_profile != CBM_MCP_TOOL_PROFILE_ALL ||
        request_length != APPLICATION_UI_CONFIG_REQUEST_SIZE) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    uint8_t update_mask = request[APPLICATION_UI_CONFIG_MASK_OFFSET];
    uint8_t enabled = request[APPLICATION_UI_CONFIG_ENABLED_OFFSET];
    uint32_t port = application_get_u32(request + APPLICATION_UI_CONFIG_PORT_OFFSET);
    bool enabled_present = (update_mask & CBM_DAEMON_APPLICATION_UI_CONFIG_ENABLED) != 0;
    bool port_present = (update_mask & CBM_DAEMON_APPLICATION_UI_CONFIG_PORT) != 0;
    if (update_mask == 0 || (update_mask & (uint8_t)~valid_mask) != 0 ||
        (enabled_present ? enabled > APPLICATION_PROTOCOL_TRUE : enabled != 0U) ||
        (port_present ? port == 0 || request[APPLICATION_UI_CONFIG_PORT_OFFSET] != 0 ||
                            request[APPLICATION_UI_CONFIG_PORT_SECOND_BYTE_OFFSET] != 0
                      : port != 0U)) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }

    cbm_mutex_lock(&application->mutex);
    if (application->stopping) {
        cbm_mutex_unlock(&application->mutex);
        return CBM_DAEMON_RUNTIME_APPLICATION_UNAVAILABLE;
    }
    cbm_ui_config_t config;
    cbm_ui_config_load(&config);
    if (enabled_present) {
        config.ui_enabled = enabled != 0;
    }
    if (port_present) {
        config.ui_port = (int)port;
    }
    bool saved = cbm_ui_config_save(&config);
    cbm_mutex_unlock(&application->mutex);
    return saved ? CBM_DAEMON_RUNTIME_APPLICATION_OK : CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
}

static cbm_daemon_runtime_application_status_t application_request_dispatch(
    cbm_daemon_application_t *application, cbm_daemon_application_session_t *session,
    const uint8_t *request, uint32_t request_length, uint8_t **response_out,
    uint32_t *response_length_out) {
    switch ((cbm_daemon_application_request_kind_t)request[0]) {
    case CBM_DAEMON_APPLICATION_REQUEST_SET_CONTEXT:
        return application_set_context(session, request, request_length);
    case CBM_DAEMON_APPLICATION_REQUEST_MCP:
        return application_mcp_request(session, request, request_length, response_out,
                                       response_length_out);
    case CBM_DAEMON_APPLICATION_REQUEST_TOOL:
        return application_tool_request(session, request, request_length, response_out,
                                        response_length_out);
    case CBM_DAEMON_APPLICATION_REQUEST_SET_UI_CONFIG:
        return application_set_ui_config(application, session, request, request_length);
    case CBM_DAEMON_APPLICATION_REQUEST_HOOK_AUGMENT: {
        if (!session->context_set || request_length <= APPLICATION_TEXT_TERMINATOR_BYTES) {
            return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
        }
        char *input = application_text_copy(request + APPLICATION_TEXT_TERMINATOR_BYTES,
                                            request_length - APPLICATION_TEXT_TERMINATOR_BYTES);
        if (!input) {
            return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
        }
        char *response = cbm_hook_augment_process_for(session->mcp, input, session->hook_event,
                                                      session->hook_dialect);
        free(input);
        if (response) {
            size_t response_length = strlen(response);
            if (response_length > UINT32_MAX) {
                free(response);
                return CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
            }
            *response_out = (uint8_t *)response;
            *response_length_out = (uint32_t)response_length;
        }
        return CBM_DAEMON_RUNTIME_APPLICATION_OK;
    }
    default:
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
}

static cbm_daemon_runtime_application_status_t application_request(
    void *context, cbm_daemon_runtime_application_session_t *opaque_session,
    cbm_daemon_runtime_application_token_t request_token, const uint8_t *request,
    uint32_t request_length, uint8_t **response_out, uint32_t *response_length_out) {
    cbm_daemon_application_t *application = context;
    cbm_daemon_application_session_t *session = (cbm_daemon_application_session_t *)opaque_session;
    if (response_out) {
        *response_out = NULL;
    }
    if (response_length_out) {
        *response_length_out = 0;
    }
    if (!application || !session || session->application != application ||
        request_token == CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID || !request ||
        request_length == 0 || !response_out || !response_length_out) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }

    cbm_mutex_lock(&application->mutex);
    if (application->stopping) {
        cbm_mutex_unlock(&application->mutex);
        return CBM_DAEMON_RUNTIME_APPLICATION_UNAVAILABLE;
    }
    if (session->session_cancelled) {
        cbm_mutex_unlock(&application->mutex);
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    if (session->request_active) {
        cbm_mutex_unlock(&application->mutex);
        return CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
    }
    if (session->request_cancel_token != request_token) {
        session->request_cancel_token = CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID;
    }
    session->request_active = true;
    session->active_request_token = request_token;
    bool mcp_scope_started = cbm_mcp_server_request_scope_begin(session->mcp);
    if (!mcp_scope_started) {
        session->request_active = false;
        session->active_request_token = CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID;
        cbm_mutex_unlock(&application->mutex);
        return CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
    }
    bool cancelled_before_entry = session->request_cancel_token == request_token;
    cbm_mutex_unlock(&application->mutex);

    cbm_daemon_runtime_application_status_t status =
        cancelled_before_entry
            ? CBM_DAEMON_RUNTIME_APPLICATION_CANCELLED
            : application_request_dispatch(application, session, request, request_length,
                                           response_out, response_length_out);

    /* This mutex boundary is the cancellation/completion linearization point.
     * A matching cancel published before it wins; a later cancel is stale and
     * cannot affect the next unique request token. */
    cbm_mutex_lock(&application->mutex);
    bool cancelled = session->session_cancelled || session->request_cancel_token == request_token;
    cbm_mcp_server_request_scope_end(session->mcp);
    session->request_active = false;
    session->active_request_token = CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID;
    if (session->request_cancel_token == request_token) {
        session->request_cancel_token = CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID;
    }
    bool activate_background =
        !cancelled && status == CBM_DAEMON_RUNTIME_APPLICATION_OK &&
        (session->pending_background_initialize ||
         (session->background_eligible &&
          (session->auto_index_retry_pending ||
           (!application->update_generation_started && !session->update_owner))));
    if (!cancelled && status == CBM_DAEMON_RUNTIME_APPLICATION_OK &&
        session->pending_update_notice) {
        session->update_notice_delivered = true;
    }
    session->pending_background_initialize = false;
    session->pending_update_notice = false;
    cbm_mutex_unlock(&application->mutex);
    if (cancelled) {
        free(*response_out);
        *response_out = NULL;
        *response_length_out = 0;
        return CBM_DAEMON_RUNTIME_APPLICATION_CANCELLED;
    }
    if (activate_background) {
        application_background_initialize(session);
    }
    return status;
}

static void application_cancel_jobs_locked(cbm_daemon_application_t *application) {
    for (cbm_daemon_application_job_t *job = application->jobs; job; job = job->next) {
        if (!job->terminal) {
            job->cancel_requested = true;
        }
    }
}

static void application_request_cancel(void *context,
                                       cbm_daemon_runtime_application_session_t *opaque_session,
                                       cbm_daemon_runtime_application_token_t request_token) {
    cbm_daemon_application_t *application = context;
    cbm_daemon_application_session_t *session = (cbm_daemon_application_session_t *)opaque_session;
    if (!application || !session || session->application != application ||
        request_token == CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID) {
        return;
    }
    cbm_mutex_lock(&application->mutex);
    if (!session->session_cancelled &&
        (!session->request_active || session->active_request_token == request_token)) {
        session->request_cancel_token = request_token;
        bool active_match = session->request_active;
        if (active_match && session->active_job && session->active_job_subscribed) {
            cbm_daemon_application_job_t *job = session->active_job;
            session->active_job = NULL;
            session->active_job_subscribed = false;
            application_job_unsubscribe_locked(job);
        }
        if (active_match) {
            /* Keep the MCP atomic cancel inside the same completion mutex.
             * Otherwise this callback could pause after unlocking and set the
             * flag on a later request that already reused this session. */
            (void)cbm_mcp_server_cancel_active(session->mcp);
        }
    }
    cbm_mutex_unlock(&application->mutex);
}

static void application_session_cancel(void *context,
                                       cbm_daemon_runtime_application_session_t *opaque_session) {
    cbm_daemon_application_t *application = context;
    cbm_daemon_application_session_t *session = (cbm_daemon_application_session_t *)opaque_session;
    if (application && session && session->application == application) {
        bool reap_update = false;
        cbm_daemon_application_job_t *join_auto_index = NULL;
        cbm_mutex_lock(&application->mutex);
        /* Runtime may need to keep the session allocation alive until its
         * request callback joins. Cancellation, not the later close, is the
         * ownership boundary for watches and session-scoped index work. */
        bool newly_cancelled = !session->session_cancelled;
        session->session_cancelled = true;
        if (session->request_active) {
            session->request_cancel_token = session->active_request_token;
        }
        if (session->active_job && session->active_job_subscribed) {
            cbm_daemon_application_job_t *job = session->active_job;
            session->active_job = NULL;
            session->active_job_subscribed = false;
            application_job_unsubscribe_locked(job);
        }
        join_auto_index = application_auto_index_release_locked(session);
        reap_update = application_update_owner_release_locked(session);
        reap_update =
            reap_update || (session->background_eligible && application->update_thread_started &&
                            application->update_owners == 0);
        application_release_session_watch_locked(session);
        bool final_live_session = newly_cancelled;
        for (cbm_daemon_application_session_t *other = application->sessions;
             final_live_session && other; other = other->next) {
            if (other != session && !other->session_cancelled) {
                final_live_session = false;
            }
        }
        if (final_live_session && !application->permanent) {
            /* The daemon runtime cannot close this allocation until an
             * in-flight callback joins. Stop new admission now and cancel
             * watcher/UI jobs that are not owned by session->active_job.
             * A PERMANENT generation deliberately outlives its sessions and
             * keeps admitting new ones; only the stop/drain paths latch it. */
            application->stopping = true;
            application_cancel_jobs_locked(application);
            application_update_cancel_locked(application);
            reap_update = reap_update || application->update_thread_started;
        }
        cbm_mutex_unlock(&application->mutex);
        (void)cbm_mcp_server_cancel_active(session->mcp);
        application_auto_index_cancel_join(application, join_auto_index);
        application_jobs_reap_completed(application);
        if (reap_update) {
            if (!application_update_reap(application, true, APPLICATION_BACKGROUND_REAP_MS)) {
                application_cleanup_force_terminate("update_cleanup");
            }
        }
    }
}

static void application_session_close(void *context,
                                      cbm_daemon_runtime_application_session_t *opaque_session) {
    cbm_daemon_application_t *application = context;
    cbm_daemon_application_session_t *session = (cbm_daemon_application_session_t *)opaque_session;
    if (!application || !session || session->application != application) {
        return;
    }
    bool reap_update = false;
    cbm_daemon_application_job_t *join_auto_index = NULL;
    cbm_mutex_lock(&application->mutex);
    cbm_daemon_application_session_t **cursor = &application->sessions;
    while (*cursor && *cursor != session) {
        cursor = &(*cursor)->next;
    }
    if (*cursor == session) {
        *cursor = session->next;
    }
    if (session->active_job && session->active_job_subscribed) {
        application_job_unsubscribe_locked(session->active_job);
        session->active_job = NULL;
        session->active_job_subscribed = false;
    }
    join_auto_index = application_auto_index_release_locked(session);
    reap_update = application_update_owner_release_locked(session);
    reap_update =
        reap_update || (session->background_eligible && application->update_thread_started &&
                        application->update_owners == 0);
    application_release_session_watch_locked(session);
    cbm_mutex_unlock(&application->mutex);
    application_auto_index_cancel_join(application, join_auto_index);
    application_jobs_reap_completed(application);
    if (reap_update) {
        if (!application_update_reap(application, true, APPLICATION_BACKGROUND_REAP_MS)) {
            application_cleanup_force_terminate("update_cleanup");
        }
    }
    cbm_mcp_server_free(session->mcp);
    free(session->hook_event);
    free(session->hook_dialect);
    free(session);
}

void cbm_daemon_application_set_permanent(cbm_daemon_application_t *application, bool permanent) {
    if (!application) {
        return;
    }
    cbm_mutex_lock(&application->mutex);
    application->permanent = permanent;
    cbm_mutex_unlock(&application->mutex);
}

cbm_daemon_application_t *cbm_daemon_application_new(
    const cbm_daemon_application_config_t *config) {
    cbm_daemon_application_t *application =
        calloc(APPLICATION_ALLOCATION_ELEMENTS_ONE, sizeof(*application));
    if (!application) {
        return NULL;
    }
    cbm_mutex_init(&application->mutex);
    application->physical_job_limit = APPLICATION_DEFAULT_PHYSICAL_JOB_LIMIT;
    size_t aggregate_memory_budget_bytes = cbm_mem_budget();
    if (config) {
        application->watcher = config->watcher;
        application->config = config->config;
        application->project_locks = config->project_locks;
        if (config->physical_job_limit > 0) {
            application->physical_job_limit = config->physical_job_limit;
        }
        if (config->aggregate_memory_budget_bytes > 0) {
            aggregate_memory_budget_bytes = config->aggregate_memory_budget_bytes;
        }
        if (config->worker_ops) {
            application->worker_ops = *config->worker_ops;
        }
        if (config->update_ops) {
            application->update_ops = *config->update_ops;
        }
    }
    /* Equal fixed slices keep admission deterministic: starting fewer jobs does
     * not let an early worker claim memory reserved for later concurrent jobs.
     * The absurd sub-byte-per-slot case is made safe by reducing effective
     * capacity before division; normal daemon budgets are many orders larger. */
    if (aggregate_memory_budget_bytes > 0 &&
        application->physical_job_limit > aggregate_memory_budget_bytes) {
        application->physical_job_limit = aggregate_memory_budget_bytes;
    }
    if (aggregate_memory_budget_bytes > 0 && application->physical_job_limit > 0) {
        application->worker_memory_budget_bytes =
            aggregate_memory_budget_bytes / application->physical_job_limit;
    }
    if (!application->worker_ops.start) {
        application->worker_ops = (cbm_daemon_application_worker_ops_t){
            .context = NULL,
            .start = application_worker_start_default,
            .poll = application_worker_poll_default,
            .cancel = application_worker_cancel_default,
            .log_path = application_worker_log_path_default,
            .destroy = application_worker_destroy_default,
        };
    }
    if (!application->worker_ops.poll || !application->worker_ops.cancel ||
        !application->worker_ops.log_path || !application->worker_ops.destroy) {
        cbm_mutex_destroy(&application->mutex);
        free(application);
        return NULL;
    }
    /* No provider means no update checking, which is the production default now
     * that the curl-based GitHub check is gone. An INCOMPLETE provider is still
     * a programming error: a caller that supplies `start` must supply the whole
     * quartet, or the thread would start work it cannot poll, cancel or free. */
    if (application->update_ops.start &&
        (!application->update_ops.poll || !application->update_ops.cancel ||
         !application->update_ops.destroy)) {
        cbm_mutex_destroy(&application->mutex);
        free(application);
        return NULL;
    }
    if (application->watcher) {
        cbm_watcher_set_project_mutation_guard(
            application->watcher, application_watcher_mutation_begin,
            application_watcher_mutation_end, application_watcher_project_pruned, application);
    }
    return application;
}

static void application_shutdown_signal_locked(cbm_daemon_application_t *application) {
    application->stopping = true;
    for (cbm_daemon_application_session_t *session = application->sessions; session;
         session = session->next) {
        (void)cbm_mcp_server_cancel_active(session->mcp);
        if (session->auto_index_job && session->auto_index_subscribed) {
            application_job_unsubscribe_locked(session->auto_index_job);
            session->auto_index_job = NULL;
            session->auto_index_subscribed = false;
        }
        (void)application_update_owner_release_locked(session);
    }
    application_cancel_jobs_locked(application);
    application_update_cancel_locked(application);
}

static bool application_shutdown_complete_locked(cbm_daemon_application_t *application) {
    if (application->active_mutations != 0 ||
        (application->update_thread_started && !application->update_thread_done)) {
        return false;
    }
    for (cbm_daemon_application_session_t *session = application->sessions; session;
         session = session->next) {
        if (session->request_active) {
            return false;
        }
    }
    for (cbm_daemon_application_job_t *job = application->jobs; job; job = job->next) {
        if (!job->thread_done || job->subscribers != 0 || job->watcher_waiters != 0) {
            return false;
        }
    }
    return true;
}

static uint32_t application_shutdown_remaining(uint64_t deadline) {
    uint64_t now = cbm_now_ms();
    if (now >= deadline) {
        return 0;
    }
    uint64_t remaining = deadline - now;
    return remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
}

bool cbm_daemon_application_shutdown(cbm_daemon_application_t *application, uint32_t timeout_ms) {
    if (!application) {
        return false;
    }
    uint64_t deadline = application_deadline_after(timeout_ms);
    cbm_mutex_lock(&application->mutex);
    application_shutdown_signal_locked(application);
    cbm_mutex_unlock(&application->mutex);
    for (;;) {
        cbm_mutex_lock(&application->mutex);
        bool all_done = application_shutdown_complete_locked(application);
        cbm_mutex_unlock(&application->mutex);
        if (all_done) {
            application_jobs_reap_completed(application);
            return application_update_reap(application, true,
                                           application_shutdown_remaining(deadline));
        }
        if (cbm_now_ms() >= deadline) {
            return false;
        }
        cbm_usleep(APPLICATION_JOB_POLL_US);
    }
}

bool cbm_daemon_application_free_with_timeout(cbm_daemon_application_t *application,
                                              uint32_t timeout_ms) {
    if (!application) {
        return true;
    }
    if (!cbm_daemon_application_shutdown(application, timeout_ms)) {
        /* Never detach/free live job threads. The caller must retain the
         * application and retry shutdown after the containment failure is
         * resolved. */
        cbm_log_error("daemon.application.free_busy", "action", "retain");
        return false;
    }
    if (application->watcher) {
        /* Waits for any in-flight prune callback before application storage is
         * detached, preventing a borrowed callback context from becoming UAF. */
        cbm_watcher_set_project_mutation_guard(application->watcher, NULL, NULL, NULL, NULL);
    }
    cbm_mutex_lock(&application->mutex);
    cbm_daemon_application_session_t *sessions = application->sessions;
    application->sessions = NULL;
    cbm_daemon_application_watch_t *watches = application->watches;
    application->watches = NULL;
    cbm_daemon_application_job_t *jobs = application->jobs;
    application->jobs = NULL;
    cbm_daemon_application_watch_job_subscription_t *watch_job_subscriptions =
        application->watch_job_subscriptions;
    application->watch_job_subscriptions = NULL;
    cbm_daemon_application_mutation_t *mutations = application->mutations;
    application->mutations = NULL;
    cbm_mutex_unlock(&application->mutex);
    while (sessions) {
        cbm_daemon_application_session_t *next = sessions->next;
        cbm_mcp_server_free(sessions->mcp);
        free(sessions);
        sessions = next;
    }
    while (watches) {
        cbm_daemon_application_watch_t *next = watches->next;
        if (application->watcher) {
            cbm_watcher_unwatch(application->watcher, watches->project);
        }
        free(watches->project);
        free(watches->root);
        free(watches);
        watches = next;
    }
    while (watch_job_subscriptions) {
        cbm_daemon_application_watch_job_subscription_t *next = watch_job_subscriptions->next;
        free(watch_job_subscriptions);
        watch_job_subscriptions = next;
    }
    while (jobs) {
        cbm_daemon_application_job_t *next = jobs->next;
        if (jobs->thread_started) {
            (void)cbm_thread_join(&jobs->thread);
        }
        application_job_free(jobs);
        jobs = next;
    }
    while (mutations) {
        cbm_daemon_application_mutation_t *next = mutations->next;
        free(mutations->project_key);
        free(mutations);
        mutations = next;
    }
    cbm_mutex_destroy(&application->mutex);
    free(application);
    return true;
}

bool cbm_daemon_application_free(cbm_daemon_application_t *application) {
    return cbm_daemon_application_free_with_timeout(application, APPLICATION_SHUTDOWN_TIMEOUT_MS);
}

cbm_daemon_runtime_application_callbacks_t cbm_daemon_application_runtime_callbacks(
    cbm_daemon_application_t *application) {
    cbm_daemon_runtime_application_callbacks_t callbacks = {
        .context = application,
        .session_open = application_session_open,
        .request = application_request,
        .request_cancel = application_request_cancel,
        .session_cancel = application_session_cancel,
        .session_close = application_session_close,
    };
    if (!application) {
        memset(&callbacks, 0, sizeof(callbacks));
    }
    return callbacks;
}

static cbm_daemon_runtime_application_status_t application_client_exchange_tagged(
    cbm_daemon_runtime_client_t *client, cbm_daemon_runtime_application_token_t request_token,
    uint8_t *request, uint32_t request_length, uint8_t **response_out,
    uint32_t *response_length_out, uint32_t timeout_ms) {
    uint8_t *response = NULL;
    uint32_t response_length = 0;
    if (response_out) {
        *response_out = NULL;
    }
    if (response_length_out) {
        *response_length_out = 0;
    }
    cbm_daemon_runtime_application_status_t status =
        request_token == CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID
            ? cbm_daemon_runtime_client_application_request(client, request, request_length,
                                                            &response, &response_length, timeout_ms)
            : cbm_daemon_runtime_client_application_request_tagged(client, request_token, request,
                                                                   request_length, &response,
                                                                   &response_length, timeout_ms);
    free(request);
    if (status != CBM_DAEMON_RUNTIME_APPLICATION_OK) {
        free(response);
        return status;
    }
    if (response) {
        uint8_t *terminated =
            realloc(response, (size_t)response_length + APPLICATION_TEXT_TERMINATOR_BYTES);
        if (!terminated) {
            free(response);
            return CBM_DAEMON_RUNTIME_APPLICATION_TRANSPORT_ERROR;
        }
        terminated[response_length] = '\0';
        response = terminated;
    }
    if (response_out) {
        *response_out = response;
    } else {
        free(response);
    }
    if (response_length_out) {
        *response_length_out = response_length;
    }
    return status;
}

static cbm_daemon_runtime_application_status_t application_client_exchange(
    cbm_daemon_runtime_client_t *client, uint8_t *request, uint32_t request_length,
    uint8_t **response_out, uint32_t *response_length_out, uint32_t timeout_ms) {
    return application_client_exchange_tagged(client, CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID,
                                              request, request_length, response_out,
                                              response_length_out, timeout_ms);
}

cbm_daemon_runtime_application_status_t cbm_daemon_application_client_set_context(
    cbm_daemon_runtime_client_t *client, const char *session_root, const char *allowed_root,
    cbm_mcp_tool_profile_t tool_profile, const char *hook_event, const char *hook_dialect,
    uint32_t timeout_ms) {
    if (!client || !session_root || !session_root[0]) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    size_t root_length = strlen(session_root);
    size_t allowed_length = allowed_root ? strlen(allowed_root) : 0;
    size_t event_length = hook_event ? strlen(hook_event) : 0;
    size_t dialect_length = hook_dialect ? strlen(hook_dialect) : 0;
    uint64_t total = (uint64_t)APPLICATION_CONTEXT_HEADER_SIZE + root_length + allowed_length +
                     event_length + dialect_length;
    if (tool_profile < CBM_MCP_TOOL_PROFILE_ALL || tool_profile > CBM_MCP_TOOL_PROFILE_SCOUT ||
        (tool_profile != CBM_MCP_TOOL_PROFILE_ALL && (event_length != 0 || dialect_length != 0)) ||
        !cbm_hook_augment_invocation_supported(hook_event, hook_dialect) ||
        root_length > UINT32_MAX || allowed_length > UINT32_MAX || event_length > UINT32_MAX ||
        dialect_length > UINT32_MAX || total > CBM_DAEMON_RUNTIME_APPLICATION_PAYLOAD_MAX) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    uint8_t *request = calloc(APPLICATION_ALLOCATION_ELEMENTS_ONE, (size_t)total);
    if (!request) {
        return CBM_DAEMON_RUNTIME_APPLICATION_TRANSPORT_ERROR;
    }
    request[0] = CBM_DAEMON_APPLICATION_REQUEST_SET_CONTEXT;
    application_put_u32(request + APPLICATION_CONTEXT_ROOT_LENGTH_OFFSET, (uint32_t)root_length);
    request[APPLICATION_CONTEXT_ALLOWED_PRESENT_OFFSET] =
        allowed_root ? APPLICATION_PROTOCOL_TRUE : 0U;
    application_put_u32(request + APPLICATION_CONTEXT_ALLOWED_LENGTH_OFFSET,
                        (uint32_t)allowed_length);
    request[APPLICATION_CONTEXT_PROFILE_OFFSET] = (uint8_t)tool_profile;
    application_put_u32(request + APPLICATION_CONTEXT_EVENT_LENGTH_OFFSET, (uint32_t)event_length);
    application_put_u32(request + APPLICATION_CONTEXT_DIALECT_LENGTH_OFFSET,
                        (uint32_t)dialect_length);
    memcpy(request + APPLICATION_CONTEXT_HEADER_SIZE, session_root, root_length);
    if (allowed_root) {
        memcpy(request + APPLICATION_CONTEXT_HEADER_SIZE + root_length, allowed_root,
               allowed_length);
    }
    if (hook_event) {
        memcpy(request + APPLICATION_CONTEXT_HEADER_SIZE + root_length + allowed_length, hook_event,
               event_length);
    }
    if (hook_dialect) {
        memcpy(request + APPLICATION_CONTEXT_HEADER_SIZE + root_length + allowed_length +
                   event_length,
               hook_dialect, dialect_length);
    }
    uint8_t *unexpected = NULL;
    uint32_t unexpected_length = 0;
    cbm_daemon_runtime_application_status_t status = application_client_exchange(
        client, request, (uint32_t)total, &unexpected, &unexpected_length, timeout_ms);
    if (status == CBM_DAEMON_RUNTIME_APPLICATION_OK && (unexpected || unexpected_length != 0)) {
        status = CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
    }
    free(unexpected);
    return status;
}

cbm_daemon_runtime_application_status_t cbm_daemon_application_client_set_ui_config(
    cbm_daemon_runtime_client_t *client, uint8_t update_mask, bool ui_enabled, int ui_port,
    uint32_t timeout_ms) {
    const uint8_t valid_mask =
        CBM_DAEMON_APPLICATION_UI_CONFIG_ENABLED | CBM_DAEMON_APPLICATION_UI_CONFIG_PORT;
    bool enabled_present = (update_mask & CBM_DAEMON_APPLICATION_UI_CONFIG_ENABLED) != 0;
    bool port_present = (update_mask & CBM_DAEMON_APPLICATION_UI_CONFIG_PORT) != 0;
    if (!client || update_mask == 0 || (update_mask & (uint8_t)~valid_mask) != 0 ||
        (!enabled_present && ui_enabled) || (!port_present && ui_port != 0) ||
        (port_present && (ui_port <= 0 || ui_port > APPLICATION_NETWORK_PORT_MAX))) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    uint8_t *request =
        calloc(APPLICATION_ALLOCATION_ELEMENTS_ONE, APPLICATION_UI_CONFIG_REQUEST_SIZE);
    if (!request) {
        return CBM_DAEMON_RUNTIME_APPLICATION_TRANSPORT_ERROR;
    }
    request[0] = CBM_DAEMON_APPLICATION_REQUEST_SET_UI_CONFIG;
    request[APPLICATION_UI_CONFIG_MASK_OFFSET] = update_mask;
    request[APPLICATION_UI_CONFIG_ENABLED_OFFSET] =
        enabled_present && ui_enabled ? APPLICATION_PROTOCOL_TRUE : 0U;
    if (port_present) {
        application_put_u32(request + APPLICATION_UI_CONFIG_PORT_OFFSET, (uint32_t)ui_port);
    }
    uint8_t *unexpected = NULL;
    uint32_t unexpected_length = 0;
    cbm_daemon_runtime_application_status_t status =
        application_client_exchange(client, request, APPLICATION_UI_CONFIG_REQUEST_SIZE,
                                    &unexpected, &unexpected_length, timeout_ms);
    if (status == CBM_DAEMON_RUNTIME_APPLICATION_OK && (unexpected || unexpected_length != 0)) {
        status = CBM_DAEMON_RUNTIME_APPLICATION_HANDLER_ERROR;
    }
    free(unexpected);
    return status;
}

static cbm_daemon_runtime_application_status_t application_client_text_request_tagged(
    cbm_daemon_runtime_client_t *client, cbm_daemon_runtime_application_token_t request_token,
    cbm_daemon_application_request_kind_t kind, const char *text, uint8_t **response_out,
    uint32_t *response_length_out, uint32_t timeout_ms) {
    if (!client || !text || !text[0]) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    size_t text_length = strlen(text);
    if (text_length + APPLICATION_TEXT_TERMINATOR_BYTES >
        CBM_DAEMON_RUNTIME_APPLICATION_PAYLOAD_MAX) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    uint8_t *request = malloc(text_length + APPLICATION_TEXT_TERMINATOR_BYTES);
    if (!request) {
        return CBM_DAEMON_RUNTIME_APPLICATION_TRANSPORT_ERROR;
    }
    request[0] = (uint8_t)kind;
    memcpy(request + APPLICATION_TEXT_TERMINATOR_BYTES, text, text_length);
    return application_client_exchange_tagged(
        client, request_token, request, (uint32_t)text_length + APPLICATION_TEXT_TERMINATOR_BYTES,
        response_out, response_length_out, timeout_ms);
}

static cbm_daemon_runtime_application_status_t application_client_text_request(
    cbm_daemon_runtime_client_t *client, cbm_daemon_application_request_kind_t kind,
    const char *text, uint8_t **response_out, uint32_t *response_length_out, uint32_t timeout_ms) {
    return application_client_text_request_tagged(
        client, CBM_DAEMON_RUNTIME_APPLICATION_TOKEN_INVALID, kind, text, response_out,
        response_length_out, timeout_ms);
}

cbm_daemon_runtime_application_status_t cbm_daemon_application_client_mcp(
    cbm_daemon_runtime_client_t *client, const char *message, uint8_t **response_out,
    uint32_t *response_length_out, uint32_t timeout_ms) {
    return application_client_text_request(client, CBM_DAEMON_APPLICATION_REQUEST_MCP, message,
                                           response_out, response_length_out, timeout_ms);
}

cbm_daemon_runtime_application_status_t cbm_daemon_application_client_mcp_tagged(
    cbm_daemon_runtime_client_t *client, cbm_daemon_runtime_application_token_t request_token,
    const char *message, uint8_t **response_out, uint32_t *response_length_out,
    uint32_t timeout_ms) {
    return application_client_text_request_tagged(client, request_token,
                                                  CBM_DAEMON_APPLICATION_REQUEST_MCP, message,
                                                  response_out, response_length_out, timeout_ms);
}

cbm_daemon_runtime_application_status_t cbm_daemon_application_client_tool(
    cbm_daemon_runtime_client_t *client, const char *tool_name, const char *args_json,
    uint8_t **response_out, uint32_t *response_length_out, uint32_t timeout_ms) {
    if (!client || !tool_name || !tool_name[0] || !args_json || !args_json[0]) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    size_t tool_length = strlen(tool_name);
    size_t args_length = strlen(args_json);
    uint64_t total = (uint64_t)APPLICATION_TOOL_HEADER_SIZE + tool_length + args_length;
    if (tool_length > UINT32_MAX || total > CBM_DAEMON_RUNTIME_APPLICATION_PAYLOAD_MAX) {
        return CBM_DAEMON_RUNTIME_APPLICATION_REJECTED;
    }
    uint8_t *request = malloc((size_t)total);
    if (!request) {
        return CBM_DAEMON_RUNTIME_APPLICATION_TRANSPORT_ERROR;
    }
    request[0] = CBM_DAEMON_APPLICATION_REQUEST_TOOL;
    application_put_u32(request + APPLICATION_TOOL_NAME_LENGTH_OFFSET, (uint32_t)tool_length);
    memcpy(request + APPLICATION_TOOL_HEADER_SIZE, tool_name, tool_length);
    memcpy(request + APPLICATION_TOOL_HEADER_SIZE + tool_length, args_json, args_length);
    return application_client_exchange(client, request, (uint32_t)total, response_out,
                                       response_length_out, timeout_ms);
}

cbm_daemon_runtime_application_status_t cbm_daemon_application_client_hook_augment(
    cbm_daemon_runtime_client_t *client, const char *input_json, uint8_t **response_out,
    uint32_t *response_length_out, uint32_t timeout_ms) {
    return application_client_text_request(client, CBM_DAEMON_APPLICATION_REQUEST_HOOK_AUGMENT,
                                           input_json, response_out, response_length_out,
                                           timeout_ms);
}

typedef struct {
    char canonical_root[APPLICATION_PATH_CAP];
    char *args;
    char *project_key;
} application_background_request_t;

static void application_background_request_free(application_background_request_t *request) {
    free(request->project_key);
    free(request->args);
}

static bool application_background_request_build(application_background_request_t *request,
                                                 const char *project_name, const char *root_path) {
    struct stat root_status;
    if (!cbm_canonical_path(root_path, request->canonical_root, sizeof(request->canonical_root)) ||
        stat(request->canonical_root, &root_status) != 0 || !S_ISDIR(root_status.st_mode)) {
        return false;
    }
    yyjson_mut_doc *document = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = document ? yyjson_mut_obj(document) : NULL;
    if (!document || !root) {
        yyjson_mut_doc_free(document);
        return false;
    }
    yyjson_mut_doc_set_root(document, root);
    bool encoded = yyjson_mut_obj_add_strcpy(document, root, "repo_path", request->canonical_root);
    char *default_project = cbm_project_name_from_path(request->canonical_root);
    bool custom_project =
        project_name[0] && (!default_project || strcmp(default_project, project_name) != 0);
    if (encoded && custom_project) {
        encoded = yyjson_mut_obj_add_strcpy(document, root, "name", project_name);
    }
    free(default_project);
    request->args = encoded ? yyjson_mut_write(document, 0, NULL) : NULL;
    yyjson_mut_doc_free(document);
    request->project_key =
        request->args ? application_index_project_key(request->canonical_root, request->args)
                      : NULL;
    if (request->project_key) {
        return true;
    }
    application_background_request_free(request);
    return false;
}

static bool application_background_job_success(cbm_daemon_application_t *application,
                                               cbm_daemon_application_job_t *job,
                                               bool require_live_watch, bool *cancelled) {
    for (;;) {
        cbm_mutex_lock(&application->mutex);
        if (!job->terminal) {
            cbm_mutex_unlock(&application->mutex);
            cbm_usleep(APPLICATION_JOB_POLL_US);
            continue;
        }
        bool successful = job->successful;
        *cancelled = job->cancelled;
        if (require_live_watch) {
            application_watch_job_unsubscribe_job_locked(application, job);
            if (job->watcher_waiters > 0) {
                job->watcher_waiters--;
            }
        } else {
            application_job_unsubscribe_locked(job);
        }
        cbm_mutex_unlock(&application->mutex);
        return successful;
    }
}

static int application_background_admission_result(application_job_subscribe_status_t status,
                                                   bool require_live_watch, bool watch_live,
                                                   bool subscriptions_ok,
                                                   size_t watch_owner_count) {
    if (require_live_watch && (!watch_live || (subscriptions_ok && watch_owner_count == 0))) {
        return APPLICATION_RESULT_SKIPPED;
    }
    return status == APPLICATION_JOB_SUBSCRIBE_OPTIONS_CONFLICT ||
                   status == APPLICATION_JOB_SUBSCRIBE_BUSY ||
                   status == APPLICATION_JOB_SUBSCRIBE_CANCELLING
               ? APPLICATION_RESULT_SKIPPED
               : APPLICATION_RESULT_FAILURE;
}

static int application_background_index(cbm_daemon_application_t *application,
                                        const char *project_name, const char *root_path,
                                        bool require_live_watch) {
    if (!application || !project_name || !root_path) {
        return APPLICATION_RESULT_FAILURE;
    }
    application_background_request_t request = {0};
    if (!application_background_request_build(&request, project_name, root_path)) {
        return APPLICATION_RESULT_FAILURE;
    }

    application_job_subscribe_status_t subscribe_status = APPLICATION_JOB_SUBSCRIBE_UNAVAILABLE;
    application_jobs_reap_completed(application);
    cbm_mutex_lock(&application->mutex);
    cbm_daemon_application_watch_t *watch =
        require_live_watch ? application_find_watch_locked(application, project_name) : NULL;
    bool watch_live = !require_live_watch || (watch && watch->subscribers > 0 &&
                                              strcmp(watch->root, request.canonical_root) == 0);
    size_t watch_owner_count = 0;
    bool watch_subscriptions_ok = true;
    cbm_daemon_application_job_t *job =
        watch_live ? application_job_subscribe_locked(application, request.project_key,
                                                      request.canonical_root, request.args,
                                                      &subscribe_status)
                   : NULL;
    if (job && require_live_watch) {
        watch_subscriptions_ok = application_watch_job_subscribe_sessions_locked(
            application, watch, job, &watch_owner_count);
        if (watch_subscriptions_ok && watch_owner_count > 0) {
            job->watcher_waiters++;
        } else if (!watch_subscriptions_ok) {
            subscribe_status = APPLICATION_JOB_SUBSCRIBE_ALLOCATION_FAILED;
        }
        /* application_job_subscribe_locked() lends the caller one ordinary
         * subscriber. A watcher callback is only a storage waiter: exact live
         * session subscriptions above own the physical work. */
        application_job_unsubscribe_locked(job);
        if (!watch_subscriptions_ok || watch_owner_count == 0) {
            job = NULL;
        }
    }
    cbm_mutex_unlock(&application->mutex);
    application_background_request_free(&request);
    if (!job) {
        return application_background_admission_result(subscribe_status, require_live_watch,
                                                       watch_live, watch_subscriptions_ok,
                                                       watch_owner_count);
    }
    bool cancelled = false;
    bool successful =
        application_background_job_success(application, job, require_live_watch, &cancelled);
    application_jobs_reap_completed(application);
    if (successful) {
        return APPLICATION_RESULT_SUCCESS;
    }
    if (cancelled) {
        return APPLICATION_RESULT_SKIPPED;
    }
    return APPLICATION_RESULT_FAILURE;
}

int cbm_daemon_application_index(cbm_daemon_application_t *application, const char *project_name,
                                 const char *root_path) {
    return application_background_index(application, project_name, root_path, false);
}

int cbm_daemon_application_watcher_index(const char *project_name, const char *root_path,
                                         void *context) {
    return application_background_index(context, project_name, root_path, true);
}

size_t cbm_daemon_application_active_jobs(cbm_daemon_application_t *application) {
    if (!application) {
        return 0;
    }
    size_t count = 0;
    cbm_mutex_lock(&application->mutex);
    for (cbm_daemon_application_job_t *job = application->jobs; job; job = job->next) {
        if (!job->terminal) {
            count++;
        }
    }
    cbm_mutex_unlock(&application->mutex);
    return count;
}

size_t cbm_daemon_application_job_subscribers(cbm_daemon_application_t *application,
                                              const char *project_key) {
    if (!application || !project_key) {
        return 0;
    }
    cbm_mutex_lock(&application->mutex);
    cbm_daemon_application_job_t *job = application_find_job_locked(application, project_key);
    size_t subscribers = job ? job->subscribers : 0;
    cbm_mutex_unlock(&application->mutex);
    return subscribers;
}

size_t cbm_daemon_application_physical_job_limit(cbm_daemon_application_t *application) {
    if (!application) {
        return 0;
    }
    cbm_mutex_lock(&application->mutex);
    size_t limit = application->physical_job_limit;
    cbm_mutex_unlock(&application->mutex);
    return limit;
}

size_t cbm_daemon_application_worker_memory_budget_bytes(cbm_daemon_application_t *application) {
    if (!application) {
        return 0;
    }
    cbm_mutex_lock(&application->mutex);
    size_t budget = application->worker_memory_budget_bytes;
    cbm_mutex_unlock(&application->mutex);
    return budget;
}

bool cbm_daemon_application_session_retains_store_for_test(
    const cbm_daemon_runtime_application_session_t *opaque_session) {
    const cbm_daemon_application_session_t *session =
        (const cbm_daemon_application_session_t *)opaque_session;
    return session && session->mcp && cbm_mcp_server_store(session->mcp) != NULL;
}
