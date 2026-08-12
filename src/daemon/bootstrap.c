/*
 * bootstrap.c — Mandatory per-account daemon startup policy.
 */
#include "daemon/bootstrap.h"

#include "daemon/daemon.h"
#include "daemon/ipc.h"
#include "daemon/runtime.h"
#include "daemon/service.h"
#include "foundation/compat.h"
#include "foundation/platform.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "foundation/subprocess.h"
#include "foundation/win_utf8.h"
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <pthread.h>
#include <spawn.h>
extern char **environ;
#endif
#endif

enum {
    BOOTSTRAP_RETRY_NS = 1000000,
    BOOTSTRAP_COORDINATION_CLEANUP_MS = 500,
    BOOTSTRAP_PATH_CAP = 4096,
    BOOTSTRAP_ARGV_FIRST_USER_INDEX = 1,
    BOOTSTRAP_ARGV_NOT_FOUND = -1,
    BOOTSTRAP_ARGV_FOUND_INDEX = 0,
    BOOTSTRAP_ARGV_NEXT_INDEX = 1,
    BOOTSTRAP_SHA256_HEX_LENGTH = 64,
    BOOTSTRAP_DECIMAL_RADIX = 10,
    BOOTSTRAP_WORKER_REQUIRED_ARGC = 9,
    BOOTSTRAP_WORKER_CLI_INDEX = 1,
    BOOTSTRAP_WORKER_MODE_INDEX = 2,
    BOOTSTRAP_WORKER_BUILD_FLAG_INDEX = 3,
    BOOTSTRAP_WORKER_FINGERPRINT_INDEX = 4,
    BOOTSTRAP_WORKER_COMMAND_INDEX = 5,
    BOOTSTRAP_WORKER_ROOT_INDEX = 6,
    BOOTSTRAP_WORKER_RESPONSE_FLAG_INDEX = 7,
    BOOTSTRAP_WORKER_RESPONSE_PATH_INDEX = 8,
    BOOTSTRAP_WORKER_OPTION_START_INDEX = 9,
    BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET = 1,
    BOOTSTRAP_WORKER_OPTION_ARGUMENTS = 2,
    BOOTSTRAP_DAEMON_ARGV_INDEX = 1,
    BOOTSTRAP_DAEMON_ARGC = 2,
    BOOTSTRAP_PERMANENT_DAEMON_ARGV_INDEX = 2,
    BOOTSTRAP_PERMANENT_DAEMON_ARGC = 3,
    BOOTSTRAP_LOCK_STATUS_HELD = 0,
    BOOTSTRAP_LOCK_STATUS_ACQUIRED = 1,
    BOOTSTRAP_LIFETIME_STATUS_FREE = 0,
    BOOTSTRAP_LIFETIME_STATUS_HELD = 1,
    BOOTSTRAP_ALLOCATION_ELEMENT_COUNT = 1,
    BOOTSTRAP_MILLISECOND_RETRY_THRESHOLD = 1,
    BOOTSTRAP_POSIX_SPAWN_ARGV_TERMINATOR = 1,
    BOOTSTRAP_THREAD_START_FAILURE = -1,
    BOOTSTRAP_NANOSECONDS_PER_MILLISECOND = 1000000,
};

static bool bootstrap_arg_is(const char *arg, const char *expected) {
    return arg && expected && strcmp(arg, expected) == 0;
}

static int bootstrap_find_arg(int argc, char *const argv[], const char *expected) {
    for (int i = BOOTSTRAP_ARGV_FIRST_USER_INDEX; argv && i < argc; i++) {
        if (bootstrap_arg_is(argv[i], expected)) {
            return i;
        }
    }
    return BOOTSTRAP_ARGV_NOT_FOUND;
}

static bool bootstrap_has_help_after(int argc, char *const argv[], int start) {
    for (int i = start; argv && i < argc; i++) {
        if (bootstrap_arg_is(argv[i], "--help") || bootstrap_arg_is(argv[i], "-h")) {
            return true;
        }
    }
    return false;
}

static bool bootstrap_worker_fingerprint_valid(const char *fingerprint) {
    if (!fingerprint || strlen(fingerprint) != BOOTSTRAP_SHA256_HEX_LENGTH) {
        return false;
    }
    for (size_t i = 0; i < BOOTSTRAP_SHA256_HEX_LENGTH; i++) {
        char ch = fingerprint[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool bootstrap_worker_budget_valid(const char *text) {
    if (!text || !text[0]) {
        return false;
    }
    size_t value = 0;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; cursor++) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        size_t digit = (size_t)(*cursor - '0');
        if (value > (SIZE_MAX - digit) / BOOTSTRAP_DECIMAL_RADIX) {
            return false;
        }
        value = (value * BOOTSTRAP_DECIMAL_RADIX) + digit;
    }
    return value > 0;
}

/* Keep the bootstrap role boundary exact and fail closed before any client or
 * worker state is initialized. index_supervisor owns the matching builder and
 * performs the captured-build comparison after this syntax-only classification. */
static bool bootstrap_worker_argv_exact(int argc, char *const argv[]) {
    if (argc < BOOTSTRAP_WORKER_REQUIRED_ARGC || !argv ||
        !bootstrap_arg_is(argv[BOOTSTRAP_WORKER_CLI_INDEX], "cli") ||
        !bootstrap_arg_is(argv[BOOTSTRAP_WORKER_MODE_INDEX], "--index-worker") ||
        !bootstrap_arg_is(argv[BOOTSTRAP_WORKER_BUILD_FLAG_INDEX], "--index-worker-build") ||
        !bootstrap_worker_fingerprint_valid(argv[BOOTSTRAP_WORKER_FINGERPRINT_INDEX]) ||
        !bootstrap_arg_is(argv[BOOTSTRAP_WORKER_COMMAND_INDEX], "index_repository") ||
        !argv[BOOTSTRAP_WORKER_ROOT_INDEX] || !argv[BOOTSTRAP_WORKER_ROOT_INDEX][0] ||
        !bootstrap_arg_is(argv[BOOTSTRAP_WORKER_RESPONSE_FLAG_INDEX], "--response-out") ||
        !argv[BOOTSTRAP_WORKER_RESPONSE_PATH_INDEX] ||
        !argv[BOOTSTRAP_WORKER_RESPONSE_PATH_INDEX][0]) {
        return false;
    }
    int next = BOOTSTRAP_WORKER_OPTION_START_INDEX;
    if (next < argc && bootstrap_arg_is(argv[next], "--index-worker-memory-budget-bytes")) {
        if (next + BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET >= argc ||
            !bootstrap_worker_budget_valid(argv[next + BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET])) {
            return false;
        }
        next += BOOTSTRAP_WORKER_OPTION_ARGUMENTS;
    }
    if (next < argc && bootstrap_arg_is(argv[next], "--index-worker-single-thread")) {
        next += BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET;
    }
    if (next < argc && bootstrap_arg_is(argv[next], "--index-worker-marker")) {
        if (next + BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET >= argc ||
            !argv[next + BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET] ||
            !argv[next + BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET][0]) {
            return false;
        }
        next += BOOTSTRAP_WORKER_OPTION_ARGUMENTS;
    }
    if (next < argc && bootstrap_arg_is(argv[next], "--index-worker-quarantine")) {
        if (next + BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET >= argc ||
            !argv[next + BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET] ||
            !argv[next + BOOTSTRAP_WORKER_OPTION_VALUE_OFFSET][0]) {
            return false;
        }
        next += BOOTSTRAP_WORKER_OPTION_ARGUMENTS;
    }
    return next == argc;
}

static cbm_daemon_process_role_t bootstrap_daemon_marker_role(int argc, char *const argv[],
                                                              int daemon_arg) {
    if (argc == BOOTSTRAP_DAEMON_ARGC && daemon_arg == BOOTSTRAP_DAEMON_ARGV_INDEX) {
        return CBM_DAEMON_PROCESS_DAEMON;
    }
    if (argc == BOOTSTRAP_PERMANENT_DAEMON_ARGC && daemon_arg == BOOTSTRAP_DAEMON_ARGV_INDEX &&
        bootstrap_arg_is(argv[BOOTSTRAP_PERMANENT_DAEMON_ARGV_INDEX], CBM_DAEMON_PERMANENT_ARG)) {
        return CBM_DAEMON_PROCESS_DAEMON;
    }
    return CBM_DAEMON_PROCESS_INVALID;
}

static bool bootstrap_stateless_command(const char *arg) {
    static const char *const commands[] = {
        "install",
        "uninstall",
        "update",
        "allow-root",
    };
    for (size_t command = 0; command < sizeof(commands) / sizeof(commands[0]); command++) {
        if (bootstrap_arg_is(arg, commands[command])) {
            return true;
        }
    }
    return false;
}

static bool bootstrap_top_level_role(int argc, char *const argv[], int arg,
                                     cbm_daemon_process_role_t *role_out) {
    const char *value = argv[arg];
    int next = arg + BOOTSTRAP_ARGV_NEXT_INDEX;
    if (bootstrap_arg_is(value, "cli") || bootstrap_arg_is(value, "config")) {
        *role_out = bootstrap_has_help_after(argc, argv, next) ? CBM_DAEMON_PROCESS_STATELESS
                                                               : CBM_DAEMON_PROCESS_LOCAL_CLI;
        return true;
    }
    if (bootstrap_arg_is(value, "hook-augment")) {
        *role_out = CBM_DAEMON_PROCESS_HOOK_CLIENT;
        return true;
    }
    if (bootstrap_arg_is(value, "daemon")) {
        *role_out = bootstrap_has_help_after(argc, argv, next) ? CBM_DAEMON_PROCESS_STATELESS
                                                               : CBM_DAEMON_PROCESS_DAEMON_CTL;
        return true;
    }
    if (bootstrap_arg_is(value, "--version") || bootstrap_arg_is(value, "--help") ||
        bootstrap_arg_is(value, "-h") || bootstrap_stateless_command(value)) {
        *role_out = CBM_DAEMON_PROCESS_STATELESS;
        return true;
    }
    return false;
}

cbm_daemon_process_role_t cbm_daemon_process_role(int argc, char *const argv[]) {
    if (argc <= 0 || !argv || !argv[0] || argv[0][0] == '\0') {
        return CBM_DAEMON_PROCESS_INVALID;
    }

    int daemon_arg = bootstrap_find_arg(argc, argv, CBM_DAEMON_INTERNAL_ARG);
    if (daemon_arg >= BOOTSTRAP_ARGV_FOUND_INDEX) {
        return bootstrap_daemon_marker_role(argc, argv, daemon_arg);
    }

    int worker_arg = bootstrap_find_arg(argc, argv, "--index-worker");
    if (worker_arg >= BOOTSTRAP_ARGV_FOUND_INDEX) {
        return bootstrap_worker_argv_exact(argc, argv) ? CBM_DAEMON_PROCESS_WORKER
                                                       : CBM_DAEMON_PROCESS_INVALID;
    }

    /* Stop at the first top-level mode token. Tool names, flag values, and JSON
     * following `cli` are opaque user input: a search query named "install"
     * or containing "--version" must never bypass the mandatory daemon. */
    for (int arg = BOOTSTRAP_ARGV_FIRST_USER_INDEX; arg < argc; arg++) {
        cbm_daemon_process_role_t role = CBM_DAEMON_PROCESS_MCP_CLIENT;
        if (bootstrap_top_level_role(argc, argv, arg, &role)) {
            return role;
        }
    }
    return CBM_DAEMON_PROCESS_MCP_CLIENT;
}

bool cbm_daemon_process_role_requires_client(cbm_daemon_process_role_t role) {
    return role == CBM_DAEMON_PROCESS_MCP_CLIENT || role == CBM_DAEMON_PROCESS_HOOK_CLIENT;
}

cbm_daemon_ipc_endpoint_t *cbm_daemon_bootstrap_endpoint_new(const char *runtime_parent) {
    char key[CBM_DAEMON_KEY_SIZE];
    if (!cbm_daemon_rendezvous_key(key)) {
        return NULL;
    }
    return cbm_daemon_ipc_endpoint_new(key, runtime_parent);
}

bool cbm_daemon_bootstrap_launch_spec_init(const char *executable_path,
                                           cbm_daemon_bootstrap_launch_spec_t *spec_out) {
    if (!executable_path || executable_path[0] == '\0' || !spec_out) {
        return false;
    }
    memset(spec_out, 0, sizeof(*spec_out));
    spec_out->executable_path = executable_path;
    spec_out->argv[0] = executable_path;
    spec_out->argv[BOOTSTRAP_DAEMON_ARGV_INDEX] = CBM_DAEMON_INTERNAL_ARG;
    spec_out->argc = BOOTSTRAP_DAEMON_ARGC;
    spec_out->detached = true;
    spec_out->inherit_standard_handles = false;
    spec_out->use_shell = false;
    return true;
}

bool cbm_daemon_bootstrap_launch_spec_init_permanent(const char *executable_path,
                                                     cbm_daemon_bootstrap_launch_spec_t *spec_out) {
    if (!cbm_daemon_bootstrap_launch_spec_init(executable_path, spec_out)) {
        return false;
    }
    spec_out->argv[BOOTSTRAP_PERMANENT_DAEMON_ARGV_INDEX] = CBM_DAEMON_PERMANENT_ARG;
    spec_out->argc = BOOTSTRAP_PERMANENT_DAEMON_ARGC;
    return true;
}

static uint64_t bootstrap_deadline_after(uint32_t timeout_ms) {
    uint64_t now = cbm_now_ms();
    return UINT64_MAX - now < timeout_ms ? UINT64_MAX : now + (uint64_t)timeout_ms;
}

static _Noreturn void bootstrap_cleanup_fail_stop(const char *component) {
    (void)fprintf(stderr,
                  "codebase-memory-mcp: coordination cleanup failed (%s); "
                  "terminating so the OS releases retained claims\n",
                  component ? component : "unknown");
    (void)fflush(stderr);
#ifdef _WIN32
    (void)TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
    abort();
#else
    _exit(EXIT_FAILURE);
#endif
}

static void bootstrap_pause(uint64_t deadline) {
    uint64_t now = cbm_now_ms();
    if (now >= deadline) {
        return;
    }
    uint64_t remaining_ms = deadline - now;
    struct timespec pause = {
        .tv_sec = 0,
        .tv_nsec = remaining_ms > BOOTSTRAP_MILLISECOND_RETRY_THRESHOLD
                       ? BOOTSTRAP_RETRY_NS
                       : (long)(remaining_ms * (uint64_t)BOOTSTRAP_NANOSECONDS_PER_MILLISECOND),
    };
    (void)cbm_nanosleep(&pause, NULL);
}

static void bootstrap_startup_lock_release_complete(const cbm_daemon_bootstrap_ops_t *ops,
                                                    cbm_daemon_bootstrap_lock_t *lock_io) {
    uint64_t deadline = bootstrap_deadline_after(BOOTSTRAP_COORDINATION_CLEANUP_MS);
    while (ops && ops->startup_lock_release && lock_io && *lock_io) {
        (void)ops->startup_lock_release(ops->context, lock_io);
        if (!*lock_io) {
            return;
        }
        if (cbm_now_ms() >= deadline) {
            bootstrap_cleanup_fail_stop("startup_lock_cleanup");
        }
        cbm_usleep(1000);
    }
}

static void bootstrap_result_reset(cbm_daemon_bootstrap_result_t *result,
                                   cbm_daemon_process_role_t role) {
    memset(result, 0, sizeof(*result));
    result->status = cbm_daemon_process_role_requires_client(role) ? CBM_DAEMON_BOOTSTRAP_FAILED
                                                                   : CBM_DAEMON_BOOTSTRAP_BYPASSED;
}

static cbm_daemon_bootstrap_status_t bootstrap_finish_probe(
    cbm_daemon_bootstrap_probe_status_t probe, cbm_daemon_runtime_client_t *client,
    const cbm_daemon_runtime_connect_result_t *connect_result,
    const cbm_daemon_bootstrap_ops_t *ops, cbm_daemon_bootstrap_result_t *result) {
    if (connect_result) {
        result->connect_result = *connect_result;
    }
    result->client = client;
    if (probe == CBM_DAEMON_BOOTSTRAP_PROBE_CONNECTED && client) {
        result->status = CBM_DAEMON_BOOTSTRAP_CONNECTED;
        return result->status;
    }
    result->client = NULL;
    if (probe == CBM_DAEMON_BOOTSTRAP_PROBE_CONFLICT) {
        result->status = CBM_DAEMON_BOOTSTRAP_CONFLICT;
        (void)snprintf(result->message, sizeof(result->message), "%s",
                       connect_result && connect_result->message[0]
                           ? connect_result->message
                           : "CBM could not start because a conflicting CBM process is active; "
                             "close all CBM sessions and commands, then retry. If a permanent "
                             "daemon from another build is running, `codebase-memory-mcp daemon "
                             "stop` retires it");
        if (ops->visible_diagnostic) {
            ops->visible_diagnostic(ops->context, result->message);
        }
        return result->status;
    }
    return CBM_DAEMON_BOOTSTRAP_FAILED;
}

static cbm_daemon_bootstrap_probe_status_t bootstrap_probe(
    const cbm_daemon_bootstrap_config_t *config, const cbm_daemon_bootstrap_ops_t *ops,
    cbm_daemon_runtime_client_t **client_out, cbm_daemon_runtime_connect_result_t *connect_result) {
    memset(connect_result, 0, sizeof(*connect_result));
    *client_out = NULL;
    return ops->probe(ops->context, config->endpoint, config->identity, config->connect_timeout_ms,
                      client_out, connect_result);
}

static bool bootstrap_probe_is_finishable(cbm_daemon_bootstrap_probe_status_t probe) {
    return probe == CBM_DAEMON_BOOTSTRAP_PROBE_CONNECTED ||
           probe == CBM_DAEMON_BOOTSTRAP_PROBE_CONFLICT;
}

static bool bootstrap_probe_is_waitable(cbm_daemon_bootstrap_probe_status_t probe) {
    return probe == CBM_DAEMON_BOOTSTRAP_PROBE_UNAVAILABLE ||
           probe == CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED ||
           probe == CBM_DAEMON_BOOTSTRAP_PROBE_TERMINAL;
}

static bool bootstrap_config_valid(const cbm_daemon_bootstrap_config_t *config,
                                   const cbm_daemon_bootstrap_ops_t *ops) {
    return config && ops && config->endpoint && config->identity && config->executable_path &&
           config->executable_path[0] && config->connect_timeout_ms > 0 &&
           config->startup_timeout_ms > 0 && ops->cohort_acquire && ops->cohort_release &&
           ops->probe && ops->startup_lock_try_acquire && ops->startup_lock_prepare_handoff &&
           ops->startup_lock_release && ops->spawn_daemon;
}

typedef struct {
    const cbm_daemon_bootstrap_config_t *config;
    const cbm_daemon_bootstrap_ops_t *ops;
    cbm_daemon_bootstrap_result_t *result;
    uint64_t deadline;
    cbm_daemon_bootstrap_cohort_t cohort;
    cbm_daemon_runtime_client_t *client;
    cbm_daemon_runtime_connect_result_t connect_result;
    cbm_daemon_bootstrap_probe_status_t probe;
    cbm_daemon_bootstrap_lock_t startup_lock;
    bool lock_acquired;
    bool generation_observed;
} bootstrap_session_t;

static void bootstrap_session_probe(bootstrap_session_t *session) {
    session->probe =
        bootstrap_probe(session->config, session->ops, &session->client, &session->connect_result);
}

static bool bootstrap_probe_has_generation(cbm_daemon_bootstrap_probe_status_t probe) {
    return probe == CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED ||
           probe == CBM_DAEMON_BOOTSTRAP_PROBE_TERMINAL;
}

static void bootstrap_session_release_lock(bootstrap_session_t *session) {
    if (session->lock_acquired) {
        bootstrap_startup_lock_release_complete(session->ops, &session->startup_lock);
        session->lock_acquired = false;
    }
}

static void bootstrap_session_wait_for_generation(bootstrap_session_t *session) {
    session->generation_observed = true;
    bootstrap_pause(session->deadline);
    bootstrap_session_probe(session);
}

static bool bootstrap_session_acquire_lock(bootstrap_session_t *session) {
    int status = session->ops->startup_lock_try_acquire(
        session->ops->context, session->config->endpoint, &session->startup_lock);
    if (status < 0 || (status != BOOTSTRAP_LOCK_STATUS_HELD &&
                       (status != BOOTSTRAP_LOCK_STATUS_ACQUIRED || !session->startup_lock))) {
        session->probe = CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
        return false;
    }
    if (status == BOOTSTRAP_LOCK_STATUS_HELD) {
        bootstrap_pause(session->deadline);
        bootstrap_session_probe(session);
        return false;
    }
    session->lock_acquired = true;
    bootstrap_session_probe(session);
    return true;
}

static bool bootstrap_session_launch(bootstrap_session_t *session) {
    cbm_daemon_bootstrap_launch_spec_t spec;
    bool ready =
        session->config->spawn_permanent
            ? cbm_daemon_bootstrap_launch_spec_init_permanent(session->config->executable_path,
                                                              &spec)
            : cbm_daemon_bootstrap_launch_spec_init(session->config->executable_path, &spec);
    if (!ready ||
        !session->ops->startup_lock_prepare_handoff(session->ops->context, session->startup_lock) ||
        !session->ops->spawn_daemon(session->ops->context, &spec)) {
        session->probe = CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
        return false;
    }
    session->result->daemon_spawned = true;
    return true;
}

static void bootstrap_session_wait_for_spawn(bootstrap_session_t *session) {
    do {
        bootstrap_pause(session->deadline);
        bootstrap_session_probe(session);
        if (bootstrap_probe_has_generation(session->probe)) {
            session->generation_observed = true;
            bootstrap_session_release_lock(session);
            return;
        }
    } while (bootstrap_probe_is_waitable(session->probe) && cbm_now_ms() < session->deadline);
}

static void bootstrap_session_process_absence(bootstrap_session_t *session) {
    if (!bootstrap_session_acquire_lock(session)) {
        return;
    }
    if (bootstrap_probe_has_generation(session->probe)) {
        session->generation_observed = true;
        bootstrap_session_release_lock(session);
        return;
    }
    if (bootstrap_probe_is_finishable(session->probe) ||
        session->probe == CBM_DAEMON_BOOTSTRAP_PROBE_ERROR) {
        return;
    }
    if (session->probe != CBM_DAEMON_BOOTSTRAP_PROBE_UNAVAILABLE ||
        !bootstrap_session_launch(session)) {
        session->probe = CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
        return;
    }
    bootstrap_session_wait_for_spawn(session);
}

static void bootstrap_session_run(bootstrap_session_t *session) {
    while (cbm_now_ms() < session->deadline && bootstrap_probe_is_waitable(session->probe)) {
        if (bootstrap_probe_has_generation(session->probe)) {
            bootstrap_session_wait_for_generation(session);
            continue;
        }
        bootstrap_session_process_absence(session);
        if (session->lock_acquired) {
            return;
        }
    }
}

static cbm_daemon_bootstrap_status_t bootstrap_cohort_failure(
    cbm_version_cohort_status_t cohort_status, cbm_daemon_bootstrap_cohort_t cohort,
    const cbm_daemon_conflict_t *conflict, const cbm_daemon_bootstrap_ops_t *ops,
    cbm_daemon_bootstrap_result_t *result) {
    result->status = cohort_status == CBM_VERSION_COHORT_CONFLICT ? CBM_DAEMON_BOOTSTRAP_CONFLICT
                                                                  : CBM_DAEMON_BOOTSTRAP_FAILED;
    bool formatted = cohort_status == CBM_VERSION_COHORT_CONFLICT &&
                     cbm_daemon_conflict_format(conflict, result->message, sizeof(result->message));
    if (!formatted) {
        const char *reason = cohort_status == CBM_VERSION_COHORT_BUSY
                                 ? "another CBM activation is in progress"
                                 : "exact-build admission could not be verified";
        (void)snprintf(result->message, sizeof(result->message), "CBM daemon could not start: %s",
                       reason);
    }
    if (ops->visible_diagnostic) {
        ops->visible_diagnostic(ops->context, result->message);
    }
    if (cohort) {
        ops->cohort_release(ops->context, cohort);
    }
    return result->status;
}

static void bootstrap_session_report_failure(bootstrap_session_t *session) {
    session->result->status = CBM_DAEMON_BOOTSTRAP_FAILED;
    const char *message = session->generation_observed
                              ? "CBM daemon is active or starting but could not accept this client "
                                "within %u ms"
                              : "CBM daemon could not start within %u ms";
    (void)snprintf(session->result->message, sizeof(session->result->message), message,
                   session->config->startup_timeout_ms);
    if (session->ops->visible_diagnostic) {
        session->ops->visible_diagnostic(session->ops->context, session->result->message);
    }
}

cbm_daemon_bootstrap_status_t cbm_daemon_bootstrap_execute_with_ops(
    const cbm_daemon_bootstrap_config_t *config, const cbm_daemon_bootstrap_ops_t *ops,
    cbm_daemon_bootstrap_result_t *result_out) {
    if (!result_out) {
        return CBM_DAEMON_BOOTSTRAP_FAILED;
    }
    cbm_daemon_process_role_t role = config ? config->role : CBM_DAEMON_PROCESS_INVALID;
    bootstrap_result_reset(result_out, role);
    if (!cbm_daemon_process_role_requires_client(role)) {
        return role == CBM_DAEMON_PROCESS_INVALID ? CBM_DAEMON_BOOTSTRAP_FAILED
                                                  : CBM_DAEMON_BOOTSTRAP_BYPASSED;
    }
    if (!bootstrap_config_valid(config, ops)) {
        return CBM_DAEMON_BOOTSTRAP_FAILED;
    }

    bootstrap_session_t session = {
        .config = config,
        .ops = ops,
        .result = result_out,
        .deadline = bootstrap_deadline_after(config->startup_timeout_ms),
    };
    cbm_daemon_conflict_t cohort_conflict;
    cbm_version_cohort_status_t cohort_status =
        ops->cohort_acquire(ops->context, config->endpoint, config->identity, session.deadline,
                            &session.cohort, &cohort_conflict);
    if (cohort_status != CBM_VERSION_COHORT_OK) {
        return bootstrap_cohort_failure(cohort_status, session.cohort, &cohort_conflict, ops,
                                        result_out);
    }

    bootstrap_session_probe(&session);
    if (bootstrap_probe_is_finishable(session.probe)) {
        cbm_daemon_bootstrap_status_t status = bootstrap_finish_probe(
            session.probe, session.client, &session.connect_result, ops, result_out);
        ops->cohort_release(ops->context, session.cohort);
        return status;
    }
    if (!bootstrap_probe_is_waitable(session.probe)) {
        session.probe = CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }

    session.generation_observed = bootstrap_probe_has_generation(session.probe);
    bootstrap_session_run(&session);
    bootstrap_session_release_lock(&session);
    if (bootstrap_probe_is_finishable(session.probe)) {
        cbm_daemon_bootstrap_status_t status = bootstrap_finish_probe(
            session.probe, session.client, &session.connect_result, ops, result_out);
        ops->cohort_release(ops->context, session.cohort);
        return status;
    }

    bootstrap_session_report_failure(&session);
    ops->cohort_release(ops->context, session.cohort);
    return result_out->status;
}

cbm_daemon_bootstrap_probe_status_t cbm_daemon_bootstrap_classify_failed_connect(
    const cbm_daemon_runtime_connect_result_t *connect_result, int lifetime_status) {
    if (!connect_result) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }
    if (connect_result->status == CBM_DAEMON_RUNTIME_CONNECT_CONFLICT) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_CONFLICT;
    }
    if (connect_result->status == CBM_DAEMON_RUNTIME_CONNECT_REJECTED) {
        if (strstr(connect_result->message, "stopping") ||
            strstr(connect_result->message, "shutting down")) {
            return CBM_DAEMON_BOOTSTRAP_PROBE_TERMINAL;
        }
        /* Capacity, admission, and other protocol-level rejections prove an
         * existing generation answered. Never reinterpret them as absence. */
        return CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED;
    }
    if (lifetime_status == BOOTSTRAP_LIFETIME_STATUS_HELD) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_RESERVED;
    }
    if (lifetime_status != BOOTSTRAP_LIFETIME_STATUS_FREE) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }
    return connect_result->status == CBM_DAEMON_RUNTIME_CONNECT_ERROR
               ? CBM_DAEMON_BOOTSTRAP_PROBE_UNAVAILABLE
               : CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
}

typedef struct bootstrap_production_cohort {
    cbm_version_cohort_manager_t *manager;
    cbm_version_cohort_lease_t *lease;
} bootstrap_production_cohort_t;

typedef struct {
    bootstrap_production_cohort_t *cohort;
#ifdef _WIN32
    DWORD spawn_error;
#elif defined(__APPLE__)
    int spawn_error;
#endif
} bootstrap_production_context_t;

static cbm_daemon_bootstrap_probe_status_t bootstrap_production_probe(
    void *context, const cbm_daemon_ipc_endpoint_t *endpoint,
    const cbm_daemon_build_identity_t *identity, uint32_t timeout_ms,
    cbm_daemon_runtime_client_t **client_out, cbm_daemon_runtime_connect_result_t *result_out) {
    bootstrap_production_context_t *production = context;
    if (!production || !production->cohort || !production->cohort->manager) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }
    cbm_version_cohort_daemon_presence_t claim =
        cbm_version_cohort_daemon_claim_presence(production->cohort->manager);
    if (claim == CBM_VERSION_COHORT_DAEMON_ABSENT) {
        int lifetime = cbm_daemon_ipc_lifetime_reservation_probe(endpoint);
        if (lifetime == BOOTSTRAP_LIFETIME_STATUS_FREE) {
            /* Do not spend the per-connect timeout polling a generation that
             * both independent ownership signals prove absent. The startup
             * lock and its mandatory re-probe serialize a concurrent launch. */
            return CBM_DAEMON_BOOTSTRAP_PROBE_UNAVAILABLE;
        }
        if (lifetime != BOOTSTRAP_LIFETIME_STATUS_HELD) {
            return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
        }
    } else if (claim != CBM_VERSION_COHORT_DAEMON_COORDINATED) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }

    *client_out = cbm_daemon_runtime_client_connect(endpoint, identity, timeout_ms, result_out);
    if (*client_out) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_CONNECTED;
    }

    /* Ownership may turn over while the connection attempt is in flight.
     * Re-observe both signals so disappearance is not sticky and a live or
     * cleaning-up generation is never mistaken for absence. */
    claim = cbm_version_cohort_daemon_claim_presence(production->cohort->manager);
    if (claim == CBM_VERSION_COHORT_DAEMON_COORDINATED) {
        return cbm_daemon_bootstrap_classify_failed_connect(result_out,
                                                            BOOTSTRAP_LIFETIME_STATUS_HELD);
    }
    if (claim != CBM_VERSION_COHORT_DAEMON_ABSENT) {
        return CBM_DAEMON_BOOTSTRAP_PROBE_ERROR;
    }
    int lifetime_status = cbm_daemon_ipc_lifetime_reservation_probe(endpoint);
    return cbm_daemon_bootstrap_classify_failed_connect(result_out, lifetime_status);
}

static cbm_version_cohort_status_t bootstrap_production_cohort_acquire(
    void *context, const cbm_daemon_ipc_endpoint_t *endpoint,
    const cbm_daemon_build_identity_t *identity, uint64_t deadline_ms,
    cbm_daemon_bootstrap_cohort_t *cohort_out, cbm_daemon_conflict_t *conflict_out) {
    *cohort_out = NULL;
    bootstrap_production_cohort_t *cohort =
        calloc(BOOTSTRAP_ALLOCATION_ELEMENT_COUNT, sizeof(*cohort));
    if (cohort) {
        cohort->manager = cbm_version_cohort_manager_new(endpoint);
    }
    if (!cohort || !cohort->manager) {
        free(cohort);
        return CBM_VERSION_COHORT_IO;
    }
    cbm_version_cohort_status_t status = cbm_version_cohort_acquire(
        cohort->manager, identity, deadline_ms, &cohort->lease, conflict_out);
    if (status == CBM_VERSION_COHORT_CONFLICT) {
        (void)cbm_version_cohort_log_conflict(conflict_out);
    }
    if (status == CBM_VERSION_COHORT_OK || cohort->lease) {
        *cohort_out = cohort;
        if (context) {
            bootstrap_production_context_t *production = context;
            production->cohort = cohort;
        }
        return status;
    }
    uint64_t cleanup_deadline = bootstrap_deadline_after(BOOTSTRAP_COORDINATION_CLEANUP_MS);
    cbm_private_file_lock_status_t cleanup = CBM_PRIVATE_FILE_LOCK_OK;
    while (cohort->manager) {
        cleanup = cbm_version_cohort_manager_free(&cohort->manager);
        if (!cohort->manager) {
            break;
        }
        if (cbm_now_ms() >= cleanup_deadline) {
            bootstrap_cleanup_fail_stop("cohort_manager_cleanup");
        }
        cbm_usleep(1000);
    }
    free(cohort);
    return cleanup == CBM_PRIVATE_FILE_LOCK_OK ? status : CBM_VERSION_COHORT_IO;
}

static void bootstrap_production_cohort_release(void *context,
                                                cbm_daemon_bootstrap_cohort_t opaque) {
    bootstrap_production_context_t *production = context;
    bootstrap_production_cohort_t *cohort = opaque;
    if (!cohort) {
        return;
    }
    uint64_t cleanup_deadline = bootstrap_deadline_after(BOOTSTRAP_COORDINATION_CLEANUP_MS);
    while (cohort->lease) {
        (void)cbm_version_cohort_lease_release(&cohort->lease);
        if (!cohort->lease) {
            break;
        }
        if (cbm_now_ms() >= cleanup_deadline) {
            bootstrap_cleanup_fail_stop("cohort_lease_cleanup");
        }
        cbm_usleep(1000);
    }
    cleanup_deadline = bootstrap_deadline_after(BOOTSTRAP_COORDINATION_CLEANUP_MS);
    while (cohort->manager) {
        (void)cbm_version_cohort_manager_free(&cohort->manager);
        if (!cohort->manager) {
            break;
        }
        if (cbm_now_ms() >= cleanup_deadline) {
            bootstrap_cleanup_fail_stop("cohort_manager_cleanup");
        }
        cbm_usleep(1000);
    }
    if (production && production->cohort == cohort) {
        production->cohort = NULL;
    }
    free(cohort);
}

static int bootstrap_production_lock(void *context, const cbm_daemon_ipc_endpoint_t *endpoint,
                                     cbm_daemon_bootstrap_lock_t *lock_out) {
    (void)context;
    cbm_daemon_ipc_startup_lock_t *lock = NULL;
    int status = cbm_daemon_ipc_startup_lock_try_acquire(endpoint, &lock);
    *lock_out = lock;
    return status;
}

static bool bootstrap_production_unlock(void *context, cbm_daemon_bootstrap_lock_t *lock_io) {
    (void)context;
    if (!lock_io) {
        return false;
    }
    cbm_daemon_ipc_startup_lock_t *lock = *lock_io;
    bool released = cbm_daemon_ipc_startup_lock_release(&lock);
    *lock_io = lock;
    return released;
}

static bool bootstrap_production_handoff(void *context, cbm_daemon_bootstrap_lock_t lock) {
    (void)context;
    return cbm_daemon_ipc_startup_lock_prepare_handoff((cbm_daemon_ipc_startup_lock_t *)lock);
}

#ifdef _WIN32
static bool bootstrap_production_spawn(void *context,
                                       const cbm_daemon_bootstrap_launch_spec_t *spec) {
    bootstrap_production_context_t *production = context;
    if (production) {
        production->spawn_error = ERROR_SUCCESS;
    }
    if (!spec || !spec->detached || spec->inherit_standard_handles || spec->use_shell) {
        if (production) {
            production->spawn_error = ERROR_INVALID_PARAMETER;
        }
        return false;
    }
    char command_line[BOOTSTRAP_PATH_CAP * 2];
    if (!cbm_build_win_cmdline(command_line, sizeof(command_line), spec->argv)) {
        if (production) {
            production->spawn_error = ERROR_INVALID_PARAMETER;
        }
        return false;
    }
    wchar_t *application = cbm_utf8_to_wide(spec->executable_path);
    wchar_t *command = cbm_utf8_to_wide(command_line);
    if (!application || !command) {
        if (production) {
            production->spawn_error = ERROR_NOT_ENOUGH_MEMORY;
        }
        free(application);
        free(command);
        return false;
    }
    STARTUPINFOW startup;
    PROCESS_INFORMATION child;
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&child, sizeof(child));
    startup.cb = sizeof(startup);
    DWORD flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
    /* A managed frontend payload is intentionally contained in the permanent
     * launcher's kill-on-close job. The account daemon outlives that one
     * frontend and therefore uses breakaway when the containing job explicitly
     * permits it. Do not request breakaway from an unrelated restrictive job:
     * CreateProcess would fail and regress portable/package-manager payloads. */
    BOOL in_job = FALSE;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits;
    memset(&job_limits, 0, sizeof(job_limits));
    if (IsProcessInJob(GetCurrentProcess(), NULL, &in_job) && in_job &&
        QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation, &job_limits,
                                  sizeof(job_limits), NULL) &&
        (job_limits.BasicLimitInformation.LimitFlags &
         (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)) != 0) {
        flags |= CREATE_BREAKAWAY_FROM_JOB;
    }
    BOOL created = CreateProcessW(application, command, NULL, NULL, FALSE, flags, NULL, NULL,
                                  &startup, &child);
    DWORD spawn_error = created ? ERROR_SUCCESS : GetLastError();
    free(application);
    free(command);
    if (production) {
        production->spawn_error = spawn_error;
    }
    if (!created) {
        return false;
    }
    (void)CloseHandle(child.hThread);
    (void)CloseHandle(child.hProcess);
    return true;
}
#elif defined(__APPLE__)
static bool bootstrap_darwin_spawn_state_init(posix_spawn_file_actions_t *actions,
                                              posix_spawnattr_t *attributes) {
    if (posix_spawn_file_actions_init(actions) != 0) {
        return false;
    }
    bool actions_ready =
        posix_spawn_file_actions_addopen(actions, STDIN_FILENO, "/dev/null", O_RDWR, 0) == 0 &&
        posix_spawn_file_actions_addopen(actions, STDOUT_FILENO, "/dev/null", O_RDWR, 0) == 0 &&
        posix_spawn_file_actions_addopen(actions, STDERR_FILENO, "/dev/null", O_RDWR, 0) == 0;
    if (!actions_ready) {
        (void)posix_spawn_file_actions_destroy(actions);
        return false;
    }
    if (posix_spawnattr_init(attributes) != 0) {
        (void)posix_spawn_file_actions_destroy(actions);
        return false;
    }
    sigset_t empty;
    (void)sigemptyset(&empty);
    short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT;
    if (posix_spawnattr_setsigmask(attributes, &empty) != 0 ||
        posix_spawnattr_setflags(attributes, flags) != 0) {
        (void)posix_spawnattr_destroy(attributes);
        (void)posix_spawn_file_actions_destroy(actions);
        return false;
    }
    return true;
}

typedef struct {
    pid_t pid;
} bootstrap_darwin_reaper_t;

static void *bootstrap_darwin_reap(void *opaque) {
    bootstrap_darwin_reaper_t *reaper = opaque;
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(reaper->pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    free(reaper);
    return NULL;
}

static bool bootstrap_darwin_reaper_start(pid_t daemon) {
    bootstrap_darwin_reaper_t *reaper = malloc(sizeof(*reaper));
    if (!reaper) {
        return false;
    }
    reaper->pid = daemon;
    pthread_attr_t attributes;
    bool attributes_ready = pthread_attr_init(&attributes) == 0;
    bool detached =
        attributes_ready && pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0;
    pthread_t thread;
    int thread_status = detached
                            ? pthread_create(&thread, &attributes, bootstrap_darwin_reap, reaper)
                            : BOOTSTRAP_THREAD_START_FAILURE;
    if (attributes_ready) {
        (void)pthread_attr_destroy(&attributes);
    }
    if (thread_status != 0) {
        free(reaper);
        return false;
    }
    return true;
}

static bool bootstrap_production_spawn(void *context,
                                       const cbm_daemon_bootstrap_launch_spec_t *spec) {
    bootstrap_production_context_t *production = context;
    if (production) {
        production->spawn_error = 0;
    }
    if (!spec || !spec->detached || spec->inherit_standard_handles || spec->use_shell) {
        return false;
    }
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    if (!bootstrap_darwin_spawn_state_init(&actions, &attributes)) {
        return false;
    }
    /* Calling library-heavy process creation between fork() and exec is not a
     * safe boundary once another thread may own libc state. Darwin's spawn
     * primitive can create the detached session and close inherited FDs in
     * one operation, so launch it from the original process and retain only a
     * tiny detached waiter to prevent a crashed daemon from becoming a
     * long-lived zombie owned by the first frontend. */
    pid_t daemon = 0;
    /* posix_spawn takes char *const argv[] for historical reasons; POSIX
     * guarantees it does not modify the strings. spec->argv holds string
     * literals and must stay const, so copy the pointer values into a mutable
     * vector for the call. Each element is read from &spec->argv[i] — the
     * address of that element — not from &spec->argv, which is the address of
     * the array and would copy argv[0]'s bytes in place of the array. */
    char *spawn_argv[CBM_DAEMON_BOOTSTRAP_LAUNCH_ARGC + BOOTSTRAP_POSIX_SPAWN_ARGV_TERMINATOR];
    for (size_t i = 0; i < sizeof(spawn_argv) / sizeof(spawn_argv[0]); i++) {
        memcpy(&spawn_argv[i], &spec->argv[i], sizeof(spawn_argv[i]));
    }
    int spawn_status =
        posix_spawn(&daemon, spec->executable_path, &actions, &attributes, spawn_argv, environ);
    (void)posix_spawnattr_destroy(&attributes);
    (void)posix_spawn_file_actions_destroy(&actions);
    if (production) {
        production->spawn_error = spawn_status;
    }
    if (spawn_status != 0) {
        return false;
    }
    if (!bootstrap_darwin_reaper_start(daemon)) {
        (void)kill(daemon, SIGKILL);
        int status = 0;
        while (waitpid(daemon, &status, 0) < 0 && errno == EINTR) {}
        if (production) {
            production->spawn_error = EAGAIN;
        }
        return false;
    }
    return true;
}
#else
static void bootstrap_child_close_fds(void) {
    long open_max = sysconf(_SC_OPEN_MAX);
    if (open_max < 0 || open_max > 1048576L) {
        open_max = 65536L;
    }
    for (int fd = 3; fd < open_max; fd++) {
        (void)close(fd);
    }
}

static void bootstrap_daemon_grandchild(const cbm_daemon_bootstrap_launch_spec_t *spec) {
    (void)umask(077);
    sigset_t empty;
    (void)sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 || dup2(null_fd, STDOUT_FILENO) < 0 ||
        dup2(null_fd, STDERR_FILENO) < 0) {
        _exit(127);
    }
    if (null_fd > STDERR_FILENO) {
        (void)close(null_fd);
    }
    bootstrap_child_close_fds();
    execv(spec->executable_path, (char *const *)spec->argv);
    _exit(127);
}

static bool bootstrap_production_spawn(void *context,
                                       const cbm_daemon_bootstrap_launch_spec_t *spec) {
    (void)context;
    if (!spec || !spec->detached || spec->inherit_standard_handles || spec->use_shell) {
        return false;
    }
    pid_t first = fork();
    if (first < 0) {
        return false;
    }
    if (first == 0) {
        if (setsid() < 0) {
            _exit(127);
        }
        pid_t daemon = fork();
        if (daemon < 0) {
            _exit(127);
        }
        if (daemon > 0) {
            _exit(0);
        }
        bootstrap_daemon_grandchild(spec);
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(first, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == first && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

static void bootstrap_production_diagnostic(void *context, const char *message) {
    bootstrap_production_context_t *production = context;
#ifdef _WIN32
    if (production && production->spawn_error != ERROR_SUCCESS) {
        (void)fprintf(stderr, "codebase-memory-mcp: %s (daemon launch error %lu)\n",
                      message ? message : "daemon startup failed",
                      (unsigned long)production->spawn_error);
        (void)fflush(stderr);
        return;
    }
#elif defined(__APPLE__)
    if (production && production->spawn_error != 0) {
        (void)fprintf(stderr, "codebase-memory-mcp: %s (daemon launch: %s)\n",
                      message ? message : "daemon startup failed",
                      strerror(production->spawn_error));
        (void)fflush(stderr);
        return;
    }
#else
    (void)production;
#endif
    (void)fprintf(stderr, "codebase-memory-mcp: %s\n", message ? message : "daemon startup failed");
    (void)fflush(stderr);
}

cbm_daemon_bootstrap_status_t cbm_daemon_bootstrap_execute(
    const cbm_daemon_bootstrap_config_t *config, cbm_daemon_bootstrap_result_t *result_out) {
    bootstrap_production_context_t context = {0};
    const cbm_daemon_bootstrap_ops_t ops = {
        .context = &context,
        .cohort_acquire = bootstrap_production_cohort_acquire,
        .cohort_release = bootstrap_production_cohort_release,
        .probe = bootstrap_production_probe,
        .startup_lock_try_acquire = bootstrap_production_lock,
        .startup_lock_prepare_handoff = bootstrap_production_handoff,
        .startup_lock_release = bootstrap_production_unlock,
        .spawn_daemon = bootstrap_production_spawn,
        .visible_diagnostic = bootstrap_production_diagnostic,
    };
    return cbm_daemon_bootstrap_execute_with_ops(config, &ops, result_out);
}
