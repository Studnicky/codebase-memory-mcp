/*
 * suite_runner.h — Suite selection shared by the test runners.
 *
 * Two binaries have a main(): tests/test_main.c runs every suite, and
 * tests/test_foundation_main.c runs only the foundation ones for a fast
 * edit-build-test loop. Both select suites from argv, both support
 * --list-suites, and both report unrecognised suite names the same way, so
 * that machinery lives here instead of in each main.
 *
 * The definitions are static: exactly one main translation unit per binary
 * includes this header, so there is nothing to link and no duplicate symbol.
 *
 * Each main keeps its OWN cleanup. The full runner releases extraction and
 * sqlite caches that the foundation binary does not even link.
 *
 * Usage:
 *     int rc = suite_runner_begin(argc, argv);
 *     if (rc >= 0) { return rc; }
 *     RUN_SELECTED_SUITE(arena);
 *     ...
 *     if (suite_runner_list_only()) { <cleanup>; return 0; }
 *     suite_runner_report_unmatched();
 *     <cleanup>;
 *     TEST_SUMMARY();
 */
#ifndef CBM_TESTS_SUITE_RUNNER_H
#define CBM_TESTS_SUITE_RUNNER_H

#include "test_framework.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The counters test_framework.h declares extern. They live here rather than in
 * a runner because every binary needs exactly one definition and exactly one
 * main includes this header. */
int tf_pass_count = 0;
int tf_fail_count = 0;
int tf_skip_count = 0;

static int g_suite_argc = 0;
static char **g_suite_argv = NULL;
static bool *g_suite_arg_matched = NULL;

/* --list-suites: print every registered suite name, one per line, without
 * running anything. The list and the run share this ONE macro table, so the
 * list can never drift from what actually executes — shard runners (make
 * test-par, the CI shard matrix) enumerate suites from here and their union
 * guard compares against it. */
static bool g_list_only = false;

/* CBM_SKIP_PERF=1 excludes throughput/scale/perf-metric suites from the run.
 * The fidelity pass (CBM_LOCAL_CI_CPUS=4) and CI PRs set it: those suites
 * measure performance, which is meaningless under artificial CPU starvation,
 * and they dominate wall-clock. Correctness coverage is unaffected — the perf
 * suites run at full power in the perf/release legs (CBM_SKIP_PERF unset). The
 * skip applies to BOTH --list-suites and the run through the same macro, so
 * the shard union guard stays consistent. */
static bool g_skip_perf = false;

static bool suite_requested(const char *name) {
    if (g_suite_argc <= 1) {
        return true;
    }
    bool requested = false;
    for (int i = 1; i < g_suite_argc; i++) {
        if (strcmp(g_suite_argv[i], name) == 0) {
            g_suite_arg_matched[i] = true;
            requested = true;
        }
    }
    return requested;
}

#define RUN_SELECTED_SUITE(name)             \
    do {                                     \
        if (g_list_only) {                   \
            printf("%s\n", #name);           \
        } else if (suite_requested(#name)) { \
            RUN_SUITE(name);                 \
        }                                    \
    } while (0)

#define RUN_SELECTED_SUITE_PERF(name)        \
    do {                                     \
        if (g_skip_perf) {                   \
            break;                           \
        }                                    \
        if (g_list_only) {                   \
            printf("%s\n", #name);           \
        } else if (suite_requested(#name)) { \
            RUN_SUITE(name);                 \
        }                                    \
    } while (0)

/* Parse suite selection out of argv. Returns a process exit code when the
 * caller must stop immediately, or -1 to carry on and run suites. */
static int suite_runner_begin(int argc, char **argv) {
    const char *skip_perf_env = getenv("CBM_SKIP_PERF");
    g_skip_perf = skip_perf_env != NULL && strcmp(skip_perf_env, "1") == 0;
    if (argc == 2 && strcmp(argv[1], "--list-suites") == 0) {
        g_list_only = true;
        g_suite_argc = 1; /* no suite-name args to match */
    } else {
        g_suite_argc = argc;
        g_suite_argv = argv;
    }
    if (g_suite_argc > 1) {
        g_suite_arg_matched = calloc((size_t)argc, sizeof(*g_suite_arg_matched));
        if (!g_suite_arg_matched) {
            fprintf(stderr, "Failed to allocate test-suite argument tracking\n");
            return 1;
        }
    }
    return -1;
}

/* A suite name on the command line that matched nothing is a failure, not a
 * silent no-op: it usually means a typo or a renamed suite, and reporting zero
 * failures for a run that executed nothing would read as success. */
static void suite_runner_report_unmatched(void) {
    bool any_suite_matched = false;
    for (int i = 1; i < g_suite_argc; i++) {
        any_suite_matched = any_suite_matched || g_suite_arg_matched[i];
    }
    fflush(stdout);
    for (int i = 1; i < g_suite_argc; i++) {
        if (!g_suite_arg_matched[i]) {
            fprintf(stderr, "Unknown test suite: %s\n", g_suite_argv[i]);
            tf_fail_count++;
        }
    }
    if (g_suite_argc > 1 && !any_suite_matched) {
        fprintf(stderr, "No matching test suites requested\n");
    }
    free(g_suite_arg_matched);
    g_suite_arg_matched = NULL;
}

#endif /* CBM_TESTS_SUITE_RUNNER_H */
