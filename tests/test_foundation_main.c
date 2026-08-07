/*
 * test_foundation_main.c — Entry point for the foundation-only test binary.
 *
 * Runs just the suites defined by TEST_FOUNDATION_SRCS, giving a fast
 * edit-build-test loop while working on src/foundation. The full runner
 * (tests/test_main.c) takes tens of minutes; this one takes seconds.
 *
 * Suite selection, --list-suites and unknown-suite reporting come from
 * suite_runner.h, shared with the full runner so the two cannot drift.
 *
 * Only foundation code is linked here, so none of the extraction, sqlite or
 * daemon caches the full runner releases exist to release. Nor are the
 * subprocess probe handlers in test_main.c needed: no foundation suite
 * re-executes this binary as a helper.
 *
 * A suite added to TEST_FOUNDATION_SRCS is added here too.
 */
#include "suite_runner.h"
#include "suites.h"
#include "test_framework.h"

int main(int argc, char **argv) {
    int selection_rc = suite_runner_begin(argc, argv);
    if (selection_rc >= 0) {
        return selection_rc;
    }
    if (!g_list_only) {
        printf("\n  codebase-memory-mcp  foundation test suite\n");
    }

    RUN_SELECTED_SUITE(arena);
    RUN_SELECTED_SUITE(hash_table);
    RUN_SELECTED_SUITE(dyn_array);
    RUN_SELECTED_SUITE(str_intern);
    RUN_SELECTED_SUITE(log);
    RUN_SELECTED_SUITE(str_util);
    RUN_SELECTED_SUITE(workspace);
    RUN_SELECTED_SUITE(platform);
    RUN_SELECTED_SUITE(diagnostics);
    RUN_SELECTED_SUITE(dump_verify);
    RUN_SELECTED_SUITE(subprocess);
    RUN_SELECTED_SUITE(private_file_lock);
    RUN_SELECTED_SUITE(lock_registry);

    if (g_list_only) {
        fflush(stdout);
        return 0;
    }
    suite_runner_report_unmatched();
    TEST_SUMMARY();
}
