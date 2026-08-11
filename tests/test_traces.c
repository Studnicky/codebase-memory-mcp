/*
 * test_traces.c — Tests for OTLP trace processing helpers.
 *
 * Ported from internal/traces/traces_test.go (5 pure helper tests).
 * The TestIngestOTLPJSON integration test is deferred (needs full MCP pipeline).
 */
#include "test_framework.h"
#include "suites.h"
#include <foundation/compat_thread.h>
#include <traces/traces.h>
#include <stdatomic.h>
#include <string.h>

/* ── TestExtractServiceName ─────────────────────────────────────── */

TEST(traces_extract_service_name) {
    cbm_trace_attr_t attrs[] = {
        {.key = "service.name", .string_value = "order-service"},
    };
    cbm_trace_resource_t r = {.attributes = attrs, .attr_count = 1};

    const char *name = cbm_extract_service_name(&r);
    ASSERT_STR_EQ(name, "order-service");
    PASS();
}

TEST(traces_extract_service_name_missing) {
    cbm_trace_attr_t attrs[] = {
        {.key = "other.attr", .string_value = "value"},
    };
    cbm_trace_resource_t r = {.attributes = attrs, .attr_count = 1};

    const char *name = cbm_extract_service_name(&r);
    ASSERT_STR_EQ(name, "");
    PASS();
}

TEST(traces_extract_service_name_null) {
    const char *name = cbm_extract_service_name(NULL);
    ASSERT_STR_EQ(name, "");
    PASS();
}

/* ── TestExtractHTTPInfo ────────────────────────────────────────── */

TEST(traces_extract_http_info) {
    cbm_trace_attr_t attrs[] = {
        {.key = "http.method", .string_value = "GET"},
        {.key = "http.route", .string_value = "/api/orders"},
        {.key = "http.status_code", .string_value = "200"},
    };
    cbm_trace_span_t span = {
        .kind = 2,
        .attributes = attrs,
        .attr_count = 3,
        .start_time = "1000000000",
        .end_time = "1050000000",
    };

    cbm_http_span_info_t info;
    bool ok = cbm_extract_http_info(&span, "svc", &info);
    ASSERT(ok);
    ASSERT_STR_EQ(info.method, "GET");
    ASSERT_STR_EQ(info.path, "/api/orders");
    ASSERT_EQ(info.duration_ns, 50000000);
    ASSERT_EQ(info.span_kind, 2);
    PASS();
}

/* ── TestExtractHTTPInfoNonHTTPSpan ─────────────────────────────── */

TEST(traces_extract_http_info_non_http) {
    cbm_trace_attr_t attrs[] = {
        {.key = "db.system", .string_value = "postgresql"},
    };
    cbm_trace_span_t span = {
        .kind = 1,
        .attributes = attrs,
        .attr_count = 1,
    };

    cbm_http_span_info_t info;
    bool ok = cbm_extract_http_info(&span, "svc", &info);
    ASSERT(!ok);
    PASS();
}

/* ── TestExtractHTTPInfo with url.full ──────────────────────────── */

TEST(traces_extract_http_info_url_full) {
    cbm_trace_attr_t attrs[] = {
        {.key = "http.method", .string_value = "GET"},
        {.key = "url.full", .string_value = "https://example.com/api/items?page=1"},
    };
    cbm_trace_span_t span = {
        .kind = 2,
        .attributes = attrs,
        .attr_count = 2,
        .start_time = "2000000000",
        .end_time = "2100000000",
    };

    cbm_http_span_info_t info;
    bool ok = cbm_extract_http_info(&span, "svc", &info);
    ASSERT(ok);
    ASSERT_STR_EQ(info.path, "/api/items");
    ASSERT_EQ(info.duration_ns, 100000000);
    PASS();
}

TEST(traces_extract_http_info_url_full_results_stay_distinct) {
    cbm_trace_attr_t first_attrs[] = {
        {.key = "http.method", .string_value = "GET"},
        {.key = "url.full", .string_value = "https://example.com/accounts?active=true"},
    };
    cbm_trace_attr_t second_attrs[] = {
        {.key = "http.method", .string_value = "GET"},
        {.key = "url.full", .string_value = "https://example.com/orders?limit=10"},
    };
    cbm_trace_span_t first_span = {.kind = 2, .attributes = first_attrs, .attr_count = 2};
    cbm_trace_span_t second_span = {.kind = 2, .attributes = second_attrs, .attr_count = 2};
    cbm_http_span_info_t first;
    cbm_http_span_info_t second;

    ASSERT(cbm_extract_http_info(&first_span, "svc", &first));
    ASSERT(cbm_extract_http_info(&second_span, "svc", &second));
    ASSERT_TRUE(first.path == first.url_path);
    ASSERT_TRUE(second.path == second.url_path);
    ASSERT_STR_EQ(first.path, "/accounts");
    ASSERT_STR_EQ(second.path, "/orders");
    ASSERT_TRUE(first.path != second.path);
    PASS();
}

typedef struct {
    const char *url;
    const char *expected_path;
    atomic_int *ready;
    atomic_bool *go;
    cbm_http_span_info_t info;
    bool succeeded;
} trace_url_extract_worker_t;

static void *trace_url_extract_worker_run(void *opaque) {
    trace_url_extract_worker_t *worker = opaque;
    cbm_trace_attr_t attrs[] = {
        {.key = "http.method", .string_value = "GET"},
        {.key = "url.full", .string_value = worker->url},
    };
    cbm_trace_span_t span = {.kind = 2, .attributes = attrs, .attr_count = 2};

    atomic_fetch_add_explicit(worker->ready, 1, memory_order_release);
    while (!atomic_load_explicit(worker->go, memory_order_acquire)) {
    }
    worker->succeeded = cbm_extract_http_info(&span, "svc", &worker->info) &&
                        strcmp(worker->info.path, worker->expected_path) == 0;
    return NULL;
}

TEST(traces_extract_http_info_url_full_concurrent_results_stay_distinct) {
    static const char *const urls[] = {
        "https://example.com/alpha?one=1",
        "https://example.com/bravo?two=2",
        "https://example.com/charlie?three=3",
        "https://example.com/delta?four=4",
        "https://example.com/echo?five=5",
        "https://example.com/foxtrot?six=6",
        "https://example.com/golf?seven=7",
        "https://example.com/hotel?eight=8",
    };
    static const char *const paths[] = {
        "/alpha", "/bravo", "/charlie", "/delta", "/echo", "/foxtrot", "/golf", "/hotel",
    };
    enum { WORKER_COUNT = (int)(sizeof(urls) / sizeof(urls[0])) };
    trace_url_extract_worker_t workers[WORKER_COUNT] = {0};
    cbm_thread_t threads[WORKER_COUNT];
    atomic_int ready;
    atomic_bool go;
    atomic_init(&ready, 0);
    atomic_init(&go, false);

    int created = 0;
    for (; created < WORKER_COUNT; created++) {
        workers[created].url = urls[created];
        workers[created].expected_path = paths[created];
        workers[created].ready = &ready;
        workers[created].go = &go;
        if (cbm_thread_create(&threads[created], 0, trace_url_extract_worker_run, &workers[created]) !=
            0) {
            break;
        }
    }
    bool all_created = created == WORKER_COUNT;
    while (all_created && atomic_load_explicit(&ready, memory_order_acquire) != WORKER_COUNT) {
    }
    atomic_store_explicit(&go, true, memory_order_release);

    bool all_joined = true;
    for (int i = 0; i < created; i++) {
        all_joined = cbm_thread_join(&threads[i]) == 0 && all_joined;
    }

    ASSERT_TRUE(all_created);
    ASSERT_TRUE(all_joined);
    for (int i = 0; i < WORKER_COUNT; i++) {
        ASSERT_TRUE(workers[i].succeeded);
        ASSERT_TRUE(workers[i].info.path == workers[i].info.url_path);
        ASSERT_STR_EQ(workers[i].info.path, paths[i]);
    }
    PASS();
}

/* ── TestExtractServiceName — edge cases ───────────────────────── */

TEST(traces_extract_service_name_empty_attrs) {
    cbm_trace_resource_t r = {.attributes = NULL, .attr_count = 0};
    const char *name = cbm_extract_service_name(&r);
    ASSERT_STR_EQ(name, "");
    PASS();
}

TEST(traces_extract_service_name_multiple_attrs) {
    /* service.name is present but not the first attribute */
    cbm_trace_attr_t attrs[] = {
        {.key = "deployment.environment", .string_value = "production"},
        {.key = "telemetry.sdk.language", .string_value = "go"},
        {.key = "service.name", .string_value = "payment-gateway"},
    };
    cbm_trace_resource_t r = {.attributes = attrs, .attr_count = 3};
    const char *name = cbm_extract_service_name(&r);
    ASSERT_STR_EQ(name, "payment-gateway");
    PASS();
}

/* ── TestExtractPathFromURL ─────────────────────────────────────── */

TEST(traces_extract_path_from_url) {
    char buf[256];

    cbm_extract_path_from_url("https://example.com/api/orders", buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "/api/orders");

    cbm_extract_path_from_url("http://localhost:8080/health?check=true", buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "/health");

    cbm_extract_path_from_url("not-a-url", buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "");

    cbm_extract_path_from_url("https://example.com/", buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "/");

    PASS();
}

/* ── TestExtractPathFromURL — edge cases ──────────────────────── */

TEST(traces_extract_path_null_url) {
    char buf[256] = "untouched";
    const char *result = cbm_extract_path_from_url(NULL, buf, sizeof(buf));
    ASSERT_STR_EQ(result, "");
    PASS();
}

TEST(traces_extract_path_empty_url) {
    char buf[256];
    cbm_extract_path_from_url("", buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "");
    PASS();
}

TEST(traces_extract_path_with_port) {
    char buf[256];
    cbm_extract_path_from_url("https://api.example.com:8443/v2/users", buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "/v2/users");
    PASS();
}

TEST(traces_extract_path_with_query_and_fragment) {
    char buf[256];
    /* Query params should be stripped (stops at '?') */
    cbm_extract_path_from_url("https://example.com/search?q=test&page=2", buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "/search");
    PASS();
}

TEST(traces_extract_path_buffer_too_small) {
    char buf[4]; /* only 4 bytes — path "/api/orders" gets truncated */
    cbm_extract_path_from_url("https://example.com/api/orders", buf, sizeof(buf));
    /* Should truncate safely to 3 chars + NUL */
    ASSERT_EQ(strlen(buf), 3);
    ASSERT_STR_EQ(buf, "/ap");
    PASS();
}

TEST(traces_extract_path_relative_path) {
    /* No scheme — "relative/path" has fewer than 3 slashes → empty */
    char buf[256];
    cbm_extract_path_from_url("/api/orders", buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "");
    PASS();
}

/* ── TestCalculateP99 ───────────────────────────────────────────── */

TEST(traces_calculate_p99) {
    int64_t values[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    int64_t p99 = cbm_calculate_p99(values, 10);
    ASSERT_EQ(p99, 100);
    PASS();
}

TEST(traces_calculate_p99_single) {
    int64_t values[] = {42};
    int64_t p99 = cbm_calculate_p99(values, 1);
    ASSERT_EQ(p99, 42);
    PASS();
}

TEST(traces_calculate_p99_empty) {
    int64_t p99 = cbm_calculate_p99(NULL, 0);
    ASSERT_EQ(p99, 0);
    PASS();
}

/* ── TestParseDuration ──────────────────────────────────────────── */

TEST(traces_parse_duration) {
    int64_t d = cbm_parse_duration("1000000000", "1050000000");
    ASSERT_EQ(d, 50000000);
    PASS();
}

TEST(traces_parse_duration_zero) {
    int64_t d = cbm_parse_duration("1000", "500");
    ASSERT_EQ(d, 0); /* end < start → 0 */
    PASS();
}

/* ── TestParseDuration — edge cases ──────────────────────────────── */

TEST(traces_parse_duration_null_start) {
    int64_t d = cbm_parse_duration(NULL, "1000");
    ASSERT_EQ(d, 0);
    PASS();
}

TEST(traces_parse_duration_null_end) {
    int64_t d = cbm_parse_duration("1000", NULL);
    ASSERT_EQ(d, 0);
    PASS();
}

TEST(traces_parse_duration_both_null) {
    int64_t d = cbm_parse_duration(NULL, NULL);
    ASSERT_EQ(d, 0);
    PASS();
}

TEST(traces_parse_duration_equal) {
    /* Same start and end → 0 */
    int64_t d = cbm_parse_duration("5000000000", "5000000000");
    ASSERT_EQ(d, 0);
    PASS();
}

TEST(traces_parse_duration_large_values) {
    /* Realistic nanosecond timestamps (epoch ~2024) */
    int64_t d = cbm_parse_duration("1700000000000000000", "1700000000050000000");
    ASSERT_EQ(d, 50000000); /* 50ms */
    PASS();
}

/* ── TestCalculateP99 — edge cases ────────────────────────────────── */

TEST(traces_calculate_p99_100_values) {
    int64_t values[100];
    for (int i = 0; i < 100; i++) {
        values[i] = (int64_t)(i + 1); /* 1..100 */
    }
    int64_t p99 = cbm_calculate_p99(values, 100);
    /* idx = (int)(100 * 0.99) = 99, values[99] = 100 */
    ASSERT_EQ(p99, 100);
    PASS();
}

TEST(traces_calculate_p99_reversed) {
    /* Reversed array — qsort should sort first */
    int64_t values[10] = {100, 90, 80, 70, 60, 50, 40, 30, 20, 10};
    int64_t p99 = cbm_calculate_p99(values, 10);
    /* After sort: 10..100, idx = (int)(10 * 0.99) = 9, values[9] = 100 */
    ASSERT_EQ(p99, 100);
    PASS();
}

TEST(traces_calculate_p99_two_values) {
    int64_t values[2] = {5, 500};
    int64_t p99 = cbm_calculate_p99(values, 2);
    /* idx = (int)(2 * 0.99) = 1, values[1] = 500 */
    ASSERT_EQ(p99, 500);
    PASS();
}

TEST(traces_calculate_p99_all_same) {
    int64_t values[5] = {42, 42, 42, 42, 42};
    int64_t p99 = cbm_calculate_p99(values, 5);
    ASSERT_EQ(p99, 42);
    PASS();
}

TEST(traces_calculate_p99_negative_count) {
    /* Negative count → treated like empty → 0 */
    int64_t values[3] = {10, 20, 30};
    int64_t p99 = cbm_calculate_p99(values, -1);
    ASSERT_EQ(p99, 0);
    PASS();
}

SUITE(traces) {
    RUN_TEST(traces_extract_service_name);
    RUN_TEST(traces_extract_service_name_missing);
    RUN_TEST(traces_extract_service_name_null);
    RUN_TEST(traces_extract_service_name_empty_attrs);
    RUN_TEST(traces_extract_service_name_multiple_attrs);
    RUN_TEST(traces_extract_http_info);
    RUN_TEST(traces_extract_http_info_non_http);
    RUN_TEST(traces_extract_http_info_url_full);
    RUN_TEST(traces_extract_http_info_url_full_results_stay_distinct);
    RUN_TEST(traces_extract_http_info_url_full_concurrent_results_stay_distinct);
    RUN_TEST(traces_extract_path_from_url);
    RUN_TEST(traces_extract_path_null_url);
    RUN_TEST(traces_extract_path_empty_url);
    RUN_TEST(traces_extract_path_with_port);
    RUN_TEST(traces_extract_path_with_query_and_fragment);
    RUN_TEST(traces_extract_path_buffer_too_small);
    RUN_TEST(traces_extract_path_relative_path);
    RUN_TEST(traces_calculate_p99);
    RUN_TEST(traces_calculate_p99_single);
    RUN_TEST(traces_calculate_p99_empty);
    RUN_TEST(traces_calculate_p99_100_values);
    RUN_TEST(traces_calculate_p99_reversed);
    RUN_TEST(traces_calculate_p99_two_values);
    RUN_TEST(traces_calculate_p99_all_same);
    RUN_TEST(traces_calculate_p99_negative_count);
    RUN_TEST(traces_parse_duration);
    RUN_TEST(traces_parse_duration_zero);
    RUN_TEST(traces_parse_duration_null_start);
    RUN_TEST(traces_parse_duration_null_end);
    RUN_TEST(traces_parse_duration_both_null);
    RUN_TEST(traces_parse_duration_equal);
    RUN_TEST(traces_parse_duration_large_values);
}
