/*
 * log.c — Structured key-value logging to stderr.
 */
#include "log.h"
#include "foundation/constants.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* These four are written by whatever thread configures logging and read by
 * every thread that logs — daemon connection workers, pipeline workers, the
 * watcher. They were plain globals, which is a data race on the SINK in the
 * strict sense that matters: emit_line reads the pointer and CALLS it, so a
 * torn or stale read is a jump through a partially-written pointer, not just
 * a stale value. Found by running the daemon_runtime suite under TSan (that
 * suite had been excluded from the TSan set, which is why it went unseen).
 *
 * Relaxed ordering is the right level: each is an independent scalar with no
 * happens-before relationship to publish alongside it, and the log path must
 * stay cheap enough that nobody is tempted to route around it. */
static _Atomic CBMLogLevel g_log_level = CBM_LOG_INFO;
static _Atomic CBMLogFormat g_log_format = CBM_LOG_FORMAT_TEXT;
/* Cast, not bare NULL: NULL is ((void*)0) and the implicit void*-to-
 * function-pointer conversion is not a compile-time constant, which
 * older Apple clang (Xcode 15.4, the macOS CI image) rejects outright
 * in a static initializer. The cast makes it an address constant. */
static _Atomic cbm_log_sink_fn g_log_sink = (cbm_log_sink_fn)NULL;
static _Atomic CBMLogSinkMode g_log_sink_mode = CBM_LOG_SINK_REPLACE;

enum {
    LOG_ASCII_DELETE = 0x7f,
    LOG_JSON_CONTROL_LIMIT = 0x20,
    LOG_HEX_NIBBLE_BITS = 4,
    LOG_HEX_NIBBLE_MASK = 0xf,
    LOG_HTTP_CLIENT_ERROR_STATUS = 400,
    LOG_HTTP_SERVER_ERROR_STATUS = 500,
};

static bool log_lowercase_value(const char *raw, char *lower, size_t capacity) {
    size_t index = 0;
    for (; index < capacity - sizeof(*lower) && raw[index] != '\0'; index++) {
        lower[index] = (char)tolower((unsigned char)raw[index]);
    }
    lower[index] = '\0';
    return raw[index] == '\0';
}

static bool log_parse_level_name(const char *raw, CBMLogLevel *level_out) {
    static const char *const names[] = {"debug", "info", "warn", "error", "none"};
    char lower[sizeof("debug")];
    if (!log_lowercase_value(raw, lower, sizeof(lower))) {
        return false;
    }
    for (size_t level = 0; level < sizeof(names) / sizeof(names[0]); level++) {
        if (strcmp(lower, names[level]) == 0) {
            *level_out = (CBMLogLevel)level;
            return true;
        }
    }
    return false;
}

static bool log_parse_level_number(const char *raw, CBMLogLevel *level_out) {
    char *end = NULL;
    long number = strtol(raw, &end, CBM_DECIMAL_BASE);
    if (end == raw || *end != '\0' || number < CBM_LOG_DEBUG || number > CBM_LOG_NONE) {
        return false;
    }
    *level_out = (CBMLogLevel)number;
    return true;
}

static void log_apply_level_from_env(const char *raw) {
    if (!raw || raw[0] == '\0') {
        return;
    }
    CBMLogLevel level;
    if (log_parse_level_name(raw, &level) || log_parse_level_number(raw, &level)) {
        cbm_log_set_level(level);
    }
}

static bool log_parse_format(const char *raw, CBMLogFormat *format_out) {
    char lower[sizeof("text")];
    if (!raw || raw[0] == '\0' || !log_lowercase_value(raw, lower, sizeof(lower))) {
        return false;
    }
    if (strcmp(lower, "json") == 0) {
        *format_out = CBM_LOG_FORMAT_JSON;
        return true;
    }
    if (strcmp(lower, "text") == 0) {
        *format_out = CBM_LOG_FORMAT_TEXT;
        return true;
    }
    return false;
}

/* CBM_LOG_LEVEL support — distilled from #414 (closes #413, thanks @santanusinha). */
void cbm_log_init_from_env(void) {
    /* getenv() is safe here: this runs at startup before any thread is created,
     * so there is no concurrent setenv() to race against. */
    log_apply_level_from_env(getenv("CBM_LOG_LEVEL"));

    /* Unrecognised value: leave the level unchanged (fail-open). */

    CBMLogFormat format;
    if (log_parse_format(getenv("CBM_LOG_FORMAT"), &format)) {
        cbm_log_set_format(format);
    }

    /* Format is intentionally explicit-only. Logs stay local to stderr and the
     * optional in-process sink; deployment environment variables must not
     * silently change the operator-selected output shape. */
}

void cbm_log_set_sink(cbm_log_sink_fn fn) {
    cbm_log_set_sink_ex(fn, CBM_LOG_SINK_REPLACE);
}

void cbm_log_set_sink_ex(cbm_log_sink_fn fn, CBMLogSinkMode mode) {
    /* Mode first: a reader that observes the new sink then reads the mode can
     * never see the mode belonging to the PREVIOUS sink. */
    atomic_store_explicit(&g_log_sink_mode, mode, memory_order_relaxed);
    atomic_store_explicit(&g_log_sink, fn, memory_order_relaxed);
}

void cbm_log_set_level(CBMLogLevel level) {
    atomic_store_explicit(&g_log_level, level, memory_order_relaxed);
}

CBMLogLevel cbm_log_get_level(void) {
    return atomic_load_explicit(&g_log_level, memory_order_relaxed);
}

void cbm_log_set_format(CBMLogFormat format) {
    atomic_store_explicit(&g_log_format, format, memory_order_relaxed);
}

CBMLogFormat cbm_log_get_format(void) {
    return atomic_load_explicit(&g_log_format, memory_order_relaxed);
}

static const char *level_str(CBMLogLevel level) {
    switch (level) {
    case CBM_LOG_DEBUG:
        return "debug";
    case CBM_LOG_INFO:
        return "info";
    case CBM_LOG_WARN:
        return "warn";
    case CBM_LOG_ERROR:
        return "error";
    default:
        return "unknown";
    }
}

static void append_char(char *buf, size_t bufsz, size_t *pos, char ch) {
    if (*pos < bufsz - sizeof(*buf)) {
        buf[*pos] = ch;
    }
    (*pos)++;
}

static void append_raw(char *buf, size_t bufsz, size_t *pos, const char *s) {
    if (!s) {
        return;
    }
    while (*s) {
        append_char(buf, bufsz, pos, *s++);
    }
}

static void append_text_atom(char *buf, size_t bufsz, size_t *pos, const char *s) {
    if (!s) {
        return;
    }
    while (*s) {
        unsigned char ch = (unsigned char)*s++;
        if (ch <= ' ' || ch == LOG_ASCII_DELETE) {
            append_char(buf, bufsz, pos, '_');
        } else {
            append_char(buf, bufsz, pos, (char)ch);
        }
    }
}

static void append_json_string(char *buf, size_t bufsz, size_t *pos, const char *s) {
    append_char(buf, bufsz, pos, '"');
    if (s) {
        while (*s) {
            unsigned char ch = (unsigned char)*s++;
            switch (ch) {
            case '"':
                append_raw(buf, bufsz, pos, "\\\"");
                break;
            case '\\':
                append_raw(buf, bufsz, pos, "\\\\");
                break;
            case '\b':
                append_raw(buf, bufsz, pos, "\\b");
                break;
            case '\f':
                append_raw(buf, bufsz, pos, "\\f");
                break;
            case '\n':
                append_raw(buf, bufsz, pos, "\\n");
                break;
            case '\r':
                append_raw(buf, bufsz, pos, "\\r");
                break;
            case '\t':
                append_raw(buf, bufsz, pos, "\\t");
                break;
            default:
                if (ch < LOG_JSON_CONTROL_LIMIT) {
                    static const char hex[] = "0123456789abcdef";
                    append_raw(buf, bufsz, pos, "\\u00");
                    append_char(buf, bufsz, pos, hex[ch >> LOG_HEX_NIBBLE_BITS]);
                    append_char(buf, bufsz, pos, hex[ch & LOG_HEX_NIBBLE_MASK]);
                } else {
                    append_char(buf, bufsz, pos, (char)ch);
                }
                break;
            }
        }
    }
    append_char(buf, bufsz, pos, '"');
}

static void finish_line(char *buf, size_t bufsz, size_t pos) {
    if (bufsz == 0) {
        return;
    }
    if (pos >= bufsz) {
        buf[bufsz - sizeof(*buf)] = '\0';
    } else {
        buf[pos] = '\0';
    }
}

static void emit_line(const char *line) {
    /* Load ONCE: re-reading the global between the test and the call would
     * let a concurrent cbm_log_set_sink turn a checked pointer into a NULL
     * call. */
    cbm_log_sink_fn sink = atomic_load_explicit(&g_log_sink, memory_order_relaxed);
    if (sink) {
        sink(line);
        if (atomic_load_explicit(&g_log_sink_mode, memory_order_relaxed) == CBM_LOG_SINK_REPLACE) {
            return;
        }
    }
    (void)fprintf(stderr, "%s\n", line);
}

void cbm_log(CBMLogLevel level, const char *msg, ...) {
    if (level < atomic_load_explicit(&g_log_level, memory_order_relaxed)) {
        return;
    }

    char line_buf[CBM_SZ_4K];
    size_t pos = 0;
    va_list args;
    va_start(args, msg);

    if (atomic_load_explicit(&g_log_format, memory_order_relaxed) == CBM_LOG_FORMAT_JSON) {
        append_raw(line_buf, sizeof(line_buf), &pos, "{\"level\":");
        append_json_string(line_buf, sizeof(line_buf), &pos, level_str(level));
        append_raw(line_buf, sizeof(line_buf), &pos, ",\"event\":");
        append_json_string(line_buf, sizeof(line_buf), &pos, msg ? msg : "");
        for (;;) {
            const char *key = va_arg(args, const char *);
            if (!key) {
                break;
            }
            const char *val = va_arg(args, const char *);
            append_char(line_buf, sizeof(line_buf), &pos, ',');
            append_json_string(line_buf, sizeof(line_buf), &pos, key);
            append_char(line_buf, sizeof(line_buf), &pos, ':');
            append_json_string(line_buf, sizeof(line_buf), &pos, val ? val : "");
        }
        append_char(line_buf, sizeof(line_buf), &pos, '}');
    } else {
        append_raw(line_buf, sizeof(line_buf), &pos, "level=");
        append_text_atom(line_buf, sizeof(line_buf), &pos, level_str(level));
        append_raw(line_buf, sizeof(line_buf), &pos, " msg=");
        append_text_atom(line_buf, sizeof(line_buf), &pos, msg ? msg : "");
        for (;;) {
            const char *key = va_arg(args, const char *);
            if (!key) {
                break;
            }
            const char *val = va_arg(args, const char *);
            append_char(line_buf, sizeof(line_buf), &pos, ' ');
            append_text_atom(line_buf, sizeof(line_buf), &pos, key);
            append_char(line_buf, sizeof(line_buf), &pos, '=');
            append_text_atom(line_buf, sizeof(line_buf), &pos, val ? val : "");
        }
    }
    va_end(args);

    finish_line(line_buf, sizeof(line_buf), pos);
    emit_line(line_buf);
}

void cbm_log_control_record(const char *msg, ...) {
    /* No threshold check: a control record's whole purpose is surviving
     * CBM_LOG_LEVEL suppression. Always JSON, independent of CBM_LOG_FORMAT,
     * so consumers get one stable, fully escaped representation. */
    char line_buf[CBM_SZ_4K];
    size_t pos = 0;
    va_list args;
    va_start(args, msg);
    append_raw(line_buf, sizeof(line_buf), &pos, "{\"level\":");
    append_json_string(line_buf, sizeof(line_buf), &pos, "control");
    append_raw(line_buf, sizeof(line_buf), &pos, ",\"event\":");
    append_json_string(line_buf, sizeof(line_buf), &pos, msg ? msg : "");
    for (;;) {
        const char *key = va_arg(args, const char *);
        if (!key) {
            break;
        }
        const char *val = va_arg(args, const char *);
        append_char(line_buf, sizeof(line_buf), &pos, ',');
        append_json_string(line_buf, sizeof(line_buf), &pos, key);
        append_char(line_buf, sizeof(line_buf), &pos, ':');
        append_json_string(line_buf, sizeof(line_buf), &pos, val ? val : "");
    }
    append_char(line_buf, sizeof(line_buf), &pos, '}');
    va_end(args);
    finish_line(line_buf, sizeof(line_buf), pos);
    emit_line(line_buf);
}

void cbm_log_int(CBMLogLevel level, const char *msg, const char *key, int64_t value) {
    char value_buf[CBM_SZ_32];
    snprintf(value_buf, sizeof(value_buf), "%" PRId64, value);
    cbm_log(level, msg, key ? key : "?", value_buf, NULL);
}

static void copy_path_without_query(const char *path, char *out, size_t outsz) {
    if (!out || outsz == 0) {
        return;
    }
    out[0] = '\0';
    if (!path) {
        return;
    }
    size_t n = 0;
    while (path[n] && path[n] != '?' && path[n] != '#' && n < outsz - sizeof(*out)) {
        out[n] = path[n];
        n++;
    }
    out[n] = '\0';
}

void cbm_log_mcp_request(const char *method, const char *tool_name, bool is_error,
                         int64_t duration_us) {
    char duration_ms[CBM_SZ_32];
    snprintf(duration_ms, sizeof(duration_ms), "%" PRId64, duration_us / 1000);
    if (tool_name && tool_name[0] != '\0') {
        cbm_log(is_error ? CBM_LOG_WARN : CBM_LOG_INFO, "mcp.request", "protocol", "jsonrpc",
                "method", method ? method : "", "tool", tool_name, "status",
                is_error ? "error" : "ok", "duration_ms", duration_ms, NULL);
    } else {
        cbm_log(is_error ? CBM_LOG_WARN : CBM_LOG_INFO, "mcp.request", "protocol", "jsonrpc",
                "method", method ? method : "", "status", is_error ? "error" : "ok", "duration_ms",
                duration_ms, NULL);
    }
}

void cbm_log_http_request(const char *component, const char *method, const char *path, int status,
                          int64_t duration_ms, size_t request_bytes, size_t response_bytes) {
    char safe_path[CBM_SZ_1K];
    char status_buf[CBM_SZ_16];
    char duration_buf[CBM_SZ_32];
    char request_buf[CBM_SZ_32];
    char response_buf[CBM_SZ_32];
    copy_path_without_query(path, safe_path, sizeof(safe_path));
    snprintf(status_buf, sizeof(status_buf), "%d", status);
    snprintf(duration_buf, sizeof(duration_buf), "%" PRId64, duration_ms);
    snprintf(request_buf, sizeof(request_buf), "%zu", request_bytes);
    snprintf(response_buf, sizeof(response_buf), "%zu", response_bytes);

    CBMLogLevel level = CBM_LOG_INFO;
    if (status >= LOG_HTTP_SERVER_ERROR_STATUS) {
        level = CBM_LOG_ERROR;
    } else if (status >= LOG_HTTP_CLIENT_ERROR_STATUS) {
        level = CBM_LOG_WARN;
    }

    cbm_log(level, "http.request", "component", component ? component : "", "method",
            method ? method : "", "path", safe_path, "status", status_buf, "duration_ms",
            duration_buf, "request_bytes", request_buf, "response_bytes", response_buf, NULL);
}
