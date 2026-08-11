/*
 * mcp.c — MCP server: JSON-RPC 2.0 over stdio with 14 graph tools.
 *
 * Uses yyjson for fast JSON parsing/building.
 * Single-threaded event loop: read line → parse → dispatch → respond.
 */

// operations

#include "foundation/constants.h"

enum {
    MCP_FIELD_SIZE = 1040,
    MCP_TIMEOUT_MS = 1000,
    MCP_HALF_SEC_US = 500000,
    MCP_COL_2 = 2,
    MCP_COL_3 = 3,
    MCP_COL_4 = 4,
    MCP_COL_7 = 7,
    MCP_COL_10 = 10,
    MCP_COL_16 = 16,
    MCP_DB_EXT = 3,      /* strlen(".db") */
    MCP_MIN_DB_NAME = 4, /* min length for "x.db" */
    MCP_SEPARATOR = 2,   /* space for separator chars */
    MCP_DEFAULT_DEPTH = 3,
    MCP_DEFAULT_BFS_DEPTH = 2,
    MCP_DEFAULT_LIMIT = 10,
    MCP_BFS_LIMIT = 100,            /* default per-direction trace budget (limit param raises) */
    MCP_BFS_LIMIT_MAX = 5000,       /* hard ceiling for the limit param (context-bomb guard) */
    MCP_DEFAULT_IMPACT_LIMIT = 200, /* detect_changes per-symbol rows; rollup stays complete */
    MCP_SNIPPET_MAX_LINES = 500,    /* get_code_snippet line cap (whole-file Module guard) */
    MCP_N_DEFAULTS_2 = 2,
    MCP_URI_PREFIX = 7,      /* strlen("file://") */
    MCP_CONTENT_PREFIX = 15, /* strlen("Content-Length:") */
    MCP_RETURN_2 = 2,
    MCP_TOOLS_PAGE_SIZE = 8,
    MCP_HELP_TOOLS_WRAP_COL = 74, /* --help tool list stays readable on 80-col terminals */
    MCP_MAX_CROSS_REPO_TARGETS = 4096,
    MCP_TOOL_PROFILE_PARSE_FAILURE = -1,
    MCP_FIRST_OPTION_ARGUMENT = 1,
    MCP_NEXT_ARGUMENT = 1,
    MCP_CURSOR_TEXT_CAP = 32,
    MCP_STRING_TERMINATOR_BYTES = 1,
    MCP_HELP_TRAILER_BYTES = 2,
    MCP_HELP_CONTINUATION_INDENT = 1,
    MCP_DECIMAL_RADIX = 10,
    MCP_PROJECT_NAME_SEGMENT_DELIMITER_BYTES = 1,
    MCP_PROJECT_NAME_UNIQUE_MATCHES = 1,
    MCP_CANCEL_REQUESTED = 1,
    MCP_CORRUPT_PENDING_MAX_ATTEMPTS = 128,
    MCP_TOKEN_PID_SHIFT = 32,
    MCP_TOKEN_SEQUENCE_INCREMENT = 1,
    MCP_PRIVATE_FILE_MODE = 0600,
    MCP_LOG_DIRECTORY_MODE = 0755,
    MCP_ROOT_PATH_SLASH_INDEX = 1,
    MCP_QUOTED_NAME_DELIMITERS = 2,
    MCP_JSON_LIST_SEPARATOR_BYTES = 1,
    MCP_PRIMARY_PROJECT_INDEX_ABSENT = CBM_NOT_FOUND,
    MCP_SINGLE_PRIMARY_PROJECT = 1,
    MCP_TRACE_DIRECTION_COUNT = 2,
    MCP_JOINED_NAME_TRAILER_BYTES = 2,
    MCP_BM25_RESULT_COLUMN_COUNT = 5,
    MCP_IDENTIFIER_RESULT_COLUMN_COUNT = 1,
    MCP_SEARCH_CORE_COLUMN_COUNT = 6,
    MCP_SEMANTIC_RESULT_COLUMN_COUNT = 4,
    MCP_QUALIFIED_NAME_SEPARATOR_BYTES = 1,
};
#define MCP_MS_TO_US 1000LL
#define MCP_S_TO_US 1000000LL

#define SLEN(s) (sizeof(s) - 1)
#include "mcp/mcp.h"
#include "mcp/mcp_internal.h"
#include "store/store.h"
#include "store/sql.h"
#include "cypher/cypher.h"
#include "discover/discover.h"
#include "pipeline/pipeline.h"
#include "pipeline/pass_cross_repo.h"
#include "git/git_context.h"
#include "watcher/watcher.h"
#include "foundation/build_version.h"
#include "foundation/mem.h"
#include "foundation/diagnostics.h"
#include "foundation/platform.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/compat_thread.h"
#include "foundation/log.h"
#include "foundation/limits.h"
#include "foundation/subprocess.h"
#include "mcp/index_supervisor.h"
#include "mcp/compact_out.h"
#include "foundation/str_util.h"
#include "foundation/workspace.h"
#include "foundation/dump_verify.h"
#include "foundation/compat_regex.h"
#include "pipeline/artifact.h"

#ifdef _WIN32
#include "foundation/win_utf8.h"
#include <direct.h>
#include <io.h>
#include <process.h>
#include <windows.h>
#define getpid _getpid
/* Write through the descriptor cbm_mkstemp returned rather than reopening its
 * path — see search_scratch_open. Mirrors config_toml_edit.c's toml_fdopen. */
#define mcp_fdopen _fdopen
#define mcp_close _close
#else
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#define mcp_fdopen fdopen
#define mcp_close close
#endif
#include <yyjson/yyjson.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h> // va_list, for the bounded help-list appender
#include <stdint.h> // int64_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <stdatomic.h>

/* ── Constants ────────────────────────────────────────────────── */

/* Default snippet fallback line count */
#define SNIPPET_DEFAULT_LINES 50

/* Idle store eviction: close cached project store after this many seconds
 * of inactivity to free SQLite memory during idle periods. */
#define STORE_IDLE_TIMEOUT_S 60

/* Directory permissions: rwxr-xr-x */
#define ADR_DIR_PERMS 0755

/* JSON-RPC 2.0 standard error codes */
#define JSONRPC_PARSE_ERROR (-32700)
#define JSONRPC_METHOD_NOT_FOUND (-32601)
#define JSONRPC_INVALID_PARAMS (-32602)
#define JSONRPC_INTERNAL_ERROR (-32603)

/* MCP stdio framing limits. The body limit is also the upper bound used by the
 * daemon IPC transport; headers stay deliberately small to prevent a peer from
 * growing getline buffers without bound through ignored extension headers. */
#define MCP_MAX_MESSAGE_SIZE ((size_t)10U * 1024U * 1024U)
#define MCP_MAX_HEADER_SIZE ((size_t)8U * 1024U)

/* ── Helpers ────────────────────────────────────────────────────── */

static char *heap_strdup(const char *s) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *d = malloc(len + SKIP_ONE);
    if (d) {
        memcpy(d, s, len + SKIP_ONE);
    }
    return d;
}

/* Write yyjson_mut_doc to heap-allocated JSON string.
 * ALLOW_INVALID_UNICODE: some database strings may contain non-UTF-8 bytes
 * from older indexing runs — don't fail serialization over it. */
static char *yy_doc_to_str(yyjson_mut_doc *doc) {
    size_t len = 0;
    char *s = yyjson_mut_write(doc, YYJSON_WRITE_ALLOW_INVALID_UNICODE, &len);
    return s;
}

/* ══════════════════════════════════════════════════════════════════
 *  JSON-RPC PARSING
 * ══════════════════════════════════════════════════════════════════ */

int cbm_jsonrpc_parse(const char *line, cbm_jsonrpc_request_t *out) {
    memset(out, 0, sizeof(*out));
    out->id = CBM_NOT_FOUND;

    yyjson_doc *doc = yyjson_read(line, strlen(line), 0);
    if (!doc) {
        return CBM_NOT_FOUND;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        yyjson_doc_free(doc);
        return CBM_NOT_FOUND;
    }

    yyjson_val *v_jsonrpc = yyjson_obj_get(root, "jsonrpc");
    yyjson_val *v_method = yyjson_obj_get(root, "method");
    yyjson_val *v_id = yyjson_obj_get(root, "id");
    yyjson_val *v_params = yyjson_obj_get(root, "params");

    if (!v_method || !yyjson_is_str(v_method)) {
        yyjson_doc_free(doc);
        return CBM_NOT_FOUND;
    }

    out->jsonrpc =
        heap_strdup(v_jsonrpc && yyjson_is_str(v_jsonrpc) ? yyjson_get_str(v_jsonrpc) : "2.0");
    out->method = heap_strdup(yyjson_get_str(v_method));

    if (v_id) {
        out->has_id = true;
        if (yyjson_is_int(v_id)) {
            out->id = yyjson_get_int(v_id);
        } else if (yyjson_is_str(v_id)) {
            /* JSON-RPC 2.0 §4 permits string ids (Claude Desktop uses them).
             * Preserve verbatim instead of coercing via strtol (issue #253). */
            out->id_str = heap_strdup(yyjson_get_str(v_id));
        }
    }

    if (v_params) {
        out->params_raw = yyjson_val_write(v_params, 0, NULL);
    }

    yyjson_doc_free(doc);
    return 0;
}

void cbm_jsonrpc_request_free(cbm_jsonrpc_request_t *r) {
    if (!r) {
        return;
    }
    safe_str_free(&r->jsonrpc);
    safe_str_free(&r->method);
    safe_str_free(&r->id_str);
    safe_str_free(&r->params_raw);
    memset(r, 0, sizeof(*r));
}

/* ══════════════════════════════════════════════════════════════════
 *  JSON-RPC FORMATTING
 * ══════════════════════════════════════════════════════════════════ */

char *cbm_jsonrpc_format_response(const cbm_jsonrpc_response_t *resp) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "jsonrpc", "2.0");
    if (resp->id_str) {
        yyjson_mut_obj_add_str(doc, root, "id", resp->id_str);
    } else {
        yyjson_mut_obj_add_int(doc, root, "id", resp->id);
    }

    if (resp->error_json) {
        /* Parse the error JSON and embed */
        yyjson_doc *err_doc = yyjson_read(resp->error_json, strlen(resp->error_json), 0);
        if (err_doc) {
            yyjson_mut_val *err_val = yyjson_val_mut_copy(doc, yyjson_doc_get_root(err_doc));
            yyjson_mut_obj_add_val(doc, root, "error", err_val);
            yyjson_doc_free(err_doc);
        }
    } else if (resp->result_json) {
        /* Parse the result JSON and embed */
        yyjson_doc *res_doc = yyjson_read(resp->result_json, strlen(resp->result_json), 0);
        if (res_doc) {
            yyjson_mut_val *res_val = yyjson_val_mut_copy(doc, yyjson_doc_get_root(res_doc));
            yyjson_mut_obj_add_val(doc, root, "result", res_val);
            yyjson_doc_free(res_doc);
        }
    } else {
        /* JSON-RPC 2.0 spec: response MUST contain "result" or "error" */
        yyjson_mut_obj_add_null(doc, root, "result");
    }

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

char *cbm_jsonrpc_format_error(int64_t id, int code, const char *message) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "jsonrpc", "2.0");
    yyjson_mut_obj_add_int(doc, root, "id", id);

    yyjson_mut_val *err = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_int(doc, err, "code", code);
    yyjson_mut_obj_add_str(doc, err, "message", message);
    yyjson_mut_obj_add_val(doc, root, "error", err);

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

/* ══════════════════════════════════════════════════════════════════
 *  MCP PROTOCOL HELPERS
 * ══════════════════════════════════════════════════════════════════ */

char *cbm_mcp_text_result(const char *text, bool is_error) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_val *content = yyjson_mut_arr(doc);
    yyjson_mut_val *item = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, item, "type", "text");
    yyjson_mut_obj_add_str(doc, item, "text", text ? text : "");
    yyjson_mut_arr_add_val(content, item);
    yyjson_mut_obj_add_val(doc, root, "content", content);

    bool has_structured_content = false;
    if (text) {
        yyjson_doc *structured_doc = yyjson_read(text, strlen(text), 0);
        if (structured_doc) {
            yyjson_val *structured_root = yyjson_doc_get_root(structured_doc);
            if (yyjson_is_obj(structured_root)) {
                yyjson_mut_val *structured = yyjson_val_mut_copy(doc, structured_root);
                if (structured) {
                    yyjson_mut_obj_add_val(doc, root, "structuredContent", structured);
                    has_structured_content = true;
                }
            }
            yyjson_doc_free(structured_doc);
        }
    }
    if (!has_structured_content) {
        /* Every advertised MCP tool declares an object outputSchema, so a
         * conforming structuredContent object is mandatory even for compact
         * TOON/plain-text and error results. What is NOT mandatory is putting
         * the whole payload in it a second time.
         *
         * It used to. For any result that is not a JSON object — which is every
         * TOON answer, i.e. the large ones — structuredContent was
         * {"text": <the entire payload>} sitting beside an identical
         * content[0].text. Measured at 2.05x the payload on a 20k-node
         * query_graph, so half of every reply was redundant bytes: half the
         * usable transport budget, and double the tokens billed to every LLM
         * caller (#1375).
         *
         * Nothing is lost by dropping it. structuredContent exists to carry
         * STRUCTURE, and a string re-wrapped in a one-key object has none —
         * a client parsing structuredContent.text learns exactly what
         * content[0].text already told it. The empty object still satisfies
         * outputSchema ({"type":"object","additionalProperties":true}), and the
         * JSON branch above is untouched: when a tool really does return an
         * object, callers still get it parsed.
         *
         * Errors keep their payload. They are bounded and small, the duplication
         * costs nothing measurable, and structuredContent.error is the only
         * machine-readable form of a failure a client has. */
        yyjson_mut_val *structured = yyjson_mut_obj(doc);
        if (is_error) {
            yyjson_mut_obj_add_str(doc, structured, "error", text ? text : "");
        }
        yyjson_mut_obj_add_val(doc, root, "structuredContent", structured);
    }
    yyjson_mut_obj_add_bool(doc, root, "isError", is_error);

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

bool cbm_mcp_cancel_request_matches(const char *params_json, int64_t active_id,
                                    const char *active_id_str) {
    if (!params_json) {
        return false;
    }

    yyjson_doc *doc = yyjson_read(params_json, strlen(params_json), 0);
    if (!doc) {
        return false;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *request_id = yyjson_obj_get(root, "requestId");
    bool matches = false;
    if (request_id) {
        if (active_id_str) {
            matches =
                yyjson_is_str(request_id) && strcmp(yyjson_get_str(request_id), active_id_str) == 0;
        } else {
            matches = yyjson_is_int(request_id) && yyjson_get_int(request_id) == active_id;
        }
    }

    yyjson_doc_free(doc);
    return matches;
}

/* ── Tool definitions ─────────────────────────────────────────── */

typedef struct {
    const char *name;
    const char *title;
    const char *description;
    const char *input_schema; /* JSON string */
} tool_def_t;

static const tool_def_t TOOLS[] = {
    {"index_repository", "Index repository",
     "Index a repository into the knowledge graph. "
     "Special mode 'cross-repo-intelligence': skip extraction, only match Routes/Channels "
     "across projects to create CROSS_HTTP_CALLS/CROSS_ASYNC_CALLS/CROSS_CHANNEL edges. "
     "Requires target_projects param. Ensure target projects have fresh indexes first. "
     "COVERAGE: the response reports files that were NOT fully indexed — 'skipped' (not "
     "indexed at all: oversized/read/parse failures) and 'parse_partial' (indexed, but "
     "constructs inside the listed line ranges could not be parsed and MAY be missing from "
     "the graph). The embedded lists carry counts plus a FEW EXAMPLES only; the complete "
     "lists are in the per-run 'logfile' (path in the response) and queryable any time via "
     "index_status or structurally via query_graph(graph=\"missed\"). Both signals are "
     "best-effort: absence of a flag is NOT a completeness guarantee; prefer grep inside "
     "flagged ranges. Separately, 'excluded' + 'not_indexed_files' list what was "
     "deliberately NOT indexed (gitignore/.cbmignore/skip-lists) — by design, not failures.",
     "{\"type\":\"object\",\"properties\":{\"repo_path\":{\"type\":\"string\",\"description\":"
     "\"Path to the repository\"},"
     "\"mode\":{\"type\":\"string\","
     "\"enum\":[\"full\",\"moderate\",\"fast\",\"cross-repo-intelligence\"],"
     "\"default\":\"full\",\"description\":\"All modes run type-aware LSP call/usage "
     "resolution (per-file + cross-file). full: all files + similarity/semantic edges. "
     "moderate: filtered files + similarity/semantic. fast: filtered files, no "
     "similarity/semantic. cross-repo-intelligence: match Routes/Channels across projects.\"},"
     "\"target_projects\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},"
     "\"description\":\"Projects to search for cross-repo links (cross-repo-intelligence mode). "
     "Use [\\\"*\\\"] for all indexed projects. Run list_projects to see available projects.\"},"
     "\"name\":{\"type\":\"string\",\"description\":"
     "\"Override the derived project name. Non-ASCII bytes are encoded and unsafe path characters "
     "are normalized.\"},"
     "\"persistence\":{\"type\":\"boolean\",\"default\":false,\"description\":"
     "\"Write compressed artifact to .codebase-memory/graph.db.zst for team sharing. "
     "Teammates can bootstrap from the artifact instead of full re-indexing.\"}"
     "},\"required\":[\"repo_path\"]}"},

    {"search_graph", "Search graph",
     "Search the code knowledge graph for functions, classes, routes, and variables. Use INSTEAD "
     "OF grep/glob when finding code definitions, implementations, or relationships. Three search "
     "modes: (1) query='update settings' for BM25 ranked full-text search with camelCase "
     "splitting and structural label boosting — recommended for natural-language discovery; "
     "(2) name_pattern='.*regex.*' for exact pattern matching; (3) semantic_query=[...] for "
     "vector cosine search that bridges vocabulary (finds 'publish' when you search 'send'). "
     "The three modes are independent and can be combined in a single call. "
     "RESPONSE: prefix-grouped tree rows by default — a shared (qn-prefix, file) group "
     "header printed once, then `name label lines in out` per row (full qn = group prefix "
     "+ dot + name). in/out = selected degree across CALLS, USAGE, CALL_REFERENCE, "
     "INHERITS, and IMPLEMENTS; other edge types are excluded. These are NOT caller/callee "
     "counts — use trace_path for callers. Add per-node "
     "property columns via "
     "fields (e.g. [\"complexity\",\"signature\",\"docstring\"]); format=\"json\" returns "
     "the SAME tree model as structured JSON. "
     "PAGINATION: results are capped at limit (default 50). The response always includes "
     "'total' (full match count before limit) and 'has_more' (true when total > "
     "offset+returned). Detect truncation with has_more, then page by re-calling with "
     "offset=offset+limit until has_more is false. Narrow first via label/file_pattern/"
     "min_degree before paginating large result sets.",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},"
     "\"query\":{\"type\":\"string\",\"description\":\"Natural-language or keyword full-text "
     "search using BM25 ranking. Tokens are split on whitespace; camelCase identifiers are "
     "indexed as individual words (updateCloudClient → update, cloud, client). Results are "
     "ranked with structural boosting: Functions/Methods +10, Routes +8, Classes/Interfaces +5. "
     "Noise labels (File/Folder/Module/Variable) are filtered out. When provided, name_pattern "
     "is ignored.\"},"
     "\"label\":{\"type\":\"string\"},\"name_pattern\":{\"type\":\"string\"},\"qn_pattern\":{"
     "\"type\":\"string\"},\"file_pattern\":{\"type\":\"string\"},"
     "\"relationship\":{\"type\":\"string\"},\"min_degree\":{\"type\":\"integer\"},"
     "\"max_degree\":{\"type\":\"integer\"},\"exclude_entry_points\":{\"type\":\"boolean\"},"
     "\"include_connected\":{\"type\":\"boolean\"},\"semantic_query\":{"
     "\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"MUST be an ARRAY of "
     "keyword strings (e.g. [\\\"send\\\",\\\"pubsub\\\",\\\"publish\\\"]) — NOT a single string. "
     "Each keyword is scored independently via per-keyword min-cosine; results reflect functions "
     "that score well on ALL keywords. Requires moderate/full index mode. Results appear in the "
     "'semantic_results' field (separate from 'results').\"},\"limit\":{\"type\":"
     "\"integer\",\"description\":\"Max results per call. Default 50. Response carries "
     "'total' (full match count) and 'has_more' (true if truncated) so callers can "
     "detect the limit and paginate.\"},\"offset\":{\"type\":\"integer\",\"default\":0,"
     "\"description\":\"Skip the first N matching nodes. Combine with 'limit' to page: "
     "increment offset by limit and re-call while has_more is true.\"},"
     "\"format\":{\"type\":\"string\",\"enum\":[\"tree\",\"json\"],\"default\":\"tree\","
     "\"description\":\"Response encoding. tree (default): prefix-grouped text rows. "
     "json: the SAME tree model as structured JSON (groups + column-ordered row arrays).\"},"
     "\"fields\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":"
     "\"Extra per-node property columns, e.g. complexity, cognitive, "
     "signature, docstring, return_type, is_test, lines(int). Core row columns "
     "(qn/label/file/lines/in/out) are always present — do not request them here. "
     "Missing values emit as empty cells.\"},"
     "\"detail\":{\"type\":\"string\",\"enum\":[\"ids\",\"default\"],\"default\":\"default\","
     "\"description\":\"ids: bare qualified-name enumeration (one column) — cheapest form "
     "for wide sweeps where per-row metadata is noise. default: full rows.\"}},"
     "\"required\":[\"project\"]}"},

    {"query_graph", "Query graph",
     "Execute a Cypher query against the knowledge graph for complex multi-hop patterns, "
     "aggregations, and cross-service analysis. The response includes 'total' (returned "
     "row count). There is a hard 100k row ceiling — for broad queries add LIMIT in the "
     "Cypher itself or use search_graph + offset/limit pagination instead. "
     "COMPLEXITY / BOTTLENECKS: every Function and Method node carries queryable complexity "
     "properties — cyclomatic (complexity), cognitive, loop_count, loop_depth (max nested-loop "
     "depth, a polynomial-degree proxy), plus interprocedural transitive_loop_depth (worst-case "
     "nested-loop degree propagated along CALLS edges) and a recursive flag. Additional "
     "hot-path signals: linear_scan_in_loop (count of find/contains/indexOf-style scans inside a "
     "loop — the hidden O(n^2) that loop_depth misses), alloc_in_loop (allocations/appends inside "
     "a loop), recursion_in_loop (a self-call inside a loop), unguarded_recursion (recursion with "
     "no conditionally-guarded base case), param_count and max_access_depth (structure smells). "
     "Find all hot-path candidates in one query, e.g. MATCH (f:Function) WHERE "
     "f.transitive_loop_depth >= 3 OR f.linear_scan_in_loop >= 1 RETURN f.qualified_name, "
     "f.transitive_loop_depth, f.linear_scan_in_loop ORDER BY f.transitive_loop_depth DESC. "
     "MISSED GRAPH: pass graph=\"missed\" to query the best-effort miss graph instead — the "
     "file structure of ONLY the files the indexer could NOT fully index (Project → Folder → "
     "File nodes with CONTAINS_FOLDER/CONTAINS_FILE edges; each File carries kind "
     "(\"parse_partial\" = indexed but constructs in the flagged line ranges MAY be missing; "
     "or a skip phase) and detail (the line ranges / reason)). Example: MATCH (f:File) WHERE "
     "f.kind = \\\"parse_partial\\\" RETURN f.file_path, f.detail. Absence from this graph is "
     "NOT a completeness guarantee.",
     "{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"Cypher "
     "query\"},\"project\":{\"type\":\"string\"},"
     "\"graph\":{\"type\":\"string\",\"enum\":[\"code\",\"missed\"],\"default\":\"code\","
     "\"description\":\"Which graph to query: the code knowledge graph (default) or the "
     "missed graph (only files not fully indexed, laid out as their file structure).\"},"
     "\"max_rows\":{\"type\":\"integer\","
     "\"description\":"
     "\"Optional row limit. Default: unlimited up to a 100k row "
     "ceiling. No offset support — use search_graph for paginated browsing.\"}},"
     "\"required\":[\"query\",\"project\"]}"},

    {"trace_path", "Trace path",
     "Trace paths through the code graph. Modes: calls (callers/callees), data_flow (value "
     "propagation with args at each hop), cross_service (through HTTP/async Route nodes). "
     "Use INSTEAD OF grep for callers, dependencies, impact analysis, or data flow tracing. "
     "RESPONSE: prefix-grouped tree rows — callees/callers grouped under their shared "
     "qn-prefix, `name hop` per row (full qn = group prefix + dot + name); exact "
     "callees_total/callers_total on every page = ALL nodes reachable within depth (transitive, "
     "not just direct; test files excluded unless include_tests). risk/args flags use a flat "
     "table. "
     "`truncated: true` + `next` = more rows — pass next back as cursor. "
     "format=\"json\" returns the SAME tree model as structured JSON.",
     "{\"type\":\"object\",\"properties\":{\"function_name\":{\"type\":\"string\"},\"project\":{"
     "\"type\":\"string\"},\"direction\":{\"type\":\"string\",\"enum\":[\"inbound\",\"outbound\","
     "\"both\"],\"default\":\"both\"},\"depth\":{\"type\":\"integer\",\"default\":3},"
     "\"limit\":{\"type\":\"integer\",\"default\":100,\"minimum\":1,\"maximum\":5000,"
     "\"description\":\"Rows per page. callees_total/callers_total always carry the exact full "
     "counts; when a page is truncated the response carries next — see cursor.\"},"
     "\"cursor\":{\"type\":\"string\",\"description\":\"Resume token from a previous response's "
     "'next' field. Pass it back with ALL other arguments identical to get the following page "
     "with no duplicates. Cursors outlive nothing: after a reindex you get a stale_cursor error "
     "— just re-run the original query.\"},\"mode\":{"
     "\"type\":\"string\",\"enum\":[\"calls\",\"data_flow\",\"cross_service\"],\"default\":"
     "\"calls\",\"description\":\"calls: follow CALLS edges. data_flow: follow CALLS+DATA_FLOWS "
     "with arg expressions. cross_service: follow HTTP_CALLS+ASYNC_CALLS+DATA_FLOWS through "
     "Routes, plus CROSS_* cross-repo edges (CROSS_HTTP_CALLS/ASYNC_CALLS/CHANNEL/GRPC_CALLS/"
     "GRAPHQL_CALLS/TRPC_CALLS) to hop into other services.\"},\"parameter_name\":{\"type\":"
     "\"string\",\"description\":\"For data_flow mode: "
     "scope trace to a specific parameter name\"},\"edge_types\":{\"type\":\"array\",\"items\":{"
     "\"type\":\"string\"}},\"risk_labels\":{\"type\":\"boolean\",\"default\":false,"
     "\"description\":\"Add risk classification (CRITICAL/HIGH/MEDIUM/LOW) based on hop distance"
     "\"},\"include_tests\":{\"type\":\"boolean\",\"default\":false,"
     "\"description\":\"Include test files in results. When false (default), test files are "
     "filtered out. When true, test nodes are included with a test column/marker.\"},"
     "\"format\":{\"type\":\"string\",\"enum\":[\"tree\",\"json\"],\"default\":\"tree\","
     "\"description\":\"Response encoding. tree (default): prefix-grouped text rows. "
     "json: the SAME tree model as structured JSON (groups + column-ordered row arrays).\"},"
     "\"include_evidence\":{\"type\":\"boolean\",\"default\":false,"
     "\"description\":\"Add how each hop was resolved: a strategy class (lsp | language_rule | "
     "heuristic | unresolved) and the resolver's confidence. Off by default — it adds two "
     "columns per row. Use it to judge whether an edge is trustworthy, not to find edges.\"}},"
     "\"required\":[\"function_name\",\"project\"]}"},

    {"get_code_snippet", "Get code snippet",
     "Read source code for a function/class/symbol. IMPORTANT: First call search_graph to find the "
     "exact qualified_name, then pass it here. This is a read tool, not a search tool. Accepts "
     "full qualified_name (exact match) or short function name (returns suggestions if ambiguous). "
     "If the response carries a 'coverage_note', the file was only partially indexed — constructs "
     "in the noted line ranges may be missing from the graph (best-effort signal); prefer grep "
     "there and treat the returned source as ground truth.",
     "{\"type\":\"object\",\"properties\":{\"qualified_name\":{\"type\":\"string\",\"description\":"
     "\"Full qualified_name from search_graph, or short function name\"},\"project\":{"
     "\"type\":\"string\"},\"include_neighbors\":{"
     "\"type\":\"boolean\",\"default\":false}},\"required\":[\"qualified_name\",\"project\"]}"},

    {"get_graph_schema", "Get graph schema",
     "Get the schema of the knowledge graph (node labels, edge types)",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"}},\"required\":["
     "\"project\"]}"},

    {"get_architecture", "Get architecture",
     "Get high-level architecture overview. DEFAULT (no aspects) is a compact summary — "
     "overview counts, languages, packages, entry_points; request more via aspects:[...] "
     "(structure, dependencies, routes, hotspots, boundaries, layers, clusters, file_tree) or "
     "[\"all\"]. 'clusters' runs Leiden community detection over the call/import graph, "
     "surfacing the de-facto modules (label, member count, cohesion score, representative "
     "top_nodes, binding packages/edge_types) — the real architectural seams, which often cut "
     "across the folder layout. Optional path scopes analysis to nodes under that directory "
     "prefix (file_path).",
     /* The aspects enum mirrors VALID_ASPECTS (see aspect_is_valid) — update both together. */
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},\"path\":{\"type\":"
     "\"string\",\"description\":\"Optional directory prefix to scope architecture (e.g. "
     "apps/hoa)\"},"
     "\"aspects\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"enum\":[\"all\","
     "\"overview\",\"structure\",\"dependencies\",\"routes\",\"languages\",\"packages\","
     "\"entry_points\",\"hotspots\",\"boundaries\",\"layers\",\"file_tree\",\"clusters\","
     "\"cycles\"]},"
     "\"description\":\"Aspects to include. 'all' = everything; 'overview' = compact summary "
     "(all except file_tree); omit = all. 'cycles' is opt-in ONLY (never via all/overview): it "
     "scans the whole call graph for circular CALLS dependencies (SCCs of size > 1).\"}},"
     "\"required\":[\"project\"]}"},

    {"search_code", "Search code",
     "Graph-augmented code search. Finds text patterns via grep, then enriches results with "
     "the knowledge graph: deduplicates matches into containing functions, ranks by structural "
     "importance (definitions first, popular functions next, tests last). "
     "Modes: compact (default, signatures only — token efficient), full (source capped at a "
     "60-line window around the first match per hit; source_truncated marks the cut — use "
     "get_code_snippet for the complete symbol), "
     "files (just file paths). Use path_filter regex to scope results. "
     "TRUNCATION: enriched results are capped at limit (default 10). Response carries "
     "'total_grep_matches' (raw grep hit count) and 'total_results' (deduplicated function "
     "count) — compare to limit to detect truncation. There is no offset parameter; to see "
     "more, raise limit or narrow the query with file_pattern / path_filter.",
     "{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\"},\"project\":{\"type\":"
     "\"string\"},\"file_pattern\":{\"type\":\"string\",\"description\":\"Glob for grep "
     "--include (e.g. *.go)\"},\"path_filter\":{\"type\":\"string\",\"description\":\"Regex "
     "filter on result file paths (e.g. ^src/ or \\\\.(go|ts)$)\"},\"mode\":{\"type\":\"string\","
     "\"enum\":[\"compact\",\"full\",\"files\"],\"default\":\"compact\",\"description\":\"compact: "
     "signatures+metadata (default). full: with source. files: just file list.\"},"
     "\"context\":{\"type\":\"integer\",\"description\":\"Lines of context around each match "
     "(like grep -C). Only used in compact mode.\"},"
     "\"regex\":{\"type\":\"boolean\",\"default\":false},\"limit\":{\"type\":\"integer\","
     "\"description\":\"Max enriched results per call. Default 10. Response includes "
     "'total_grep_matches' and 'total_results' so callers can detect truncation. No "
     "offset parameter — raise limit or narrow with file_pattern / path_filter to see more."
     "\",\"default\":10}},\"required\":[\"pattern\",\"project\"]}"},

    {"list_projects", "List projects", "List all indexed projects",
     "{\"type\":\"object\",\"properties\":{}}"},
    {"delete_project", "Delete project", "Delete a project from the index",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"}},\"required\":["
     "\"project\"]}"},

    {"index_status", "Index status",
     "Get the indexing status of a project: node/edge counts, root path, git context, and the "
     "indexing-COVERAGE report — which files the indexer could NOT fully cover (best-effort "
     "signal): 'parse_partial' files WERE indexed but contain line ranges tree-sitter could not "
     "parse — constructs there MAY be missing from the graph (some are still recovered); "
     "'skipped' files were not indexed at all (oversized/read/parse failure). Use this before "
     "trusting graph completeness on a file: if a file is listed, ALSO grep it (especially the "
     "flagged ranges). IMPORTANT: absence from these lists is NOT a completeness guarantee — the "
     "signal only marks what the indexer can detect. For structural queries over the misses use "
     "query_graph(graph=\"missed\"). The report also carries 'not_indexed' — files/dirs excluded "
     "BY DESIGN (gitignore/.cbmignore/skip-lists): deliberate and deterministic, not failures; "
     "change the ignore rules and re-index to include them.",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},"
     "\"verbose\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Include the git "
     "context block (worktree/shadow path variants). Only needed when debugging where an index "
     "lives — omitted by default to keep the status lean.\"}},\"required\":["
     "\"project\"]}"},

    {"check_index_coverage", "Check index coverage",
     "Check authoritative indexing-coverage metadata for exact repository-relative paths and "
     "bounded path scopes. Use this after graph discovery for every cited or operated-on file; "
     "use scopes before negative/exhaustive claims because fully skipped files cannot appear in "
     "normal graph results. Returns coverage status separately from filesystem metadata freshness, "
     "plus structured parse-error ranges and direct-source fallback actions. The signal is "
     "best-effort: indexed_no_recorded_gap is not a completeness guarantee.",
     "{\"type\":\"object\",\"properties\":{"
     "\"project\":{\"type\":\"string\"},"
     "\"paths\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"maxItems\":128,"
     "\"description\":\"Repository-relative files to check exactly.\"},"
     "\"scopes\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"maxItems\":32,"
     "\"description\":\"Repository-relative path prefixes; use . for the project root.\"},"
     "\"scope_limit\":{\"type\":\"integer\",\"default\":200,\"minimum\":1,\"maximum\":1000},"
     "\"scope_offset\":{\"type\":\"integer\",\"default\":0,\"minimum\":0}},"
     "\"required\":[\"project\"],\"anyOf\":[{\"required\":[\"paths\"]},{\"required\":[\"scopes\"]}]"
     "}"},

    {"detect_changes", "Detect changes",
     "Map a git diff to its BLAST RADIUS. Resolves changed files to the symbols they define, then "
     "runs ONE multi-source graph traversal to the transitive impact set. RESPONSE: base + "
     "merge_base SHA, changed_files list, then impacted = prefix-grouped tree rows (name label "
     "hop; "
     "full qn = group prefix + dot + name) + an impacted_modules rollup; impacted_total + "
     "truncated are exact. Seeds (the changed symbols) are excluded from impacted; a changed file "
     "reached from another changed file is not counted as extra impact. format=\"json\" returns "
     "the "
     "same model as structured JSON.",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},\"scope\":{\"type\":"
     "\"string\",\"enum\":[\"files\",\"impact\"],\"description\":\"files: changed files only "
     "(no traversal). impact (default): files + the transitive impact set.\"},"
     "\"direction\":{\"type\":\"string\",\"enum\":[\"inbound\",\"outbound\",\"both\"],\"default\":"
     "\"inbound\",\"description\":\"inbound (default) = the blast radius: transitive CALLERS of "
     "the "
     "changed symbols. outbound = what the changed code depends on. both = union.\"},"
     "\"depth\":{\"type\":\"integer\",\"default\":2,\"description\":\"Max traversal hops from the "
     "changed symbols.\"},\"limit\":{\"type\":\"integer\",\"default\":200,\"maximum\":5000,"
     "\"description\":\"Per-symbol impacted rows shown (nearest hops first). impacted_total is "
     "always exact and the impacted_modules rollup always complete regardless.\"},"
     "\"base_branch\":{\"type\":"
     "\"string\",\"default\":\"main\"},\"since\":{\"type\":\"string\",\"description\":"
     "\"Git ref or tag to compare from (e.g. HEAD~5, v0.5.0). Diffs <ref>...HEAD.\"},"
     "\"format\":{\"type\":\"string\",\"enum\":[\"tree\",\"json\"],\"default\":\"tree\"}},"
     "\"required\":"
     "[\"project\"]}"},

    {"manage_adr", "Manage ADR", "Create or update Architecture Decision Records",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},\"mode\":{\"type\":"
     "\"string\",\"enum\":[\"get\",\"update\",\"sections\"],\"description\":\"update replaces "
     "the entire ADR document; sections only lists existing "
     "headings\"},\"content\":{\"type\":\"string\",\"description\":\"Complete replacement document "
     "required by update\"}},\"additionalProperties\":false,"
     "\"required\":[\"project\"]}"},

};

static const int TOOL_COUNT = sizeof(TOOLS) / sizeof(TOOLS[0]);

static const char MCP_TOOL_OUTPUT_SCHEMA[] = "{\"type\":\"object\",\"additionalProperties\":true}";

typedef struct {
    const char *name;
    bool read_only;
    bool destructive;
    bool idempotent;
    bool open_world;
} tool_annotation_def_t;

/* Tool annotations are deliberately explicit. All tools operate on the local
 * repository/index domain, so none cross an open-world trust boundary. */
static const tool_annotation_def_t TOOL_ANNOTATIONS[] = {
    {"index_repository", false, false, true, false},
    {"search_graph", false, true, true, false},
    {"query_graph", false, true, true, false},
    {"trace_path", false, true, true, false},
    {"get_code_snippet", false, true, true, false},
    {"get_graph_schema", false, true, true, false},
    {"get_architecture", false, true, true, false},
    {"search_code", false, true, true, false},
    {"list_projects", true, false, true, false},
    {"delete_project", false, true, true, false},
    {"index_status", false, true, true, false},
    {"check_index_coverage", false, true, true, false},
    {"detect_changes", false, true, true, false},
    {"manage_adr", false, true, false, false},
};

static const tool_annotation_def_t *mcp_tool_annotations(const char *name) {
    size_t count = sizeof(TOOL_ANNOTATIONS) / sizeof(TOOL_ANNOTATIONS[0]);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(TOOL_ANNOTATIONS[i].name, name) == 0) {
            return &TOOL_ANNOTATIONS[i];
        }
    }
    return NULL;
}

static void mcp_add_json_schema(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key,
                                const char *schema_json) {
    yyjson_doc *schema_doc = yyjson_read(schema_json, strlen(schema_json), 0);
    if (schema_doc) {
        yyjson_mut_val *schema = yyjson_val_mut_copy(doc, yyjson_doc_get_root(schema_doc));
        if (schema) {
            yyjson_mut_obj_add_val(doc, obj, key, schema);
        }
        yyjson_doc_free(schema_doc);
    }
}

static void mcp_add_tool_def(yyjson_mut_doc *doc, yyjson_mut_val *tools, int i) {
    yyjson_mut_val *tool = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, tool, "name", TOOLS[i].name);
    yyjson_mut_obj_add_str(doc, tool, "title", TOOLS[i].title);
    yyjson_mut_obj_add_str(doc, tool, "description", TOOLS[i].description);

    mcp_add_json_schema(doc, tool, "inputSchema", TOOLS[i].input_schema);
    mcp_add_json_schema(doc, tool, "outputSchema", MCP_TOOL_OUTPUT_SCHEMA);

    const tool_annotation_def_t *def = mcp_tool_annotations(TOOLS[i].name);
    yyjson_mut_val *annotations = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_bool(doc, annotations, "readOnlyHint", def ? def->read_only : false);
    yyjson_mut_obj_add_bool(doc, annotations, "destructiveHint", def ? def->destructive : true);
    yyjson_mut_obj_add_bool(doc, annotations, "idempotentHint", def ? def->idempotent : false);
    yyjson_mut_obj_add_bool(doc, annotations, "openWorldHint", def ? def->open_world : true);
    yyjson_mut_obj_add_val(doc, tool, "annotations", annotations);

    yyjson_mut_arr_add_val(tools, tool);
}

static bool mcp_tool_allowed(cbm_mcp_tool_profile_t profile, const char *name) {
    static const char *const analysis_tools[] = {
        "search_graph",     "query_graph",          "trace_path",     "get_code_snippet",
        "get_graph_schema", "get_architecture",     "search_code",    "list_projects",
        "index_status",     "check_index_coverage", "detect_changes",
    };
    static const char *const scout_tools[] = {
        "search_graph",  "trace_path",   "get_code_snippet",     "get_architecture",
        "list_projects", "index_status", "check_index_coverage",
    };
    if (!name) {
        return false;
    }
    if (profile == CBM_MCP_TOOL_PROFILE_ALL) {
        return true;
    }
    const char *const *allowed = NULL;
    size_t allowed_count = 0U;
    if (profile == CBM_MCP_TOOL_PROFILE_ANALYSIS) {
        allowed = analysis_tools;
        allowed_count = sizeof(analysis_tools) / sizeof(analysis_tools[0]);
    } else if (profile == CBM_MCP_TOOL_PROFILE_SCOUT) {
        allowed = scout_tools;
        allowed_count = sizeof(scout_tools) / sizeof(scout_tools[0]);
    }
    for (size_t i = 0U; i < allowed_count; i++) {
        if (strcmp(name, allowed[i]) == 0) {
            return true;
        }
    }
    return false;
}

static const char *mcp_tool_profile_name(cbm_mcp_tool_profile_t profile) {
    return profile == CBM_MCP_TOOL_PROFILE_SCOUT ? "scout" : "analysis";
}

int cbm_mcp_parse_tool_profile_args(int argc, const char *const argv[const],
                                    cbm_mcp_tool_profile_t *profile_out) {
    if (argc < 0 || !argv || !profile_out) {
        return MCP_TOOL_PROFILE_PARSE_FAILURE;
    }
    *profile_out = CBM_MCP_TOOL_PROFILE_ALL;
    for (int i = MCP_FIRST_OPTION_ARGUMENT; i < argc; i++) {
        const char *arg = argv[i];
        if (!arg) {
            return MCP_TOOL_PROFILE_PARSE_FAILURE;
        }
        if (strcmp(arg, "--tool-profile=analysis") == 0) {
            *profile_out = CBM_MCP_TOOL_PROFILE_ANALYSIS;
            continue;
        }
        if (strcmp(arg, "--tool-profile=scout") == 0) {
            *profile_out = CBM_MCP_TOOL_PROFILE_SCOUT;
            continue;
        }
        if (strcmp(arg, "--tool-profile") == 0) {
            if (i + MCP_NEXT_ARGUMENT >= argc || !argv[i + MCP_NEXT_ARGUMENT]) {
                return MCP_TOOL_PROFILE_PARSE_FAILURE;
            }
            if (strcmp(argv[i + MCP_NEXT_ARGUMENT], "analysis") == 0) {
                *profile_out = CBM_MCP_TOOL_PROFILE_ANALYSIS;
            } else if (strcmp(argv[i + MCP_NEXT_ARGUMENT], "scout") == 0) {
                *profile_out = CBM_MCP_TOOL_PROFILE_SCOUT;
            } else {
                return MCP_TOOL_PROFILE_PARSE_FAILURE;
            }
            i++;
            continue;
        }
        if (strncmp(arg, "--tool-profile=", strlen("--tool-profile=")) == 0) {
            return MCP_TOOL_PROFILE_PARSE_FAILURE;
        }
    }
    return 0;
}

bool cbm_mcp_tool_profile_allows_http(cbm_mcp_tool_profile_t profile) {
    return profile == CBM_MCP_TOOL_PROFILE_ALL;
}

static int mcp_allowed_tool_count(cbm_mcp_tool_profile_t profile) {
    int count = 0;
    for (int i = 0; i < TOOL_COUNT; i++) {
        if (mcp_tool_allowed(profile, TOOLS[i].name)) {
            count++;
        }
    }
    return count;
}

static char *cbm_mcp_tools_list_range(cbm_mcp_tool_profile_t profile, int offset, int limit,
                                      bool include_next_cursor) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_val *tools = yyjson_mut_arr(doc);

    if (offset < 0) {
        offset = 0;
    }
    int allowed_count = mcp_allowed_tool_count(profile);
    if (offset > allowed_count) {
        offset = allowed_count;
    }
    if (limit < 0 || limit > allowed_count) {
        limit = allowed_count;
    }

    int end = offset + limit;
    if (end > allowed_count) {
        end = allowed_count;
    }

    int visible = 0;
    for (int i = 0; i < TOOL_COUNT && visible < end; i++) {
        if (!mcp_tool_allowed(profile, TOOLS[i].name)) {
            continue;
        }
        if (visible >= offset) {
            mcp_add_tool_def(doc, tools, i);
        }
        visible++;
    }

    yyjson_mut_obj_add_val(doc, root, "tools", tools);
    if (include_next_cursor && end < allowed_count) {
        char cursor[MCP_CURSOR_TEXT_CAP];
        snprintf(cursor, sizeof(cursor), "%d", end);
        yyjson_mut_obj_add_strcpy(doc, root, "nextCursor", cursor);
    }

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

char *cbm_mcp_tools_list(void) {
    return cbm_mcp_tools_list_range(CBM_MCP_TOOL_PROFILE_ALL, 0, TOOL_COUNT, false);
}

/* Return the JSON input_schema string for a tool by name, or NULL if unknown.
 * Used by the CLI to build --flag arguments and per-tool --help from the same
 * source of truth the MCP tools/list advertises. Static lifetime; do not free. */
const char *cbm_mcp_tool_input_schema(const char *tool_name) {
    if (!tool_name) {
        return NULL;
    }
    for (int i = 0; i < TOOL_COUNT; i++) {
        if (strcmp(TOOLS[i].name, tool_name) == 0) {
            return TOOLS[i].input_schema;
        }
    }
    return NULL;
}

int cbm_mcp_tool_count(void) {
    return TOOL_COUNT;
}

const char *cbm_mcp_tool_name(int index) {
    if (index < 0 || index >= TOOL_COUNT) {
        return NULL;
    }
    return TOOLS[index].name;
}

/* Render the top-level --help "Tools:" block from the registry tools/list
 * serves. The list used to be hand-maintained in the help text and drifted
 * when check_index_coverage was added (#1361); deriving it here makes that
 * divergence impossible. Heap-allocated; caller frees. */
/* Append at out[len] and return the bytes ACTUALLY written.
 *
 * snprintf returns the length it WOULD have written, so accumulating that value
 * lets len run past cap; the next `cap - len` then underflows to a huge size_t
 * and the following write lands outside the buffer. CodeQL flagged exactly that
 * shape here, and it is the same class #1173 just fixed in the Cypher list
 * builder. The capacity computed below does happen to be sufficient today —
 * which makes this the more dangerous version, not the safer one: the code is
 * correct only by an argument made ten lines away, so renaming a tool or
 * changing the wrap rule would turn it into an overflow with nothing to notice.
 * Clamping makes `len <= cap - 1` a local invariant no later edit can void. */
static size_t help_append(char *out, size_t cap, size_t len, const char *fmt, ...) {
    if (len + MCP_STRING_TERMINATOR_BYTES >= cap) {
        return 0;
    }
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(out + len, cap - len, fmt, args);
    va_end(args);
    if (written <= 0) {
        return 0;
    }
    size_t room = cap - len - MCP_STRING_TERMINATOR_BYTES;
    return (size_t)written > room ? room : (size_t)written;
}

char *cbm_mcp_tools_help_list(void) {
    size_t cap = SLEN("Tools:") + MCP_HELP_TRAILER_BYTES; /* trailing newline + NUL */
    for (int i = 0; i < TOOL_COUNT; i++) {
        cap += strlen(TOOLS[i].name) + SLEN(" ,\n "); /* per-tool worst case incl. a wrap */
    }
    char *out = malloc(cap);
    if (!out) {
        return NULL;
    }
    size_t len = help_append(out, cap, 0, "Tools:");
    size_t col = len;
    for (int i = 0; i < TOOL_COUNT; i++) {
        const char *sep = (i + MCP_NEXT_ARGUMENT < TOOL_COUNT) ? "," : "";
        size_t item = SLEN(" ") + strlen(TOOLS[i].name) + strlen(sep);
        if (i > 0 && col + item > MCP_HELP_TOOLS_WRAP_COL) {
            len += help_append(out, cap, len, "\n ");
            col = MCP_HELP_CONTINUATION_INDENT;
        }
        size_t wrote = help_append(out, cap, len, " %s%s", TOOLS[i].name, sep);
        len += wrote;
        col += wrote;
    }
    len += help_append(out, cap, len, "\n");
    (void)len; /* final length is not needed; the buffer is NUL-terminated */
    return out;
}

static int mcp_tools_cursor_offset(const char *params_json, bool *has_cursor_out) {
    if (has_cursor_out) {
        *has_cursor_out = false;
    }
    if (!params_json) {
        return 0;
    }

    yyjson_doc *doc = yyjson_read(params_json, strlen(params_json), 0);
    if (!doc) {
        return 0;
    }

    int offset = 0;
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *cursor = root ? yyjson_obj_get(root, "cursor") : NULL;
    if (cursor) {
        if (has_cursor_out) {
            *has_cursor_out = true;
        }
        offset = TOOL_COUNT;
        if (yyjson_is_str(cursor)) {
            const char *cursor_str = yyjson_get_str(cursor);
            if (cursor_str && *cursor_str != '\0') {
                char *endptr = NULL;
                errno = 0;
                long parsed = strtol(cursor_str, &endptr, MCP_DECIMAL_RADIX);
                if (endptr && *endptr == '\0' && errno == 0 && parsed >= 0) {
                    offset = parsed > TOOL_COUNT ? TOOL_COUNT : (int)parsed;
                }
            }
        }
    }

    yyjson_doc_free(doc);
    return offset;
}

static char *cbm_mcp_tools_list_page(cbm_mcp_tool_profile_t profile, const char *params_json) {
    bool has_cursor = false;
    int offset = mcp_tools_cursor_offset(params_json, &has_cursor);
    if (!has_cursor) {
        return cbm_mcp_tools_list_range(profile, 0, TOOL_COUNT, false);
    }
    return cbm_mcp_tools_list_range(profile, offset, MCP_TOOLS_PAGE_SIZE, true);
}

/* ── Prompt definitions ───────────────────────────────────────── */

static void mcp_add_prompt_argument(yyjson_mut_doc *doc, yyjson_mut_val *arguments,
                                    const char *name, const char *title, const char *description,
                                    bool required) {
    yyjson_mut_val *argument = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, argument, "name", name);
    yyjson_mut_obj_add_str(doc, argument, "title", title);
    yyjson_mut_obj_add_str(doc, argument, "description", description);
    yyjson_mut_obj_add_bool(doc, argument, "required", required);
    yyjson_mut_arr_add_val(arguments, argument);
}

static char *cbm_mcp_prompts_list(void) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_val *prompts = yyjson_mut_arr(doc);

    yyjson_mut_val *explore = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, explore, "name", "explore_codebase");
    yyjson_mut_obj_add_str(doc, explore, "title", "Explore codebase");
    yyjson_mut_obj_add_str(doc, explore, "description",
                           "Explore a codebase with graph-first structural discovery.");
    yyjson_mut_val *explore_arguments = yyjson_mut_arr(doc);
    mcp_add_prompt_argument(doc, explore_arguments, "project", "Project",
                            "Indexed project name from list_projects.", true);
    mcp_add_prompt_argument(doc, explore_arguments, "question", "Question",
                            "Architecture or implementation question to investigate.", true);
    yyjson_mut_obj_add_val(doc, explore, "arguments", explore_arguments);
    yyjson_mut_arr_add_val(prompts, explore);

    yyjson_mut_val *review = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, review, "name", "review_change_impact");
    yyjson_mut_obj_add_str(doc, review, "title", "Review change impact");
    yyjson_mut_obj_add_str(doc, review, "description",
                           "Review affected callers, tests, boundaries, and risks.");
    yyjson_mut_val *review_arguments = yyjson_mut_arr(doc);
    mcp_add_prompt_argument(doc, review_arguments, "project", "Project",
                            "Indexed project name from list_projects.", true);
    mcp_add_prompt_argument(doc, review_arguments, "change", "Change",
                            "Change, symbol, or area whose impact should be reviewed.", true);
    mcp_add_prompt_argument(doc, review_arguments, "base_branch", "Base branch",
                            "Git branch or ref for detect_changes; defaults to main.", false);
    yyjson_mut_obj_add_val(doc, review, "arguments", review_arguments);
    yyjson_mut_arr_add_val(prompts, review);

    yyjson_mut_obj_add_val(doc, root, "prompts", prompts);
    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

static const char *mcp_prompt_string_argument(yyjson_val *arguments, const char *name) {
    if (!arguments || !yyjson_is_obj(arguments)) {
        return NULL;
    }
    yyjson_val *value = yyjson_obj_get(arguments, name);
    if (!value || !yyjson_is_str(value)) {
        return NULL;
    }
    const char *text = yyjson_get_str(value);
    return text && text[0] ? text : NULL;
}

static char *mcp_prompt_result(const char *description, const char *text) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "description", description);

    yyjson_mut_val *messages = yyjson_mut_arr(doc);
    yyjson_mut_val *message = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, message, "role", "user");
    yyjson_mut_val *content = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, content, "type", "text");
    yyjson_mut_obj_add_str(doc, content, "text", text);
    yyjson_mut_obj_add_val(doc, message, "content", content);
    yyjson_mut_arr_add_val(messages, message);
    yyjson_mut_obj_add_val(doc, root, "messages", messages);

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

static char *mcp_prompt_error_json(int code, const char *message) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_int(doc, root, "code", code);
    yyjson_mut_obj_add_str(doc, root, "message", message);
    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

static char *mcp_prompt_fail(yyjson_doc *params_doc, char **error_json, int code,
                             const char *message) {
    *error_json = mcp_prompt_error_json(code, message);
    if (params_doc) {
        yyjson_doc_free(params_doc);
    }
    return NULL;
}

static const char *mcp_prompt_base_branch(yyjson_val *arguments, bool is_review, bool *valid_out) {
    *valid_out = true;
    if (!is_review || !arguments || !yyjson_is_obj(arguments)) {
        return "main";
    }
    yyjson_val *value = yyjson_obj_get(arguments, "base_branch");
    if (!value) {
        return "main";
    }
    if (!yyjson_is_str(value) || !yyjson_get_str(value)[0]) {
        *valid_out = false;
        return NULL;
    }
    return yyjson_get_str(value);
}

static char *cbm_mcp_prompt_get(const char *params_json, char **error_json) {
    *error_json = NULL;
    yyjson_doc *params_doc = params_json ? yyjson_read(params_json, strlen(params_json), 0) : NULL;
    yyjson_val *params = params_doc ? yyjson_doc_get_root(params_doc) : NULL;
    yyjson_val *name_value =
        params && yyjson_is_obj(params) ? yyjson_obj_get(params, "name") : NULL;
    if (!name_value || !yyjson_is_str(name_value)) {
        return mcp_prompt_fail(params_doc, error_json, JSONRPC_INVALID_PARAMS,
                               "Invalid prompt name");
    }

    const char *name = yyjson_get_str(name_value);
    bool is_explore = strcmp(name, "explore_codebase") == 0;
    bool is_review = strcmp(name, "review_change_impact") == 0;
    if (!is_explore && !is_review) {
        return mcp_prompt_fail(params_doc, error_json, JSONRPC_INVALID_PARAMS,
                               "Invalid prompt name");
    }

    yyjson_val *arguments = yyjson_obj_get(params, "arguments");
    const char *project = mcp_prompt_string_argument(arguments, "project");
    const char *request = mcp_prompt_string_argument(arguments, is_explore ? "question" : "change");
    if (!project || !request) {
        return mcp_prompt_fail(params_doc, error_json, JSONRPC_INVALID_PARAMS,
                               "Missing required prompt arguments");
    }

    bool base_branch_valid = false;
    const char *base_branch = mcp_prompt_base_branch(arguments, is_review, &base_branch_valid);
    if (!base_branch_valid) {
        return mcp_prompt_fail(params_doc, error_json, JSONRPC_INVALID_PARAMS,
                               "Invalid prompt arguments");
    }

    static const char EXPLORE_TEMPLATE[] =
        "Explore project \"%s\" to answer: %s\n\n"
        "Use graph tools first: search_graph to find relevant symbols, get_code_snippet for "
        "exact source, and trace_path(direction=\"both\") for callers and callees. Use "
        "get_architecture for broad orientation and query_graph only for multi-hop patterns. "
        "Check has_more and paginate. Fall back to search_code or grep only for literal or "
        "non-code text, or where graph coverage is incomplete.";
    static const char REVIEW_TEMPLATE[] =
        "Review change impact in project \"%s\" for: %s\n\n"
        "Use detect_changes with base_branch \"%s\", then trace_path(direction=\"both\", "
        "include_tests=true) for affected callers, callees, and tests. Read exact definitions "
        "with get_code_snippet and use query_graph for cross-boundary patterns. Report affected "
        "callers, tests, boundaries, and risks; do not modify files.";

    size_t text_size = strlen(project) + strlen(request) + strlen(base_branch) +
                       (is_explore ? sizeof(EXPLORE_TEMPLATE) : sizeof(REVIEW_TEMPLATE));
    char *text = malloc(text_size);
    if (!text) {
        return mcp_prompt_fail(params_doc, error_json, JSONRPC_INTERNAL_ERROR, "Internal error");
    }
    if (is_explore) {
        snprintf(text, text_size, EXPLORE_TEMPLATE, project, request);
    } else {
        snprintf(text, text_size, REVIEW_TEMPLATE, project, request, base_branch);
    }

    char *result = mcp_prompt_result(
        is_explore ? "Graph-first codebase exploration" : "Graph-first change-impact review", text);
    free(text);
    yyjson_doc_free(params_doc);
    return result;
}

/* Supported protocol versions, newest first. The server picks the newest
 * version that it shares with the client (per MCP spec version negotiation). */
static const char *SUPPORTED_PROTOCOL_VERSIONS[] = {
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
};
static const int SUPPORTED_VERSION_COUNT =
    (int)(sizeof(SUPPORTED_PROTOCOL_VERSIONS) / sizeof(SUPPORTED_PROTOCOL_VERSIONS[0]));

static const char MCP_SERVER_INSTRUCTIONS[] =
    "Use graph tools first for structural code discovery: search_graph to find symbols, "
    "trace_path for callers and callees, get_code_snippet for exact source, query_graph for "
    "complex multi-hop patterns, and get_architecture for orientation. Use search_code or "
    "filesystem grep for literal or non-code text, or when graph coverage is insufficient. "
    "Call list_projects before initial use and index_repository only when a repository is not "
    "indexed or to force immediate freshness after a large external update. Once indexed, "
    "watched projects auto-refresh in the background; use index_status for project health and "
    "check_index_coverage for every cited path and for scopes behind negative or exhaustive "
    "claims. Coverage is best-effort, never proof of completeness. Check has_more or nextCursor "
    "and paginate when present.";

static const char MCP_ANALYSIS_SERVER_INSTRUCTIONS[] =
    "This is the analysis tool profile; graph and index mutation tools are unavailable. Use "
    "list_projects and index_status to select a current graph project, then use search_graph, "
    "trace_path, get_code_snippet, query_graph, get_architecture, and search_code for read-only "
    "analysis. Call check_index_coverage for every cited path and for scopes behind negative or "
    "exhaustive claims; read flagged ranges or skipped files directly. Coverage is best-effort, "
    "never proof of completeness. Check has_more or nextCursor and paginate when present. If the "
    "project is missing or stale, ask the parent agent to index or refresh it.";

static const char MCP_SCOUT_SERVER_INSTRUCTIONS[] =
    "This is the scout tool profile; only the fast positive-discovery graph tools are available. "
    "Use list_projects and index_status to select a current graph project, then use search_graph, "
    "trace_path, get_code_snippet, and get_architecture with narrow limits. Call "
    "check_index_coverage once for every cited path and read flagged ranges directly. Findings "
    "are provisional: do not make absence, exhaustive-impact, or dead-code claims. If the project "
    "is missing or stale, ask the parent agent to index or refresh it.";

static char *cbm_mcp_initialize_response_for_profile(const char *params_json,
                                                     cbm_mcp_tool_profile_t profile) {
    /* Determine protocol version: if client requests a version we support,
     * echo it back; otherwise respond with our latest. */
    const char *version = SUPPORTED_PROTOCOL_VERSIONS[0]; /* default: latest */
    if (params_json) {
        yyjson_doc *pdoc = yyjson_read(params_json, strlen(params_json), 0);
        if (pdoc) {
            yyjson_val *pv = yyjson_obj_get(yyjson_doc_get_root(pdoc), "protocolVersion");
            if (pv && yyjson_is_str(pv)) {
                const char *requested = yyjson_get_str(pv);
                for (int i = 0; i < SUPPORTED_VERSION_COUNT; i++) {
                    if (strcmp(requested, SUPPORTED_PROTOCOL_VERSIONS[i]) == 0) {
                        version = SUPPORTED_PROTOCOL_VERSIONS[i];
                        break;
                    }
                }
            }
            yyjson_doc_free(pdoc);
        }
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "protocolVersion", version);

    yyjson_mut_val *impl = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, impl, "name", "codebase-memory-mcp");
    yyjson_mut_obj_add_str(doc, impl, "version", cbm_build_version_get());
    yyjson_mut_obj_add_val(doc, root, "serverInfo", impl);

    yyjson_mut_val *caps = yyjson_mut_obj(doc);
    yyjson_mut_val *tools_cap = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_bool(doc, tools_cap, "listChanged", false);
    yyjson_mut_obj_add_val(doc, caps, "tools", tools_cap);
    yyjson_mut_val *prompts_cap = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_bool(doc, prompts_cap, "listChanged", false);
    yyjson_mut_obj_add_val(doc, caps, "prompts", prompts_cap);
    yyjson_mut_obj_add_val(doc, root, "capabilities", caps);
    const char *instructions = MCP_SERVER_INSTRUCTIONS;
    if (profile == CBM_MCP_TOOL_PROFILE_ANALYSIS) {
        instructions = MCP_ANALYSIS_SERVER_INSTRUCTIONS;
    } else if (profile == CBM_MCP_TOOL_PROFILE_SCOUT) {
        instructions = MCP_SCOUT_SERVER_INSTRUCTIONS;
    }
    yyjson_mut_obj_add_str(doc, root, "instructions", instructions);

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

char *cbm_mcp_initialize_response(const char *params_json) {
    return cbm_mcp_initialize_response_for_profile(params_json, CBM_MCP_TOOL_PROFILE_ALL);
}

/* ══════════════════════════════════════════════════════════════════
 *  ARGUMENT EXTRACTION
 * ══════════════════════════════════════════════════════════════════ */

char *cbm_mcp_get_tool_name(const char *params_json) {
    yyjson_doc *doc = yyjson_read(params_json, strlen(params_json), 0);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *name = yyjson_obj_get(root, "name");
    char *result = NULL;
    if (name && yyjson_is_str(name)) {
        result = heap_strdup(yyjson_get_str(name));
    }
    yyjson_doc_free(doc);
    return result;
}

char *cbm_mcp_get_arguments(const char *params_json) {
    yyjson_doc *doc = yyjson_read(params_json, strlen(params_json), 0);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *args = yyjson_obj_get(root, "arguments");
    char *result = NULL;
    if (args) {
        result = yyjson_val_write(args, 0, NULL);
    }
    yyjson_doc_free(doc);
    return result ? result : heap_strdup("{}");
}

char *cbm_mcp_get_string_arg(const char *args_json, const char *key) {
    yyjson_doc *doc = yyjson_read(args_json, strlen(args_json), 0);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *val = yyjson_obj_get(root, key);
    char *result = NULL;
    if (val && yyjson_is_str(val)) {
        result = heap_strdup(yyjson_get_str(val));
    }
    yyjson_doc_free(doc);
    return result;
}

static char *canonicalize_repo_path_if_exists(char *repo_path) {
    if (!repo_path) {
        return NULL;
    }
    bool root_syntax = true;
    for (const char *p = repo_path; *p; p++) {
        if (*p != '/' && *p != '\\' && *p != ':') {
            root_syntax = false;
            break;
        }
    }
    if (root_syntax) {
        return repo_path;
    }

    char real[CBM_SZ_4K];
    /* Wide-path canonicalization: the old _access/_fullpath pair decoded the
     * UTF-8 repo_path through the ANSI codepage and corrupted CJK paths on
     * CJK-locale systems (#973). */
    if (cbm_canonical_path(repo_path, real, sizeof(real))) {
        cbm_normalize_path_sep(real);
        char *canonical = heap_strdup(real);
        if (canonical) {
            free(repo_path);
            return canonical;
        }
    }

    return repo_path;
}

static bool repo_path_is_absolute(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }
#ifdef _WIN32
    /* Path separators are normalized before this helper is called. A drive-
     * relative path such as "C:repo" is deliberately not considered absolute. */
    return (path[0] == '/' && path[1] == '/') ||
           (isalpha((unsigned char)path[0]) && path[1] == ':' && path[2] == '/');
#else
    return path[0] == '/';
#endif
}

static char *normalize_project_arg(char *project) {
    if (!project || (!strchr(project, '/') && !strchr(project, '\\'))) {
        return project;
    }

    project = canonicalize_repo_path_if_exists(project);
    char *normalized = cbm_project_name_from_path(project);
    if (normalized) {
        free(project);
        return normalized;
    }
    return project;
}

/* Forward decls — defined below alongside store resolution. */
static const char *cache_dir(char *buf, size_t bufsz);
static bool is_project_db_file(const char *name, size_t len);

/* #1025: agents naturally pass the repo FOLDER name ("codebase-memory-mcp"),
 * but indexed project names derive from the full path
 * (E:\project\graph\x -> "E-project-graph-x"), so the exact lookup fails
 * while list_projects clearly shows the project. When no <project>.db exists,
 * scan cache-dir FILENAMES for a segment-aligned tail match ("-<project>.db"):
 * exactly one match adopts the full name; zero or several keep the original so
 * the existing not-found error (which lists all candidates) fires. Filename-
 * level only — internal-name drift stays #704's fallback in resolve_store. */
static char *resolve_project_tail(char *project) {
    if (!project || !cbm_validate_project_name(project)) {
        return project;
    }
    char dir[CBM_SZ_1K];
    cache_dir(dir, sizeof(dir));
    char exact[CBM_SZ_2K];
    snprintf(exact, sizeof(exact), "%s/%s.db", dir, project);
    if (cbm_file_exists(exact)) {
        return project; /* exact name — untouched fast path */
    }
    size_t plen = strlen(project);
    char match[CBM_SZ_1K] = "";
    int matches = 0;
    cbm_dir_t *d = cbm_opendir(dir);
    if (!d) {
        return project;
    }
    cbm_dirent_t *entry;
    while ((entry = cbm_readdir(d)) != NULL) {
        const char *n = entry->name;
        size_t len = strlen(n);
        if (!is_project_db_file(n, len)) {
            continue;
        }
        size_t stem_len = len - MCP_DB_EXT; /* strip ".db" */
        if (stem_len <= plen + MCP_PROJECT_NAME_SEGMENT_DELIMITER_BYTES ||
            stem_len >= sizeof(match)) {
            continue;
        }
        if (n[stem_len - plen - MCP_PROJECT_NAME_SEGMENT_DELIMITER_BYTES] != '-' ||
            strncmp(n + stem_len - plen, project, plen) != 0) {
            continue;
        }
        matches++;
        if (matches > MCP_PROJECT_NAME_UNIQUE_MATCHES) {
            break; /* ambiguous — keep the original name */
        }
        memcpy(match, n, stem_len);
        match[stem_len] = '\0';
    }
    cbm_closedir(d);
    if (matches == MCP_PROJECT_NAME_UNIQUE_MATCHES) {
        cbm_log_info("mcp.project_tail_resolved", "passed", project, "resolved", match);
        free(project);
        return heap_strdup(match);
    }
    return project;
}

/* Resolve the project argument, accepting the canonical "project" key plus the
 * aliases a caller naturally reaches for (#640): list_projects surfaces the
 * field as "name" and the not-found hint says "pass the project name", so
 * "project_name" is the usual guess; "project_id" / "projectName" are accepted
 * too. NOT bare "name" — index_repository uses "name" for an explicit
 * project-name override. Caller must free() the result. */
static char *get_project_arg(const char *args_json) {
    char *p = cbm_mcp_get_string_arg(args_json, "project");
    if (!p) {
        p = cbm_mcp_get_string_arg(args_json, "project_name");
    }
    if (!p) {
        p = cbm_mcp_get_string_arg(args_json, "project_id");
    }
    if (!p) {
        p = cbm_mcp_get_string_arg(args_json, "projectName");
    }
    return resolve_project_tail(normalize_project_arg(p));
}

int cbm_mcp_get_int_arg(const char *args_json, const char *key, int default_val) {
    yyjson_doc *doc = yyjson_read(args_json, strlen(args_json), 0);
    if (!doc) {
        return default_val;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *val = yyjson_obj_get(root, key);
    int result = default_val;
    if (val && yyjson_is_int(val)) {
        result = yyjson_get_int(val);
    }
    yyjson_doc_free(doc);
    return result;
}

bool cbm_mcp_get_bool_arg(const char *args_json, const char *key) {
    yyjson_doc *doc = yyjson_read(args_json, strlen(args_json), 0);
    if (!doc) {
        return false;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *val = yyjson_obj_get(root, key);
    bool result = false;
    if (val && yyjson_is_bool(val)) {
        result = yyjson_get_bool(val);
    }
    yyjson_doc_free(doc);
    return result;
}

/* ══════════════════════════════════════════════════════════════════
 *  MCP SERVER
 * ══════════════════════════════════════════════════════════════════ */

struct cbm_mcp_server {
    cbm_store_t *store;     /* currently open project store (or NULL) */
    bool owns_store;        /* true if we opened the store */
    char *current_project;  /* which project store is open for (heap) */
    time_t store_last_used; /* last time resolve_store was called for a named project */

    /* Session + auto-index state */
    char session_root[CBM_SZ_1K];     /* detected project root path */
    char session_project[CBM_SZ_256]; /* derived project name */
    bool session_detected;            /* true after first detection attempt */
    char *allowed_root;               /* explicit per-session boundary (heap, nullable) */
    bool allowed_root_policy_set;     /* true even when explicit policy is unrestricted */
    bool background_tasks;            /* per-server update/auto-index work enabled */
    struct cbm_watcher *watcher;      /* external watcher ref (not owned) */
    struct cbm_config *config;        /* external config ref (not owned) */
    cbm_mcp_index_executor_fn index_executor;
    void *index_executor_context;
    cbm_proc_log_cb index_log_callback;
    void *index_log_context;
    cbm_mcp_project_mutation_begin_fn mutation_begin;
    cbm_mcp_project_mutation_try_begin_fn mutation_try_begin;
    cbm_mcp_project_mutation_end_fn mutation_end;
    void *mutation_context;
    cbm_mcp_quarantine_test_hook_fn quarantine_test_hook;
    void *quarantine_test_context;
    cbm_mcp_command_test_hook_fn command_test_hook;
    void *command_test_context;
    cbm_thread_t autoindex_tid;
    bool autoindex_active; /* true if auto-index thread was started */

    /* Request-scoped cancellation. The flag is shared by every cancellable
     * operation reached during one tool dispatch; active_pipeline remains a
     * diagnostic pointer for index_repository only. */
    cbm_mutex_t request_scope_mutex;
    unsigned int request_scope_depth;
    atomic_int pipeline_cancel_requested;
    cbm_pipeline_t *active_pipeline; /* non-NULL while index_repository runs */
    int64_t active_request_id;       /* JSON-RPC id of the in-progress tool call */
    char *active_request_id_str;     /* string JSON-RPC id of the in-progress tool call */
    cbm_mcp_tool_profile_t tool_profile;
};

cbm_mcp_server_t *cbm_mcp_server_new(const char *store_path) {
    cbm_mcp_server_t *srv = calloc(CBM_ALLOC_ONE, sizeof(*srv));
    if (!srv) {
        return NULL;
    }
    cbm_mutex_init(&srv->request_scope_mutex);
    atomic_init(&srv->pipeline_cancel_requested, 0);

    /* If a store_path is given, open that project directly.
     * Otherwise, create an in-memory store for test/embedded use. */
    if (store_path) {
        srv->store = cbm_store_open(store_path);
        srv->current_project = heap_strdup(store_path);
    } else {
        srv->store = cbm_store_open_memory();
    }
    srv->owns_store = true;
    srv->tool_profile = CBM_MCP_TOOL_PROFILE_ALL;
    srv->background_tasks = true;

    return srv;
}

void cbm_mcp_server_set_tool_profile(cbm_mcp_server_t *srv, cbm_mcp_tool_profile_t profile) {
    if (srv) {
        srv->tool_profile = profile;
    }
}

cbm_store_t *cbm_mcp_server_store(cbm_mcp_server_t *srv) {
    return srv ? srv->store : NULL;
}

void cbm_mcp_server_set_project(cbm_mcp_server_t *srv, const char *project) {
    if (!srv) {
        return;
    }
    free(srv->current_project);
    srv->current_project = project ? heap_strdup(project) : NULL;
}

void cbm_mcp_server_set_watcher(cbm_mcp_server_t *srv, struct cbm_watcher *w) {
    if (srv) {
        srv->watcher = w;
    }
}

void cbm_mcp_server_set_config(cbm_mcp_server_t *srv, struct cbm_config *cfg) {
    if (srv) {
        srv->config = cfg;
    }
}

bool cbm_mcp_server_set_session_context(cbm_mcp_server_t *srv, const char *session_root,
                                        const char *allowed_root) {
    if (!srv || !session_root || session_root[0] == '\0' ||
        strlen(session_root) >= sizeof(srv->session_root)) {
        return false;
    }

    char *project = cbm_project_name_from_path(session_root);
    if (!project || project[0] == '\0' || strlen(project) >= sizeof(srv->session_project)) {
        free(project);
        return false;
    }

    char *allowed_copy = allowed_root ? heap_strdup(allowed_root) : NULL;
    if (allowed_root && !allowed_copy) {
        free(project);
        return false;
    }

    snprintf(srv->session_root, sizeof(srv->session_root), "%s", session_root);
    snprintf(srv->session_project, sizeof(srv->session_project), "%s", project);
    free(project);

    free(srv->allowed_root);
    srv->allowed_root = allowed_copy;
    srv->allowed_root_policy_set = true;
    srv->session_detected = true;
    return true;
}

const char *cbm_mcp_server_session_root(const cbm_mcp_server_t *srv) {
    return srv ? srv->session_root : NULL;
}

const char *cbm_mcp_server_session_project(const cbm_mcp_server_t *srv) {
    return srv ? srv->session_project : NULL;
}

const char *cbm_mcp_server_allowed_root(const cbm_mcp_server_t *srv) {
    return srv ? srv->allowed_root : NULL;
}

void cbm_mcp_server_set_background_tasks(cbm_mcp_server_t *srv, bool enabled) {
    if (srv) {
        srv->background_tasks = enabled;
    }
}

void cbm_mcp_server_set_index_executor(cbm_mcp_server_t *srv, cbm_mcp_index_executor_fn executor,
                                       void *context) {
    if (srv) {
        srv->index_executor = executor;
        srv->index_executor_context = context;
    }
}

void cbm_mcp_server_set_index_log_callback(cbm_mcp_server_t *srv, cbm_proc_log_cb callback,
                                           void *context) {
    if (srv) {
        srv->index_log_callback = callback;
        srv->index_log_context = callback ? context : NULL;
    }
}

void cbm_mcp_server_set_project_mutation_guard(cbm_mcp_server_t *srv,
                                               cbm_mcp_project_mutation_begin_fn begin,
                                               cbm_mcp_project_mutation_end_fn end, void *context) {
    if (!srv) {
        return;
    }
    /* A half-configured guard could acquire without releasing (or mutate
     * without acquiring), so accept only complete callback pairs. */
    if ((begin == NULL) != (end == NULL)) {
        return;
    }
    srv->mutation_begin = begin;
    srv->mutation_try_begin = NULL;
    srv->mutation_end = end;
    srv->mutation_context = begin ? context : NULL;
}

void cbm_mcp_server_set_project_mutation_try_guard(
    cbm_mcp_server_t *srv, cbm_mcp_project_mutation_try_begin_fn try_begin) {
    if (srv && srv->mutation_begin) {
        srv->mutation_try_begin = try_begin;
    }
}

static bool mcp_project_mutation_begin(cbm_mcp_server_t *srv, const char *project) {
    return srv && (!srv->mutation_begin || srv->mutation_begin(srv->mutation_context, project));
}

static bool mcp_project_mutation_try_begin(cbm_mcp_server_t *srv, const char *project) {
    return srv &&
           (!srv->mutation_begin ||
            (srv->mutation_try_begin && srv->mutation_try_begin(srv->mutation_context, project)));
}

static void mcp_project_mutation_end(cbm_mcp_server_t *srv, const char *project) {
    if (srv && srv->mutation_end) {
        srv->mutation_end(srv->mutation_context, project);
    }
}

void cbm_mcp_server_free(cbm_mcp_server_t *srv) {
    if (!srv) {
        return;
    }
    if (srv->autoindex_active) {
        cbm_thread_join(&srv->autoindex_tid);
    }
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
    }
    free(srv->current_project);
    free(srv->allowed_root);
    free(srv->active_request_id_str);
    cbm_mutex_destroy(&srv->request_scope_mutex);
    free(srv);
}

/* ── Idle store eviction ──────────────────────────────────────── */

void cbm_mcp_server_evict_idle(cbm_mcp_server_t *srv, int timeout_s) {
    if (!srv || !srv->store) {
        return;
    }
    /* Protect initial in-memory stores that were never accessed via a named project.
     * store_last_used stays 0 until resolve_store is called with a non-NULL project. */
    if (srv->store_last_used == 0) {
        return;
    }

    time_t now = time(NULL);
    if ((now - srv->store_last_used) < timeout_s) {
        return;
    }

    if (srv->owns_store) {
        cbm_store_close(srv->store);
    }
    srv->store = NULL;
    free(srv->current_project);
    srv->current_project = NULL;
    srv->store_last_used = 0;
}

bool cbm_mcp_server_has_cached_store(cbm_mcp_server_t *srv) {
    return (srv && srv->store != NULL) != 0;
}

bool cbm_mcp_server_release_pristine_memory_store(cbm_mcp_server_t *srv) {
    const char *db_path = srv && srv->store ? cbm_store_db_path(srv->store) : NULL;
    if (!srv || !srv->owns_store || !srv->store || srv->current_project ||
        srv->store_last_used != 0 || db_path != NULL) {
        return false;
    }
    cbm_store_close(srv->store);
    srv->store = NULL;
    return true;
}

cbm_pipeline_t *cbm_mcp_server_active_pipeline(cbm_mcp_server_t *srv) {
    return srv ? srv->active_pipeline : NULL;
}

bool cbm_mcp_server_cancel_active(cbm_mcp_server_t *srv) {
    if (!srv) {
        return false;
    }
    cbm_mutex_lock(&srv->request_scope_mutex);
    bool active = srv->request_scope_depth != 0;
    if (active) {
        atomic_store_explicit(&srv->pipeline_cancel_requested, MCP_CANCEL_REQUESTED,
                              memory_order_release);
    }
    cbm_mutex_unlock(&srv->request_scope_mutex);
    return active;
}

bool cbm_mcp_server_request_scope_begin(cbm_mcp_server_t *srv) {
    if (!srv) {
        return false;
    }
    cbm_mutex_lock(&srv->request_scope_mutex);
    bool available = srv->request_scope_depth < UINT_MAX;
    if (available) {
        if (srv->request_scope_depth == 0) {
            atomic_store_explicit(&srv->pipeline_cancel_requested, 0, memory_order_release);
        }
        srv->request_scope_depth++;
    }
    cbm_mutex_unlock(&srv->request_scope_mutex);
    return available;
}

void cbm_mcp_server_request_scope_end(cbm_mcp_server_t *srv) {
    if (!srv) {
        return;
    }
    cbm_mutex_lock(&srv->request_scope_mutex);
    if (srv->request_scope_depth > 0) {
        srv->request_scope_depth--;
        if (srv->request_scope_depth == 0) {
            atomic_store_explicit(&srv->pipeline_cancel_requested, 0, memory_order_release);
        }
    }
    cbm_mutex_unlock(&srv->request_scope_mutex);
}

static bool mcp_request_cancelled(const cbm_mcp_server_t *srv) {
    return srv && atomic_load_explicit(&srv->pipeline_cancel_requested, memory_order_acquire) != 0;
}

void cbm_mcp_server_set_quarantine_test_hook(cbm_mcp_server_t *srv,
                                             cbm_mcp_quarantine_test_hook_fn hook, void *context) {
    if (!srv) {
        return;
    }
    srv->quarantine_test_hook = hook;
    srv->quarantine_test_context = context;
}

void cbm_mcp_server_set_command_test_hook(cbm_mcp_server_t *srv, cbm_mcp_command_test_hook_fn hook,
                                          void *context) {
    if (!srv) {
        return;
    }
    srv->command_test_hook = hook;
    srv->command_test_context = context;
}

/* ── Cache dir + project DB path helpers ───────────────────────── */

/* Returns the cache directory. Writes to buf, returns buf for convenience. */
static const char *cache_dir(char *buf, size_t bufsz) {
    const char *dir = cbm_resolve_cache_dir();
    if (!dir) {
        dir = cbm_tmpdir();
    }
    snprintf(buf, bufsz, "%s", dir);
    return buf;
}

/* Returns full .db path for a project: <cache_dir>/<project>.db */
static const char *project_db_path(const char *project, char *buf, size_t bufsz) {
    if (!cbm_validate_project_name(project)) {
        buf[0] = '\0';
        return buf;
    }
    char dir[CBM_SZ_1K];
    cache_dir(dir, sizeof(dir));
    snprintf(buf, bufsz, "%s/%s.db", dir, project);
    return buf;
}

/* ── Store resolution ──────────────────────────────────────────── */

/* Read the sole INTERNAL project name from a .db file at full_path.
 * Opens the file query-mode (no create) and succeeds ONLY when the db holds
 * exactly one project row with a non-empty name — this filters ghost/empty
 * /corrupt dbs (0-byte file, missing `projects` table, or >1 row). On success
 * the internal name is copied into name_out; if out_store is non-NULL the open
 * handle is transferred to the caller (who must cbm_store_close it). On failure
 * the store is always closed. Defined after is_project_db_file below. */
static bool db_internal_project_name(const char *full_path, char *name_out, size_t name_sz,
                                     cbm_store_t **out_store);

/* #704 fallback: scan the cache dir for the db whose sole internal project name
 * equals `project`, returning an open store handle (caller owns it) or NULL.
 * Used only when <project>.db is absent or its internal name differs from the
 * passed name (drifted filename). Defined after is_project_db_file below. */
static cbm_store_t *resolve_store_fallback_scan(const char *project);

static bool reserve_unique_corrupt_pending(const char *path, char *pending, size_t pending_size,
                                           char *backup, size_t backup_size) {
    static atomic_uint_fast64_t sequence = 0;
    for (unsigned int attempt = 0; attempt < MCP_CORRUPT_PENDING_MAX_ATTEMPTS; attempt++) {
        uint64_t token = cbm_now_ns() ^ ((uint64_t)(unsigned int)getpid() << MCP_TOKEN_PID_SHIFT) ^
                         atomic_fetch_add_explicit(&sequence, MCP_TOKEN_SEQUENCE_INCREMENT,
                                                   memory_order_relaxed);
        int backup_written =
            snprintf(backup, backup_size, "%s.corrupt.%016llx", path, (unsigned long long)token);
        int pending_written = snprintf(pending, pending_size, "%s.corrupt.pending.%016llx", path,
                                       (unsigned long long)token);
        if (backup_written <= 0 || (size_t)backup_written >= backup_size || pending_written <= 0 ||
            (size_t)pending_written >= pending_size) {
            return false;
        }
        if (cbm_file_exists(backup)) {
            continue;
        }
#ifdef _WIN32
        wchar_t *wide = cbm_path_to_wide(pending);
        HANDLE file = wide ? CreateFileW(wide, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                         FILE_ATTRIBUTE_NORMAL, NULL)
                           : INVALID_HANDLE_VALUE;
        DWORD create_error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        free(wide);
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
            return true;
        }
        if (create_error != ERROR_FILE_EXISTS && create_error != ERROR_ALREADY_EXISTS) {
            return false;
        }
#else
        int fd = open(pending, O_WRONLY | O_CREAT | O_EXCL, MCP_PRIVATE_FILE_MODE);
        if (fd >= 0) {
            (void)close(fd);
            return true;
        }
        if (errno != EEXIST) {
            return false;
        }
#endif
    }
    return false;
}

static void discard_corrupt_pending(const char *pending) {
    if (!pending) {
        return;
    }
    (void)cbm_remove_db_sidecars(pending);
    (void)cbm_unlink(pending);
}

#ifndef _WIN32
static bool sync_parent_directory(const char *path) {
    char directory[CBM_SZ_2K];
    int written = snprintf(directory, sizeof(directory), "%s", path ? path : "");
    if (written <= 0 || (size_t)written >= sizeof(directory)) {
        return false;
    }
    char *slash = strrchr(directory, '/');
    if (!slash) {
        snprintf(directory, sizeof(directory), ".");
    } else if (slash == directory) {
        slash[MCP_ROOT_PATH_SLASH_INDEX] = '\0';
    } else {
        *slash = '\0';
    }
    int fd = open(directory, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        return false;
    }
    int rc;
    do {
        rc = fsync(fd);
    } while (rc != 0 && errno == EINTR);
    (void)close(fd);
    return rc == 0;
}
#endif

/* Publish only a fully closed SQLite snapshot, without ever replacing a prior
 * recovery file. POSIX link() and Windows MoveFileExW without REPLACE are
 * atomic no-clobber operations within the cache directory. */
static bool publish_corrupt_backup(const char *pending, const char *backup) {
#ifdef _WIN32
    wchar_t *wide_pending = cbm_path_to_wide(pending);
    wchar_t *wide_backup = cbm_path_to_wide(backup);
    bool published = wide_pending && wide_backup &&
                     MoveFileExW(wide_pending, wide_backup, MOVEFILE_WRITE_THROUGH) != 0;
    free(wide_pending);
    free(wide_backup);
    return published;
#else
    if (link(pending, backup) != 0) {
        return false;
    }
    if (!sync_parent_directory(backup)) {
        (void)cbm_unlink(backup);
        return false;
    }
    /* A crash before this cleanup merely leaves a second link to the same
     * complete snapshot; the published recovery generation is already safe. */
    (void)cbm_unlink(pending);
    (void)sync_parent_directory(backup);
    return true;
#endif
}

static bool quarantine_step_allowed(cbm_mcp_server_t *srv, const char *step) {
    return !srv || !srv->quarantine_test_hook ||
           srv->quarantine_test_hook(srv->quarantine_test_context, step);
}

/* Create one transactionally consistent, self-contained recovery snapshot
 * (SQLite backup incorporates committed WAL frames), publish it atomically,
 * and only then remove the corrupt live generation. A crash can therefore
 * leave the live DB, the completed backup, or both, but never destroys the
 * only recoverable generation. */
static bool quarantine_corrupt_store(cbm_mcp_server_t *srv, const char *project, const char *path,
                                     char *backup_out, size_t backup_out_size) {
    char backup[CBM_SZ_2K];
    char pending[CBM_SZ_2K];
    /* #1425 belt-and-braces: an empty store path would render the backup as a
     * bare relative ".corrupt.<hex>" in the process cwd. There is nothing at
     * such a path worth quarantining. */
    if (!path || !path[0]) {
        cbm_log_error("store.auto_clean_failed", "project", project, "path", "", "reason",
                      "empty store path");
        return false;
    }
    if (!reserve_unique_corrupt_pending(path, pending, sizeof(pending), backup, sizeof(backup))) {
        cbm_log_error("store.auto_clean_failed", "project", project, "path", path, "reason",
                      "cannot reserve unique backup");
        return false;
    }

    if (cbm_store_backup_path(path, pending) != CBM_STORE_OK ||
        cbm_store_prepare_path_for_replace(pending) != CBM_STORE_OK) {
        discard_corrupt_pending(pending);
        cbm_log_error("store.auto_clean_failed", "project", project, "path", path, "reason",
                      "cannot create self-contained recovery snapshot");
        return false;
    }

    cbm_store_t *snapshot = cbm_store_open_path_query(pending);
    if (!snapshot) {
        discard_corrupt_pending(pending);
        cbm_log_error("store.auto_clean_failed", "project", project, "path", path, "reason",
                      "recovery snapshot cannot be reopened");
        return false;
    }
    cbm_store_close(snapshot);

    if (!quarantine_step_allowed(srv, "before_snapshot_publish") ||
        !publish_corrupt_backup(pending, backup)) {
        discard_corrupt_pending(pending);
        cbm_log_error("store.auto_clean_failed", "project", project, "path", path, "reason",
                      "cannot atomically publish recovery snapshot");
        return false;
    }
    discard_corrupt_pending(pending);

    if (!quarantine_step_allowed(srv, "after_snapshot_publish")) {
        cbm_log_error("store.auto_clean_failed", "project", project, "path", path, "reason",
                      "backup complete; live generation retained", "backup", backup);
        return false;
    }

    if (cbm_unlink(path) != 0 && errno != ENOENT) {
        cbm_log_error("store.auto_clean_failed", "project", project, "path", path, "reason",
                      "backup complete; live database removal failed", "backup", backup);
        return false;
    }
    if (cbm_remove_db_sidecars(path) != 0) {
        cbm_log_error("store.auto_clean_sidecars", "project", project, "path", path, "reason",
                      "backup complete; stale sidecar cleanup deferred");
    }

    if (backup_out && backup_out_size > 0) {
        snprintf(backup_out, backup_out_size, "%s", backup);
    }
    return true;
}

/* Open the right project's .db file for query tools.
 * Caches the connection — reopens only when project changes.
 * Tracks last-access time so the event loop can evict idle stores. */
typedef enum {
    STORE_RECOVERY_NONE,
    STORE_RECOVERY_BUSY,
    STORE_RECOVERY_TRY_GUARD_UNAVAILABLE,
} store_recovery_status_t;

static void mcp_store_adopt(cbm_mcp_server_t *srv, const char *project, cbm_store_t *store) {
    srv->store = store;
    srv->owns_store = true;
    free(srv->current_project);
    srv->current_project = heap_strdup(project);
}

static void mcp_store_close_owned(cbm_mcp_server_t *srv) {
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
        srv->store = NULL;
    }
}

static bool mcp_store_recovery_acquire(cbm_mcp_server_t *srv, const char *project,
                                       bool mutation_already_held, bool nonblocking_recovery,
                                       store_recovery_status_t *recovery_status) {
    if (mutation_already_held) {
        return true;
    }
    bool acquired = nonblocking_recovery ? mcp_project_mutation_try_begin(srv, project)
                                         : mcp_project_mutation_begin(srv, project);
    if (!acquired && nonblocking_recovery && recovery_status) {
        *recovery_status =
            srv->mutation_try_begin ? STORE_RECOVERY_BUSY : STORE_RECOVERY_TRY_GUARD_UNAVAILABLE;
    }
    return acquired;
}

static bool mcp_store_recover_corrupt(cbm_mcp_server_t *srv, const char *project, const char *path,
                                      bool mutation_already_held, bool nonblocking_recovery,
                                      store_recovery_status_t *recovery_status) {
    cbm_store_close(srv->store);
    srv->store = NULL;
    if (!mcp_store_recovery_acquire(srv, project, mutation_already_held, nonblocking_recovery,
                                    recovery_status)) {
        return false;
    }
    srv->store = cbm_store_open_path_query(path);
    bool current_valid = srv->store && cbm_store_check_integrity(srv->store);
    if (!current_valid) {
        cbm_store_close(srv->store);
        srv->store = NULL;
        char backup[CBM_SZ_2K] = {0};
        bool quarantined = quarantine_corrupt_store(srv, project, path, backup, sizeof(backup));
        cbm_log_error("store.auto_clean", "project", project, "path", path, "action",
                      quarantined ? "corrupt generation quarantined"
                                  : "corrupt generation preserved",
                      "backup", quarantined ? backup : "none");
    }
    if (!mutation_already_held) {
        mcp_project_mutation_end(srv, project);
    }
    return srv->store != NULL;
}

static bool mcp_store_current_project_matches(cbm_mcp_server_t *srv, const char *project) {
    cbm_project_t verified_project = {0};
    if (cbm_store_get_project(srv->store, project, &verified_project) != CBM_STORE_OK) {
        return false;
    }
    cbm_project_free_fields(&verified_project);
    mcp_store_adopt(srv, project, srv->store);
    return true;
}

static cbm_store_t *resolve_store_internal(cbm_mcp_server_t *srv, const char *project,
                                           bool mutation_already_held, bool nonblocking_recovery,
                                           store_recovery_status_t *recovery_status) {
    if (recovery_status) {
        *recovery_status = STORE_RECOVERY_NONE;
    }
    if (!srv || !project) {
        return NULL; /* project is required — no implicit fallback */
    }

    srv->store_last_used = time(NULL);

    /* Already open for this project? */
    if (srv->current_project && strcmp(srv->current_project, project) == 0 && srv->store) {
        return srv->store;
    }

    /* Close old store. */
    mcp_store_close_owned(srv);

    /* Open project's .db file — query-only open (no SQLITE_OPEN_CREATE) to
     * prevent ghost .db file creation for unknown/unindexed projects.
     * #1425: an invalid project name yields an empty path. SQLite opens ""
     * as an anonymous temp db, which then fails the integrity check and
     * quarantines a db that never existed — as a RELATIVE .corrupt.<hex>
     * file in the daemon's cwd. Skip the direct open entirely; the fallback
     * scan below still resolves legacy dbs whose internal name predates
     * validation. */
    char path[CBM_SZ_1K];
    project_db_path(project, path, sizeof(path));
    srv->store = path[0] ? cbm_store_open_path_query(path) : NULL;
    if (srv->store) {
        /* Check DB integrity — back up (never silently delete) a corrupt DB */
        if (!cbm_store_check_integrity(srv->store) &&
            !mcp_store_recover_corrupt(srv, project, path, mutation_already_held,
                                       nonblocking_recovery, recovery_status)) {
            return NULL;
        }

        /* Verify the project actually exists in this database.
         * A .db file may exist but be empty (e.g., after delete_project on
         * Linux where unlink defers actual removal). Opening an empty/deleted
         * store without closing it leaks the SQLite connection. */
        if (mcp_store_current_project_matches(srv, project)) {
            return srv->store; /* fast path: filename == internal name */
        }
        /* #704: <project>.db exists but its INTERNAL project name differs from
         * the passed name (a copied/renamed db, or a legacy '.'-vs-'-' username
         * twin). Close it and fall through to the cache-dir scan below. */
        cbm_store_close(srv->store);
        srv->store = NULL;
    }

    /* #704 fallback: either <project>.db is absent or its internal name drifted
     * from its filename. Node rows are keyed on the INTERNAL name (== the passed
     * name, since list_projects now advertises internal names), so scan the
     * cache dir for the db whose sole internal project name equals `project` and
     * adopt it. Runs ONLY on the fallback — the common fast path is unchanged.
     * No match → NULL (a genuine typo stays not-found). */
    cbm_store_t *scanned = resolve_store_fallback_scan(project);
    if (scanned) {
        mcp_store_adopt(srv, project, scanned);
    }

    return srv->store;
}

static cbm_store_t *resolve_store(cbm_mcp_server_t *srv, const char *project) {
    return resolve_store_internal(srv, project, false, false, NULL);
}

/* Forward decl — definition lives below alongside list_projects. */

/* Forward decl — definition lives below in handle_trace_call_path's helpers. */
static void free_node_contents(cbm_node_t *n);

/* Scan cache dir for .db files, writing comma-separated quoted names into out.
 * Returns the number of projects found. */
static int collect_db_project_names(const char *dir_path, char *out, size_t out_sz) {
    int count = 0;
    int offset = 0;
    cbm_dir_t *d = cbm_opendir(dir_path);
    if (!d) {
        return 0;
    }
    cbm_dirent_t *entry;
    while ((entry = cbm_readdir(d)) != NULL) {
        const char *n = entry->name;
        size_t len = strlen(n);
        if (!is_project_db_file(n, len)) {
            continue;
        }
        /* #704: advertise the db's INTERNAL project name, not its filename, and
         * skip ghost/empty/corrupt dbs — so the hint lists names the user can
         * actually pass to resolve a store. */
        char full_path[CBM_SZ_2K];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, n);
        char iname[CBM_SZ_1K];
        if (!db_internal_project_name(full_path, iname, sizeof(iname), NULL)) {
            continue;
        }
        /* Element-boundary write: only emit this name if the WHOLE element —
         * optional leading comma + "iname" — plus the NUL fits in what remains.
         * Never truncate mid-token; a partial name would corrupt the JSON array
         * (issue #235). Stop cleanly at the last name that fits: the array then
         * always holds complete names and `count` == its length. */
        size_t off = (size_t)offset;
        size_t need = strlen(iname) + MCP_QUOTED_NAME_DELIMITERS /* quotes */ +
                      (count > 0 ? MCP_JSON_LIST_SEPARATOR_BYTES : 0U) /* comma */;
        if (off + need + MCP_STRING_TERMINATOR_BYTES > out_sz) {
            break; /* would not fit entirely — stop at this element boundary */
        }
        if (count > 0) {
            out[offset++] = ',';
        }
        int wrote = snprintf(out + offset, out_sz - (size_t)offset, "\"%s\"", iname);
        if (wrote > 0) {
            offset += wrote; /* guaranteed to fit (checked above) — no truncation */
        }
        count++;
    }
    cbm_closedir(d);
    return count;
}

static void add_git_context_string(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key,
                                   const char *value) {
    if (value) {
        yyjson_mut_obj_add_strcpy(doc, obj, key, value);
    } else {
        yyjson_mut_obj_add_null(doc, obj, key);
    }
}

static void add_git_context_json(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *root_path,
                                 const cbm_mcp_server_t *srv) {
    cbm_git_context_t ctx = {0};
    (void)cbm_git_context_resolve_cancellable(root_path,
                                              srv ? &srv->pipeline_cancel_requested : NULL, &ctx);

    yyjson_mut_val *git = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_bool(doc, git, "is_git", ctx.is_git);
    yyjson_mut_obj_add_bool(doc, git, "is_worktree", ctx.is_worktree);
    yyjson_mut_obj_add_bool(doc, git, "is_detached", ctx.is_detached);
    yyjson_mut_obj_add_bool(doc, git, "root_exists", ctx.root_exists);
    add_git_context_string(doc, git, "worktree_root", ctx.worktree_root);
    add_git_context_string(doc, git, "git_dir", ctx.git_dir);
    add_git_context_string(doc, git, "git_common_dir", ctx.git_common_dir);
    add_git_context_string(doc, git, "canonical_root", ctx.canonical_root);
    add_git_context_string(doc, git, "branch", ctx.branch);
    add_git_context_string(doc, git, "branch_slug", ctx.branch_slug);
    add_git_context_string(doc, git, "head_sha", ctx.head_sha);
    add_git_context_string(doc, git, "base_sha", ctx.base_sha);
    yyjson_mut_obj_add_val(doc, obj, "git", git);

    cbm_git_context_free(&ctx);
}

/* Build a helpful error listing available projects. Caller must free() result. */
static char *build_project_list_error(const char *reason) {
    char dir_path[CBM_SZ_1K];
    cache_dir(dir_path, sizeof(dir_path));

    char projects[CBM_SZ_4K] = "";
    int count = collect_db_project_names(dir_path, projects, sizeof(projects));

    enum { ERR_BUF_SZ = 5120 };
    char buf[ERR_BUF_SZ];
    if (count > 0) {
        snprintf(buf, sizeof(buf),
                 "{\"error\":\"%s\",\"hint\":\"Use list_projects to see all indexed projects, "
                 "then pass it as the \\\"project\\\" "
                 "argument.\",\"available_projects\":[%s],\"count\":%d}",
                 reason, projects, count);
    } else {
        snprintf(buf, sizeof(buf),
                 "{\"error\":\"%s\",\"hint\":\"No projects indexed yet. "
                 "Call index_repository first.\"}",
                 reason);
    }
    return heap_strdup(buf);
}

/* Distinct from "unknown project": the caller omitted the project argument
 * entirely (no recognized key). Name the literal "project" key so the fix is
 * obvious (#640). Caller must free() result. */
static char *build_missing_project_error(void) {
    return heap_strdup("{\"error\":\"missing required argument: project\",\"hint\":\"Pass "
                       "the project as the \\\"project\\\" argument, e.g. "
                       "{\\\"project\\\":\\\"<name from list_projects>\\\"}. Run "
                       "list_projects to see indexed projects.\"}");
}

/* Pick the right no-store error: a NULL project means the argument was missing
 * (clearer message); a non-NULL project that didn't resolve means it's
 * unknown/unindexed (list the available ones). */
static char *build_no_store_error(const char *project) {
    return project ? build_project_list_error("project not found or not indexed")
                   : build_missing_project_error();
}

/* Bail with the right error when no store is available. */
#define REQUIRE_STORE(store, project)                     \
    do {                                                  \
        if (!(store)) {                                   \
            char *_err = build_no_store_error(project);   \
            char *_res = cbm_mcp_text_result(_err, true); \
            free(_err);                                   \
            free(project);                                \
            return _res;                                  \
        }                                                 \
    } while (0)

static bool project_has_adr(cbm_store_t *store, const char *project, const char *root_path) {
    if (store && project) {
        cbm_adr_t adr;
        memset(&adr, 0, sizeof(adr));
        if (cbm_store_adr_get(store, project, &adr) == CBM_STORE_OK) {
            cbm_store_adr_free(&adr);
            return true;
        }
    }

    if (!root_path) {
        return false;
    }

    char adr_path[CBM_SZ_4K];
    snprintf(adr_path, sizeof(adr_path), "%s/.codebase-memory/adr.md", root_path);
    struct stat adr_st;
    return stat(adr_path, &adr_st) == 0;
}

/* ── Tool handler implementations ─────────────────────────────── */

/* Return true if filename is a valid project .db file (not temp/internal).
 *
 * Project names derived from /tmp/... source roots legitimately begin with
 * "tmp-" (cbm_project_name_from_path: "/tmp/bench/..." → "tmp-bench-...";
 * see tests/test_pipeline.c fixtures), so the prefix must NOT be excluded.
 * The "_" prefix is reserved for internal/hidden DBs, and ":memory:" is the
 * SQLite in-memory marker (defensive — never appears as a real file). */
static bool is_project_db_file(const char *name, size_t len) {
    if (len < MCP_MIN_DB_NAME || strcmp(name + len - MCP_DB_EXT, ".db") != 0) {
        return false;
    }
    if (strncmp(name, "_", SLEN("_")) == 0 || strncmp(name, ":memory:", SLEN(":memory:")) == 0) {
        return false;
    }
    return true;
}

/* db_internal_project_name — see forward declaration above resolve_store. */
static bool db_internal_project_name(const char *full_path, char *name_out, size_t name_sz,
                                     cbm_store_t **out_store) {
    if (out_store) {
        *out_store = NULL;
    }
    cbm_store_t *st = cbm_store_open_path_query(full_path);
    if (!st) {
        return false; /* nonexistent / unreadable */
    }
    cbm_project_t *projs = NULL;
    int n = 0;
    bool ok = false;
    if (cbm_store_list_projects(st, &projs, &n) == CBM_STORE_OK) {
        /* Ignore internal shadow projects ("<name>::missed" miss-graph rows):
         * they share the db with the primary project and must not make it
         * unresolvable — requiring n == 1 over ALL rows made every project
         * with a miss graph vanish from list_projects and the UI (#1044). */
        int primary = MCP_PRIMARY_PROJECT_INDEX_ABSENT;
        int primary_count = 0;
        for (int i = 0; i < n; i++) {
            if (projs[i].name && projs[i].name[0] && !strstr(projs[i].name, "::")) {
                primary = i;
                primary_count++;
            }
        }
        if (primary_count == MCP_SINGLE_PRIMARY_PROJECT) {
            snprintf(name_out, name_sz, "%s", projs[primary].name);
            ok = true;
        }
    }
    cbm_store_free_projects(projs, n);
    if (ok && out_store) {
        *out_store = st; /* transfer ownership to caller */
    } else {
        cbm_store_close(st);
    }
    return ok;
}

/* resolve_store_fallback_scan — see forward declaration above resolve_store. */
static cbm_store_t *resolve_store_fallback_scan(const char *project) {
    char dir_path[CBM_SZ_1K];
    cache_dir(dir_path, sizeof(dir_path));
    cbm_dir_t *d = cbm_opendir(dir_path);
    if (!d) {
        return NULL;
    }
    cbm_store_t *found = NULL;
    cbm_dirent_t *entry;
    while ((entry = cbm_readdir(d)) != NULL) {
        const char *n = entry->name;
        size_t len = strlen(n);
        if (!is_project_db_file(n, len)) {
            continue;
        }
        char full_path[CBM_SZ_2K];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, n);
        char iname[CBM_SZ_1K];
        cbm_store_t *st = NULL;
        if (db_internal_project_name(full_path, iname, sizeof(iname), &st)) {
            if (strcmp(iname, project) == 0) {
                found = st; /* adopt — caller takes ownership */
                break;
            }
            cbm_store_close(st);
        }
    }
    cbm_closedir(d);
    return found;
}

/* Open a .db file briefly, collect node/edge counts and root_path,
 * then append a JSON entry to arr. */
static void build_project_json_entry(yyjson_mut_doc *doc, yyjson_mut_val *arr, const char *dir_path,
                                     const char *name, size_t name_len, int64_t size_bytes,
                                     bool metadata_only, const cbm_mcp_server_t *srv) {
    (void)name_len;

    char full_path[CBM_SZ_2K];
    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);

    /* #704: key on the db's INTERNAL project name, not its filename. Node/edge
     * rows are tagged with the internal name, so a drifted filename (copied or
     * renamed db, legacy '.'-vs-'-' username twin) would otherwise report 0
     * nodes/edges and be unresolvable. Skip ghost/empty/corrupt dbs entirely so
     * they don't appear as resolvable projects. */
    char project_name[CBM_SZ_1K];
    cbm_store_t *pstore = NULL;
    if (!db_internal_project_name(full_path, project_name, sizeof(project_name), &pstore)) {
        return; /* ghost / unreadable — not a resolvable project */
    }

    int nodes = 0;
    int edges = 0;
    if (!metadata_only) {
        nodes = cbm_store_count_nodes(pstore, project_name);
        edges = cbm_store_count_edges(pstore, project_name);
    }
    char root_path_buf[CBM_SZ_1K] = "";
    cbm_project_t proj = {0};
    if (cbm_store_get_project(pstore, project_name, &proj) == CBM_STORE_OK) {
        if (proj.root_path) {
            snprintf(root_path_buf, sizeof(root_path_buf), "%s", proj.root_path);
        }
        cbm_project_free_fields(&proj);
    }
    cbm_store_close(pstore);

    yyjson_mut_val *p = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, p, "name", project_name);
    yyjson_mut_obj_add_strcpy(doc, p, "root_path", root_path_buf);
    /* Listing stays lean: only the branch (the one git fact that
     * disambiguates same-repo projects). The 12-field git block — mostly
     * null for non-git roots — cost ~10KB across a full cache and is one
     * index_status call away for the project you actually care about. */
    if (!metadata_only && root_path_buf[0]) {
        cbm_git_context_t gctx = {0};
        (void)cbm_git_context_resolve_cancellable(
            root_path_buf, srv ? &srv->pipeline_cancel_requested : NULL, &gctx);
        if (gctx.is_git && gctx.branch) {
            yyjson_mut_obj_add_strcpy(doc, p, "branch", gctx.branch);
        }
        cbm_git_context_free(&gctx);
    }
    if (!metadata_only) {
        yyjson_mut_obj_add_int(doc, p, "nodes", nodes);
        yyjson_mut_obj_add_int(doc, p, "edges", edges);
        yyjson_mut_obj_add_int(doc, p, "size_bytes", size_bytes);
    }
    yyjson_mut_arr_add_val(arr, p);
}

/* list_projects: scan cache directory for .db files.
 * Each project is a single .db file — no central registry needed. */
static char *handle_list_projects(cbm_mcp_server_t *srv, const char *args) {
    bool metadata_only = false;
    yyjson_doc *args_doc = args ? yyjson_read(args, strlen(args), 0) : NULL;
    yyjson_val *args_root = args_doc ? yyjson_doc_get_root(args_doc) : NULL;
    yyjson_val *metadata_value =
        args_root && yyjson_is_obj(args_root) ? yyjson_obj_get(args_root, "metadata_only") : NULL;
    metadata_only = metadata_value && yyjson_is_true(metadata_value);
    if (args_doc) {
        yyjson_doc_free(args_doc);
    }

    char dir_path[CBM_SZ_1K];
    cache_dir(dir_path, sizeof(dir_path));

    cbm_dir_t *d = cbm_opendir(dir_path);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_val *arr = yyjson_mut_arr(doc);

    if (!d) {
        char msg[CBM_SZ_1K];
        snprintf(msg, sizeof(msg),
                 "{\"error\":\"cannot read cache directory: %s\",\"hint\":"
                 "\"Check directory permissions or run index_repository first.\"}",
                 dir_path);
        yyjson_mut_doc_free(doc);
        return cbm_mcp_text_result(msg, true);
    }

    cbm_dirent_t *entry;
    while ((entry = cbm_readdir(d)) != NULL) {
        const char *name = entry->name;
        size_t len = strlen(name);
        if (!is_project_db_file(name, len)) {
            continue;
        }
        char full_path[CBM_SZ_2K];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);
        int64_t size_bytes = cbm_file_size(full_path);
        if (size_bytes < 0) {
            continue;
        }
        build_project_json_entry(doc, arr, dir_path, name, len, size_bytes, metadata_only, srv);
    }
    cbm_closedir(d);

    yyjson_mut_obj_add_val(doc, root, "projects", arr);

    /* Guide user when no projects are indexed */
    if (yyjson_mut_arr_size(arr) == 0) {
        yyjson_mut_obj_add_str(doc, root, "hint",
                               "No projects indexed. Call index_repository(repo_path=...) first.");
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* verify_project_indexed — returns a heap-allocated error JSON string when the
 * named project has not been indexed yet, or NULL when the project exists.
 * resolve_store uses cbm_store_open_path_query (no SQLITE_OPEN_CREATE), so
 * store is NULL for missing .db files (REQUIRE_STORE fires first). This
 * function catches the remaining case: a .db file exists but has no indexed
 * nodes (e.g., an empty or half-initialised project).
 * Callers that receive a non-NULL return value must free(project) themselves
 * before returning the error string. */
static char *verify_project_indexed(cbm_store_t *store, const char *project) {
    cbm_project_t proj_check = {0};
    if (cbm_store_get_project(store, project, &proj_check) != CBM_STORE_OK) {
        char *err = build_project_list_error("project not indexed — run index_repository first");
        char *res = cbm_mcp_text_result(err, true);
        free(err);
        return res;
    }
    cbm_project_free_fields(&proj_check);
    return NULL;
}

static bool sg_field_blocked(const char *f); /* internal-only fields, defined with search_graph */

static char *handle_get_graph_schema(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    REQUIRE_STORE(store, project);

    char *not_indexed = verify_project_indexed(store, project);
    if (not_indexed) {
        free(project);
        return not_indexed;
    }

    cbm_schema_info_t schema = {0};
    cbm_store_get_schema(store, project, &schema);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_val *labels = yyjson_mut_arr(doc);
    for (int i = 0; i < schema.node_label_count; i++) {
        yyjson_mut_val *lbl = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_str(doc, lbl, "label", schema.node_labels[i].label);
        yyjson_mut_obj_add_int(doc, lbl, "count", schema.node_labels[i].count);
        yyjson_mut_val *props = yyjson_mut_arr(doc);
        for (int j = 0; j < schema.node_labels[i].property_count; j++) {
            /* Internal similarity intermediates (fp/sp/bt) are blocked from every
             * tool response — advertising them here invited agents to request
             * fields the server then silently refuses. Filter them from the
             * schema so it only describes obtainable properties. */
            if (sg_field_blocked(schema.node_labels[i].properties[j])) {
                continue;
            }
            yyjson_mut_arr_add_str(doc, props, schema.node_labels[i].properties[j]);
        }
        yyjson_mut_obj_add_val(doc, lbl, "properties", props);
        yyjson_mut_arr_add_val(labels, lbl);
    }
    yyjson_mut_obj_add_val(doc, root, "node_labels", labels);

    yyjson_mut_val *types = yyjson_mut_arr(doc);
    for (int i = 0; i < schema.edge_type_count; i++) {
        yyjson_mut_val *typ = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_str(doc, typ, "type", schema.edge_types[i].type);
        yyjson_mut_obj_add_int(doc, typ, "count", schema.edge_types[i].count);
        yyjson_mut_val *eprops = yyjson_mut_arr(doc);
        for (int j = 0; j < schema.edge_types[i].property_count; j++) {
            yyjson_mut_arr_add_str(doc, eprops, schema.edge_types[i].properties[j]);
        }
        yyjson_mut_obj_add_val(doc, typ, "properties", eprops);
        yyjson_mut_arr_add_val(types, typ);
    }
    yyjson_mut_obj_add_val(doc, root, "edge_types", types);

    /* Check ADR presence */
    cbm_project_t proj_info = {0};
    if (cbm_store_get_project(store, project, &proj_info) == 0 && proj_info.root_path) {
        bool adr_exists = project_has_adr(store, project, proj_info.root_path);
        yyjson_mut_obj_add_bool(doc, root, "adr_present", adr_exists);
        if (!adr_exists) {
            yyjson_mut_obj_add_str(
                doc, root, "adr_hint",
                "No ADR found. Use manage_adr(mode='update') to persist architectural "
                "decisions across sessions. Run get_architecture(aspects=['all']) first.");
        }
        cbm_project_free_fields(&proj_info);
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    cbm_store_schema_free(&schema);
    free(project);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* Validate edge type: uppercase letters + underscore only, max 64 chars. */
static bool validate_edge_type(const char *s) {
    if (!s || strlen(s) > CBM_SZ_64) {
        return false;
    }
    for (const char *c = s; *c; c++) {
        if (!(*c >= 'A' && *c <= 'Z') && *c != '_') {
            return false;
        }
    }
    return true;
}

/* Enrich search result with 1-hop connected node names. */
/* Add BFS results to a yyjson array (deduped by name). */
static void enrich_add_bfs(yyjson_mut_doc *doc, yyjson_mut_val *arr, cbm_traverse_result_t *tr) {
    for (int j = 0; j < tr->visited_count; j++) {
        if (tr->visited[j].node.name) {
            yyjson_mut_arr_add_strcpy(doc, arr, tr->visited[j].node.name);
        }
    }
}

/* Enrich search result with 1-hop connected node names (inbound + outbound). */
/* Build the connected-names array (1-hop callers + callees) for a node.
 * Returns a (possibly empty) yyjson array owned by doc. */
static yyjson_mut_val *enrich_connected(yyjson_mut_doc *doc, cbm_store_t *store, int64_t node_id,
                                        const char *relationship) {
    const char *et[] = {relationship ? relationship : "CALLS"};
    yyjson_mut_val *conn = yyjson_mut_arr(doc);

    /* BFS doesn't support "both" — run inbound + outbound separately. */
    cbm_traverse_result_t tr_in = {0};
    cbm_store_bfs(store, node_id, "inbound", et, SKIP_ONE, SKIP_ONE, MCP_DEFAULT_LIMIT, &tr_in);
    enrich_add_bfs(doc, conn, &tr_in);
    cbm_store_traverse_free(&tr_in);

    cbm_traverse_result_t tr_out = {0};
    cbm_store_bfs(store, node_id, "outbound", et, SKIP_ONE, SKIP_ONE, MCP_DEFAULT_LIMIT, &tr_out);
    enrich_add_bfs(doc, conn, &tr_out);
    cbm_store_traverse_free(&tr_out);

    return conn;
}

/* Text-tree variant: the same 1-hop neighbor names ';'-joined into buf (no
 * commas/spaces in names, so the cell needs no quoting). Empty when none. */
static void enrich_connected_joined(cbm_store_t *store, int64_t node_id, const char *relationship,
                                    char *buf, size_t bufsz) {
    buf[0] = '\0';
    const char *et[] = {relationship ? relationship : "CALLS"};
    size_t off = 0;
    const char *dirs[MCP_TRACE_DIRECTION_COUNT] = {"inbound", "outbound"};
    for (int d = 0; d < MCP_TRACE_DIRECTION_COUNT; d++) {
        cbm_traverse_result_t tr = {0};
        cbm_store_bfs(store, node_id, dirs[d], et, SKIP_ONE, SKIP_ONE, MCP_DEFAULT_LIMIT, &tr);
        for (int j = 0; j < tr.visited_count && off + MCP_JOINED_NAME_TRAILER_BYTES < bufsz; j++) {
            if (!tr.visited[j].node.name) {
                continue;
            }
            int n =
                snprintf(buf + off, bufsz - off, "%s%s", off ? ";" : "", tr.visited[j].node.name);
            if (n < 0 || (size_t)n >= bufsz - off) {
                buf[off] = '\0';
                break;
            }
            off += (size_t)n;
        }
        cbm_store_traverse_free(&tr);
    }
}

/* Build an FTS5 MATCH expression from a free-form query string by splitting
 * on whitespace and joining the terms with OR.  Each token is also sanitized:
 * anything that isn't alnum or underscore is dropped, so the caller can't
 * inject FTS5 operators or double-quoted phrases.  Returns the number of
 * tokens emitted (0 if the query contained no usable terms). */
enum {
    BM25_MIN_BUF = 2, /* minimum buffer size: at least NUL + one char */
    BM25_SEP_RESERVE = 1,
    BM25_QUERY_BUF = 1024,
    BM25_DEFAULT_LIMIT = 50,
    BM25_COL_ID = 0,
    BM25_COL_LABEL = 1,
    BM25_COL_NAME = 2,
    BM25_COL_QN = 3,
    BM25_COL_FILE = 4,
    BM25_COL_START = 5,
    BM25_COL_END = 6,
    BM25_COL_RANK = 7,
    BM25_BIND_QUERY = 1,
    BM25_BIND_PROJECT = 2,
    BM25_BIND_LIMIT = 3,
    BM25_BIND_OFFSET = 4,
    BM25_BIND_INNER = 5,
    BM25_BIND_FILE = 6,
    BM25_SQL_AUTO_LEN = -1,
    /* Inner FTS5 candidate cap.  SQLite can early-terminate a plain FTS5 query
     * (no JOIN/WHERE on outer table) of the form:
     *   SELECT rowid, bm25() FROM nodes_fts WHERE MATCH ? ORDER BY bm25() LIMIT N
     * By fetching only the top BM25_INNER_LIMIT candidates from the FTS5 index
     * and then joining/filtering/re-ranking those, we bound all work to O(N) where
     * N = BM25_INNER_LIMIT rather than the full match set size. */
    BM25_INNER_LIMIT = 2000,
};

static int bm25_build_match(const char *query, char *out, size_t out_size) {
    if (!query || !out || out_size < BM25_MIN_BUF) {
        return 0;
    }
    size_t pos = 0;
    int tokens = 0;
    const char *p = query;
    while (*p) {
        while (*p && !((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                       (*p >= '0' && *p <= '9') || *p == '_')) {
            p++;
        }
        if (!*p) {
            break;
        }
        const char *tok_start = p;
        while (*p && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                      (*p >= '0' && *p <= '9') || *p == '_')) {
            p++;
        }
        size_t tok_len = (size_t)(p - tok_start);
        if (tok_len == 0) {
            continue;
        }
        const char *sep = (tokens > 0) ? " OR " : "";
        size_t sep_len = strlen(sep);
        if (pos + sep_len + tok_len + BM25_SEP_RESERVE >= out_size) {
            break; /* out of room — stop cleanly, keep what we have */
        }
        memcpy(out + pos, sep, sep_len);
        pos += sep_len;
        memcpy(out + pos, tok_start, tok_len);
        pos += tok_len;
        tokens++;
    }
    out[pos] = '\0';
    return tokens;
}

static char *bm25_file_pattern_like(const char *file_pattern) {
    if (!file_pattern) {
        return NULL;
    }
    char *like = cbm_glob_to_like(file_pattern);
    if (like && !strchr(file_pattern, '*') && !strchr(file_pattern, '?')) {
        size_t len = strlen(like);
        char *contains = malloc(len + MCP_SEPARATOR + SKIP_ONE);
        if (contains) {
            contains[0] = '%';
            memcpy(contains + SKIP_ONE, like, len);
            contains[len + SKIP_ONE] = '%';
            contains[len + MCP_SEPARATOR] = '\0';
            free(like);
            like = contains;
        }
    }
    return like;
}

static const char *const BM25_RESULT_COLUMNS[] = {"qn", "label", "file", "lines", "rank"};

static void bm25_bind_file_filter(cbm_sql_stmt_t *stmt, const char *file_like) {
    if (file_like) {
        cbm_sql_bind_text(stmt, BM25_BIND_FILE, file_like);
    } else {
        cbm_sql_bind_null(stmt, BM25_BIND_FILE);
    }
}

/* The inner FTS5 query has no outer predicates, allowing its WAND/MaxScore
 * early termination. The outer query then applies project/file filters and
 * deterministic boost/tie ordering to that bounded candidate window. */
static cbm_sql_stmt_t *bm25_prepare_results(cbm_sql_t *db, const char *fts_query,
                                            const char *project, const char *file_like, int limit,
                                            int offset) {
    static const char *const sql =
        "SELECT n.id, n.label, n.name, n.qualified_name, n.file_path, n.start_line, n.end_line, "
        "       (fts.base_rank "
        "        - CASE WHEN n.label IN ('Function','Method') THEN 10.0 "
        "               WHEN n.label = 'Route' THEN 8.0 "
        "               WHEN n.label IN (" CBM_SQL_TYPE_LIKE_LABELS ") THEN 5.0 "
        "               ELSE 0.0 END) AS rank "
        "FROM ("
        "    SELECT rowid, bm25(nodes_fts) AS base_rank"
        "    FROM nodes_fts WHERE nodes_fts MATCH ?1"
        "    ORDER BY base_rank LIMIT ?5"
        ") fts "
        "JOIN nodes n ON n.id = fts.rowid "
        "WHERE n.project = ?2 "
        "  AND n.label NOT IN ('File','Folder','Module','Section','Variable','Project') "
        "  AND (?6 IS NULL OR n.file_path LIKE ?6) "
        "ORDER BY rank, n.id "
        "LIMIT ?3 OFFSET ?4";
    cbm_sql_stmt_t *stmt = NULL;
    if (!cbm_sql_prepare(db, sql, &stmt)) {
        return NULL;
    }
    cbm_sql_bind_text(stmt, BM25_BIND_QUERY, fts_query);
    cbm_sql_bind_text(stmt, BM25_BIND_PROJECT, project);
    cbm_sql_bind_int(stmt, BM25_BIND_LIMIT, limit > 0 ? limit : BM25_DEFAULT_LIMIT);
    cbm_sql_bind_int(stmt, BM25_BIND_OFFSET, offset > 0 ? offset : 0);
    cbm_sql_bind_int(stmt, BM25_BIND_INNER, BM25_INNER_LIMIT);
    bm25_bind_file_filter(stmt, file_like);
    return stmt;
}

static int bm25_count_candidates(cbm_sql_t *db, const char *fts_query, const char *project,
                                 const char *file_like) {
    static const char *const count_sql =
        "SELECT COUNT(*) FROM ("
        "    SELECT fts.rowid FROM ("
        "        SELECT rowid FROM nodes_fts WHERE nodes_fts MATCH ?1"
        "        ORDER BY bm25(nodes_fts) LIMIT ?3"
        "    ) fts "
        "    JOIN nodes n ON n.id = fts.rowid "
        "    WHERE n.project = ?2 "
        "      AND n.label NOT IN ('File','Folder','Module','Section','Variable','Project')"
        "      AND (?6 IS NULL OR n.file_path LIKE ?6)"
        ")";
    cbm_sql_stmt_t *count_stmt = NULL;
    if (!cbm_sql_prepare(db, count_sql, &count_stmt)) {
        return 0;
    }
    cbm_sql_bind_text(count_stmt, BM25_BIND_QUERY, fts_query);
    cbm_sql_bind_text(count_stmt, BM25_BIND_PROJECT, project);
    cbm_sql_bind_int(count_stmt, BM25_BIND_LIMIT, BM25_INNER_LIMIT);
    bm25_bind_file_filter(count_stmt, file_like);
    int total = cbm_sql_step(count_stmt) == CBM_SQL_ROW ? cbm_sql_column_int(count_stmt, 0) : 0;
    cbm_sql_finalize(count_stmt);
    return total;
}

static void bm25_line_range(cbm_sql_stmt_t *stmt, char *lines, size_t lines_size) {
    int start_line = cbm_sql_column_int(stmt, BM25_COL_START);
    int end_line = cbm_sql_column_int(stmt, BM25_COL_END);
    if (start_line > 0) {
        snprintf(lines, lines_size, "%d-%d", start_line,
                 end_line > start_line ? end_line : start_line);
    } else {
        lines[0] = '\0';
    }
}

static char *bm25_render_toon(cbm_sql_stmt_t *stmt, int total, int offset) {
    cbm_sb_t rows;
    cbm_sb_init(&rows);
    int emitted = 0;
    while (cbm_sql_step(stmt) == CBM_SQL_ROW) {
        char lines[CBM_SZ_32];
        bm25_line_range(stmt, lines, sizeof(lines));
        cbm_tree_row_begin(&rows);
        cbm_tree_cell_str(&rows, cbm_sql_column_text(stmt, BM25_COL_QN), true);
        cbm_tree_cell_str(&rows, cbm_sql_column_text(stmt, BM25_COL_LABEL), false);
        cbm_tree_cell_str(&rows, cbm_sql_column_text(stmt, BM25_COL_FILE), false);
        cbm_tree_cell_str(&rows, lines, false);
        cbm_tree_cell_real(&rows, cbm_sql_column_double(stmt, BM25_COL_RANK), false);
        cbm_tree_row_end(&rows);
        emitted++;
    }
    cbm_sb_t result;
    cbm_sb_init(&result);
    cbm_tree_scalar_int(&result, "total", total);
    cbm_tree_scalar_str(&result, "search_mode", "bm25");
    cbm_tree_table_header(&result, "results", emitted, BM25_RESULT_COLUMNS,
                          MCP_BM25_RESULT_COLUMN_COUNT);
    char *rows_text = cbm_sb_finish(&rows);
    cbm_sb_append(&result, rows_text ? rows_text : "");
    free(rows_text);
    cbm_tree_scalar_bool(&result, "has_more", total > offset + emitted);
    return cbm_sb_finish(&result);
}

static char *bm25_render_json(cbm_sql_stmt_t *stmt, int total, int offset) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_int(doc, root, "total", total);
    yyjson_mut_obj_add_str(doc, root, "search_mode", "bm25");
    yyjson_mut_val *columns = yyjson_mut_arr(doc);
    for (size_t i = 0; i < sizeof(BM25_RESULT_COLUMNS) / sizeof(BM25_RESULT_COLUMNS[0]); i++) {
        yyjson_mut_arr_add_str(doc, columns, BM25_RESULT_COLUMNS[i]);
    }
    yyjson_mut_obj_add_val(doc, root, "cols", columns);
    yyjson_mut_val *rows = yyjson_mut_arr(doc);
    int emitted = 0;
    while (cbm_sql_step(stmt) == CBM_SQL_ROW) {
        char lines[CBM_SZ_32];
        bm25_line_range(stmt, lines, sizeof(lines));
        yyjson_mut_val *row = yyjson_mut_arr(doc);
        yyjson_mut_arr_add_strcpy(doc, row, cbm_sql_column_text(stmt, BM25_COL_QN));
        yyjson_mut_arr_add_strcpy(doc, row, cbm_sql_column_text(stmt, BM25_COL_LABEL));
        yyjson_mut_arr_add_strcpy(doc, row, cbm_sql_column_text(stmt, BM25_COL_FILE));
        yyjson_mut_arr_add_strcpy(doc, row, lines);
        yyjson_mut_arr_add_real(doc, row, cbm_sql_column_double(stmt, BM25_COL_RANK));
        yyjson_mut_arr_add_val(rows, row);
        emitted++;
    }
    yyjson_mut_obj_add_val(doc, root, "rows", rows);
    yyjson_mut_obj_add_bool(doc, root, "has_more", total > offset + emitted);
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return json;
}

/* Run the BM25 full-text search path and return the JSON result string.
 * Returns NULL if FTS5 is unavailable or the query produced no usable tokens,
 * in which case the caller falls back to the regex-based search path. */
static char *bm25_search(cbm_store_t *store, const char *project, const char *query,
                         const char *file_pattern, int limit, int offset, bool toon) {
    cbm_sql_t *db = cbm_store_sql(store);
    if (!db) {
        return NULL;
    }
    char fts_query[BM25_QUERY_BUF];
    if (bm25_build_match(query, fts_query, sizeof(fts_query)) == 0) {
        return NULL;
    }
    char *file_like = bm25_file_pattern_like(file_pattern);
    cbm_sql_stmt_t *stmt = bm25_prepare_results(db, fts_query, project, file_like, limit, offset);
    if (!stmt) {
        free(file_like);
        return NULL;
    }
    int total = bm25_count_candidates(db, fts_query, project, file_like);
    char *result =
        toon ? bm25_render_toon(stmt, total, offset) : bm25_render_json(stmt, total, offset);
    cbm_sql_finalize(stmt);
    free(file_like);
    return result;
}

/* Extract keyword strings from a yyjson array into `keywords`.  Returns the
 * number of strings copied (capped at `max_out`). */
static int extract_semantic_keywords(yyjson_val *sq_val, const char **keywords, int max_out) {
    int kw_count = (int)yyjson_arr_size(sq_val);
    if (kw_count > max_out) {
        kw_count = max_out;
    }
    size_t kw_idx = 0;
    size_t kw_max = 0;
    yyjson_val *kw_val;
    int ki = 0;
    yyjson_arr_foreach(sq_val, kw_idx, kw_max, kw_val) {
        if (ki < kw_count && yyjson_is_str(kw_val)) {
            keywords[ki++] = yyjson_get_str(kw_val);
        }
    }
    return ki;
}

/* Emit vector-search hits in the json-tree model: "semantic": {cols, rows}
 * — score order preserved (ranked output is never regrouped). */
static void emit_semantic_results(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                  cbm_vector_result_t *vresults, int vcount) {
    yyjson_mut_val *sem = yyjson_mut_obj(doc);
    yyjson_mut_val *scols = yyjson_mut_arr(doc);
    static const char *const sem_cols[] = {"qn", "label", "file", "score"};
    for (size_t ci = 0; ci < sizeof(sem_cols) / sizeof(sem_cols[0]); ci++) {
        yyjson_mut_arr_add_str(doc, scols, sem_cols[ci]);
    }
    yyjson_mut_obj_add_val(doc, sem, "cols", scols);
    yyjson_mut_val *sem_results = yyjson_mut_arr(doc);
    for (int v = 0; v < vcount; v++) {
        yyjson_mut_val *vitem = yyjson_mut_arr(doc);
        yyjson_mut_arr_add_strcpy(doc, vitem, vresults[v].qualified_name);
        yyjson_mut_arr_add_strcpy(doc, vitem, vresults[v].label);
        yyjson_mut_arr_add_strcpy(doc, vitem, vresults[v].file_path);
        yyjson_mut_arr_add_real(doc, vitem, vresults[v].score);
        yyjson_mut_arr_add_val(sem_results, vitem);
    }
    yyjson_mut_obj_add_val(doc, sem, "rows", sem_results);
    yyjson_mut_obj_add_val(doc, root, "semantic", sem);
}

/* Run the semantic_query vector search from raw args. Sets *out_vresults /
 * *out_vcount (caller frees via cbm_store_free_vector_results when vcount>0).
 * Returns true if semantic_query was provided as a non-array (type error —
 * caller should surface to the user). */
static bool run_semantic_query_core(const char *args, cbm_store_t *store, const char *project,
                                    int limit, cbm_vector_result_t **out_vresults, int *out_vcount,
                                    bool *out_present) {
    enum { MAX_KW_SEARCH = 32 };
    *out_vresults = NULL;
    *out_vcount = 0;
    if (out_present) {
        *out_present = false;
    }
    yyjson_doc *args_doc = yyjson_read(args, strlen(args), 0);
    yyjson_val *args_root = args_doc ? yyjson_doc_get_root(args_doc) : NULL;
    yyjson_val *sq_val = args_root ? yyjson_obj_get(args_root, "semantic_query") : NULL;
    if (out_present && sq_val) {
        *out_present = true;
    }
    bool type_error = false;
    if (sq_val && !yyjson_is_arr(sq_val)) {
        type_error = true;
    } else if (sq_val && yyjson_arr_size(sq_val) > 0) {
        const char *keywords[MAX_KW_SEARCH];
        int ki = extract_semantic_keywords(sq_val, keywords, MAX_KW_SEARCH);
        cbm_vector_result_t *vresults = NULL;
        int vcount = 0;
        int sem_limit = limit > 0 ? limit : CBM_SZ_16;
        if (cbm_store_vector_search(store, project, keywords, ki, sem_limit, &vresults, &vcount) ==
                CBM_STORE_OK &&
            vcount > 0) {
            *out_vresults = vresults;
            *out_vcount = vcount;
        }
    }
    if (args_doc) {
        yyjson_doc_free(args_doc);
    }
    return type_error;
}

/* Append the semantic_query vector-search results onto the doc.  Returns
 * true if semantic_query was provided as a non-array (type error — caller
 * should surface to the user). */
static bool run_semantic_query(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *args,
                               cbm_store_t *store, const char *project, int limit) {
    cbm_vector_result_t *vresults = NULL;
    int vcount = 0;
    bool type_error =
        run_semantic_query_core(args, store, project, limit, &vresults, &vcount, NULL);
    if (vcount > 0) {
        emit_semantic_results(doc, root, vresults, vcount);
        cbm_store_free_vector_results(vresults, vcount);
    }
    return type_error;
}

/* ── Tree output for search_graph ───────────────────────────────────
 * Default response encoding: grouped tree rows (compact_out.h). The same
 * model is available as structured JSON via format:"json"; include_connected
 * adds a `connected` column in BOTH encodings. */

enum { SG_MAX_EXTRA_FIELDS = 12 };

/* Internal-only node properties never emitted to agents: similarity /
 * semantic pipeline intermediates (minhash fingerprint, structural profile,
 * body-token bag). They dominate payload size and carry zero agent value. */
static bool sg_field_blocked(const char *f) {
    return strcmp(f, "fp") == 0 || strcmp(f, "sp") == 0 || strcmp(f, "bt") == 0;
}

/* Core row columns every search result already carries. Requesting one as an
 * extra `fields` entry used to emit a silent empty column (core values are
 * node columns, never in the properties JSON) — field-eval agents burned a
 * round-trip on exactly that. Drop them and teach instead. */
static bool sg_field_is_core(const char *f) {
    return strcmp(f, "qn") == 0 || strcmp(f, "qualified_name") == 0 || strcmp(f, "name") == 0 ||
           strcmp(f, "label") == 0 || strcmp(f, "file") == 0 || strcmp(f, "file_path") == 0 ||
           strcmp(f, "path") == 0 || strcmp(f, "lines") == 0 || strcmp(f, "in") == 0 ||
           strcmp(f, "out") == 0;
}

/* Parse the `fields` argument (array of property names) into out[] as
 * pointers owned by the returned doc (caller frees the doc after emission).
 * Blocked internal fields are silently dropped; core-column requests are
 * dropped too and reported via *core_requested so the emitter can hint. */
static int sg_parse_fields(const char *args, const char *out[], int max_out, yyjson_doc **out_owner,
                           bool *core_requested) {
    *out_owner = NULL;
    if (core_requested) {
        *core_requested = false;
    }
    yyjson_doc *args_doc = yyjson_read(args, strlen(args), 0);
    yyjson_val *args_root = args_doc ? yyjson_doc_get_root(args_doc) : NULL;
    yyjson_val *fv = args_root ? yyjson_obj_get(args_root, "fields") : NULL;
    if (!fv || !yyjson_is_arr(fv)) {
        if (args_doc) {
            yyjson_doc_free(args_doc);
        }
        return 0;
    }
    int n = 0;
    size_t idx = 0;
    size_t max = 0;
    yyjson_val *item;
    yyjson_arr_foreach(fv, idx, max, item) {
        const char *s = yyjson_get_str(item);
        if (!s || !s[0] || sg_field_blocked(s)) {
            continue;
        }
        if (sg_field_is_core(s)) {
            if (core_requested) {
                *core_requested = true;
            }
            continue;
        }
        if (n < max_out) {
            out[n++] = s;
        }
    }
    if (n == 0) {
        yyjson_doc_free(args_doc);
        return 0;
    }
    *out_owner = args_doc;
    return n;
}

/* Append one row's extra-field cells, pulled from the node's properties. */
static void sg_toon_extra_cells(cbm_sb_t *sb, const char *props_json, const char *const *fields,
                                int nfields) {
    yyjson_doc *pd =
        (props_json && props_json[0]) ? yyjson_read(props_json, strlen(props_json), 0) : NULL;
    yyjson_val *pr = pd ? yyjson_doc_get_root(pd) : NULL;
    for (int f = 0; f < nfields; f++) {
        yyjson_val *v = (pr && yyjson_is_obj(pr)) ? yyjson_obj_get(pr, fields[f]) : NULL;
        if (v && yyjson_is_str(v)) {
            cbm_tree_cell_str(sb, yyjson_get_str(v), false);
        } else if (v && yyjson_is_bool(v)) {
            cbm_tree_cell_bool(sb, yyjson_get_bool(v), false);
        } else if (v && yyjson_is_int(v)) {
            cbm_tree_cell_int(sb, yyjson_get_int(v), false);
        } else if (v && yyjson_is_real(v)) {
            cbm_tree_cell_real(sb, yyjson_get_real(v), false);
        } else {
            cbm_tree_cell_str(sb, "", false);
        }
    }
    if (pd) {
        yyjson_doc_free(pd);
    }
}

static void sg_json_extra_cells(yyjson_mut_doc *doc, yyjson_mut_val *row, const char *props_json,
                                const char *const *fields, int nfields) {
    yyjson_doc *properties =
        (props_json && props_json[0]) ? yyjson_read(props_json, strlen(props_json), 0) : NULL;
    yyjson_val *root = properties ? yyjson_doc_get_root(properties) : NULL;
    for (int field_index = 0; field_index < nfields; field_index++) {
        yyjson_val *value =
            (root && yyjson_is_obj(root)) ? yyjson_obj_get(root, fields[field_index]) : NULL;
        if (value && yyjson_is_str(value)) {
            yyjson_mut_arr_add_strcpy(doc, row, yyjson_get_str(value));
        } else if (value && yyjson_is_int(value)) {
            yyjson_mut_arr_add_int(doc, row, yyjson_get_int(value));
        } else if (value && yyjson_is_real(value)) {
            yyjson_mut_arr_add_real(doc, row, yyjson_get_real(value));
        } else if (value && yyjson_is_bool(value)) {
            yyjson_mut_arr_add_bool(doc, row, yyjson_get_bool(value));
        } else {
            yyjson_mut_arr_add_null(doc, row);
        }
    }
    if (properties) {
        yyjson_doc_free(properties);
    }
}

/* "start-end" line range, or empty when the node carries no line info. */
static void sg_lines_str(char *out, size_t sz, int start, int end) {
    if (start > 0) {
        snprintf(out, sz, "%d-%d", start, end > start ? end : start);
    } else {
        out[0] = '\0';
    }
}

/* Emit the regex-path search results as a TOON table. */
static void emit_search_results_toon(cbm_sb_t *sb, const cbm_search_output_t *out, int offset,
                                     const char *const *fields, int nfields, bool detail_ids) {
    cbm_tree_scalar_int(sb, "total", out->total);
    if (detail_ids) {
        /* ids tier: bare qn enumeration — for "list everything matching X"
         * sweeps where per-row metadata is noise (LocAgent's fold tier). */
        static const char *const id_cols[] = {"qn"};
        cbm_tree_table_header(sb, "results", out->count, id_cols,
                              MCP_IDENTIFIER_RESULT_COLUMN_COUNT);
        for (int i = 0; i < out->count; i++) {
            cbm_tree_row_begin(sb);
            cbm_tree_cell_str(sb, out->results[i].node.qualified_name, true);
            cbm_tree_row_end(sb);
        }
        cbm_tree_scalar_bool(sb, "has_more", out->total > offset + out->count);
        return;
    }
    const char *cols[MCP_SEARCH_CORE_COLUMN_COUNT + SG_MAX_EXTRA_FIELDS] = {
        "qn", "label", "file", "lines", "in", "out"};
    int ncols = MCP_SEARCH_CORE_COLUMN_COUNT;
    for (int f = 0; f < nfields; f++) {
        cols[ncols++] = fields[f];
    }
    cbm_tree_table_header(sb, "results", out->count, cols, ncols);
    for (int i = 0; i < out->count; i++) {
        const cbm_search_result_t *sr = &out->results[i];
        char lines[CBM_SZ_32];
        sg_lines_str(lines, sizeof(lines), sr->node.start_line, sr->node.end_line);
        cbm_tree_row_begin(sb);
        cbm_tree_cell_str(sb, sr->node.qualified_name, true);
        cbm_tree_cell_str(sb, sr->node.label, false);
        cbm_tree_cell_str(sb, sr->node.file_path, false);
        cbm_tree_cell_str(sb, lines, false);
        cbm_tree_cell_int(sb, sr->in_degree, false);
        cbm_tree_cell_int(sb, sr->out_degree, false);
        sg_toon_extra_cells(sb, sr->node.properties_json, fields, nfields);
        cbm_tree_row_end(sb);
    }
    cbm_tree_scalar_bool(sb, "has_more", out->total > offset + out->count);
}

/* ── Tree format (Phase-2 A/B candidate) ────────────────────────────
 * Prefix-factored, file-grouped output: the shared (qn-prefix, file) pair is
 * printed ONCE per group, rows beneath carry only the short name + data
 * cells. The reconstruction rule (qn = group-prefix + "." + name) is stated
 * once in the header so agents can copy exact join keys into follow-up
 * calls. Research basis: HDT front-coding (prefix factoring), LocAgent tree
 * ablation (tree > flat/DOT for LLM comprehension), Lost-in-Distance
 * (related rows adjacent — grouping by module does exactly that). */

/* qn-prefix = qualified_name minus its last '.'-segment. Returns length. */
static size_t sg_qn_prefix_len(const char *qn) {
    const char *last = qn ? strrchr(qn, '.') : NULL;
    return last ? (size_t)(last - qn) : 0;
}

static int sg_cmp_by_qn(const void *pa, const void *pb) {
    const cbm_search_result_t *a = (const cbm_search_result_t *)pa;
    const cbm_search_result_t *b = (const cbm_search_result_t *)pb;
    const char *qa = a->node.qualified_name;
    const char *qb = b->node.qualified_name;
    return strcmp(qa, qb);
}

static void sg_sort_results_by_qn(cbm_search_output_t *out) {
    if (out->count > MCP_SINGLE_PRIMARY_PROJECT) {
        qsort(out->results, (size_t)out->count, sizeof(cbm_search_result_t), sg_cmp_by_qn);
    }
}

static void sg_tree_append_header(cbm_sb_t *sb, const cbm_search_output_t *out,
                                  const char *const *fields, int nfields, bool include_connected) {
    char extra_columns[CBM_SZ_256] = "";
    for (int field_index = 0; field_index < nfields; field_index++) {
        strncat(extra_columns, " ", sizeof(extra_columns) - strlen(extra_columns) - 1);
        strncat(extra_columns, fields[field_index],
                sizeof(extra_columns) - strlen(extra_columns) - 1);
    }
    if (include_connected) {
        strncat(extra_columns, " connected", sizeof(extra_columns) - strlen(extra_columns) - 1);
    }
    char header[CBM_SZ_512];
    snprintf(header, sizeof(header),
             "total: %d\nresults: %d  (rows: name label lines in out%s; "
             "qn = group prefix + \".\" + name)\n",
             out->total, out->count, extra_columns);
    cbm_sb_append(sb, header);
}

static void sg_tree_append_result(cbm_sb_t *sb, const cbm_search_result_t *result,
                                  size_t prefix_len, const char *const *fields, int nfields,
                                  cbm_store_t *store, const char *relationship,
                                  bool include_connected) {
    const char *qualified_name = result->node.qualified_name;
    const char *short_name = prefix_len
                                 ? qualified_name + prefix_len + MCP_QUALIFIED_NAME_SEPARATOR_BYTES
                                 : qualified_name;
    char lines[CBM_SZ_32];
    sg_lines_str(lines, sizeof(lines), result->node.start_line, result->node.end_line);
    char row[CBM_SZ_1K];
    snprintf(row, sizeof(row), "  %s %s %s %d %d", short_name, result->node.label, lines,
             result->in_degree, result->out_degree);
    cbm_sb_append(sb, row);
    if (nfields > 0) {
        sg_toon_extra_cells(sb, result->node.properties_json, fields, nfields);
    }
    if (include_connected && result->node.id > 0) {
        char joined[CBM_SZ_1K];
        enrich_connected_joined(store, result->node.id, relationship, joined, sizeof(joined));
        cbm_tree_cell_str(sb, joined, false);
    }
    cbm_sb_append(sb, "\n");
}

static void emit_search_results_tree(cbm_sb_t *sb, cbm_search_output_t *out, int offset,
                                     const char *const *fields, int nfields, cbm_store_t *store,
                                     const char *relationship, bool include_connected) {
    sg_tree_append_header(sb, out, fields, nfields, include_connected);
    sg_sort_results_by_qn(out);
    char current_group[CBM_SZ_1K] = "";
    for (int i = 0; i < out->count; i++) {
        const cbm_search_result_t *result = &out->results[i];
        const char *qualified_name = result->node.qualified_name;
        size_t prefix_len = sg_qn_prefix_len(qualified_name);
        char group[CBM_SZ_1K];
        snprintf(group, sizeof(group), "%.*s (%s)", (int)prefix_len, qualified_name,
                 result->node.file_path);
        if (strcmp(group, current_group) != 0) {
            snprintf(current_group, sizeof(current_group), "%s", group);
            cbm_sb_append(sb, group);
            cbm_sb_append(sb, ":\n");
        }
        sg_tree_append_result(sb, result, prefix_len, fields, nfields, store, relationship,
                              include_connected);
    }
    char footer[CBM_SZ_512];
    snprintf(footer, sizeof(footer), "has_more: %s\n",
             out->total > offset + out->count ? "true" : "false");
    cbm_sb_append(sb, footer);
}

static void sg_json_add_columns(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                const char *const *fields, int nfields, bool include_connected) {
    static const char *const core_columns[] = {"name", "label", "lines", "in", "out"};
    yyjson_mut_val *columns = yyjson_mut_arr(doc);
    for (size_t i = 0; i < sizeof(core_columns) / sizeof(core_columns[0]); i++) {
        yyjson_mut_arr_add_str(doc, columns, core_columns[i]);
    }
    for (int field_index = 0; field_index < nfields; field_index++) {
        yyjson_mut_arr_add_strcpy(doc, columns, fields[field_index]);
    }
    if (include_connected) {
        yyjson_mut_arr_add_str(doc, columns, "connected");
    }
    yyjson_mut_obj_add_val(doc, root, "cols", columns);
}

static yyjson_mut_val *sg_json_start_group(yyjson_mut_doc *doc, yyjson_mut_val *groups,
                                           const char *qualified_name, size_t prefix_len,
                                           const char *file_path) {
    yyjson_mut_val *group = yyjson_mut_obj(doc);
    char prefix[CBM_SZ_1K];
    snprintf(prefix, sizeof(prefix), "%.*s", (int)prefix_len, qualified_name);
    yyjson_mut_obj_add_strcpy(doc, group, "qn_prefix", prefix);
    yyjson_mut_obj_add_strcpy(doc, group, "file", file_path);
    yyjson_mut_val *rows = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, group, "rows", rows);
    yyjson_mut_arr_add_val(groups, group);
    return rows;
}

static void sg_json_append_result(yyjson_mut_doc *doc, yyjson_mut_val *rows,
                                  const cbm_search_result_t *result, size_t prefix_len,
                                  const char *const *fields, int nfields, cbm_store_t *store,
                                  const char *relationship, bool include_connected) {
    const char *qualified_name = result->node.qualified_name;
    char lines[CBM_SZ_32];
    sg_lines_str(lines, sizeof(lines), result->node.start_line, result->node.end_line);
    yyjson_mut_val *row = yyjson_mut_arr(doc);
    yyjson_mut_arr_add_strcpy(doc, row,
                              prefix_len
                                  ? qualified_name + prefix_len + MCP_QUALIFIED_NAME_SEPARATOR_BYTES
                                  : qualified_name);
    yyjson_mut_arr_add_strcpy(doc, row, result->node.label);
    yyjson_mut_arr_add_strcpy(doc, row, lines);
    yyjson_mut_arr_add_int(doc, row, result->in_degree);
    yyjson_mut_arr_add_int(doc, row, result->out_degree);
    if (nfields > 0) {
        sg_json_extra_cells(doc, row, result->node.properties_json, fields, nfields);
    }
    if (include_connected && result->node.id > 0) {
        yyjson_mut_arr_add_val(row, enrich_connected(doc, store, result->node.id, relationship));
    }
    yyjson_mut_arr_add_val(rows, row);
}

/* json-stringified tree: the SAME grouped model as the text tree, serialized
 * as JSON for agents that need structured parsing — groups with a shared
 * (qn_prefix, file) and column-ordered row ARRAYS (never per-row key
 * envelopes; that legacy shape was 84% key overhead). */
static void emit_search_results_tree_json(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                          cbm_search_output_t *out, int offset,
                                          const char *const *fields, int nfields,
                                          cbm_store_t *store, const char *relationship,
                                          bool include_connected) {
    yyjson_mut_obj_add_int(doc, root, "total", out->total);
    yyjson_mut_obj_add_int(doc, root, "count", out->count);
    sg_json_add_columns(doc, root, fields, nfields, include_connected);
    sg_sort_results_by_qn(out);
    yyjson_mut_val *groups = yyjson_mut_arr(doc);
    yyjson_mut_val *current_rows = NULL;
    char current_key[CBM_SZ_1K] = "";
    for (int i = 0; i < out->count; i++) {
        const cbm_search_result_t *result = &out->results[i];
        const char *qualified_name = result->node.qualified_name;
        size_t prefix_len = sg_qn_prefix_len(qualified_name);
        char key[CBM_SZ_1K];
        snprintf(key, sizeof(key), "%.*s|%s", (int)prefix_len, qualified_name,
                 result->node.file_path);
        if (!current_rows || strcmp(key, current_key) != 0) {
            snprintf(current_key, sizeof(current_key), "%s", key);
            current_rows = sg_json_start_group(doc, groups, qualified_name, prefix_len,
                                               result->node.file_path);
        }
        sg_json_append_result(doc, current_rows, result, prefix_len, fields, nfields, store,
                              relationship, include_connected);
    }
    yyjson_mut_obj_add_val(doc, root, "groups", groups);
    yyjson_mut_obj_add_bool(doc, root, "has_more", out->total > offset + out->count);
}

/* Emit semantic vector-search results as a TOON table. */
static void emit_semantic_results_toon(cbm_sb_t *sb, const cbm_vector_result_t *vresults,
                                       int vcount) {
    static const char *const cols[] = {"qn", "label", "file", "score"};
    cbm_tree_table_header(sb, "semantic", vcount, cols, MCP_SEMANTIC_RESULT_COLUMN_COUNT);
    for (int v = 0; v < vcount; v++) {
        cbm_tree_row_begin(sb);
        cbm_tree_cell_str(sb, vresults[v].qualified_name, true);
        cbm_tree_cell_str(sb, vresults[v].label, false);
        cbm_tree_cell_str(sb, vresults[v].file_path, false);
        cbm_tree_cell_real(sb, vresults[v].score, false);
        cbm_tree_row_end(sb);
    }
}

typedef struct {
    char *project;
    char *query;
    char *label;
    char *name_pattern;
    char *qn_pattern;
    char *file_pattern;
    char *relationship;
    bool legacy_json;
    bool exclude_entry_points;
    bool include_connected;
    int limit;
    int offset;
    int min_degree;
    int max_degree;
} search_graph_request_t;

static void search_graph_request_init(search_graph_request_t *request, const char *args) {
    *request = (search_graph_request_t){
        .project = get_project_arg(args),
        .query = cbm_mcp_get_string_arg(args, "query"),
        .label = cbm_mcp_get_string_arg(args, "label"),
        .name_pattern = cbm_mcp_get_string_arg(args, "name_pattern"),
        .qn_pattern = cbm_mcp_get_string_arg(args, "qn_pattern"),
        .file_pattern = cbm_mcp_get_string_arg(args, "file_pattern"),
        .relationship = cbm_mcp_get_string_arg(args, "relationship"),
        .exclude_entry_points = cbm_mcp_get_bool_arg(args, "exclude_entry_points"),
        .include_connected = cbm_mcp_get_bool_arg(args, "include_connected"),
        .limit = cbm_mcp_get_int_arg(args, "limit", CBM_DEFAULT_SEARCH_LIMIT),
        .offset = cbm_mcp_get_int_arg(args, "offset", 0),
        .min_degree = cbm_mcp_get_int_arg(args, "min_degree", CBM_NOT_FOUND),
        .max_degree = cbm_mcp_get_int_arg(args, "max_degree", CBM_NOT_FOUND),
    };
    char *format = cbm_mcp_get_string_arg(args, "format");
    request->legacy_json = format && strcmp(format, "json") == 0;
    free(format);
}

static void search_graph_request_dispose(search_graph_request_t *request) {
    free(request->project);
    free(request->query);
    free(request->label);
    free(request->name_pattern);
    free(request->qn_pattern);
    free(request->file_pattern);
    free(request->relationship);
    *request = (search_graph_request_t){0};
}

static cbm_search_params_t search_graph_params(const search_graph_request_t *request) {
    return (cbm_search_params_t){
        .project = request->project,
        .label = request->label,
        .name_pattern = request->name_pattern,
        .qn_pattern = request->qn_pattern,
        .file_pattern = request->file_pattern,
        .relationship = request->relationship,
        .exclude_entry_points = request->exclude_entry_points,
        .include_connected = request->include_connected,
        .limit = request->limit,
        .offset = request->offset,
        .min_degree = request->min_degree,
        .max_degree = request->max_degree,
    };
}

static bool search_graph_has_filters(const search_graph_request_t *request) {
    return request->label || request->name_pattern || request->qn_pattern ||
           request->file_pattern || request->relationship || request->exclude_entry_points ||
           request->min_degree != CBM_NOT_FOUND || request->max_degree != CBM_NOT_FOUND;
}

static const char *search_graph_empty_hint(const search_graph_request_t *request) {
    if (request->name_pattern && request->label) {
        return "No results. Try removing the label filter or broadening the name_pattern regex.";
    }
    if (request->name_pattern) {
        return "No nodes match this pattern. Check spelling or try a broader regex.";
    }
    if (request->label) {
        return "No nodes with this label. Available labels: Function, Method, Class, Interface, "
               "Route, Variable, Module, Package, File, Folder.";
    }
    return NULL;
}

static char *search_graph_bm25_response(cbm_store_t *store, const char *args,
                                        const search_graph_request_t *request) {
    if (!request->query || !request->query[0]) {
        return NULL;
    }
    int limit = cbm_mcp_get_int_arg(args, "limit", BM25_DEFAULT_LIMIT);
    int offset = cbm_mcp_get_int_arg(args, "offset", 0);
    char *text = bm25_search(store, request->project, request->query, request->file_pattern, limit,
                             offset, !request->legacy_json);
    if (!text) {
        return NULL;
    }
    char *result = cbm_mcp_text_result(text, false);
    free(text);
    return result;
}

static char *search_graph_toon_response(cbm_store_t *store, const char *args,
                                        const search_graph_request_t *request) {
    const char *fields[SG_MAX_EXTRA_FIELDS];
    yyjson_doc *fields_owner = NULL;
    bool core_fields_requested = false;
    int field_count =
        sg_parse_fields(args, fields, SG_MAX_EXTRA_FIELDS, &fields_owner, &core_fields_requested);
    char *detail = cbm_mcp_get_string_arg(args, "detail");
    bool detail_ids = detail && strcmp(detail, "ids") == 0;
    free(detail);
    cbm_vector_result_t *vector_results = NULL;
    int vector_count = 0;
    bool semantic_present = false;
    bool semantic_type_error =
        run_semantic_query_core(args, store, request->project, request->limit, &vector_results,
                                &vector_count, &semantic_present);
    if (semantic_type_error) {
        if (fields_owner) {
            yyjson_doc_free(fields_owner);
        }
        return cbm_mcp_text_result(
            "semantic_query must be an array of keyword strings, e.g. "
            "[\"send\",\"pubsub\",\"publish\"] — not a single string. Split your query "
            "into individual keywords; each is scored independently via per-keyword min-cosine.",
            true);
    }
    bool semantic_only = semantic_present && !search_graph_has_filters(request);
    cbm_sb_t sb;
    cbm_sb_init(&sb);
    cbm_search_output_t output = {0};
    if (!semantic_only) {
        cbm_search_params_t params = search_graph_params(request);
        cbm_store_search(store, &params, &output);
        if (detail_ids) {
            emit_search_results_toon(&sb, &output, request->offset, fields, field_count, true);
        } else {
            emit_search_results_tree(&sb, &output, request->offset, fields, field_count, store,
                                     request->relationship, request->include_connected);
        }
        if (core_fields_requested) {
            cbm_tree_scalar_str(
                &sb, "hint",
                "some requested fields (file/name/qn/label/lines) are already core row columns "
                "and were skipped — `fields` is for extra property columns like complexity, "
                "cognitive, signature");
        }
        const char *hint = output.total == 0 ? search_graph_empty_hint(request) : NULL;
        if (hint) {
            cbm_tree_scalar_str(&sb, "hint", hint);
        }
    }
    if (vector_count > 0) {
        emit_semantic_results_toon(&sb, vector_results, vector_count);
        cbm_store_free_vector_results(vector_results, vector_count);
    } else if (semantic_only) {
        static const char *const semantic_columns[] = {"qn", "label", "file", "score"};
        cbm_tree_table_header(&sb, "semantic", 0, semantic_columns,
                              MCP_SEMANTIC_RESULT_COLUMN_COUNT);
        cbm_tree_scalar_str(&sb, "hint",
                            "No semantic matches. semantic_query needs a moderate/full index; "
                            "try broader or fewer keywords.");
    }
    if (fields_owner) {
        yyjson_doc_free(fields_owner);
    }
    cbm_store_search_free(&output);
    char *text = cbm_sb_finish(&sb);
    char *result = cbm_mcp_text_result(text ? text : "out of memory", text == NULL);
    free(text);
    return result;
}

static char *search_graph_json_response(cbm_store_t *store, const char *args,
                                        const search_graph_request_t *request) {
    cbm_search_params_t params = search_graph_params(request);
    cbm_search_output_t output = {0};
    cbm_store_search(store, &params, &output);
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    const char *fields[SG_MAX_EXTRA_FIELDS];
    yyjson_doc *fields_owner = NULL;
    int field_count = sg_parse_fields(args, fields, SG_MAX_EXTRA_FIELDS, &fields_owner, NULL);
    emit_search_results_tree_json(doc, root, &output, request->offset, fields, field_count, store,
                                  request->relationship, request->include_connected);
    if (fields_owner) {
        yyjson_doc_free(fields_owner);
    }
    const char *hint = output.total == 0 ? search_graph_empty_hint(request) : NULL;
    if (hint) {
        yyjson_mut_obj_add_str(doc, root, "hint", hint);
    }
    bool semantic_type_error =
        run_semantic_query(doc, root, args, store, request->project, request->limit);
    if (semantic_type_error) {
        yyjson_mut_doc_free(doc);
        cbm_store_search_free(&output);
        return cbm_mcp_text_result(
            "semantic_query must be an array of keyword strings, e.g. "
            "[\"send\",\"pubsub\",\"publish\"] — not a single string. Split your query "
            "into individual keywords; each is scored independently via per-keyword min-cosine.",
            true);
    }
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    cbm_store_search_free(&output);
    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

static char *handle_search_graph(cbm_mcp_server_t *srv, const char *args) {
    /* Inner phase split: every tool leaks the same ~4 MB per request, so the
     * retainer is in what the handlers share -- store resolution or the query
     * itself. These marks separate the two. */
    cbm_mem_phase_mark("handler.args");
    search_graph_request_t request = {0};
    search_graph_request_init(&request, args);
    cbm_mem_phase_mark("handler.resolve_store");
    cbm_store_t *store = resolve_store(srv, request.project);
    cbm_mem_phase_mark("handler.body");
    if (!store) {
        char *error = build_project_list_error("project not found or not indexed");
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        search_graph_request_dispose(&request);
        return result;
    }
    char *not_indexed = verify_project_indexed(store, request.project);
    if (not_indexed) {
        search_graph_request_dispose(&request);
        return not_indexed;
    }
    if (request.relationship && !validate_edge_type(request.relationship)) {
        search_graph_request_dispose(&request);
        return cbm_mcp_text_result("relationship must be uppercase letters and underscores", true);
    }
    char *result = search_graph_bm25_response(store, args, &request);
    if (!result) {
        result = request.legacy_json ? search_graph_json_response(store, args, &request)
                                     : search_graph_toon_response(store, args, &request);
    }
    search_graph_request_dispose(&request);
    return result;
}

static void query_graph_append_toon_rows(cbm_sb_t *sb, const cbm_cypher_result_t *result) {
    for (int row_index = 0; row_index < result->row_count; row_index++) {
        cbm_tree_row_begin(sb);
        for (int column_index = 0; column_index < result->col_count; column_index++) {
            cbm_tree_cell_str(sb, result->rows[row_index][column_index], column_index == 0);
        }
        cbm_tree_row_end(sb);
    }
}

static char *query_graph_render_toon(const cbm_cypher_result_t *result) {
    cbm_sb_t sb;
    cbm_sb_init(&sb);
    cbm_tree_table_header(&sb, "rows", result->row_count, (const char *const *)result->columns,
                          result->col_count);
    query_graph_append_toon_rows(&sb, result);
    cbm_tree_scalar_int(&sb, "total", result->row_count);
    if (result->warning) {
        cbm_tree_scalar_str(&sb, "warning", result->warning);
    }
    if (result->row_count == 0) {
        cbm_tree_scalar_str(&sb, "hint",
                            "Query returned no results. Use get_graph_schema() to see "
                            "available labels and edge types.");
    }
    return cbm_sb_finish(&sb);
}

static void query_graph_append_json_columns(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                            const cbm_cypher_result_t *result) {
    yyjson_mut_val *columns = yyjson_mut_arr(doc);
    for (int column_index = 0; column_index < result->col_count; column_index++) {
        yyjson_mut_arr_add_str(doc, columns, result->columns[column_index]);
    }
    yyjson_mut_obj_add_val(doc, root, "columns", columns);
}

static void query_graph_append_json_rows(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                         const cbm_cypher_result_t *result) {
    yyjson_mut_val *rows = yyjson_mut_arr(doc);
    for (int row_index = 0; row_index < result->row_count; row_index++) {
        yyjson_mut_val *row = yyjson_mut_arr(doc);
        for (int column_index = 0; column_index < result->col_count; column_index++) {
            yyjson_mut_arr_add_str(doc, row, result->rows[row_index][column_index]);
        }
        yyjson_mut_arr_add_val(rows, row);
    }
    yyjson_mut_obj_add_val(doc, root, "rows", rows);
}

static char *query_graph_render_json(const cbm_cypher_result_t *result) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    query_graph_append_json_columns(doc, root, result);
    query_graph_append_json_rows(doc, root, result);
    yyjson_mut_obj_add_int(doc, root, "total", result->row_count);
    if (result->warning) {
        yyjson_mut_obj_add_str(doc, root, "warning", result->warning);
    }
    if (result->row_count == 0) {
        yyjson_mut_obj_add_str(
            doc, root, "hint",
            "Query returned no results. Use get_graph_schema() to see available labels and "
            "edge types.");
    }
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return json;
}

static char *handle_query_graph(cbm_mcp_server_t *srv, const char *args) {
    char *query = cbm_mcp_get_string_arg(args, "query");
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    int max_rows = cbm_mcp_get_int_arg(args, "max_rows", 0);

    /* graph="missed" (#963): run the SAME cypher against the derived
     * miss-graph view (shadow project "<project>::missed") instead of the
     * code graph — file structure of not-fully-indexed files only. */
    char *graph_arg = cbm_mcp_get_string_arg(args, "graph");
    bool missed_graph = graph_arg && strcmp(graph_arg, "missed") == 0;
    free(graph_arg);

    if (!query) {
        free(project);
        return cbm_mcp_text_result("query is required", true);
    }
    if (missed_graph && !project) {
        free(query);
        return cbm_mcp_text_result("project is required when graph=\"missed\"", true);
    }
    if (!store) {
        char *_err = build_project_list_error("project not found or not indexed");
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        free(project);
        free(query);
        return _res;
    }

    char *not_indexed = verify_project_indexed(store, project);
    if (not_indexed) {
        free(project);
        free(query);
        return not_indexed;
    }

    char covproj[CBM_SZ_512];
    const char *cypher_project = project;
    if (missed_graph) {
        cbm_store_coverage_shadow_project(covproj, sizeof(covproj), project);
        cypher_project = covproj;
    }

    cbm_cypher_result_t result = {0};
    int rc = cbm_cypher_execute(store, query, cypher_project, max_rows, &result);

    if (rc < 0) {
        char *err_msg = result.error ? result.error : "query execution failed";
        char *resp = cbm_mcp_text_result(err_msg, true);
        cbm_cypher_result_free(&result);
        free(query);
        free(project);
        return resp;
    }

    /* Response encoding: TOON table by default (the columns double as the
     * table header); format:"json" restores the legacy columns/rows arrays. */
    char *qg_format = cbm_mcp_get_string_arg(args, "format");
    bool qg_legacy_json = qg_format && strcmp(qg_format, "json") == 0;
    free(qg_format);

    char *json =
        qg_legacy_json ? query_graph_render_json(&result) : query_graph_render_toon(&result);
    cbm_cypher_result_free(&result);
    free(query);
    free(project);

    char *res = cbm_mcp_text_result(json ? json : "out of memory", json == NULL);
    free(json);
    return res;
}

/* Indexing-coverage report (#963), attached to index_status: the best-effort
 * signal from the separate index_coverage table (coverage is metadata ABOUT
 * the graph, stored outside it). Full per-project list, capped generously. */
enum { COVERAGE_FILE_CAP = 500 };

typedef struct {
    yyjson_mut_val *entries;
    int count;
} coverage_bucket_t;

static void coverage_append_file_entry(yyjson_mut_doc *doc, coverage_bucket_t *bucket,
                                       const cbm_coverage_row_t *row, const char *detail_key,
                                       bool include_phase) {
    if (bucket->count < COVERAGE_FILE_CAP) {
        yyjson_mut_val *entry = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_strcpy(doc, entry, "path", row->rel_path);
        yyjson_mut_obj_add_strcpy(doc, entry, detail_key, row->detail ? row->detail : "");
        if (include_phase) {
            yyjson_mut_obj_add_strcpy(doc, entry, "phase", row->kind ? row->kind : "");
        }
        yyjson_mut_arr_add_val(bucket->entries, entry);
    }
    bucket->count++;
}

static void coverage_append_not_indexed_directory(yyjson_mut_doc *doc, coverage_bucket_t *bucket,
                                                  const cbm_coverage_row_t *row) {
    if (bucket->count < COVERAGE_FILE_CAP) {
        yyjson_mut_arr_add_strcpy(doc, bucket->entries, row->rel_path);
    }
    bucket->count++;
}

static void coverage_record_row(yyjson_mut_doc *doc, const cbm_coverage_row_t *row,
                                coverage_bucket_t *parse_partial, coverage_bucket_t *skipped,
                                coverage_bucket_t *not_indexed_directories,
                                coverage_bucket_t *not_indexed_files) {
    const char *kind = row->kind ? row->kind : "";
    if (strcmp(kind, "parse_partial") == 0) {
        coverage_append_file_entry(doc, parse_partial, row, "error_ranges", false);
    } else if (strcmp(kind, "not_indexed_dir") == 0) {
        coverage_append_not_indexed_directory(doc, not_indexed_directories, row);
    } else if (strcmp(kind, "not_indexed_file") == 0) {
        coverage_append_file_entry(doc, not_indexed_files, row, "reason", false);
    } else {
        coverage_append_file_entry(doc, skipped, row, "reason", true);
    }
}

static void coverage_add_file_section(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *key,
                                      coverage_bucket_t *bucket) {
    yyjson_mut_val *section = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, section, "files", bucket->entries);
    yyjson_mut_obj_add_int(doc, section, "count", bucket->count);
    yyjson_mut_obj_add_bool(doc, section, "truncated", bucket->count > COVERAGE_FILE_CAP);
    yyjson_mut_obj_add_val(doc, root, key, section);
}

static void coverage_add_not_indexed_section(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                             coverage_bucket_t *directories,
                                             coverage_bucket_t *files) {
    yyjson_mut_val *section = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, section, "dirs", directories->entries);
    yyjson_mut_obj_add_int(doc, section, "dirs_count", directories->count);
    yyjson_mut_obj_add_val(doc, section, "files", files->entries);
    yyjson_mut_obj_add_int(doc, section, "files_count", files->count);
    yyjson_mut_obj_add_bool(doc, section, "truncated",
                            directories->count > COVERAGE_FILE_CAP ||
                                files->count > COVERAGE_FILE_CAP);
    if (directories->count > 0 || files->count > 0) {
        yyjson_mut_obj_add_str(doc, section, "note",
                               "Purposely not indexed — excluded BY DESIGN via "
                               "gitignore/.cbmignore/skip-lists (see each file's reason). Not an "
                               "error: change the ignore rules and re-index to include them.");
    }
    yyjson_mut_obj_add_val(doc, root, "not_indexed", section);
}

static void add_coverage_report(yyjson_mut_doc *doc, yyjson_mut_val *root, cbm_store_t *store,
                                const char *project) {
    cbm_coverage_row_t *rows = NULL;
    int count = 0;
    (void)cbm_store_coverage_get(store, project, &rows, &count);

    coverage_bucket_t parse_partial = {.entries = yyjson_mut_arr(doc), .count = 0};
    coverage_bucket_t skipped = {.entries = yyjson_mut_arr(doc), .count = 0};
    coverage_bucket_t not_indexed_directories = {.entries = yyjson_mut_arr(doc), .count = 0};
    coverage_bucket_t not_indexed_files = {.entries = yyjson_mut_arr(doc), .count = 0};
    for (int i = 0; i < count; i++) {
        coverage_record_row(doc, &rows[i], &parse_partial, &skipped, &not_indexed_directories,
                            &not_indexed_files);
    }
    cbm_store_free_coverage(rows, count);

    coverage_add_file_section(doc, root, "parse_partial", &parse_partial);
    coverage_add_file_section(doc, root, "skipped", &skipped);

    /* By-design exclusions (#963 "purposely not indexed"): a deliberate,
     * deterministic class — NOT a failure and NOT best-effort. Dirs are
     * exhaustive; per-file entries are capped in discovery (2000) with the
     * truncation explicit. */
    coverage_add_not_indexed_section(doc, root, &not_indexed_directories, &not_indexed_files);

    if (parse_partial.count > 0 || skipped.count > 0) {
        yyjson_mut_obj_add_str(
            doc, root, "coverage_note",
            "Best-effort signal, not a completeness guarantee: parse_partial files WERE indexed, "
            "but constructs inside the listed line ranges (1-based) MAY be missing from the graph "
            "(tree-sitter error recovery still salvages some). skipped files were not indexed at "
            "all. Prefer text search (grep) for flagged files/ranges. Files absent from this list "
            "are NOT guaranteed to be fully indexed. (not_indexed entries are a separate, "
            "BY-DESIGN class — deliberate ignore rules, not failures.)");
    }
}

enum {
    COVERAGE_PATH_MAX = 128,
    COVERAGE_SCOPE_MAX = 32,
    COVERAGE_SCOPE_DEFAULT_LIMIT = 200,
    COVERAGE_SCOPE_MAX_LIMIT = 1000,
    COVERAGE_SCOPE_MIN_LIMIT = 1,
    COVERAGE_RANGE_MAX = 128,
    COVERAGE_NOT_INDEXED_PREFIX_LEN = sizeof("not_indexed") - SKIP_ONE,
    COVERAGE_WINDOWS_DRIVE_PREFIX_LEN = 2U,
    COVERAGE_WINDOWS_DRIVE_SEPARATOR_INDEX = 1U,
    COVERAGE_ASCII_CONTROL_FIRST = 0x20U,
    COVERAGE_DOT_COMPONENT_LEN = 1U,
    COVERAGE_PARENT_COMPONENT_LEN = 2U,
    COVERAGE_PARENT_COMPONENT_SECOND_INDEX = 1U,
    COVERAGE_PATH_SEPARATOR_BYTES = 1U,
};

typedef enum {
    COVERAGE_PATH_OK = 0,
    COVERAGE_PATH_OUTSIDE,
    COVERAGE_PATH_INVALID,
} coverage_path_result_t;

typedef enum {
    COVERAGE_ISSUE_PARTIAL,
    COVERAGE_ISSUE_EXCLUDED,
    COVERAGE_ISSUE_SKIPPED,
    COVERAGE_ISSUE_NONE,
} coverage_issue_t;

typedef enum {
    COVERAGE_COMPONENT_APPEND,
    COVERAGE_COMPONENT_SKIP,
    COVERAGE_COMPONENT_OUTSIDE,
    COVERAGE_COMPONENT_INVALID,
} coverage_component_result_t;

static bool coverage_path_is_absolute_or_drive(const char *input, size_t len) {
    return input[0] == '/' || input[0] == '\\' ||
           (len >= COVERAGE_WINDOWS_DRIVE_PREFIX_LEN && isalpha((unsigned char)input[0]) &&
            input[COVERAGE_WINDOWS_DRIVE_SEPARATOR_INDEX] == ':');
}

static coverage_component_result_t coverage_component_validate(const char *input, size_t start,
                                                               size_t length) {
    for (size_t index = start; index < start + length; index++) {
        if ((unsigned char)input[index] < COVERAGE_ASCII_CONTROL_FIRST) {
            return COVERAGE_COMPONENT_INVALID;
        }
    }
    if (length == COVERAGE_DOT_COMPONENT_LEN && input[start] == '.') {
        return COVERAGE_COMPONENT_SKIP;
    }
    if (length == COVERAGE_PARENT_COMPONENT_LEN && input[start] == '.' &&
        input[start + COVERAGE_PARENT_COMPONENT_SECOND_INDEX] == '.') {
        return COVERAGE_COMPONENT_OUTSIDE;
    }
    return COVERAGE_COMPONENT_APPEND;
}

static bool coverage_component_append(char *out, size_t out_size, size_t *written_io,
                                      const char *input, size_t start, size_t length) {
    size_t written = *written_io;
    if (written > 0U) {
        if (written + COVERAGE_PATH_SEPARATOR_BYTES >= out_size) {
            return false;
        }
        out[written++] = '/';
    }
    if (written + length >= out_size) {
        return false;
    }
    memcpy(out + written, input + start, length);
    *written_io = written + length;
    return true;
}

/* Normalize an untrusted repository-relative path without touching the
 * filesystem. Absolute paths, drive/UNC paths, control bytes, and any `..`
 * component are rejected. A root scope (`.`) normalizes to the empty prefix. */
static coverage_path_result_t coverage_normalize_rel(const char *input, bool allow_root, char *out,
                                                     size_t out_size) {
    if (!input || !out || out_size == 0U) {
        return COVERAGE_PATH_INVALID;
    }
    out[0] = '\0';
    size_t len = strlen(input);
    if (len == 0U || len >= out_size || coverage_path_is_absolute_or_drive(input, len)) {
        return COVERAGE_PATH_OUTSIDE;
    }

    size_t in = 0U;
    size_t written = 0U;
    while (in < len) {
        while (in < len && (input[in] == '/' || input[in] == '\\')) {
            in++;
        }
        if (in >= len) {
            break;
        }
        size_t start = in;
        while (in < len && input[in] != '/' && input[in] != '\\') {
            in++;
        }
        size_t part_len = in - start;
        coverage_component_result_t component = coverage_component_validate(input, start, part_len);
        if (component == COVERAGE_COMPONENT_SKIP) {
            continue;
        }
        if (component == COVERAGE_COMPONENT_OUTSIDE) {
            return COVERAGE_PATH_OUTSIDE;
        }
        if (component == COVERAGE_COMPONENT_INVALID ||
            !coverage_component_append(out, out_size, &written, input, start, part_len)) {
            return COVERAGE_PATH_INVALID;
        }
    }
    out[written] = '\0';
    return written > 0U || allow_root ? COVERAGE_PATH_OK : COVERAGE_PATH_INVALID;
}

static int64_t coverage_stat_mtime_ns(const struct stat *st) {
#ifdef __APPLE__
    return ((int64_t)st->st_mtimespec.tv_sec * (int64_t)CBM_NSEC_PER_SEC) +
           (int64_t)st->st_mtimespec.tv_nsec;
#elif defined(_WIN32)
    return (int64_t)st->st_mtime * (int64_t)CBM_NSEC_PER_SEC;
#else
    return ((int64_t)st->st_mtim.tv_sec * (int64_t)CBM_NSEC_PER_SEC) + (int64_t)st->st_mtim.tv_nsec;
#endif
}

static const char *coverage_path_freshness(cbm_store_t *store, const char *project,
                                           const char *root_path, const char *rel_path,
                                           bool *outside) {
    *outside = false;
    if (!root_path || !root_path[0]) {
        return "unavailable";
    }
    char abs_path[CBM_SZ_4K];
    int n = snprintf(abs_path, sizeof(abs_path), "%s%s%s", root_path,
                     root_path[strlen(root_path) - 1U] == '/' ? "" : "/", rel_path);
    if (n < 0 || (size_t)n >= sizeof(abs_path)) {
        return "unavailable";
    }
    struct stat st;
    if (stat(abs_path, &st) != 0) {
        return "missing";
    }
    if (!cbm_path_within_root(root_path, abs_path)) {
        *outside = true;
        return "outside_project";
    }

    cbm_file_hash_t hash = {0};
    int rc = cbm_store_get_file_hash(store, project, rel_path, &hash);
    if (rc == CBM_STORE_NOT_FOUND) {
        return "not_tracked";
    }
    if (rc != CBM_STORE_OK) {
        return "unavailable";
    }
    bool matches = hash.mtime_ns == coverage_stat_mtime_ns(&st) && hash.size == st.st_size;
    cbm_store_clear_file_hash(&hash);
    return matches ? "metadata_match" : "metadata_changed";
}

static void coverage_add_ranges(yyjson_mut_doc *doc, yyjson_mut_val *row, const char *detail) {
    if (!detail || !detail[0]) {
        return;
    }
    yyjson_mut_val *ranges = yyjson_mut_arr(doc);
    const char *p = detail;
    int emitted = 0;
    while (*p && emitted < COVERAGE_RANGE_MAX) {
        while (*p == ' ' || *p == ',') {
            p++;
        }
        if (!isdigit((unsigned char)*p)) {
            break;
        }
        char *endptr = NULL;
        long start = strtol(p, &endptr, MCP_DECIMAL_RADIX);
        if (endptr == p || start <= 0 || start > INT32_MAX) {
            break;
        }
        p = endptr;
        long end = start;
        if (*p == '-') {
            p++;
            long parsed = strtol(p, &endptr, MCP_DECIMAL_RADIX);
            if (endptr == p || parsed < start || parsed > INT32_MAX) {
                break;
            }
            end = parsed;
            p = endptr;
        }
        yyjson_mut_val *range = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_int(doc, range, "start", start);
        yyjson_mut_obj_add_int(doc, range, "end", end);
        yyjson_mut_arr_add_val(ranges, range);
        emitted++;
        while (*p == ' ') {
            p++;
        }
        if (*p && *p != ',') {
            break;
        }
    }
    if (emitted > 0) {
        yyjson_mut_obj_add_val(doc, row, "ranges", ranges);
    }
}

static void coverage_add_row_json(yyjson_mut_doc *doc, yyjson_mut_val *array,
                                  const cbm_coverage_row_t *row, const char *requested_path) {
    yyjson_mut_val *item = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, item, "path", row->rel_path ? row->rel_path : "");
    yyjson_mut_obj_add_strcpy(doc, item, "kind", row->kind ? row->kind : "");
    yyjson_mut_obj_add_strcpy(doc, item, "detail", row->detail ? row->detail : "");
    if (requested_path) {
        yyjson_mut_obj_add_str(
            doc, item, "match",
            row->rel_path && strcmp(row->rel_path, requested_path) == 0 ? "exact" : "ancestor");
    }
    if (row->kind && strcmp(row->kind, "parse_partial") == 0) {
        coverage_add_ranges(doc, item, row->detail);
    }
    yyjson_mut_arr_add_val(array, item);
}

static bool coverage_has_exact_row(const cbm_coverage_row_t *rows, int count,
                                   const char *requested_path) {
    for (int i = 0; i < count; i++) {
        if (rows[i].rel_path && strcmp(rows[i].rel_path, requested_path) == 0) {
            return true;
        }
    }
    return false;
}

static coverage_issue_t coverage_issue_from_kind(const char *kind) {
    if (!kind || !kind[0]) {
        return COVERAGE_ISSUE_NONE;
    }
    if (strcmp(kind, "parse_partial") == 0) {
        return COVERAGE_ISSUE_PARTIAL;
    }
    if (strncmp(kind, "not_indexed", COVERAGE_NOT_INDEXED_PREFIX_LEN) == 0) {
        return COVERAGE_ISSUE_EXCLUDED;
    }
    return COVERAGE_ISSUE_SKIPPED;
}

static coverage_issue_t coverage_strongest_issue(const cbm_coverage_row_t *rows, int count,
                                                 const char *requested_path, bool exact) {
    coverage_issue_t strongest = COVERAGE_ISSUE_NONE;
    for (int i = 0; i < count; i++) {
        if (exact && (!rows[i].rel_path || strcmp(rows[i].rel_path, requested_path) != 0)) {
            continue;
        }
        coverage_issue_t issue = coverage_issue_from_kind(rows[i].kind);
        if (issue < strongest) {
            strongest = issue;
        }
    }
    return strongest;
}

static const char *coverage_status(const cbm_coverage_row_t *rows, int count,
                                   const char *requested_path, const char *recording_status,
                                   bool generation_matches, bool lookup_ok) {
    if (!lookup_ok) {
        return "coverage_unavailable";
    }
    coverage_issue_t issue = coverage_strongest_issue(
        rows, count, requested_path, coverage_has_exact_row(rows, count, requested_path));
    if (issue == COVERAGE_ISSUE_PARTIAL) {
        return "partial";
    }
    if (issue == COVERAGE_ISSUE_EXCLUDED) {
        return "excluded";
    }
    if (issue == COVERAGE_ISSUE_SKIPPED) {
        return "skipped";
    }
    if (!generation_matches || !recording_status || strcmp(recording_status, "complete") != 0) {
        return "coverage_unavailable";
    }
    return "no_recorded_issue";
}

static const char *coverage_recommended_action(const char *status, const char *freshness) {
    if (!freshness || strcmp(freshness, "metadata_match") != 0) {
        return "read_source_and_reindex";
    }
    if (strcmp(status, "partial") == 0) {
        return "read_ranges_and_verify_scope";
    }
    if (strcmp(status, "skipped") == 0) {
        return "read_source_directly";
    }
    if (strcmp(status, "excluded") == 0) {
        return "read_source_or_change_ignore_rules";
    }
    if (strcmp(status, "no_recorded_issue") == 0) {
        return "use_graph_with_best_effort_caveat";
    }
    return "read_source_and_reindex";
}

typedef struct {
    cbm_store_t *store;
    const char *project;
    const char *project_root;
    const char *recording_status;
    bool generation_matches;
} coverage_lookup_context_t;

typedef struct {
    int limit;
    int offset;
} coverage_scope_page_t;

static void coverage_add_metadata_json(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                       const cbm_project_t *project, bool have_project,
                                       const cbm_coverage_meta_t *metadata, bool have_metadata,
                                       bool generation_matches, const char *recording_status) {
    yyjson_mut_obj_add_strcpy(doc, root, "indexed_at",
                              have_project && project->indexed_at ? project->indexed_at : "");
    yyjson_mut_val *value = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, value, "generation",
                              have_metadata && metadata->generation ? metadata->generation : "");
    yyjson_mut_obj_add_strcpy(doc, value, "index_mode",
                              have_metadata && metadata->index_mode ? metadata->index_mode
                                                                    : "unknown");
    yyjson_mut_obj_add_strcpy(doc, value, "recorded_at",
                              have_metadata && metadata->recorded_at ? metadata->recorded_at : "");
    yyjson_mut_obj_add_strcpy(doc, value, "recording_status", recording_status);
    yyjson_mut_obj_add_int(doc, value, "ignored_files_stored",
                           have_metadata ? metadata->ignored_files_stored : 0);
    yyjson_mut_obj_add_int(doc, value, "ignored_files_total",
                           have_metadata ? metadata->ignored_files_total : 0);
    yyjson_mut_obj_add_bool(doc, value, "hash_records_complete",
                            have_metadata && metadata->hash_records_complete);
    yyjson_mut_obj_add_int(doc, value, "coverage_version",
                           have_metadata ? metadata->coverage_version : 0);
    yyjson_mut_obj_add_bool(doc, value, "generation_matches", generation_matches);
    yyjson_mut_obj_add_val(doc, root, "metadata", value);
}

static void coverage_add_path_result(yyjson_mut_doc *doc, yyjson_mut_val *results,
                                     const coverage_lookup_context_t *context, const char *input) {
    yyjson_mut_val *item = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, item, "requested_path", input ? input : "");
    char relative_path[CBM_SZ_4K];
    coverage_path_result_t normalized =
        coverage_normalize_rel(input, false, relative_path, sizeof(relative_path));
    if (normalized != COVERAGE_PATH_OK) {
        yyjson_mut_obj_add_str(doc, item, "status",
                               normalized == COVERAGE_PATH_OUTSIDE ? "outside_project"
                                                                   : "invalid_path");
        yyjson_mut_obj_add_str(doc, item, "freshness", "unavailable");
        yyjson_mut_obj_add_str(doc, item, "recommended_action", "use_project_relative_path");
        yyjson_mut_arr_add_val(results, item);
        return;
    }
    yyjson_mut_obj_add_strcpy(doc, item, "path", relative_path);
    cbm_coverage_row_t *rows = NULL;
    int row_count = 0;
    int coverage_rc = cbm_store_coverage_get_path(context->store, context->project, relative_path,
                                                  &rows, &row_count);
    bool lookup_ok = coverage_rc == CBM_STORE_OK || coverage_rc == CBM_STORE_NOT_FOUND;
    if (!lookup_ok) {
        row_count = 0;
        yyjson_mut_obj_add_str(doc, item, "coverage_lookup", "error");
    }
    bool outside = false;
    const char *freshness = coverage_path_freshness(context->store, context->project,
                                                    context->project_root, relative_path, &outside);
    const char *status =
        outside ? "outside_project"
                : coverage_status(rows, row_count, relative_path, context->recording_status,
                                  context->generation_matches, lookup_ok);
    yyjson_mut_obj_add_strcpy(doc, item, "status", status);
    yyjson_mut_obj_add_strcpy(doc, item, "freshness", freshness);
    yyjson_mut_obj_add_strcpy(doc, item, "recommended_action",
                              coverage_recommended_action(status, freshness));
    yyjson_mut_val *coverage = yyjson_mut_arr(doc);
    for (int row_index = 0; row_index < row_count; row_index++) {
        coverage_add_row_json(doc, coverage, &rows[row_index], relative_path);
    }
    yyjson_mut_obj_add_val(doc, item, "coverage", coverage);
    cbm_store_free_coverage(rows, row_count);
    yyjson_mut_arr_add_val(results, item);
}

static void coverage_add_path_results(yyjson_mut_doc *doc, yyjson_mut_val *results,
                                      const yyjson_val *paths,
                                      const coverage_lookup_context_t *context) {
    if (!paths) {
        return;
    }
    size_t index;
    size_t max;
    yyjson_val *value;
    yyjson_arr_foreach(paths, index, max, value) {
        coverage_add_path_result(doc, results, context,
                                 yyjson_is_str(value) ? yyjson_get_str(value) : NULL);
    }
}

static coverage_scope_page_t coverage_scope_page_parse(const char *args) {
    coverage_scope_page_t page = {
        .limit = cbm_mcp_get_int_arg(args, "scope_limit", COVERAGE_SCOPE_DEFAULT_LIMIT),
        .offset = cbm_mcp_get_int_arg(args, "scope_offset", 0),
    };
    if (page.limit < COVERAGE_SCOPE_MIN_LIMIT) {
        page.limit = COVERAGE_SCOPE_MIN_LIMIT;
    } else if (page.limit > COVERAGE_SCOPE_MAX_LIMIT) {
        page.limit = COVERAGE_SCOPE_MAX_LIMIT;
    }
    if (page.offset < 0) {
        page.offset = 0;
    }
    return page;
}

static void coverage_add_scope_result(yyjson_mut_doc *doc, yyjson_mut_val *results,
                                      const coverage_lookup_context_t *context,
                                      coverage_scope_page_t page, const char *input) {
    yyjson_mut_val *item = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, item, "requested_scope", input ? input : "");
    char scope[CBM_SZ_4K];
    coverage_path_result_t normalized = coverage_normalize_rel(input, true, scope, sizeof(scope));
    if (normalized != COVERAGE_PATH_OK) {
        yyjson_mut_obj_add_str(doc, item, "status",
                               normalized == COVERAGE_PATH_OUTSIDE ? "outside_project"
                                                                   : "invalid_path");
        yyjson_mut_arr_add_val(results, item);
        return;
    }
    yyjson_mut_obj_add_strcpy(doc, item, "scope", scope[0] ? scope : ".");
    cbm_coverage_row_t *rows = NULL;
    int row_count = 0;
    int coverage_rc =
        cbm_store_coverage_get_scope(context->store, context->project, scope, &rows, &row_count);
    bool lookup_ok = coverage_rc == CBM_STORE_OK || coverage_rc == CBM_STORE_NOT_FOUND;
    if (!lookup_ok) {
        row_count = 0;
        yyjson_mut_obj_add_str(doc, item, "coverage_lookup", "error");
    }
    yyjson_mut_obj_add_int(doc, item, "total", row_count);
    int start = page.offset < row_count ? page.offset : row_count;
    int end = start + page.limit < row_count ? start + page.limit : row_count;
    yyjson_mut_obj_add_bool(doc, item, "has_more", end < row_count);
    if (end < row_count) {
        yyjson_mut_obj_add_int(doc, item, "next_offset", end);
    }
    yyjson_mut_val *entries = yyjson_mut_arr(doc);
    for (int row_index = start; row_index < end; row_index++) {
        coverage_add_row_json(doc, entries, &rows[row_index], NULL);
    }
    yyjson_mut_obj_add_val(doc, item, "entries", entries);
    const char *status = "coverage_unavailable";
    if (lookup_ok && context->generation_matches) {
        if (row_count > 0) {
            status = "known_gaps";
        } else if (strcmp(context->recording_status, "complete") == 0) {
            status = "no_recorded_issue";
        }
    }
    yyjson_mut_obj_add_str(doc, item, "status", status);
    cbm_store_free_coverage(rows, row_count);
    yyjson_mut_arr_add_val(results, item);
}

static void coverage_add_scope_results(yyjson_mut_doc *doc, yyjson_mut_val *results,
                                       const yyjson_val *scopes,
                                       const coverage_lookup_context_t *context,
                                       coverage_scope_page_t page) {
    if (!scopes) {
        return;
    }
    size_t index;
    size_t max;
    yyjson_val *value;
    yyjson_arr_foreach(scopes, index, max, value) {
        coverage_add_scope_result(doc, results, context, page,
                                  yyjson_is_str(value) ? yyjson_get_str(value) : NULL);
    }
}

static char *handle_check_index_coverage(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    REQUIRE_STORE(store, project);

    yyjson_doc *adoc = yyjson_read(args, strlen(args), 0);
    yyjson_val *aroot = adoc ? yyjson_doc_get_root(adoc) : NULL;
    yyjson_val *paths = aroot ? yyjson_obj_get(aroot, "paths") : NULL;
    yyjson_val *scopes = aroot ? yyjson_obj_get(aroot, "scopes") : NULL;
    size_t path_count = paths && yyjson_is_arr(paths) ? yyjson_arr_size(paths) : 0U;
    size_t scope_count = scopes && yyjson_is_arr(scopes) ? yyjson_arr_size(scopes) : 0U;
    if (!aroot || (paths && !yyjson_is_arr(paths)) || (scopes && !yyjson_is_arr(scopes)) ||
        (path_count == 0U && scope_count == 0U) || path_count > COVERAGE_PATH_MAX ||
        scope_count > COVERAGE_SCOPE_MAX) {
        if (adoc) {
            yyjson_doc_free(adoc);
        }
        free(project);
        return cbm_mcp_text_result(
            "paths or scopes is required (arrays; max 128 paths and 32 scopes)", true);
    }

    cbm_project_t proj = {0};
    bool have_project = cbm_store_get_project(store, project, &proj) == CBM_STORE_OK;
    cbm_coverage_meta_t meta = {0};
    bool have_meta = cbm_store_coverage_meta_get(store, project, &meta) == CBM_STORE_OK;
    bool generation_matches = have_project && have_meta && proj.indexed_at && meta.generation &&
                              strcmp(proj.indexed_at, meta.generation) == 0;
    const char *recording_status =
        have_meta && meta.recording_status ? meta.recording_status : "unknown";

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_strcpy(doc, root, "project", project);
    yyjson_mut_obj_add_str(doc, root, "signal", "best_effort");
    coverage_add_metadata_json(doc, root, &proj, have_project, &meta, have_meta, generation_matches,
                               recording_status);

    coverage_lookup_context_t context = {
        .store = store,
        .project = project,
        .project_root = have_project ? proj.root_path : NULL,
        .recording_status = recording_status,
        .generation_matches = generation_matches,
    };

    yyjson_mut_val *path_results = yyjson_mut_arr(doc);
    coverage_add_path_results(doc, path_results, paths, &context);
    yyjson_mut_obj_add_val(doc, root, "paths", path_results);

    yyjson_mut_val *scope_results = yyjson_mut_arr(doc);
    coverage_add_scope_results(doc, scope_results, scopes, &context,
                               coverage_scope_page_parse(args));
    yyjson_mut_obj_add_val(doc, root, "scopes", scope_results);
    yyjson_mut_obj_add_str(
        doc, root, "caveat",
        "Best-effort signal only. No recorded issue does not prove graph or source completeness; "
        "read flagged source and qualify claims when metadata is changed or unavailable.");

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    yyjson_doc_free(adoc);
    if (have_meta) {
        cbm_store_coverage_meta_clear(&meta);
    }
    if (have_project) {
        safe_str_free(&proj.name);
        safe_str_free(&proj.indexed_at);
        safe_str_free(&proj.root_path);
    }
    free(project);
    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

static char *handle_index_status(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    REQUIRE_STORE(store, project);
    /* The git context block (worktree/shadow path variants) only matters when
     * debugging index-location issues — gate it so the common status call
     * stays lean. */
    bool verbose = cbm_mcp_get_bool_arg(args, "verbose");

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    if (project) {
        int nodes = cbm_store_count_nodes(store, project);
        int edges = cbm_store_count_edges(store, project);
        yyjson_mut_obj_add_str(doc, root, "project", project);
        yyjson_mut_obj_add_int(doc, root, "nodes", nodes);
        yyjson_mut_obj_add_int(doc, root, "edges", edges);
        yyjson_mut_obj_add_str(doc, root, "status", nodes > 0 ? "ready" : "empty");
        cbm_project_t proj_info = {0};
        if (cbm_store_get_project(store, project, &proj_info) == CBM_STORE_OK) {
            yyjson_mut_obj_add_strcpy(doc, root, "root_path",
                                      proj_info.root_path ? proj_info.root_path : "");
            if (verbose) {
                add_git_context_json(doc, root, proj_info.root_path, srv);
            }
            safe_str_free(&proj_info.name);
            safe_str_free(&proj_info.indexed_at);
            safe_str_free(&proj_info.root_path);
        }
        add_coverage_report(doc, root, store, project);
        if (nodes == 0) {
            yyjson_mut_obj_add_str(
                doc, root, "hint",
                "Project is empty. Re-run index_repository(repo_path=...) to populate.");
        }
    } else {
        yyjson_mut_obj_add_str(doc, root, "status", "no_project");
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(project);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* delete_project: just erase the .db file (and WAL/SHM). */
static char *handle_delete_project(cbm_mcp_server_t *srv, const char *args) {
    char *name = get_project_arg(args);
    if (!name) {
        return cbm_mcp_text_result("project is required", true);
    }
    if (!mcp_project_mutation_begin(srv, name)) {
        free(name);
        return cbm_mcp_text_result("project operation cancelled or blocked by an active index",
                                   true);
    }

    /* Close store if it's the project being deleted */
    if (srv->current_project && strcmp(srv->current_project, name) == 0) {
        if (srv->owns_store && srv->store) {
            cbm_store_close(srv->store);
            srv->store = NULL;
        }
        free(srv->current_project);
        srv->current_project = NULL;
    }

    /* Wait for any in-progress pipeline to finish before deleting */
    cbm_pipeline_lock();

    /* Delete the .db file + WAL/SHM */
    char path[CBM_SZ_1K];
    project_db_path(name, path, sizeof(path));

    char wal[CBM_SZ_1K];
    char shm[CBM_SZ_1K];
    snprintf(wal, sizeof(wal), "%s-wal", path);
    snprintf(shm, sizeof(shm), "%s-shm", path);

    bool exists = (access(path, F_OK) == 0);
    const char *status = "not_found";
    const char *error_detail = NULL;
    bool is_error = false;

    if (exists) {
        int rc = cbm_unlink(path);
        (void)cbm_unlink(wal);
        (void)cbm_unlink(shm);
        if (rc == 0) {
            status = "deleted";
        } else {
            status = "delete_failed";
            error_detail = strerror(errno);
            is_error = true;
        }
    } else {
        is_error = true;
    }

    cbm_pipeline_unlock();

    if (srv->watcher) {
        cbm_watcher_unwatch(srv->watcher, name);
    }

    cbm_mem_collect(); /* return freed pages to OS after closing database */
    mcp_project_mutation_end(srv, name);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "project", name);
    yyjson_mut_obj_add_str(doc, root, "status", status);
    if (error_detail) {
        yyjson_mut_obj_add_str(doc, root, "error", error_detail);
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(name);

    char *result = cbm_mcp_text_result(json, is_error);
    free(json);
    return result;
}

/* Canonical list of valid aspect tokens for get_architecture. Single source
 * of truth for the server-side validation (authoritative); the JSON-Schema
 * enum in the TOOLS entry above is the advisory client-side mirror — update
 * both together when the aspect set changes. */
static const char *VALID_ASPECTS[] = {"all",      "overview",   "structure", "dependencies",
                                      "routes",   "languages",  "packages",  "entry_points",
                                      "hotspots", "boundaries", "layers",    "file_tree",
                                      "clusters", "cycles",     NULL};

/* ── SCC / cycle condensation (get_architecture "cycles") ─────────
 * Iterative Tarjan over the CALLS call graph. Recursion would overflow on a
 * large graph, so the DFS state lives on explicit heap stacks. Reports the
 * strongly-connected components of size > 1 — the circular call dependencies,
 * the non-trivial content of the condensation quotient. */
typedef struct {
    int64_t *ids;  /* sorted unique node ids; index = position */
    int nverts;    /* |V| */
    int *adj_head; /* CSR row starts, length nverts+1 */
    int *adj;      /* CSR column (target vertex indices), length nedges */
    int nedges;    /* |E| within the vertex set */
} scc_graph_t;

enum {
    SCC_INDEX_NOT_FOUND = -1,
    SCC_INDEX_STEP = 1,
    SCC_BINARY_SEARCH_DIVISOR = 2,
    SCC_EDGE_ENDPOINT_COUNT = 2U,
    SCC_EDGE_TARGET_OFFSET = 1U,
    SCC_ADJ_HEAD_TRAILER = 1,
    SCC_NONTRIVIAL_COMPONENT_MIN_VERTICES = 2,
};

static int scc_id_index(const int64_t *ids, int n, int64_t id) {
    int lo = 0;
    int hi = n - SCC_INDEX_STEP;
    while (lo <= hi) {
        int mid = (lo + hi) / SCC_BINARY_SEARCH_DIVISOR;
        if (ids[mid] < id) {
            lo = mid + SCC_INDEX_STEP;
        } else if (ids[mid] > id) {
            hi = mid - SCC_INDEX_STEP;
        } else {
            return mid;
        }
    }
    return SCC_INDEX_NOT_FOUND;
}

static int cmp_int64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a;
    int64_t y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* Build the CSR call graph from parallel (src,tgt) edge arrays. Returns false
 * on OOM/empty. */
static bool scc_build(const int64_t *src, const int64_t *tgt, int ecount, scc_graph_t *g) {
    memset(g, 0, sizeof(*g));
    if (ecount <= 0) {
        return false;
    }
    size_t endpoint_count = (size_t)ecount * SCC_EDGE_ENDPOINT_COUNT;
    int64_t *all = malloc(endpoint_count * sizeof(int64_t));
    if (!all) {
        return false;
    }
    for (size_t i = 0; i < (size_t)ecount; i++) {
        all[SCC_EDGE_ENDPOINT_COUNT * i] = src[i];
        all[(SCC_EDGE_ENDPOINT_COUNT * i) + SCC_EDGE_TARGET_OFFSET] = tgt[i];
    }
    qsort(all, endpoint_count, sizeof(int64_t), cmp_int64);
    int nv = 0;
    for (size_t i = 0; i < endpoint_count; i++) {
        if (i == 0 || all[i] != all[i - SCC_INDEX_STEP]) {
            all[nv++] = all[i];
        }
    }
    g->ids = all;
    g->nverts = nv;
    g->adj_head = calloc((size_t)nv + SCC_ADJ_HEAD_TRAILER, sizeof(int));
    g->adj = malloc((size_t)ecount * sizeof(int));
    if (!g->adj_head || !g->adj) {
        free(g->ids);
        free(g->adj_head);
        free(g->adj);
        memset(g, 0, sizeof(*g));
        return false;
    }
    /* two-pass CSR fill. Every endpoint is in ids[] by construction (ids is
     * built from these same edge arrays), so a negative lookup is unreachable
     * -- but that invariant is invisible to path-sensitive analysis, and a
     * guard keeps a future collection bug from becoming an OOB write. Both
     * passes must skip identically or the cursors desync. */
    for (int i = 0; i < ecount; i++) {
        int u = scc_id_index(g->ids, nv, src[i]);
        int v = scc_id_index(g->ids, nv, tgt[i]);
        if (u < 0 || v < 0) {
            continue;
        }
        g->adj_head[u + SCC_ADJ_HEAD_TRAILER]++;
    }
    for (int i = 0; i < nv; i++) {
        g->adj_head[i + SCC_ADJ_HEAD_TRAILER] += g->adj_head[i];
    }
    int *cursor = malloc((size_t)nv * sizeof(int));
    if (!cursor) {
        free(g->ids);
        free(g->adj_head);
        free(g->adj);
        memset(g, 0, sizeof(*g));
        return false;
    }
    for (int i = 0; i < nv; i++) {
        cursor[i] = g->adj_head[i];
    }
    int filled = 0;
    for (int i = 0; i < ecount; i++) {
        int u = scc_id_index(g->ids, nv, src[i]);
        int v = scc_id_index(g->ids, nv, tgt[i]);
        if (u < 0 || v < 0) {
            continue;
        }
        g->adj[cursor[u]++] = v;
        filled++;
    }
    free(cursor);
    g->nedges = filled;
    return true;
}

static void scc_free(scc_graph_t *g) {
    free(g->ids);
    free(g->adj_head);
    free(g->adj);
    memset(g, 0, sizeof(*g));
}

typedef struct {
    int *index;
    int *low;
    bool *on_stack;
    int *tarjan_stack;
    int *dfs_vertex;
    int *dfs_edge;
    int counter;
    int tarjan_stack_size;
    int component_count;
} scc_tarjan_state_t;

static void scc_tarjan_state_free(scc_tarjan_state_t *state) {
    free(state->index);
    free(state->low);
    free(state->on_stack);
    free(state->tarjan_stack);
    free(state->dfs_vertex);
    free(state->dfs_edge);
    memset(state, 0, sizeof(*state));
}

static bool scc_tarjan_state_init(scc_tarjan_state_t *state, int nverts, int *comp) {
    memset(state, 0, sizeof(*state));
    state->index = malloc((size_t)nverts * sizeof(int));
    state->low = malloc((size_t)nverts * sizeof(int));
    state->on_stack = calloc((size_t)nverts, sizeof(bool));
    state->tarjan_stack = malloc((size_t)nverts * sizeof(int));
    state->dfs_vertex = malloc((size_t)nverts * sizeof(int));
    state->dfs_edge = malloc((size_t)nverts * sizeof(int));
    if (!state->index || !state->low || !state->on_stack || !state->tarjan_stack ||
        !state->dfs_vertex || !state->dfs_edge) {
        scc_tarjan_state_free(state);
        return false;
    }
    for (int i = 0; i < nverts; i++) {
        state->index[i] = SCC_INDEX_NOT_FOUND;
        comp[i] = SCC_INDEX_NOT_FOUND;
    }
    return true;
}

static void scc_tarjan_discover(scc_tarjan_state_t *state, int vertex) {
    state->index[vertex] = state->counter;
    state->low[vertex] = state->counter;
    state->counter++;
    state->tarjan_stack[state->tarjan_stack_size++] = vertex;
    state->on_stack[vertex] = true;
}

static bool scc_tarjan_visit_next_edge(const scc_graph_t *graph, scc_tarjan_state_t *state,
                                       int *dfs_depth_io) {
    int dfs_depth = *dfs_depth_io;
    int vertex = state->dfs_vertex[dfs_depth];
    if (state->dfs_edge[dfs_depth] >= graph->adj_head[vertex + SCC_ADJ_HEAD_TRAILER]) {
        return false;
    }
    int adjacent = graph->adj[state->dfs_edge[dfs_depth]++];
    if (state->index[adjacent] == SCC_INDEX_NOT_FOUND) {
        scc_tarjan_discover(state, adjacent);
        dfs_depth += SCC_INDEX_STEP;
        state->dfs_vertex[dfs_depth] = adjacent;
        state->dfs_edge[dfs_depth] = graph->adj_head[adjacent];
        *dfs_depth_io = dfs_depth;
    } else if (state->on_stack[adjacent] && state->index[adjacent] < state->low[vertex]) {
        state->low[vertex] = state->index[adjacent];
    }
    return true;
}

static void scc_tarjan_finish_vertex(scc_tarjan_state_t *state, int *comp, int *dfs_depth_io) {
    int dfs_depth = *dfs_depth_io;
    int vertex = state->dfs_vertex[dfs_depth];
    if (state->low[vertex] == state->index[vertex]) {
        while (true) {
            int member = state->tarjan_stack[--state->tarjan_stack_size];
            state->on_stack[member] = false;
            comp[member] = state->component_count;
            if (member == vertex) {
                break;
            }
        }
        state->component_count++;
    }
    dfs_depth--;
    if (dfs_depth >= 0 && state->low[vertex] < state->low[state->dfs_vertex[dfs_depth]]) {
        state->low[state->dfs_vertex[dfs_depth]] = state->low[vertex];
    }
    *dfs_depth_io = dfs_depth;
}

/* Iterative Tarjan. Fills comp[v] with a component id; components are numbered
 * in discovery order. Returns the component count, or -1 on OOM. */
static int scc_tarjan(const scc_graph_t *g, int *comp) {
    int nv = g->nverts;
    scc_tarjan_state_t state;
    if (!scc_tarjan_state_init(&state, nv, comp)) {
        return SCC_INDEX_NOT_FOUND;
    }
    for (int s = 0; s < nv; s++) {
        if (state.index[s] != SCC_INDEX_NOT_FOUND) {
            continue;
        }
        int dfs_depth = 0;
        state.dfs_vertex[dfs_depth] = s;
        state.dfs_edge[dfs_depth] = g->adj_head[s];
        scc_tarjan_discover(&state, s);
        while (dfs_depth >= 0) {
            if (!scc_tarjan_visit_next_edge(g, &state, &dfs_depth)) {
                scc_tarjan_finish_vertex(&state, comp, &dfs_depth);
            }
        }
    }
    int component_count = state.component_count;
    scc_tarjan_state_free(&state);
    return component_count;
}

static bool aspect_is_valid(const char *name) {
    if (!name) {
        return false;
    }
    for (int i = 0; VALID_ASPECTS[i]; i++) {
        if (strcmp(name, VALID_ASPECTS[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* Check if an aspect is requested. NULL aspects = all. The array can contain
 * "all" (everything), "overview" (everything except file_tree — see
 * cbm_store_arch_aspect_in_overview in store.c), or the aspect name itself. */
/* True ONLY when `name` is explicitly present in the aspects array — never via
 * the no-filter default, "all", or "overview". For expensive opt-in aspects
 * (cycles scans the whole call graph) that must not run on a bare call. */
static bool aspect_explicitly_named(yyjson_val *aspects_arr, const char *name) {
    if (!aspects_arr) {
        return false;
    }
    yyjson_arr_iter iter;
    yyjson_arr_iter_init(aspects_arr, &iter);
    yyjson_val *val;
    while ((val = yyjson_arr_iter_next(&iter)) != NULL) {
        const char *s = yyjson_get_str(val);
        if (s && strcmp(s, name) == 0) {
            return true;
        }
    }
    return false;
}

static bool aspect_wanted(yyjson_doc *aspects_doc, yyjson_val *aspects_arr, const char *name) {
    if (!aspects_arr) {
        return true; /* no filter = all */
    }
    yyjson_arr_iter iter;
    yyjson_arr_iter_init(aspects_arr, &iter);
    yyjson_val *val;
    while ((val = yyjson_arr_iter_next(&iter)) != NULL) {
        const char *s = yyjson_get_str(val);
        if (!s) {
            continue;
        }
        if (strcmp(s, "all") == 0) {
            return true;
        }
        if (strcmp(s, "overview") == 0 && cbm_store_arch_aspect_in_overview(name)) {
            return true;
        }
        if (strcmp(s, name) == 0) {
            return true;
        }
    }
    (void)aspects_doc;
    return false;
}

/* Append cross_repo_links summary to architecture JSON if CROSS_* edges exist. */
static void append_cross_repo_summary(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                      const cbm_schema_info_t *schema) {
    /* Scan edge types for any CROSS_* edges and sum them */
    int cross_total = 0;
    yyjson_mut_val *cr = yyjson_mut_obj(doc);
    static const char *cross_types[] = {"CROSS_HTTP_CALLS",    "CROSS_ASYNC_CALLS",
                                        "CROSS_CHANNEL",       "CROSS_GRPC_CALLS",
                                        "CROSS_GRAPHQL_CALLS", "CROSS_TRPC_CALLS"};
    for (int t = 0; t < (int)(sizeof(cross_types) / sizeof(cross_types[0])); t++) {
        for (int i = 0; i < schema->edge_type_count; i++) {
            if (strcmp(schema->edge_types[i].type, cross_types[t]) == 0) {
                yyjson_mut_obj_add_int(doc, cr, cross_types[t], schema->edge_types[i].count);
                cross_total += schema->edge_types[i].count;
                break;
            }
        }
    }
    if (cross_total > 0) {
        yyjson_mut_obj_add_int(doc, cr, "total", cross_total);
        yyjson_mut_obj_add_val(doc, root, "cross_repo_links", cr);
    }
}

/* Join a string list into buf with ';' separators (keeps TOON cells
 * comma-free so they need no quoting). Truncates silently at sz. */
static void arch_join_list(char *buf, size_t sz, const char **items, int n) {
    size_t pos = 0;
    buf[0] = '\0';
    for (int i = 0; i < n; i++) {
        const char *s = items[i] ? items[i] : "";
        int w = snprintf(buf + pos, sz - pos, "%s%s", i > 0 ? ";" : "", s);
        if (w < 0 || (size_t)w >= sz - pos) {
            break;
        }
        pos += (size_t)w;
    }
}

/* Compute the circular-dependency SCCs (size > 1) of the CALLS graph. Returns
 * a malloc'd array of components, each a malloc'd int64 array of member node
 * ids, with sizes in *out_sizes and count in *out_ncycles; sets *scanned_edges
 * and *edges_truncated. Caller frees each component + the arrays. Returns
 * CBM_STORE_OK, or CBM_STORE_ERR on failure (all outs zeroed). */
enum { ARCH_SCC_MAX_EDGES = 400000, ARCH_SCC_MAX_CYCLES = 100, ARCH_SCC_MEMBERS_SHOWN = 20 };

static int *arch_component_sizes(const scc_graph_t *graph, const int *components,
                                 int component_count) {
    if (component_count <= 0) {
        return NULL;
    }
    int *sizes = calloc((size_t)component_count, sizeof(*sizes));
    if (!sizes) {
        return NULL;
    }
    for (int vertex = 0; vertex < graph->nverts; vertex++) {
        sizes[components[vertex]]++;
    }
    return sizes;
}

static int arch_nontrivial_component_count(const int *component_sizes, int component_count) {
    int cycles = 0;
    for (int component = 0; component < component_count; component++) {
        if (component_sizes[component] >= SCC_NONTRIVIAL_COMPONENT_MIN_VERTICES) {
            cycles++;
        }
    }
    return cycles;
}

static bool arch_allocate_cycle_output(const int *component_sizes, int component_count,
                                       int cycle_count, int64_t ***out_members, int **out_sizes,
                                       int **out_slots) {
    int64_t **members = cycle_count > 0 ? calloc((size_t)cycle_count, sizeof(*members)) : NULL;
    int *sizes = cycle_count > 0 ? calloc((size_t)cycle_count, sizeof(*sizes)) : NULL;
    int *slots = malloc((size_t)component_count * sizeof(*slots));
    if ((cycle_count > 0 && (!members || !sizes)) || !slots) {
        free(members);
        free(sizes);
        free(slots);
        return false;
    }
    int next_slot = 0;
    for (int component = 0; component < component_count; component++) {
        if (component_sizes[component] >= SCC_NONTRIVIAL_COMPONENT_MIN_VERTICES &&
            next_slot < cycle_count) {
            slots[component] = next_slot;
            sizes[next_slot] = component_sizes[component];
            members[next_slot] = malloc((size_t)component_sizes[component] * sizeof(int64_t));
            next_slot++;
        } else {
            slots[component] = SCC_INDEX_NOT_FOUND;
        }
    }
    *out_members = members;
    *out_sizes = sizes;
    *out_slots = slots;
    return true;
}

static int arch_compute_cycles(cbm_store_t *store, const char *project, int64_t ***out_members,
                               int **out_sizes, int *out_ncycles, int *out_total_cycles,
                               int *scanned_edges, bool *edges_truncated) {
    *out_members = NULL;
    *out_sizes = NULL;
    *out_ncycles = 0;
    *out_total_cycles = 0;
    *scanned_edges = 0;
    *edges_truncated = false;

    int64_t *src = NULL;
    int64_t *tgt = NULL;
    int ecount = 0;
    if (cbm_store_fetch_call_edges(store, project, ARCH_SCC_MAX_EDGES, &src, &tgt, &ecount,
                                   edges_truncated) != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }
    *scanned_edges = ecount;
    scc_graph_t g;
    if (!scc_build(src, tgt, ecount, &g)) {
        free(src);
        free(tgt);
        return CBM_STORE_OK; /* no edges = no cycles, not an error */
    }
    free(src);
    free(tgt);

    int *comp = malloc((size_t)g.nverts * sizeof(int));
    if (!comp) {
        scc_free(&g);
        return CBM_STORE_ERR;
    }
    int ncomp = scc_tarjan(&g, comp);
    if (ncomp < 0) {
        free(comp);
        scc_free(&g);
        return CBM_STORE_ERR;
    }
    /* Tarjan assigns every vertex a component, so ncomp >= 1 whenever
     * nverts >= 1 -- state it, so the zero-size-allocation path below is
     * provably confined to the empty graph. */
    if (g.nverts > 0 && ncomp <= 0) {
        free(comp);
        scc_free(&g);
        return CBM_STORE_ERR;
    }
    int *csize = arch_component_sizes(&g, comp, ncomp);
    if (!csize) {
        free(comp);
        scc_free(&g);
        return CBM_STORE_ERR;
    }
    int ncyc = arch_nontrivial_component_count(csize, ncomp);
    *out_total_cycles = ncyc; /* the TRUE count, before the display clamp */
    if (ncyc > ARCH_SCC_MAX_CYCLES) {
        ncyc = ARCH_SCC_MAX_CYCLES;
    }
    int64_t **members = NULL;
    int *sizes = NULL;
    int *slot = NULL;
    if (!arch_allocate_cycle_output(csize, ncomp, ncyc, &members, &sizes, &slot)) {
        free(csize);
        free(comp);
        scc_free(&g);
        return CBM_STORE_ERR;
    }
    int *fill = ncyc > 0 ? calloc((size_t)ncyc, sizeof(*fill)) : NULL;
    if (ncyc > 0 && !fill) {
        for (int i = 0; i < ncyc; i++) {
            free(members[i]);
        }
        free(members);
        free(sizes);
        free(slot);
        free(csize);
        free(comp);
        scc_free(&g);
        return CBM_STORE_ERR;
    }
    /* With ncyc == 0 no slot is ever >= 0 (the slot loop can't assign one),
     * so members -- NULL in that case -- is never indexed; make that
     * invariant local instead of cross-loop so it is checkable. */
    if (ncyc > 0) {
        for (int v = 0; v < g.nverts; v++) {
            int sl = slot[comp[v]];
            if (sl >= 0) {
                members[sl][fill[sl]++] = g.ids[v];
            }
        }
    }
    free(fill);
    free(slot);
    free(csize);
    free(comp);
    scc_free(&g);
    *out_members = members;
    *out_sizes = sizes;
    *out_ncycles = ncyc;
    return CBM_STORE_OK;
}

/* Begin a json-tree {cols, rows} section under `key` on root; returns the
 * rows array for the caller to fill with column-ordered row arrays. */
static yyjson_mut_val *arch_json_section(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *key,
                                         const char *const *cols, int ncols) {
    yyjson_mut_val *sec = yyjson_mut_obj(doc);
    yyjson_mut_val *c = yyjson_mut_arr(doc);
    for (int i = 0; i < ncols; i++) {
        yyjson_mut_arr_add_str(doc, c, cols[i]);
    }
    yyjson_mut_obj_add_val(doc, sec, "cols", c);
    yyjson_mut_val *rows = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, sec, "rows", rows);
    yyjson_mut_obj_add_val(doc, root, key, sec);
    return rows;
}

/* Fetch the qualified_name for a node id, or a "#<id>" fallback. */
static void arch_node_qn(cbm_store_t *store, int64_t id, char *out, size_t outsz) {
    cbm_node_t n = {0};
    if (cbm_store_find_node_by_id(store, id, &n) == CBM_STORE_OK && n.qualified_name) {
        snprintf(out, outsz, "%s", n.qualified_name);
    } else {
        snprintf(out, outsz, "#%lld", (long long)id);
    }
    free_node_contents(&n);
}

enum {
    ARCH_NODE_LABEL_COLUMN_COUNT = 2,
    ARCH_EDGE_TYPE_COLUMN_COUNT = 2,
    ARCH_RELATIONSHIP_PATTERN_COLUMN_COUNT = 1,
    ARCH_LANGUAGE_COLUMN_COUNT = 2,
    ARCH_PACKAGE_COLUMN_COUNT = 4,
    ARCH_ENTRY_POINT_COLUMN_COUNT = 2,
    ARCH_ROUTE_COLUMN_COUNT = 3,
    ARCH_HOTSPOT_COLUMN_COUNT = 2,
    ARCH_BOUNDARY_COLUMN_COUNT = 3,
    ARCH_SERVICE_COLUMN_COUNT = 4,
    ARCH_LAYER_COLUMN_COUNT = 3,
    ARCH_CLUSTER_COLUMN_COUNT = 7,
    ARCH_FILE_TREE_COLUMN_COUNT = 3,
    ARCH_CYCLE_ROW_APPEND_RESERVE = 2,
    ARCH_CYCLE_TRUNCATION_RESERVE = 8,
};

static char *handle_get_architecture(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    /* REQUIRE_STORE returns without freeing anything but `project`, so every
     * other allocation must come after it (scope_path leaked here before —
     * caught by the clang-analyzer unix.Malloc lane). */
    REQUIRE_STORE(store, project);
    char *scope_path = cbm_mcp_get_string_arg(args, "path");

    char *not_indexed = verify_project_indexed(store, project);
    if (not_indexed) {
        free(project);
        free(scope_path);
        return not_indexed;
    }

    /* Parse aspects array from args */
    yyjson_doc *aspects_doc = NULL;
    yyjson_val *aspects_arr = NULL;
    {
        yyjson_doc *args_doc = yyjson_read(args, strlen(args), 0);
        if (args_doc) {
            yyjson_val *aval = yyjson_obj_get(yyjson_doc_get_root(args_doc), "aspects");
            if (yyjson_is_arr(aval)) {
                aspects_doc = args_doc; /* keep alive */
                aspects_arr = aval;
            } else {
                yyjson_doc_free(args_doc);
            }
        }
    }

    /* Build a C string array from aspects for cbm_store_get_architecture.
     * Strings point into aspects_doc memory so aspects_doc must outlive this array. */
    const char *aspects_strs[MCP_COL_16];
    int aspects_strs_count = 0;
    if (aspects_arr) {
        size_t aspect_idx;
        size_t aspect_max;
        yyjson_val *aspect_val;
        yyjson_arr_foreach(aspects_arr, aspect_idx, aspect_max, aspect_val) {
            const char *s = yyjson_get_str(aspect_val);
            if (s && aspects_strs_count < MCP_COL_16) {
                aspects_strs[aspects_strs_count++] = s;
            }
        }
    }

    /* Server-side validation: reject unknown aspect tokens with an isError
     * result listing the valid values. The JSON-Schema enum is advisory —
     * many MCP clients do not validate arguments against tool schemas — so
     * without this check a typo degraded to a silent near-empty payload. */
    for (int i = 0; i < aspects_strs_count; i++) {
        if (!aspect_is_valid(aspects_strs[i])) {
            char valid_list[CBM_SZ_256];
            size_t off = 0;
            for (int j = 0; VALID_ASPECTS[j] && off < sizeof(valid_list); j++) {
                int n = snprintf(valid_list + off, sizeof(valid_list) - off, "%s%s",
                                 j > 0 ? ", " : "", VALID_ASPECTS[j]);
                if (n < 0) {
                    break;
                }
                off += (size_t)n;
            }
            char msg[CBM_SZ_512];
            snprintf(msg, sizeof(msg), "Unknown aspect '%s'. Valid: %s.", aspects_strs[i],
                     valid_list);
            char *err = cbm_mcp_text_result(msg, true);
            free(project);
            free(scope_path);
            if (aspects_doc) {
                yyjson_doc_free(aspects_doc);
            }
            return err;
        }
    }

    /* Default (no aspects) = compact summary. The old default rendered ALL
     * aspects including the full file_tree — ~94KB (~23K tokens) on a
     * mid-size repo, a context bomb for the LLM consumers. Explicit
     * aspects (or ["all"]) keep full access to every section. */
    bool default_summary = false;
    if (aspects_strs_count == 0) {
        /* NOT "overview" — that means everything-except-file_tree. Totals and
         * node_labels/edge_types counts are always emitted alongside. */
        aspects_strs[aspects_strs_count++] = "languages";
        aspects_strs[aspects_strs_count++] = "packages";
        aspects_strs[aspects_strs_count++] = "entry_points";
        default_summary = true;
    }

    cbm_schema_info_t schema = {0};
    /* Counts-only: this handler renders label/type counts but never property
     * keys, and full key discovery json_each-scans every row (seconds-to-
     * minutes on multi-million-node graphs). */
    cbm_store_get_schema_counts_scoped(store, project, scope_path, &schema);

    cbm_architecture_info_t arch = {0};
    cbm_store_get_architecture(store, project, scope_path, aspects_strs, aspects_strs_count, &arch);

    int node_count = cbm_store_count_nodes_scoped(store, project, scope_path);
    int edge_count = cbm_store_count_edges_scoped(store, project, scope_path);
    char norm_path[CBM_SZ_512];
    bool path_scoped = cbm_store_normalize_arch_path(scope_path, norm_path, sizeof(norm_path));

    /* Response encoding: tree tables by default; format:"json" emits the
     * same model as structured JSON ({cols, rows} per section). */
    char *arch_format = cbm_mcp_get_string_arg(args, "format");
    bool arch_legacy_json = arch_format && strcmp(arch_format, "json") == 0;
    free(arch_format);

    if (!arch_legacy_json) {
        cbm_sb_t sb;
        cbm_sb_init(&sb);
        if (project) {
            cbm_tree_scalar_str(&sb, "project", project);
        }
        if (default_summary) {
            cbm_tree_scalar_str(&sb, "aspects_hint",
                                "Summary view (default). More on request via aspects:[...] — "
                                "structure, dependencies, routes, hotspots, boundaries, layers, "
                                "clusters, file_tree — or [\"all\"] for everything.");
        }
        if (path_scoped) {
            cbm_tree_scalar_str(&sb, "path", norm_path);
            cbm_tree_scalar_int(&sb, "root_total_nodes", cbm_store_count_nodes(store, project));
            cbm_tree_scalar_int(&sb, "root_total_edges", cbm_store_count_edges(store, project));
            cbm_tree_scalar_int(&sb, "scoped_total_nodes", node_count);
            cbm_tree_scalar_int(&sb, "scoped_total_edges", edge_count);
        }
        cbm_tree_scalar_int(&sb, "total_nodes", node_count);
        cbm_tree_scalar_int(&sb, "total_edges", edge_count);

        if (aspect_wanted(aspects_doc, aspects_arr, "structure") && schema.node_label_count > 0) {
            static const char *const lcols[] = {"label", "count"};
            cbm_tree_table_header(&sb, "node_labels", schema.node_label_count, lcols,
                                  ARCH_NODE_LABEL_COLUMN_COUNT);
            for (int i = 0; i < schema.node_label_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, schema.node_labels[i].label, true);
                cbm_tree_cell_int(&sb, schema.node_labels[i].count, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (aspect_wanted(aspects_doc, aspects_arr, "dependencies") && schema.edge_type_count > 0) {
            static const char *const tcols[] = {"type", "count"};
            cbm_tree_table_header(&sb, "edge_types", schema.edge_type_count, tcols,
                                  ARCH_EDGE_TYPE_COLUMN_COUNT);
            for (int i = 0; i < schema.edge_type_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, schema.edge_types[i].type, true);
                cbm_tree_cell_int(&sb, schema.edge_types[i].count, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (aspect_wanted(aspects_doc, aspects_arr, "routes") && schema.rel_pattern_count > 0) {
            static const char *const pcols[] = {"pattern"};
            cbm_tree_table_header(&sb, "relationship_patterns", schema.rel_pattern_count, pcols,
                                  ARCH_RELATIONSHIP_PATTERN_COLUMN_COUNT);
            for (int i = 0; i < schema.rel_pattern_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, schema.rel_patterns[i], true);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.language_count > 0) {
            static const char *const gcols[] = {"language", "files"};
            cbm_tree_table_header(&sb, "languages", arch.language_count, gcols,
                                  ARCH_LANGUAGE_COLUMN_COUNT);
            for (int i = 0; i < arch.language_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, arch.languages[i].language, true);
                cbm_tree_cell_int(&sb, arch.languages[i].file_count, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.package_count > 0) {
            static const char *const kcols[] = {"name", "nodes", "fan_in", "fan_out"};
            cbm_tree_table_header(&sb, "packages", arch.package_count, kcols,
                                  ARCH_PACKAGE_COLUMN_COUNT);
            for (int i = 0; i < arch.package_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, arch.packages[i].name, true);
                cbm_tree_cell_int(&sb, arch.packages[i].node_count, false);
                cbm_tree_cell_int(&sb, arch.packages[i].fan_in, false);
                cbm_tree_cell_int(&sb, arch.packages[i].fan_out, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.entry_point_count > 0) {
            /* qn only — `name` is its last segment. */
            static const char *const ecols[] = {"qn", "file"};
            cbm_tree_table_header(&sb, "entry_points", arch.entry_point_count, ecols,
                                  ARCH_ENTRY_POINT_COLUMN_COUNT);
            for (int i = 0; i < arch.entry_point_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, arch.entry_points[i].qualified_name, true);
                cbm_tree_cell_str(&sb, arch.entry_points[i].file, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.route_count > 0) {
            static const char *const rcols[] = {"method", "path", "handler"};
            cbm_tree_table_header(&sb, "routes", arch.route_count, rcols, ARCH_ROUTE_COLUMN_COUNT);
            for (int i = 0; i < arch.route_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, arch.routes[i].method, true);
                cbm_tree_cell_str(&sb, arch.routes[i].path, false);
                cbm_tree_cell_str(&sb, arch.routes[i].handler, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.hotspot_count > 0) {
            static const char *const hcols[] = {"qn", "fan_in"};
            cbm_tree_table_header(&sb, "hotspots", arch.hotspot_count, hcols,
                                  ARCH_HOTSPOT_COLUMN_COUNT);
            for (int i = 0; i < arch.hotspot_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, arch.hotspots[i].qualified_name, true);
                cbm_tree_cell_int(&sb, arch.hotspots[i].fan_in, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.boundary_count > 0) {
            static const char *const bcols[] = {"from", "to", "calls"};
            cbm_tree_table_header(&sb, "boundaries", arch.boundary_count, bcols,
                                  ARCH_BOUNDARY_COLUMN_COUNT);
            for (int i = 0; i < arch.boundary_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, arch.boundaries[i].from, true);
                cbm_tree_cell_str(&sb, arch.boundaries[i].to, false);
                cbm_tree_cell_int(&sb, arch.boundaries[i].call_count, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.service_count > 0) {
            static const char *const scols[] = {"from", "to", "type", "count"};
            cbm_tree_table_header(&sb, "services", arch.service_count, scols,
                                  ARCH_SERVICE_COLUMN_COUNT);
            for (int i = 0; i < arch.service_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, arch.services[i].from, true);
                cbm_tree_cell_str(&sb, arch.services[i].to, false);
                cbm_tree_cell_str(&sb, arch.services[i].type, false);
                cbm_tree_cell_int(&sb, arch.services[i].count, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.layer_count > 0) {
            static const char *const ycols[] = {"name", "layer", "reason"};
            cbm_tree_table_header(&sb, "layers", arch.layer_count, ycols, ARCH_LAYER_COLUMN_COUNT);
            for (int i = 0; i < arch.layer_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, arch.layers[i].name, true);
                cbm_tree_cell_str(&sb, arch.layers[i].layer, false);
                cbm_tree_cell_str(&sb, arch.layers[i].reason, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.cluster_count > 0) {
            /* Nested lists become ';'-joined cells. */
            static const char *const ccols[] = {"id",        "label",    "members",   "cohesion",
                                                "top_nodes", "packages", "edge_types"};
            cbm_tree_table_header(&sb, "clusters", arch.cluster_count, ccols,
                                  ARCH_CLUSTER_COLUMN_COUNT);
            for (int i = 0; i < arch.cluster_count; i++) {
                const cbm_cluster_info_t *c = &arch.clusters[i];
                char joined[CBM_SZ_1K];
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_int(&sb, c->id, true);
                cbm_tree_cell_str(&sb, c->label, false);
                cbm_tree_cell_int(&sb, c->members, false);
                cbm_tree_cell_real(&sb, c->cohesion, false);
                arch_join_list(joined, sizeof(joined), c->top_nodes, c->top_node_count);
                cbm_tree_cell_str(&sb, joined, false);
                arch_join_list(joined, sizeof(joined), c->packages, c->package_count);
                cbm_tree_cell_str(&sb, joined, false);
                arch_join_list(joined, sizeof(joined), c->edge_types, c->edge_type_count);
                cbm_tree_cell_str(&sb, joined, false);
                cbm_tree_row_end(&sb);
            }
        }
        if (arch.file_tree_count > 0) {
            static const char *const fcols[] = {"path", "type", "children"};
            cbm_tree_table_header(&sb, "file_tree", arch.file_tree_count, fcols,
                                  ARCH_FILE_TREE_COLUMN_COUNT);
            for (int i = 0; i < arch.file_tree_count; i++) {
                cbm_tree_row_begin(&sb);
                cbm_tree_cell_str(&sb, arch.file_tree[i].path, true);
                cbm_tree_cell_str(&sb, arch.file_tree[i].type, false);
                cbm_tree_cell_int(&sb, arch.file_tree[i].children, false);
                cbm_tree_row_end(&sb);
            }
        }
        /* Cross-repo edge summary (mirrors append_cross_repo_summary). */
        {
            static const char *const cross_types[] = {"CROSS_HTTP_CALLS",    "CROSS_ASYNC_CALLS",
                                                      "CROSS_CHANNEL",       "CROSS_GRPC_CALLS",
                                                      "CROSS_GRAPHQL_CALLS", "CROSS_TRPC_CALLS"};
            int cross_total = 0;
            for (int t = 0; t < (int)(sizeof(cross_types) / sizeof(cross_types[0])); t++) {
                for (int i = 0; i < schema.edge_type_count; i++) {
                    if (strcmp(schema.edge_types[i].type, cross_types[t]) == 0) {
                        cross_total += schema.edge_types[i].count;
                        break;
                    }
                }
            }
            if (cross_total > 0) {
                cbm_tree_scalar_int(&sb, "cross_repo_links_total", cross_total);
            }
        }

        /* cycles: circular CALLS dependencies (SCCs of size > 1) — opt-in, it
         * scans the whole call graph. A quotient/condensation view. */
        if (aspect_explicitly_named(aspects_arr, "cycles")) {
            int64_t **members = NULL;
            int *sizes = NULL;
            int ncyc = 0;
            int total_cyc = 0;
            int scanned = 0;
            bool etrunc = false;
            if (arch_compute_cycles(store, project, &members, &sizes, &ncyc, &total_cyc, &scanned,
                                    &etrunc) == CBM_STORE_OK) {
                cbm_tree_scalar_int(&sb, "call_edges_scanned", scanned);
                cbm_tree_scalar_int(&sb, "cycles_total", total_cyc);
                if (etrunc) {
                    cbm_tree_scalar_bool(&sb, "cycles_partial", true);
                    cbm_tree_scalar_str(&sb, "cycles_hint",
                                        "call graph exceeded the scan budget; cycle list may be "
                                        "incomplete");
                }
                if (total_cyc > ncyc) {
                    char omit[CBM_SZ_128];
                    snprintf(omit, sizeof(omit), "cycles_omitted: %d  (showing the first %d)\n",
                             total_cyc - ncyc, ncyc);
                    cbm_sb_append(&sb, omit);
                }
                char hdr[CBM_SZ_128];
                snprintf(hdr, sizeof(hdr),
                         "cycles: %d  (rows: size members; circular CALLS dependencies)\n", ncyc);
                cbm_sb_append(&sb, hdr);
                for (int c = 0; c < ncyc; c++) {
                    char row[CBM_SZ_2K];
                    int off = snprintf(row, sizeof(row), "  %d ", sizes[c]);
                    bool clipped = sizes[c] > ARCH_SCC_MEMBERS_SHOWN;
                    int show = clipped ? ARCH_SCC_MEMBERS_SHOWN : sizes[c];
                    for (int m = 0;
                         m < show && off < (int)sizeof(row) - ARCH_CYCLE_ROW_APPEND_RESERVE; m++) {
                        char qn[CBM_SZ_512];
                        arch_node_qn(store, members[c][m], qn, sizeof(qn));
                        // Loop guard above holds off in [0, sizeof(row) - 2).
                        off += snprintf(row + off, sizeof(row) - (size_t)off, "%s%s", m ? ";" : "",
                                        qn);
                    }
                    if (clipped && off < (int)sizeof(row) - ARCH_CYCLE_TRUNCATION_RESERVE) {
                        // Guard above holds off in [0, sizeof(row) - 8).
                        snprintf(row + off, sizeof(row) - (size_t)off, ";+%d", sizes[c] - show);
                    }
                    cbm_sb_append(&sb, row);
                    cbm_sb_append(&sb, "\n");
                    free(members[c]);
                }
                free(members);
                free(sizes);
            }
        }

        cbm_store_architecture_free(&arch);
        cbm_store_schema_free(&schema);
        if (aspects_doc) {
            yyjson_doc_free(aspects_doc);
        }
        free(project);
        free(scope_path);
        char *text = cbm_sb_finish(&sb);
        char *result = cbm_mcp_text_result(text ? text : "out of memory", text == NULL);
        free(text);
        return result;
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    if (project) {
        yyjson_mut_obj_add_str(doc, root, "project", project);
    }
    if (default_summary) {
        yyjson_mut_obj_add_str(doc, root, "aspects_hint",
                               "Summary view (default). More on request via aspects:[...] — "
                               "structure, dependencies, routes, hotspots, boundaries, layers, "
                               "clusters, file_tree — or [\"all\"] for everything.");
    }
    if (path_scoped) {
        yyjson_mut_obj_add_str(doc, root, "path", norm_path);
        int root_nodes = cbm_store_count_nodes(store, project);
        int root_edges = cbm_store_count_edges(store, project);
        yyjson_mut_obj_add_int(doc, root, "root_total_nodes", root_nodes);
        yyjson_mut_obj_add_int(doc, root, "root_total_edges", root_edges);
        yyjson_mut_obj_add_int(doc, root, "scoped_total_nodes", node_count);
        yyjson_mut_obj_add_int(doc, root, "scoped_total_edges", edge_count);
    }
    yyjson_mut_obj_add_int(doc, root, "total_nodes", node_count);
    yyjson_mut_obj_add_int(doc, root, "total_edges", edge_count);

    /* Every section below is the json-tree model: {cols, rows[[...]]} —
     * mirrors the text tree tables one-for-one. */
    if (aspect_wanted(aspects_doc, aspects_arr, "structure")) {
        static const char *const lcols[] = {"label", "count"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "node_labels", lcols, ARCH_NODE_LABEL_COLUMN_COUNT);
        for (int i = 0; i < schema.node_label_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(doc, row, schema.node_labels[i].label);
            yyjson_mut_arr_add_int(doc, row, schema.node_labels[i].count);
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (aspect_wanted(aspects_doc, aspects_arr, "dependencies")) {
        static const char *const tcols[] = {"type", "count"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "edge_types", tcols, ARCH_EDGE_TYPE_COLUMN_COUNT);
        for (int i = 0; i < schema.edge_type_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(doc, row, schema.edge_types[i].type);
            yyjson_mut_arr_add_int(doc, row, schema.edge_types[i].count);
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    /* Relationship patterns (a plain list — no columns to factor) */
    if (aspect_wanted(aspects_doc, aspects_arr, "routes") && schema.rel_pattern_count > 0) {
        yyjson_mut_val *pats = yyjson_mut_arr(doc);
        for (int i = 0; i < schema.rel_pattern_count; i++) {
            yyjson_mut_arr_add_str(doc, pats, schema.rel_patterns[i]);
        }
        yyjson_mut_obj_add_val(doc, root, "relationship_patterns", pats);
    }

    if (arch.language_count > 0) {
        static const char *const gcols[] = {"language", "files"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "languages", gcols, ARCH_LANGUAGE_COLUMN_COUNT);
        for (int i = 0; i < arch.language_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(doc, row,
                                      arch.languages[i].language ? arch.languages[i].language : "");
            yyjson_mut_arr_add_int(doc, row, arch.languages[i].file_count);
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (arch.package_count > 0) {
        static const char *const kcols[] = {"name", "nodes", "fan_in", "fan_out"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "packages", kcols, ARCH_PACKAGE_COLUMN_COUNT);
        for (int i = 0; i < arch.package_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(doc, row, arch.packages[i].name ? arch.packages[i].name : "");
            yyjson_mut_arr_add_int(doc, row, arch.packages[i].node_count);
            yyjson_mut_arr_add_int(doc, row, arch.packages[i].fan_in);
            yyjson_mut_arr_add_int(doc, row, arch.packages[i].fan_out);
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (arch.entry_point_count > 0) {
        static const char *const ecols[] = {"qn", "file"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "entry_points", ecols, ARCH_ENTRY_POINT_COLUMN_COUNT);
        for (int i = 0; i < arch.entry_point_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(
                doc, row,
                arch.entry_points[i].qualified_name ? arch.entry_points[i].qualified_name : "");
            yyjson_mut_arr_add_strcpy(doc, row,
                                      arch.entry_points[i].file ? arch.entry_points[i].file : "");
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (arch.route_count > 0) {
        static const char *const rcols[] = {"method", "path", "handler"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "routes", rcols, ARCH_ROUTE_COLUMN_COUNT);
        for (int i = 0; i < arch.route_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(doc, row, arch.routes[i].method ? arch.routes[i].method : "");
            yyjson_mut_arr_add_strcpy(doc, row, arch.routes[i].path ? arch.routes[i].path : "");
            yyjson_mut_arr_add_strcpy(doc, row,
                                      arch.routes[i].handler ? arch.routes[i].handler : "");
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (arch.hotspot_count > 0) {
        static const char *const hcols[] = {"qn", "fan_in"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "hotspots", hcols, ARCH_HOTSPOT_COLUMN_COUNT);
        for (int i = 0; i < arch.hotspot_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(
                doc, row, arch.hotspots[i].qualified_name ? arch.hotspots[i].qualified_name : "");
            yyjson_mut_arr_add_int(doc, row, arch.hotspots[i].fan_in);
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (arch.boundary_count > 0) {
        static const char *const bcols[] = {"from", "to", "calls"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "boundaries", bcols, ARCH_BOUNDARY_COLUMN_COUNT);
        for (int i = 0; i < arch.boundary_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(doc, row,
                                      arch.boundaries[i].from ? arch.boundaries[i].from : "");
            yyjson_mut_arr_add_strcpy(doc, row, arch.boundaries[i].to ? arch.boundaries[i].to : "");
            yyjson_mut_arr_add_int(doc, row, arch.boundaries[i].call_count);
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (arch.service_count > 0) {
        static const char *const scols[] = {"from", "to", "type", "count"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "services", scols, ARCH_SERVICE_COLUMN_COUNT);
        for (int i = 0; i < arch.service_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(doc, row, arch.services[i].from ? arch.services[i].from : "");
            yyjson_mut_arr_add_strcpy(doc, row, arch.services[i].to ? arch.services[i].to : "");
            yyjson_mut_arr_add_strcpy(doc, row, arch.services[i].type ? arch.services[i].type : "");
            yyjson_mut_arr_add_int(doc, row, arch.services[i].count);
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (arch.layer_count > 0) {
        static const char *const ycols[] = {"name", "layer", "reason"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "layers", ycols, ARCH_LAYER_COLUMN_COUNT);
        for (int i = 0; i < arch.layer_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(doc, row, arch.layers[i].name ? arch.layers[i].name : "");
            yyjson_mut_arr_add_strcpy(doc, row, arch.layers[i].layer ? arch.layers[i].layer : "");
            yyjson_mut_arr_add_strcpy(doc, row, arch.layers[i].reason ? arch.layers[i].reason : "");
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (arch.cluster_count > 0) {
        /* Nested lists stay nested arrays within the row (tree-json). */
        static const char *const ccols[] = {"id",        "label",    "members",   "cohesion",
                                            "top_nodes", "packages", "edge_types"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "clusters", ccols, ARCH_CLUSTER_COLUMN_COUNT);
        for (int i = 0; i < arch.cluster_count; i++) {
            const cbm_cluster_info_t *c = &arch.clusters[i];
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_int(doc, row, c->id);
            yyjson_mut_arr_add_strcpy(doc, row, c->label);
            yyjson_mut_arr_add_int(doc, row, c->members);
            yyjson_mut_arr_add_real(doc, row, c->cohesion);
            yyjson_mut_val *top = yyjson_mut_arr(doc);
            for (int j = 0; j < c->top_node_count; j++) {
                yyjson_mut_arr_add_str(doc, top, c->top_nodes[j] ? c->top_nodes[j] : "");
            }
            yyjson_mut_arr_add_val(row, top);
            yyjson_mut_val *pkgs = yyjson_mut_arr(doc);
            for (int j = 0; j < c->package_count; j++) {
                yyjson_mut_arr_add_str(doc, pkgs, c->packages[j] ? c->packages[j] : "");
            }
            yyjson_mut_arr_add_val(row, pkgs);
            yyjson_mut_val *etypes = yyjson_mut_arr(doc);
            for (int j = 0; j < c->edge_type_count; j++) {
                yyjson_mut_arr_add_str(doc, etypes, c->edge_types[j] ? c->edge_types[j] : "");
            }
            yyjson_mut_arr_add_val(row, etypes);
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    if (arch.file_tree_count > 0) {
        static const char *const fcols[] = {"path", "type", "children"};
        yyjson_mut_val *rows =
            arch_json_section(doc, root, "file_tree", fcols, ARCH_FILE_TREE_COLUMN_COUNT);
        for (int i = 0; i < arch.file_tree_count; i++) {
            yyjson_mut_val *row = yyjson_mut_arr(doc);
            yyjson_mut_arr_add_strcpy(doc, row,
                                      arch.file_tree[i].path ? arch.file_tree[i].path : "");
            yyjson_mut_arr_add_strcpy(doc, row,
                                      arch.file_tree[i].type ? arch.file_tree[i].type : "");
            yyjson_mut_arr_add_int(doc, row, arch.file_tree[i].children);
            yyjson_mut_arr_add_val(rows, row);
        }
    }

    append_cross_repo_summary(doc, root, &schema);

    /* cycles: SCCs of size > 1 in the CALLS graph (same model as tree). */
    if (aspect_explicitly_named(aspects_arr, "cycles")) {
        int64_t **members = NULL;
        int *sizes = NULL;
        int ncyc = 0;
        int total_cyc = 0;
        int scanned = 0;
        bool etrunc = false;
        if (arch_compute_cycles(store, project, &members, &sizes, &ncyc, &total_cyc, &scanned,
                                &etrunc) == CBM_STORE_OK) {
            yyjson_mut_obj_add_int(doc, root, "call_edges_scanned", scanned);
            yyjson_mut_obj_add_int(doc, root, "cycles_total", total_cyc);
            yyjson_mut_obj_add_bool(doc, root, "cycles_partial", etrunc);
            yyjson_mut_val *cyc = yyjson_mut_arr(doc);
            for (int c = 0; c < ncyc; c++) {
                yyjson_mut_val *o = yyjson_mut_obj(doc);
                yyjson_mut_obj_add_int(doc, o, "size", sizes[c]);
                yyjson_mut_val *mem = yyjson_mut_arr(doc);
                int show = sizes[c] < ARCH_SCC_MEMBERS_SHOWN ? sizes[c] : ARCH_SCC_MEMBERS_SHOWN;
                for (int m = 0; m < show; m++) {
                    char qn[CBM_SZ_512];
                    arch_node_qn(store, members[c][m], qn, sizeof(qn));
                    yyjson_mut_arr_add_strcpy(doc, mem, qn);
                }
                yyjson_mut_obj_add_val(doc, o, "members", mem);
                yyjson_mut_arr_add_val(cyc, o);
                free(members[c]);
            }
            yyjson_mut_obj_add_val(doc, root, "cycles", cyc);
            free(members);
            free(sizes);
        }
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    cbm_store_architecture_free(&arch);
    cbm_store_schema_free(&schema);
    if (aspects_doc) {
        yyjson_doc_free(aspects_doc);
    }
    free(project);
    free(scope_path);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* Resolve edge types from args: explicit array > mode-based > default ("CALLS").
 * Writes types into out_types (max 16). Returns the parsed yyjson_doc if explicit
 * edge_types were found (caller must keep alive until types are consumed), or NULL. */
static yyjson_doc *resolve_trace_edge_types(const char *args, const char *mode,
                                            const char **out_types, int *out_count) {
    static const char *mode_calls[] = {"CALLS"};
    static const char *mode_data_flow[] = {"CALLS", "DATA_FLOWS"};
    static const char *mode_cross_svc[] = {
        "HTTP_CALLS",          "ASYNC_CALLS",       "DATA_FLOWS",    "CALLS",
        "CROSS_HTTP_CALLS",    "CROSS_ASYNC_CALLS", "CROSS_CHANNEL", "CROSS_GRPC_CALLS",
        "CROSS_GRAPHQL_CALLS", "CROSS_TRPC_CALLS"};

    *out_count = 0;

    yyjson_doc *et_doc = yyjson_read(args, strlen(args), 0);
    if (et_doc) {
        yyjson_val *et_arr = yyjson_obj_get(yyjson_doc_get_root(et_doc), "edge_types");
        if (et_arr && yyjson_is_arr(et_arr)) {
            size_t idx2;
            size_t max2;
            yyjson_val *val2;
            yyjson_arr_foreach(et_arr, idx2, max2, val2) {
                if (yyjson_is_str(val2) && *out_count < MCP_COL_16) {
                    out_types[(*out_count)++] = yyjson_get_str(val2);
                }
            }
        }
    }

    if (*out_count > 0) {
        return et_doc; /* caller must keep alive — pointers reference doc memory */
    }

    yyjson_doc_free(et_doc); /* no explicit types found, free */

    const char **defaults = mode_calls;
    int n_defaults = SKIP_ONE;
    if (mode && strcmp(mode, "data_flow") == 0) {
        defaults = mode_data_flow;
        n_defaults = MCP_N_DEFAULTS_2;
    } else if (mode && strcmp(mode, "cross_service") == 0) {
        defaults = mode_cross_svc;
        n_defaults = (int)(sizeof(mode_cross_svc) / sizeof(mode_cross_svc[0]));
    }
    for (int i = 0; i < n_defaults; i++) {
        out_types[i] = defaults[i];
    }
    *out_count = n_defaults;
    return NULL;
}

/* Check if a file path looks like a test file. */
static bool is_test_file(const char *path) {
    if (!path) {
        return false;
    }
    return strstr(path, "/test") != NULL || strstr(path, "test_") != NULL ||
           strstr(path, "_test.") != NULL || strstr(path, "/tests/") != NULL ||
           strstr(path, "/spec/") != NULL || strstr(path, ".test.") != NULL;
}

/* Convert BFS traversal results into a yyjson_mut array. */
/* Find the CALLS-edge "args" JSON (the serialized arg expressions) on the edge
 * that leads to the given hop node, so data_flow mode can surface argument
 * expressions (#514). Returns the borrowed substring "[...]" inside the edge's
 * properties_json, with its length, or NULL when no args are recorded. */
static const char *bfs_edge_args_for_hop(cbm_traverse_result_t *tr, int64_t hop_node_id,
                                         size_t *out_len) {
    for (int e = 0; e < tr->edge_count; e++) {
        /* The hop node is the edge endpoint reached from the root side: for an
         * outbound trace it is the target, for inbound it is the source. Match
         * on either so both directions surface their args. */
        if (tr->edges[e].target_id != hop_node_id && tr->edges[e].source_id != hop_node_id) {
            continue;
        }
        const char *pj = tr->edges[e].properties_json;
        if (!pj) {
            continue;
        }
        const char *args = strstr(pj, "\"args\"");
        if (!args) {
            continue;
        }
        const char *open = strchr(args, '[');
        if (!open) {
            continue;
        }
        int depth = 0;
        const char *p = open;
        for (; *p; p++) {
            if (*p == '[') {
                depth++;
            } else if (*p == ']') {
                depth--;
                if (depth == 0) {
                    p++;
                    break;
                }
            }
        }
        *out_len = (size_t)(p - open);
        return open;
    }
    return NULL;
}

/* Classify a resolver strategy into the CLOSED public vocabulary.
 *
 * The indexer records ~20 internal strategy names on CALLS edges
 * (lsp_trait_dispatch, php_self_static, callee_suffix, ...) and the set grows
 * with every language. Publishing those verbatim would make each internal
 * resolver name public API by accident, so a rename would silently change a
 * user-visible field. We publish the CLASS instead: adding lsp_foo_dispatch
 * maps automatically, while a genuinely new KIND of resolution fails the
 * pinning test in tests/test_mcp.c and forces a deliberate decision.
 *
 * Returns NULL only for a NULL/empty strategy — every non-empty value lands in
 * a class, so an unmapped strategy can never silently vanish from output. */
static const char MCP_STRATEGY_LSP_PREFIX[] = "lsp_";
static const char MCP_STRATEGY_PHP_PREFIX[] = "php_";
static const char MCP_STRATEGY_PERL_PREFIX[] = "perl_";
static const char MCP_STRATEGY_JSON_KEY[] = "\"strategy\"";

enum {
    MCP_JSON_CHARACTER_STEP = 1,
    MCP_BFS_TOON_CORE_COLUMN_COUNT = 2,
    MCP_BFS_TOON_MAX_COLUMN_COUNT = 5,
};

static const double MCP_EDGE_CONFIDENCE_UNRECORDED = -1.0;

const char *cbm_mcp_edge_strategy_class(const char *strategy) {
    if (!strategy || !strategy[0]) {
        return NULL;
    }
    /* Order matters: lsp_unresolved is an LSP strategy that failed, and the
     * caller cares that it did NOT resolve — so it classifies as unresolved. */
    if (strcmp(strategy, "lsp_unresolved") == 0 || strcmp(strategy, "unknown") == 0) {
        return "unresolved";
    }
    if (strncmp(strategy, MCP_STRATEGY_LSP_PREFIX,
                sizeof(MCP_STRATEGY_LSP_PREFIX) - MCP_JSON_CHARACTER_STEP) == 0) {
        return "lsp";
    }
    if (strncmp(strategy, MCP_STRATEGY_PHP_PREFIX,
                sizeof(MCP_STRATEGY_PHP_PREFIX) - MCP_JSON_CHARACTER_STEP) == 0 ||
        strncmp(strategy, MCP_STRATEGY_PERL_PREFIX,
                sizeof(MCP_STRATEGY_PERL_PREFIX) - MCP_JSON_CHARACTER_STEP) == 0) {
        return "language_rule";
    }
    /* Everything else is a name/shape heuristic: callee_suffix,
     * field_type_hint, service_pattern, fastapi_depends, unique_name, ... */
    return "heuristic";
}

/* Find the resolution evidence on the edge that leads to the given hop node —
 * the same endpoint-matching rule as bfs_edge_args_for_hop (target for an
 * outbound trace, source for inbound, so both directions surface it).
 *
 * Reads only from tr->edges, and callers pass the PAGINATED view, so evidence
 * is emitted for the rows on this page and nothing else.
 *
 * Returns false when the edge carries no strategy (non-CALLS edges do not). */
static bool bfs_edge_evidence_for_hop(cbm_traverse_result_t *tr, int64_t hop_node_id,
                                      const char **class_out, double *confidence_out) {
    for (int e = 0; e < tr->edge_count; e++) {
        if (tr->edges[e].target_id != hop_node_id && tr->edges[e].source_id != hop_node_id) {
            continue;
        }
        const char *pj = tr->edges[e].properties_json;
        if (!pj) {
            continue;
        }
        const char *key = strstr(pj, MCP_STRATEGY_JSON_KEY);
        if (!key) {
            continue;
        }
        const char *open =
            strchr(key + sizeof(MCP_STRATEGY_JSON_KEY) - MCP_JSON_CHARACTER_STEP, '"');
        if (!open) {
            continue;
        }
        open += MCP_JSON_CHARACTER_STEP;
        const char *close = strchr(open, '"');
        if (!close || close == open) {
            continue;
        }
        char raw[CBM_SZ_64];
        size_t len = (size_t)(close - open);
        if (len >= sizeof(raw)) {
            len = sizeof(raw) - MCP_STRING_TERMINATOR_BYTES;
        }
        memcpy(raw, open, len);
        raw[len] = '\0';
        const char *cls = cbm_mcp_edge_strategy_class(raw);
        if (!cls) {
            continue;
        }
        *class_out = cls;
        /* Confidence rides on the same edge; absent is reported as -1 so a
         * genuine 0.0 stays distinguishable from "not recorded". */
        *confidence_out = MCP_EDGE_CONFIDENCE_UNRECORDED;
        const char *conf = strstr(pj, "\"confidence\"");
        if (conf) {
            const char *colon = strchr(conf, ':');
            if (colon) {
                *confidence_out = strtod(colon + MCP_JSON_CHARACTER_STEP, NULL);
            }
        }
        return true;
    }
    return false;
}

/* TOON table for one trace direction: callees[N]{qn,hop,...} with optional
 * risk / test / args columns. `name` is omitted (it is the qn's last
 * segment); the per-item JSON key envelope was 84% of the legacy payload. */
static void bfs_to_toon_table(cbm_sb_t *sb, const char *key, cbm_traverse_result_t *tr,
                              bool risk_labels, bool include_tests, bool data_flow) {
    int visible = 0;
    for (int i = 0; i < tr->visited_count; i++) {
        if (!include_tests && is_test_file(tr->visited[i].node.file_path)) {
            continue;
        }
        visible++;
    }
    const char *cols[MCP_BFS_TOON_MAX_COLUMN_COUNT] = {"qn", "hop"};
    int ncols = MCP_BFS_TOON_CORE_COLUMN_COUNT;
    if (risk_labels) {
        cols[ncols++] = "risk";
    }
    if (include_tests) {
        cols[ncols++] = "test";
    }
    if (data_flow) {
        cols[ncols++] = "args";
    }
    cbm_tree_table_header(sb, key, visible, cols, ncols);
    for (int i = 0; i < tr->visited_count; i++) {
        const char *fp = tr->visited[i].node.file_path;
        bool test = is_test_file(fp);
        if (!include_tests && test) {
            continue;
        }
        cbm_tree_row_begin(sb);
        cbm_tree_cell_str(sb, tr->visited[i].node.qualified_name, true);
        cbm_tree_cell_int(sb, tr->visited[i].hop, false);
        if (risk_labels) {
            cbm_tree_cell_str(sb, cbm_risk_label(cbm_hop_to_risk(tr->visited[i].hop)), false);
        }
        if (include_tests) {
            cbm_tree_cell_bool(sb, test, false);
        }
        if (data_flow) {
            size_t alen = 0;
            const char *ea = bfs_edge_args_for_hop(tr, tr->visited[i].node.id, &alen);
            if (ea && alen > 0 && alen < CBM_SZ_1K) {
                char abuf[CBM_SZ_1K];
                memcpy(abuf, ea, alen);
                abuf[alen] = '\0';
                cbm_tree_cell_str(sb, abuf, false);
            } else {
                cbm_tree_cell_str(sb, "", false);
            }
        }
        cbm_tree_row_end(sb);
    }
}

static char *snippet_suggestions(const char *input, cbm_node_t *nodes, int count);

/* Rank a candidate for name resolution. The label tier (callable > class-like >
 * module/file) is the primary key; WITHIN a tier the larger definition by line
 * span wins. In practice the .c-over-.h and C-main-over-shell-main preferences
 * come primarily from span (the real definition has the larger body), since the
 * competing matches usually share a tier — no file extension is hardcoded.
 * Consequence: two same-tier candidates with equal span tie and are reported
 * ambiguous (see pick_resolved_node) rather than guessed. */
enum {
    RES_RANK_CALLABLE = 2,      /* Function / Method */
    RES_RANK_OTHER = 1,         /* Class / Struct / etc. */
    RES_RANK_MODULE = 0,        /* Module / File */
    RES_LABEL_WEIGHT = 1000000, /* label tier dominates span */
    RESOLUTION_UNIQUE_CANDIDATE_COUNT = 1,
    NODE_HOP_ORDER_LESS = -1,
    NODE_HOP_ORDER_GREATER = 1,
    BFS_COLLECTION_GROWTH_FACTOR = 2,
    BFS_COLLECTION_INITIAL_CAPACITY = 8,
    BFS_COLLECTION_SORT_MINIMUM_COUNT = 1,
    TRACE_CURSOR_GENERATION_CAPACITY = 96,
    TRACE_CURSOR_NUMBER_TEXT_CAPACITY = 64,
    TRACE_CURSOR_LEG_FIELD_BYTES = 2,
    TRACE_CURSOR_HEX_RADIX = 16,
    TRACE_CURSOR_BOOLEAN_TRUE = 1,
};

static const uint64_t TRACE_FNV1A_64_PRIME = UINT64_C(0x100000001b3);
static const uint64_t TRACE_FNV1A_64_OFFSET_BASIS = UINT64_C(0xcbf29ce484222325);
static const char TRACE_CURSOR_PREFIX[] = "c1.";
static long node_resolution_score(const cbm_node_t *n) {
    long label_rank = RES_RANK_MODULE;
    if (n->label) {
        if (strcmp(n->label, "Function") == 0 || strcmp(n->label, "Method") == 0) {
            label_rank = RES_RANK_CALLABLE;
        } else if (strcmp(n->label, "Module") != 0 && strcmp(n->label, "File") != 0) {
            label_rank = RES_RANK_OTHER;
        }
    }
    long span = (long)n->end_line - (long)n->start_line;
    if (span < 0) {
        span = 0;
    }
    return (label_rank * (long)RES_LABEL_WEIGHT) + span;
}

/* A "real" callable definition: a Function/Method node with a non-empty body
 * span (end_line > start_line). A body-less node (start_line == end_line) is an
 * ambient declaration / signature stub — e.g. a TypeScript `.d.ts` declaration
 * — which is a *fragment* of one logical symbol, not a distinct definition. The
 * distinction lets pick_resolved_node union a stub with its real implementation
 * (#546) while still treating two genuinely-different same-named functions as
 * ambiguous rather than conflating their caller sets. */
static bool node_is_real_callable_def(const cbm_node_t *n) {
    if (!n->label) {
        return false;
    }
    if (strcmp(n->label, "Function") != 0 && strcmp(n->label, "Method") != 0) {
        return false;
    }
    return (long)n->end_line - (long)n->start_line > 0;
}

/* Pick the best-resolving node among name matches. Sets *ambiguous when the
 * matches can't be reduced to one logical symbol, so resolution never silently
 * traces (or conflates) the wrong same-named node:
 *   1. the top score is shared by >1 candidate (a genuine rank/span tie), or
 *   2. two or more *real* callable definitions share the name — distinct
 *      implementations, not a definition plus its body-less stub(s).
 * Rule 2 completes rule 1: without it, two same-named functions whose bodies
 * differ in length score differently, dodge the tie, and get their caller sets
 * unioned by bfs_union_same_name (#546) into one confidently-conflated answer.
 * Body-less .d.ts stubs still union with their implementation (#650). */
static int pick_resolved_node(const cbm_node_t *nodes, int count, bool *ambiguous) {
    *ambiguous = false;
    if (count <= RESOLUTION_UNIQUE_CANDIDATE_COUNT) {
        return 0;
    }
    int best = 0;
    long best_score = node_resolution_score(&nodes[0]);
    for (int i = RESOLUTION_UNIQUE_CANDIDATE_COUNT; i < count; i++) {
        long s = node_resolution_score(&nodes[i]);
        if (s > best_score) {
            best_score = s;
            best = i;
        }
    }
    int top_count = 0;
    int real_def_count = 0;
    for (int i = 0; i < count; i++) {
        if (node_resolution_score(&nodes[i]) == best_score) {
            top_count++;
        }
        if (node_is_real_callable_def(&nodes[i])) {
            real_def_count++;
        }
    }
    if (real_def_count > RESOLUTION_UNIQUE_CANDIDATE_COUNT) {
        *ambiguous = true;
    }
    if (top_count > RESOLUTION_UNIQUE_CANDIDATE_COUNT) {
        *ambiguous = true;
    }
    return best;
}

static int node_hop_cmp_hop_id(const void *pa, const void *pb) {
    const cbm_node_hop_t *a = (const cbm_node_hop_t *)pa;
    const cbm_node_hop_t *b = (const cbm_node_hop_t *)pb;
    if (a->hop != b->hop) {
        return a->hop < b->hop ? NODE_HOP_ORDER_LESS : NODE_HOP_ORDER_GREATER;
    }
    if (a->node.id != b->node.id) {
        return a->node.id < b->node.id ? NODE_HOP_ORDER_LESS : NODE_HOP_ORDER_GREATER;
    }
    return 0;
}

enum { BFS_UNION_INDEX_NOT_FOUND = -1 };

static int bfs_visited_index_by_id(const cbm_traverse_result_t *result, int64_t node_id) {
    for (int index = 0; index < result->visited_count; index++) {
        if (result->visited[index].node.id == node_id) {
            return index;
        }
    }
    return BFS_UNION_INDEX_NOT_FOUND;
}

static bool bfs_edge_exists(const cbm_traverse_result_t *result, const cbm_edge_info_t *candidate) {
    for (int index = 0; index < result->edge_count; index++) {
        const cbm_edge_info_t *existing = &result->edges[index];
        if (existing->source_id == candidate->source_id &&
            existing->target_id == candidate->target_id && existing->type && candidate->type &&
            strcmp(existing->type, candidate->type) == 0) {
            return true;
        }
    }
    return false;
}

static size_t bfs_next_capacity(size_t capacity) {
    return capacity ? capacity * BFS_COLLECTION_GROWTH_FACTOR : BFS_COLLECTION_INITIAL_CAPACITY;
}

static void bfs_union_visited(cbm_traverse_result_t *out, cbm_traverse_result_t *incoming,
                              size_t *capacity_io) {
    for (int index = 0; index < incoming->visited_count; index++) {
        cbm_node_hop_t *candidate = &incoming->visited[index];
        int existing_index = bfs_visited_index_by_id(out, candidate->node.id);
        if (existing_index != BFS_UNION_INDEX_NOT_FOUND) {
            /* Merging multiple seed traversals preserves the minimum distance
             * used by risk labels and pagination watermarks. */
            if (candidate->hop < out->visited[existing_index].hop) {
                out->visited[existing_index].hop = candidate->hop;
            }
            continue;
        }
        if ((size_t)out->visited_count >= *capacity_io) {
            *capacity_io = bfs_next_capacity(*capacity_io);
            out->visited =
                cbm_realloc_or_abort(out->visited, *capacity_io * sizeof(cbm_node_hop_t));
        }
        out->visited[out->visited_count++] = *candidate;
        memset(candidate, 0, sizeof(*candidate));
    }
}

static void bfs_union_edges(cbm_traverse_result_t *out, cbm_traverse_result_t *incoming,
                            size_t *capacity_io) {
    for (int index = 0; index < incoming->edge_count; index++) {
        cbm_edge_info_t *candidate = &incoming->edges[index];
        /* Overlapping seed neighborhoods can reach the same typed edge. */
        if (bfs_edge_exists(out, candidate)) {
            continue;
        }
        if ((size_t)out->edge_count >= *capacity_io) {
            *capacity_io = bfs_next_capacity(*capacity_io);
            out->edges = cbm_realloc_or_abort(out->edges, *capacity_io * sizeof(cbm_edge_info_t));
        }
        out->edges[out->edge_count++] = *candidate;
        memset(candidate, 0, sizeof(*candidate));
    }
}

/* BFS from EVERY node sharing the resolved name and merge the results, so the
 * caller/callee set is complete even when one logical symbol is represented by
 * more than one graph node — e.g. a real .ts implementation plus an ambient
 * .d.ts stub, whose inbound CALLS edges are otherwise split across the two
 * nodes and silently truncated by tracing only one (#546). visited hops are
 * deduped by node id; edges are concatenated. Ownership of all heap fields
 * transfers into *out, freed by cbm_store_traverse_free. */
static void bfs_union_same_name(cbm_store_t *store, const cbm_node_t *nodes, int node_count,
                                const char *direction, const char **edge_types, int edge_type_count,
                                int depth, int limit, cbm_traverse_result_t *out) {
    memset(out, 0, sizeof(*out));
    size_t vcap = 0;
    size_t ecap = 0;
    for (int k = 0; k < node_count; k++) {
        cbm_traverse_result_t tr = {0};
        cbm_store_bfs(store, nodes[k].id, direction, edge_types, edge_type_count, depth, limit,
                      &tr);
        bfs_union_visited(out, &tr, &vcap);
        bfs_union_edges(out, &tr, &ecap);
        cbm_store_traverse_free(&tr); /* frees only the un-moved (root + dup) fields */
    }
    /* Canonical (hop, id) order — a pure function of the graph, independent of
     * seed iteration order; required for deterministic output and watermarks. */
    if (out->visited_count > BFS_COLLECTION_SORT_MINIMUM_COUNT) {
        qsort(out->visited, (size_t)out->visited_count, sizeof(cbm_node_hop_t),
              node_hop_cmp_hop_id);
    }
}

/* ── Pagination cursors (stateless, exactly-once) ────────────────────
 * Token: "c1.<leg>.<generation>.<qhash>.<hop>.<id>" — version, trace leg
 * (o=callees, i=callers), the store generation (per-DB uid + mutation
 * counter), an FNV-1a-64 hash of the canonical query params, and the
 * (hop, node_id) watermark of the last emitted row in canonical order.
 * Stateless by design: the server re-traverses (the recursive CTE pays the
 * full reachable-set cost regardless of LIMIT, so a page costs what one
 * call costs today) and skips to the watermark. The generation stamp turns
 * every post-reindex cursor into a loud, actionable error — node ids are
 * never reused across rebuilds, so silently resuming would be wrong. */

static uint64_t cursor_fnv1a64(const char *s, uint64_t h) {
    while (s && *s) {
        h ^= (uint64_t)(unsigned char)*s++;
        h *= TRACE_FNV1A_64_PRIME;
    }
    return h;
}

typedef struct {
    char leg;                                          /* 'o' callees, 'i' callers */
    char generation[TRACE_CURSOR_GENERATION_CAPACITY]; /* store generation at mint time */
    uint64_t qhash;                                    /* canonical-params hash */
    int hop;                                           /* watermark: last emitted row */
    int64_t node_id;
} trace_cursor_t;

/* Hash the params that define the traversal identity. A cursor replayed with
 * different params must fail loudly, never silently mis-skip. */
static uint64_t trace_params_hash(const char *project, const char *func_name, const char *direction,
                                  const char *mode, int depth, bool include_tests, int limit) {
    uint64_t h = TRACE_FNV1A_64_OFFSET_BASIS;
    h = cursor_fnv1a64(project ? project : "", h);
    h = cursor_fnv1a64("|", h);
    h = cursor_fnv1a64(func_name ? func_name : "", h);
    h = cursor_fnv1a64("|", h);
    h = cursor_fnv1a64(direction ? direction : "", h);
    h = cursor_fnv1a64("|", h);
    h = cursor_fnv1a64(mode ? mode : "", h);
    char nums[TRACE_CURSOR_NUMBER_TEXT_CAPACITY];
    snprintf(nums, sizeof(nums), "|%d|%d|%d", depth, include_tests ? TRACE_CURSOR_BOOLEAN_TRUE : 0,
             limit);
    h = cursor_fnv1a64(nums, h);
    return h;
}

static void trace_cursor_encode(const trace_cursor_t *c, char *buf, size_t bufsz) {
    snprintf(buf, bufsz, "c1.%c.%s.%016llx.%d.%lld", c->leg, c->generation,
             (unsigned long long)c->qhash, c->hop, (long long)c->node_id);
}

static bool trace_cursor_parse_numbers(const char *text, trace_cursor_t *out) {
    errno = 0;
    char *hash_end = NULL;
    unsigned long long query_hash = strtoull(text, &hash_end, TRACE_CURSOR_HEX_RADIX);
    if (errno != 0 || hash_end == text || *hash_end != '.') {
        return false;
    }
    errno = 0;
    char *hop_end = NULL;
    long hop = strtol(hash_end + MCP_STRING_TERMINATOR_BYTES, &hop_end, MCP_DECIMAL_RADIX);
    if (errno != 0 || hop_end == hash_end + MCP_STRING_TERMINATOR_BYTES || *hop_end != '.' ||
        hop < INT_MIN || hop > INT_MAX) {
        return false;
    }
    errno = 0;
    char *node_end = NULL;
    long long node_id =
        strtoll(hop_end + MCP_STRING_TERMINATOR_BYTES, &node_end, MCP_DECIMAL_RADIX);
    if (errno != 0 || node_end == hop_end + MCP_STRING_TERMINATOR_BYTES || *node_end != '\0') {
        return false;
    }
    out->qhash = query_hash;
    out->hop = (int)hop;
    out->node_id = node_id;
    return true;
}

/* Decode + validate. Returns NULL on success, else a static teaching error. */
static const char *trace_cursor_decode(const char *token, const char *current_generation,
                                       uint64_t expected_qhash, trace_cursor_t *out) {
    memset(out, 0, sizeof(*out));
    if (!token || strncmp(token, TRACE_CURSOR_PREFIX,
                          sizeof(TRACE_CURSOR_PREFIX) - MCP_STRING_TERMINATOR_BYTES) != 0) {
        return "invalid_cursor: unrecognized token — re-run the original query without 'cursor'";
    }
    const char *p = token + sizeof(TRACE_CURSOR_PREFIX) - MCP_STRING_TERMINATOR_BYTES;
    if (*p != 'o' && *p != 'i') {
        return "invalid_cursor: unrecognized token — re-run the original query without 'cursor'";
    }
    out->leg = *p;
    p += TRACE_CURSOR_LEG_FIELD_BYTES; /* leg + '.' */
    const char *gen_end = strchr(p, '.');
    if (!gen_end || (size_t)(gen_end - p) >= sizeof(out->generation)) {
        return "invalid_cursor: unrecognized token — re-run the original query without 'cursor'";
    }
    memcpy(out->generation, p, (size_t)(gen_end - p));
    out->generation[gen_end - p] = '\0';
    if (!trace_cursor_parse_numbers(gen_end + MCP_STRING_TERMINATOR_BYTES, out)) {
        return "invalid_cursor: unrecognized token — re-run the original query without 'cursor'";
    }
    if (out->qhash != expected_qhash) {
        return "cursor_params_mismatch: this cursor was issued for different arguments — "
               "pass the cursor back with ALL other arguments identical";
    }
    if (strcmp(out->generation, current_generation) != 0) {
        return "stale_cursor: the project was reindexed since this cursor was issued — "
               "re-run the original query without 'cursor' (node identities changed)";
    }
    return NULL;
}

/* Slice a canonically-ordered traversal at the watermark: index of the first
 * row strictly AFTER (hop, id). */
static int trace_watermark_index(const cbm_traverse_result_t *tr, int hop, int64_t node_id) {
    for (int i = 0; i < tr->visited_count; i++) {
        if (tr->visited[i].hop > hop ||
            (tr->visited[i].hop == hop && tr->visited[i].node.id > node_id)) {
            return i;
        }
    }
    return tr->visited_count;
}

enum {
    BFS_TREE_QN_SEPARATOR_BYTES = 1,
    BFS_TREE_SORT_MINIMUM_COUNT = 1,
};

static bool bfs_tree_skip_visited(const cbm_node_hop_t *visited, bool include_tests) {
    return !include_tests && is_test_file(visited->node.file_path);
}

static const char *bfs_tree_qualified_name(const cbm_node_hop_t *visited) {
    return visited->node.qualified_name ? visited->node.qualified_name : "";
}

static size_t bfs_tree_prefix_length(const char *qualified_name, size_t group_capacity) {
    size_t prefix_length = sg_qn_prefix_len(qualified_name);
    return prefix_length < group_capacity ? prefix_length : 0;
}

static const char *bfs_tree_local_name(const char *qualified_name, size_t prefix_length) {
    return prefix_length ? qualified_name + prefix_length + BFS_TREE_QN_SEPARATOR_BYTES
                         : qualified_name;
}

typedef struct {
    char name[CBM_SZ_1K];
    yyjson_mut_val *rows;
    bool initialized;
} bfs_tree_json_group_t;

static bool bfs_tree_group_matches(const char *current_group, const char *qualified_name,
                                   size_t prefix_length) {
    return strncmp(current_group, qualified_name, prefix_length) == 0 &&
           current_group[prefix_length] == '\0';
}

static yyjson_mut_val *bfs_tree_json_group_rows(yyjson_mut_doc *doc, yyjson_mut_val *groups,
                                                bfs_tree_json_group_t *group,
                                                const char *qualified_name, size_t prefix_length) {
    if (group->initialized && bfs_tree_group_matches(group->name, qualified_name, prefix_length)) {
        return group->rows;
    }
    snprintf(group->name, sizeof(group->name), "%.*s", (int)prefix_length, qualified_name);
    group->initialized = true;
    yyjson_mut_val *next_group = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, next_group, "qn_prefix", group->name);
    group->rows = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, next_group, "rows", group->rows);
    yyjson_mut_arr_add_val(groups, next_group);
    return group->rows;
}

static void bfs_tree_json_add_columns(yyjson_mut_doc *doc, yyjson_mut_val *leg, bool risk_labels,
                                      bool data_flow) {
    yyjson_mut_val *columns = yyjson_mut_arr(doc);
    yyjson_mut_arr_add_str(doc, columns, "name");
    yyjson_mut_arr_add_str(doc, columns, "hop");
    if (risk_labels) {
        yyjson_mut_arr_add_str(doc, columns, "risk");
    }
    if (data_flow) {
        yyjson_mut_arr_add_str(doc, columns, "args");
    }
    yyjson_mut_obj_add_val(doc, leg, "cols", columns);
}

static void bfs_tree_json_add_args(yyjson_mut_doc *doc, yyjson_mut_val *row,
                                   cbm_traverse_result_t *tr, int64_t node_id) {
    size_t arguments_length = 0;
    const char *arguments = bfs_edge_args_for_hop(tr, node_id, &arguments_length);
    yyjson_mut_val *arguments_json = arguments && arguments_length > 0
                                         ? yyjson_mut_rawn(doc, arguments, arguments_length)
                                         : NULL;
    if (arguments_json) {
        yyjson_mut_arr_add_val(row, arguments_json);
    } else {
        yyjson_mut_arr_add_str(doc, row, "");
    }
}

static void bfs_tree_json_add_row(yyjson_mut_doc *doc, yyjson_mut_val *rows,
                                  cbm_traverse_result_t *tr, const cbm_node_hop_t *visited,
                                  const char *qualified_name, size_t prefix_length,
                                  bool risk_labels, bool data_flow) {
    yyjson_mut_val *row = yyjson_mut_arr(doc);
    yyjson_mut_arr_add_strcpy(doc, row, bfs_tree_local_name(qualified_name, prefix_length));
    yyjson_mut_arr_add_int(doc, row, visited->hop);
    if (risk_labels) {
        yyjson_mut_arr_add_str(doc, row, cbm_risk_label(cbm_hop_to_risk(visited->hop)));
    }
    if (data_flow) {
        bfs_tree_json_add_args(doc, row, tr, visited->node.id);
    }
    yyjson_mut_arr_add_val(rows, row);
}

/* json-stringified tree for one trace leg: same grouped model as the text
 * output — {cols, groups:[{qn_prefix, rows:[[name,hop,...]]}]}. Optional
 * risk/args columns mirror the flags. */
static yyjson_mut_val *bfs_to_tree_json(yyjson_mut_doc *doc, cbm_traverse_result_t *tr,
                                        bool risk_labels, bool include_tests, bool data_flow) {
    yyjson_mut_val *leg = yyjson_mut_obj(doc);
    bfs_tree_json_add_columns(doc, leg, risk_labels, data_flow);
    yyjson_mut_val *groups = yyjson_mut_arr(doc);
    bfs_tree_json_group_t group = {0};
    for (int index = 0; index < tr->visited_count; index++) {
        const cbm_node_hop_t *visited = &tr->visited[index];
        if (bfs_tree_skip_visited(visited, include_tests)) {
            continue;
        }
        const char *qualified_name = bfs_tree_qualified_name(visited);
        size_t prefix_length = bfs_tree_prefix_length(qualified_name, sizeof(group.name));
        yyjson_mut_val *rows =
            bfs_tree_json_group_rows(doc, groups, &group, qualified_name, prefix_length);
        bfs_tree_json_add_row(doc, rows, tr, visited, qualified_name, prefix_length, risk_labels,
                              data_flow);
    }
    yyjson_mut_obj_add_val(doc, leg, "groups", groups);
    return leg;
}

/* Tree-format trace leg: rows grouped by qn-prefix (printed once), each row
 * `name hop` — same data as the TOON table, prefix-factored. Test-file rows
 * honor include_tests exactly like bfs_to_toon_table. Rows arrive in
 * canonical (hop,id) order; grouping re-sorts by (prefix, hop, id) so
 * same-module rows are adjacent (Lost-in-Distance) while hop stays visible. */
static int tree_hop_cmp_qn(const void *pa, const void *pb) {
    const cbm_node_hop_t *a = (const cbm_node_hop_t *)pa;
    const cbm_node_hop_t *b = (const cbm_node_hop_t *)pb;
    const char *qa = a->node.qualified_name;
    const char *qb = b->node.qualified_name;
    int c = strcmp(qa, qb);
    if (c != 0) {
        return c;
    }
    return a->hop - b->hop;
}

static int bfs_tree_visible_count(const cbm_traverse_result_t *tr, bool include_tests) {
    int visible = 0;
    for (int index = 0; index < tr->visited_count; index++) {
        if (!bfs_tree_skip_visited(&tr->visited[index], include_tests)) {
            visible++;
        }
    }
    return visible;
}

static void bfs_tree_table_add_header(cbm_sb_t *output, const char *key, int visible,
                                      bool include_evidence) {
    char buffer[CBM_SZ_256];
    const char *description =
        include_evidence ? "rows: name hop strategy confidence; qn = group prefix + \".\" + name"
                         : "rows: name hop; qn = group prefix + \".\" + name";
    snprintf(buffer, sizeof(buffer), "%s: %d  (%s)\n", key, visible, description);
    cbm_sb_append(output, buffer);
}

static void bfs_tree_sort_visited(cbm_traverse_result_t *tr) {
    if (tr->visited_count > BFS_TREE_SORT_MINIMUM_COUNT) {
        qsort(tr->visited, (size_t)tr->visited_count, sizeof(cbm_node_hop_t), tree_hop_cmp_qn);
    }
}

static void bfs_tree_table_add_row(cbm_sb_t *output, cbm_traverse_result_t *tr,
                                   const cbm_node_hop_t *visited, const char *qualified_name,
                                   size_t prefix_length, bool include_evidence) {
    char row[CBM_SZ_512];
    const char *local_name = bfs_tree_local_name(qualified_name, prefix_length);
    const char *evidence_class = NULL;
    double evidence_confidence = -1.0;
    bool has_evidence =
        include_evidence &&
        bfs_edge_evidence_for_hop(tr, visited->node.id, &evidence_class, &evidence_confidence);
    if (!include_evidence) {
        snprintf(row, sizeof(row), "  %s %d\n", local_name, visited->hop);
    } else if (!has_evidence) {
        snprintf(row, sizeof(row), "  %s %d - -\n", local_name, visited->hop);
    } else if (evidence_confidence >= 0.0) {
        snprintf(row, sizeof(row), "  %s %d %s %.2f\n", local_name, visited->hop, evidence_class,
                 evidence_confidence);
    } else {
        snprintf(row, sizeof(row), "  %s %d %s -\n", local_name, visited->hop, evidence_class);
    }
    cbm_sb_append(output, row);
}

static void bfs_tree_table_add_rows(cbm_sb_t *output, cbm_traverse_result_t *tr, bool include_tests,
                                    bool include_evidence) {
    char current_group[CBM_SZ_1K] = "";
    for (int index = 0; index < tr->visited_count; index++) {
        const cbm_node_hop_t *visited = &tr->visited[index];
        if (bfs_tree_skip_visited(visited, include_tests)) {
            continue;
        }
        const char *qualified_name = bfs_tree_qualified_name(visited);
        size_t prefix_length = bfs_tree_prefix_length(qualified_name, sizeof(current_group));
        if (!bfs_tree_group_matches(current_group, qualified_name, prefix_length)) {
            snprintf(current_group, sizeof(current_group), "%.*s", (int)prefix_length,
                     qualified_name);
            cbm_sb_append(output, current_group);
            cbm_sb_append(output, ":\n");
        }
        bfs_tree_table_add_row(output, tr, visited, qualified_name, prefix_length,
                               include_evidence);
    }
}

static void bfs_to_tree_table(cbm_sb_t *sb, const char *key, cbm_traverse_result_t *tr,
                              bool include_tests, bool include_evidence) {
    bfs_tree_table_add_header(sb, key, bfs_tree_visible_count(tr, include_tests), include_evidence);
    bfs_tree_sort_visited(tr);
    bfs_tree_table_add_rows(sb, tr, include_tests, include_evidence);
}

/* Clamp a client-supplied traversal depth to the MCP ceiling (cbm_mcp_max_depth),
 * WARN-logging when it does so — never a silent truncation (#887). An unclamped
 * `depth` would drive the shared cbm_store_bfs to an arbitrary hop count. */
static int clamp_mcp_depth(int depth, const char *tool) {
    int cap = cbm_mcp_max_depth();
    if (depth > cap) {
        char req_buf[16];
        char cap_buf[16];
        snprintf(req_buf, sizeof(req_buf), "%d", depth);
        snprintf(cap_buf, sizeof(cap_buf), "%d", cap);
        cbm_log_warn("mcp.depth_capped", "tool", tool, "requested", req_buf, "cap", cap_buf);
        return cap;
    }
    return depth;
}

static char *handle_trace_call_path(cbm_mcp_server_t *srv, const char *args) {
    char *func_name = cbm_mcp_get_string_arg(args, "function_name");
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    char *direction = cbm_mcp_get_string_arg(args, "direction");
    char *mode = cbm_mcp_get_string_arg(args, "mode");
    char *param_name = cbm_mcp_get_string_arg(args, "parameter_name");
    int depth = cbm_mcp_get_int_arg(args, "depth", MCP_DEFAULT_DEPTH);
    depth = clamp_mcp_depth(depth, "trace_call_path");
    /* Per-direction node budget for the BFS working set. The old fixed
     * MCP_BFS_LIMIT silently truncated hub traces at 100 nodes with no
     * signal; now the limit is a documented parameter and hitting it emits
     * `truncated: true` (never a silent truncation — same policy as the
     * depth clamp, #887). */
    int trace_limit = cbm_mcp_get_int_arg(args, "limit", MCP_BFS_LIMIT);
    if (trace_limit < 1) {
        trace_limit = 1;
    }
    if (trace_limit > MCP_BFS_LIMIT_MAX) {
        trace_limit = MCP_BFS_LIMIT_MAX;
    }
    bool risk_labels = cbm_mcp_get_bool_arg(args, "risk_labels");
    bool include_tests = cbm_mcp_get_bool_arg(args, "include_tests");
    /* Off by default: two extra columns on every row is exactly the kind of
     * inflation the tree format exists to avoid. Opt in when you need to judge
     * whether an edge is trustworthy. */
    bool include_evidence = cbm_mcp_get_bool_arg(args, "include_evidence");

    if (!func_name) {
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        return cbm_mcp_text_result("function_name is required", true);
    }
    if (!store) {
        char *_err = build_project_list_error("project not found or not indexed");
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        return _res;
    }

    char *not_indexed = verify_project_indexed(store, project);
    if (not_indexed) {
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        return not_indexed;
    }

    /* Pagination: decode + validate the resume cursor (if any) against the
     * current store generation and the canonical params. Errors teach the
     * recovery action instead of silently restarting from page 1. */
    char generation[96];
    (void)cbm_store_generation(store, generation, sizeof(generation));
    char *cursor_arg = cbm_mcp_get_string_arg(args, "cursor");
    trace_cursor_t cur = {0};
    bool have_cursor = false;
    /* A "legacy" generation (pre-migration DB, e.g. opened read-only before
     * any reindex) offers NO staleness detection: "legacy" == "legacy" across
     * rebuilds, so a stale watermark would silently resume on wrong node ids.
     * Cursors are therefore never minted nor accepted under it. */
    bool gen_legacy = strcmp(generation, "legacy") == 0;
    if (gen_legacy && cursor_arg && cursor_arg[0]) {
        free(cursor_arg);
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        return cbm_mcp_text_result(
            "cursor_unsupported: this project's index predates generation tracking, so cursor "
            "staleness cannot be detected. Re-call with a higher 'limit' instead, or re-index "
            "the project to enable pagination.",
            true);
    }
    if (cursor_arg && cursor_arg[0]) {
        uint64_t qh =
            trace_params_hash(project, func_name, direction ? direction : "both", mode,
                              cbm_mcp_get_int_arg(args, "depth", MCP_DEFAULT_DEPTH), include_tests,
                              cbm_mcp_get_int_arg(args, "limit", MCP_BFS_LIMIT));
        const char *cerr = trace_cursor_decode(cursor_arg, generation, qh, &cur);
        if (cerr) {
            free(cursor_arg);
            free(func_name);
            free(project);
            free(direction);
            free(mode);
            free(param_name);
            return cbm_mcp_text_result(cerr, true);
        }
        have_cursor = true;
    }
    free(cursor_arg);
    if (!direction) {
        direction = heap_strdup("both");
    }
    /* Teaching error: an unknown direction used to silently produce an empty
     * trace (both leg flags false) — a field-eval agent burned four calls on
     * "callers"/"callees" before falling back to Cypher. */
    if (strcmp(direction, "inbound") != 0 && strcmp(direction, "outbound") != 0 &&
        strcmp(direction, "both") != 0) {
        char errbuf[CBM_SZ_256];
        snprintf(errbuf, sizeof(errbuf),
                 "invalid direction \"%s\" — use \"inbound\" (callers), \"outbound\" (callees), "
                 "or \"both\"",
                 direction);
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        return cbm_mcp_text_result(errbuf, true);
    }

    /* Find the node by name. If the bare-name lookup misses, fall back to
     * qualified_name so callers passing a fully-qualified identifier (which
     * the not-found hint actually recommends) hit the same path. The QN
     * lookup uses the same scan_node helper as the bare lookup, so the
     * shallow struct copy below transfers ownership of the strdup'd string
     * fields cleanly and cbm_store_free_nodes will free them. */
    cbm_node_t *nodes = NULL;
    int node_count = 0;
    cbm_store_find_nodes_by_name(store, project, func_name, &nodes, &node_count);

    if (node_count == 0) {
        cbm_node_t qn_node = {0};
        if (cbm_store_find_node_by_qn(store, project, func_name, &qn_node) == CBM_STORE_OK) {
            nodes = malloc(sizeof(cbm_node_t));
            if (nodes) {
                nodes[0] = qn_node;
                node_count = 1;
            } else {
                free_node_contents(&qn_node);
            }
        }
    }

    if (node_count == 0) {
        enum { HINT_BUF_SZ = 512 };
        char hint[HINT_BUF_SZ];
        snprintf(hint, sizeof(hint),
                 "{\"error\":\"function not found\",\"function_name\":\"%s\","
                 "\"hint\":\"Use search_graph(name_pattern=\\\".*%s.*\\\") to find the exact "
                 "name, then pass it to trace_path.\"}",
                 func_name, func_name);
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        cbm_store_free_nodes(nodes, 0);
        return cbm_mcp_text_result(hint, true);
    }

    /* Disambiguate same-named matches: prefer the real definition, and report
     * ambiguity (rather than silently tracing nodes[0]) on a genuine tie — e.g.
     * a C main() vs a same-named shell-script main(). */
    bool trace_ambiguous = false;
    int sel = pick_resolved_node(nodes, node_count, &trace_ambiguous);
    if (trace_ambiguous) {
        char *result = snippet_suggestions(func_name, nodes, node_count);
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        cbm_store_free_nodes(nodes, node_count);
        return result;
    }

    /* Response encoding: tree tables by default; format:"json" emits the
     * same grouped model as structured JSON. */
    char *trace_format = cbm_mcp_get_string_arg(args, "format");
    bool trace_legacy_json = trace_format && strcmp(trace_format, "json") == 0;
    free(trace_format);

    /* Edge types: explicit > mode-based > default */
    const char *edge_types[MCP_COL_16];
    int edge_type_count = 0;
    yyjson_doc *et_doc_keep = resolve_trace_edge_types(args, mode, edge_types, &edge_type_count);

    /* Run BFS for each requested direction.
     * IMPORTANT: emitters borrow node-string pointers — traversal results
     * must stay alive until after serialization. */
    bool do_outbound = strcmp(direction, "outbound") == 0 || strcmp(direction, "both") == 0;
    bool do_inbound = strcmp(direction, "inbound") == 0 || strcmp(direction, "both") == 0;

    cbm_traverse_result_t tr_out = {0};
    cbm_traverse_result_t tr_in = {0};

    bool data_flow = mode && strcmp(mode, "data_flow") == 0;

    (void)sel; /* union across all same-name nodes — see bfs_union_same_name (#546) */

    /* Traverse with the SAFETY ceiling (not the page size): the recursive CTE
     * enumerates the full depth-bounded reachable set regardless of LIMIT, so
     * materializing up to MCP_BFS_LIMIT_MAX rows costs the same traversal —
     * and gives exact totals plus the rows every later page needs. The page
     * size (trace_limit) only bounds what THIS response emits. */
    if (do_outbound) {
        bfs_union_same_name(store, nodes, node_count, "outbound", edge_types, edge_type_count,
                            depth, MCP_BFS_LIMIT_MAX, &tr_out);
    }
    if (do_inbound) {
        bfs_union_same_name(store, nodes, node_count, "inbound", edge_types, edge_type_count, depth,
                            MCP_BFS_LIMIT_MAX, &tr_in);
    }

    /* Page windows in canonical (hop,id) order. Legs drain in a fixed order
     * (callees, then callers); a resume cursor starts its leg at the row
     * after the watermark, and a page that finishes one leg with budget to
     * spare continues into the next. */
    int out_start = 0;
    int in_start = 0;
    if (have_cursor) {
        if (cur.leg == 'o') {
            out_start = trace_watermark_index(&tr_out, cur.hop, cur.node_id);
        } else {
            out_start = tr_out.visited_count; /* callees leg already drained */
            in_start = trace_watermark_index(&tr_in, cur.hop, cur.node_id);
        }
    }
    int budget = trace_limit;
    int out_len = 0;
    int in_len = 0;
    if (do_outbound) {
        out_len = tr_out.visited_count - out_start;
        if (out_len > budget) {
            out_len = budget;
        }
        budget -= out_len;
    }
    if (do_inbound) {
        in_len = tr_in.visited_count - in_start;
        if (in_len > budget) {
            in_len = budget;
        }
    }
    bool out_more = do_outbound && out_start + out_len < tr_out.visited_count;
    bool in_more = do_inbound && in_start + in_len < tr_in.visited_count;
    bool more_rows = out_more || in_more;
    char next_tok[192] = "";
    /* Never mint a cursor under a "legacy" generation (no staleness
     * detection); the truncated flag + raise-limit hint still fire below. */
    if (more_rows && !gen_legacy) {
        trace_cursor_t nc = {0};
        snprintf(nc.generation, sizeof(nc.generation), "%s", generation);
        nc.qhash = trace_params_hash(project, func_name, direction, mode, depth, include_tests,
                                     trace_limit);
        if (out_more) {
            nc.leg = 'o';
            nc.hop = tr_out.visited[out_start + out_len - 1].hop;
            nc.node_id = tr_out.visited[out_start + out_len - 1].node.id;
        } else {
            nc.leg = 'i';
            nc.hop = tr_in.visited[in_start + in_len - 1].hop;
            nc.node_id = tr_in.visited[in_start + in_len - 1].node.id;
        }
        trace_cursor_encode(&nc, next_tok, sizeof(next_tok));
    }

    /* Window views: visited offset + count; the full edges array stays
     * attached so data_flow args resolve for boundary nodes whose incoming
     * edge originated on an earlier page. */
    cbm_traverse_result_t view_out = tr_out;
    view_out.visited = tr_out.visited ? tr_out.visited + out_start : NULL;
    view_out.visited_count = out_len;
    cbm_traverse_result_t view_in = tr_in;
    view_in.visited = tr_in.visited ? tr_in.visited + in_start : NULL;
    view_in.visited_count = in_len;

    /* Totals must count what the caller can actually enumerate: when
     * include_tests=false the tables hide test-file rows, so raw
     * visited_count overstated the reachable set (a field-eval agent read
     * callers_total=175 against a handful of visible rows and distrusted
     * the tool). Count with the same filter the emitters apply. */
    int out_total = 0;
    for (int i = 0; i < tr_out.visited_count; i++) {
        if (include_tests || !is_test_file(tr_out.visited[i].node.file_path)) {
            out_total++;
        }
    }
    int in_total = 0;
    for (int i = 0; i < tr_in.visited_count; i++) {
        if (include_tests || !is_test_file(tr_in.visited[i].node.file_path)) {
            in_total++;
        }
    }

    char *json = NULL;
    if (!trace_legacy_json) {
        cbm_sb_t sb;
        cbm_sb_init(&sb);
        cbm_tree_scalar_str(&sb, "function", func_name);
        cbm_tree_scalar_str(&sb, "direction", direction);
        if (mode) {
            cbm_tree_scalar_str(&sb, "mode", mode);
        }
        /* Grouped tree is THE default; risk_labels/data_flow keep the flat
         * table (extra columns) in the same tree syntax. */
        bool flat_trace = risk_labels || data_flow;
        if (do_outbound) {
            cbm_tree_scalar_int(&sb, "callees_total", out_total);
            if (flat_trace) {
                bfs_to_toon_table(&sb, "callees", &view_out, risk_labels, include_tests, data_flow);
            } else {
                bfs_to_tree_table(&sb, "callees", &view_out, include_tests, include_evidence);
            }
        }
        if (do_inbound) {
            cbm_tree_scalar_int(&sb, "callers_total", in_total);
            if (flat_trace) {
                bfs_to_toon_table(&sb, "callers", &view_in, risk_labels, include_tests, data_flow);
            } else {
                bfs_to_tree_table(&sb, "callers", &view_in, include_tests, include_evidence);
            }
        }
        if (more_rows) {
            cbm_tree_scalar_bool(&sb, "truncated", true);
            if (next_tok[0]) {
                cbm_tree_scalar_str(&sb, "next", next_tok);
                cbm_tree_scalar_str(&sb, "hint",
                                    "more rows exist — re-call with cursor set to 'next' and ALL "
                                    "other arguments identical (no duplicates), or narrow with "
                                    "depth/edge_types");
            } else {
                cbm_tree_scalar_str(&sb, "hint",
                                    "more rows exist — re-call with a higher 'limit' (cursors "
                                    "unavailable: index predates generation tracking)");
            }
        }
        json = cbm_sb_finish(&sb);
    } else {
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
        yyjson_mut_val *root = yyjson_mut_obj(doc);
        yyjson_mut_doc_set_root(doc, root);

        yyjson_mut_obj_add_str(doc, root, "function", func_name);
        yyjson_mut_obj_add_str(doc, root, "direction", direction);
        if (mode) {
            yyjson_mut_obj_add_str(doc, root, "mode", mode);
        }
        if (do_outbound) {
            yyjson_mut_obj_add_int(doc, root, "callees_total", out_total);
            yyjson_mut_obj_add_val(
                doc, root, "callees",
                bfs_to_tree_json(doc, &view_out, risk_labels, include_tests, data_flow));
        }
        if (do_inbound) {
            yyjson_mut_obj_add_int(doc, root, "callers_total", in_total);
            yyjson_mut_obj_add_val(
                doc, root, "callers",
                bfs_to_tree_json(doc, &view_in, risk_labels, include_tests, data_flow));
        }
        if (more_rows) {
            yyjson_mut_obj_add_bool(doc, root, "truncated", true);
            if (next_tok[0]) {
                yyjson_mut_obj_add_strcpy(doc, root, "next_cursor", next_tok);
            }
        }
        /* Serialize BEFORE freeing traversal results (yyjson borrows strings) */
        json = yy_doc_to_str(doc);
        yyjson_mut_doc_free(doc);
    }

    /* Now safe to free traversal data */
    if (do_outbound) {
        cbm_store_traverse_free(&tr_out);
    }
    if (do_inbound) {
        cbm_store_traverse_free(&tr_in);
    }

    cbm_store_free_nodes(nodes, node_count);
    free(func_name);
    free(project);
    free(direction);
    free(mode);
    free(param_name);
    if (et_doc_keep) {
        yyjson_doc_free(et_doc_keep);
    }

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* ── Helper: free heap fields of a stack-allocated node ────────── */

static void free_node_contents(cbm_node_t *n) {
    safe_str_free(&n->project);
    safe_str_free(&n->label);
    safe_str_free(&n->name);
    safe_str_free(&n->qualified_name);
    safe_str_free(&n->file_path);
    safe_str_free(&n->properties_json);
    memset(n, 0, sizeof(*n));
}

/* ── Helper: read lines [start, end] from a file ─────────────── */

static char *read_file_lines(const char *path, int start, int end) {
    FILE *fp = cbm_fopen(path, "r");
    if (!fp) {
        return NULL;
    }

    size_t cap = CBM_SZ_4K;
    char *buf = malloc(cap);
    size_t len = 0;
    buf[0] = '\0';

    char line[CBM_SZ_2K];
    int lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        if (lineno < start) {
            continue;
        }
        if (lineno > end) {
            break;
        }
        size_t ll = strlen(line);
        while (len + ll + SKIP_ONE > cap) {
            cap *= PAIR_LEN;
            buf = cbm_realloc_or_abort(buf, cap);
        }
        memcpy(buf + len, line, ll);
        len += ll;
        buf[len] = '\0';
    }

    (void)fclose(fp);
    if (len == 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* ── Helper: get project root_path from store ─────────────────── */

static char *project_root_from_store(cbm_store_t *store, const char *project) {
    if (!store || !project) {
        return NULL;
    }
    cbm_project_t proj = {0};
    if (cbm_store_get_project(store, project, &proj) != CBM_STORE_OK) {
        return NULL;
    }
    char *root = heap_strdup(proj.root_path);
    safe_str_free(&proj.name);
    safe_str_free(&proj.indexed_at);
    safe_str_free(&proj.root_path);
    return root;
}

static char *get_project_root(cbm_mcp_server_t *srv, const char *project) {
    return project_root_from_store(resolve_store(srv, project), project);
}

/* ── index_repository ─────────────────────────────────────────── */

static int cross_repo_project_key_compare(const void *left, const void *right) {
    const char *const *left_key = left;
    const char *const *right_key = right;
    return strcmp(*left_key, *right_key);
}

static unsigned char cross_repo_project_lock_fold(unsigned char ch) {
    return ch >= 'A' && ch <= 'Z' ? (unsigned char)(ch + ('a' - 'A')) : ch;
}

/* Match daemon/project_lock.c's OS-key identity exactly: only ASCII A-Z folds.
 * The raw strcmp tie-break gives qsort a total, input-order-independent order
 * while keeping the caller's original project spelling as the lease value. */
static int cross_repo_project_lock_key_compare_values(const char *left, const char *right) {
    const unsigned char *left_cursor = (const unsigned char *)left;
    const unsigned char *right_cursor = (const unsigned char *)right;
    while (*left_cursor && *right_cursor) {
        unsigned char left_folded = cross_repo_project_lock_fold(*left_cursor);
        unsigned char right_folded = cross_repo_project_lock_fold(*right_cursor);
        if (left_folded != right_folded) {
            return left_folded < right_folded ? -1 : 1;
        }
        left_cursor++;
        right_cursor++;
    }
    if (*left_cursor != *right_cursor) {
        return *left_cursor ? 1 : -1;
    }
    return strcmp(left, right);
}

static int cross_repo_project_lock_key_compare(const void *left, const void *right) {
    const char *const *left_key = left;
    const char *const *right_key = right;
    return cross_repo_project_lock_key_compare_values(*left_key, *right_key);
}

static bool cross_repo_project_lock_keys_equivalent(const char *left, const char *right) {
    const unsigned char *left_cursor = (const unsigned char *)left;
    const unsigned char *right_cursor = (const unsigned char *)right;
    while (*left_cursor && *right_cursor) {
        if (cross_repo_project_lock_fold(*left_cursor) !=
            cross_repo_project_lock_fold(*right_cursor)) {
            return false;
        }
        left_cursor++;
        right_cursor++;
    }
    return *left_cursor == *right_cursor;
}

typedef struct {
    yyjson_doc *jdoc;
    const char **items;
    int count;
    bool all_projects;
} cross_repo_targets_t;

static void cross_repo_targets_dispose(cross_repo_targets_t *targets) {
    free(targets->items);
    yyjson_doc_free(targets->jdoc);
    *targets = (cross_repo_targets_t){0};
}

static const char *cross_repo_targets_parse(const char *args, cross_repo_targets_t *targets) {
    targets->jdoc = yyjson_read(args, strlen(args), 0);
    yyjson_val *root = targets->jdoc ? yyjson_doc_get_root(targets->jdoc) : NULL;
    yyjson_val *items = root ? yyjson_obj_get(root, "target_projects") : NULL;
    if (!items || !yyjson_is_arr(items) || yyjson_arr_size(items) == 0) {
        return "{\"error\":\"target_projects is required for cross-repo-intelligence mode. "
               "Use [\\\"*\\\"] for all projects. Run list_projects to see available.\"}";
    }
    size_t item_count = yyjson_arr_size(items);
    if (item_count > MCP_MAX_CROSS_REPO_TARGETS) {
        return "too many cross-repo target projects";
    }
    targets->count = (int)item_count;
    targets->items = malloc(item_count * sizeof(*targets->items));
    if (!targets->items) {
        return "failed to allocate cross-repo project leases";
    }
    size_t index;
    size_t max;
    yyjson_val *value;
    int parsed_count = 0;
    yyjson_arr_foreach(items, index, max, value) {
        const char *target = yyjson_is_str(value) ? yyjson_get_str(value) : NULL;
        if (!target || !target[0] || strlen(target) >= CBM_SZ_256 ||
            (strcmp(target, "*") != 0 && !cbm_validate_project_name(target))) {
            return "target_projects must contain valid project names or '*'";
        }
        targets->items[parsed_count++] = target;
        targets->all_projects = targets->all_projects || strcmp(target, "*") == 0;
    }
    if (parsed_count != targets->count) {
        return "target_projects must contain valid project names or '*'";
    }
    if (targets->all_projects && targets->count != 1) {
        return "target_projects wildcard '*' must be the only entry";
    }
    if (!targets->all_projects) {
        qsort(targets->items, (size_t)targets->count, sizeof(*targets->items),
              cross_repo_project_key_compare);
        int unique_count = 0;
        for (int i = 0; i < targets->count; i++) {
            if (unique_count == 0 ||
                strcmp(targets->items[i], targets->items[unique_count - 1]) != 0) {
                targets->items[unique_count++] = targets->items[i];
            }
        }
        targets->count = unique_count;
    }
    return NULL;
}

static const char *cross_repo_lease_keys_build(const char *project,
                                               const cross_repo_targets_t *targets,
                                               const char ***out_keys, int *out_count) {
    const char **lease_keys = malloc(((size_t)targets->count + 1U) * sizeof(*lease_keys));
    if (!lease_keys) {
        return "failed to allocate cross-repo project leases";
    }
    int lease_count = 0;
    if (targets->all_projects) {
        lease_keys[lease_count++] = "*";
    } else {
        lease_keys[lease_count++] = project;
        for (int i = 0; i < targets->count; i++) {
            lease_keys[lease_count++] = targets->items[i];
        }
        qsort(lease_keys, (size_t)lease_count, sizeof(*lease_keys),
              cross_repo_project_lock_key_compare);
        int unique_count = 0;
        for (int i = 0; i < lease_count; i++) {
            if (unique_count == 0 || !cross_repo_project_lock_keys_equivalent(
                                         lease_keys[i], lease_keys[unique_count - 1])) {
                lease_keys[unique_count++] = lease_keys[i];
            }
        }
        lease_count = unique_count;
    }
    *out_keys = lease_keys;
    *out_count = lease_count;
    return NULL;
}

static bool cross_repo_leases_acquire(cbm_mcp_server_t *srv, const char *const *lease_keys,
                                      int lease_count) {
    int held_count = 0;
    while (held_count < lease_count && mcp_project_mutation_begin(srv, lease_keys[held_count])) {
        held_count++;
    }
    bool cancelled =
        atomic_load_explicit(&srv->pipeline_cancel_requested, memory_order_acquire) != 0;
    if (held_count == lease_count && !cancelled) {
        return true;
    }
    while (held_count > 0) {
        held_count--;
        mcp_project_mutation_end(srv, lease_keys[held_count]);
    }
    return false;
}

static void cross_repo_leases_release(cbm_mcp_server_t *srv, const char *const *lease_keys,
                                      int lease_count) {
    while (lease_count > 0) {
        lease_count--;
        mcp_project_mutation_end(srv, lease_keys[lease_count]);
    }
}

static char *cross_repo_result_response(const char *project, cbm_cross_repo_result_t result) {
    int total = result.http_edges + result.async_edges + result.channel_edges + result.grpc_edges +
                result.graphql_edges + result.trpc_edges;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "status", result.cancelled ? "cancelled" : "success");
    yyjson_mut_obj_add_str(doc, root, "mode", "cross-repo-intelligence");
    yyjson_mut_obj_add_strcpy(doc, root, "project", project);
    if (result.cancelled) {
        yyjson_mut_obj_add_bool(doc, root, "partial_results", result.partial_results);
        yyjson_mut_obj_add_str(
            doc, root, "message",
            result.partial_results
                ? "cross-repo operation cancelled with partial results; completed database "
                  "writes were retained"
                : "cross-repo operation cancelled before database writes");
    }
    yyjson_mut_obj_add_int(doc, root, "projects_scanned", result.projects_scanned);
    yyjson_mut_obj_add_int(doc, root, "cross_http_calls", result.http_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_async_calls", result.async_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_channel", result.channel_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_grpc_calls", result.grpc_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_graphql_calls", result.graphql_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_trpc_calls", result.trpc_edges);
    yyjson_mut_obj_add_int(doc, root, "total_cross_edges", total);
    yyjson_mut_obj_add_real(doc, root, "elapsed_ms", result.elapsed_ms);
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    char *out = cbm_mcp_text_result(json, result.cancelled);
    free(json);
    return out;
}

/* Handle mode="cross-repo-intelligence" — extract to reduce complexity. */
static char *handle_cross_repo_mode(cbm_mcp_server_t *srv, const char *repo_path,
                                    const char *name_override, const char *args) {
    if (name_override && name_override[0] && !cbm_validate_project_name(name_override)) {
        return cbm_mcp_text_result("invalid project name", true);
    }
    char *project = name_override && name_override[0] ? heap_strdup(name_override)
                                                      : cbm_project_name_from_path(repo_path);
    if (!project) {
        return cbm_mcp_text_result("cannot derive project name", true);
    }
    cross_repo_targets_t targets = {0};
    const char *error = cross_repo_targets_parse(args, &targets);
    if (error) {
        cross_repo_targets_dispose(&targets);
        free(project);
        return cbm_mcp_text_result(error, true);
    }
    const char **lease_keys = NULL;
    int lease_count = 0;
    error = cross_repo_lease_keys_build(project, &targets, &lease_keys, &lease_count);
    if (error) {
        cross_repo_targets_dispose(&targets);
        free(project);
        return cbm_mcp_text_result(error, true);
    }
    if (!cross_repo_leases_acquire(srv, lease_keys, lease_count)) {
        free(lease_keys);
        cross_repo_targets_dispose(&targets);
        free(project);
        return cbm_mcp_text_result("cross-repo operation cancelled or blocked by active indexing",
                                   true);
    }
    cbm_cross_repo_result_t result = cbm_cross_repo_match_cancellable(
        project, targets.items, targets.count, &srv->pipeline_cancel_requested);
    cross_repo_leases_release(srv, lease_keys, lease_count);
    free(lease_keys);
    cross_repo_targets_dispose(&targets);
    if (result.failed) {
        free(project);
        return cbm_mcp_text_result(
            "cross-repo source or target project is missing, invalid, or not indexed", true);
    }
    char *out = cross_repo_result_response(project, result);
    free(project);
    return out;
}

/* Bootstrap from artifact if no local DB exists for this project. */
static void try_artifact_bootstrap(const char *project_name, const char *repo_path) {
    char db_buf[CBM_SZ_1K];
    project_db_path(project_name, db_buf, sizeof(db_buf));
    if (cbm_file_size(db_buf) < 0 && cbm_artifact_exists(repo_path)) {
        cbm_log_info("index.artifact_bootstrap", "project", project_name);
        cbm_artifact_import(repo_path, db_buf);
    }
}

/* Cap on excluded dir paths listed in the response — keep it compact on large
 * repos (node_modules / vendor / etc. can produce many skip points). The full
 * count is still reported via "count" + "truncated". */
enum { INDEX_EXCLUDED_DIR_CAP = 5 }; /* examples only — see INDEX_SKIPPED_FILE_CAP note */

/* Attach a compact summary of directory subtrees skipped during discovery (#411).
 * Shape: "excluded": {"dirs": [up to 25 rel-paths], "count": <total>, "truncated": <bool>}.
 * No-op when nothing was excluded. excluded_dirs[] is borrowed (copied into doc). */
static void add_excluded_summary(yyjson_mut_doc *doc, yyjson_mut_val *root, char **excluded_dirs,
                                 int excluded_count) {
    if (!excluded_dirs || excluded_count <= 0) {
        return;
    }
    yyjson_mut_val *excluded = yyjson_mut_obj(doc);
    yyjson_mut_val *dirs = yyjson_mut_arr(doc);
    int shown = excluded_count < INDEX_EXCLUDED_DIR_CAP ? excluded_count : INDEX_EXCLUDED_DIR_CAP;
    for (int i = 0; i < shown; i++) {
        if (excluded_dirs[i]) {
            yyjson_mut_arr_add_strcpy(doc, dirs, excluded_dirs[i]);
        }
    }
    yyjson_mut_obj_add_val(doc, excluded, "dirs", dirs);
    yyjson_mut_obj_add_int(doc, excluded, "count", excluded_count);
    yyjson_mut_obj_add_bool(doc, excluded, "truncated", excluded_count > INDEX_EXCLUDED_DIR_CAP);
    yyjson_mut_obj_add_val(doc, root, "excluded", excluded);
}

/* Cap on per-file skips embedded in the JSON response — keep it compact on
 * large repos. The FULL, uncapped list always goes to the per-run logfile;
 * the JSON carries "count" + "truncated" so nothing is silently hidden. */
/* In-response coverage lists are EXAMPLES, not the record: the full uncapped
 * lists live in the per-run logfile (path in the same response) and are
 * queryable via index_status (scope_limit) / query_graph(graph="missed").
 * Five examples orient the agent; anything more duplicates the logfile into
 * every index response (53 KB observed on a large repo). */
enum { INDEX_SKIPPED_FILE_CAP = 5 };

/* Attach the by-design ignored-FILES summary (#963 "purposely not indexed").
 * Individual files dropped by ignore rules — deliberate, not failures; whole
 * excluded subtrees are reported separately via "excluded". Always emits
 * "not_indexed_files_count" (the uncapped total); the list itself is capped
 * like skipped[] and marked truncated when discovery hit its storage cap. */
static void add_not_indexed_files_summary(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                          cbm_pipeline_t *p) {
    cbm_ignored_file_t *ignored = NULL;
    int stored = 0;
    int total = 0;
    cbm_pipeline_get_ignored(p, &ignored, &stored, &total);
    yyjson_mut_obj_add_int(doc, root, "not_indexed_files_count", total);
    if (!ignored || stored <= 0) {
        return;
    }
    yyjson_mut_val *ni = yyjson_mut_obj(doc);
    yyjson_mut_val *files = yyjson_mut_arr(doc);
    int shown = stored < INDEX_SKIPPED_FILE_CAP ? stored : INDEX_SKIPPED_FILE_CAP;
    for (int i = 0; i < shown; i++) {
        yyjson_mut_val *fe = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_strcpy(doc, fe, "path", ignored[i].rel_path ? ignored[i].rel_path : "");
        yyjson_mut_obj_add_strcpy(doc, fe, "reason", ignored[i].reason ? ignored[i].reason : "");
        yyjson_mut_arr_add_val(files, fe);
    }
    yyjson_mut_obj_add_val(doc, ni, "files", files);
    yyjson_mut_obj_add_int(doc, ni, "count", total);
    yyjson_mut_obj_add_bool(doc, ni, "truncated", total > shown);
    yyjson_mut_obj_add_str(doc, ni, "note",
                           "Excluded by design (gitignore/.cbmignore/skip-lists); examples only — "
                           "full list in 'logfile'.");
    yyjson_mut_obj_add_val(doc, root, "not_indexed_files", ni);
}

/* True when a recorded per-file entry is the parse-partial coverage signal
 * (#963) rather than a genuine skip. Kept out of skipped[]/skipped_count so
 * the "skipped" contract (file NOT indexed) stays exact. */
static bool is_parse_partial(const cbm_file_error_t *e) {
    return e->phase && strcmp(e->phase, "parse_partial") == 0;
}

/* Attach a summary of per-file skips (Stage 2 / Track B). Always emits a
 * top-level "skipped_count" (0 on clean runs) so consumers can rely on it.
 * When there are skips, also emits:
 *   "skipped": {"files":[{path,reason,phase}..(<=50)], "count":N, "truncated":bool}
 * and, if a per-run logfile was written, "logfile": "<path>".
 * The run status stays "indexed" — a skipped file is the expected handled
 * outcome, not a failure. errs[] is borrowed (copied into doc) and may contain
 * parse_partial entries, which are filtered out here (reported separately by
 * add_parse_partial_summary). */
static void add_skipped_summary(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                const cbm_file_error_t *errs, int count, const char *logfile) {
    int skips = 0;
    for (int i = 0; i < count; i++) {
        if (!is_parse_partial(&errs[i])) {
            skips++;
        }
    }
    yyjson_mut_obj_add_int(doc, root, "skipped_count", skips);
    if (logfile && logfile[0]) {
        yyjson_mut_obj_add_strcpy(doc, root, "logfile", logfile);
    }
    if (!errs || skips <= 0) {
        return;
    }
    yyjson_mut_val *skipped = yyjson_mut_obj(doc);
    yyjson_mut_val *files = yyjson_mut_arr(doc);
    int shown = 0;
    for (int i = 0; i < count && shown < INDEX_SKIPPED_FILE_CAP; i++) {
        if (is_parse_partial(&errs[i])) {
            continue;
        }
        yyjson_mut_val *fe = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_strcpy(doc, fe, "path", errs[i].path ? errs[i].path : "");
        yyjson_mut_obj_add_strcpy(doc, fe, "reason", errs[i].reason ? errs[i].reason : "");
        yyjson_mut_obj_add_strcpy(doc, fe, "phase", errs[i].phase ? errs[i].phase : "");
        yyjson_mut_arr_add_val(files, fe);
        shown++;
    }
    yyjson_mut_obj_add_val(doc, skipped, "files", files);
    yyjson_mut_obj_add_int(doc, skipped, "count", skips);
    yyjson_mut_obj_add_bool(doc, skipped, "truncated", skips > INDEX_SKIPPED_FILE_CAP);
    yyjson_mut_obj_add_val(doc, root, "skipped", skipped);
}

static bool is_parse_partial_coverage_row(const cbm_coverage_row_t *row) {
    return row->kind && strcmp(row->kind, "parse_partial") == 0;
}

static int count_parse_partial_coverage_rows(const cbm_coverage_row_t *rows, int row_count) {
    int partials = 0;
    for (int index = 0; index < row_count; index++) {
        if (is_parse_partial_coverage_row(&rows[index])) {
            partials++;
        }
    }
    return partials;
}

static int count_parse_partial_errors(const cbm_file_error_t *errors, int error_count) {
    int partials = 0;
    for (int index = 0; index < error_count; index++) {
        if (is_parse_partial(&errors[index])) {
            partials++;
        }
    }
    return partials;
}

static void add_parse_partial_file(yyjson_mut_doc *doc, yyjson_mut_val *files, const char *path,
                                   const char *error_ranges) {
    yyjson_mut_val *file = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, file, "path", path ? path : "");
    yyjson_mut_obj_add_strcpy(doc, file, "error_ranges", error_ranges ? error_ranges : "");
    yyjson_mut_arr_add_val(files, file);
}

static void add_parse_partial_coverage_files(yyjson_mut_doc *doc, yyjson_mut_val *files,
                                             const cbm_coverage_row_t *rows, int row_count) {
    int shown = 0;
    for (int index = 0; index < row_count && shown < INDEX_SKIPPED_FILE_CAP; index++) {
        if (!is_parse_partial_coverage_row(&rows[index])) {
            continue;
        }
        add_parse_partial_file(doc, files, rows[index].rel_path, rows[index].detail);
        shown++;
    }
}

static void add_parse_partial_error_files(yyjson_mut_doc *doc, yyjson_mut_val *files,
                                          const cbm_file_error_t *errors, int error_count) {
    int shown = 0;
    for (int index = 0; index < error_count && shown < INDEX_SKIPPED_FILE_CAP; index++) {
        if (!is_parse_partial(&errors[index])) {
            continue;
        }
        add_parse_partial_file(doc, files, errors[index].path, errors[index].reason);
        shown++;
    }
}

static void add_parse_partial_details(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                      yyjson_mut_val *files, int partials) {
    yyjson_mut_val *summary = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, summary, "files", files);
    yyjson_mut_obj_add_int(doc, summary, "count", partials);
    yyjson_mut_obj_add_bool(doc, summary, "truncated", partials > INDEX_SKIPPED_FILE_CAP);
    yyjson_mut_obj_add_str(doc, summary, "note",
                           "Indexed, but constructs in these line ranges may be missing (best-"
                           "effort signal); examples only — full list via index_status or "
                           "'logfile'.");
    yyjson_mut_obj_add_val(doc, root, "parse_partial", summary);
}

/* Attach the best-effort parse-coverage summary (#963). Always emits a
 * top-level "parse_partial_count" (0 on clean runs). When files were flagged:
 *   "parse_partial": {"files":[{path,error_ranges}..(<=50)], "count":N,
 *                     "truncated":bool, "note":"..."}
 * These files WERE indexed — constructs inside the listed 1-based line ranges
 * are missing from the graph because tree-sitter could not parse them. The
 * note spells out the best-effort framing: absence from this list is NOT a
 * completeness guarantee. */
static void add_parse_partial_summary(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                      const cbm_file_error_t *errors, int error_count,
                                      cbm_store_t *store, const char *project) {
    cbm_coverage_row_t *rows = NULL;
    int row_count = 0;
    bool from_store = store && project &&
                      cbm_store_coverage_get(store, project, &rows, &row_count) == CBM_STORE_OK;
    int partials = from_store ? count_parse_partial_coverage_rows(rows, row_count)
                              : count_parse_partial_errors(errors, error_count);
    yyjson_mut_obj_add_int(doc, root, "parse_partial_count", partials);
    if (partials > 0) {
        yyjson_mut_val *files = yyjson_mut_arr(doc);
        if (from_store) {
            add_parse_partial_coverage_files(doc, files, rows, row_count);
        } else {
            add_parse_partial_error_files(doc, files, errors, error_count);
        }
        add_parse_partial_details(doc, root, files, partials);
    }
    cbm_store_free_coverage(rows, row_count);
}

static bool build_skip_logfile_path(const char *project, char *path, size_t path_size) {
    const char *override = getenv("CBM_INDEX_LOG");
    if (override && override[0]) {
        snprintf(path, path_size, "%s", override);
        return true;
    }
    const char *cache_directory = cbm_resolve_cache_dir();
    if (!cache_directory) {
        return false;
    }
    char log_directory[CBM_SZ_1K];
    snprintf(log_directory, sizeof(log_directory), "%s/logs", cache_directory);
    cbm_mkdir_p(log_directory, MCP_LOG_DIRECTORY_MODE);
    snprintf(path, path_size, "%s/%s-%lld.log", log_directory, project ? project : "index",
             (long long)time(NULL));
    return true;
}

static void write_skip_logfile_contents(FILE *file, const char *project,
                                        const cbm_file_error_t *errors, int error_count) {
    int partials = count_parse_partial_errors(errors, error_count);
    (void)fprintf(file, "# codebase-memory-mcp index coverage report\n");
    (void)fprintf(file, "# project=%s skipped=%d parse_partial=%d\n", project ? project : "",
                  error_count - partials, partials);
    (void)fprintf(file, "# columns: phase\treason\tpath\n");
    for (int index = 0; index < error_count; index++) {
        const cbm_file_error_t *error = &errors[index];
        (void)fprintf(file, "%s\t%s\t%s\n", error->phase ? error->phase : "",
                      error->reason ? error->reason : "", error->path ? error->path : "");
    }
}

static void copy_skip_logfile_path(char *out_path, size_t out_size, const char *path) {
    if (out_path && out_size) {
        snprintf(out_path, out_size, "%s", path);
    }
}

/* Write the FULL (uncapped) skip list to a per-run logfile — ONLY when >=1 file
 * was skipped (no logfile on a clean run). Location:
 *   $CBM_INDEX_LOG (override) else <cache_dir>/logs/<project>-<epoch>.log
 * Returns true and fills out_path on success. */
static bool write_skip_logfile(const char *project, const cbm_file_error_t *errors, int error_count,
                               char *out_path, size_t out_size) {
    if (!errors || error_count <= 0) {
        return false;
    }
    char path[CBM_SZ_1K];
    if (!build_skip_logfile_path(project, path, sizeof(path))) {
        return false;
    }
    FILE *f = cbm_fopen(path, "wb");
    if (!f) {
        cbm_log_warn("index.logfile_open_fail", "path", path);
        return false;
    }
    write_skip_logfile_contents(f, project, errors, error_count);
    (void)fclose(f);
    copy_skip_logfile_path(out_path, out_size, path);
    return true;
}

typedef struct {
    int expected_nodes;
    int expected_edges;
    int nodes;
    int edges;
    bool degraded;
} index_response_counts_t;

static void add_index_response_summaries(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                         char **excluded_dirs, int excluded_count,
                                         const cbm_file_error_t *file_errors, int file_error_count,
                                         const char *logfile, cbm_store_t *store,
                                         const char *project_name, cbm_pipeline_t *pipeline) {
    add_excluded_summary(doc, root, excluded_dirs, excluded_count);
    add_skipped_summary(doc, root, file_errors, file_error_count, logfile);
    add_parse_partial_summary(doc, root, file_errors, file_error_count, store, project_name);
    add_not_indexed_files_summary(doc, root, pipeline);
}

static index_response_counts_t index_response_counts(cbm_store_t *store, const char *project_name,
                                                     cbm_pipeline_t *pipeline) {
    index_response_counts_t counts = {.expected_nodes = -1, .expected_edges = -1};
    cbm_pipeline_get_committed_counts(pipeline, &counts.expected_nodes, &counts.expected_edges);
    const double ratio = cbm_dump_verify_min_ratio();
    const int min_floor = CBM_DUMP_VERIFY_MIN_FLOOR;
    if (!store) {
        counts.degraded = true;
        return counts;
    }
    counts.nodes = cbm_store_count_nodes(store, project_name);
    counts.edges = cbm_store_count_edges(store, project_name);
    if (counts.nodes < 0) {
        counts.degraded = true;
        counts.nodes = 0;
        counts.edges = counts.edges >= 0 ? counts.edges : 0;
        return counts;
    }
    if (!cbm_dump_verify_is_degraded(counts.expected_nodes, counts.nodes, ratio, min_floor)) {
        return counts;
    }
    (void)cbm_store_checkpoint(store);
    int refreshed_nodes = cbm_store_count_nodes(store, project_name);
    int refreshed_edges = cbm_store_count_edges(store, project_name);
    if (refreshed_nodes >= 0) {
        counts.nodes = refreshed_nodes;
    }
    if (refreshed_edges >= 0) {
        counts.edges = refreshed_edges;
    }
    counts.degraded =
        cbm_dump_verify_is_degraded(counts.expected_nodes, counts.nodes, ratio, min_floor);
    return counts;
}

static void add_index_counts(yyjson_mut_doc *doc, yyjson_mut_val *root,
                             const index_response_counts_t *counts) {
    yyjson_mut_obj_add_int(doc, root, "nodes", counts->nodes);
    yyjson_mut_obj_add_int(doc, root, "edges", counts->edges);
    if (counts->expected_nodes >= 0) {
        yyjson_mut_obj_add_int(doc, root, "expected_nodes", counts->expected_nodes);
        yyjson_mut_obj_add_int(doc, root, "expected_edges", counts->expected_edges);
    }
}

static void add_index_degraded_hint(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                    const index_response_counts_t *counts, bool store_exists) {
    if (counts->degraded) {
        if (!store_exists) {
            yyjson_mut_obj_add_str(doc, root, "hint",
                                   "Index database failed integrity check and was removed. "
                                   "Re-run index_repository(repo_path=...) to rebuild.");
            cbm_log_warn("dump.verify", "reason", "store_missing", "expected_nodes",
                         counts->expected_nodes >= 0 ? "set" : "unknown");
        } else {
            char exp_buf[MCP_FIELD_SIZE];
            char got_buf[MCP_FIELD_SIZE];
            snprintf(exp_buf, sizeof(exp_buf), "%d", counts->expected_nodes);
            snprintf(got_buf, sizeof(got_buf), "%d", counts->nodes);
            yyjson_mut_obj_add_str(
                doc, root, "hint",
                "Persisted far fewer nodes than indexed — likely durability loss from a "
                "hard-killed sibling process. Re-run index_repository(repo_path=...) to rebuild.");
            cbm_log_warn("dump.verify", "expected_nodes", exp_buf, "persisted_nodes", got_buf);
        }
    }
}

/* Build the success portion of the index_repository response.
 * Returns true when status should be "degraded" (#334 plausibility gate). */
static bool build_index_success_response(cbm_mcp_server_t *srv, yyjson_mut_doc *doc,
                                         yyjson_mut_val *root, const char *project_name,
                                         const char *repo_path, bool persistence, cbm_pipeline_t *p,
                                         char **excluded_dirs, int excluded_count,
                                         const cbm_file_error_t *file_errors, int file_error_count,
                                         const char *logfile) {
    cbm_store_t *store = resolve_store(srv, project_name);
    add_index_response_summaries(doc, root, excluded_dirs, excluded_count, file_errors,
                                 file_error_count, logfile, store, project_name, p);
    index_response_counts_t counts = index_response_counts(store, project_name, p);
    add_index_counts(doc, root, &counts);
    add_index_degraded_hint(doc, root, &counts, store != NULL);
    bool adr_exists = project_has_adr(store, project_name, repo_path);
    yyjson_mut_obj_add_bool(doc, root, "adr_present", adr_exists);
    if (!adr_exists && !counts.degraded) {
        yyjson_mut_obj_add_str(
            doc, root, "adr_hint",
            "Project indexed. Consider creating an Architecture Decision Record: "
            "explore the codebase with get_architecture(aspects=['all']), then use "
            "manage_adr(mode='update') to persist architectural insights across sessions.");
    }

    bool has_artifact = cbm_artifact_exists(repo_path);
    yyjson_mut_obj_add_bool(doc, root, "artifact_present", has_artifact);
    if (persistence && has_artifact) {
        yyjson_mut_obj_add_str(doc, root, "artifact_hint",
                               "Persistent artifact written to .codebase-memory/graph.db.zst. "
                               "Commit this file to share the index with teammates.");
    }

    return counts.degraded;
}

/* Build the response for a worker that crashed/hung/failed without producing a
 * result. The crash is already contained (this process survived); we report it
 * rather than dying. Precise skip-and-continue (quarantine the culprit, index the
 * rest) is layered on in the probe stage. */
static char *build_worker_failure_response(const char *args, cbm_proc_outcome_t outcome) {
    char *repo_path = cbm_mcp_get_string_arg(args, "repo_path");
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "status", "error");
    yyjson_mut_obj_add_str(doc, root, "outcome", cbm_proc_outcome_str(outcome));
    const char *hint = NULL;
    if (outcome == CBM_PROC_SPAWN_FAILED) {
        hint = "Indexing worker could not be started. Supervision is mandatory in a CBM "
               "host, so no in-process fallback was attempted.";
    } else if (outcome == CBM_PROC_HANG) {
        hint = "Indexing worker timed out (a file made no progress). The worker was "
               "terminated and the server survived. Re-run to retry.";
    } else if (outcome == CBM_PROC_CRASH) {
        hint = "Indexing worker crashed on a file. The crash was contained (the server "
               "survived). Re-run to retry; a future release isolates the culprit file.";
    } else if (outcome == CBM_PROC_CLEAN) {
        hint = "Indexing worker exited without a valid response. No in-process fallback "
               "was attempted.";
    } else {
        hint = "Indexing worker did not complete successfully. The failure was contained "
               "and no in-process fallback was attempted.";
    }
    yyjson_mut_obj_add_str(doc, root, "hint", hint);
    if (repo_path) {
        yyjson_mut_obj_add_strcpy(doc, root, "repo_path", repo_path);
    }
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(repo_path);
    char *result = cbm_mcp_text_result(json, true);
    free(json);
    return result;
}

static char *build_worker_unsafe_terminal_response(const char *args, cbm_proc_outcome_t outcome,
                                                   bool cancellation_requested) {
    char *repo_path = cbm_mcp_get_string_arg(args, "repo_path");
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "status", "error");
    yyjson_mut_obj_add_str(doc, root, "outcome", cbm_proc_outcome_str(outcome));
    yyjson_mut_obj_add_str(
        doc, root, "hint",
        cancellation_requested
            ? "Indexing worker was cancelled. No in-process retry was started."
            : "Indexing worker process-tree containment failed. No in-process retry was "
              "started; inspect daemon logs.");
    if (repo_path) {
        yyjson_mut_obj_add_strcpy(doc, root, "repo_path", repo_path);
    }
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(repo_path);
    char *response = cbm_mcp_text_result(json, true);
    free(json);
    return response;
}

/* Drop the cached store so the next query reopens whatever the worker wrote (each
 * worker is a fresh process that deletes + recreates the .db). NULL-safe: the
 * background watcher path (main.c) has no MCP server / cached store — the child
 * writes the DB and the parent only needs the return code, so there is nothing
 * to invalidate. */
static void invalidate_cached_store(cbm_mcp_server_t *srv) {
    if (!srv) {
        return;
    }
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
        srv->store = NULL;
    }
    free(srv->current_project);
    srv->current_project = NULL;
}

/* Resolve a per-supervisor-run temp path <cache_dir>/logs/.supervisor-<pid><suffix>
 * (falls back to the CWD if the cache dir is unresolvable). Used for the crash-
 * attribution marker and the quarantine list during the recovery re-run. */
static void supervisor_tmp_path(char *out, size_t out_sz, const char *suffix) {
    const char *cdir = cbm_resolve_cache_dir();
    if (cdir && cdir[0]) {
        char logdir[CBM_SZ_1K];
        snprintf(logdir, sizeof(logdir), "%s/logs", cdir);
        cbm_mkdir_p(logdir, 0755);
        snprintf(out, out_sz, "%s/.supervisor-%d%s", logdir, (int)getpid(), suffix);
    } else {
        snprintf(out, out_sz, ".supervisor-%d%s", (int)getpid(), suffix);
    }
}

/* Parse the worker's marker JOURNAL ("S <rel>" / "D <rel>" lines, one event
 * per line — see cbm_index_mark_start/done) into the crash/hang SUSPECT set:
 * files whose last event is an S with no closing D, i.e. the in-flight set
 * at kill time. Recovery runs are PARALLEL, so there are up to worker_count
 * suspects; a torn final line (no trailing newline) is discarded by design.
 * Returns a malloc'd array of malloc'd rel paths, OLDEST OPEN S FIRST (for a
 * hang, the oldest still-open file IS the stuck one). Caller frees via
 * supervisor_free_suspects. */
enum {
    SUPERVISOR_JOURNAL_EVENT_BYTES = 2,
    SUPERVISOR_JOURNAL_MIN_LINE_BYTES = 3,
    SUPERVISOR_INITIAL_SUSPECT_CAPACITY = 16,
    SUPERVISOR_SUSPECT_GROWTH_FACTOR = 2,
    SUPERVISOR_DEFAULT_RESTART_CAP = 100,
};

static int supervisor_restart_cap(void) {
    const char *value = getenv("CBM_INDEX_MAX_RESTARTS");
    if (!value || !value[0]) {
        return SUPERVISOR_DEFAULT_RESTART_CAP;
    }
    errno = 0;
    char *end = NULL;
    long parsed = strtol(value, &end, MCP_DECIMAL_RADIX);
    if (errno != 0 || end == value || *end != '\0' || parsed <= 0 || parsed > INT_MAX) {
        return SUPERVISOR_DEFAULT_RESTART_CAP;
    }
    return (int)parsed;
}

static int supervisor_open_path_index(char *const *paths, int count, const char *path) {
    for (int index = 0; index < count; index++) {
        if (strcmp(paths[index], path) == 0) {
            return index;
        }
    }
    return CBM_NOT_FOUND;
}

static bool supervisor_add_open_path(char ***paths, int *count, size_t *capacity,
                                     const char *path) {
    if (supervisor_open_path_index(*paths, *count, path) != CBM_NOT_FOUND) {
        return true;
    }
    if ((size_t)*count == *capacity) {
        size_t new_capacity = *capacity ? *capacity * SUPERVISOR_SUSPECT_GROWTH_FACTOR
                                        : SUPERVISOR_INITIAL_SUSPECT_CAPACITY;
        char **grown = realloc(*paths, new_capacity * sizeof(*grown));
        if (!grown) {
            return false;
        }
        *paths = grown;
        *capacity = new_capacity;
    }
    (*paths)[(*count)++] = cbm_strdup(path);
    return true;
}

static void supervisor_remove_open_path(char **paths, int *count, const char *path) {
    int index = supervisor_open_path_index(paths, *count, path);
    if (index == CBM_NOT_FOUND) {
        return;
    }
    free(paths[index]);
    memmove(&paths[index], &paths[index + 1], (size_t)(*count - index - 1) * sizeof(*paths));
    (*count)--;
}

static const char *supervisor_journal_path(char *line, char *event) {
    size_t length = strlen(line);
    if (length == 0 || line[length - 1] != '\n') {
        return NULL;
    }
    line[--length] = '\0';
    if (length > 0 && line[length - 1] == '\r') {
        line[--length] = '\0';
    }
    if (length < SUPERVISOR_JOURNAL_MIN_LINE_BYTES || (line[0] != 'S' && line[0] != 'D') ||
        line[1] != ' ') {
        return "";
    }
    *event = line[0];
    return line + SUPERVISOR_JOURNAL_EVENT_BYTES;
}

static char **supervisor_read_suspects(const char *path, int *out_n) {
    *out_n = 0;
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    char **open_paths = NULL;
    int open_n = 0;
    size_t open_cap = 0;
    char line[CBM_SZ_1K];
    while (fgets(line, sizeof(line), f)) {
        char event = '\0';
        const char *relative_path = supervisor_journal_path(line, &event);
        if (!relative_path) {
            break;
        }
        if (event == '\0') {
            continue;
        }
        if (event == 'S') {
            if (!supervisor_add_open_path(&open_paths, &open_n, &open_cap, relative_path)) {
                break;
            }
        } else {
            supervisor_remove_open_path(open_paths, &open_n, relative_path);
        }
    }
    (void)fclose(f);
    if (open_n == 0) {
        free(open_paths);
        return NULL;
    }
    *out_n = open_n;
    return open_paths;
}

static void supervisor_free_suspects(char **s, int n) {
    if (!s) {
        return;
    }
    for (int i = 0; i < n; i++) {
        free(s[i]);
    }
    free(s);
}

static bool supervisor_suspect_contains(char **s, int n, const char *rel) {
    for (int i = 0; i < n; i++) {
        if (s[i] && strcmp(s[i], rel) == 0) {
            return true;
        }
    }
    return false;
}

/* Append one quarantine entry "rel\tphase\n" (phase = "crash"|"hang") to the
 * quarantine list. The worker's loader parses this back and reports the skip's
 * phase in skipped[]; a bare "rel" line is still tolerated there (defaults crash). */
static bool supervisor_append_quarantine(const char *path, const char *rel, const char *phase) {
    FILE *f = cbm_fopen(path, "ab");
    if (!f) {
        return false;
    }
    (void)fprintf(f, "%s\t%s\n", rel, phase);
    (void)fclose(f);
    return true;
}

cbm_mcp_supervised_result_disposition_t cbm_mcp_supervised_result_disposition(
    int spawn_result, const cbm_index_worker_result_t *worker_result) {
    if (spawn_result != 0 || !worker_result || worker_result->outcome == CBM_PROC_SPAWN_FAILED) {
        return CBM_MCP_SUPERVISED_RESULT_FALLBACK;
    }
    if (worker_result->cancellation_requested || !worker_result->tree_quiesced ||
        worker_result->supervision_failed) {
        return CBM_MCP_SUPERVISED_RESULT_UNSAFE_TERMINAL;
    }
    if (worker_result->outcome == CBM_PROC_CLEAN) {
        return worker_result->response ? CBM_MCP_SUPERVISED_RESULT_SUCCESS
                                       : CBM_MCP_SUPERVISED_RESULT_FALLBACK;
    }
    return CBM_MCP_SUPERVISED_RESULT_CONTAINED_FAILURE;
}

typedef struct {
    char *response;
    cbm_proc_outcome_t last_outcome;
    char **previous_suspects;
    int previous_suspect_count;
    int quarantined_count;
    bool unsafe_terminal;
    bool terminal_cancelled;
} supervisor_recovery_state_t;

static char *supervisor_initial_response(cbm_mcp_server_t *srv, const char *args,
                                         cbm_proc_outcome_t *outcome) {
    cbm_index_worker_result_t worker;
    int spawn_result = cbm_index_spawn_worker_with_log_cancel(
        args, false, NULL, NULL, srv ? srv->index_log_callback : NULL,
        srv ? srv->index_log_context : NULL, srv ? &srv->pipeline_cancel_requested : NULL, &worker);
    cbm_mcp_supervised_result_disposition_t disposition =
        cbm_mcp_supervised_result_disposition(spawn_result, &worker);
    if (disposition == CBM_MCP_SUPERVISED_RESULT_FALLBACK) {
        char *response = build_worker_failure_response(args, worker.outcome);
        cbm_index_worker_result_free(&worker);
        return response;
    }
    if (disposition == CBM_MCP_SUPERVISED_RESULT_UNSAFE_TERMINAL) {
        char *response = build_worker_unsafe_terminal_response(args, worker.outcome,
                                                               worker.cancellation_requested);
        cbm_index_worker_result_free(&worker);
        return response;
    }
    if (disposition == CBM_MCP_SUPERVISED_RESULT_SUCCESS) {
        char *response = worker.response;
        worker.response = NULL;
        cbm_index_worker_result_free(&worker);
        return response;
    }
    *outcome = worker.outcome;
    cbm_index_worker_result_free(&worker);
    return NULL;
}

static bool supervisor_record_fault(const char *marker_path, const char *quarantine_path,
                                    cbm_proc_outcome_t outcome, int attempt,
                                    supervisor_recovery_state_t *state) {
    const char *phase = outcome == CBM_PROC_HANG ? "hang" : "crash";
    int suspect_count = 0;
    char **suspects = supervisor_read_suspects(marker_path, &suspect_count);
    (void)remove(marker_path);
    if (!suspects || suspect_count == 0) {
        supervisor_free_suspects(suspects, suspect_count);
        cbm_log_warn("index.supervisor.unattributable", "action", "give_up");
        return false;
    }
    if (state->previous_suspects) {
        const char *pick = NULL;
        for (int index = 0; index < suspect_count && !pick; index++) {
            if (supervisor_suspect_contains(state->previous_suspects, state->previous_suspect_count,
                                            suspects[index])) {
                pick = suspects[index];
            }
        }
        if (!pick || !supervisor_append_quarantine(quarantine_path, pick, phase)) {
            supervisor_free_suspects(suspects, suspect_count);
            cbm_log_warn(!pick ? "index.supervisor.unattributable"
                               : "index.supervisor.quarantine_write_fail",
                         !pick ? "action" : "path", !pick ? "give_up" : pick);
            return false;
        }
        state->quarantined_count++;
        char attempt_text[MCP_FIELD_SIZE];
        snprintf(attempt_text, sizeof(attempt_text), "%d", attempt + MCP_STRING_TERMINATOR_BYTES);
        cbm_log_warn("index.file_quarantined", "path", pick, "outcome", phase, "attempt",
                     attempt_text);
    }
    supervisor_free_suspects(state->previous_suspects, state->previous_suspect_count);
    state->previous_suspects = suspects;
    state->previous_suspect_count = suspect_count;
    return true;
}

static bool supervisor_recovery_attempt(cbm_mcp_server_t *srv, const char *args,
                                        const char *marker_path, const char *quarantine_path,
                                        int attempt, supervisor_recovery_state_t *state) {
    cbm_index_worker_result_t worker;
    int spawn_result = cbm_index_spawn_worker_with_log_cancel(
        args, false, marker_path, quarantine_path, srv ? srv->index_log_callback : NULL,
        srv ? srv->index_log_context : NULL, srv ? &srv->pipeline_cancel_requested : NULL, &worker);
    cbm_mcp_supervised_result_disposition_t disposition =
        cbm_mcp_supervised_result_disposition(spawn_result, &worker);
    state->last_outcome = worker.outcome;
    if (disposition == CBM_MCP_SUPERVISED_RESULT_SUCCESS) {
        state->response = worker.response;
        worker.response = NULL;
        cbm_index_worker_result_free(&worker);
        return false;
    }
    if (disposition == CBM_MCP_SUPERVISED_RESULT_UNSAFE_TERMINAL) {
        state->unsafe_terminal = true;
        state->terminal_cancelled = worker.cancellation_requested;
        cbm_index_worker_result_free(&worker);
        return false;
    }
    if (disposition == CBM_MCP_SUPERVISED_RESULT_FALLBACK) {
        cbm_index_worker_result_free(&worker);
        return false;
    }
    cbm_proc_outcome_t outcome = worker.outcome;
    cbm_index_worker_result_free(&worker);
    if (outcome != CBM_PROC_CRASH && outcome != CBM_PROC_HANG) {
        return false;
    }
    return supervisor_record_fault(marker_path, quarantine_path, outcome, attempt, state);
}

static void supervisor_try_partial(cbm_mcp_server_t *srv, const char *args,
                                   const char *quarantine_path,
                                   supervisor_recovery_state_t *state) {
    if (state->response || state->unsafe_terminal || state->quarantined_count == 0) {
        return;
    }
    cbm_index_worker_result_t worker;
    int spawn_result = cbm_index_spawn_worker_with_log_cancel(
        args, false, NULL, quarantine_path, srv ? srv->index_log_callback : NULL,
        srv ? srv->index_log_context : NULL, srv ? &srv->pipeline_cancel_requested : NULL, &worker);
    cbm_mcp_supervised_result_disposition_t disposition =
        cbm_mcp_supervised_result_disposition(spawn_result, &worker);
    if (disposition == CBM_MCP_SUPERVISED_RESULT_SUCCESS) {
        state->response = worker.response;
        worker.response = NULL;
        char quarantined[MCP_FIELD_SIZE];
        snprintf(quarantined, sizeof(quarantined), "%d", state->quarantined_count);
        cbm_log_error("index.supervisor.partial", "quarantined", quarantined, "outcome",
                      cbm_proc_outcome_str(state->last_outcome));
    } else if (disposition == CBM_MCP_SUPERVISED_RESULT_UNSAFE_TERMINAL) {
        state->last_outcome = worker.outcome;
        state->unsafe_terminal = true;
        state->terminal_cancelled = worker.cancellation_requested;
    }
    cbm_index_worker_result_free(&worker);
}

static char *supervisor_recovery_response(cbm_mcp_server_t *srv, const char *args,
                                          cbm_proc_outcome_t initial_outcome) {
    char marker_path[CBM_SZ_1K];
    char quarantine_path[CBM_SZ_1K];
    supervisor_tmp_path(marker_path, sizeof(marker_path), ".marker");
    supervisor_tmp_path(quarantine_path, sizeof(quarantine_path), ".quarantine");
    (void)remove(marker_path);
    FILE *quarantine_file = cbm_fopen(quarantine_path, "wb");
    if (quarantine_file) {
        (void)fclose(quarantine_file);
    }
    supervisor_recovery_state_t state = {.last_outcome = initial_outcome};
    int cap = supervisor_restart_cap();
    for (int attempt = 0;
         attempt < cap &&
         supervisor_recovery_attempt(srv, args, marker_path, quarantine_path, attempt, &state);
         attempt++) {}
    supervisor_free_suspects(state.previous_suspects, state.previous_suspect_count);
    (void)remove(marker_path);
    supervisor_try_partial(srv, args, quarantine_path, &state);
    (void)remove(quarantine_path);
    if (state.response) {
        return state.response;
    }
    if (state.unsafe_terminal) {
        return build_worker_unsafe_terminal_response(args, state.last_outcome,
                                                     state.terminal_cancelled);
    }
    return build_worker_failure_response(args, state.last_outcome);
}

/* Run index_repository in a supervised worker subprocess with skip-and-continue
 * (Stage 3c). Returns the response string (caller frees):
 *   - the worker's own response on a clean first run (the common path);
 *   - after a crash/hang, the response from a clean single-threaded RECOVERY run
 *     that quarantines the culprit file(s) — status="indexed" with them listed in
 *     skipped[] as phase="crash"/"hang", and the good files indexed;
 *   - a best-effort PARTIAL index (one final quarantine-only run) if the recovery
 *     loop cannot converge but at least one file was quarantined;
 *   - a contained-failure response only if even that cannot produce a clean run.
 * A physical CBM host never falls back to its in-process pipeline: an initial
 * start/protocol failure is returned as an explicit error response. */
static char *index_run_supervised(cbm_mcp_server_t *srv, const char *args) {
    invalidate_cached_store(srv);
    cbm_proc_outcome_t initial_outcome = CBM_PROC_SPAWN_FAILED;
    char *response = supervisor_initial_response(srv, args, &initial_outcome);
    invalidate_cached_store(srv);
    return response ? response : supervisor_recovery_response(srv, args, initial_outcome);
}

/* Build a minimal {"repo_path": "<root>"} args object (path safely escaped) and
 * run it through index_run_supervised. Shared by the session auto-index (srv
 * present → its cached store is invalidated) and the watcher re-index (srv NULL).
 * Returns the worker's response string (caller frees) or NULL to degrade. */
static char *index_run_supervised_path(cbm_mcp_server_t *srv, const char *root_path) {
    if (!root_path || !root_path[0]) {
        return NULL;
    }
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_strcpy(doc, root, "repo_path", root_path);
    char *args = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    if (!args) {
        return NULL;
    }
    char *resp = index_run_supervised(srv, args);
    free(args);
    return resp;
}

/* Public entry (see mcp.h): the watcher re-index in main.c has no MCP server, so
 * it reaches the supervised runner through this srv-less wrapper. */
char *cbm_mcp_index_run_supervised_path(const char *root_path) {
    return index_run_supervised_path(NULL, root_path);
}

/* Resolve relative index requests against an explicitly supplied MCP session
 * root, never against the long-lived daemon process cwd. */
static bool resolve_session_repo_path(cbm_mcp_server_t *srv, char **repo_path) {
    if (!srv || !repo_path || !*repo_path || !srv->allowed_root_policy_set ||
        srv->session_root[0] == '\0' || repo_path_is_absolute(*repo_path)) {
        return true;
    }

    size_t root_len = strlen(srv->session_root);
    size_t path_len = strlen(*repo_path);
    bool needs_separator = root_len > 0 && srv->session_root[root_len - 1] != '/';
    if (root_len > SIZE_MAX - path_len - (needs_separator ? 2U : 1U)) {
        return false;
    }

    size_t joined_size = root_len + (needs_separator ? 1U : 0U) + path_len + 1U;
    char *joined = malloc(joined_size);
    if (!joined) {
        return false;
    }
    (void)snprintf(joined, joined_size, "%s%s%s", srv->session_root, needs_separator ? "/" : "",
                   *repo_path);
    cbm_normalize_path_sep(joined);
    free(*repo_path);
    *repo_path = joined;
    return true;
}

/* Preserve every index option while replacing all caller-supplied repo_path
 * keys with the one canonical path that was actually authorized. */
static char *index_args_with_repo_path(const char *args, const char *canonical_repo_path) {
    if (!args || !canonical_repo_path) {
        return NULL;
    }
    yyjson_doc *source = yyjson_read(args, strlen(args), 0);
    yyjson_val *source_root = source ? yyjson_doc_get_root(source) : NULL;
    if (!source_root || !yyjson_is_obj(source_root)) {
        yyjson_doc_free(source);
        return NULL;
    }

    yyjson_mut_doc *copy = yyjson_doc_mut_copy(source, NULL);
    yyjson_doc_free(source);
    yyjson_mut_val *copy_root = copy ? yyjson_mut_doc_get_root(copy) : NULL;
    if (!copy_root || !yyjson_mut_is_obj(copy_root)) {
        yyjson_mut_doc_free(copy);
        return NULL;
    }
    (void)yyjson_mut_obj_remove_key(copy_root, "repo_path");
    if (!yyjson_mut_obj_add_strcpy(copy, copy_root, "repo_path", canonical_repo_path)) {
        yyjson_mut_doc_free(copy);
        return NULL;
    }
    char *rewritten = yy_doc_to_str(copy);
    yyjson_mut_doc_free(copy);
    return rewritten;
}

/* #1211: index_repository requires repo_path, but list_projects only ever
 * advertises the project NAME, and every read tool accepts that name back via
 * get_project_arg's "project"/"project_name"/"project_id"/"projectName"
 * aliases (mcp.c:1385). Re-indexing an already-indexed project by that same
 * name had no resolution path and fell straight to "repo_path is required".
 * Look up the project's own stored root_path (list_projects proves it's on
 * file) before giving up. Query-only open, always closed here: this never
 * creates a store or touches srv->store/srv->current_project, so it cannot
 * disturb whatever project the server has cached. */
static char *resolved_repo_path_from_project_arg(const char *args) {
    char *project = get_project_arg(args);
    if (!project) {
        return NULL;
    }
    char db_path[CBM_SZ_1K];
    project_db_path(project, db_path, sizeof(db_path));
    cbm_store_t *store = db_path[0] ? cbm_store_open_path_query(db_path) : NULL;
    char *root_path = NULL;
    if (store) {
        cbm_project_t proj = {0};
        if (cbm_store_get_project(store, project, &proj) == CBM_STORE_OK) {
            root_path = proj.root_path ? heap_strdup(proj.root_path) : NULL;
            cbm_project_free_fields(&proj);
        }
        cbm_store_close(store);
    }
    free(project);
    return root_path;
}

static char *handle_index_repository(cbm_mcp_server_t *srv, const char *args) {
    if (!srv) {
        return cbm_mcp_text_result("MCP server is unavailable", true);
    }
    char *repo_path = cbm_mcp_get_string_arg(args, "repo_path");
    char *mode_str = cbm_mcp_get_string_arg(args, "mode");
    char *name_override = cbm_mcp_get_string_arg(args, "name");
    cbm_normalize_path_sep(repo_path);

    if (!repo_path) {
        repo_path = resolved_repo_path_from_project_arg(args);
        cbm_normalize_path_sep(repo_path);
    }

    if (!repo_path) {
        free(mode_str);
        free(name_override);
        return cbm_mcp_text_result("repo_path is required", true);
    }

    if (!resolve_session_repo_path(srv, &repo_path)) {
        free(mode_str);
        free(name_override);
        free(repo_path);
        return cbm_mcp_text_result("failed to resolve repo_path", true);
    }

    repo_path = canonicalize_repo_path_if_exists(repo_path);

    /* Workspace boundary. Embedded/daemon sessions supply their explicit policy,
     * including an explicit NULL meaning unrestricted; a standalone server falls
     * back to the process-wide CBM_ALLOWED_ROOT. The decision itself lives in one
     * shared function so this handler and the HTTP UI indexing route cannot drift
     * apart — they had, and the divergence was the defect. */
    const char *allowed_root =
        srv->allowed_root_policy_set ? srv->allowed_root : getenv("CBM_ALLOWED_ROOT");
    /* repo_path is legitimately absent when the caller names an already-known
     * project instead; the root is resolved downstream. Only a path supplied here
     * is classified here — the previous check had the same tolerance. */
    char boundary_err[CBM_SZ_1K];
    if (repo_path && repo_path[0] &&
        !cbm_workspace_root_allowed(repo_path, cbm_workspace_home_dir(), cbm_workspace_cache_dir(),
                                    allowed_root, boundary_err, sizeof(boundary_err))) {
        free(mode_str);
        free(name_override);
        free(repo_path);
        return cbm_mcp_text_result(boundary_err, true);
    }

    if (mode_str && strcmp(mode_str, "cross-repo-intelligence") == 0) {
        free(mode_str);
        char *result = handle_cross_repo_mode(srv, repo_path, name_override, args);
        free(name_override);
        free(repo_path);
        return result;
    }

    /* A daemon session delegates the one physical write to its shared job
     * registry only after path canonicalization and workspace authorization. */
    if (srv->index_executor) {
        char *worker_args = index_args_with_repo_path(args, repo_path);
        char *coordinated =
            worker_args ? srv->index_executor(srv->index_executor_context, repo_path, worker_args)
                        : NULL;
        free(worker_args);
        free(repo_path);
        free(mode_str);
        free(name_override);
        return coordinated ? coordinated
                           : cbm_mcp_text_result(
                                 "daemon index coordinator could not start the operation", true);
    }

    /* Resolve the exact project key before choosing supervised or in-process
     * execution. A supervised worker owns the OS mutation lease itself: if the
     * CLI parent is killed, the worker must keep project exclusion until its
     * parent-death watchdog reaps the complete worker tree. */
    char *mutation_project =
        cbm_project_name_from_path(name_override && name_override[0] ? name_override : repo_path);
    if (!mutation_project) {
        free(repo_path);
        free(mode_str);
        free(name_override);
        return cbm_mcp_text_result("could not resolve index project name", true);
    }

    /* Supervisor gate: validate the canonical path and the host session's
     * workspace policy before handing work to a crash/hang-isolating worker.
     * The parent deliberately owns no project lease on this path; the worker
     * installs the same guard before running the in-process pipeline. A marked
     * host fails closed if preparation or worker startup cannot complete. */
    if (cbm_index_supervisor_should_wrap()) {
        char *worker_args = index_args_with_repo_path(args, repo_path);
        if (!worker_args) {
            free(mutation_project);
            free(repo_path);
            free(mode_str);
            free(name_override);
            return cbm_mcp_text_result("failed to prepare supervised index request", true);
        }
        char *supervised = index_run_supervised(srv, worker_args);
        free(worker_args);
        if (supervised) {
            free(mutation_project);
            free(repo_path);
            free(mode_str);
            free(name_override);
            return supervised;
        }
        free(mutation_project);
        free(repo_path);
        free(mode_str);
        free(name_override);
        return cbm_mcp_text_result(
            "index supervision failed before a contained worker could start; no "
            "in-process fallback was attempted",
            true);
    }

    if (!mcp_project_mutation_begin(srv, mutation_project)) {
        free(mutation_project);
        free(repo_path);
        free(mode_str);
        free(name_override);
        return cbm_mcp_text_result("index operation blocked by another mutation for this project",
                                   true);
    }
    if (mcp_request_cancelled(srv)) {
        mcp_project_mutation_end(srv, mutation_project);
        free(mutation_project);
        free(repo_path);
        free(mode_str);
        free(name_override);
        return cbm_mcp_text_result("index operation cancelled for this request", true);
    }

    cbm_index_mode_t mode = CBM_MODE_FULL;
    if (mode_str && strcmp(mode_str, "fast") == 0) {
        mode = CBM_MODE_FAST;
    } else if (mode_str && strcmp(mode_str, "moderate") == 0) {
        mode = CBM_MODE_MODERATE;
    }
    free(mode_str);

    bool persistence = cbm_mcp_get_bool_arg(args, "persistence");

    cbm_pipeline_t *p = cbm_pipeline_new(repo_path, NULL, mode);
    if (!p) {
        mcp_project_mutation_end(srv, mutation_project);
        free(mutation_project);
        free(name_override);
        free(repo_path);
        return cbm_mcp_text_result("failed to create pipeline", true);
    }
    if (name_override && name_override[0] && !cbm_pipeline_set_project_name(p, name_override)) {
        cbm_pipeline_free(p);
        mcp_project_mutation_end(srv, mutation_project);
        free(mutation_project);
        free(name_override);
        free(repo_path);
        return cbm_mcp_text_result("invalid project name", true);
    }
    free(name_override);
    cbm_pipeline_set_persistence(p, persistence);

    char *project_name = heap_strdup(cbm_pipeline_project_name(p));

    /* Bootstrap from artifact if no local DB exists */
    try_artifact_bootstrap(project_name, repo_path);

    /* Close cached store — pipeline will delete + recreate the .db file */
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
        srv->store = NULL;
    }
    free(srv->current_project);
    srv->current_project = NULL;

    /* Serialize pipeline runs to prevent concurrent writes.
     * Track active pipeline so signal handler and notifications/cancelled
     * can cancel it mid-run. */
    cbm_pipeline_lock();
    cbm_pipeline_bind_cancel_flag(p, &srv->pipeline_cancel_requested);
    srv->active_pipeline = p;
    int rc = cbm_pipeline_run(p);
    srv->active_pipeline = NULL;
    cbm_pipeline_unlock();

    /* Capture the excluded-subtree list (#411) while the pipeline (which owns
     * the strings) is still alive — the response builder copies them into the
     * JSON doc, so they need only outlive that call, not cbm_pipeline_free. */
    char **excluded_dirs = NULL;
    int excluded_count = 0;
    cbm_pipeline_get_excluded(p, &excluded_dirs, &excluded_count);

    /* Capture the per-file skip list (Stage 2 / Track B) while the pipeline
     * still owns the strings; the response builder copies them into the doc. */
    cbm_file_error_t *file_errors = NULL;
    int file_error_count = 0;
    cbm_pipeline_get_file_errors(p, &file_errors, &file_error_count);

    cbm_mem_collect(); /* return mimalloc pages to OS after large indexing */

    /* Invalidate cached store so next query reopens the fresh database */
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
        srv->store = NULL;
    }
    free(srv->current_project);
    srv->current_project = NULL;

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "project", project_name);

    if (rc == 0) {
        /* Write the per-run logfile ONLY when there were skips (no logfile on a
         * clean run). The FULL list goes to the file; the JSON caps at 50. */
        char logfile_path[CBM_SZ_1K];
        logfile_path[0] = '\0';
        bool has_logfile = write_skip_logfile(project_name, file_errors, file_error_count,
                                              logfile_path, sizeof(logfile_path));
        bool degraded = build_index_success_response(
            srv, doc, root, project_name, repo_path, persistence, p, excluded_dirs, excluded_count,
            file_errors, file_error_count, has_logfile ? logfile_path : NULL);
        yyjson_mut_obj_add_str(doc, root, "status", degraded ? "degraded" : "indexed");
    } else {
        yyjson_mut_obj_add_str(doc, root, "status", "error");
        yyjson_mut_obj_add_str(doc, root, "hint",
                               "Pipeline failed. Check repo_path exists and contains source files. "
                               "Try mode='fast' for a quicker diagnostic run.");
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    /* Free the pipeline only after the response doc copied the excluded list.
     * Supervised worker: skip the deep free — the process exits right after
     * handing over the response (main.c fast-exits), and piecemeal-freeing a
     * multi-GB graph before process death costs minutes on kernel-scale repos;
     * the OS reclaims it wholesale at exit. In-process paths (tests, kill
     * switch, degrade) still free normally. */
    if (cbm_index_worker_active()) {
        cbm_log_info("index.worker.fast_exit", "skip", "pipeline_free");
    } else {
        cbm_pipeline_free(p);
    }
    free(project_name);
    free(repo_path);

    mcp_project_mutation_end(srv, mutation_project);
    free(mutation_project);

    char *result = cbm_mcp_text_result(json, rc != 0);
    free(json);
    return result;
}

/* ── get_code_snippet ─────────────────────────────────────────── */

/* Copy a node from an array into a heap-allocated standalone node. */
static void copy_node(const cbm_node_t *src, cbm_node_t *dst) {
    dst->id = src->id;
    dst->project = heap_strdup(src->project);
    dst->label = heap_strdup(src->label);
    dst->name = heap_strdup(src->name);
    dst->qualified_name = heap_strdup(src->qualified_name);
    dst->file_path = heap_strdup(src->file_path);
    dst->start_line = src->start_line;
    dst->end_line = src->end_line;
    dst->properties_json = src->properties_json ? heap_strdup(src->properties_json) : NULL;
}

/* Build a JSON suggestions response for ambiguous or fuzzy results. */
static char *snippet_suggestions(const char *input, cbm_node_t *nodes, int count) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "status", "ambiguous");

    char msg[CBM_SZ_512];
    snprintf(msg, sizeof(msg),
             "%d matches for \"%s\". Pick a qualified_name from suggestions below, "
             "or use search_graph(name_pattern=\"...\") to narrow results.",
             count, input);
    yyjson_mut_obj_add_str(doc, root, "message", msg);

    yyjson_mut_val *arr = yyjson_mut_arr(doc);
    for (int i = 0; i < count; i++) {
        yyjson_mut_val *s = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_str(doc, s, "qualified_name",
                               nodes[i].qualified_name ? nodes[i].qualified_name : "");
        yyjson_mut_obj_add_str(doc, s, "name", nodes[i].name ? nodes[i].name : "");
        yyjson_mut_obj_add_str(doc, s, "label", nodes[i].label ? nodes[i].label : "");
        yyjson_mut_obj_add_str(doc, s, "file_path", nodes[i].file_path ? nodes[i].file_path : "");
        yyjson_mut_arr_append(arr, s);
    }
    yyjson_mut_obj_add_val(doc, root, "suggestions", arr);

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* Resolve an absolute path from root_path + file_path, verify containment,
 * and read source lines. Sets *out_abs_path (caller frees). Returns source
 * string (caller frees) or NULL if path is invalid/unreadable. */
/* True only when abs_path, after realpath/_fullpath resolution (which collapses
 * `..` and resolves symlinks/junctions), stays within root_path. This is the
 * single containment guard every MCP file-read sink must pass before reading a
 * file into a tool response: both the snippet path (resolve_snippet_source) and
 * the search path (attach_result_source) route through it, so a result whose
 * indexed path escapes the project root — via a `..` segment, or a symlink /
 * Windows junction picked up during discovery — is never read back out. */

static char *resolve_snippet_source(const char *root_path, const char *file_path, int start,
                                    int end, char **out_abs_path) {
    *out_abs_path = NULL;
    if (!root_path || !file_path) {
        return NULL;
    }
    size_t apsz = strlen(root_path) + strlen(file_path) + MCP_SEPARATOR;
    char *abs_path = malloc(apsz);
    snprintf(abs_path, apsz, "%s/%s", root_path, file_path);

    *out_abs_path = abs_path;
    if (cbm_path_within_root(root_path, abs_path)) {
        return read_file_lines(abs_path, start, end);
    }
    return NULL;
}

static bool utf8_is_cont(unsigned char c) {
    return (c & 0xC0) == 0x80;
}

static char *sanitize_utf8_lossy(const char *s) {
    enum {
        UTF8_REPLACEMENT_LEN = 3,
        UTF8_THREE_BYTE_LEN = 3,
        UTF8_FOUR_BYTE_LEN = 4,
        UTF8_FOURTH_BYTE = 3,
    };
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    if (len > (((size_t)-1) - SKIP_ONE) / UTF8_REPLACEMENT_LEN) {
        return NULL;
    }
    char *out = malloc((len * UTF8_REPLACEMENT_LEN) + SKIP_ONE);
    if (!out) {
        return NULL;
    }

    const unsigned char *p = (const unsigned char *)s;
    const unsigned char *end = p + len;
    unsigned char *dst = (unsigned char *)out;
    while (p < end) {
        unsigned char c = *p;
        size_t n = 0;
        if (c < 0x80) {
            n = 1;
        } else if (c >= 0xC2 && c <= 0xDF && p + 1 < end && utf8_is_cont(p[1])) {
            n = 2;
        } else if (c == 0xE0 && p + 2 < end && p[1] >= 0xA0 && p[1] <= 0xBF && utf8_is_cont(p[2])) {
            n = UTF8_THREE_BYTE_LEN;
        } else if (c >= 0xE1 && c <= 0xEC && p + 2 < end && utf8_is_cont(p[1]) &&
                   utf8_is_cont(p[2])) {
            n = UTF8_THREE_BYTE_LEN;
        } else if (c == 0xED && p + 2 < end && p[1] >= 0x80 && p[1] <= 0x9F && utf8_is_cont(p[2])) {
            n = UTF8_THREE_BYTE_LEN;
        } else if (c >= 0xEE && c <= 0xEF && p + 2 < end && utf8_is_cont(p[1]) &&
                   utf8_is_cont(p[2])) {
            n = UTF8_THREE_BYTE_LEN;
        } else if (c == 0xF0 && p + UTF8_FOURTH_BYTE < end && p[1] >= 0x90 && p[1] <= 0xBF &&
                   utf8_is_cont(p[2]) && utf8_is_cont(p[UTF8_FOURTH_BYTE])) {
            n = UTF8_FOUR_BYTE_LEN;
        } else if (c >= 0xF1 && c <= 0xF3 && p + UTF8_FOURTH_BYTE < end && utf8_is_cont(p[1]) &&
                   utf8_is_cont(p[2]) && utf8_is_cont(p[UTF8_FOURTH_BYTE])) {
            n = UTF8_FOUR_BYTE_LEN;
        } else if (c == 0xF4 && p + UTF8_FOURTH_BYTE < end && p[1] >= 0x80 && p[1] <= 0x8F &&
                   utf8_is_cont(p[2]) && utf8_is_cont(p[UTF8_FOURTH_BYTE])) {
            n = UTF8_FOUR_BYTE_LEN;
        }

        if (n > 0) {
            memcpy(dst, p, n);
            dst += n;
            p += n;
        } else {
            *dst++ = 0xEF;
            *dst++ = 0xBF;
            *dst++ = 0xBD;
            p++;
        }
    }
    *dst = '\0';
    return out;
}

/* Build an enriched snippet response for a resolved node. */
/* Add a string array to a JSON object (no-op if count == 0). */
static void add_string_array(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key,
                             char **strings, int count) {
    if (count <= 0) {
        return;
    }
    yyjson_mut_val *arr = yyjson_mut_arr(doc);
    for (int i = 0; i < count; i++) {
        yyjson_mut_arr_add_str(doc, arr, strings[i]);
    }
    yyjson_mut_obj_add_val(doc, obj, key, arr);
}

/* get_code_snippet coverage note (#963): if the resolved node's file is
 * flagged parse_partial, warn that the graph may under-report this file.
 * Correlated by construction — the result names its file. (An entirely-
 * skipped file cannot appear here: it has no nodes to resolve a snippet
 * from.) */
static void add_snippet_coverage_note(yyjson_mut_doc *doc, yyjson_mut_val *root_obj,
                                      cbm_store_t *store, const cbm_node_t *node) {
    if (!node->file_path || !node->file_path[0] || !node->project) {
        return;
    }
    cbm_coverage_row_t *rows = NULL;
    int count = 0;
    if (cbm_store_coverage_get_path(store, node->project, node->file_path, &rows, &count) !=
        CBM_STORE_OK) {
        return;
    }
    for (int i = 0; i < count; i++) {
        if (rows[i].rel_path && strcmp(rows[i].rel_path, node->file_path) == 0 && rows[i].kind &&
            strcmp(rows[i].kind, "parse_partial") == 0) {
            char note[CBM_SZ_1K];
            snprintf(note, sizeof(note),
                     "This file was only PARTIALLY indexed — line range(s) %s could not be "
                     "parsed, so constructs there may be missing from the graph (callers/callees "
                     "and search results can under-report this file). The source above is ground "
                     "truth. (best-effort signal)",
                     rows[i].detail && rows[i].detail[0] ? rows[i].detail : "?");
            yyjson_mut_obj_add_strcpy(doc, root_obj, "coverage_note", note);
            break;
        }
    }
    cbm_store_free_coverage(rows, count);
}

static char *build_snippet_response(cbm_mcp_server_t *srv, cbm_node_t *node,
                                    const char *match_method, bool include_neighbors,
                                    cbm_node_t *alternatives, int alt_count) {
    char *root_path = get_project_root(srv, node->project);

    int start = node->start_line > 0 ? node->start_line : SKIP_ONE;
    int end = node->end_line > start ? node->end_line : start + SNIPPET_DEFAULT_LINES;
    /* Context-bomb guard: a structural node (Module/File) spans its whole file,
     * so an unclipped read returned the ENTIRE source — a field-eval agent that
     * fell back to a Module snippet pulled 400KB in one call. Cap the line span
     * (far above any real function) and flag it; the exact range is still in
     * start_line/end_line for a targeted re-read. */
    bool snippet_clipped = false;
    if (end - start + 1 > MCP_SNIPPET_MAX_LINES) {
        end = start + MCP_SNIPPET_MAX_LINES - 1;
        snippet_clipped = true;
    }
    char *abs_path = NULL;
    char *source = resolve_snippet_source(root_path, node->file_path, start, end, &abs_path);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root_obj = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root_obj);

    yyjson_mut_obj_add_str(doc, root_obj, "name", node->name);
    yyjson_mut_obj_add_str(doc, root_obj, "qualified_name", node->qualified_name);
    yyjson_mut_obj_add_str(doc, root_obj, "label", node->label);

    const char *display_path = "";
    if (abs_path) {
        display_path = abs_path;
    } else if (node->file_path) {
        display_path = node->file_path;
    }
    yyjson_mut_obj_add_str(doc, root_obj, "file_path", display_path);
    yyjson_mut_obj_add_int(doc, root_obj, "start_line", start);
    yyjson_mut_obj_add_int(doc, root_obj, "end_line", end);
    if (snippet_clipped) {
        yyjson_mut_obj_add_bool(doc, root_obj, "source_clipped", true);
        yyjson_mut_obj_add_int(doc, root_obj, "clipped_at_lines", MCP_SNIPPET_MAX_LINES);
    }

    if (source) {
        char *safe_source = sanitize_utf8_lossy(source);
        if (safe_source) {
            yyjson_mut_obj_add_strcpy(doc, root_obj, "source", safe_source);
            free(safe_source);
        } else {
            yyjson_mut_obj_add_str(doc, root_obj, "source", "(source not available)");
        }
    } else {
        yyjson_mut_obj_add_str(doc, root_obj, "source", "(source not available)");
    }

    /* match_method — omitted for exact matches */
    if (match_method) {
        yyjson_mut_obj_add_str(doc, root_obj, "match_method", match_method);
    }

    /* No property-blob enrichment: the verbatim source IS the payload here —
     * signature/docstring are literally in it, and the similarity internals
     * (fp/sp/bt) plus metric fields were 41% of the response for zero agent
     * value. Metrics stay reachable via search_graph fields=[...]. */
    yyjson_doc *props_doc = NULL;

    /* Caller/callee counts — store already resolved by calling handler */
    cbm_store_t *store = srv->store;
    int in_deg = 0;
    int out_deg = 0;
    cbm_store_node_degree(store, node->id, &in_deg, &out_deg);
    yyjson_mut_obj_add_int(doc, root_obj, "callers", in_deg);
    yyjson_mut_obj_add_int(doc, root_obj, "callees", out_deg);

    add_snippet_coverage_note(doc, root_obj, store, node);

    char **nb_callers = NULL;
    int nb_caller_count = 0;
    char **nb_callees = NULL;
    int nb_callee_count = 0;
    if (include_neighbors) {
        cbm_store_node_neighbor_names(store, node->id, MCP_DEFAULT_LIMIT, &nb_callers,
                                      &nb_caller_count, &nb_callees, &nb_callee_count);
        add_string_array(doc, root_obj, "caller_names", nb_callers, nb_caller_count);
        add_string_array(doc, root_obj, "callee_names", nb_callees, nb_callee_count);
    }

    /* Alternatives (when auto-resolved from ambiguous) */
    if (alternatives && alt_count > 0) {
        yyjson_mut_val *arr = yyjson_mut_arr(doc);
        for (int i = 0; i < alt_count; i++) {
            yyjson_mut_val *a = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, a, "qualified_name",
                                   alternatives[i].qualified_name ? alternatives[i].qualified_name
                                                                  : "");
            yyjson_mut_obj_add_str(doc, a, "file_path",
                                   alternatives[i].file_path ? alternatives[i].file_path : "");
            yyjson_mut_arr_append(arr, a);
        }
        yyjson_mut_obj_add_val(doc, root_obj, "alternatives", arr);
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    yyjson_doc_free(props_doc); /* safe if NULL */
    for (int i = 0; i < nb_caller_count; i++) {
        free(nb_callers[i]);
    }
    for (int i = 0; i < nb_callee_count; i++) {
        free(nb_callees[i]);
    }
    free(nb_callers);
    free(nb_callees);
    free(root_path);
    free(abs_path);
    free(source);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

static char *handle_get_code_snippet(cbm_mcp_server_t *srv, const char *args) {
    char *qn = cbm_mcp_get_string_arg(args, "qualified_name");
    char *project = get_project_arg(args);
    bool include_neighbors = cbm_mcp_get_bool_arg(args, "include_neighbors");

    if (!qn) {
        free(project);
        return cbm_mcp_text_result("qualified_name is required", true);
    }

    cbm_store_t *store = resolve_store(srv, project);
    if (!store) {
        char *_err = build_project_list_error("project not found or not indexed");
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        free(qn);
        free(project);
        return _res;
    }

    char *not_indexed = verify_project_indexed(store, project);
    if (not_indexed) {
        free(qn);
        free(project);
        return not_indexed;
    }

    /* Default to current project (same as all other tools) */
    const char *effective_project = project ? project : srv->current_project;

    /* Tier 1: Exact QN match */
    cbm_node_t node = {0};
    int rc = cbm_store_find_node_by_qn(store, effective_project, qn, &node);
    if (rc == CBM_STORE_OK) {
        char *result = build_snippet_response(srv, &node, NULL, include_neighbors, NULL, 0);
        free_node_contents(&node);
        free(qn);
        free(project);
        return result;
    }

    /* Tier 2: Suffix match — handles partial QNs ("main.HandleRequest")
     * and short names ("ProcessOrder") via LIKE '%.X'. */
    cbm_node_t *suffix_nodes = NULL;
    int suffix_count = 0;
    cbm_store_find_nodes_by_qn_suffix(store, effective_project, qn, &suffix_nodes, &suffix_count);

    if (suffix_count == SKIP_ONE) {
        copy_node(&suffix_nodes[0], &node);
        cbm_store_free_nodes(suffix_nodes, suffix_count);
        char *result = build_snippet_response(srv, &node, "suffix", include_neighbors, NULL, 0);
        free_node_contents(&node);
        free(qn);
        free(project);
        return result;
    }

    if (suffix_count > SKIP_ONE) {
        /* Prefer the real definition (a .c body over a .h declaration, a Function
         * over a Module) so an unambiguous-by-preference match resolves directly
         * instead of forcing a disambiguation round trip; only a genuine tie still
         * returns suggestions. */
        bool snip_ambiguous = false;
        int ssel = pick_resolved_node(suffix_nodes, suffix_count, &snip_ambiguous);
        if (!snip_ambiguous) {
            copy_node(&suffix_nodes[ssel], &node);
            cbm_store_free_nodes(suffix_nodes, suffix_count);
            char *result = build_snippet_response(srv, &node, "suffix", include_neighbors, NULL, 0);
            free_node_contents(&node);
            free(qn);
            free(project);
            return result;
        }
        char *result = snippet_suggestions(qn, suffix_nodes, suffix_count);
        cbm_store_free_nodes(suffix_nodes, suffix_count);
        free(qn);
        free(project);
        return result;
    }

    cbm_store_free_nodes(suffix_nodes, suffix_count);
    free(qn);
    free(project);

    /* Nothing found — guide the caller toward search_graph */
    return cbm_mcp_text_result(
        "symbol not found. Use search_graph(name_pattern=\"...\") first to discover "
        "the exact qualified_name, then pass it to get_code_snippet.",
        true);
}

/* ── search_code v2: graph-augmented code search ─────────────── */

/* Strip non-ASCII bytes to guarantee valid UTF-8 JSON output */
enum { ASCII_MAX = 127 };
static void sanitize_ascii(char *s) {
    for (unsigned char *p = (unsigned char *)s; *p; p++) {
        if (*p > ASCII_MAX) {
            *p = '?';
        }
    }
}

/* Intermediate grep match */
typedef struct {
    char file[CBM_SZ_512];
    int line;
    char content[CBM_SZ_1K];
} grep_match_t;

/* Deduped result: one per containing graph node */
typedef struct {
    int64_t node_id; /* 0 = raw match (no containing node) */
    char node_name[CBM_SZ_256];
    char qualified_name[CBM_SZ_512];
    char label[CBM_SZ_64];
    char file[CBM_SZ_512];
    int start_line;
    int end_line;
    int in_degree;
    int out_degree;
    int score;
    int match_lines[CBM_SZ_64];
    int match_count;
} search_result_t;

/* Score a result for ranking: project source first, vendored last, tests lowest */
enum { SCORE_FUNC = 10, SCORE_ROUTE = 15, SCORE_VENDORED = -50, SCORE_TEST = -5 };
enum { MAX_LINE_SPAN = 999999 };

static int compute_search_score(const search_result_t *r) {
    int score = r->in_degree;
    if (strcmp(r->label, "Function") == 0 || strcmp(r->label, "Method") == 0) {
        score += SCORE_FUNC;
    }
    if (strcmp(r->label, "Route") == 0) {
        score += SCORE_ROUTE;
    }
    if (strstr(r->file, "vendored/") || strstr(r->file, "vendor/") ||
        strstr(r->file, "node_modules/")) {
        score += SCORE_VENDORED;
    }
    /* Penalize test files */
    if (strstr(r->file, "test") || strstr(r->file, "spec") || strstr(r->file, "_test.")) {
        score += SCORE_TEST;
    }
    return score;
}

static int search_result_cmp(const void *a, const void *b) {
    const search_result_t *ra = (const search_result_t *)a;
    const search_result_t *rb = (const search_result_t *)b;
    return rb->score - ra->score; /* descending */
}

/* Build the grep/search command string based on scoped vs recursive mode.
 * On Windows, uses PowerShell Select-String with tab-delimited output.
 * On POSIX, uses grep with colon-delimited output. */
static void build_grep_cmd(char *cmd, size_t cmd_sz, bool use_regex, bool scoped,
                           const char *file_pattern, const char *tmpfile, const char *filelist,
                           const char *root_path) {
#ifdef _WIN32
    const char *sm = use_regex ? "" : " -SimpleMatch";
    if (scoped) {
        if (file_pattern) {
            snprintf(
                cmd, cmd_sz,
                "powershell -Command \"$pat = Get-Content -Encoding UTF8 -LiteralPath '%s'; "
                "Get-Content -Encoding UTF8 -LiteralPath '%s' | ForEach-Object { Select-String "
                "-LiteralPath $_ -Pattern $pat%s "
                "-ErrorAction SilentlyContinue }"
                " | Where-Object { $_.Path -like '*%s' }"
                " | ForEach-Object { $_.Path + [char]9 + $_.LineNumber + [char]9 + $_.Line }\"",
                tmpfile, filelist, sm, file_pattern);
        } else {
            snprintf(
                cmd, cmd_sz,
                "powershell -Command \"$pat = Get-Content -Encoding UTF8 -LiteralPath '%s'; "
                "Get-Content -Encoding UTF8 -LiteralPath '%s' | ForEach-Object { Select-String "
                "-LiteralPath $_ -Pattern $pat%s "
                "-ErrorAction SilentlyContinue }"
                " | ForEach-Object { $_.Path + [char]9 + $_.LineNumber + [char]9 + $_.Line }\"",
                tmpfile, filelist, sm);
        }
    } else {
        if (file_pattern) {
            snprintf(
                cmd, cmd_sz,
                "powershell -Command \"Get-ChildItem -Recurse -Path '%s\\*' -Include '%s' -File "
                "-ErrorAction SilentlyContinue"
                " | Select-String -Pattern (Get-Content -Encoding UTF8 -LiteralPath '%s')%s "
                "-ErrorAction SilentlyContinue"
                " | ForEach-Object { $_.Path + [char]9 + $_.LineNumber + [char]9 + $_.Line }\"",
                root_path, file_pattern, tmpfile, sm);
        } else {
            snprintf(
                cmd, cmd_sz,
                "powershell -Command \"Get-ChildItem -Recurse -Path '%s\\*' -File -ErrorAction "
                "SilentlyContinue"
                " | Select-String -Pattern (Get-Content -Encoding UTF8 -LiteralPath '%s')%s "
                "-ErrorAction SilentlyContinue"
                " | ForEach-Object { $_.Path + [char]9 + $_.LineNumber + [char]9 + $_.Line }\"",
                root_path, tmpfile, sm);
        }
    }
#else
    const char *flag = use_regex ? "-E" : "-F";
    if (scoped) {
        if (file_pattern) {
            /* -0: read NUL-separated paths from the filelist so paths containing
             * spaces stay one argument (issue #687). Pairs with the NUL separator
             * written by write_scoped_filelist. */
            snprintf(cmd, cmd_sz, "xargs -0 grep -Hn %s --include='%s' -f '%s' < '%s' 2>/dev/null",
                     flag, file_pattern, tmpfile, filelist);
        } else {
            snprintf(cmd, cmd_sz, "xargs -0 grep -Hn %s -f '%s' < '%s' 2>/dev/null", flag, tmpfile,
                     filelist);
        }
    } else {
        if (file_pattern) {
            snprintf(cmd, cmd_sz, "grep -rn %s --include='%s' -f '%s' '%s' 2>/dev/null", flag,
                     file_pattern, tmpfile, root_path);
        } else {
            snprintf(cmd, cmd_sz, "grep -rn %s -f '%s' '%s' 2>/dev/null", flag, tmpfile, root_path);
        }
    }
#endif
}

/* Build deduplicated file list from search results + raw matches. */
static yyjson_mut_val *build_dedup_files_array(yyjson_mut_doc *doc, search_result_t *sr,
                                               int output_count, grep_match_t *raw, int raw_count) {
    yyjson_mut_val *files_arr = yyjson_mut_arr(doc);
    char *seen_files[CBM_SZ_512];
    int seen_count = 0;
    for (int fi = 0; fi < output_count; fi++) {
        bool dup = false;
        for (int j = 0; j < seen_count; j++) {
            if (strcmp(seen_files[j], sr[fi].file) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup && seen_count < CBM_SZ_512) {
            seen_files[seen_count++] = sr[fi].file;
            yyjson_mut_arr_add_str(doc, files_arr, sr[fi].file);
        }
    }
    for (int fi = 0; fi < raw_count && seen_count < CBM_SZ_512; fi++) {
        bool dup = false;
        for (int j = 0; j < seen_count; j++) {
            if (strcmp(seen_files[j], raw[fi].file) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            seen_files[seen_count++] = raw[fi].file;
            yyjson_mut_arr_add_str(doc, files_arr, raw[fi].file);
        }
    }
    return files_arr;
}

/* Attach source or context lines to a search result JSON item. */
static void attach_result_source(yyjson_mut_doc *doc, yyjson_mut_val *item, search_result_t *r,
                                 int mode, int context_lines, const char *root_path) {
    enum { MODE_FULL = 1 };
    if (r->start_line <= 0 || r->end_line <= 0) {
        return;
    }
    char abs_path[CBM_SZ_1K];
    snprintf(abs_path, sizeof(abs_path), "%s/%s", root_path, r->file);

    /* Containment: a search result whose indexed path resolves outside the
     * project root (a `..` segment, or a symlink/junction that discovery
     * followed) must not be read back into the response. Same guard the
     * snippet path already uses. */
    if (!cbm_path_within_root(root_path, abs_path)) {
        return;
    }

    if (mode == MODE_FULL) {
        /* Cap each hit's source at a match-anchored window: uncapped
         * whole-symbol dumps ran to 5.7KB × N hits (142KB responses). The
         * complete symbol stays one get_code_snippet call away;
         * source_start/source_truncated make the cut explicit. */
        enum { SC_FULL_MAX_LINES = 60, SC_FULL_LEAD = 5 };
        int s = r->start_line;
        int e = r->end_line;
        bool truncated = false;
        if (e - s + 1 > SC_FULL_MAX_LINES) {
            if (r->match_count > 0 && r->match_lines[0] - SC_FULL_LEAD > s) {
                s = r->match_lines[0] - SC_FULL_LEAD;
            }
            e = s + SC_FULL_MAX_LINES - 1;
            if (e > r->end_line) {
                e = r->end_line;
            }
            truncated = true;
        }
        char *source = read_file_lines(abs_path, s, e);
        if (source) {
            sanitize_ascii(source);
            yyjson_mut_obj_add_strcpy(doc, item, "source", source);
            free(source);
            if (truncated) {
                yyjson_mut_obj_add_int(doc, item, "source_start", s);
                yyjson_mut_obj_add_bool(doc, item, "source_truncated", true);
            }
        }
    } else if (context_lines > 0 && r->match_count > 0) {
        int ctx_start = r->match_lines[0] - context_lines;
        int ctx_end = r->match_lines[r->match_count - SKIP_ONE] + context_lines;
        if (ctx_start < SKIP_ONE) {
            ctx_start = SKIP_ONE;
        }
        char *ctx = read_file_lines(abs_path, ctx_start, ctx_end);
        if (ctx) {
            sanitize_ascii(ctx);
            yyjson_mut_obj_add_strcpy(doc, item, "context", ctx);
            yyjson_mut_obj_add_int(doc, item, "context_start", ctx_start);
            free(ctx);
        }
    }
}

/* Build directory distribution object from search results (top-level dir → count). */
/* Aggregate hits by top-level directory. Shared by the JSON object and the
 * TOON table emission. Returns the number of distinct directories. */
static int aggregate_search_dirs(const search_result_t *sr, int sr_count,
                                 char dir_names[][CBM_SZ_128], int *dir_counts, int max_dirs) {
    int dir_n = 0;
    for (int di = 0; di < sr_count; di++) {
        char top[CBM_SZ_128] = "";
        const char *slash = strchr(sr[di].file, '/');
        if (slash) {
            size_t dlen = (size_t)(slash - sr[di].file + SKIP_ONE);
            if (dlen >= sizeof(top)) {
                dlen = sizeof(top) - SKIP_ONE;
            }
            memcpy(top, sr[di].file, dlen);
            top[dlen] = '\0';
        } else {
            snprintf(top, sizeof(top), "%s", sr[di].file);
        }
        int found = CBM_NOT_FOUND;
        for (int d = 0; d < dir_n; d++) {
            if (strcmp(dir_names[d], top) == 0) {
                found = d;
                break;
            }
        }
        if (found >= 0) {
            dir_counts[found]++;
        } else if (dir_n < max_dirs) {
            snprintf(dir_names[dir_n], CBM_SZ_128, "%s", top);
            dir_counts[dir_n] = SKIP_ONE;
            dir_n++;
        }
    }
    return dir_n;
}

static yyjson_mut_val *build_dir_distribution(yyjson_mut_doc *doc, search_result_t *sr,
                                              int sr_count) {
    yyjson_mut_val *dirs = yyjson_mut_obj(doc);
    char dir_names[CBM_SZ_64][CBM_SZ_128];
    int dir_counts[CBM_SZ_64];
    int dir_n = aggregate_search_dirs(sr, sr_count, dir_names, dir_counts, CBM_SZ_64);
    for (int d = 0; d < dir_n; d++) {
        yyjson_mut_val *key = yyjson_mut_strcpy(doc, dir_names[d]);
        yyjson_mut_val *val = yyjson_mut_int(doc, dir_counts[d]);
        yyjson_mut_obj_add(dirs, key, val);
    }
    return dirs;
}

enum {
    SEARCH_OUTPUT_MODE_COMPACT = 0,
    SEARCH_OUTPUT_MODE_FULL = 1,
    SEARCH_OUTPUT_MODE_FILES = 2,
    SEARCH_OUTPUT_SLOW_MS = 5000,
    SEARCH_OUTPUT_RAW_LIMIT = 20,
    SEARCH_TOON_RESULT_COLUMN_COUNT = 7,
    SEARCH_TOON_RAW_COLUMN_COUNT = 3,
    SEARCH_TOON_DIR_COLUMN_COUNT = 2,
    SEARCH_TOON_MATCH_MIN_REMAINING_BYTES = 12,
};

static void search_toon_format_match_lines(char *matches, size_t matches_size,
                                           const search_result_t *result) {
    size_t position = 0;
    matches[0] = '\0';
    for (int index = 0; index < result->match_count &&
                        position + SEARCH_TOON_MATCH_MIN_REMAINING_BYTES < matches_size;
         index++) {
        int written = snprintf(matches + position, matches_size - position, "%s%d",
                               index > 0 ? ";" : "", result->match_lines[index]);
        if (written < 0) {
            break;
        }
        position += (size_t)written;
    }
}

static void search_toon_add_result_rows(cbm_sb_t *output, const search_result_t *results,
                                        int result_count) {
    static const char *const columns[] = {"qn", "label", "file", "lines", "matches", "in", "out"};
    cbm_tree_table_header(output, "results", result_count, columns,
                          SEARCH_TOON_RESULT_COLUMN_COUNT);
    for (int index = 0; index < result_count; index++) {
        const search_result_t *result = &results[index];
        char lines[CBM_SZ_32];
        char matches[CBM_SZ_256];
        sg_lines_str(lines, sizeof(lines), result->start_line, result->end_line);
        search_toon_format_match_lines(matches, sizeof(matches), result);
        cbm_tree_row_begin(output);
        cbm_tree_cell_str(output, result->qualified_name, true);
        cbm_tree_cell_str(output, result->label, false);
        cbm_tree_cell_str(output, result->file, false);
        cbm_tree_cell_str(output, lines, false);
        cbm_tree_cell_str(output, matches, false);
        cbm_tree_cell_int(output, result->in_degree, false);
        cbm_tree_cell_int(output, result->out_degree, false);
        cbm_tree_row_end(output);
    }
}

static void search_toon_add_raw_rows(cbm_sb_t *output, const grep_match_t *raw, int raw_count) {
    static const char *const columns[] = {"file", "line", "content"};
    int output_count = raw_count < SEARCH_OUTPUT_RAW_LIMIT ? raw_count : SEARCH_OUTPUT_RAW_LIMIT;
    if (output_count <= 0) {
        return;
    }
    cbm_tree_table_header(output, "raw", output_count, columns, SEARCH_TOON_RAW_COLUMN_COUNT);
    for (int index = 0; index < output_count; index++) {
        cbm_tree_row_begin(output);
        cbm_tree_cell_str(output, raw[index].file, true);
        cbm_tree_cell_int(output, raw[index].line, false);
        cbm_tree_cell_str(output, raw[index].content, false);
        cbm_tree_row_end(output);
    }
}

static void search_toon_add_directory_rows(cbm_sb_t *output, const search_result_t *results,
                                           int result_count) {
    static const char *const columns[] = {"dir", "hits"};
    char names[CBM_SZ_64][CBM_SZ_128];
    int counts[CBM_SZ_64];
    int directory_count = aggregate_search_dirs(results, result_count, names, counts, CBM_SZ_64);
    if (directory_count <= 0) {
        return;
    }
    cbm_tree_table_header(output, "dirs", directory_count, columns, SEARCH_TOON_DIR_COLUMN_COUNT);
    for (int index = 0; index < directory_count; index++) {
        cbm_tree_row_begin(output);
        cbm_tree_cell_str(output, names[index], true);
        cbm_tree_cell_int(output, counts[index], false);
        cbm_tree_row_end(output);
    }
}

static void search_toon_add_summary(cbm_sb_t *output, int result_count, int raw_count,
                                    int grep_match_count, bool warn_literal_pipe,
                                    uint64_t elapsed_ms) {
    cbm_tree_scalar_int(output, "total_grep_matches", grep_match_count);
    cbm_tree_scalar_int(output, "total_results", result_count);
    cbm_tree_scalar_int(output, "raw_match_count", raw_count);
    cbm_tree_scalar_int(output, "elapsed_ms", (long long)elapsed_ms);
    if (warn_literal_pipe) {
        cbm_tree_scalar_str(output, "warning",
                            "pattern contains '|' but regex=false, so it is matched literally "
                            "(not as alternation). Pass regex=true for 'foo|bar' to mean "
                            "'foo OR bar'.");
    }
    if (elapsed_ms >= SEARCH_OUTPUT_SLOW_MS) {
        cbm_tree_scalar_str(output, "warning_slow",
                            "search was slow; narrow file_pattern/path_filter or use a more "
                            "specific pattern");
    }
}

/* TOON emission for compact-mode search results: one row per hit
 * (qn/label/file/lines/matches/degrees — `node` dropped, it duplicates the
 * qn's last segment), a raw[] table for uncorrelated matches, a dirs[]
 * distribution table, and the summary scalars. */
static char *assemble_search_output_toon(search_result_t *sr, int sr_count, grep_match_t *raw,
                                         int raw_count, int gm_count, int limit,
                                         bool warn_literal_pipe, uint64_t elapsed_ms) {
    cbm_sb_t output;
    cbm_sb_init(&output);
    int output_count = sr_count < limit ? sr_count : limit;
    search_toon_add_result_rows(&output, sr, output_count);
    search_toon_add_raw_rows(&output, raw, raw_count);
    search_toon_add_directory_rows(&output, sr, sr_count);
    search_toon_add_summary(&output, sr_count, raw_count, gm_count, warn_literal_pipe, elapsed_ms);
    return cbm_sb_finish(&output);
}

static void search_output_add_columns(yyjson_mut_doc *doc, yyjson_mut_val *root, int mode) {
    static const char *const columns[] = {"qn", "label", "file", "lines", "matches", "in", "out"};
    yyjson_mut_val *json_columns = yyjson_mut_arr(doc);
    for (size_t index = 0; index < sizeof(columns) / sizeof(columns[0]); index++) {
        yyjson_mut_arr_add_str(doc, json_columns, columns[index]);
    }
    if (mode == SEARCH_OUTPUT_MODE_FULL) {
        yyjson_mut_arr_add_str(doc, json_columns, "source");
    }
    yyjson_mut_obj_add_val(doc, root, "cols", json_columns);
}

static void search_output_append_result(yyjson_mut_doc *doc, yyjson_mut_val *rows,
                                        search_result_t *result, int mode, int context_lines,
                                        const char *root_path) {
    char lines[CBM_SZ_32];
    sg_lines_str(lines, sizeof(lines), result->start_line, result->end_line);
    yyjson_mut_val *row = yyjson_mut_arr(doc);
    yyjson_mut_arr_add_strcpy(doc, row, result->qualified_name);
    yyjson_mut_arr_add_strcpy(doc, row, result->label);
    yyjson_mut_arr_add_strcpy(doc, row, result->file);
    yyjson_mut_arr_add_strcpy(doc, row, lines);
    yyjson_mut_val *match_lines = yyjson_mut_arr(doc);
    for (int index = 0; index < result->match_count; index++) {
        yyjson_mut_arr_add_int(doc, match_lines, result->match_lines[index]);
    }
    yyjson_mut_arr_add_val(row, match_lines);
    yyjson_mut_arr_add_int(doc, row, result->in_degree);
    yyjson_mut_arr_add_int(doc, row, result->out_degree);
    if (mode == SEARCH_OUTPUT_MODE_FULL) {
        yyjson_mut_val *source = yyjson_mut_obj(doc);
        attach_result_source(doc, source, result, mode, context_lines, root_path);
        yyjson_mut_arr_add_val(row, source);
    }
    yyjson_mut_arr_add_val(rows, row);
}

static void search_output_add_results(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                      search_result_t *results, int result_count, int mode,
                                      int context_lines, const char *root_path) {
    search_output_add_columns(doc, root, mode);
    yyjson_mut_val *rows = yyjson_mut_arr(doc);
    for (int index = 0; index < result_count; index++) {
        search_output_append_result(doc, rows, &results[index], mode, context_lines, root_path);
    }
    yyjson_mut_obj_add_val(doc, root, "rows", rows);
}

static void search_output_add_raw_matches(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                          const grep_match_t *raw, int raw_count) {
    static const char *const columns[] = {"file", "line", "content"};
    yyjson_mut_val *section = yyjson_mut_obj(doc);
    yyjson_mut_val *json_columns = yyjson_mut_arr(doc);
    for (size_t index = 0; index < sizeof(columns) / sizeof(columns[0]); index++) {
        yyjson_mut_arr_add_str(doc, json_columns, columns[index]);
    }
    yyjson_mut_obj_add_val(doc, section, "cols", json_columns);
    yyjson_mut_val *rows = yyjson_mut_arr(doc);
    int output_count = raw_count < SEARCH_OUTPUT_RAW_LIMIT ? raw_count : SEARCH_OUTPUT_RAW_LIMIT;
    for (int index = 0; index < output_count; index++) {
        yyjson_mut_val *row = yyjson_mut_arr(doc);
        yyjson_mut_arr_add_str(doc, row, raw[index].file);
        yyjson_mut_arr_add_int(doc, row, raw[index].line);
        yyjson_mut_arr_add_str(doc, row, raw[index].content);
        yyjson_mut_arr_add_val(rows, row);
    }
    yyjson_mut_obj_add_val(doc, section, "rows", rows);
    yyjson_mut_obj_add_val(doc, root, "raw_matches", section);
}

static void search_output_add_summary(yyjson_mut_doc *doc, yyjson_mut_val *root, int result_count,
                                      int raw_count, int grep_match_count, uint64_t elapsed_ms) {
    yyjson_mut_obj_add_int(doc, root, "total_grep_matches", grep_match_count);
    yyjson_mut_obj_add_int(doc, root, "total_results", result_count);
    yyjson_mut_obj_add_int(doc, root, "raw_match_count", raw_count);
    yyjson_mut_obj_add_int(doc, root, "elapsed_ms", (int)elapsed_ms);
    if (result_count > 0 && grep_match_count > 0) {
        char ratio[CBM_SZ_32];
        snprintf(ratio, sizeof(ratio), "%.1fx",
                 (double)grep_match_count / (double)(result_count + raw_count));
        yyjson_mut_obj_add_strcpy(doc, root, "dedup_ratio", ratio);
    }
}

static void search_output_add_warnings(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                       bool warn_literal_pipe, uint64_t elapsed_ms) {
    yyjson_mut_val *warnings = yyjson_mut_arr(doc);
    if (warn_literal_pipe) {
        yyjson_mut_arr_add_strcpy(
            doc, warnings,
            "pattern contains '|' but regex=false, so it is matched literally (not as "
            "alternation). Pass regex=true for 'foo|bar' to mean 'foo OR bar'.");
    }
    if (elapsed_ms >= SEARCH_OUTPUT_SLOW_MS) {
        char slow[CBM_SZ_128];
        snprintf(slow, sizeof(slow),
                 "search took %dms (>%ds); narrow file_pattern/path_filter or use a more "
                 "specific pattern",
                 (int)elapsed_ms, SEARCH_OUTPUT_SLOW_MS / 1000);
        yyjson_mut_arr_add_strcpy(doc, warnings, slow);
        char elapsed_text[CBM_SZ_32];
        snprintf(elapsed_text, sizeof(elapsed_text), "%d", (int)elapsed_ms);
        cbm_log_warn("search.slow", "elapsed_ms", elapsed_text);
    }
    if (yyjson_mut_arr_size(warnings) > 0) {
        yyjson_mut_obj_add_val(doc, root, "warnings", warnings);
    }
}

/* Phase 4: assemble JSON output from search results */
static char *assemble_search_output(search_result_t *sr, int sr_count, grep_match_t *raw,
                                    int raw_count, int gm_count, int limit, int mode,
                                    int context_lines, const char *root_path,
                                    bool warn_literal_pipe, uint64_t elapsed_ms) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root_obj = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root_obj);

    int output_count = sr_count < limit ? sr_count : limit;

    if (mode == SEARCH_OUTPUT_MODE_FILES) {
        yyjson_mut_obj_add_val(doc, root_obj, "files",
                               build_dedup_files_array(doc, sr, output_count, raw, raw_count));
    } else {
        search_output_add_results(doc, root_obj, sr, output_count, mode, context_lines, root_path);
        search_output_add_raw_matches(doc, root_obj, raw, raw_count);
    }

    yyjson_mut_obj_add_val(doc, root_obj, "directories", build_dir_distribution(doc, sr, sr_count));
    search_output_add_summary(doc, root_obj, sr_count, raw_count, gm_count, elapsed_ms);
    search_output_add_warnings(doc, root_obj, warn_literal_pipe, elapsed_ms);

    char *json = yy_doc_to_str(doc);
    if (json) {
        sanitize_ascii(json);
    }
    yyjson_mut_doc_free(doc);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* Read grep output from fp, parse file:line:content format, apply path filter,
 * and return a dynamically-allocated grep_match_t array. */
/* Strip root path prefix from a file path. */
static const char *strip_root_prefix(const char *path, const char *root, size_t root_len) {
    if (strncmp(path, root, root_len) != 0) {
        return path;
    }
    const char *p = path + root_len;
    if (*p == '/') {
        p++;
    }
    return p;
}

static grep_match_t *collect_grep_matches(FILE *fp, const char *root_path, size_t root_len,
                                          bool has_path_filter, cbm_regex_t *path_regex,
                                          int grep_limit, int *out_count) {
    size_t gm_cap = CBM_SZ_64;
    int gm_count = 0;
    grep_match_t *gm = malloc(gm_cap * sizeof(grep_match_t));
    char line[CBM_SZ_2K];

    while (fgets(line, sizeof(line), fp) && gm_count < grep_limit) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - SKIP_ONE] == '\n' || line[len - SKIP_ONE] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }

        /* PowerShell output uses tab as delimiter (paths may contain colons
         * on Windows, e.g. C:\dir\file). Unix grep uses colon. */
#ifdef _WIN32
        char sep = '\t';
#else
        char sep = ':';
#endif
        char *sep1 = strchr(line, (unsigned char)sep);
        if (!sep1) {
            continue;
        }
        char *sep2 = strchr(sep1 + SKIP_ONE, (unsigned char)sep);
        if (!sep2) {
            continue;
        }
        *sep1 = '\0';
        *sep2 = '\0';

#ifdef _WIN32
        cbm_normalize_path_sep(line);
#endif
        const char *path = line;
        const char *file = strip_root_prefix(path, root_path, root_len);

        if (has_path_filter && cbm_regexec(path_regex, file, 0, NULL, 0) != CBM_REG_OK) {
            continue;
        }

        safe_grow(gm, gm_count, gm_cap, PAIR_LEN);
        snprintf(gm[gm_count].file, sizeof(gm[0].file), "%s", file);
        gm[gm_count].line = (int)strtol(sep1 + SKIP_ONE, NULL, CBM_DECIMAL_BASE);
        snprintf(gm[gm_count].content, sizeof(gm[0].content), "%s", sep2 + SKIP_ONE);
        sanitize_ascii(gm[gm_count].content);
        gm_count++;
    }

    *out_count = gm_count;
    return gm;
}

/* Find the tightest node containing a line in a file. Returns index or -1. */
static int find_tightest_node(cbm_node_t *nodes, int count, int line) {
    int best = CBM_NOT_FOUND;
    int best_span = MAX_LINE_SPAN;
    for (int j = 0; j < count; j++) {
        if (nodes[j].start_line <= line && nodes[j].end_line >= line) {
            int span = nodes[j].end_line - nodes[j].start_line;
            if (span < best_span) {
                best = j;
                best_span = span;
            }
        }
    }
    return best;
}

/* Add a grep hit to the search result set (merge into existing or create new). */
static void add_to_search_results(search_result_t **sr, int *sr_count, size_t *sr_cap,
                                  cbm_node_t *n, int line) {
    for (int j = 0; j < *sr_count; j++) {
        if ((*sr)[j].node_id == n->id) {
            if ((*sr)[j].match_count < CBM_SZ_64) {
                (*sr)[j].match_lines[(*sr)[j].match_count++] = line;
            }
            return;
        }
    }
    if ((size_t)*sr_count >= *sr_cap) {
        *sr_cap *= PAIR_LEN;
        *sr = cbm_realloc_or_abort(*sr, *sr_cap * sizeof(search_result_t));
        memset(&(*sr)[*sr_count], 0, (*sr_cap - (size_t)*sr_count) * sizeof(search_result_t));
    }
    search_result_t *r = &(*sr)[*sr_count];
    r->node_id = n->id;
    snprintf(r->node_name, sizeof(r->node_name), "%s", n->name);
    snprintf(r->qualified_name, sizeof(r->qualified_name), "%s", n->qualified_name);
    snprintf(r->label, sizeof(r->label), "%s", n->label);
    snprintf(r->file, sizeof(r->file), "%s", n->file_path);
    r->start_line = n->start_line;
    r->end_line = n->end_line;
    r->match_lines[0] = line;
    r->match_count = SKIP_ONE;
    (*sr_count)++;
}

/* Match a single grep hit to the tightest containing node, then add to sr or raw. */
static void classify_grep_hit(grep_match_t *hit, cbm_node_t *file_nodes, int file_node_count,
                              search_result_t **sr, int *sr_count, size_t *sr_cap,
                              grep_match_t **raw, int *raw_count, size_t *raw_cap) {
    int best = find_tightest_node(file_nodes, file_node_count, hit->line);
    if (best >= 0) {
        add_to_search_results(sr, sr_count, sr_cap, &file_nodes[best], hit->line);
    } else {
        if ((size_t)*raw_count >= *raw_cap) {
            *raw_cap = (*raw_cap == 0) ? CBM_SZ_32 : *raw_cap * PAIR_LEN;
            *raw = cbm_realloc_or_free(*raw, *raw_cap * sizeof(grep_match_t));
        }
        if (*raw) {
            (*raw)[(*raw_count)++] = *hit;
        }
    }
}

/* Free a file_nodes array returned from cbm_store_find_nodes_by_file. */
static void free_file_nodes(cbm_node_t *nodes, int count) {
    for (int j = 0; j < count; j++) {
        safe_str_free(&nodes[j].project);
        safe_str_free(&nodes[j].label);
        safe_str_free(&nodes[j].name);
        safe_str_free(&nodes[j].qualified_name);
        safe_str_free(&nodes[j].file_path);
        safe_str_free(&nodes[j].properties_json);
    }
    free(nodes);
}

/* Classify all grep matches file-by-file into search results and raw hits. */
static void classify_all_grep_hits(grep_match_t *gm, int gm_count, cbm_store_t *store,
                                   const char *project, search_result_t **sr, int *sr_count,
                                   size_t *sr_cap, grep_match_t **raw, int *raw_count,
                                   size_t *raw_cap) {
    qsort(gm, (size_t)gm_count, sizeof(grep_match_t), (int (*)(const void *, const void *))strcmp);
    int i = 0;
    while (i < gm_count) {
        const char *cur_file = gm[i].file;
        int file_start = i;
        while (i < gm_count && strcmp(gm[i].file, cur_file) == 0) {
            i++;
        }
        cbm_node_t *file_nodes = NULL;
        int file_node_count = 0;
        if (store) {
            cbm_store_find_nodes_by_file(store, project, cur_file, &file_nodes, &file_node_count);
        }
        for (int mi = file_start; mi < i; mi++) {
            classify_grep_hit(&gm[mi], file_nodes, file_node_count, sr, sr_count, sr_cap, raw,
                              raw_count, raw_cap);
        }
        free_file_nodes(file_nodes, file_node_count);
    }
}

/* Write indexed file list for scoped grep. Returns true if scoped.
 * When a path_filter is provided, apply it here — before grep — so large
 * indexed projects do not scan files only for collect_grep_matches to discard
 * them later. The predicate is IDENTICAL to the post-grep filter: the same
 * compiled regex run against the same root-relative path (separators
 * normalized on Windows first), so prefiltering can only skip files whose
 * hits would be dropped anyway — results-preserving by construction.
 * *out_written receives the number of records written (0 = the filter
 * excluded every indexed file).
 *
 * `fl` is the caller's already-open binary stream on the descriptor cbm_mkstemp
 * created inside the private scratch directory; this function never opens or
 * closes it, so the list is never reachable through a predictable pathname. */
static bool write_scoped_filelist(cbm_mcp_server_t *srv, const char *project, const char *root_path,
                                  FILE *fl, bool has_path_filter, cbm_regex_t *path_regex,
                                  int *out_written) {
    *out_written = 0;
    cbm_store_t *pre_store = resolve_store(srv, project);
    if (!pre_store) {
        return false;
    }
    char **indexed_files = NULL;
    int indexed_count = 0;
    if (cbm_store_list_files(pre_store, project, &indexed_files, &indexed_count) != CBM_STORE_OK ||
        indexed_count == 0) {
        return false;
    }
    bool ok = false;
    int written = 0;
    if (fl) {
        for (int fi = 0; fi < indexed_count; fi++) {
            /* A source path never legitimately contains a newline or carriage
             * return. Those bytes are exactly the record separator on the
             * Windows filelist (and would split naive line readers elsewhere),
             * so a crafted indexed path with an embedded newline could inject
             * an extra entry into the scan set. Skip such paths entirely. */
            if (strpbrk(indexed_files[fi], "\r\n") != NULL) {
                continue;
            }
            if (has_path_filter && path_regex) {
#ifdef _WIN32
                cbm_normalize_path_sep(indexed_files[fi]);
#endif
                if (cbm_regexec(path_regex, indexed_files[fi], 0, NULL, 0) != CBM_REG_OK) {
                    continue;
                }
            }
            /* Write "<root>/<file>" piece-by-piece (no fixed-size buffer, so an
             * arbitrarily long absolute path cannot overflow). Forward slash join
             * so xargs doesn't treat Windows backslashes as escapes; binary mode
             * (wb) prevents CRLF translation. Record separator differs by platform:
             *   - Unix: NUL, consumed by `xargs -0` — handles spaces in paths (a
             *     newline separator would split plain xargs on the space).
             *   - Windows: newline, consumed by PowerShell `Get-Content |
             *     Select-String -LiteralPath` (NUL bytes break Get-Content). */
            (void)fwrite(root_path, 1, strlen(root_path), fl);
            (void)fputc('/', fl);
            (void)fwrite(indexed_files[fi], 1, strlen(indexed_files[fi]), fl);
#ifdef _WIN32
            (void)fputc('\n', fl);
#else
            (void)fputc('\0', fl);
#endif
            written++;
        }
        /* The stream stays open — the caller owns it and closes it (flushing
         * these records to disk) before the grep subprocess reads the list. */
        ok = true;
    }
    for (int fi = 0; fi < indexed_count; fi++) {
        free(indexed_files[fi]);
    }
    free(indexed_files);
    *out_written = written;
    return ok;
}

/* Parse search mode string (0=compact, 1=full, 2=files). */
static int parse_search_mode(const char *mode_str) {
    if (!mode_str) {
        return 0;
    }
    if (strcmp(mode_str, "full") == 0) {
        return SKIP_ONE;
    }
    if (strcmp(mode_str, "files") == 0) {
        return MCP_RETURN_2;
    }
    return 0;
}

/* Validate shell-safe arguments for search. */
/* Search/grep paths and globs are ALWAYS single-quoted (POSIX sh) or
 * double-/single-quoted (Windows cmd/PowerShell) on the command line, which
 * neutralises '&' — a very common character in real paths (R&D, "Foo & Bar",
 * OneDrive). Accept '&' here while still rejecting every metacharacter that
 * could break out of the quoting (#272). */
static bool validate_search_path_arg(const char *s) {
    if (!s) {
        return false;
    }
    for (const char *p = s; *p; p++) {
        switch (*p) {
        case '\'':
        case '"':
        case ';':
        case '|':
        case '$':
        case '`':
        case '<':
        case '>':
        case '\n':
        case '\r':
#ifndef _WIN32
        case '\\':
#endif
            return false;
        default:
            break;
        }
    }
    return true;
}

/* These characters retain command-language meaning inside quoted cmd.exe
 * arguments: percent expands environment variables, exclamation can expand
 * delayed variables, and caret changes parsing. Never interpolate them from a
 * stored project root or request branch into the Windows detect_changes payload.
 * /V:OFF is defense in depth for exclamation; validation remains the boundary. */
static bool validate_windows_cmd_interpolation_arg(const char *s) {
#ifdef _WIN32
    return s && strpbrk(s, "%!^") == NULL;
#else
    return s != NULL;
#endif
}

static bool validate_search_args(const char *root_path, const char *file_pattern) {
    if (!validate_search_path_arg(root_path)) {
        return false;
    }
    if (file_pattern && !validate_search_path_arg(file_pattern)) {
        return false;
    }
    return true;
}

/* Private scratch for one search_code scan: the grep -f pattern file and the
 * scoped file list.
 *
 * Both used to be fixed, guessable paths derived from the pid —
 * "<tmp>/cbm_search_<pid>.pat" and its ".files" companion — opened with a plain
 * fopen. Another local user could pre-plant a symlink at either name and
 * redirect the write; two searches in the same process could also collide on
 * them. Now both live inside a directory created by cbm_mkdtemp (0700 on POSIX,
 * an explicit owner-only DACL on Windows) under an unguessable XXXXXX suffix,
 * and each file is created by cbm_mkstemp — O_CREAT|O_EXCL at mode 0600, so the
 * create fails rather than following anything already at the name. Every write
 * goes through the descriptor cbm_mkstemp returned; neither path is ever
 * reopened by name.
 *
 * Sizing: cbm_mkdtemp copies its expanded result back into `dir`, and its own
 * internal buffer is CBM_SZ_512, so `dir` must be at least that big to receive
 * it. The two file paths are `dir` plus a short basename. */
typedef struct {
    char dir[CBM_SZ_512];
    char pattern_path[CBM_SZ_1K];
    char filelist_path[CBM_SZ_1K];
    FILE *filelist; /* held open for write_scoped_filelist; closed by the caller */
} search_scratch_t;

/* Create <scratch>/<basename>-XXXXXX exclusively and return a stream on the
 * descriptor. On failure `path_out` is emptied so cleanup skips it. */
static FILE *search_scratch_file(const char *dir, const char *basename, char *path_out,
                                 size_t path_sz) {
    path_out[0] = '\0';
    int written = snprintf(path_out, path_sz, "%s/%s-XXXXXX", dir, basename);
    if (written <= 0 || (size_t)written >= path_sz) {
        path_out[0] = '\0';
        return NULL;
    }
    int descriptor = cbm_mkstemp(path_out);
    if (descriptor < 0) {
        path_out[0] = '\0';
        return NULL;
    }
    /* Binary mode: the file list uses an explicit per-platform record separator
     * (NUL for xargs -0, newline for PowerShell) that CRLF translation would
     * corrupt — the same reason the previous code opened it "wb". */
    FILE *stream = mcp_fdopen(descriptor, "wb");
    if (!stream) {
        (void)mcp_close(descriptor);
        (void)cbm_unlink(path_out);
        path_out[0] = '\0';
    }
    return stream;
}

/* Anchored cleanup: removes both scratch files and the private directory. Safe
 * to call more than once and on any partially-initialised scratch, so every
 * exit from handle_search_code can call it unconditionally. rmdir succeeding is
 * itself the proof nothing was left inside. */
static void search_scratch_close(search_scratch_t *scratch) {
    if (scratch->filelist) {
        (void)fclose(scratch->filelist);
        scratch->filelist = NULL;
    }
    if (scratch->pattern_path[0] != '\0') {
        (void)cbm_unlink(scratch->pattern_path);
        scratch->pattern_path[0] = '\0';
    }
    if (scratch->filelist_path[0] != '\0') {
        (void)cbm_unlink(scratch->filelist_path);
        scratch->filelist_path[0] = '\0';
    }
    if (scratch->dir[0] != '\0') {
        (void)cbm_rmdir(scratch->dir);
        scratch->dir[0] = '\0';
    }
}

/* Open the scratch directory, write `pattern` to the grep -f file, and leave the
 * file list open for write_scoped_filelist. Returns true on success; on failure
 * everything already created is removed before returning. */
static bool search_scratch_open(search_scratch_t *scratch, const char *pattern) {
    scratch->dir[0] = '\0';
    scratch->pattern_path[0] = '\0';
    scratch->filelist_path[0] = '\0';
    scratch->filelist = NULL;

    int written =
        snprintf(scratch->dir, sizeof(scratch->dir), "%s/cbm-search-XXXXXX", cbm_tmpdir());
    if (written <= 0 || (size_t)written >= sizeof(scratch->dir) || !cbm_mkdtemp(scratch->dir)) {
        scratch->dir[0] = '\0';
        return false;
    }

    FILE *pattern_file = search_scratch_file(scratch->dir, "pat", scratch->pattern_path,
                                             sizeof(scratch->pattern_path));
    if (!pattern_file) {
        search_scratch_close(scratch);
        return false;
    }
    bool ok = fprintf(pattern_file, "%s\n", pattern) >= 0;
    ok = fclose(pattern_file) == 0 && ok;
    if (!ok) {
        search_scratch_close(scratch);
        return false;
    }

    scratch->filelist = search_scratch_file(scratch->dir, "files", scratch->filelist_path,
                                            sizeof(scratch->filelist_path));
    if (!scratch->filelist) {
        search_scratch_close(scratch);
        return false;
    }
    return true;
}

/* Compile a path filter regex. Returns true if compiled successfully. */
static bool compile_path_filter(const char *filter, cbm_regex_t *re) {
    if (!filter || !filter[0]) {
        return false;
    }
    return cbm_regcomp(re, filter, CBM_REG_EXTENDED | CBM_REG_NOSUB) == CBM_REG_OK;
}

enum { SEARCH_LITERAL_REGEX_MAX_EXPANSION = 3 };

static char *search_literal_words_to_regex(const char *pattern) {
    size_t pattern_length = strlen(pattern);
    char *regex_pattern =
        malloc((pattern_length * SEARCH_LITERAL_REGEX_MAX_EXPANSION) + MCP_STRING_TERMINATOR_BYTES);
    if (!regex_pattern) {
        return NULL;
    }
    char *destination = regex_pattern;
    bool in_space = false;
    for (const char *source = pattern; *source; source++) {
        if (*source == ' ' || *source == '\t') {
            if (!in_space) {
                *destination++ = '.';
                *destination++ = '*';
                in_space = true;
            }
        } else {
            if (strchr("\\^$.|?*+()[]{}", *source)) {
                *destination++ = '\\';
            }
            *destination++ = *source;
            in_space = false;
        }
    }
    *destination = '\0';
    return regex_pattern;
}

static bool search_regex_is_valid(const char *pattern) {
    cbm_regex_t probe;
    if (cbm_regcomp(&probe, pattern, CBM_REG_EXTENDED | CBM_REG_NOSUB) != CBM_REG_OK) {
        return false;
    }
    cbm_regfree(&probe);
    return true;
}

static bool search_has_invalid_regex(bool use_regex, const char *pattern) {
    return use_regex && !search_regex_is_valid(pattern);
}

static void search_apply_degree_counts(cbm_store_t *store, search_result_t *results,
                                       int result_count) {
    if (!store || result_count <= 0) {
        return;
    }
    int64_t *ids = malloc((size_t)result_count * sizeof(*ids));
    int *in_degrees = malloc((size_t)result_count * sizeof(*in_degrees));
    int *out_degrees = malloc((size_t)result_count * sizeof(*out_degrees));
    for (int index = 0; index < result_count; index++) {
        ids[index] = results[index].node_id;
    }
    if (cbm_store_batch_count_degrees(store, ids, result_count, "CALLS", in_degrees, out_degrees) ==
        CBM_STORE_OK) {
        for (int index = 0; index < result_count; index++) {
            results[index].in_degree = in_degrees[index];
            results[index].out_degree = out_degrees[index];
        }
    }
    free(ids);
    free(in_degrees);
    free(out_degrees);
}

static void search_score_and_sort_results(search_result_t *results, int result_count) {
    for (int index = 0; index < result_count; index++) {
        results[index].score = compute_search_score(&results[index]);
    }
    if (result_count > SKIP_ONE) {
        qsort(results, (size_t)result_count, sizeof(*results), search_result_cmp);
    }
}

static char *search_render_result(const char *args, search_result_t *results, int result_count,
                                  grep_match_t *raw, int raw_count, int grep_match_count, int limit,
                                  int mode, int context_lines, const char *root_path,
                                  bool warn_literal_pipe, uint64_t elapsed_ms) {
    char *format = cbm_mcp_get_string_arg(args, "format");
    bool use_json = format && strcmp(format, "json") == 0;
    free(format);
    if (mode != 0 || use_json) {
        return assemble_search_output(results, result_count, raw, raw_count, grep_match_count,
                                      limit, mode, context_lines, root_path, warn_literal_pipe,
                                      elapsed_ms);
    }
    char *toon =
        assemble_search_output_toon(results, result_count, raw, raw_count, grep_match_count, limit,
                                    warn_literal_pipe, elapsed_ms);
    char *result = cbm_mcp_text_result(toon ? toon : "out of memory", toon == NULL);
    free(toon);
    return result;
}

static char *handle_search_code(cbm_mcp_server_t *srv, const char *args) {
    char *pattern = cbm_mcp_get_string_arg(args, "pattern");
    char *project = get_project_arg(args);
    char *file_pattern = cbm_mcp_get_string_arg(args, "file_pattern");
    char *path_filter = cbm_mcp_get_string_arg(args, "path_filter");
    char *mode_str = cbm_mcp_get_string_arg(args, "mode");
    int limit = cbm_mcp_get_int_arg(args, "limit", MCP_DEFAULT_LIMIT);
    int context_lines = cbm_mcp_get_int_arg(args, "context", 0);
    bool use_regex = cbm_mcp_get_bool_arg(args, "regex");
    uint64_t search_t0 = cbm_now_ms();
    /* In literal (non-regex) mode a '|' is matched as a byte, not alternation —
     * a common silent 0-match trap; flagged in the result warnings (#282). */
    bool pat_has_pipe = pattern && strchr(pattern, '|') != NULL;

    int mode = parse_search_mode(mode_str);
    free(mode_str);

    cbm_regex_t path_regex;
    bool has_path_filter = compile_path_filter(path_filter, &path_regex);
    free(path_filter);
    path_filter = NULL;

    if (!pattern) {
        free(project);
        free(file_pattern);
        return cbm_mcp_text_result("pattern is required", true);
    }

    /* Project is required */
    if (!project) {
        free(pattern);
        free(file_pattern);
        char *_err = build_project_list_error("project is required");
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        return _res;
    }

    char *root_path = get_project_root(srv, project);
    if (!root_path) {
        free(pattern);
        free(project);
        free(file_pattern);
        char *_err = build_project_list_error("project not found or not indexed");
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        return _res;
    }

    if (!validate_search_args(root_path, file_pattern)) {
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        free(root_path);
        free(pattern);
        free(project);
        free(file_pattern);
        return cbm_mcp_text_result("path or file_pattern contains invalid characters", true);
    }

    /* issue #283: when regex=true, a syntactically invalid pattern (e.g. an
     * unclosed group) makes the underlying grep fail, which the handler would
     * otherwise report as an empty result set — indistinguishable from a
     * legitimate no-match. Validate the user's regex up front and return an
     * explicit error so callers can tell "broken pattern" from "no matches". */
    if (search_has_invalid_regex(use_regex, pattern)) {
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        free(root_path);
        free(pattern);
        free(project);
        free(file_pattern);
        return cbm_mcp_text_result(
            "invalid regex pattern (regex=true): check for unbalanced (), [], or {}", true);
    }

    /* ── Phase 0.5: Multi-word → regex conversion ───────────── */
    /* If pattern contains whitespace and is not already a regex, convert to a
     * regex that matches all words in order: "foo bar baz" → "foo.*bar.*baz".
     * This avoids requiring the exact phrase as a contiguous substring. */
    if (!use_regex && strchr(pattern, ' ')) {
        char *regex_pat = search_literal_words_to_regex(pattern);
        if (regex_pat) {
            free(pattern);
            pattern = regex_pat;
            use_regex = true;
        }
    }

    /* ── Phase 1: Grep scan ──────────────────────────────────── */
    search_scratch_t scratch;
    if (!search_scratch_open(&scratch, pattern)) {
        char errmsg[CBM_SZ_256];
        snprintf(errmsg, sizeof(errmsg), "search failed: cannot create temp file (%s)",
                 strerror(errno));
        free(root_path);
        free(pattern);
        free(project);
        free(file_pattern);
        return cbm_mcp_text_result(errmsg, true);
    }
    const char *tmpfile = scratch.pattern_path;
    const char *filelist = scratch.filelist_path;

    /* No grep-level match limit — let grep find all matches, then dedup and
     * cap in our code. The -m flag caused results from large vendored files
     * to exhaust the quota before reaching project source files. */
    enum { GREP_MAX_MATCHES = 500 };
    int grep_limit = GREP_MAX_MATCHES;

    /* Scope grep to indexed files only — avoids scanning vendored/generated code.
     * Query the graph for distinct file paths, write them to a temp file,
     * then use xargs to pass them to grep. Falls back to recursive grep if
     * no indexed files found (project not fully indexed). */
    bool scoped = false;
    int scoped_written = 0;

    scoped = write_scoped_filelist(srv, project, root_path, scratch.filelist, has_path_filter,
                                   has_path_filter ? &path_regex : NULL, &scoped_written);
    /* Close before grep runs: this is what flushes the records the helper wrote
     * through the descriptor. Clearing the field hands ownership to
     * search_scratch_close, which still unlinks the file itself. */
    (void)fclose(scratch.filelist);
    scratch.filelist = NULL;

    /* Collect grep matches into array */
    int gm_count = 0;
    grep_match_t *gm = NULL;
    if (scoped && scoped_written == 0) {
        /* The path_filter excluded every indexed file — nothing to scan.
         * Skip the grep subprocess: xargs on an empty filelist is
         * platform-dependent (GNU execs grep once with no operands, BSD
         * skips), and the post-grep filter would drop every hit anyway. */
        gm = malloc(sizeof(grep_match_t)); /* empty set; freed below */
        search_scratch_close(&scratch);
    } else {
        char cmd[CBM_SZ_4K];
        build_grep_cmd(cmd, sizeof(cmd), use_regex, scoped, file_pattern, tmpfile, filelist,
                       root_path);

        FILE *fp = cbm_popen(cmd, "r");
        if (!fp) {
            search_scratch_close(&scratch);
            free(root_path);
            free(pattern);
            free(project);
            free(file_pattern);
            return cbm_mcp_text_result("search failed", true);
        }

        gm = collect_grep_matches(fp, root_path, strlen(root_path), has_path_filter, &path_regex,
                                  grep_limit, &gm_count);
        cbm_pclose(fp);
        /* Both scratch files and the private directory go here — unlike the old
         * code, the file list is removed even when the scan was not scoped. */
        search_scratch_close(&scratch);
    }

    /* ── Phase 2+3: Block expansion + graph ranking ──────────── */
    /* Sort grep matches by file for contiguous processing.
     * Then: one SQL query per unique file for nodes, one batch query for all degrees. */

    cbm_store_t *store = resolve_store(srv, project);

    size_t sr_cap = CBM_SZ_32;
    int sr_count = 0;
    search_result_t *sr = calloc(sr_cap, sizeof(search_result_t));

    size_t raw_cap = CBM_SZ_32;
    int raw_count = 0;
    grep_match_t *raw = malloc(raw_cap * sizeof(grep_match_t));

    /* Sort matches by file path for contiguous per-file processing */
    qsort(gm, (size_t)gm_count, sizeof(grep_match_t), (int (*)(const void *, const void *))strcmp);

    classify_all_grep_hits(gm, gm_count, store, project, &sr, &sr_count, &sr_cap, &raw, &raw_count,
                           &raw_cap);

    /* Phase 3: batch degree query — ONE query for all results instead of 2×N */
    search_apply_degree_counts(store, sr, sr_count);

    search_score_and_sort_results(sr, sr_count);

    char *result = search_render_result(args, sr, sr_count, raw, raw_count, gm_count, limit, mode,
                                        context_lines, root_path, pat_has_pipe && !use_regex,
                                        cbm_now_ms() - search_t0);
    free(gm);
    free(sr);
    free(raw);
    free(root_path);
    free(pattern);
    free(project);
    free(file_pattern);
    if (has_path_filter) {
        cbm_regfree(&path_regex);
    }
    return result;
}

/* ── detect_changes ───────────────────────────────────────────── */

/* Run shell-backed query helpers inside the same process-tree containment used
 * by indexing. A plain popen owns only its shell stream: on disconnect there is
 * no safe handle with which to stop a blocked git child or its descendants. */
static bool mcp_command_output_path(char out[CBM_SZ_2K]) {
    char directory[CBM_SZ_1K];
    const char *cache = cbm_resolve_cache_dir();
    int written;
    if (cache && cache[0]) {
        written = snprintf(directory, sizeof(directory), "%s/logs", cache);
        if (written <= 0 || written >= (int)sizeof(directory) || !cbm_mkdir_p(directory, 0700)) {
            return false;
        }
    } else {
        written = snprintf(directory, sizeof(directory), "%s", cbm_tmpdir());
        if (written <= 0 || written >= (int)sizeof(directory)) {
            return false;
        }
    }
    written = snprintf(out, CBM_SZ_2K, "%s/.mcp-command-XXXXXX", directory);
    if (written <= 0 || written >= CBM_SZ_2K) {
        out[0] = '\0';
        return false;
    }
    int descriptor = cbm_mkstemp(out);
    if (descriptor < 0) {
        out[0] = '\0';
        return false;
    }
#ifdef _WIN32
    (void)_close(descriptor);
#else
    (void)close(descriptor);
#endif
    return true;
}

#ifdef _WIN32
/* Resolve the OS-owned command processor without consulting PATH or mutable
 * COMSPEC. cbm_subprocess receives this as lpApplicationName and validates the
 * same absolute cmd.exe path before using the dedicated payload serializer. */
static bool mcp_resolve_windows_cmd(char out[CBM_SZ_4K]) {
    if (!out) {
        return false;
    }
    out[0] = '\0';
    wchar_t system_directory[MAX_PATH + 1];
    UINT directory_length = GetSystemDirectoryW(system_directory, MAX_PATH + 1);
    static const wchar_t suffix[] = L"\\cmd.exe";
    if (directory_length == 0 || directory_length > MAX_PATH ||
        (size_t)directory_length + (sizeof(suffix) / sizeof(suffix[0])) >
            sizeof(system_directory) / sizeof(system_directory[0])) {
        return false;
    }
    memcpy(system_directory + directory_length, suffix, sizeof(suffix));
    char *candidate = cbm_wide_to_utf8(system_directory);
    if (!candidate) {
        return false;
    }
    bool resolved = cbm_canonical_path(candidate, out, CBM_SZ_4K) != 0;
    free(candidate);
    return resolved;
}
#endif

static int mcp_run_shell_command_cancellable(cbm_mcp_server_t *srv, const char *command,
                                             char output_path[CBM_SZ_2K],
                                             cbm_proc_result_t *result_out) {
    if (!srv || !command || !output_path || !result_out || !mcp_command_output_path(output_path)) {
        return -1;
    }
    /* Internal test seam: rejecting after output allocation exercises the same
     * cleanup contract as a contained process-tree failure. */
    if (srv->command_test_hook && !srv->command_test_hook(srv->command_test_context, command)) {
        return -1;
    }
#ifdef _WIN32
    char shell[CBM_SZ_4K];
    if (!mcp_resolve_windows_cmd(shell)) {
        (void)cbm_unlink(output_path);
        output_path[0] = '\0';
        return -1;
    }
#else
    const char *shell = "/bin/sh";
    const char *argv[] = {"sh", "-c", command, NULL};
#endif
    cbm_proc_opts_t options = {
        .bin = shell,
#ifdef _WIN32
        .windows_cmd_payload = command,
#else
        .argv = argv,
#endif
        .log_file = output_path,
        .quiet_timeout_ms = 0,
        .cancel_grace_ms = CBM_SUBPROCESS_DEFAULT_CANCEL_GRACE_MS,
        .delete_log_on_exit = false,
    };
    cbm_subprocess_t *process = NULL;
    if (cbm_subprocess_spawn(&options, &process) != 0) {
        (void)cbm_unlink(output_path);
        output_path[0] = '\0';
        return -1;
    }

    cbm_proc_poll_t state;
    for (;;) {
        if (mcp_request_cancelled(srv)) {
            (void)cbm_subprocess_request_cancel(process);
        }
        state = cbm_subprocess_poll(process, result_out);
        if (state != CBM_PROC_POLL_RUNNING) {
            break;
        }
        cbm_usleep(10000);
    }
    bool contained = state == CBM_PROC_POLL_TERMINAL && result_out->tree_quiesced &&
                     !result_out->supervision_failed;
    cbm_subprocess_destroy(process);
    return contained ? 0 : -1;
}

/* Does `node`'s line range overlap any recorded hunk for `file`? Used to scope
 * seed detection to the actually-changed lines rather than the whole file.
 * Non-static (declared in mcp_internal.h) so tests can exercise the overlap
 * logic directly, matching this file's existing white-box test hooks. */
bool cbm_detect_node_in_hunks(const cbm_node_t *node, const cbm_changed_hunk_t *hunks,
                              int hunk_count, const char *file) {
    for (int h = 0; h < hunk_count; h++) {
        if (strcmp(hunks[h].path, file) == 0 && node->start_line <= hunks[h].end_line &&
            node->end_line >= hunks[h].start_line) {
            return true;
        }
    }
    return false;
}

/* Collect BFS seed ids for one changed file (everything but the structural
 * container labels — those have no CALLS edges). These anchor the
 * multi-source impact traversal.
 *
 * When `hunks` has at least one entry for `file`, only definitions whose line
 * range overlaps a hunk become seeds — a one-line edit inside a single
 * function no longer seeds every other definition in the file. When no hunk
 * is recorded for `file` (a brand-new/untracked file has no comparable
 * "before" state, or the hunk fetch failed/was skipped), every non-container
 * definition in the file is a seed — the previous, whole-file behavior — so
 * this is a precision improvement, not a new failure mode. */
/* Structural container labels carry no CALLS edges and span the whole file, so
 * they are never seeds. Shared by the seeding loop and the overlap probe. */
static bool detect_is_seedable_label(const char *lb) {
    return lb && strcmp(lb, "File") != 0 && strcmp(lb, "Folder") != 0 &&
           strcmp(lb, "Project") != 0 && strcmp(lb, "Module") != 0 && strcmp(lb, "Package") != 0 &&
           strcmp(lb, "Section") != 0;
}

static void detect_collect_seeds(cbm_store_t *store, const char *project, const char *file,
                                 const cbm_changed_hunk_t *hunks, int hunk_count, int64_t **seeds,
                                 int *n, size_t *cap) {
    cbm_node_t *nodes = NULL;
    int ncount = 0;
    cbm_store_find_nodes_by_file(store, project, file, &nodes, &ncount);
    bool scope_to_hunks = false;
    for (int h = 0; h < hunk_count; h++) {
        if (strcmp(hunks[h].path, file) == 0) {
            scope_to_hunks = true;
            break;
        }
    }
    /* A file can have hunks yet no SEEDABLE definition overlapping any of them:
     * an import-only edit, a module-level constant, or a change above the first
     * definition all land outside every definition's line range. Scoping would
     * then drop the file from the seed set entirely — strictly worse recall
     * than the whole-file behavior this replaces. Probe for an overlap first
     * and keep whole-file seeding for that file when there is none.
     *
     * The probe must apply the same label filter as the seeding loop below:
     * container nodes span the whole file (a Module node is lines 1..EOF), so
     * counting them would report an overlap for every hunk and defeat the
     * fallback entirely. */
    if (scope_to_hunks) {
        bool any_overlap = false;
        for (int i = 0; i < ncount && !any_overlap; i++) {
            any_overlap = detect_is_seedable_label(nodes[i].label) &&
                          cbm_detect_node_in_hunks(&nodes[i], hunks, hunk_count, file);
        }
        scope_to_hunks = any_overlap;
    }
    for (int i = 0; i < ncount; i++) {
        if (detect_is_seedable_label(nodes[i].label)) {
            if (scope_to_hunks && !cbm_detect_node_in_hunks(&nodes[i], hunks, hunk_count, file)) {
                continue;
            }
            if ((size_t)*n >= *cap) {
                *cap = *cap ? *cap * 2 : 16;
                *seeds = cbm_realloc_or_abort(*seeds, *cap * sizeof(int64_t));
            }
            (*seeds)[(*n)++] = nodes[i].id;
        }
    }
    cbm_store_free_nodes(nodes, ncount);
}

/* Module key for the impacted rollup = the first TWO path segments
 * ("src/mcp/mcp.c" -> "src/mcp"), a quotient of the blast radius coarse enough
 * to fit yet specific enough to localize (one segment collapses a whole tree
 * to "src"). Falls back to one segment, then the whole path. */
static void detect_module_of(const char *file, char *out, size_t outsz) {
    if (!file || !file[0]) {
        snprintf(out, outsz, "(root)");
        return;
    }
    const char *s1 = strchr(file, '/');
    if (!s1) {
        snprintf(out, outsz, "%s", file);
        return;
    }
    const char *s2 = strchr(s1 + 1, '/');
    size_t len = s2 ? (size_t)(s2 - file) : strlen(file);
    if (len >= outsz) {
        len = outsz - 1;
    }
    memcpy(out, file, len);
    out[len] = '\0';
}

/* Aggregate the impact set into the 2-segment module rollup. Fills up to
 * DETECT_MODCAP (module, count) pairs; symbols beyond the cap land in
 * *overflow (surfaced as "(other)", never silently dropped). Shared by the
 * tree and json emitters so both encodings carry the same model. */
enum { DETECT_MODCAP = 256 };

static int detect_module_rollup(const cbm_traverse_result_t *impact, char mods[][CBM_SZ_128],
                                int *mcnt, int *overflow) {
    int nmods = 0;
    *overflow = 0;
    for (int i = 0; i < impact->visited_count; i++) {
        char m[CBM_SZ_128];
        detect_module_of(impact->visited[i].node.file_path, m, sizeof(m));
        int j = 0;
        for (; j < nmods; j++) {
            if (strcmp(mods[j], m) == 0) {
                mcnt[j]++;
                break;
            }
        }
        if (j == nmods) {
            if (nmods < DETECT_MODCAP) {
                snprintf(mods[nmods], CBM_SZ_128, "%s", m);
                mcnt[nmods] = 1;
                nmods++;
            } else {
                (*overflow)++;
            }
        }
    }
    return nmods;
}

/* Emit the impacted set as a grouped tree leg: rows grouped under their shared
 * (qn-prefix, file), `name label hop` per row. At most `limit` rows are listed
 * (the visited array is hop-ordered, so the closest — highest-signal — impact
 * shows first); impacted_total always carries the exact full count, and
 * `impacted_shown < impacted_total` is the honest truncation signal. The
 * module rollup (emitted by the caller) stays complete regardless. */
static void detect_emit_impacted_tree(cbm_sb_t *sb, cbm_traverse_result_t *tr, int limit) {
    cbm_tree_scalar_int(sb, "impacted_total", tr->visited_count);
    int shown = tr->visited_count < limit ? tr->visited_count : limit;
    /* qn order for stable grouping, but keep hop-closeness: sort by (hop) is
     * lost under qn sort, so group AFTER selecting the nearest `shown` rows —
     * the visited array is already (hop,id)-ordered from the BFS. */
    char hdr[CBM_SZ_128];
    snprintf(hdr, sizeof(hdr),
             "impacted_shown: %d\nimpacted: %d  (rows: name label hop; qn = group prefix + \".\" "
             "+ name; nearest hops first)\n",
             shown, shown);
    cbm_sb_append(sb, hdr);
    if (shown > 1) {
        qsort(tr->visited, (size_t)shown, sizeof(cbm_node_hop_t), tree_hop_cmp_qn);
    }
    char cur_group[CBM_SZ_1K] = "";
    for (int i = 0; i < shown; i++) {
        const char *qn =
            tr->visited[i].node.qualified_name ? tr->visited[i].node.qualified_name : "";
        const char *file = tr->visited[i].node.file_path ? tr->visited[i].node.file_path : "";
        size_t plen = sg_qn_prefix_len(qn);
        char group[CBM_SZ_1K];
        snprintf(group, sizeof(group), "%.*s (%s)", (int)plen, qn, file);
        if (strcmp(group, cur_group) != 0) {
            snprintf(cur_group, sizeof(cur_group), "%s", group);
            cbm_sb_append(sb, group);
            cbm_sb_append(sb, ":\n");
        }
        char row[CBM_SZ_512];
        snprintf(row, sizeof(row), "  %s %s %d\n", plen ? qn + plen + 1 : qn,
                 tr->visited[i].node.label ? tr->visited[i].node.label : "", tr->visited[i].hop);
        cbm_sb_append(sb, row);
    }
    if (shown < tr->visited_count) {
        char more[CBM_SZ_256];
        snprintf(more, sizeof(more),
                 "impacted_omitted: %d  (see impacted_modules for the full rollup; raise 'limit' "
                 "or lower 'depth' to see specifics)\n",
                 tr->visited_count - shown);
        cbm_sb_append(sb, more);
    }
}

static char *handle_detect_changes(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    char *base_branch = cbm_mcp_get_string_arg(args, "base_branch");
    char *since = cbm_mcp_get_string_arg(args, "since");
    char *scope = cbm_mcp_get_string_arg(args, "scope");
    int depth = cbm_mcp_get_int_arg(args, "depth", MCP_DEFAULT_BFS_DEPTH);
    depth = clamp_mcp_depth(depth, "detect_changes");

    /* scope: "files" = just changed files, "symbols" = files + symbols (default) */
    bool want_symbols = !scope || strcmp(scope, "symbols") == 0 || strcmp(scope, "impact") == 0;

    /* `since` (e.g. "HEAD~10", "v0.5.0") is the documented diff base but was
     * previously parsed and never used: it takes precedence over base_branch.
     * Route it through base_branch so the shared shell-arg validation and the
     * existing `<base>...HEAD` (three-dot) diff apply unchanged — `since` thus
     * adopts the same merge-base semantics base_branch already uses. */
    if (since && since[0]) {
        free(base_branch);
        base_branch = since; /* transfer ownership */
        since = NULL;
    }
    free(since); /* no-op after the swap (since is NULL); frees it otherwise */

    if (!base_branch) {
        base_branch = heap_strdup("main");
    }

    /* Reject shell metacharacters, and a leading '-', in the user-supplied
     * branch name. base_branch is spliced into `git diff --name-only
     * "<base>"...HEAD`; a value starting with '-' would be read by git as an
     * option rather than a ref (e.g. `--output=<path>` writes the diff to an
     * arbitrary file). A real git ref never begins with '-'. */
    if (!cbm_validate_shell_arg(base_branch) || base_branch[0] == '-' ||
        !validate_windows_cmd_interpolation_arg(base_branch)) {
        free(project);
        free(base_branch);
        free(scope);
        return cbm_mcp_text_result("base_branch contains invalid characters", true);
    }

    char *root_path = get_project_root(srv, project);
    if (!root_path) {
        char *err = build_no_store_error(project);
        char *res = cbm_mcp_text_result(err, true);
        free(err);
        free(project);
        free(base_branch);
        free(scope);
        return res;
    }

    if (!validate_search_path_arg(root_path) ||
        !validate_windows_cmd_interpolation_arg(root_path)) {
        free(root_path);
        free(project);
        free(base_branch);
        free(scope);
        return cbm_mcp_text_result("project path contains invalid characters", true);
    }

    /* Get changed files via git (-C avoids cd + quoting issues on Windows).
     * Three sources are merged:
     *   1. committed changes vs base   (diff <base>...HEAD)
     *   2. unstaged tracked changes    (diff)
     *   3. untracked + staged-new files (status --porcelain) — these are
     *      invisible to `git diff` and were silently missed before, so a
     *      brand-new file never appeared until a manual re-index (#520).
     * status --porcelain prefixes each path with a 2-char code + space
     * ("?? path", "A  path"); the prefix is stripped when parsing below. */
    char cmd[CBM_SZ_2K];
#ifdef _WIN32
    snprintf(cmd, sizeof(cmd),
             "git -C \"%s\" diff --name-only \"%s\"...HEAD 2>NUL & "
             "git -C \"%s\" diff --name-only 2>NUL & "
             "git --no-optional-locks -C \"%s\" status --porcelain "
             "--untracked-files=normal 2>NUL",
             root_path, base_branch, root_path, root_path);
#else
    snprintf(cmd, sizeof(cmd),
             "{ git -C '%s' diff --name-only '%s'...HEAD 2>/dev/null; "
             "git -C '%s' diff --name-only 2>/dev/null; "
             "git --no-optional-locks -C '%s' status --porcelain "
             "--untracked-files=normal 2>/dev/null; } | sort -u",
             root_path, base_branch, root_path, root_path);
#endif

    char output_path[CBM_SZ_2K] = {0};
    cbm_proc_result_t git_result = {0};
    int git_run = mcp_run_shell_command_cancellable(srv, cmd, output_path, &git_result);
    bool git_cancelled = git_result.cancellation_requested || mcp_request_cancelled(srv);
    if (git_cancelled) {
        (void)cbm_unlink(output_path);
        free(root_path);
        free(project);
        free(base_branch);
        free(scope);
        return cbm_mcp_text_result("detect_changes cancelled for this request", true);
    }
    if (git_run != 0) {
        (void)cbm_unlink(output_path);
        char errmsg[CBM_SZ_256];
        snprintf(errmsg, sizeof(errmsg),
                 "git diff failed: the contained command could not complete. "
                 "Check that git is installed.");
        free(root_path);
        free(project);
        free(base_branch);
        free(scope);
        return cbm_mcp_text_result(errmsg, true);
    }
    FILE *fp = cbm_fopen(output_path, "rb");
    if (!fp) {
        (void)cbm_unlink(output_path);
        free(root_path);
        free(project);
        free(base_branch);
        free(scope);
        return cbm_mcp_text_result("git diff failed: contained output could not be read", true);
    }

    /* resolve_store already called via get_project_root above */
    cbm_store_t *store = srv->store;

    /* Direction of impact. Default inbound = the BLAST RADIUS: the transitive
     * CALLERS of the changed symbols, which may need review. outbound = what
     * the changed code depends on; both = union. */
    char *direction = cbm_mcp_get_string_arg(args, "direction");
    if (!direction) {
        direction = heap_strdup("inbound");
    }
    /* Teaching error, same contract as trace_path: never silently correct an
     * unknown direction — the caller would misread the result's semantics. */
    if (strcmp(direction, "inbound") != 0 && strcmp(direction, "outbound") != 0 &&
        strcmp(direction, "both") != 0) {
        char errbuf[CBM_SZ_256];
        snprintf(errbuf, sizeof(errbuf),
                 "invalid direction \"%s\" — use \"inbound\" (blast radius: transitive callers), "
                 "\"outbound\" (dependencies), or \"both\"",
                 direction);
        free(direction);
        free(root_path);
        free(project);
        free(base_branch);
        free(scope);
        (void)fclose(fp);
        (void)cbm_unlink(output_path);
        return cbm_mcp_text_result(errbuf, true);
    }
    char *fmt = cbm_mcp_get_string_arg(args, "format");
    bool legacy_json = fmt && strcmp(fmt, "json") == 0;
    free(fmt);

    /* Per-symbol impacted-row display cap (the module rollup stays complete).
     * impacted_total always reports the true count, so this never hides scale. */
    int imp_limit = cbm_mcp_get_int_arg(args, "limit", MCP_DEFAULT_IMPACT_LIMIT);
    if (imp_limit < 1) {
        imp_limit = 1;
    }
    if (imp_limit > MCP_BFS_LIMIT_MAX) {
        imp_limit = MCP_BFS_LIMIT_MAX;
    }

    /* Collect changed file paths into a C array (drives seeds, the rollup, and
     * both output encodings). */
    char **files = NULL;
    int file_count = 0;
    size_t file_cap = 0;
    int64_t *seeds = NULL;
    int seed_count = 0;
    size_t seed_cap = 0;

    /* Hunk line ranges (unified=0 diff), used to scope seed detection to the
     * actually-changed lines instead of every definition in a changed file
     * (see detect_collect_seeds). Best-effort: any failure here just leaves
     * `hunks` empty and every file falls back to its previous whole-file
     * seeding — this is a precision improvement, not a correctness
     * dependency, so it is never treated as a request-level failure.
     *
     * Coordinate systems: `base...HEAD` hunks carry HEAD-side line numbers,
     * the worktree diff carries worktree-side ones, and node line ranges come
     * from the indexed snapshot. These agree while the index is fresh — the
     * watcher reindexes on HEAD movement and on a dirty tree — but a stale
     * index combined with insertions earlier in the file shifts the node lines
     * relative to the hunks and can mis-scope. The failure is bounded by
     * detect_collect_seeds' zero-overlap fallback: a file whose definitions all
     * miss reverts to whole-file seeding rather than dropping out. */
    cbm_changed_hunk_t *hunks = NULL;
    int hunk_count = 0;
    if (want_symbols) {
        char hunk_cmd[CBM_SZ_2K];
#ifdef _WIN32
        snprintf(hunk_cmd, sizeof(hunk_cmd),
                 "git -C \"%s\" diff --unified=0 \"%s\"...HEAD 2>NUL & "
                 "git -C \"%s\" diff --unified=0 2>NUL",
                 root_path, base_branch, root_path);
#else
        snprintf(hunk_cmd, sizeof(hunk_cmd),
                 "{ git -C '%s' diff --unified=0 '%s'...HEAD 2>/dev/null; "
                 "git -C '%s' diff --unified=0 2>/dev/null; }",
                 root_path, base_branch, root_path);
#endif
        char hunk_output_path[CBM_SZ_2K] = {0};
        cbm_proc_result_t hunk_result = {0};
        int hunk_run =
            mcp_run_shell_command_cancellable(srv, hunk_cmd, hunk_output_path, &hunk_result);
        bool hunk_cancelled = hunk_result.cancellation_requested || mcp_request_cancelled(srv);
        FILE *hfp = (!hunk_cancelled && hunk_run == 0) ? cbm_fopen(hunk_output_path, "rb") : NULL;
        if (hfp) {
            (void)fseek(hfp, 0, SEEK_END);
            long hsz = ftell(hfp);
            if (hsz > 0) {
                (void)fseek(hfp, 0, SEEK_SET);
                char *hbuf = malloc((size_t)hsz + SKIP_ONE);
                if (hbuf) {
                    size_t hread = fread(hbuf, SKIP_ONE, (size_t)hsz, hfp);
                    hbuf[hread] = '\0';
                    enum { HUNK_CAP = 4096 };
                    hunks =
                        cbm_realloc_or_abort(NULL, (size_t)HUNK_CAP * sizeof(cbm_changed_hunk_t));
                    hunk_count = cbm_parse_hunks(hbuf, hunks, HUNK_CAP);
                    /* A filled buffer means the diff was truncated: the hunks
                     * past the cap are gone, so files captured only partially
                     * would still look scoped and silently under-seed. Drop
                     * scoping for the whole request rather than under-report a
                     * large refactor — whole-file seeding is the safe side. */
                    if (hunk_count >= HUNK_CAP) {
                        cbm_log_info("detect_changes.hunks", "action", "scoping_disabled", "reason",
                                     "hunk_cap_reached");
                        free(hunks);
                        hunks = NULL;
                        hunk_count = 0;
                    }
                    free(hbuf);
                }
            }
            (void)fclose(hfp);
        }
        if (hunk_output_path[0]) {
            (void)cbm_unlink(hunk_output_path);
        }
    }

    char line[CBM_SZ_1K];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - SKIP_ONE] == '\n' || line[len - SKIP_ONE] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }
        /* Strip the `git status --porcelain` 2-char code + space; for a rename
         * ("R  old -> new") keep the destination path. */
        char *path_line = line;
        if (len > PAIR_LEN && line[PAIR_LEN] == ' ' && strchr(" MADRCU?!", line[0]) &&
            strchr(" MADRCU?!", line[1])) {
            path_line = line + PAIR_LEN + SKIP_ONE;
            char *arrow = strstr(path_line, " -> ");
            if (arrow) {
                enum { ARROW_LEN = 4 };
                path_line = arrow + ARROW_LEN;
            }
        }
        if (path_line[0] == '\0') {
            continue;
        }
        /* Dedup: the three git sources are sorted+unioned on POSIX but not on
         * Windows (separate commands), and a path can repeat. */
        bool dup = false;
        for (int i = 0; i < file_count; i++) {
            if (strcmp(files[i], path_line) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) {
            continue;
        }
        if ((size_t)file_count >= file_cap) {
            file_cap = file_cap ? file_cap * 2 : 16;
            files = cbm_realloc_or_abort(files, file_cap * sizeof(char *));
        }
        files[file_count++] = heap_strdup(path_line);
        if (want_symbols) {
            detect_collect_seeds(store, project, path_line, hunks, hunk_count, &seeds, &seed_count,
                                 &seed_cap);
        }
    }
    (void)fclose(fp);
    (void)cbm_unlink(output_path);
    int git_status = git_result.exit_code;

    /* merge-base SHA: the exact commit the diff is measured against, so the
     * result is reproducible even as base_branch advances. Best-effort. */
    char merge_base[64] = "";
    {
        char mbcmd[CBM_SZ_2K];
#ifdef _WIN32
        snprintf(mbcmd, sizeof(mbcmd), "git -C \"%s\" merge-base \"%s\" HEAD 2>NUL", root_path,
                 base_branch);
#else
        snprintf(mbcmd, sizeof(mbcmd), "git -C '%s' merge-base '%s' HEAD 2>/dev/null", root_path,
                 base_branch);
#endif
        char mb_output_path[CBM_SZ_2K] = {0};
        cbm_proc_result_t mb_result = {0};
        int mb_run = mcp_run_shell_command_cancellable(srv, mbcmd, mb_output_path, &mb_result);
        bool mb_cancelled = mb_result.cancellation_requested || mcp_request_cancelled(srv);
        bool mb_containment_failed = mb_run != 0 && mb_output_path[0] != '\0';
        FILE *mbfp =
            mb_run == 0 && mb_result.exit_code == 0 ? cbm_fopen(mb_output_path, "rb") : NULL;
        if (mbfp && !mb_cancelled) {
            if (fgets(merge_base, sizeof(merge_base), mbfp)) {
                size_t l = strlen(merge_base);
                while (l > 0 && (merge_base[l - 1] == '\n' || merge_base[l - 1] == '\r')) {
                    merge_base[--l] = '\0';
                }
            }
        }
        if (mbfp) {
            (void)fclose(mbfp);
        }
        if (mb_output_path[0]) {
            (void)cbm_unlink(mb_output_path);
        }
        if (mb_cancelled || mb_containment_failed) {
            for (int i = 0; i < file_count; i++) {
                free(files[i]);
            }
            free(files);
            free(seeds);
            free(hunks);
            free(direction);
            free(root_path);
            free(project);
            free(base_branch);
            free(scope);
            return cbm_mcp_text_result(
                mb_cancelled ? "detect_changes cancelled for this request"
                             : "git merge-base failed: the contained command could not complete",
                true);
        }
    }

    /* The impact traversal: ONE multi-source BFS over all seeds. */
    cbm_traverse_result_t impact = {0};
    bool truncated = false;
    if (want_symbols && seed_count > 0) {
        (void)cbm_store_bfs_multi(store, seeds, seed_count, direction, NULL, 0, depth,
                                  MCP_BFS_LIMIT_MAX, &impact, &truncated);
    }

    bool is_error = (git_status != 0 && file_count == 0);
    char *out_str = NULL;

    if (!legacy_json) {
        cbm_sb_t sb;
        cbm_sb_init(&sb);
        cbm_tree_scalar_str(&sb, "base", base_branch);
        if (merge_base[0]) {
            cbm_tree_scalar_str(&sb, "merge_base", merge_base);
        }
        cbm_tree_scalar_str(&sb, "direction", direction);
        if (is_error) {
            char hint_buf[CBM_SZ_256];
            snprintf(hint_buf, sizeof(hint_buf),
                     "git diff exited with status %d. Check that branch '%s' exists.", git_status,
                     base_branch);
            cbm_tree_scalar_str(&sb, "hint", hint_buf);
        }
        /* changed files (the git result) */
        char cf[CBM_SZ_64];
        snprintf(cf, sizeof(cf), "changed_files: %d\n", file_count);
        cbm_sb_append(&sb, cf);
        for (int i = 0; i < file_count; i++) {
            cbm_sb_append(&sb, "  ");
            cbm_sb_append(&sb, files[i]);
            cbm_sb_append(&sb, "\n");
        }
        cbm_tree_scalar_int(&sb, "seed_symbols", seed_count);
        if (want_symbols) {
            detect_emit_impacted_tree(&sb, &impact, imp_limit);
            /* module rollup: a quotient view of the blast radius */
            if (impact.visited_count > 0) {
                cbm_sb_append(&sb, "impacted_modules: (rows: module count)\n");
                char (*mods)[CBM_SZ_128] = malloc((size_t)DETECT_MODCAP * CBM_SZ_128);
                int *mcnt = malloc((size_t)DETECT_MODCAP * sizeof(int));
                if (mods && mcnt) {
                    int overflow = 0;
                    int nmods = detect_module_rollup(&impact, mods, mcnt, &overflow);
                    for (int j = 0; j < nmods; j++) {
                        char mrow[CBM_SZ_256];
                        snprintf(mrow, sizeof(mrow), "  %s %d\n", mods[j], mcnt[j]);
                        cbm_sb_append(&sb, mrow);
                    }
                    if (overflow > 0) {
                        char orow[CBM_SZ_128];
                        snprintf(orow, sizeof(orow), "  (other) %d\n", overflow);
                        cbm_sb_append(&sb, orow);
                    }
                }
                free(mods);
                free(mcnt);
            }
            if (truncated) {
                cbm_tree_scalar_bool(&sb, "truncated", true);
                cbm_tree_scalar_str(&sb, "hint",
                                    "impact hit the safety ceiling — narrow with a lower "
                                    "'depth' or a smaller diff");
            }
        }
        out_str = cbm_sb_finish(&sb);
    } else {
        /* format:"json" = json-stringified tree: same model, structured. */
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
        yyjson_mut_val *root_obj = yyjson_mut_obj(doc);
        yyjson_mut_doc_set_root(doc, root_obj);
        yyjson_mut_obj_add_strcpy(doc, root_obj, "base", base_branch);
        if (merge_base[0]) {
            yyjson_mut_obj_add_strcpy(doc, root_obj, "merge_base", merge_base);
        }
        yyjson_mut_obj_add_strcpy(doc, root_obj, "direction", direction);
        yyjson_mut_val *cf = yyjson_mut_arr(doc);
        for (int i = 0; i < file_count; i++) {
            yyjson_mut_arr_add_strcpy(doc, cf, files[i]);
        }
        yyjson_mut_obj_add_val(doc, root_obj, "changed_files", cf);
        yyjson_mut_obj_add_int(doc, root_obj, "seed_symbols", seed_count);
        yyjson_mut_obj_add_int(doc, root_obj, "impacted_total", impact.visited_count);
        int imp_shown = impact.visited_count < imp_limit ? impact.visited_count : imp_limit;
        yyjson_mut_obj_add_int(doc, root_obj, "impacted_shown", imp_shown);
        yyjson_mut_val *imp = yyjson_mut_arr(doc);
        for (int i = 0; i < imp_shown; i++) {
            yyjson_mut_val *o = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_strcpy(
                doc, o, "qn",
                impact.visited[i].node.qualified_name ? impact.visited[i].node.qualified_name : "");
            yyjson_mut_obj_add_strcpy(
                doc, o, "label", impact.visited[i].node.label ? impact.visited[i].node.label : "");
            yyjson_mut_obj_add_strcpy(
                doc, o, "file",
                impact.visited[i].node.file_path ? impact.visited[i].node.file_path : "");
            yyjson_mut_obj_add_int(doc, o, "hop", impact.visited[i].hop);
            yyjson_mut_arr_add_val(imp, o);
        }
        yyjson_mut_obj_add_val(doc, root_obj, "impacted", imp);
        /* Model parity with the tree encoding: the complete module rollup. */
        if (impact.visited_count > 0) {
            char (*mods)[CBM_SZ_128] = malloc((size_t)DETECT_MODCAP * CBM_SZ_128);
            int *mcnt = malloc((size_t)DETECT_MODCAP * sizeof(int));
            if (mods && mcnt) {
                int overflow = 0;
                int nmods = detect_module_rollup(&impact, mods, mcnt, &overflow);
                yyjson_mut_val *rollup = yyjson_mut_arr(doc);
                for (int j = 0; j < nmods; j++) {
                    yyjson_mut_val *o = yyjson_mut_obj(doc);
                    yyjson_mut_obj_add_strcpy(doc, o, "module", mods[j]);
                    yyjson_mut_obj_add_int(doc, o, "count", mcnt[j]);
                    yyjson_mut_arr_add_val(rollup, o);
                }
                if (overflow > 0) {
                    yyjson_mut_val *o = yyjson_mut_obj(doc);
                    yyjson_mut_obj_add_strcpy(doc, o, "module", "(other)");
                    yyjson_mut_obj_add_int(doc, o, "count", overflow);
                    yyjson_mut_arr_add_val(rollup, o);
                }
                yyjson_mut_obj_add_val(doc, root_obj, "impacted_modules", rollup);
            }
            free(mods);
            free(mcnt);
        }
        yyjson_mut_obj_add_bool(doc, root_obj, "truncated", truncated);
        if (is_error) {
            char hint_buf[CBM_SZ_256];
            snprintf(hint_buf, sizeof(hint_buf),
                     "git diff exited with status %d. Check that branch '%s' exists.", git_status,
                     base_branch);
            yyjson_mut_obj_add_strcpy(doc, root_obj, "hint", hint_buf);
        }
        out_str = yy_doc_to_str(doc);
        yyjson_mut_doc_free(doc);
    }

    cbm_store_traverse_free(&impact);
    for (int i = 0; i < file_count; i++) {
        free(files[i]);
    }
    free(files);
    free(seeds);
    free(hunks);
    free(direction);
    free(root_path);
    free(project);
    free(base_branch);
    free(scope);

    char *result = cbm_mcp_text_result(out_str, is_error);
    free(out_str);
    return result;
}

/* ── manage_adr ───────────────────────────────────────────────── */

/* ADR "sections" mode: list markdown headers ('#'-prefixed lines) from the
 * ADR content string. */
static void adr_list_sections_from_content(yyjson_mut_doc *doc, yyjson_mut_val *root_obj,
                                           const char *content) {
    yyjson_mut_val *sections = yyjson_mut_arr(doc);
    const char *p = content;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
        while (linelen > 0 && p[linelen - SKIP_ONE] == '\r') {
            linelen--;
        }
        if (linelen > 0 && p[0] == '#') {
            char hdr[CBM_SZ_1K];
            if (linelen >= sizeof(hdr)) {
                linelen = sizeof(hdr) - SKIP_ONE;
            }
            memcpy(hdr, p, linelen);
            hdr[linelen] = '\0';
            yyjson_mut_arr_add_strcpy(doc, sections, hdr);
        }
        if (!eol) {
            break;
        }
        p = eol + SKIP_ONE;
    }
    yyjson_mut_obj_add_val(doc, root_obj, "sections", sections);
}

/* Read the legacy file-based ADR (<root>/.codebase-memory/adr.md), used by
 * older versions. Returns a heap buffer (caller frees) or NULL if missing/
 * empty. Kept only to migrate old ADRs into the store (#256). */
static char *adr_read_legacy_file(const char *root_path) {
    if (!root_path) {
        return NULL;
    }
    char adr_path[CBM_SZ_4K];
    snprintf(adr_path, sizeof(adr_path), "%s/.codebase-memory/adr.md", root_path);
    FILE *fp = cbm_fopen(adr_path, "r");
    if (!fp) {
        return NULL;
    }
    (void)fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz <= 0) {
        (void)fclose(fp);
        return NULL;
    }
    (void)fseek(fp, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + SKIP_ONE);
    if (!buf) {
        (void)fclose(fp);
        return NULL;
    }
    size_t n = fread(buf, SKIP_ONE, (size_t)sz, fp);
    buf[n] = '\0';
    (void)fclose(fp);
    if (buf[0] == '\0') {
        free(buf);
        return NULL;
    }
    return buf;
}

#define ADR_EMPTY_HINT                                                             \
    "No ADR yet. Create one with manage_adr(mode='update', "                       \
    "content='## PURPOSE\\n...\\n\\n## STACK\\n...\\n\\n## ARCHITECTURE\\n..."     \
    "\\n\\n## PATTERNS\\n...\\n\\n## TRADEOFFS\\n...\\n\\n## PHILOSOPHY\\n...'). " \
    "For guided creation: explore the codebase with get_architecture, "            \
    "then draft and store. Sections: PURPOSE, STACK, ARCHITECTURE, "               \
    "PATTERNS, TRADEOFFS, PHILOSOPHY."

/* resolve_store opens file-backed projects query-only. A mutation must release
 * that reader before opening a dedicated writer because atomic publication uses
 * a self-contained DELETE-mode database that switches back to WAL on write. */
static cbm_store_t *open_adr_store_for_write(cbm_mcp_server_t *srv, cbm_store_t *resolved,
                                             cbm_store_t **owned_rw) {
    if (!srv || !resolved || !owned_rw) {
        return NULL;
    }
    const char *resolved_db_path = cbm_store_db_path(resolved);
    if (!resolved_db_path) {
        return resolved;
    }
    char *rw_path = heap_strdup(resolved_db_path);
    if (!rw_path) {
        return NULL;
    }
    invalidate_cached_store(srv);
    *owned_rw = cbm_store_open_path(rw_path);
    free(rw_path);
    return *owned_rw;
}

static char *handle_manage_adr(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    char *mode_str = cbm_mcp_get_string_arg(args, "mode");
    char *content = cbm_mcp_get_string_arg(args, "content");

    if (!mode_str) {
        mode_str = heap_strdup("get");
    }

    /* `sections` used to be advertised as an input argument, but it was never
     * consumed: mode=update still replaced the whole document. Reject the old
     * shape explicitly before opening a store so a stale client cannot mistake
     * a whole-document replacement for a section-scoped update. */
    bool has_sections_arg = false;
    yyjson_doc *args_doc = yyjson_read(args, strlen(args), 0);
    if (args_doc) {
        yyjson_val *args_root = yyjson_doc_get_root(args_doc);
        has_sections_arg =
            args_root && yyjson_is_obj(args_root) && yyjson_obj_get(args_root, "sections") != NULL;
        yyjson_doc_free(args_doc);
    }
    if (has_sections_arg) {
        free(project);
        free(mode_str);
        free(content);
        return cbm_mcp_text_result(
            "{\"status\":\"invalid_arguments\",\"error\":\"The sections argument is not an "
            "update primitive and has been removed. No ADR write was performed.\"}",
            true);
    }

    bool write_request =
        content && (strcmp(mode_str, "update") == 0 || strcmp(mode_str, "store") == 0);
    bool mutation_held = false;
    if (write_request && project) {
        mutation_held = mcp_project_mutation_begin(srv, project);
        if (!mutation_held) {
            free(project);
            free(mode_str);
            free(content);
            return cbm_mcp_text_result("project operation cancelled or blocked by an active index",
                                       true);
        }
        if (mcp_request_cancelled(srv)) {
            mcp_project_mutation_end(srv, project);
            free(project);
            free(mode_str);
            free(content);
            return cbm_mcp_text_result("project operation cancelled for this request", true);
        }
    }

    /* ADRs are stored in the SQLite store (project_summaries), the SAME
     * backend the UI /api/adr endpoints use — so writes via the MCP tool and
     * the UI are visible to each other (#256). */
    store_recovery_status_t recovery_status = STORE_RECOVERY_NONE;
    cbm_store_t *resolved =
        resolve_store_internal(srv, project, mutation_held, !write_request, &recovery_status);
    if (!resolved) {
        char *res = NULL;
        if (recovery_status == STORE_RECOVERY_BUSY) {
            res = cbm_mcp_text_result("project is busy; retry after indexing", true);
        } else if (recovery_status == STORE_RECOVERY_TRY_GUARD_UNAVAILABLE) {
            res =
                cbm_mcp_text_result("project recovery requires a nonblocking mutation guard", true);
        } else {
            char *err = build_no_store_error(project);
            res = cbm_mcp_text_result(err, true);
            free(err);
        }
        if (mutation_held) {
            mcp_project_mutation_end(srv, project);
        }
        free(project);
        free(mode_str);
        free(content);
        return res;
    }

    cbm_store_t *store = resolved;
    cbm_store_t *owned_rw = NULL;
    if (write_request) {
        store = open_adr_store_for_write(srv, resolved, &owned_rw);
        if (!store) {
            if (mutation_held) {
                mcp_project_mutation_end(srv, project);
            }
            free(project);
            free(mode_str);
            free(content);
            return cbm_mcp_text_result("failed to open writable ADR store", true);
        }
    }

    /* One-time migration: older versions wrote ADRs to a file at
     * <root>/.codebase-memory/adr.md. A read never waits for the project lease:
     * it returns the legacy content immediately and attempts migration only if
     * a nonblocking acquire succeeds. */
    cbm_adr_t adr;
    memset(&adr, 0, sizeof(adr));
    bool have_adr = (cbm_store_adr_get(store, project, &adr) == CBM_STORE_OK);
    char *legacy = NULL;
    if (!have_adr && !write_request) {
        char *root_path = project_root_from_store(store, project);
        legacy = adr_read_legacy_file(root_path);
        free(root_path);
        if (legacy && mcp_project_mutation_try_begin(srv, project)) {
            if (!mcp_request_cancelled(srv)) {
                /* A publisher may have completed before the lease was granted.
                 * File-backed stores must reopen after acquisition and trust
                 * only that generation. Embedded stores have no publication
                 * boundary, so retain their live handle. */
                if (cbm_store_db_path(resolved)) {
                    invalidate_cached_store(srv);
                    resolved = NULL;
                    store = NULL;
                    resolved = resolve_store_internal(srv, project, true, false, NULL);
                }
                if (resolved) {
                    store = open_adr_store_for_write(srv, resolved, &owned_rw);
                    if (store) {
                        have_adr = (cbm_store_adr_get(store, project, &adr) == CBM_STORE_OK);
                        if (!have_adr &&
                            cbm_store_adr_store(store, project, legacy) == CBM_STORE_OK) {
                            have_adr = (cbm_store_adr_get(store, project, &adr) == CBM_STORE_OK);
                        }
                    }
                }
            }
            mcp_project_mutation_end(srv, project);
        }
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root_obj = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root_obj);

    bool is_error = false;
    const char *adr_content = have_adr ? adr.content : legacy;
    if (write_request) {
        if (cbm_store_adr_store(store, project, content) == CBM_STORE_OK) {
            yyjson_mut_obj_add_str(doc, root_obj, "status", "updated");
            yyjson_mut_obj_add_str(doc, root_obj, "semantics", "whole_document_replaced");
        } else {
            yyjson_mut_obj_add_str(doc, root_obj, "status", "write_error");
            is_error = true;
        }
    } else if (strcmp(mode_str, "sections") == 0) {
        adr_list_sections_from_content(doc, root_obj, adr_content);
    } else { /* get */
        if (adr_content) {
            yyjson_mut_obj_add_strcpy(doc, root_obj, "content", adr_content);
        } else {
            yyjson_mut_obj_add_str(doc, root_obj, "content", "");
            yyjson_mut_obj_add_str(doc, root_obj, "status", "no_adr");
            yyjson_mut_obj_add_str(doc, root_obj, "adr_hint", ADR_EMPTY_HINT);
        }
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    if (have_adr) {
        cbm_store_adr_free(&adr);
    }
    if (owned_rw) {
        cbm_store_close(owned_rw);
    }
    if (mutation_held) {
        mcp_project_mutation_end(srv, project);
    }
    free(legacy);
    free(project);
    free(mode_str);
    free(content);

    char *result = cbm_mcp_text_result(json, is_error);
    free(json);
    return result;
}

/* ── ingest_traces ────────────────────────────────────────────── */

static char *handle_ingest_traces(void) {
    return cbm_mcp_text_result("ingest_traces is not supported", true);
}

/* ── Tool dispatch ────────────────────────────────────────────── */

static char *dispatch_tool(cbm_mcp_server_t *srv, const char *tool_name, const char *args_json) {
    if (!tool_name) {
        return cbm_mcp_text_result("missing tool name", true);
    }
    if (srv && !mcp_tool_allowed(srv->tool_profile, tool_name)) {
        char message[CBM_SZ_256];
        snprintf(message, sizeof(message), "tool '%s' is not available in the %s tool profile",
                 tool_name, mcp_tool_profile_name(srv->tool_profile));
        return cbm_mcp_text_result(message, true);
    }

    if (strcmp(tool_name, "list_projects") == 0) {
        return handle_list_projects(srv, args_json);
    }
    if (strcmp(tool_name, "get_graph_schema") == 0) {
        return handle_get_graph_schema(srv, args_json);
    }
    if (strcmp(tool_name, "search_graph") == 0) {
        return handle_search_graph(srv, args_json);
    }
    if (strcmp(tool_name, "query_graph") == 0) {
        return handle_query_graph(srv, args_json);
    }
    if (strcmp(tool_name, "index_status") == 0) {
        return handle_index_status(srv, args_json);
    }
    if (strcmp(tool_name, "check_index_coverage") == 0) {
        return handle_check_index_coverage(srv, args_json);
    }
    if (strcmp(tool_name, "delete_project") == 0) {
        return handle_delete_project(srv, args_json);
    }
    if (strcmp(tool_name, "trace_path") == 0 || strcmp(tool_name, "trace_call_path") == 0) {
        return handle_trace_call_path(srv, args_json);
    }
    if (strcmp(tool_name, "get_architecture") == 0) {
        return handle_get_architecture(srv, args_json);
    }

    /* Pipeline-dependent tools */
    if (strcmp(tool_name, "index_repository") == 0) {
        return handle_index_repository(srv, args_json);
    }
    if (strcmp(tool_name, "get_code_snippet") == 0) {
        return handle_get_code_snippet(srv, args_json);
    }
    if (strcmp(tool_name, "search_code") == 0) {
        return handle_search_code(srv, args_json);
    }
    if (strcmp(tool_name, "detect_changes") == 0) {
        return handle_detect_changes(srv, args_json);
    }
    if (strcmp(tool_name, "manage_adr") == 0) {
        return handle_manage_adr(srv, args_json);
    }
    if (strcmp(tool_name, "ingest_traces") == 0) {
        return handle_ingest_traces();
    }
    char msg[CBM_SZ_256];
    snprintf(msg, sizeof(msg), "unknown tool: %s", tool_name);
    return cbm_mcp_text_result(msg, true);
}

/* File-backed query stores are request-scoped. Keeping one open between MCP
 * calls pins an old database generation after another process atomically
 * replaces the project DB. On Windows it can also prevent that replacement
 * entirely. Embedded/in-memory stores have no path and retain their existing
 * process lifetime. */
static void release_request_store(cbm_mcp_server_t *srv) {
    if (!srv || !srv->owns_store || !srv->store || !cbm_store_db_path(srv->store)) {
        return;
    }
    cbm_store_close(srv->store);
    srv->store = NULL;
    free(srv->current_project);
    srv->current_project = NULL;
    /* The close above frees a connection's worth of page cache. Ask the
     * allocator to hand those pages back now, which keeps a long-lived daemon
     * flat across thousands of request-scoped stores (#581). This only became
     * meaningful once the Windows interposer made the pages mimalloc's: an
     * earlier attempt aimed at the CRT heap instead and could not release
     * them. POSIX already purges on free, so this is a no-op there. */
    cbm_mem_collect();
}

char *cbm_mcp_handle_tool(cbm_mcp_server_t *srv, const char *tool_name, const char *args_json) {
    /* Phase marks bracket the WHOLE request with no unlabelled gap, so growth
     * cannot hide between them (CBM_MEM_PHASES=1; see foundation/mem.h). The
     * "idle" label owns everything outside a request, which is what makes a
     * request-path retainer distinguishable from background growth. */
    cbm_mem_phase_mark("request.scope_begin");
    bool request_scope = !srv || cbm_mcp_server_request_scope_begin(srv);
    if (!request_scope) {
        release_request_store(srv);
        cbm_mem_phase_mark("idle");
        return cbm_mcp_text_result("request cancellation scope unavailable", true);
    }
    cbm_mem_phase_mark("request.dispatch_tool");
    char *result = dispatch_tool(srv, tool_name, args_json);
    cbm_mem_phase_mark("request.scope_end");
    if (srv) {
        cbm_mcp_server_request_scope_end(srv);
    }
    cbm_mem_phase_mark("request.release_store");
    release_request_store(srv);
    cbm_mem_phase_mark("idle");
    /* One census per completed request, so growth can be attributed to a POOL
     * rather than inferred from a process total (#581). Emitted after the
     * request store is released, which is the point where a well-behaved
     * request has given everything back. */
    cbm_mem_census_log("mcp.request");
    return result;
}

/* ── Session detection + auto-index ────────────────────────────── */

/* Detect session root from CWD (fallback: single indexed project from DB). */
static void detect_session(cbm_mcp_server_t *srv) {
    if (srv->session_detected) {
        return;
    }
    srv->session_detected = true;

    /* 1. Try CWD */
    char cwd[CBM_SZ_1K];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        const char *home = cbm_get_home_dir();
        /* Skip useless roots: / and $HOME */
        if (strcmp(cwd, "/") != 0 && (home == NULL || strcmp(cwd, home) != 0)) {
            snprintf(srv->session_root, sizeof(srv->session_root), "%s", cwd);
            cbm_log_info("session.root.cwd", "path", cwd);
        }
    }

    /* Derive project name from path — must match cbm_project_name_from_path
     * used by the pipeline, otherwise session queries look for a .db file
     * that doesn't match the indexed project name. */
    if (srv->session_root[0]) {
        char *pname = cbm_project_name_from_path(srv->session_root);
        if (pname) {
            snprintf(srv->session_project, sizeof(srv->session_project), "%s", pname);
            free(pname);
        }
    }
}

/* auto_watch config: gates background watcher registration (default on).
 * Multi-project users can contain a session to its own project with
 * `config set auto_watch false`. */
static bool auto_watch_enabled(cbm_mcp_server_t *srv) {
    if (!srv->config) {
        return true; /* default on */
    }
    return cbm_config_get_bool(srv->config, CBM_CONFIG_AUTO_WATCH, true);
}

/* Register the session project with the background watcher for ongoing
 * change detection — unless auto_watch is disabled. */
static void register_watcher_if_enabled(cbm_mcp_server_t *srv) {
    if (!srv->watcher || srv->session_project[0] == '\0' || srv->session_root[0] == '\0') {
        return;
    }
    if (!auto_watch_enabled(srv)) {
        cbm_log_info("watcher.register.skipped", "reason", "auto_watch_off", "project",
                     srv->session_project);
        return;
    }
    cbm_watcher_watch(srv->watcher, srv->session_project, srv->session_root);
}

/* Background auto-index thread function */
static void *autoindex_thread(void *arg) {
    cbm_mcp_server_t *srv = (cbm_mcp_server_t *)arg;

    cbm_log_info("autoindex.start", "project", srv->session_project, "path", srv->session_root);

    /* #832: use the supervised worker subprocess. Indexing the whole session in
     * this long-lived server thread ratchets RSS (mimalloc v3 does not reclaim the
     * pages worker threads abandon at exit); running it in a child that exits hands
     * 100% of that memory back to the OS every cycle. In a marked host this is a
     * safety boundary: preparation/start failure stops the operation. */
    if (cbm_index_supervisor_should_wrap()) {
        char *resp = index_run_supervised_path(srv, srv->session_root);
        if (resp) {
            free(resp);
            cbm_log_info("autoindex.done", "project", srv->session_project, "mode", "supervised");
            /* Register with watcher for ongoing change detection — gated on
             * auto_watch (#849), same as the in-process branch below. A bare
             * `if (srv->watcher)` would register even when the user set
             * `config set auto_watch false`, since srv->watcher is always set. */
            register_watcher_if_enabled(srv);
            return NULL;
        }
        cbm_log_error("autoindex.supervision_failed", "project", srv->session_project, "action",
                      "fail_closed");
        return NULL;
    }

    cbm_pipeline_t *p = cbm_pipeline_new(srv->session_root, NULL, CBM_MODE_FULL);
    if (!p) {
        cbm_log_warn("autoindex.err", "msg", "pipeline_create_failed");
        return NULL;
    }

    /* Block until any concurrent pipeline finishes */
    cbm_pipeline_lock();
    int rc = cbm_pipeline_run(p);
    cbm_pipeline_unlock();

    cbm_pipeline_free(p);
    cbm_mem_collect(); /* return mimalloc pages to OS after indexing (in-process only) */

    if (rc == 0) {
        cbm_log_info("autoindex.done", "project", srv->session_project);
        register_watcher_if_enabled(srv);
    } else {
        cbm_log_warn("autoindex.err", "msg", "pipeline_run_failed");
    }
    return NULL;
}

bool cbm_mcp_auto_index_within_file_limit(const char *root_path, int file_limit,
                                          int *file_count_out) {
    if (file_count_out) {
        *file_count_out = -1;
    }
    if (!root_path || !root_path[0] || file_limit < 0) {
        return false;
    }
    enum { AUTO_INDEX_COUNT_TIMEOUT_MS = 5000 };
    cbm_discover_opts_t options = {
        .mode = CBM_MODE_FULL,
        .ignore_file = NULL,
        .max_file_size = 0,
    };
    int count = -1;
    cbm_discover_status_t status = cbm_discover_count_bounded(
        root_path, &options, file_limit, cbm_now_ms() + AUTO_INDEX_COUNT_TIMEOUT_MS, &count);
    if (file_count_out) {
        *file_count_out = count;
        if (status == CBM_DISCOVER_LIMIT_EXCEEDED) {
            *file_count_out = file_limit < INT_MAX ? file_limit + 1 : INT_MAX;
        }
    }
    return status == CBM_DISCOVER_OK;
}

/* Start auto-indexing if configured and project not yet indexed. */
static void maybe_auto_index(cbm_mcp_server_t *srv) {
    if (srv->session_root[0] == '\0') {
        return; /* no session root detected */
    }

    /* Check if project already has a DB */
    const char *home = cbm_get_home_dir();
    if (home) {
        char db_check[CBM_SZ_1K];
        snprintf(db_check, sizeof(db_check), "%s/%s.db", cbm_resolve_cache_dir(),
                 srv->session_project);
        if (cbm_file_size(db_check) >= 0) {
            /* Already indexed → register watcher for change detection */
            cbm_log_info("autoindex.skip", "reason", "already_indexed", "project",
                         srv->session_project);
            register_watcher_if_enabled(srv);
            return;
        }
    }

    /* Check auto_index config */
    bool auto_index = false;
    int file_limit = CBM_MCP_DEFAULT_AUTO_INDEX_LIMIT;
    if (srv->config) {
        auto_index = cbm_config_get_bool(srv->config, CBM_CONFIG_AUTO_INDEX, false);
        file_limit = cbm_config_get_int(srv->config, CBM_CONFIG_AUTO_INDEX_LIMIT,
                                        CBM_MCP_DEFAULT_AUTO_INDEX_LIMIT);
    }

    if (!auto_index) {
        cbm_log_info("autoindex.skip", "reason", "disabled", "hint",
                     "run: codebase-memory-mcp config set auto_index true");
        return;
    }

    /* Quick tracked-file count check to avoid OOM on massive repos. */
    int file_count = -1;
    if (!cbm_mcp_auto_index_within_file_limit(srv->session_root, file_limit, &file_count)) {
        char files[32];
        (void)snprintf(files, sizeof(files), "%d", file_count);
        cbm_log_warn("autoindex.skip", "reason",
                     file_count >= 0 ? "too_many_files" : "unsafe_or_unavailable_path", "files",
                     files, "limit", CBM_CONFIG_AUTO_INDEX_LIMIT);
        return;
    }

    /* Launch auto-index in background */
    if (cbm_thread_create(&srv->autoindex_tid, 0, autoindex_thread, srv) == 0) {
        srv->autoindex_active = true;
    }
}

/* ── Server request handler ───────────────────────────────────── */

bool cbm_mcp_jsonrpc_response_prepend_notice(char **response_io, const char *notice) {
    if (!response_io || !*response_io || !notice || !notice[0]) {
        return false;
    }
    yyjson_doc *document = yyjson_read(*response_io, strlen(*response_io), 0);
    if (!document) {
        return false;
    }
    yyjson_mut_doc *mutable_document = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root =
        mutable_document ? yyjson_val_mut_copy(mutable_document, yyjson_doc_get_root(document))
                         : NULL;
    yyjson_doc_free(document);
    if (!mutable_document || !root) {
        yyjson_mut_doc_free(mutable_document);
        return false;
    }
    yyjson_mut_doc_set_root(mutable_document, root);
    yyjson_mut_val *result = yyjson_mut_is_obj(root) ? yyjson_mut_obj_get(root, "result") : NULL;
    yyjson_mut_val *content =
        result && yyjson_mut_is_obj(result) ? yyjson_mut_obj_get(result, "content") : NULL;
    yyjson_mut_val *item =
        content && yyjson_mut_is_arr(content) ? yyjson_mut_obj(mutable_document) : NULL;
    bool added = item && yyjson_mut_obj_add_str(mutable_document, item, "type", "text") &&
                 yyjson_mut_obj_add_str(mutable_document, item, "text", notice) &&
                 yyjson_mut_arr_prepend(content, item);
    if (!added) {
        yyjson_mut_doc_free(mutable_document);
        return false;
    }
    char *replacement =
        yyjson_mut_write(mutable_document, YYJSON_WRITE_ALLOW_INVALID_UNICODE, NULL);
    yyjson_mut_doc_free(mutable_document);
    if (!replacement) {
        return false;
    }
    free(*response_io);
    *response_io = replacement;
    return true;
}

char *cbm_mcp_server_handle(cbm_mcp_server_t *srv, const char *line) {
    cbm_jsonrpc_request_t req = {0};
    if (cbm_jsonrpc_parse(line, &req) < 0) {
        return cbm_jsonrpc_format_error(0, JSONRPC_PARSE_ERROR, "Parse error");
    }

    /* Notifications (no id) → handle cancellation, then no response */
    if (!req.has_id) {
        if (req.method && strcmp(req.method, "notifications/cancelled") == 0) {
            if (cbm_mcp_cancel_request_matches(req.params_raw, srv->active_request_id,
                                               srv->active_request_id_str) &&
                cbm_mcp_server_cancel_active(srv)) {
                cbm_log_info("mcp.cancelled", "match", "true");
            }
        }
        cbm_jsonrpc_request_free(&req);
        return NULL;
    }

    if (!cbm_mcp_server_request_scope_begin(srv)) {
        int64_t request_id = req.id;
        cbm_jsonrpc_request_free(&req);
        return cbm_jsonrpc_format_error(request_id, JSONRPC_INTERNAL_ERROR,
                                        "Request cancellation scope unavailable");
    }

    struct timespec req_t0;
    cbm_clock_gettime(CLOCK_MONOTONIC, &req_t0);
    char *result_json = NULL;
    char *request_error_json = NULL;
    bool request_logged = false;

    if (strcmp(req.method, "initialize") == 0) {
        result_json = cbm_mcp_initialize_response_for_profile(req.params_raw, srv->tool_profile);
        detect_session(srv);
        if (srv->background_tasks && srv->tool_profile == CBM_MCP_TOOL_PROFILE_ALL) {
            maybe_auto_index(srv);
        }
    } else if (strcmp(req.method, "ping") == 0) {
        result_json = heap_strdup("{}");
    } else if (strcmp(req.method, "resources/list") == 0) {
        /* This server exposes no resources, but clients probe these on
         * connect regardless of declared capabilities and surface -32601 as
         * a failed connection (#958). Empty lists are interoperable. */
        result_json = heap_strdup("{\"resources\":[]}");
    } else if (strcmp(req.method, "resources/templates/list") == 0) {
        result_json = heap_strdup("{\"resourceTemplates\":[]}");
    } else if (strcmp(req.method, "prompts/list") == 0) {
        result_json = cbm_mcp_prompts_list();
    } else if (strcmp(req.method, "prompts/get") == 0) {
        result_json = cbm_mcp_prompt_get(req.params_raw, &request_error_json);
    } else if (strcmp(req.method, "tools/list") == 0) {
        result_json = cbm_mcp_tools_list_page(srv->tool_profile, req.params_raw);
    } else if (strcmp(req.method, "tools/call") == 0) {
        char *tool_name = req.params_raw ? cbm_mcp_get_tool_name(req.params_raw) : NULL;
        char *tool_args =
            req.params_raw ? cbm_mcp_get_arguments(req.params_raw) : heap_strdup("{}");
        srv->active_request_id = req.id;
        free(srv->active_request_id_str);
        srv->active_request_id_str = req.id_str ? heap_strdup(req.id_str) : NULL;

        struct timespec t0;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t0);
        result_json = cbm_mcp_handle_tool(srv, tool_name, tool_args);
        srv->active_request_id = CBM_NOT_FOUND;
        free(srv->active_request_id_str);
        srv->active_request_id_str = NULL;
        struct timespec t1;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t1);
        long long dur_us = ((long long)(t1.tv_sec - t0.tv_sec) * MCP_S_TO_US) +
                           ((long long)(t1.tv_nsec - t0.tv_nsec) / MCP_MS_TO_US);
        bool is_err = (result_json != NULL) && (strstr(result_json, "\"isError\":true") != NULL);
        cbm_diag_record_query(dur_us, is_err);
        long long request_dur_us = ((long long)(t1.tv_sec - req_t0.tv_sec) * MCP_S_TO_US) +
                                   ((long long)(t1.tv_nsec - req_t0.tv_nsec) / MCP_MS_TO_US);
        cbm_log_mcp_request(req.method, tool_name, is_err, request_dur_us);
        request_logged = true;

        free(tool_name);
        free(tool_args);
    } else {
        /* Echo the original id (string or numeric, issue #253) on the error. */
        char err_obj[160];
        snprintf(err_obj, sizeof(err_obj), "{\"code\":%d,\"message\":\"Method not found\"}",
                 JSONRPC_METHOD_NOT_FOUND);
        cbm_jsonrpc_response_t err_resp = {
            .id = req.id,
            .id_str = req.id_str,
            .error_json = err_obj,
        };
        char *err = cbm_jsonrpc_format_response(&err_resp);
        struct timespec t1;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t1);
        long long dur_us = ((long long)(t1.tv_sec - req_t0.tv_sec) * MCP_S_TO_US) +
                           ((long long)(t1.tv_nsec - req_t0.tv_nsec) / MCP_MS_TO_US);
        cbm_log_mcp_request(req.method, NULL, true, dur_us);
        cbm_mcp_server_request_scope_end(srv);
        cbm_jsonrpc_request_free(&req);
        return err;
    }

    if (request_error_json) {
        cbm_jsonrpc_response_t err_resp = {
            .id = req.id,
            .id_str = req.id_str,
            .error_json = request_error_json,
        };
        char *err = cbm_jsonrpc_format_response(&err_resp);
        struct timespec t1;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t1);
        long long dur_us = ((long long)(t1.tv_sec - req_t0.tv_sec) * MCP_S_TO_US) +
                           ((long long)(t1.tv_nsec - req_t0.tv_nsec) / MCP_MS_TO_US);
        cbm_log_mcp_request(req.method, NULL, true, dur_us);
        free(request_error_json);
        cbm_mcp_server_request_scope_end(srv);
        cbm_jsonrpc_request_free(&req);
        return err;
    }

    if (!request_logged) {
        struct timespec t1;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t1);
        long long dur_us = ((long long)(t1.tv_sec - req_t0.tv_sec) * MCP_S_TO_US) +
                           ((long long)(t1.tv_nsec - req_t0.tv_nsec) / MCP_MS_TO_US);
        cbm_log_mcp_request(req.method, NULL, false, dur_us);
    }

    cbm_jsonrpc_response_t resp = {
        .id = req.id,
        .id_str = req.id_str,
        .result_json = result_json,
    };
    char *out = cbm_jsonrpc_format_response(&resp);
    free(result_json);
    cbm_mcp_server_request_scope_end(srv);
    cbm_jsonrpc_request_free(&req);
    return out;
}

enum {
    BOUNDED_LINE_TERMINATOR_BYTES = 1,
    BOUNDED_LINE_NEXT_BYTE_BYTES = 1,
    BOUNDED_LINE_INITIAL_CAPACITY = 256,
    BOUNDED_LINE_GROWTH_FACTOR = 2,
};

static size_t bounded_line_capacity(size_t current_capacity, size_t required_capacity,
                                    size_t maximum_capacity) {
    size_t capacity = current_capacity ? current_capacity : maximum_capacity;
    while (capacity < required_capacity && capacity < maximum_capacity) {
        size_t doubled_capacity = capacity * BOUNDED_LINE_GROWTH_FACTOR;
        capacity = doubled_capacity > maximum_capacity ? maximum_capacity : doubled_capacity;
    }
    return capacity;
}

static bool grow_bounded_line(char **line, size_t *capacity, size_t length, size_t max_bytes) {
    size_t required_capacity =
        length + BOUNDED_LINE_NEXT_BYTE_BYTES + BOUNDED_LINE_TERMINATOR_BYTES;
    if (*capacity >= required_capacity) {
        return true;
    }
    size_t maximum_capacity = max_bytes + BOUNDED_LINE_TERMINATOR_BYTES;
    size_t initial_capacity = maximum_capacity < BOUNDED_LINE_INITIAL_CAPACITY
                                  ? maximum_capacity
                                  : BOUNDED_LINE_INITIAL_CAPACITY;
    size_t new_capacity = bounded_line_capacity(*capacity ? *capacity : initial_capacity,
                                                required_capacity, maximum_capacity);
    if (new_capacity < required_capacity) {
        return false;
    }
    char *grown = realloc(*line, new_capacity);
    if (!grown) {
        return false;
    }
    memset(grown + length, 0, new_capacity - length);
    *line = grown;
    *capacity = new_capacity;
    return true;
}

static int bounded_line_eof_result(FILE *input, size_t length) {
    if (ferror(input)) {
        return CBM_NOT_FOUND;
    }
    return length == 0 ? 0 : SKIP_ONE;
}

/* Read through one newline without ever growing the buffer beyond max_bytes.
 * Returns 1 for a line (including a final unterminated line), 0 for clean EOF,
 * and -1 for I/O, allocation, or size failure. */
static int read_bounded_line(FILE *input, char **line, size_t *capacity, size_t max_bytes,
                             size_t *out_length) {
    if (!input || !line || !capacity || !out_length || max_bytes == 0) {
        return CBM_NOT_FOUND;
    }
    size_t length = 0;
    for (;;) {
        int next_character = fgetc(input);
        if (next_character == EOF) {
            int eof_result = bounded_line_eof_result(input, length);
            if (eof_result != SKIP_ONE) {
                return eof_result;
            }
            break;
        }
        if (length >= max_bytes || !grow_bounded_line(line, capacity, length, max_bytes)) {
            return CBM_NOT_FOUND;
        }
        (*line)[length++] = (char)next_character;
        if (next_character == '\n') {
            break;
        }
    }
    (*line)[length] = '\0';
    *out_length = length;
    return SKIP_ONE;
}

static bool parse_content_length(const char *line, size_t *out) {
    if (!line || !out || strncmp(line, "Content-Length:", SLEN("Content-Length:")) != 0) {
        return false;
    }

    const char *cursor = line + MCP_CONTENT_PREFIX;
    while (*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    if (!isdigit((unsigned char)*cursor)) {
        return false;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(cursor, &end, CBM_DECIMAL_BASE);
    if (errno == ERANGE || end == cursor) {
        return false;
    }
    while (*end == ' ' || *end == '\t') {
        end++;
    }
    if (*end != '\0' || parsed == 0 || parsed > MCP_MAX_MESSAGE_SIZE) {
        return false;
    }
    *out = (size_t)parsed;
    return true;
}

static size_t mcp_strip_line_endings(char *line, size_t length) {
    while (length > 0 && (line[length - SKIP_ONE] == '\n' || line[length - SKIP_ONE] == '\r')) {
        line[--length] = '\0';
    }
    return length;
}

static bool mcp_read_header_separator(FILE *input, char **line, size_t *capacity,
                                      size_t initial_header_bytes) {
    size_t header_bytes = initial_header_bytes;
    for (;;) {
        if (header_bytes >= MCP_MAX_HEADER_SIZE) {
            return false;
        }
        size_t header_read = 0;
        int header_status = read_bounded_line(input, line, capacity,
                                              MCP_MAX_HEADER_SIZE - header_bytes, &header_read);
        if (header_status <= 0 || memchr(*line, '\0', header_read) != NULL) {
            return false;
        }
        header_bytes += header_read;
        if (mcp_strip_line_endings(*line, header_read) == 0) {
            return true;
        }
    }
}

static char *mcp_read_framed_body(FILE *input, size_t content_length) {
    char *body = malloc(content_length + SKIP_ONE);
    if (!body) {
        return NULL;
    }
    size_t total_read = 0;
    while (total_read < content_length) {
        size_t read_count = fread(body + total_read, SKIP_ONE, content_length - total_read, input);
        if (read_count == 0) {
            free(body);
            return NULL;
        }
        total_read += read_count;
    }
    if (memchr(body, '\0', content_length) != NULL) {
        free(body);
        return NULL;
    }
    body[content_length] = '\0';
    return body;
}

int cbm_mcp_read_message(FILE *in, char **message, bool *content_length_framed) {
    if (!in || !message || !content_length_framed) {
        return CBM_NOT_FOUND;
    }
    *message = NULL;
    *content_length_framed = false;

    char *line = NULL;
    size_t cap = 0;
    for (;;) {
        size_t line_read = 0;
        int line_status = read_bounded_line(in, &line, &cap, MCP_MAX_MESSAGE_SIZE, &line_read);
        if (line_status <= 0) {
            free(line);
            return line_status;
        }
        if (memchr(line, '\0', line_read) != NULL) {
            free(line);
            return CBM_NOT_FOUND;
        }

        size_t len = mcp_strip_line_endings(line, line_read);
        if (len == 0) {
            continue;
        }

        if (strncmp(line, "Content-Length:", SLEN("Content-Length:")) != 0) {
            *message = line;
            return SKIP_ONE;
        }

        size_t content_len = 0;
        if (line_read > MCP_MAX_HEADER_SIZE || !parse_content_length(line, &content_len)) {
            free(line);
            return CBM_NOT_FOUND;
        }

        if (!mcp_read_header_separator(in, &line, &cap, line_read)) {
            free(line);
            return CBM_NOT_FOUND;
        }
        free(line);
        char *body = mcp_read_framed_body(in, content_len);
        if (!body) {
            return CBM_NOT_FOUND;
        }
        *message = body;
        *content_length_framed = true;
        return SKIP_ONE;
    }
}

#ifndef _WIN32
/* Unix 3-phase poll: non-blocking fd check, FILE* buffer peek, blocking poll.
 * Returns: 1 = data ready, 0 = timeout (evicted idle stores), -1 = error/EOF. */
static int poll_for_input_unix(cbm_mcp_server_t *srv, int fd, FILE *in) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int pr = poll(&pfd, SKIP_ONE, 0); /* Phase 1: non-blocking */

    if (pr < 0) {
        return CBM_NOT_FOUND;
    }
    if (pr > 0) {
        return SKIP_ONE;
    }

    /* Phase 2: peek FILE* buffer */
    int saved_flags = fcntl(fd, F_GETFL);
    if (saved_flags < 0) {
        /* fcntl failed — fall through to a short blocking poll (see the Phase-3
         * note below on why the interval is bounded, not the full idle timeout) */
        pr = poll(&pfd, SKIP_ONE, MCP_TIMEOUT_MS);
        if (pr < 0) {
            return CBM_NOT_FOUND;
        }
        if (pr == 0) {
            cbm_mcp_server_evict_idle(srv, STORE_IDLE_TIMEOUT_S);
            return 0;
        }
        return SKIP_ONE;
    }

    (void)fcntl(fd, F_SETFL, saved_flags | O_NONBLOCK);
    int c = fgetc(in);
    (void)fcntl(fd, F_SETFL, saved_flags);

    if (c == EOF) {
        if (feof(in)) {
            return CBM_NOT_FOUND; /* true EOF */
        }
        clearerr(in);
        /* Phase 3: blocking poll, bounded to a SHORT interval (not the full idle
         * timeout). macOS poll()/select() do NOT report POLLIN/POLLHUP when a
         * FIFO's last writer closes — only read() returns 0 there (verified). A
         * 60s poll would therefore leave the server blocked up to a full idle
         * timeout after stdin EOF (a client that closes the pipe would appear to
         * hang). Waking every MCP_TIMEOUT_MS lets the Phase-2 read() above detect
         * the EOF within ~1s. Idle-store eviction (threshold STORE_IDLE_TIMEOUT_S)
         * is idempotent, so checking it on each short tick is harmless. */
        pr = poll(&pfd, SKIP_ONE, MCP_TIMEOUT_MS);
        if (pr < 0) {
            return CBM_NOT_FOUND;
        }
        if (pr == 0) {
            cbm_mcp_server_evict_idle(srv, STORE_IDLE_TIMEOUT_S);
            return 0;
        }
        return SKIP_ONE;
    }

    (void)ungetc(c, in);
    return SKIP_ONE;
}
#endif

/* ── Event loop ───────────────────────────────────────────────── */

int cbm_mcp_server_run(cbm_mcp_server_t *srv, FILE *in, FILE *out) {
    int fd = cbm_fileno(in);

#ifdef _WIN32
    /* Ensure stdio is in binary mode to prevent CRLF translation from corrupting
     * Content-Length byte counts and causing fread() to hang. */
    _setmode(cbm_fileno(in), _O_BINARY);
    _setmode(cbm_fileno(out), _O_BINARY);
#endif

    for (;;) {
        /* Poll with idle timeout so we can evict unused stores between requests.
         *
         * IMPORTANT: poll() operates on the raw fd, but getline() reads from a
         * buffered FILE*. When a client sends multiple messages in rapid
         * succession, the first getline() call may drain ALL kernel data into
         * libc's internal FILE* buffer. Subsequent poll() calls then see an
         * empty kernel fd and block for STORE_IDLE_TIMEOUT_S seconds even
         * though the next messages are already in the FILE* buffer.
         *
         * Fix (Unix): use a three-phase approach —
         *   Phase 1: non-blocking poll (timeout=0) to check the kernel fd.
         *   Phase 2: if Phase 1 returns 0, peek the FILE* buffer via fgetc/
         *            ungetc to detect data buffered by a prior getline() call.
         *            The fd is temporarily set O_NONBLOCK so fgetc() returns
         *            immediately (EAGAIN → EOF + ferror) instead of blocking
         *            when the FILE* buffer is empty, which would otherwise
         *            bypass the Phase 3 idle eviction timeout.
         *   Phase 3: only if both phases confirm no data, do blocking poll. */
#ifdef _WIN32
        /* Windows: WaitForSingleObject on stdin handle */
        HANDLE hStdin = (HANDLE)_get_osfhandle(fd);
        DWORD wr = WaitForSingleObject(hStdin, STORE_IDLE_TIMEOUT_S * MCP_TIMEOUT_MS);
        if (wr == WAIT_FAILED) {
            break;
        }
        if (wr == WAIT_TIMEOUT) {
            cbm_mcp_server_evict_idle(srv, STORE_IDLE_TIMEOUT_S);
            continue;
        }
#else
        int pr = poll_for_input_unix(srv, fd, in);
        if (pr < 0) {
            break;
        }
        if (pr == 0) {
            continue; /* timeout — idle stores evicted */
        }
#endif

        char *message = NULL;
        bool content_length_framed = false;
        if (cbm_mcp_read_message(in, &message, &content_length_framed) <= 0) {
            break;
        }

        char *resp = cbm_mcp_server_handle(srv, message);
        free(message);
        if (resp) {
            if (content_length_framed) {
                size_t response_len = strlen(resp);
                (void)fprintf(out, "Content-Length: %zu\r\n\r\n%s", response_len, resp);
            } else {
                (void)fprintf(out, "%s\n", resp);
            }
            (void)fflush(out);
            free(resp);
        }
    }

    return 0;
}

/* ── cbm_parse_file_uri ──────────────────────────────────────── */

bool cbm_parse_file_uri(const char *uri, char *out_path, int out_size) {
    if (!uri || !out_path || out_size <= 0) {
        if (out_path && out_size > 0) {
            out_path[0] = '\0';
        }
        return false;
    }

    /* Must start with file:// */
    if (strncmp(uri, "file://", SLEN("file://")) != 0) {
        out_path[0] = '\0';
        return false;
    }

    const char *path = uri + MCP_URI_PREFIX;

    /* On Windows, file:///C:/path → /C:/path. Strip leading / before drive letter. */
    if (path[0] == '/' && path[SKIP_ONE] &&
        ((path[SKIP_ONE] >= 'A' && path[SKIP_ONE] <= 'Z') ||
         (path[SKIP_ONE] >= 'a' && path[SKIP_ONE] <= 'z')) &&
        path[PAIR_LEN] == ':') {
        path++; /* skip the leading / */
    }

    /* out_size is a public API parameter; the out_size <= 0 guard above makes
     * it positive here, so the size_t conversion is safe. */
    snprintf(out_path, (size_t)out_size, "%s", path);
    return true;
}
