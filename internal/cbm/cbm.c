#include "cbm.h"
#include "arena.h" // CBMArena, cbm_arena_init/alloc/strdup/destroy
#include "helpers.h"
#include "lang_specs.h"
#include "extract_unified.h"
#include "lsp/go_lsp.h"
#include "lsp/c_lsp.h"
#include "lsp/php_lsp.h"
#include "lsp/perl_lsp.h"
#include "lsp/py_lsp.h"
#include "lsp/ts_lsp.h"
#include "lsp/cs_lsp.h"
#include "lsp/java_lsp.h"
#include "lsp/kotlin_lsp.h"
#include "lsp/rust_lsp.h"
#include "preprocessor.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"  // cbm_fopen — crash-supervisor per-file marker write
#include "foundation/hash_table.h" // CBMHashTable — crash-supervisor quarantine set
#include "tree_sitter/api.h" // TSParser, TSNode, TSTree, TSInput, TSLanguage, TSPoint, TSParseOptions, TSParseState
#include "foundation/constants.h"
#include <limits.h> // INT_MAX
#include <stdint.h> // uint32_t, uint64_t, int64_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h> // struct timespec, CLOCK_MONOTONIC

#if defined(CBM_BIND_TS_ALLOCATOR) && CBM_BIND_TS_ALLOCATOR
#include <mimalloc.h>
#endif

// Atomic counters for profiling parse vs extraction time (nanoseconds).
// Accessed from multiple threads; using _Atomic for safe accumulation.
#include <stdatomic.h>
static _Atomic uint64_t total_parse_ns = 0;
static _Atomic uint64_t total_extract_ns = 0;
static _Atomic uint64_t total_lsp_ns = 0;
static _Atomic uint64_t total_preprocess_ns = 0;
static _Atomic uint64_t total_files_preprocessed = 0;
static _Atomic uint64_t total_files = 0;

enum { CBM_MACRO_EXTRACTION_ENABLED = CBM_INIT_DONE };

// C/C++ preprocessor #define macros are extracted as Macro nodes (#375). On a
// macro-dense codebase (e.g. the Linux kernel: ~2.4M macros, 49% of all nodes)
// this is the dominant extraction cost, so it is gated to the full/advanced
// index modes. Default ON to preserve behavior for direct callers/tests; the
// pipeline sets it from the index mode before extraction. Set once pre-extract,
// read-only during, so a relaxed atomic is sufficient.
static _Atomic int g_extract_macros = CBM_MACRO_EXTRACTION_ENABLED;
void cbm_set_macro_extraction(int enabled) {
    atomic_store_explicit(&g_extract_macros, enabled ? CBM_MACRO_EXTRACTION_ENABLED : 0,
                          memory_order_relaxed);
}
int cbm_macro_extraction_enabled(void) {
    return atomic_load_explicit(&g_extract_macros, memory_order_relaxed);
}

#define NSEC_PER_SEC 1000000000ULL
#define USEC_TO_NSEC 1000ULL
/* Use compat.h's cbm_clock_gettime which accepts CLOCK_MONOTONIC (value
 * varies by platform: 1 on Linux/Windows, 6 on macOS). We pass the
 * platform value via the compat.h fallback. */
#ifdef CLOCK_MONOTONIC
#define CBM_CLOCK_MONO CLOCK_MONOTONIC
#elif defined(__APPLE__)
#define CBM_CLOCK_MONO 6
#else
#define CBM_CLOCK_MONO 1
#endif

static uint64_t now_ns(void) {
    struct timespec ts;
    cbm_clock_gettime(CBM_CLOCK_MONO, &ts);
    return ((uint64_t)ts.tv_sec * NSEC_PER_SEC) + (uint64_t)ts.tv_nsec;
}

// cbm_get_profile returns accumulated parse/extract times and file count.
void cbm_get_profile(cbm_profile_out_t out) {
    *out.parse_ns = atomic_load(&total_parse_ns);
    *out.extract_ns = atomic_load(&total_extract_ns);
    *out.files = atomic_load(&total_files);
}

uint64_t cbm_get_lsp_ns(void) {
    return atomic_load(&total_lsp_ns);
}

uint64_t cbm_get_preprocess_ns(void) {
    return atomic_load(&total_preprocess_ns);
}

uint64_t cbm_get_files_preprocessed(void) {
    return atomic_load(&total_files_preprocessed);
}

// cbm_reset_profile zeros the profiling counters.
void cbm_reset_profile(void) {
    atomic_store(&total_parse_ns, 0);
    atomic_store(&total_extract_ns, 0);
    atomic_store(&total_lsp_ns, 0);
    atomic_store(&total_preprocess_ns, 0);
    atomic_store(&total_files_preprocessed, 0);
    atomic_store(&total_files, 0);
}

// --- Growable array push functions ---

#define GROW_ARRAY(arr, arena)                                                                   \
    do {                                                                                         \
        if ((arr)->count >= (arr)->cap) {                                                        \
            if ((arr)->cap > INT_MAX / PAIR_LEN)                                                 \
                return;                                                                          \
            int new_cap = (arr)->cap == 0 ? CBM_SZ_32 : (arr)->cap * PAIR_LEN;                   \
            void *new_items = cbm_arena_alloc((arena), (size_t)new_cap * sizeof(*(arr)->items)); \
            if (!new_items)                                                                      \
                return;                                                                          \
            if ((arr)->items && (arr)->count > 0) {                                              \
                memcpy(new_items, (arr)->items, (size_t)(arr)->count * sizeof(*(arr)->items));   \
            }                                                                                    \
            (arr)->items = new_items;                                                            \
            (arr)->cap = new_cap;                                                                \
        }                                                                                        \
    } while (0)

void cbm_defs_push(CBMDefArray *arr, CBMArena *a, CBMDefinition def) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = def;
}

void cbm_calls_push(CBMCallArray *arr, CBMArena *a, CBMCall call) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = call;
}

void cbm_imports_push(CBMImportArray *arr, CBMArena *a, CBMImport imp) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = imp;
}

void cbm_usages_push(CBMUsageArray *arr, CBMArena *a, CBMUsage usage) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = usage;
}

void cbm_throws_push(CBMThrowArray *arr, CBMArena *a, CBMThrow thr) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = thr;
}

void cbm_rw_push(CBMRWArray *arr, CBMArena *a, CBMReadWrite rw) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = rw;
}

void cbm_typerefs_push(CBMTypeRefArray *arr, CBMArena *a, CBMTypeRef tr) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = tr;
}

void cbm_envaccess_push(CBMEnvAccessArray *arr, CBMArena *a, CBMEnvAccess ea) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = ea;
}

void cbm_typeassign_push(CBMTypeAssignArray *arr, CBMArena *a, CBMTypeAssign ta) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = ta;
}

void cbm_stringref_push(CBMStringRefArray *arr, CBMArena *a, CBMStringRef sr) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = sr;
}

void cbm_infrabinding_push(CBMInfraBindingArray *arr, CBMArena *a, CBMInfraBinding ib) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = ib;
}

void cbm_impltrait_push(CBMImplTraitArray *arr, CBMArena *a, CBMImplTrait it) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = it;
}

void cbm_resolvedcall_push(CBMResolvedCallArray *arr, CBMArena *a, CBMResolvedCall rc) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = rc;
}

void cbm_channels_push(CBMChannelArray *arr, CBMArena *a, CBMChannel ch) {
    GROW_ARRAY(arr, a);
    arr->items[arr->count++] = ch;
}

// --- String input reader (for parse_with_options) ---

typedef struct {
    const char *string;
    uint32_t length;
} CBMStringInput;

static const char *cbm_string_read(void *payload, uint32_t byte, TSPoint point,
                                   uint32_t *bytes_read) {
    (void)point;
    CBMStringInput *self = (CBMStringInput *)payload;
    if (byte >= self->length) {
        *bytes_read = 0;
        return "";
    }
    *bytes_read = self->length - byte;
    return self->string + byte;
}

// --- Parse timeout callback ---

static bool cbm_timeout_cb(TSParseState *state) {
    uint64_t deadline = *(uint64_t *)state->payload;
    return now_ns() > deadline;
}

// --- Thread-local parser pool ---
// TSParser is not thread-safe, but can be reused across files on the same thread.
// We keep one parser per thread, and just switch language as needed.
// This avoids ~70K ts_parser_new()/ts_parser_delete() cycles on large repos.

static CBM_TLS TSParser *tl_parser = NULL;
static CBM_TLS CBMLanguage tl_parser_lang = CBM_LANG_COUNT; // invalid sentinel

// Get or create a thread-local parser configured for the given language.
static TSParser *get_thread_parser(const TSLanguage *ts_lang, CBMLanguage lang) {
    if (!tl_parser) {
        tl_parser = ts_parser_new();
        if (!tl_parser) {
            return NULL;
        }
        tl_parser_lang = CBM_LANG_COUNT;
    }
    if (tl_parser_lang != lang) {
        ts_parser_set_language(tl_parser, ts_lang);
        tl_parser_lang = lang;
    }
    return tl_parser;
}

// --- Allocator binding (defense-in-depth, #424) ---

/* Bind tree-sitter to mimalloc explicitly so a correct
 * binary does NOT depend on the fragile MI_OVERRIDE symbol override. Under
 * MI_OVERRIDE=1 — particularly the Windows static-MinGW link with
 * --allow-multiple-definition — `malloc`/`free` can resolve to DIFFERENT
 * allocators (mimalloc vs the CRT) inside third-party libs, so a block
 * allocated by mimalloc gets freed by the CRT (or vice-versa), corrupting the
 * heap freelist (#424). Binding each library through one explicit allocator
 * eliminates that mismatch class generically, on every platform.
 *
 * Guarded to the production build (CBM_BIND_TS_ALLOCATOR=1, which CFLAGS_PROD
 * defines alongside MI_OVERRIDE=1). The test build is CRT + ASan, where binding
 * to mimalloc would mismatch ASan/CRT frees — there these binds compile to
 * no-ops and the build stays unchanged. */

#if defined(CBM_BIND_TS_ALLOCATOR) && CBM_BIND_TS_ALLOCATOR

/* tree-sitter allocates its parse trees through these, and they skip the
 * malloc interposer, so without a hook here they are invisible to the
 * attribution profile (#581). */
static void *cbm_ts_malloc(size_t n) {
    void *block = mi_malloc(n);
    return block;
}
static void *cbm_ts_calloc(size_t count, size_t size) {
    void *block = mi_calloc(count, size);
    return block;
}
static void *cbm_ts_realloc(void *p, size_t n) {
    if (p) {}
    void *grown = mi_realloc(p, n);
    return grown;
}
static void cbm_ts_free(void *p) {
    mi_free(p);
}

#endif /* CBM_BIND_TS_ALLOCATOR */

void cbm_alloc_init(void) {
#if defined(CBM_BIND_TS_ALLOCATOR) && CBM_BIND_TS_ALLOCATOR
    static int alloc_bound = 0; /* single-threaded startup; plain int is fine */
    if (alloc_bound) {
        return;
    }
    alloc_bound = 1;

    ts_set_allocator(cbm_ts_malloc, cbm_ts_calloc, cbm_ts_realloc, cbm_ts_free);

#endif /* CBM_BIND_TS_ALLOCATOR */
}

// --- Init/Shutdown ---

static int cbm_initialized = 0;

int cbm_init(void) {
    if (cbm_initialized) {
        return 0;
    }
    enum { CBM_INIT_COMPLETE = 1 };
    cbm_initialized = CBM_INIT_COMPLETE;
    /* Defense-in-depth allocator bind (idempotent). main() calls
     * cbm_alloc_init first; this covers non-main entry points, which reach
     * extraction through cbm_init (pipeline passes). */
    cbm_alloc_init();
    return 0;
}

void cbm_reset_thread_parser(void) {
    // Release parser's internal slab-allocated subtrees (stack, cached token).
    // Must be called BEFORE cbm_slab_reset_thread() to avoid corrupting
    // live slab chunks that the parser still references.
    if (tl_parser) {
        ts_parser_reset(tl_parser);
    }
}

void cbm_destroy_thread_parser(void) {
    // Full cleanup: delete the parser. Call on worker thread exit.
    if (tl_parser) {
        ts_parser_delete(tl_parser);
        tl_parser = NULL;
        tl_parser_lang = CBM_LANG_COUNT;
    }
}

void cbm_shutdown(void) {
    // Clean up thread-local parser for the calling thread.
    // Note: other threads' TLS parsers are freed when those threads exit.
    cbm_destroy_thread_parser();
    cbm_initialized = 0;
}

// --- Bottleneck call-name classification (language-agnostic heuristics) ---

// Case-insensitive equality for short callee names.
static bool name_ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
    }
    return *a == '\0' && *b == '\0';
}

static bool name_in_set(const char *name, const char *const *set) {
    for (const char *const *s = set; *s; s++) {
        if (name_ieq(name, *s)) {
            return true;
        }
    }
    return false;
}

// Linear-scan / membership calls: a hit inside a loop is the textbook hidden
// O(n^2) (cf. Olivo et al., PLDI'15) that syntactic loop-depth alone misses.
static bool is_linear_scan_name(const char *n) {
    static const char *const set[] = {"find",    "indexof",   "contains", "includes", "search",
                                      "lookup",  "strstr",    "strchr",   "strrchr",  "memchr",
                                      "find_if", "findindex", "count",    "index",    NULL};
    return name_in_set(n, set);
}

// Allocation / growable-append calls: repeated inside a loop is the classic
// accidental reallocation / string-concat O(n^2). Names are deliberately
// conservative; meaningless in some languages → simply never matches there.
static bool is_alloc_name(const char *n) {
    static const char *const set[] = {"malloc",  "calloc",    "realloc",      "strdup", "strndup",
                                      "append",  "push_back", "emplace_back", "concat", "strcat",
                                      "strncat", "push",      "pushback",     NULL};
    return name_in_set(n, set);
}

// Extract the receiver identifier from a def's receiver text — Go's
// "(s *Store)" / "(s Store)" → "s". Stores the identifier start in *out and
// returns its length; returns 0 for unnamed receivers ("(*Store)", "(Store)"),
// where no second token follows the identifier (a lone token is the TYPE, not
// a name — such methods have no receiver variable to call through anyway).
static size_t receiver_ident(const char *recv_text, const char **out) {
    const char *p = recv_text;
    if (*p == '(') {
        p++;
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    const char *start = p;
    while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
           *p == '_') {
        p++;
    }
    size_t len = (size_t)(p - start);
    if (len == 0) {
        return 0; // "(*Store)": leading '*', no identifier
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p == ')' || *p == '\0') {
        return 0; // "(Store)": single token is the type, receiver unnamed
    }
    *out = start;
    return len;
}

// Whether a callee expression targets the same instance/class as the enclosing
// def, i.e. counts as genuine self-recursion rather than a same-named call on a
// different receiver. callee_name may be bare ("recur") or qualified
// ("self.recur", "this.recur", "super().save", "axios.get", "self.obj.recur").
//
// Bare names have no receiver → assume self-call (free function calling itself
// by bare name; preserves prior behavior). Qualified names: the receiver chain
// is everything before the LAST '.', and the WHOLE chain must name the same
// object — self/this/cls/@self, or the enclosing def's own receiver identifier
// (Go: `s` in `func (s *Store) save()`, from CBMDefinition.receiver). Matching
// the whole chain (not its first segment) keeps self.obj.recur() out: it
// targets self's FIELD obj, a different object. super() is the parent class and
// any other receiver (axios, console, ...) a different target. See #599.
static bool is_self_receiver(const char *callee_name, const char *def_receiver) {
    if (!callee_name || !callee_name[0]) {
        return false;
    }
    const char *dot = strrchr(callee_name, '.');
    if (!dot) {
        return true; // bare name → self-recursion candidate
    }
    size_t rlen = (size_t)(dot - callee_name);
    static const char *const self_receivers[] = {"self", "this", "cls", "@self", NULL};
    for (int i = 0; self_receivers[i]; i++) {
        size_t sl = strlen(self_receivers[i]);
        if (rlen == sl && strncmp(callee_name, self_receivers[i], sl) == 0) {
            return true;
        }
    }
    if (def_receiver) {
        const char *rid = NULL;
        size_t ril = receiver_ident(def_receiver, &rid);
        if (ril > 0 && ril == rlen && strncmp(callee_name, rid, ril) == 0) {
            return true; // call through the enclosing method's own receiver
        }
    }
    return false; // super() / axios / console / self.obj / any other receiver
}

// Count parameters from a signature string like "(int a, Foo* b, cb (*)(int,int))".
// Fallback for languages where param_names isn't populated (e.g. C keeps only the
// signature text). Counts commas at the top paren level; treats "()"/"(void)" as 0.
// Approximate by design (a structural smell, not an exact arity).
static int count_params_from_signature(const char *sig) {
    if (!sig) {
        return 0;
    }
    const char *p = sig;
    while (*p && *p != '(') {
        p++;
    }
    if (*p != '(') {
        return 0;
    }
    p++;
    const char *list = p;
    int commas = 0;
    bool any = false;
    int depth = 0;
    for (; *p; p++) {
        char ch = *p;
        if (strchr("([{<", ch)) {
            depth++;
        } else if (ch == ')') {
            if (depth == 0) {
                break;
            }
            depth--;
        } else if (strchr("]}>", ch)) {
            if (depth > 0) {
                depth--;
            }
        } else if (ch == ',' && depth == 0) {
            commas++;
        } else if (!isspace((unsigned char)ch)) {
            any = true;
        }
    }
    if (!any) {
        return 0;
    }
    while (*list == ' ' || *list == '\t') {
        list++;
    }
    return commas == 0 && strncmp(list, "void", CBM_SZ_4) == 0 &&
                   (list[CBM_SZ_4] == ')' || list[CBM_SZ_4] == ' ' || list[CBM_SZ_4] == '\0')
               ? 0
               : commas + SKIP_ONE;
}

// --- Main extraction function ---

/* Test-only deterministic fault injection for the crash/hang supervisor tests.
 * Gated entirely behind env vars that are never set in production; a matching
 * rel_path either aborts (a fault signal the supervisor classifies as a crash)
 * or spins forever (an external-scanner infinite loop the quiet-timeout kills).
 * This gives an honest guard — green iff the supervisor actually contains a real
 * fault — instead of a fixture that may stop faulting once a root cause is fixed. */
/* Crash-supervisor per-file marker JOURNAL (Stage 3c skip-and-continue,
 * parallel-safe). Recovery re-runs are PARALLEL (there are no sequential
 * production runs), so a single overwrite-style marker would race across
 * workers and — worse — go stale during non-extract phases, blaming
 * whatever file was extracted LAST (that mis-quarantined four innocent
 * ms-typescript fixtures, one 15-minute retry at a time). Instead every
 * worker APPENDS one short line per event: "S <rel_path>" when it STARTS
 * work on a file, "D <rel_path>" when it finishes it. A single short
 * append of one line is atomic in practice on every target platform, and
 * the parent discards a torn final line by design. The parent's suspect
 * set after a crash/hang = files with an S but no D — exactly the
 * in-flight set; a file is only quarantined after appearing in the
 * suspect set of TWO CONSECUTIVE failed runs, so a stale or merely
 * unlucky in-flight file is never quarantined alone. The env var is set
 * solely by the supervisor during recovery — a no-op on normal runs. */
static void cbm_index_mark(const char *rel_path, char event) {
    const char *mf = getenv("CBM_INDEX_MARKER_FILE");
    if (!mf || !mf[0] || !rel_path || !rel_path[0]) {
        return;
    }
    FILE *f = cbm_fopen(mf, "ab");
    if (f) {
        (void)fprintf(f, "%c %s\n", event, rel_path);
        (void)fclose(f);
    }
}

void cbm_index_mark_start(const char *rel_path) {
    cbm_index_mark(rel_path, 'S');
}

void cbm_index_mark_done(const char *rel_path) {
    cbm_index_mark(rel_path, 'D');
}

/* ── Crash-quarantine set (Stage 3c skip-and-continue) ──────────────────────
 * After a crash the supervisor re-runs the worker single-threaded, passing
 * CBM_INDEX_QUARANTINE_FILE — a newline-delimited list of repo-relative paths
 * that already crashed the indexer and MUST NOT be extracted again. Owned here,
 * next to the other env-driven extract hooks (marker + fault injector), so the
 * single hard guard lives at the one choke point every pass funnels through
 * (cbm_extract_file): whether a pass re-extracts from disk on a cache miss
 * (sequential pass_calls/usages/semantic) or extracts fresh, a quarantined file
 * short-circuits to an empty result and never reaches the parser/crash. The
 * pipeline extract loops separately REPORT the skip as phase="crash" via
 * cbm_index_is_quarantined() so the crasher surfaces in the response skipped[].
 * Loaded once, lazily; read-only after load (safe for the parallel workers,
 * though recovery runs single-threaded). Unset env ⇒ empty set ⇒ cheap no-op. */
static CBMHashTable *g_quarantine_set = NULL;
enum { CBM_QSET_UNINIT = 0, CBM_QSET_INITING = 1, CBM_QSET_INITED = 2 };
static atomic_int g_quarantine_state = CBM_QSET_UNINIT;

static void cbm_quarantine_trim_line(char *line) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - SKIP_ONE] == '\n' || line[len - SKIP_ONE] == '\r')) {
        line[--len] = '\0';
    }
}

static const char *cbm_quarantine_line_phase(char *line) {
    char *tab = strchr(line, '\t');
    if (!tab) {
        return "crash";
    }
    *tab = '\0';
    return tab[SKIP_ONE] ? tab + SKIP_ONE : "crash";
}

static void cbm_quarantine_add(CBMHashTable *set, const char *path, const char *phase) {
    char *value = cbm_strdup(phase);
    if (!value) {
        return;
    }
    if (cbm_ht_has(set, path)) {
        free(cbm_ht_set(set, path, value));
        return;
    }
    char *key = cbm_strdup(path);
    if (key) {
        cbm_ht_set(set, key, value);
    } else {
        free(value);
    }
}

static void cbm_quarantine_load(void) {
    const char *qf = getenv("CBM_INDEX_QUARANTINE_FILE");
    if (!qf || !qf[0]) {
        return; /* normal path: empty set */
    }
    FILE *f = cbm_fopen(qf, "rb");
    if (!f) {
        return;
    }
    CBMHashTable *set = cbm_ht_create(CBM_SZ_16);
    if (!set) {
        (void)fclose(f);
        return;
    }
    char line[CBM_SZ_2K];
    while (fgets(line, sizeof(line), f)) {
        cbm_quarantine_trim_line(line);
        if (!line[0]) {
            continue;
        }
        /* Line format: "path\tphase" where phase is "crash" or "hang". A bare
         * "path" line (no tab) is tolerated and defaults to phase "crash" for
         * backward compatibility with older quarantine files. */
        const char *phase = cbm_quarantine_line_phase(line);
        if (line[0] == '\0') {
            continue; /* empty path (line began with a tab) — skip */
        }
        /* The table borrows the key + value pointers, so dup both. Intentionally
         * never freed: the set lives for the whole (short-lived worker) process.
         * The value stores the phase so cbm_index_quarantine_phase() can report
         * "crash" vs "hang"; membership (cbm_index_is_quarantined) is value != NULL. */
        cbm_quarantine_add(set, line, phase);
    }
    (void)fclose(f);
    g_quarantine_set = set;
}

bool cbm_index_is_quarantined(const char *rel_path) {
    if (!rel_path || !rel_path[0]) {
        return false;
    }
    int state = atomic_load(&g_quarantine_state);
    if (state != CBM_QSET_INITED) {
        /* First caller wins the CAS and loads; racers spin until INITED.
         * Same once-init pattern as cbm_ui_log_init (http_server.c). */
        state = CBM_QSET_UNINIT;
        if (atomic_compare_exchange_strong(&g_quarantine_state, &state, CBM_QSET_INITING)) {
            cbm_quarantine_load();
            atomic_store(&g_quarantine_state, CBM_QSET_INITED);
        } else {
            while (atomic_load(&g_quarantine_state) != CBM_QSET_INITED) {
                cbm_usleep(1000); /* 1ms */
            }
        }
    }
    return g_quarantine_set && cbm_ht_has(g_quarantine_set, rel_path);
}

const char *cbm_index_quarantine_phase(const char *rel_path) {
    /* cbm_index_is_quarantined drives the lazy once-load and returns true only
     * when the set is loaded and holds rel_path — so on true, g_quarantine_set is
     * non-NULL and the stored value is the phase string ("crash"/"hang"). */
    if (!cbm_index_is_quarantined(rel_path)) {
        return NULL;
    }
    return (const char *)cbm_ht_get(g_quarantine_set, rel_path);
}

static void cbm_test_fault_inject(const char *rel_path) {
    if (!rel_path || !rel_path[0]) {
        return;
    }
    const char *crash_on = getenv("CBM_TEST_CRASH_ON");
    if (crash_on && crash_on[0] && strstr(rel_path, crash_on)) {
        abort(); /* SIGABRT → WIFSIGNALED → classified as a crash */
    }
    const char *hang_on = getenv("CBM_TEST_HANG_ON");
    if (hang_on && hang_on[0] && strstr(rel_path, hang_on)) {
        for (;;) {
            /* Busy-spin: the supervisor's quiet-timeout kills + reports us. */
        }
    }
}

/* Pre-parse nesting guard for pathologically nested input. tree-sitter's GLR
 * parser recurses once per nesting level inside stack_node_add_link
 * (vendored ts_runtime/src/stack.c) while merging ambiguous parse-stack heads.
 * The Perl grammar is genuinely ambiguous for `f(...)` (function call vs.
 * bareword), so a deeply nested call chain `f(f(f(...)))` drives that recursion
 * as deep as the nesting and overflows a small (1 MB Windows) stack *during the
 * parse* — before any of the LSP walk-depth guards can fire. Unambiguous
 * grammars (C/Java/Python) keep a single stack head and don't hit this, which is
 * why only Perl crashed on the Windows/ARM CI runners.
 *
 * This is a workaround: the proper fix is bounding the GLR stack-merge recursion
 * inside the vendored tree-sitter runtime, tracked upstream as #913. Remove this
 * guard once that lands.
 *
 * cbm_source_nesting_exceeds scans the raw bytes for the maximum bracket-nesting
 * depth and returns true as soon as it passes the cap (early-exit, O(n)). Real
 * source never nests brackets this deep, so a file that does is skipped as a
 * parse error (zero edges — graceful degradation, never a crash). Brackets in
 * strings/comments are counted too: the only consequence of a false positive is
 * skipping one absurd file, so string-awareness is not worth the cost. */
#define CBM_PERL_MAX_PARSE_NESTING 128

static bool cbm_source_nesting_exceeds(const char *source, int source_len, int cap) {
    int depth = 0;
    for (int i = 0; i < source_len; i++) {
        char c = source[i];
        if (c == '(' || c == '[' || c == '{') {
            if (++depth > cap) {
                return true;
            }
        } else if ((c == ')' || c == ']' || c == '}') && depth > 0) {
            depth--;
        }
    }
    return false;
}

/* Best-effort parse-coverage collection (#963). Walks only the has_error paths
 * of the tree and records the 1-based line ranges of the TOP-MOST ERROR/MISSING
 * nodes (does not descend into an error subtree — one range per failed region).
 * Bounded by CBM_MAX_ERROR_REGIONS so pathological input can't blow up the
 * output. The ranges mark where constructs were dropped; they are a detection
 * aid, never a completeness proof. */
#define CBM_MAX_ERROR_REGIONS 64
typedef struct {
    uint32_t starts[CBM_MAX_ERROR_REGIONS];
    uint32_t ends[CBM_MAX_ERROR_REGIONS];
    int count;
} cbm_error_regions_t;

static void cbm_error_regions_push(cbm_error_regions_t *acc, TSNode n) {
    if (acc->count >= CBM_MAX_ERROR_REGIONS) {
        return;
    }
    acc->starts[acc->count] = ts_node_start_point(n).row + TS_LINE_OFFSET;
    acc->ends[acc->count] = ts_node_end_point(n).row + TS_LINE_OFFSET;
    acc->count++;
}

static void cbm_collect_error_regions(TSNode n, cbm_error_regions_t *acc) {
    TSTreeCursor cursor = ts_tree_cursor_new(n);
    bool descend = true;
    while (acc->count < CBM_MAX_ERROR_REGIONS) {
        if (descend && ts_tree_cursor_goto_first_child(&cursor)) {
        } else {
            while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
                if (!ts_tree_cursor_goto_parent(&cursor)) {
                    ts_tree_cursor_delete(&cursor);
                    return;
                }
            }
        }
        TSNode current = ts_tree_cursor_current_node(&cursor);
        if (ts_node_is_missing(current) || strcmp(ts_node_type(current), "ERROR") == 0) {
            cbm_error_regions_push(acc, current);
            descend = false;
        } else {
            descend = ts_node_has_error(current);
        }
    }
    ts_tree_cursor_delete(&cursor);
}

/* Recovery subtraction (#963): tree-sitter error recovery plus the
 * ERROR-descending def walker often still extract constructs INSIDE a failed
 * region (verified: a function in an #ifdef-split ERROR region and even a
 * `def broken(:` both came back as defs). A region whose every line is
 * covered by definitions that START inside it is definitely recovered — its
 * constructs ARE in the graph — so flagging it would be a false miss.
 * Container defs (Module/Package) are ignored: a file-spanning Module node is
 * not evidence the region's constructs survived. Conservative: partially
 * covered regions stay flagged. */
static bool cbm_region_is_recovered(uint32_t rs, uint32_t re, const CBMDefArray *defs) {
    enum { MAX_COVER_DEFS = 256 };
    uint32_t starts[MAX_COVER_DEFS];
    uint32_t ends[MAX_COVER_DEFS];
    int n = 0;
    for (int i = 0; i < defs->count && n < MAX_COVER_DEFS; i++) {
        const CBMDefinition *d = &defs->items[i];
        if (!d->label || strcmp(d->label, "Module") == 0 || strcmp(d->label, "Package") == 0) {
            continue;
        }
        if (d->start_line < rs || d->start_line > re) {
            continue; /* recovery evidence must originate inside the region */
        }
        starts[n] = d->start_line;
        ends[n] = d->end_line < d->start_line ? d->start_line : d->end_line;
        n++;
    }
    if (n == 0) {
        return false;
    }
    /* Insertion-sort by start, then sweep for gaps in [rs, re]. */
    for (int i = SKIP_ONE; i < n; i++) {
        uint32_t s = starts[i];
        uint32_t e = ends[i];
        int j = i - SKIP_ONE;
        while (j >= 0 && starts[j] > s) {
            starts[j + SKIP_ONE] = starts[j];
            ends[j + SKIP_ONE] = ends[j];
            j--;
        }
        starts[j + SKIP_ONE] = s;
        ends[j + SKIP_ONE] = e;
    }
    uint32_t covered_to = rs - SKIP_ONE;
    for (int i = 0; i < n; i++) {
        if (starts[i] > covered_to + SKIP_ONE) {
            return false; /* uncovered gap */
        }
        if (ends[i] > covered_to) {
            covered_to = ends[i];
        }
    }
    return covered_to >= re;
}

/* #961: true when 1-based `line` of `src` contains `name` (used to verify a
 * def recovered from EXPANDED source really lives on that ORIGINAL line —
 * rejects header-inlined defs whose physical expanded lines alias unrelated
 * raw lines when compile_commands include paths are present). */
static bool cbm_line_contains(const char *src, int src_len, uint32_t line, const char *name) {
    if (!src || !name || !name[0] || line == 0) {
        return false;
    }
    uint32_t cur = TS_LINE_OFFSET;
    int i = 0;
    while (i < src_len && cur < line) {
        if (src[i] == '\n') {
            cur++;
        }
        i++;
    }
    if (cur != line) {
        return false;
    }
    int end = i;
    while (end < src_len && src[end] != '\n') {
        end++;
    }
    size_t nlen = strlen(name);
    for (int j = i; j + (int)nlen <= end; j++) {
        if (strncmp(src + j, name, nlen) == 0) {
            return true;
        }
    }
    return false;
}

static bool cbm_identifier_char(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

static bool cbm_source_line_span(const char *src, int src_len, uint32_t start_line,
                                 uint32_t end_line, int *span_start, int *span_end) {
    int start = 0;
    uint32_t line = TS_LINE_OFFSET;
    while (start < src_len && line < start_line) {
        if (src[start++] == '\n') {
            line++;
        }
    }
    if (line != start_line) {
        return false;
    }
    int end = start;
    while (end < src_len && line <= end_line) {
        if (src[end++] == '\n') {
            line++;
        }
    }
    *span_start = start;
    *span_end = end;
    return true;
}

static bool cbm_name_at_span(const char *src, int src_len, int pos, int name_len,
                             const char *name) {
    return strncmp(src + pos, name, (size_t)name_len) == 0 &&
           (pos == 0 || !cbm_identifier_char(src[pos - SKIP_ONE])) &&
           (pos + name_len >= src_len || !cbm_identifier_char(src[pos + name_len]));
}

static bool cbm_has_callable_prefix(const char *src, int span_start, int pos) {
    int before = pos;
    while (before > span_start && isspace((unsigned char)src[before - SKIP_ONE])) {
        before--;
    }
    return before == span_start || !strchr("(,=!?[.", src[before - SKIP_ONE]);
}

static int cbm_after_callable_parameters(const char *src, int span_end, int open) {
    int depth = 0;
    for (int i = open; i < span_end; i++) {
        if (src[i] == '(') {
            depth++;
        } else if (src[i] == ')' && --depth == 0) {
            return i + SKIP_ONE;
        }
    }
    return CBM_NOT_FOUND;
}

static bool cbm_has_callable_body(const char *src, int span_end, int after_parameters) {
    for (int i = after_parameters; i < span_end; i++) {
        if (src[i] == '{') {
            return true;
        }
        if (src[i] == ';') {
            return false;
        }
    }
    return false;
}

static bool cbm_name_is_invoked(const char *src, int src_len, int span_start, int span_end,
                                const char *name) {
    size_t name_len_size = strlen(name);
    if (name_len_size > (size_t)INT_MAX) {
        return false;
    }
    int name_len = (int)name_len_size;
    for (int pos = span_start; pos + name_len <= span_end; pos++) {
        if (!cbm_name_at_span(src, src_len, pos, name_len, name)) {
            continue;
        }
        int open = pos + name_len;
        while (open < span_end && isspace((unsigned char)src[open])) {
            open++;
        }
        if (open < span_end && src[open] == '(') {
            return true;
        }
    }
    return false;
}

/* Verify that the mapped original span contains callable-definition syntax,
 * not merely the name at a macro invocation or call site. */
static bool cbm_span_contains_callable_def(const char *src, int src_len, uint32_t start_line,
                                           uint32_t end_line, const char *name) {
    if (!src || src_len <= 0 || !name || !name[0] || start_line == 0 || end_line < start_line) {
        return false;
    }
    int span_start;
    int span_end;
    if (!cbm_source_line_span(src, src_len, start_line, end_line, &span_start, &span_end)) {
        return false;
    }
    /* This function works in int offsets throughout (matching src_len's
     * public-API int type), so convert name's length to int once here,
     * guarding the one place a size_t could exceed INT_MAX, instead of
     * re-casting it at every use below. */
    size_t name_len_sz = strlen(name);
    if (name_len_sz > (size_t)INT_MAX) {
        return false;
    }
    int name_len = (int)name_len_sz;
    for (int pos = span_start; pos + name_len <= span_end; pos++) {
        if (!cbm_name_at_span(src, src_len, pos, name_len, name)) {
            continue;
        }
        if (!cbm_has_callable_prefix(src, span_start, pos)) {
            continue;
        }
        int open = pos + name_len;
        while (open < span_end && isspace((unsigned char)src[open])) {
            open++;
        }
        if (open >= span_end || src[open] != '(') {
            continue;
        }
        int after_parameters = cbm_after_callable_parameters(src, span_end, open);
        if (after_parameters < 0) {
            continue;
        }
        if (cbm_has_callable_body(src, span_end, after_parameters)) {
            return true;
        }
    }
    return false;
}

/* Remap an expanded-source definition back to the original input file. Every
 * line in the definition must be attributable to the main file; generated
 * macro bodies, included headers, and ambiguous spans fail closed. */
static bool cbm_remap_preprocessed_def(CBMDefinition *def, const CBMPreprocessedSource *pp) {
    if (!def || !pp || !pp->original_line_by_expanded_line || !pp->belongs_to_main_file ||
        def->start_line == 0 || def->end_line < def->start_line ||
        def->end_line > (uint32_t)pp->expanded_line_count) {
        return false;
    }

    uint32_t original_start = pp->original_line_by_expanded_line[def->start_line];
    uint32_t original_end = pp->original_line_by_expanded_line[def->end_line];
    if (!original_start || !original_end || original_end < original_start) {
        return false;
    }
    for (uint32_t line = def->start_line; line <= def->end_line; line++) {
        if (!pp->belongs_to_main_file[line] || !pp->original_line_by_expanded_line[line]) {
            return false;
        }
    }

    def->start_line = original_start;
    def->end_line = original_end;
    def->lines = (int)(original_end - original_start + SKIP_ONE);
    return true;
}

static void cbm_subtract_recovered_regions(cbm_error_regions_t *regs, const CBMDefArray *defs) {
    int kept = 0;
    for (int i = 0; i < regs->count; i++) {
        if (!cbm_region_is_recovered(regs->starts[i], regs->ends[i], defs)) {
            regs->starts[kept] = regs->starts[i];
            regs->ends[kept] = regs->ends[i];
            kept++;
        }
    }
    regs->count = kept;
}

/* #1071: a function-like macro invocation whose argument is a type token
 * (e.g. ALLOC(int, n)) makes tree-sitter's C/C++ grammar emit an ERROR node — it
 * parses `int` in expression position — which would be recorded as a parse_partial
 * coverage gap. But the macro is #defined in THIS file, so nothing is actually
 * missing from the graph; it's a benign call the grammar can't parse without the
 * preprocessor. True if the [start_line, end_line] span contains a call `NAME(` to
 * a file-defined function-like macro (Macro label + a parameter signature). */
static bool cbm_span_is_macro_invocation(const char *src, int src_len, uint32_t start_line,
                                         uint32_t end_line, const CBMDefArray *defs) {
    if (!src || src_len <= 0 || !defs || start_line == 0 || end_line < start_line) {
        return false;
    }
    int span_start;
    int span_end;
    if (!cbm_source_line_span(src, src_len, start_line, end_line, &span_start, &span_end)) {
        return false;
    }
    for (int di = 0; di < defs->count; di++) {
        const CBMDefinition *d = &defs->items[di];
        /* Function-like macros only: an object-like macro (#define PI 3.14) has no
         * parameter signature and can't be mistaken for a call. */
        if (!d->label || strcmp(d->label, "Macro") != 0 || !d->signature || !d->name ||
            !d->name[0]) {
            continue;
        }
        if (cbm_name_is_invoked(src, src_len, span_start, span_end, d->name)) {
            return true;
        }
    }
    return false;
}

/* True if [rs, re] is fully enclosed by an extracted callable definition (a
 * Function/Method body). A macro invocation INSIDE a real function body is an
 * expression-level use where nothing is missing (#1071). A TOP-LEVEL invocation
 * is different: the macro may itself expand to a definition that the original
 * span doesn't contain (#949), which must stay flagged. Restricting the #1071
 * suppression to in-body calls keeps that #949 gap honest and fails safe. */
static bool cbm_region_inside_callable(uint32_t rs, uint32_t re, const CBMDefArray *defs) {
    for (int i = 0; i < defs->count; i++) {
        const CBMDefinition *d = &defs->items[i];
        if (!d->label) {
            continue;
        }
        if (strcmp(d->label, "Function") != 0 && strcmp(d->label, "Method") != 0 &&
            strcmp(d->label, "Constructor") != 0 && strcmp(d->label, "Destructor") != 0) {
            continue;
        }
        if (d->start_line <= rs && d->end_line >= re && d->end_line > d->start_line) {
            return true;
        }
    }
    return false;
}

static void cbm_subtract_macro_invocation_regions(cbm_error_regions_t *regs,
                                                  const CBMDefArray *defs, const char *src,
                                                  int src_len) {
    int kept = 0;
    for (int i = 0; i < regs->count; i++) {
        bool benign =
            cbm_span_is_macro_invocation(src, src_len, regs->starts[i], regs->ends[i], defs) &&
            cbm_region_inside_callable(regs->starts[i], regs->ends[i], defs);
        if (!benign) {
            regs->starts[kept] = regs->starts[i];
            regs->ends[kept] = regs->ends[i];
            kept++;
        }
    }
    regs->count = kept;
}

/* Serialize collected regions as "start-end,start-end,..." into the arena. */
static const char *cbm_error_ranges_str(CBMArena *a, const cbm_error_regions_t *regs) {
    if (regs->count <= 0) {
        return NULL;
    }
    enum { RANGE_MAX = 24 }; /* "4294967295-4294967295," */
    char *buf = (char *)cbm_arena_alloc(a, (size_t)regs->count * RANGE_MAX);
    if (!buf) {
        return NULL;
    }
    size_t off = 0;
    for (int i = 0; i < regs->count; i++) {
        off += (size_t)snprintf(buf + off, RANGE_MAX, "%s%u-%u", i ? "," : "", regs->starts[i],
                                regs->ends[i]);
    }
    return buf;
}

static bool cbm_has_suffix(const char *path, const char *suffix, size_t suffix_length) {
    if (!path) {
        return false;
    }
    size_t length = strlen(path);
    return length >= suffix_length && strcmp(path + length - suffix_length, suffix) == 0;
}

static void cbm_run_lsp_extractors(CBMArena *arena, CBMFileResult *result, const char *source,
                                   int source_len, TSNode root, CBMLanguage language,
                                   const char *rel_path) {
    if (language == CBM_LANG_GO) {
        cbm_run_go_lsp(arena, result, source, source_len, root);
    }
    if (language == CBM_LANG_C || language == CBM_LANG_CPP || language == CBM_LANG_CUDA) {
        cbm_run_c_lsp(arena, result, source, source_len, root, language != CBM_LANG_C,
                      CBM_SOURCE_ORIGIN_RAW);
    }
    if (language == CBM_LANG_PHP) {
        cbm_run_php_lsp(arena, result, source, source_len, root);
    }
    if (language == CBM_LANG_PERL) {
        cbm_run_perl_lsp(arena, result, source, source_len, root);
    }
    if (language == CBM_LANG_PYTHON) {
        cbm_run_py_lsp(arena, result, source, source_len, root);
    }
    if (language == CBM_LANG_JAVASCRIPT || language == CBM_LANG_TYPESCRIPT ||
        language == CBM_LANG_TSX) {
        bool js_mode = language == CBM_LANG_JAVASCRIPT;
        bool jsx_mode =
            language == CBM_LANG_TSX || (js_mode && cbm_has_suffix(rel_path, ".jsx", CBM_SZ_4));
        bool dts_mode =
            language == CBM_LANG_TYPESCRIPT && cbm_has_suffix(rel_path, ".d.ts", CBM_SZ_5);
        cbm_run_ts_lsp(arena, result, source, source_len, root, js_mode, jsx_mode, dts_mode);
    }
    if (language == CBM_LANG_CSHARP) {
        cbm_run_cs_lsp(arena, result, source, source_len, root);
    }
    if (language == CBM_LANG_JAVA) {
        cbm_run_java_lsp(arena, result, source, source_len, root);
    }
    if (language == CBM_LANG_KOTLIN) {
        cbm_run_kotlin_lsp(arena, result, source, source_len, root);
    }
    if (language == CBM_LANG_RUST) {
        cbm_run_rust_lsp(arena, result, source, source_len, root);
    }
}

static void cbm_run_primary_extractors(CBMExtractCtx *ctx) {
    cbm_extract_definitions(ctx);
    cbm_extract_imports(ctx);
    cbm_extract_unified(ctx);
    cbm_extract_channels(ctx);
    if (ctx->language == CBM_LANG_KUSTOMIZE || ctx->language == CBM_LANG_K8S) {
        cbm_extract_k8s(ctx);
    }
}

static void cbm_set_definition_parameter_counts(CBMDefArray *defs) {
    for (int i = 0; i < defs->count; i++) {
        CBMDefinition *definition = &defs->items[i];
        int count = 0;
        while (definition->param_names && definition->param_names[count]) {
            count++;
        }
        definition->param_count = count == 0 && definition->signature
                                      ? count_params_from_signature(definition->signature)
                                      : count;
    }
}

static int cbm_enclosing_callable_index(const CBMDefArray *defs, int line) {
    int best = CBM_NOT_FOUND;
    int best_span = CBM_NOT_FOUND;
    for (int i = 0; i < defs->count; i++) {
        const CBMDefinition *definition = &defs->items[i];
        bool callable = definition->label && (strcmp(definition->label, "Function") == 0 ||
                                              strcmp(definition->label, "Method") == 0);
        if (!callable || !definition->name || (int)definition->start_line > line ||
            line > (int)definition->end_line) {
            continue;
        }
        int span = (int)definition->end_line - (int)definition->start_line;
        if (best < 0 || span < best_span) {
            best = i;
            best_span = span;
        }
    }
    return best;
}

static void cbm_update_self_metrics(CBMDefinition *definition, const CBMCall *call,
                                    int definition_index, bool *has_self, bool *has_guarded) {
    const char *dot = strrchr(call->callee_name, '.');
    const char *short_name = dot ? dot + SKIP_ONE : call->callee_name;
    bool in_loop = call->loop_depth > 0;
    if (strcmp(short_name, definition->name) == 0 &&
        is_self_receiver(call->callee_name, definition->receiver)) {
        definition->is_recursive = true;
        if (has_self) {
            has_self[definition_index] = true;
        }
        if (in_loop) {
            definition->recursion_in_loop = true;
        }
        if (call->branch_depth > 0 && has_guarded) {
            has_guarded[definition_index] = true;
        }
    }
    if (in_loop && is_linear_scan_name(short_name)) {
        definition->linear_scan_in_loop++;
    }
    if (in_loop && is_alloc_name(short_name)) {
        definition->alloc_in_loop++;
    }
}

static void cbm_record_call_metrics(CBMFileResult *result, int call_count, bool *has_self,
                                    bool *has_guarded) {
    for (int i = 0; i < call_count; i++) {
        const CBMCall *call = &result->calls.items[i];
        if (!call->callee_name || call->start_line <= 0) {
            continue;
        }
        int definition_index = cbm_enclosing_callable_index(&result->defs, call->start_line);
        if (definition_index < 0) {
            continue;
        }
        CBMDefinition *definition = &result->defs.items[definition_index];
        cbm_update_self_metrics(definition, call, definition_index, has_self, has_guarded);
    }
}

static void cbm_compute_metrics(CBMFileResult *result, int call_count) {
    int definition_count = result->defs.count;
    bool *has_self =
        definition_count > 0 ? calloc((size_t)definition_count, sizeof(*has_self)) : NULL;
    bool *has_guarded =
        definition_count > 0 ? calloc((size_t)definition_count, sizeof(*has_guarded)) : NULL;
    cbm_set_definition_parameter_counts(&result->defs);
    cbm_record_call_metrics(result, call_count, has_self, has_guarded);
    for (int i = 0; i < definition_count; i++) {
        if (has_self && has_self[i] && !(has_guarded && has_guarded[i])) {
            result->defs.items[i].unguarded_recursion = true;
        }
    }
    free(has_self);
    free(has_guarded);
}

static void cbm_record_parse_coverage(CBMFileResult *result, TSNode root, CBMArena *arena,
                                      const char *source, int source_len) {
    if (!ts_node_has_error(root)) {
        return;
    }
    cbm_error_regions_t regions = {{0}, {0}, 0};
    cbm_collect_error_regions(root, &regions);
    if (regions.count == 0 && result->defs.count == 0 && strcmp(ts_node_type(root), "ERROR") == 0) {
        cbm_error_regions_push(&regions, root);
    }
    cbm_subtract_recovered_regions(&regions, &result->defs);
    cbm_subtract_macro_invocation_regions(&regions, &result->defs, source, source_len);
    if (regions.count > 0) {
        result->parse_incomplete = true;
        result->error_region_count = regions.count;
        result->error_ranges = cbm_error_ranges_str(arena, &regions);
    }
}

static void cbm_stamp_preprocessed_parser_origins(CBMFileResult *result, int calls_before,
                                                  int usages_before) {
    for (int i = calls_before; i < result->calls.count; i++) {
        result->calls.items[i].source_origin = CBM_SOURCE_ORIGIN_PREPROCESSED;
    }
    for (int i = usages_before; i < result->usages.count; i++) {
        result->usages.items[i].source_origin = CBM_SOURCE_ORIGIN_PREPROCESSED;
    }
}

static void cbm_stamp_preprocessed_lsp_origins(CBMFileResult *result, int resolved_before) {
    for (int i = resolved_before; i < result->resolved_calls.count; i++) {
        result->resolved_calls.items[i].source_origin = CBM_SOURCE_ORIGIN_PREPROCESSED;
    }
}

static bool cbm_definition_overlaps_regions(const CBMDefinition *definition,
                                            const cbm_error_regions_t *regions) {
    for (int i = 0; i < regions->count; i++) {
        if (definition->start_line <= regions->ends[i] &&
            definition->end_line >= regions->starts[i]) {
            return true;
        }
    }
    return false;
}

static bool cbm_definition_has_unique_qn(const CBMDefArray *definitions, int limit,
                                         const CBMDefinition *definition) {
    for (int i = 0; i < limit; i++) {
        const char *existing = definitions->items[i].qualified_name;
        if (existing && definition->qualified_name &&
            strcmp(existing, definition->qualified_name) == 0) {
            return false;
        }
    }
    return true;
}

static bool cbm_accept_recovered_definition(CBMDefinition *definition,
                                            const CBMPreprocessedSource *preprocessed,
                                            const cbm_error_regions_t *regions,
                                            const CBMDefArray *definitions, int original_count,
                                            const char *source, int source_len) {
    return cbm_remap_preprocessed_def(definition, preprocessed) &&
           cbm_definition_overlaps_regions(definition, regions) && definition->name &&
           cbm_line_contains(source, source_len, definition->start_line, definition->name) &&
           cbm_span_contains_callable_def(source, source_len, definition->start_line,
                                          definition->end_line, definition->name) &&
           cbm_definition_has_unique_qn(definitions, original_count, definition);
}

static void cbm_recover_preprocessed_definitions(CBMExtractCtx *expanded_context, TSNode raw_root,
                                                 const CBMPreprocessedSource *preprocessed,
                                                 const char *source, int source_len) {
    if (!ts_node_has_error(raw_root)) {
        return;
    }
    cbm_error_regions_t regions = {{0}, {0}, 0};
    cbm_collect_error_regions(raw_root, &regions);
    if (regions.count == 0) {
        return;
    }
    CBMDefArray *definitions = &expanded_context->result->defs;
    int original_count = definitions->count;
    cbm_extract_definitions(expanded_context);
    int write_index = original_count;
    for (int i = original_count; i < definitions->count; i++) {
        CBMDefinition *definition = &definitions->items[i];
        if (cbm_accept_recovered_definition(definition, preprocessed, &regions, definitions,
                                            original_count, source, source_len)) {
            definitions->items[write_index++] = *definition;
        }
    }
    definitions->count = write_index;
}

static void cbm_extract_expanded_source(CBMArena *arena, CBMFileResult *result,
                                        const CBMPreprocessedSource *preprocessed,
                                        const TSLanguage *language_parser, CBMLanguage language,
                                        const char *project, const char *rel_path, TSNode raw_root,
                                        const char *source, int source_len) {
    char *expanded = preprocessed->source;
    int expanded_len = (int)strlen(expanded);
    TSParser *parser = get_thread_parser(language_parser, language);
    if (!parser) {
        return;
    }
    ts_parser_reset(parser);
    CBMStringInput input = {expanded, (uint32_t)expanded_len};
    TSInput tree_input = {&input, cbm_string_read, TSInputEncodingUTF8, NULL};
    TSTree *tree = ts_parser_parse_with_options(parser, NULL, tree_input, (TSParseOptions){0});
    if (!tree) {
        return;
    }
    int calls_before = result->calls.count;
    int usages_before = result->usages.count;
    int resolved_before = result->resolved_calls.count;
    TSNode root = ts_tree_root_node(tree);
    CBMExtractCtx context = {.arena = arena,
                             .result = result,
                             .source = expanded,
                             .source_len = expanded_len,
                             .language = language,
                             .project = project,
                             .rel_path = rel_path,
                             .module_qn = result->module_qn,
                             .root = root};
    cbm_extract_unified(&context);
    cbm_stamp_preprocessed_parser_origins(result, calls_before, usages_before);
    cbm_run_c_lsp(arena, result, expanded, expanded_len, root, language != CBM_LANG_C,
                  CBM_SOURCE_ORIGIN_PREPROCESSED);
    cbm_stamp_preprocessed_lsp_origins(result, resolved_before);
    cbm_recover_preprocessed_definitions(&context, raw_root, preprocessed, source, source_len);
    ts_tree_delete(tree);
}

static void cbm_extract_preprocessor_phase(CBMArena *arena, CBMFileResult *result,
                                           const char *source, int source_len, const char *rel_path,
                                           const char **extra_defines, const char **include_paths,
                                           const TSLanguage *ts_language, CBMLanguage language,
                                           const char *project, TSNode raw_root) {
    if (language != CBM_LANG_C && language != CBM_LANG_CPP && language != CBM_LANG_CUDA) {
        return;
    }
    uint64_t phase_start = now_ns();
    CBMPreprocessedSource *preprocessed = cbm_preprocess_with_map(
        source, source_len, rel_path, extra_defines, include_paths, language != CBM_LANG_C);
    if (preprocessed && preprocessed->source) {
        cbm_extract_expanded_source(arena, result, preprocessed, ts_language, language, project,
                                    rel_path, raw_root, source, source_len);
        atomic_fetch_add(&total_files_preprocessed, 1);
    }
    cbm_preprocessed_source_free(preprocessed);
    atomic_fetch_add(&total_preprocess_ns, now_ns() - phase_start);
}

/* Public entry: run the extraction and journal completion. The DONE mark on
 * every ordinary return (including error/timeout results) tells the crash
 * supervisor this file did NOT kill the worker — only a file whose S has no
 * D is a crash/hang suspect. */
CBMFileResult *cbm_extract_file(const char *source, int source_len, CBMLanguage language,
                                const char *project, const char *rel_path, int64_t timeout_micros,
                                const char **extra_defines, const char **include_paths) {
    CBMFileResult *r =
        cbm_extract_file_ex(source, source_len, language, project, rel_path, timeout_micros,
                            extra_defines, include_paths, NULL, NULL);
    return r;
}

CBMFileResult *cbm_extract_file_ex(const char *source, int source_len, CBMLanguage language,
                                   const char *project, const char *rel_path,
                                   int64_t timeout_micros, const char **extra_defines,
                                   const char **include_paths, const CBMMacroTable *macro_table,
                                   const CBMReturnTypeTable *return_type_table) {
    // Allocate result on heap (arena inside for all string data)
    enum { SINGLE = 1 };
    CBMFileResult *result = (CBMFileResult *)calloc(SINGLE, sizeof(CBMFileResult));
    if (!result) {
        return NULL;
    }

    cbm_arena_init(&result->arena);
    CBMArena *a = &result->arena;

    /* Crash-quarantine hard guard (Stage 3c): a file the supervisor pinned as a
     * crasher must NEVER be parsed again. Return a clean empty result BEFORE the
     * marker write and fault injector so no pass (including sequential re-extract
     * passes that miss the result cache) can crash on it. The pipeline extract
     * loops separately record it as a phase="crash" skip. Checked before the
     * marker so quarantined files never overwrite it — the marker keeps pointing
     * at the real (non-quarantined) file being processed when a crash hits. */
    if (cbm_index_is_quarantined(rel_path)) {
        return result;
    }

    cbm_index_mark_start(rel_path);
    cbm_test_fault_inject(rel_path);

    // Get language spec
    const CBMLangSpec *spec = cbm_lang_spec(language);
    if (!spec) {
        result->has_error = true;
        result->error_msg = cbm_arena_strdup(a, "unsupported language");
        cbm_index_mark_done(rel_path);
        return result;
    }

    // Get tree-sitter language
    const TSLanguage *ts_lang = cbm_ts_language(language);
    if (!ts_lang) {
        result->has_error = true;
        result->error_msg = cbm_arena_strdup(a, "no tree-sitter grammar");
        cbm_index_mark_done(rel_path);
        return result;
    }

    // Skip pathologically nested Perl before tree-sitter's recursive GLR stack
    // merge overflows a small stack during the parse (see
    // cbm_source_nesting_exceeds). Scoped to Perl: its ambiguous call grammar is
    // the only one that drives that recursion to the nesting depth.
    if (language == CBM_LANG_PERL &&
        cbm_source_nesting_exceeds(source, source_len, CBM_PERL_MAX_PARSE_NESTING)) {
        result->has_error = true;
        result->error_msg = cbm_arena_strdup(a, "perl source nesting too deep; skipped");
        return result;
    }

    // Get thread-local parser (reused across files on same thread)
    TSParser *parser = get_thread_parser(ts_lang, language);
    if (!parser) {
        result->has_error = true;
        result->error_msg = cbm_arena_strdup(a, "parser alloc failed");
        cbm_index_mark_done(rel_path);
        return result;
    }

    // Reset parser state from any previous parse (cancellation flags etc.)
    ts_parser_reset(parser);

    uint64_t t0 = now_ns();

    // Build string input + timeout options for parse_with_options
    CBMStringInput str_input = {source, (uint32_t)source_len};
    TSInput ts_input = {
        &str_input,
        cbm_string_read,
        TSInputEncodingUTF8,
        NULL,
    };

    TSParseOptions opts = {0};
    uint64_t deadline_ns = 0; // cppcheck-suppress unreadVariable
    if (timeout_micros > 0) {
        deadline_ns = t0 + ((uint64_t)timeout_micros * USEC_TO_NSEC);
        opts.payload = &deadline_ns;
        opts.progress_callback = cbm_timeout_cb;
    }

    TSTree *tree = ts_parser_parse_with_options(parser, NULL, ts_input, opts);
    uint64_t t1 = now_ns();

    if (!tree) {
        result->has_error = true;
        result->error_msg =
            cbm_arena_strdup(a, timeout_micros > 0 ? "parse timeout" : "parse failed");
        cbm_index_mark_done(rel_path);
        return result;
    }

    TSNode root = ts_tree_root_node(tree);

    // Compute module QN. Java/Go derive the module from the CONTAINING
    // DIRECTORY (package semantics) rather than baking the filename stem in,
    // so def QNs, the LSP caller_qn, and the textual calls-enclosing QN all
    // agree (e.g. Outer.java -> module "proj", not "proj.Outer"). Other
    // languages are unchanged.
    result->module_qn = cbm_fqn_module_source_lang(a, project, rel_path, language);
    result->is_test_file = cbm_is_test_file(rel_path, language);

    // Build extraction context
    CBMExtractCtx ctx = {
        .arena = a,
        .result = result,
        .source = source,
        .source_len = source_len,
        .language = language,
        .project = project,
        .rel_path = rel_path,
        .module_qn = result->module_qn,
        .root = root,
        .macro_table = macro_table,
        .return_type_table = return_type_table,
    };

    cbm_run_primary_extractors(&ctx);

    // LSP type-aware call/usage resolution (per-file). Runs in every mode;
    // refines the tree-sitter + textual-resolution graph with type info.
    uint64_t lsp_start = now_ns();
    cbm_run_lsp_extractors(a, result, source, source_len, root, language, rel_path);
    atomic_fetch_add(&total_lsp_ns, now_ns() - lsp_start);

    // Calls extracted so far all carry ORIGINAL-source line numbers; the C/C++
    // preprocessor second pass below appends calls with EXPANDED-source lines,
    // which must not be used for the def line-range attribution of the bottleneck
    // metrics. Remember the boundary.
    int orig_calls_count = result->calls.count;

    cbm_extract_preprocessor_phase(a, result, source, source_len, rel_path, extra_defines,
                                   include_paths, ts_lang, language, project, root);

    cbm_compute_metrics(result, orig_calls_count);
    uint64_t t2 = now_ns();
    cbm_record_parse_coverage(result, root, a, source, source_len);

    result->imports_count = result->imports.count;

    // Accumulate profiling counters
    atomic_fetch_add(&total_parse_ns, t1 - t0);
    atomic_fetch_add(&total_extract_ns, t2 - t1);
    atomic_fetch_add(&total_files, 1);

    // Retain tree for cross-file LSP reuse (caller frees via cbm_free_tree)
    result->cached_tree = tree;
    result->cached_lang = language;
    cbm_index_mark_done(rel_path);
    return result;
}

typedef struct {
    CBMFileResult *result;
    int next_child;
} CBMResultFreeFrame;

static void cbm_free_result_payload(CBMFileResult *result) {
    if (result->cached_tree) {
        ts_tree_delete(result->cached_tree);
    }
    free(result->owned_results);
    cbm_arena_destroy(&result->arena);
    free(result);
}

void cbm_free_result(CBMFileResult *result) {
    if (!result) {
        return;
    }
    int capacity = CBM_SZ_16;
    int top = 0;
    CBMResultFreeFrame *stack = calloc((size_t)capacity, sizeof(*stack));
    if (!stack) {
        return;
    }
    stack[top++] = (CBMResultFreeFrame){result, 0};
    while (top > 0) {
        CBMResultFreeFrame *frame = &stack[top - SKIP_ONE];
        if (frame->next_child < frame->result->owned_result_count) {
            CBMFileResult *child = frame->result->owned_results[frame->next_child++];
            if (!child) {
                continue;
            }
            if (top == capacity) {
                int new_capacity = capacity * PAIR_LEN;
                CBMResultFreeFrame *grown = realloc(stack, (size_t)new_capacity * sizeof(*stack));
                if (!grown) {
                    break;
                }
                stack = grown;
                capacity = new_capacity;
            }
            stack[top++] = (CBMResultFreeFrame){child, 0};
            continue;
        }
        cbm_free_result_payload(frame->result);
        top--;
    }
    free(stack);
}

void cbm_free_tree(CBMFileResult *result) {
    if (result && result->cached_tree) {
        ts_tree_delete(result->cached_tree);
        result->cached_tree = NULL;
    }
}

void cbm_free_tree_ptr(TSTree *tree) {
    if (tree) {
        ts_tree_delete(tree);
    }
}
