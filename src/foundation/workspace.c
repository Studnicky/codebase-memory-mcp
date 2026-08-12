/*
 * workspace.c — workspace boundary policy. See workspace.h for the contract and
 * for why this is only the breadth half of the boundary.
 */
#include "foundation/workspace.h"

#include "foundation/constants.h"
#include "foundation/compat_fs.h"
#include "foundation/platform.h"
#include "foundation/sha256.h"

#include <stdlib.h>

#include <stdio.h>
#include <string.h>

enum { WS_PATH_LAST_CHAR_OFFSET = 1 };

/* ── Path containment ─────────────────────────────────────────────
 *
 * cbm_path_within_root is declared in workspace.h and used by the root
 * matching below, so it lives here with the rest of foundation. It was
 * defined in src/mcp/mcp.c, which made foundation depend on an adapter at
 * link time — invisible to the include-graph gate, and only reachable as a
 * missing symbol once a binary links foundation without mcp.
 *
 * Its dependencies are all foundation: cbm_canonical_path (compat_fs),
 * cbm_utf8_to_wide and cbm_normalize_path_sep (platform). */
/* Canonicalize `path` (resolve symlinks/junctions and `..`) into `out`
 * (>= CBM_SZ_4K bytes); returns true on success. Isolating the per-OS resolver
 * keeps cbm_path_within_root's control flow unconditional: the previous `#ifdef`
 * opened the `if (...) {` brace in one branch and a different one in the other,
 * sharing a single close brace — legal C, but it splits the function's braces
 * across preprocessor branches, which defeats source-level tooling that parses
 * without the preprocessor (and left this function unindexed in the graph). */
static bool resolve_canonical_path(const char *path, char *out, size_t out_sz) {
    /* cbm_canonical_path: realpath on POSIX; an opened handle plus
     * GetFinalPathNameByHandleW on Windows.  The old bare _fullpath was ANSI
     * (CJK-locale corruption, #973), accepted nonexistent paths, and lexical
     * expansion alone did not resolve junctions for containment checks. */
    if (!cbm_canonical_path(path, out, out_sz)) {
        return false;
    }
#ifdef _WIN32
    cbm_normalize_path_sep(out);
#endif
    return true;
}

static bool canonical_path_has_root(const char *root_path, const char *candidate_path) {
#ifdef _WIN32
    wchar_t *wide_root = cbm_utf8_to_wide(root_path);
    wchar_t *wide_candidate = cbm_utf8_to_wide(candidate_path);
    bool contained = false;
    if (wide_root && wide_candidate) {
        size_t root_len = wcslen(wide_root);
        size_t candidate_len = wcslen(wide_candidate);
        bool prefix_equal = root_len <= candidate_len && root_len <= INT_MAX &&
                            CompareStringOrdinal(wide_candidate, (int)root_len, wide_root,
                                                 (int)root_len, TRUE) == CSTR_EQUAL;
        bool root_ends_separator =
            root_len > 0 && (wide_root[root_len - 1] == L'/' || wide_root[root_len - 1] == L'\\');
        bool boundary = root_ends_separator || root_len == candidate_len ||
                        (root_len < candidate_len &&
                         (wide_candidate[root_len] == L'/' || wide_candidate[root_len] == L'\\'));
        contained = prefix_equal && boundary;
    }
    free(wide_root);
    free(wide_candidate);
    return contained;
#else
    size_t root_len = strlen(root_path);
    size_t candidate_len = strlen(candidate_path);
    bool prefix_equal =
        root_len <= candidate_len && strncmp(candidate_path, root_path, root_len) == 0;
    bool root_ends_separator =
        root_len > 0 && root_path[root_len - WS_PATH_LAST_CHAR_OFFSET] == '/';
    bool boundary = root_ends_separator || root_len == candidate_len ||
                    (root_len < candidate_len && candidate_path[root_len] == '/');
    return prefix_equal && boundary;
#endif
}

bool cbm_path_within_root(const char *root_path, const char *abs_path) {
    if (!root_path || !abs_path) {
        return false;
    }
    char real_root[CBM_SZ_4K];
    char real_file[CBM_SZ_4K];
    if (resolve_canonical_path(root_path, real_root, sizeof(real_root)) &&
        resolve_canonical_path(abs_path, real_file, sizeof(real_file))) {
        if (canonical_path_has_root(real_root, real_file)) {
            return true;
        }
    }
    return false;
}

enum {
    /* POSIX: two components, so every top-level tree is refused in one rule with
     * no list to maintain — "/etc", "/home", "/Users", "/var", "/opt", "/srv".
     * Depth alone cannot do this on Windows, where the equivalent system trees
     * and a perfectly ordinary workspace are both one component below the drive
     * ("C:/Windows" and "D:/repos"), so Windows uses one component plus the
     * named system directories below. Windows' top-level set is small and stable
     * enough for a list; POSIX's is not. */
    WS_MIN_DEPTH_POSIX = 2,
    WS_MIN_DEPTH_WINDOWS = 1,
    WS_PATH_SECOND_CHAR_INDEX = 1,
    WS_PATH_THIRD_CHAR_INDEX = 2,
    WS_POSIX_ROOT_PREFIX_LENGTH = 1,
    WS_DRIVE_PREFIX_LENGTH = 2,
    WS_DRIVE_ROOT_PREFIX_LENGTH = 3,
    WS_PRIVATE_COMPONENT_LENGTH = sizeof("private") - sizeof(""),
    WS_PREVIOUS_CHAR_OFFSET = 1,
    WS_NEXT_CHAR_OFFSET = 1,
    WS_GRANT_MARKER_LENGTH = 1,
    WS_WINDOWS_USER_TREE_COUNT = 1,
    WS_FREAD_ITEM_COUNT = 1,
    WS_ASCII_PRINTABLE_START = 0x20,
};

static bool ws_is_sep(char c) {
    return c == '/' || c == '\\';
}

/* Length of the volume prefix: "/" on POSIX, "C:/" for a drive, "//srv/share"
 * for a UNC share. Returns 0 when the path is not absolute. */
static size_t ws_volume_prefix_len(const char *path) {
    if (!path || !path[0]) {
        return 0;
    }
    /* UNC: two separators, a host, then a share. */
    if (ws_is_sep(path[0]) && ws_is_sep(path[WS_PATH_SECOND_CHAR_INDEX])) {
        size_t i = WS_DRIVE_PREFIX_LENGTH;
        while (path[i] && !ws_is_sep(path[i])) { /* host */
            i++;
        }
        while (ws_is_sep(path[i])) {
            i++;
        }
        while (path[i] && !ws_is_sep(path[i])) { /* share */
            i++;
        }
        return i;
    }
    if (ws_is_sep(path[0])) {
        return WS_POSIX_ROOT_PREFIX_LENGTH;
    }
    /* Drive-letter root, with or without a trailing separator. */
    if (path[WS_PATH_SECOND_CHAR_INDEX] == ':' &&
        ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'))) {
        return ws_is_sep(path[WS_PATH_THIRD_CHAR_INDEX]) ? WS_DRIVE_ROOT_PREFIX_LENGTH
                                                         : WS_DRIVE_PREFIX_LENGTH;
    }
    return 0;
}

static bool ws_is_unc(const char *path) {
    return path && ws_is_sep(path[0]) && ws_is_sep(path[WS_PATH_SECOND_CHAR_INDEX]);
}

static bool ws_is_windows_style(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    return path[WS_PATH_SECOND_CHAR_INDEX] == ':' &&
           ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'));
}

int cbm_workspace_path_depth(const char *canonical_path) {
    size_t prefix = ws_volume_prefix_len(canonical_path);
    if (prefix == 0) {
        return 0;
    }
    int depth = 0;
    const char *p = canonical_path + prefix;
    /* macOS firmlinks /etc, /tmp and /var under /private, so canonicalizing any
     * of them adds a component: "/etc" resolves to "/private/etc" and would count
     * as two deep, sailing past a minimum of two — exactly the path the reports
     * demonstrate. Treat a leading "private" as transparent so depth reflects the
     * tree the user named. "/private/tmp/proj" still counts two and is allowed. */
    if (strncmp(p, "private", WS_PRIVATE_COMPONENT_LENGTH) == 0 &&
        (ws_is_sep(p[WS_PRIVATE_COMPONENT_LENGTH]) || p[WS_PRIVATE_COMPONENT_LENGTH] == '\0')) {
        p += WS_PRIVATE_COMPONENT_LENGTH;
    }
    while (*p) {
        while (ws_is_sep(*p)) {
            p++;
        }
        if (!*p) {
            break;
        }
        depth++;
        while (*p && !ws_is_sep(*p)) {
            p++;
        }
    }
    return depth;
}

/* Case-insensitive on Windows-style paths, exact elsewhere: NTFS is
 * case-insensitive, so ".SSH" must not slip past a case-sensitive compare. */
static bool ws_component_equals(const char *component, size_t len, const char *name,
                                bool fold_case) {
    if (strlen(name) != len) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        char a = component[i];
        char b = name[i];
        if (fold_case) {
            if (a >= 'A' && a <= 'Z') {
                a = (char)(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = (char)(b - 'A' + 'a');
            }
        }
        if (a != b) {
            return false;
        }
    }
    return true;
}

/* Directory and file names that carry credentials. Matched against every
 * component, so both "…/.ssh" and "…/.ssh/sub" are refused. Additive by design:
 * a pull request appending a name here needs no design authority. */
static const char *const WS_CREDENTIAL_NAMES[] = {
    ".ssh",
    ".aws",
    ".gnupg",
    ".gpg",
    ".kube",
    ".docker",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".azure",
    ".gcloud",
    "Keychains",
    ".password-store",
    ".authinfo",
};

/* Windows system trees, matched only as the FIRST component below the drive.
 * Nothing legitimate is indexed inside them at any depth.
 *
 * "Users" is deliberately NOT here. Every Windows user's files live under
 * C:\Users\<name>, so matching it the way credential names are matched — against
 * every component — refuses every ordinary Windows project path. It is handled
 * below as the tree root only, mirroring POSIX where "/Users" is refused but
 * "/Users/dev/projects" is not. */
static const char *const WS_WINDOWS_SYSTEM_TREES[] = {
    "Windows",
    "ProgramData",
    "Program Files",
    "Program Files (x86)",
};

/* Roots that are the tree itself rather than something inside it. */
static const char *const WS_WINDOWS_USER_TREE = "Users";

/* Match only the first component below the volume prefix. */
static bool ws_first_component_matches(const char *path, const char *const *names, size_t count,
                                       bool fold_case) {
    const char *p = path + ws_volume_prefix_len(path);
    while (ws_is_sep(*p)) {
        p++;
    }
    const char *start = p;
    while (*p && !ws_is_sep(*p)) {
        p++;
    }
    size_t len = (size_t)(p - start);
    for (size_t i = 0; i < count; i++) {
        if (ws_component_equals(start, len, names[i], fold_case)) {
            return true;
        }
    }
    return false;
}

static bool ws_any_component_matches(const char *path, const char *const *names, size_t count,
                                     bool fold_case) {
    size_t prefix = ws_volume_prefix_len(path);
    const char *p = path + prefix;
    while (*p) {
        while (ws_is_sep(*p)) {
            p++;
        }
        if (!*p) {
            break;
        }
        const char *start = p;
        while (*p && !ws_is_sep(*p)) {
            p++;
        }
        size_t len = (size_t)(p - start);
        for (size_t i = 0; i < count; i++) {
            if (ws_component_equals(start, len, names[i], fold_case)) {
                return true;
            }
        }
    }
    return false;
}

/* True when b is a or lives under a. Compares on a separator boundary so
 * "/a/bc" is not treated as living under "/a/b". */
static bool ws_is_ancestor_or_equal(const char *a, const char *b) {
    if (!a || !b || !a[0] || !b[0]) {
        return false;
    }
    size_t la = strlen(a);
    while (la > WS_POSIX_ROOT_PREFIX_LENGTH && ws_is_sep(a[la - WS_PREVIOUS_CHAR_OFFSET])) {
        la--;
    }
    if (strncmp(a, b, la) != 0) {
        return false;
    }
    return b[la] == '\0' || ws_is_sep(b[la]);
}

static bool ws_paths_equal(const char *a, const char *b) {
    return ws_is_ancestor_or_equal(a, b) && ws_is_ancestor_or_equal(b, a);
}

cbm_ws_verdict_t cbm_workspace_classify_root(const char *canonical_path, const char *home_dir,
                                             const char *cache_dir) {
    if (!canonical_path || !canonical_path[0] || ws_volume_prefix_len(canonical_path) == 0) {
        /* A relative or empty path is not a usable root; refuse it the same way
         * as a volume root rather than letting it fall through as allowed. */
        return CBM_WS_DENY_ABSOLUTE;
    }

    bool windows_style = ws_is_windows_style(canonical_path);
    int depth = cbm_workspace_path_depth(canonical_path);

    /* A volume, drive or share root, whatever the platform. */
    if (depth == 0) {
        return CBM_WS_DENY_ABSOLUTE;
    }

    /* Order matters below, and not for cosmetic reasons.
     *
     * The home directory normally CONTAINS the cache directory, so testing the
     * cache first would report every $HOME as "holds the cache" — and, worse,
     * would make it absolutely denied when the design says a person may override
     * it. Home is therefore classified first.
     *
     * Depth comes before the cache test for the same kind of reason: "/Users" is
     * both too broad and an ancestor of the cache, and "too broad, name a
     * project directory below it" is the reason that actually helps the reader. */
    if (home_dir && home_dir[0] && ws_paths_equal(canonical_path, home_dir)) {
        return CBM_WS_DENY_SENSITIVE;
    }

    /* Below a drive or a UNC share the first component is already user space
     * ("D:/repos", "//srv/share/proj"), so one component is enough there. Below a
     * POSIX root it is a system tree, so require two. */
    int min_depth =
        (windows_style || ws_is_unc(canonical_path)) ? WS_MIN_DEPTH_WINDOWS : WS_MIN_DEPTH_POSIX;
    if (depth < min_depth) {
        return CBM_WS_DENY_TOO_SHALLOW;
    }

    /* No rule here for "this root contains the cache directory".
     *
     * An earlier draft refused such roots outright, on the theory that indexing
     * them would absorb every other project's graph database. Two things make
     * that wrong. The indexer only parses recognised source files, and a graph
     * database is binary SQLite it would never extract; and refusing an entire
     * root is the wrong remedy even where the concern holds — the right one is to
     * not walk the cache. Excluding the cache from discovery is tracked
     * separately; classifying the root is not the place for it.
     *
     * cache_dir stays in the signature because the exclusion work will need it
     * and because callers already have it to hand. */
    (void)cache_dir;

    if (ws_any_component_matches(canonical_path, WS_CREDENTIAL_NAMES,
                                 sizeof(WS_CREDENTIAL_NAMES) / sizeof(WS_CREDENTIAL_NAMES[0]),
                                 windows_style)) {
        return CBM_WS_DENY_SENSITIVE;
    }

    if (windows_style && ws_first_component_matches(canonical_path, WS_WINDOWS_SYSTEM_TREES,
                                                    sizeof(WS_WINDOWS_SYSTEM_TREES) /
                                                        sizeof(WS_WINDOWS_SYSTEM_TREES[0]),
                                                    true)) {
        return CBM_WS_DENY_SENSITIVE;
    }

    /* "C:/Users" is the user tree itself — refuse it as a root, but leave the
     * projects below it alone; that is where Windows users actually work. */
    if (windows_style && depth == WS_MIN_DEPTH_WINDOWS &&
        ws_first_component_matches(canonical_path, &WS_WINDOWS_USER_TREE,
                                   WS_WINDOWS_USER_TREE_COUNT, true)) {
        return CBM_WS_DENY_SENSITIVE;
    }

    return CBM_WS_ALLOW;
}

const char *cbm_workspace_verdict_reason(cbm_ws_verdict_t verdict) {
    switch (verdict) {
    case CBM_WS_ALLOW:
        return "allowed";
    case CBM_WS_DENY_TOO_SHALLOW:
        return "path is too broad to index as one root; name a project directory below it";
    case CBM_WS_DENY_ABSOLUTE:
        return "path is a volume root or holds the codebase-memory cache; it cannot be indexed";
    case CBM_WS_DENY_SENSITIVE:
        return "path is a home or credential directory";
    default:
        break;
    }
    return "refused";
}

bool cbm_workspace_verdict_is_overridable(cbm_ws_verdict_t verdict) {
    return verdict == CBM_WS_DENY_SENSITIVE;
}

/* ── Grant store ──────────────────────────────────────────────────────────── */

enum { WS_LINE_MAX = 4096 };

/* A line may carry a leading '!' meaning "a person explicitly approved this
 * sensitive root". The marker is stored rather than inferred so re-classifying
 * later (a new credential name is added to the list, say) cannot silently
 * upgrade an ordinary grant into a sensitive one. */
static const char WS_SENSITIVE_MARK = '!';

bool cbm_workspace_grant_path(const char *cache_dir, char *out, size_t out_sz) {
    if (!cache_dir || !cache_dir[0] || !out || out_sz == 0) {
        return false;
    }
    int n = snprintf(out, out_sz, "%s/allowed_roots", cache_dir);
    return n > 0 && (size_t)n < out_sz;
}

/* Walk the grant file, invoking visit for each entry. visit returns true to stop.
 * Returns the number of entries seen. */
static int ws_grant_walk(const char *cache_dir,
                         bool (*visit)(const char *root, bool sensitive, void *ctx), void *ctx) {
    char store[WS_LINE_MAX];
    if (!cbm_workspace_grant_path(cache_dir, store, sizeof(store))) {
        return 0;
    }
    FILE *f = cbm_fopen(store, "r");
    if (!f) {
        return 0;
    }
    char line[WS_LINE_MAX];
    int seen = 0;
    while (fgets(line, (int)sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - WS_PREVIOUS_CHAR_OFFSET] == '\n' ||
                           line[len - WS_PREVIOUS_CHAR_OFFSET] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0 || line[0] == '#') {
            continue;
        }
        bool sensitive = line[0] == WS_SENSITIVE_MARK;
        const char *root = sensitive ? line + WS_GRANT_MARKER_LENGTH : line;
        if (!root[0]) {
            continue;
        }
        seen++;
        if (visit && visit(root, sensitive, ctx)) {
            break;
        }
    }
    (void)fclose(f);
    return seen;
}

typedef struct {
    const char *candidate;
    bool contained;       /* candidate is at or below some granted root */
    bool exact_sensitive; /* candidate is itself a grant marked sensitive */
} ws_match_t;

static bool ws_match_visit(const char *root, bool sensitive, void *ctx) {
    ws_match_t *m = ctx;
    if (cbm_path_within_root(root, m->candidate)) {
        m->contained = true;
        if (sensitive && ws_paths_equal(root, m->candidate)) {
            m->exact_sensitive = true;
        }
    }
    return false; /* visit every entry: a later one may be the exact match */
}

typedef struct {
    char *out;
    size_t out_sz;
    size_t used;
} ws_list_t;

static bool ws_list_visit(const char *root, bool sensitive, void *ctx) {
    ws_list_t *l = ctx;
    int n = snprintf(l->out + l->used, l->out_sz - l->used, "%s%s\n",
                     sensitive ? "(approved) " : "", root);
    if (n > 0 && (size_t)n < l->out_sz - l->used) {
        l->used += (size_t)n;
    }
    return false;
}

bool cbm_workspace_grant_list(const char *cache_dir, char *out, size_t out_sz) {
    if (!out || out_sz == 0) {
        return false;
    }
    out[0] = '\0';
    ws_list_t l = {out, out_sz, 0};
    return ws_grant_walk(cache_dir, ws_list_visit, &l) > 0;
}

static void ws_set_error(char *err, size_t err_sz, const char *message) {
    if (err && err_sz) {
        (void)snprintf(err, err_sz, "%s", message);
    }
}

static bool ws_grant_verdict_allowed(cbm_ws_verdict_t verdict, bool approve_sensitive, char *err,
                                     size_t err_sz) {
    if (verdict == CBM_WS_ALLOW) {
        return true;
    }
    if (!cbm_workspace_verdict_is_overridable(verdict)) {
        ws_set_error(err, err_sz, cbm_workspace_verdict_reason(verdict));
        return false;
    }
    if (approve_sensitive) {
        return true;
    }
    if (err && err_sz) {
        (void)snprintf(err, err_sz, "%s; re-run with --approve-sensitive if that is intended",
                       cbm_workspace_verdict_reason(verdict));
    }
    return false;
}

static bool ws_write_grant(const char *cache_dir, const char *canonical_path, bool sensitive,
                           char *err, size_t err_sz) {
    char store[WS_LINE_MAX];
    if (!cbm_workspace_grant_path(cache_dir, store, sizeof(store))) {
        ws_set_error(err, err_sz, "cache path too long");
        return false;
    }
    FILE *file = cbm_fopen(store, "a");
    if (!file) {
        if (err && err_sz) {
            (void)snprintf(err, err_sz, "cannot write %s", store);
        }
        return false;
    }
    (void)fprintf(file, "%s%s\n", sensitive ? "!" : "", canonical_path);
    bool written = fclose(file) == 0;
    if (!written && err && err_sz) {
        (void)snprintf(err, err_sz, "cannot write %s", store);
    }
    return written;
}

bool cbm_workspace_grant_add(const char *cache_dir, const char *home_dir,
                             const char *canonical_path, bool approve_sensitive, char *err,
                             size_t err_sz) {
    if (err && err_sz) {
        err[0] = '\0';
    }
    if (!cache_dir || !cache_dir[0] || !canonical_path || !canonical_path[0]) {
        if (err) {
            snprintf(err, err_sz, "no path given");
        }
        return false;
    }

    cbm_ws_verdict_t verdict = cbm_workspace_classify_root(canonical_path, home_dir, cache_dir);
    if (!ws_grant_verdict_allowed(verdict, approve_sensitive, err, err_sz)) {
        return false;
    }

    /* Already present is success, not a duplicate error. */
    ws_match_t existing = {canonical_path, false, false};
    (void)ws_grant_walk(cache_dir, ws_match_visit, &existing);
    if (existing.contained) {
        return true;
    }

    return ws_write_grant(cache_dir, canonical_path, verdict == CBM_WS_DENY_SENSITIVE, err, err_sz);
}

static bool ws_root_matches_declared_boundary(const char *canonical_path, const char *cache_dir,
                                              const char *configured_root, ws_match_t *match) {
    int grants = ws_grant_walk(cache_dir, ws_match_visit, match);
    bool configured = configured_root && configured_root[0];
    bool configured_contains = configured && cbm_path_within_root(configured_root, canonical_path);
    return (grants == 0 && !configured) || match->contained || configured_contains;
}

static void ws_set_boundary_error(char *err, size_t err_sz, const char *canonical_path) {
    if (err && err_sz) {
        (void)snprintf(err, err_sz,
                       "%s is outside the allowed root. To allow it, run: "
                       "codebase-memory-mcp allow-root %s",
                       canonical_path, canonical_path);
    }
}

static bool ws_root_verdict_allowed(cbm_ws_verdict_t verdict, const ws_match_t *match,
                                    const char *canonical_path, char *err, size_t err_sz) {
    if (verdict == CBM_WS_ALLOW || (verdict == CBM_WS_DENY_SENSITIVE && match->exact_sensitive)) {
        return true;
    }
    if (err && err_sz) {
        if (cbm_workspace_verdict_is_overridable(verdict)) {
            (void)snprintf(err, err_sz,
                           "%s: %s. To index it anyway, run: codebase-memory-mcp allow-root "
                           "--approve-sensitive %s",
                           canonical_path, cbm_workspace_verdict_reason(verdict), canonical_path);
        } else {
            (void)snprintf(err, err_sz, "%s: %s", canonical_path,
                           cbm_workspace_verdict_reason(verdict));
        }
    }
    return false;
}

bool cbm_workspace_root_allowed(const char *canonical_path, const char *home_dir,
                                const char *cache_dir, const char *configured_root, char *err,
                                size_t err_sz) {
    if (err && err_sz) {
        err[0] = '\0';
    }
    if (!canonical_path || !canonical_path[0]) {
        if (err) {
            snprintf(err, err_sz, "no repository path given");
        }
        return false;
    }

    ws_match_t match = {canonical_path, false, false};

    /* Containment first when a boundary has actually been declared. A path
     * outside a configured root is best explained as exactly that, and the
     * wording is what callers and the shell contracts already match on. Breadth
     * then applies to paths that ARE inside the declared root but are still too
     * broad to index as one unit. */
    bool boundary_allows =
        ws_root_matches_declared_boundary(canonical_path, cache_dir, configured_root, &match);
    /* No manifest consultation here, deliberately.
     *
     * A project's manifest authorizes outside roots FOR THAT PROJECT, so the
     * question it answers is "may project P pull in tree T", not "may T be indexed
     * standalone". This function only ever sees one path, so it has no project
     * context to ask that question with — an earlier draft passed the candidate as
     * its own project root, which read a manifest that by definition was not the
     * one that requested it and so never authorized anything.
     *
     * The consuming half belongs where the project context exists: discovery
     * walking a project's approved extra roots. cbm_workspace_manifest_allows is
     * the query that half will use. */
    if (!boundary_allows) {
        ws_set_boundary_error(err, err_sz, canonical_path);
        return false;
    }

    cbm_ws_verdict_t verdict = cbm_workspace_classify_root(canonical_path, home_dir, cache_dir);
    return ws_root_verdict_allowed(verdict, &match, canonical_path, err, err_sz);
}

/* ── Environment helpers ──────────────────────────────────────────────────── */

/* Callers should not each re-derive these; a caller that resolved the home
 * directory differently would classify the same path differently. */
const char *cbm_workspace_home_dir(void) {
    const char *home = getenv("HOME");
    if (home && home[0]) {
        return home;
    }
    home = getenv("USERPROFILE");
    return (home && home[0]) ? home : NULL;
}

const char *cbm_workspace_cache_dir(void) {
    return cbm_resolve_cache_dir();
}

/* ── Per-project request manifest ─────────────────────────────────────────── */

static char *ws_manifest_read_raw(FILE *file, size_t *raw_len) {
    char *raw = NULL;
    *raw_len = 0;
    char chunk[WS_LINE_MAX];
    size_t got = 0;
    while ((got = fread(chunk, WS_FREAD_ITEM_COUNT, sizeof(chunk), file)) > 0) {
        char *grown = realloc(raw, *raw_len + got);
        if (!grown) {
            free(raw);
            return NULL;
        }
        raw = grown;
        memcpy(raw + *raw_len, chunk, got);
        *raw_len += got;
    }
    return raw;
}

static bool ws_manifest_append_entry(cbm_ws_manifest_t *manifest, const char *entry,
                                     size_t length) {
    if (length >= sizeof(manifest->entries[0]) || manifest->count >= CBM_WS_MANIFEST_MAX_ENTRIES) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        if ((unsigned char)entry[i] < WS_ASCII_PRINTABLE_START) {
            return false;
        }
    }
    memcpy(manifest->entries[manifest->count], entry, length);
    manifest->entries[manifest->count][length] = '\0';
    manifest->count++;
    return true;
}

static bool ws_manifest_parse(cbm_ws_manifest_t *manifest, const char *raw, size_t raw_len) {
    size_t line_start = 0;
    for (size_t i = 0; i <= raw_len; i++) {
        if (i != raw_len && raw[i] != '\n') {
            continue;
        }
        size_t length = i - line_start;
        while (length > 0 && (raw[line_start + length - WS_PREVIOUS_CHAR_OFFSET] == '\r' ||
                              raw[line_start + length - WS_PREVIOUS_CHAR_OFFSET] == ' ')) {
            length--;
        }
        if (length > 0 && raw[line_start] != '#' &&
            !ws_manifest_append_entry(manifest, raw + line_start, length)) {
            return false;
        }
        line_start = i + WS_NEXT_CHAR_OFFSET;
    }
    return true;
}

bool cbm_workspace_manifest_read(const char *project_root, cbm_ws_manifest_t *out) {
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!project_root || !project_root[0]) {
        return true; /* nothing to read is not a malformed manifest */
    }

    char path[WS_LINE_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", project_root, CBM_WS_MANIFEST_NAME);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        return true;
    }
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return true;
    }

    /* Hash the raw bytes, not the parsed entries: a comment or ordering change is
     * still a change the approver has not seen, and should lapse approval. */
    size_t raw_len = 0;
    char *raw = ws_manifest_read_raw(f, &raw_len);
    (void)fclose(f);
    if (!raw && raw_len != 0) {
        return false;
    }
    out->present = true;
    cbm_sha256_hex(raw ? raw : "", raw_len, out->digest);

    bool ok = ws_manifest_parse(out, raw ? raw : "", raw_len);
    free(raw);
    if (!ok) {
        memset(out, 0, sizeof(*out));
    }
    return ok;
}

static bool ws_approval_path(const char *cache_dir, char *out, size_t out_sz) {
    if (!cache_dir || !cache_dir[0]) {
        return false;
    }
    int n = snprintf(out, out_sz, "%s/approved_manifests", cache_dir);
    return n > 0 && (size_t)n < out_sz;
}

bool cbm_workspace_manifest_is_approved(const char *cache_dir, const char *project_root,
                                        const cbm_ws_manifest_t *manifest) {
    if (!manifest || !manifest->present || !manifest->digest[0] || !project_root) {
        return false;
    }
    char store[WS_LINE_MAX];
    if (!ws_approval_path(cache_dir, store, sizeof(store))) {
        return false;
    }
    FILE *f = cbm_fopen(store, "r");
    if (!f) {
        return false;
    }
    char line[WS_LINE_MAX];
    bool found = false;
    while (!found && fgets(line, (int)sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - WS_PREVIOUS_CHAR_OFFSET] == '\n' ||
                           line[len - WS_PREVIOUS_CHAR_OFFSET] == '\r')) {
            line[--len] = '\0';
        }
        char *sep = strchr(line, ' ');
        if (!sep) {
            continue;
        }
        *sep = '\0';
        /* Both the digest and the project must match: an approval is for this
         * content in this project, not for the content anywhere. */
        found = strcmp(line, manifest->digest) == 0 &&
                ws_paths_equal(sep + WS_GRANT_MARKER_LENGTH, project_root);
    }
    (void)fclose(f);
    return found;
}

static bool ws_manifest_entries_approvable(const cbm_ws_manifest_t *manifest, const char *home_dir,
                                           const char *cache_dir, char *err, size_t err_sz) {
    for (int i = 0; i < manifest->count; i++) {
        cbm_ws_verdict_t verdict =
            cbm_workspace_classify_root(manifest->entries[i], home_dir, cache_dir);
        if (verdict != CBM_WS_ALLOW) {
            if (err && err_sz) {
                (void)snprintf(err, err_sz, "requested path %s: %s", manifest->entries[i],
                               cbm_workspace_verdict_reason(verdict));
            }
            return false;
        }
    }
    return true;
}

static bool ws_manifest_write_approval(const char *cache_dir, const char *project_root,
                                       const cbm_ws_manifest_t *manifest, char *err,
                                       size_t err_sz) {
    char store[WS_LINE_MAX];
    if (!ws_approval_path(cache_dir, store, sizeof(store))) {
        ws_set_error(err, err_sz, "cache path too long");
        return false;
    }
    if (cbm_workspace_manifest_is_approved(cache_dir, project_root, manifest)) {
        return true;
    }
    FILE *file = cbm_fopen(store, "a");
    if (!file) {
        if (err && err_sz) {
            (void)snprintf(err, err_sz, "cannot write %s", store);
        }
        return false;
    }
    (void)fprintf(file, "%s %s\n", manifest->digest, project_root);
    bool written = fclose(file) == 0;
    if (!written && err && err_sz) {
        (void)snprintf(err, err_sz, "cannot write %s", store);
    }
    return written;
}

bool cbm_workspace_manifest_approve(const char *cache_dir, const char *home_dir,
                                    const char *project_root, char *err, size_t err_sz) {
    if (err && err_sz) {
        err[0] = '\0';
    }
    cbm_ws_manifest_t m;
    if (!cbm_workspace_manifest_read(project_root, &m)) {
        if (err) {
            snprintf(err, err_sz,
                     "%s is malformed (control characters, an over-long entry, or "
                     "more than %d entries)",
                     CBM_WS_MANIFEST_NAME, CBM_WS_MANIFEST_MAX_ENTRIES);
        }
        return false;
    }
    if (!m.present) {
        if (err) {
            snprintf(err, err_sz, "no %s in %s", CBM_WS_MANIFEST_NAME,
                     project_root ? project_root : "(none)");
        }
        return false;
    }

    return ws_manifest_entries_approvable(&m, home_dir, cache_dir, err, err_sz) &&
           ws_manifest_write_approval(cache_dir, project_root, &m, err, err_sz);
}

bool cbm_workspace_manifest_allows(const char *cache_dir, const char *home_dir,
                                   const char *project_root, const char *candidate) {
    if (!candidate || !candidate[0]) {
        return false;
    }
    cbm_ws_manifest_t m;
    if (!cbm_workspace_manifest_read(project_root, &m) || !m.present) {
        return false;
    }
    if (!cbm_workspace_manifest_is_approved(cache_dir, project_root, &m)) {
        return false;
    }
    for (int i = 0; i < m.count; i++) {
        /* Re-classify at use time as well as at approval time: the credential list
         * may have grown since, and a stored approval must not outrank it. */
        if (cbm_workspace_classify_root(m.entries[i], home_dir, cache_dir) != CBM_WS_ALLOW) {
            continue;
        }
        if (cbm_path_within_root(m.entries[i], candidate)) {
            return true;
        }
    }
    return false;
}
