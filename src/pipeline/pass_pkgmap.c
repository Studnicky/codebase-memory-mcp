/*
 * pass_pkgmap.c — Generic package/module manifest resolution.
 *
 * Scans discovered files for manifest files (package.json, go.mod, Cargo.toml,
 * pyproject.toml, composer.json, pubspec.yaml, pom.xml, build.gradle, mix.exs,
 * *.gemspec, Package.swift) and builds a hash table mapping bare package specifiers to resolved
 * module QNs. This enables IMPORTS edges for non-relative imports like
 * "@myorg/pkg", "github.com/foo/bar", "use my_crate::foo".
 *
 * Integration: called from parallel extract workers (per-worker local arrays)
 * and merged sequentially before registry build.
 */
#include "cbm.h"
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "discover/discover.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/hash_table.h"
#include "foundation/log.h"
#include "foundation/platform.h"
#include "foundation/str_util.h"
#include "foundation/win_utf8.h"
#include "foundation/yaml.h"

#include <yyjson/yyjson.h>

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Read an entire file into a malloc'd buffer. Returns NULL on failure. */
static char *pkgmap_read_file(const char *path, int *out_len) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    (void)fseek(f, 0, SEEK_END);
    long size = ftell(f);
    (void)fseek(f, 0, SEEK_SET);
    if (size <= 0 || size > (long)CBM_SZ_1K * CBM_SZ_1K) { /* 1MB cap for manifests */
        (void)fclose(f);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)size + SKIP_ONE);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t nread = fread(buf, SKIP_ONE, (size_t)size, f);
    (void)fclose(f);
    buf[nread] = '\0';
    *out_len = (int)nread;
    return buf;
}

/* ── Constants ─────────────────────────────────────────────────── */

enum {
    PKGMAP_INIT_CAP = 16,
    PKGMAP_PATH_BUF = 1024,
    PKGMAP_LINE_BUF = 512,
    PKGMAP_HT_INIT = 64,
    PKGMAP_ITOA_BUF = 16,
    PKGMAP_IMPORT_PATH_BUF = 1024,
    PKGMAP_IMPORT_SYMBOL_BUF = 256,
    PKGMAP_EXACT_FILE_NAME_CANDIDATES = 2,
    PKGMAP_SIBLING_FILE_CANDIDATES = 5,
    PKGMAP_IMPORT_SYMBOL_CANDIDATES = 8,
    PKGMAP_DOT_ENTRY_COMPONENTS = 2,
    PKGMAP_RELATIVE_PREFIX_LEN = 2,
    /* Hard ceiling on recursive directory descent. This is the
     * non-negotiable termination guarantee for the manifest walk: even
     * if the filesystem contains directory junctions / symlink cycles
     * (the documented reason the walk was once disabled on Windows),
     * descent stops at this depth so the walk can never hang. 64 is far
     * deeper than any real source tree. */
    PKGMAP_WALK_MAX_DEPTH = 64,
    /* String lengths for manifest parsing (avoid magic numbers in memcmp) */
    TOML_NAME_LEN = 4,      /* strlen("name") */
    TOML_NAME_SP = 5,       /* strlen("name ") */
    TOML_NAME_EQ = 5,       /* strlen("name=") */
    XML_PARENT_OPEN = 8,    /* strlen("<parent>") */
    XML_PARENT_CLOSE = 9,   /* strlen("</parent>") */
    XML_GROUP_OPEN = 9,     /* strlen("<groupId>") */
    XML_ARTIFACT_OPEN = 12, /* strlen("<artifactId>") */
};

/* Thread-local int→string for log key-value pairs */
static const char *pkgmap_itoa(int val) {
    static _Thread_local char buf[PKGMAP_ITOA_BUF];
    snprintf(buf, sizeof(buf), "%d", val);
    return buf;
}

/* Check if src at position p starts with literal str of known length. */
static bool at_prefix(const char *p, const char *end, const char *prefix, int prefix_len) {
    return p + prefix_len <= end && memcmp(p, prefix, (size_t)prefix_len) == 0;
}

/* ── Per-worker collection ─────────────────────────────────────── */

void cbm_pkg_entries_init(cbm_pkg_entries_t *e) {
    e->items = NULL;
    e->count = 0;
    e->cap = 0;
}

static void pkg_entries_push(cbm_pkg_entries_t *e, char *pkg_name, char *entry_rel) {
    if (e->count >= e->cap) {
        /* e->cap is a fixed int per cbm_pkg_entries_t's header contract, so the
         * doubling grows in size_t first (no signed-overflow UB) and is
         * range-checked before truncating back into that int field. */
        size_t new_cap =
            e->cap == 0 ? (size_t)PKGMAP_INIT_CAP : (size_t)e->cap * SKIP_ONE * PAIR_LEN;
        if (new_cap > (size_t)INT_MAX) {
            free(pkg_name);
            free(entry_rel);
            return;
        }
        cbm_pkg_entry_t *tmp = realloc(e->items, new_cap * sizeof(cbm_pkg_entry_t));
        if (!tmp) {
            free(pkg_name);
            free(entry_rel);
            return;
        }
        e->items = tmp;
        e->cap = (int)new_cap;
    }
    e->items[e->count].pkg_name = pkg_name;
    e->items[e->count].entry_rel = entry_rel;
    e->count++;
}

void cbm_pkg_entries_free(cbm_pkg_entries_t *e) {
    for (int i = 0; i < e->count; i++) {
        free(e->items[i].pkg_name);
        free(e->items[i].entry_rel);
    }
    free(e->items);
    e->items = NULL;
    e->count = 0;
    e->cap = 0;
}

/* ── Helpers ───────────────────────────────────────────────────── */

/* Get the basename from a relative path. Returns pointer into rel_path. */
static const char *path_basename(const char *rel_path) {
    const char *last = strrchr(rel_path, '/');
    return last ? last + SKIP_ONE : rel_path;
}

/* Get the directory part of a relative path (without trailing slash).
 * Returns heap-allocated string. For "foo.json" returns "". */
static char *path_dirname(const char *rel_path) {
    const char *last = strrchr(rel_path, '/');
    if (!last) {
        return strdup("");
    }
    return cbm_strndup(rel_path, (size_t)(last - rel_path));
}

/* Strip file extension from a path. Returns heap-allocated string.
 * "src/index.ts" → "src/index", "lib/main" → "lib/main" */
static char *strip_extension(const char *path) {
    size_t len = strlen(path);
    for (size_t i = len; i > 0; i--) {
        if (path[i - SKIP_ONE] == '.') {
            return cbm_strndup(path, i - SKIP_ONE);
        }
        if (path[i - SKIP_ONE] == '/') {
            break;
        }
    }
    return strdup(path);
}

/* Join directory + relative entry path, normalize.
 * "packages/foo" + "src/index.ts" → "packages/foo/src/index" (stripped ext) */
static char *join_and_strip(const char *dir, const char *entry) {
    if (!entry || entry[0] == '\0') {
        return NULL;
    }
    /* Skip leading ./ from entry */
    if (entry[0] == '.' && entry[SKIP_ONE] == '/') {
        entry += PAIR_LEN;
    }
    char buf[PKGMAP_PATH_BUF];
    if (dir[0] == '\0') {
        snprintf(buf, sizeof(buf), "%s", entry);
    } else {
        snprintf(buf, sizeof(buf), "%s/%s", dir, entry);
    }
    return strip_extension(buf);
}

/* Check if a string ends with a suffix. */
static bool ends_with(const char *s, const char *suffix) {
    size_t slen = strlen(s);
    size_t suflen = strlen(suffix);
    if (suflen > slen) {
        return false;
    }
    return strcmp(s + slen - suflen, suffix) == 0;
}

/* Find a line starting with a prefix in source. Returns pointer to first char
 * after prefix, or NULL. Handles leading whitespace. */
static const char *find_line_value(const char *src, int src_len, const char *prefix) {
    size_t plen = strlen(prefix);
    const char *p = src;
    const char *end = src + src_len;
    while (p < end) {
        /* Skip leading whitespace */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (p + plen <= end && memcmp(p, prefix, plen) == 0) {
            return p + plen;
        }
        /* Skip to next line */
        while (p < end && *p != '\n') {
            p++;
        }
        if (p < end) {
            p++; /* skip \n */
        }
    }
    return NULL;
}

/* Extract a quoted string value from position. Handles both "..." and '...'
 * Returns heap-allocated string, or NULL. */
static char *extract_quoted(const char *p, const char *end) {
    /* Skip whitespace and = sign */
    while (p < end && (*p == ' ' || *p == '\t' || *p == '=')) {
        p++;
    }
    if (p >= end) {
        return NULL;
    }
    char quote = *p;
    if (quote != '"' && quote != '\'') {
        return NULL;
    }
    p++;
    const char *start = p;
    while (p < end && *p != quote && *p != '\n') {
        p++;
    }
    if (p >= end || *p != quote) {
        return NULL;
    }
    return cbm_strndup(start, (size_t)(p - start));
}

/* ── Language-specific manifest parsers ────────────────────────── */

/* Resolve JS/TS entry point from exports["."] object. */
static const char *resolve_exports_dot(yyjson_val *dot) {
    if (yyjson_is_str(dot)) {
        return yyjson_get_str(dot);
    }
    if (!yyjson_is_obj(dot)) {
        return NULL;
    }
    static const char *keys[] = {"import", "default", "require"};
    for (int i = 0; i < (int)(sizeof(keys) / sizeof(keys[0])); i++) {
        yyjson_val *v = yyjson_obj_get(dot, keys[i]);
        if (yyjson_is_str(v)) {
            return yyjson_get_str(v);
        }
    }
    return NULL;
}

/* Resolve JS/TS entry point from package.json root. */
static const char *resolve_pkg_entry(yyjson_val *root) {
    yyjson_val *exports = yyjson_obj_get(root, "exports");
    if (yyjson_is_obj(exports)) {
        const char *e = resolve_exports_dot(yyjson_obj_get(exports, "."));
        if (e) {
            return e;
        }
    }
    static const char *fallback_keys[] = {"main", "module"};
    for (int i = 0; i < (int)(sizeof(fallback_keys) / sizeof(fallback_keys[0])); i++) {
        yyjson_val *v = yyjson_obj_get(root, fallback_keys[i]);
        if (yyjson_is_str(v)) {
            return yyjson_get_str(v);
        }
    }
    return "src/index.ts"; /* last resort default */
}

/* JS/TS: package.json — name + entry point resolution */
static void parse_package_json(const char *source, int source_len, const char *rel_path,
                               cbm_pkg_entries_t *entries) {
    yyjson_doc *doc = yyjson_read(source, (size_t)source_len, 0);
    if (!doc) {
        return;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        yyjson_doc_free(doc);
        return;
    }

    yyjson_val *name_val = yyjson_obj_get(root, "name");
    if (!yyjson_is_str(name_val)) {
        yyjson_doc_free(doc);
        return;
    }
    const char *name = yyjson_get_str(name_val);
    if (!name || name[0] == '\0') {
        yyjson_doc_free(doc);
        return;
    }

    const char *entry = resolve_pkg_entry(root);
    if (entry) {
        char *dir = path_dirname(rel_path);
        char *resolved = join_and_strip(dir, entry);
        if (resolved) {
            pkg_entries_push(entries, strdup(name), resolved);
        }
        free(dir);
    }

    yyjson_doc_free(doc);
}

/* Go: go.mod — module directive */
static void parse_go_mod(const char *source, int source_len, const char *rel_path,
                         cbm_pkg_entries_t *entries) {
    const char *end = source + source_len;
    const char *val = find_line_value(source, source_len, "module ");
    if (!val) {
        return;
    }
    /* Extract module path (rest of line, trimmed) */
    while (val < end && (*val == ' ' || *val == '\t')) {
        val++;
    }
    const char *start = val;
    while (val < end && *val != '\n' && *val != '\r' && *val != ' ') {
        val++;
    }
    if (val <= start) {
        return;
    }
    char *module_path = cbm_strndup(start, (size_t)(val - start));
    char *dir = path_dirname(rel_path);

    /* The module path maps to the directory containing go.mod.
     * For "." dir, use empty string. */
    pkg_entries_push(entries, module_path, strdup(dir));
    free(dir);
}

/* Extract "name" value from a TOML section. Scans from section_start until
 * the next [...] header or EOF. Returns heap string or NULL. */
static char *toml_extract_name(const char *section_start, const char *end) {
    const char *p = section_start;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (p < end && *p == '[') {
            break;
        }
        if (at_prefix(p, end, "name ", TOML_NAME_SP)) {
            return extract_quoted(p + TOML_NAME_SP, end);
        }
        if (at_prefix(p, end, "name=", TOML_NAME_EQ)) {
            return extract_quoted(p + TOML_NAME_EQ, end);
        }
        while (p < end && *p != '\n') {
            p++;
        }
        if (p < end) {
            p++;
        }
    }
    return NULL;
}

/* Build entry path: dir/suffix or just suffix if dir is empty. */
static char *build_entry_path(const char *rel_path, const char *suffix) {
    char *dir = path_dirname(rel_path);
    char buf[PKGMAP_PATH_BUF];
    snprintf(buf, sizeof(buf), "%s%s%s", dir[0] ? dir : "", dir[0] ? "/" : "", suffix);
    free(dir);
    return strdup(buf);
}

/* Rust: Cargo.toml — [package] name */
static void parse_cargo_toml(const char *source, int source_len, const char *rel_path,
                             cbm_pkg_entries_t *entries) {
    const char *section = find_line_value(source, source_len, "[package]");
    if (!section) {
        return;
    }
    char *name = toml_extract_name(section, source + source_len);
    if (!name) {
        return;
    }
    char *entry = build_entry_path(rel_path, "src/lib");
    pkg_entries_push(entries, name, entry);
}

/* Python: pyproject.toml — [project] name */
/* Normalize Python package name: hyphens → underscores (PEP 503). */
static void py_normalize_name(char *name) {
    for (char *c = name; *c; c++) {
        if (*c == '-') {
            *c = '_';
        }
    }
}

static void parse_pyproject_toml(const char *source, int source_len, const char *rel_path,
                                 cbm_pkg_entries_t *entries) {
    const char *section = find_line_value(source, source_len, "[project]");
    if (!section) {
        return;
    }
    char *name = toml_extract_name(section, source + source_len);
    if (!name) {
        return;
    }
    py_normalize_name(name);

    /* Register src/<name>/__init__ as primary entry */
    char suffix[PKGMAP_PATH_BUF];
    snprintf(suffix, sizeof(suffix), "src/%s/__init__", name);
    char *entry = build_entry_path(rel_path, suffix);
    char *name_copy = strdup(name);
    pkg_entries_push(entries, name, entry);

    /* Also register <name>/__init__ as alternative (no src/ prefix) */
    char *alt_entry = NULL;
    if (name_copy) {
        snprintf(suffix, sizeof(suffix), "%s/__init__", name_copy);
        alt_entry = build_entry_path(rel_path, suffix);
    }

    if (name_copy && alt_entry) {
        pkg_entries_push(entries, name_copy, alt_entry);
    } else {
        free(name_copy);
        free(alt_entry);
    }
}

/* Extract PSR-4 autoload entries from composer.json root. */
static void extract_psr4(yyjson_val *root, const char *dir, cbm_pkg_entries_t *entries) {
    yyjson_val *autoload = yyjson_obj_get(root, "autoload");
    if (!yyjson_is_obj(autoload)) {
        return;
    }
    yyjson_val *psr4 = yyjson_obj_get(autoload, "psr-4");
    if (!yyjson_is_obj(psr4)) {
        return;
    }
    yyjson_val *key = NULL;
    yyjson_obj_iter iter = yyjson_obj_iter_with(psr4);
    while ((key = yyjson_obj_iter_next(&iter)) != NULL) {
        yyjson_val *val = yyjson_obj_iter_get_val(key);
        if (!yyjson_is_str(key) || !yyjson_is_str(val)) {
            continue;
        }
        const char *ns_prefix = yyjson_get_str(key);
        const char *ns_dir = yyjson_get_str(val);
        char ns_entry[PKGMAP_PATH_BUF];
        if (dir[0]) {
            snprintf(ns_entry, sizeof(ns_entry), "%s/%s", dir, ns_dir);
        } else {
            snprintf(ns_entry, sizeof(ns_entry), "%s", ns_dir);
        }
        size_t nelen = strlen(ns_entry);
        if (nelen > 0 && ns_entry[nelen - SKIP_ONE] == '/') {
            ns_entry[nelen - SKIP_ONE] = '\0';
        }
        pkg_entries_push(entries, strdup(ns_prefix), strdup(ns_entry));
    }
}

/* PHP: composer.json — name + PSR-4 autoload */
static void parse_composer_json(const char *source, int source_len, const char *rel_path,
                                cbm_pkg_entries_t *entries) {
    yyjson_doc *doc = yyjson_read(source, (size_t)source_len, 0);
    if (!doc) {
        return;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        yyjson_doc_free(doc);
        return;
    }

    char *dir = path_dirname(rel_path);

    /* Register package name → directory */
    yyjson_val *name_val = yyjson_obj_get(root, "name");
    if (yyjson_is_str(name_val)) {
        const char *name = yyjson_get_str(name_val);
        if (name && name[0] != '\0') {
            pkg_entries_push(entries, strdup(name), strdup(dir));
        }
    }

    extract_psr4(root, dir, entries);

    free(dir);
    yyjson_doc_free(doc);
}

/* Dart: pubspec.yaml — name */
static void parse_pubspec_yaml(const char *source, int source_len, const char *rel_path,
                               cbm_pkg_entries_t *entries) {
    cbm_yaml_node_t *root = cbm_yaml_parse(source, source_len);
    if (!root) {
        return;
    }
    const char *name = cbm_yaml_get_str(root, "name");
    if (name && name[0] != '\0') {
        char *dir = path_dirname(rel_path);
        char entry[PKGMAP_PATH_BUF];
        snprintf(entry, sizeof(entry), "%s%slib", dir[0] ? dir : "", dir[0] ? "/" : "");
        pkg_entries_push(entries, strdup(name), strdup(entry));
        free(dir);
    }
    cbm_yaml_free(root);
}

/* Extract text content of an XML tag at position p. Returns heap string or NULL.
 * p must point to the char after the opening tag's '>'. */
static char *xml_tag_content(const char *p, const char *end) {
    const char *s = p;
    while (p < end && *p != '<') {
        p++;
    }
    if (p <= s) {
        return NULL;
    }
    return cbm_strndup(s, (size_t)(p - s));
}

/* Java: pom.xml — <groupId> + <artifactId> */
/* Scan pom.xml for a top-level XML tag (outside <parent>). Returns heap string or NULL. */
static char *pom_find_tag(const char *source, const char *end, const char *tag, int tag_len) {
    const char *p = source;
    bool in_parent = false;
    while (p < end) {
        if (at_prefix(p, end, "<parent>", XML_PARENT_OPEN)) {
            in_parent = true;
        }
        if (at_prefix(p, end, "</parent>", XML_PARENT_CLOSE)) {
            in_parent = false;
        }
        if (!in_parent && at_prefix(p, end, tag, tag_len)) {
            return xml_tag_content(p + tag_len, end);
        }
        p++;
    }
    return NULL;
}

static void parse_pom_xml(const char *source, int source_len, const char *rel_path,
                          cbm_pkg_entries_t *entries) {
    const char *end = source + source_len;
    char *group_id = pom_find_tag(source, end, "<groupId>", XML_GROUP_OPEN);
    char *artifact_id = pom_find_tag(source, end, "<artifactId>", XML_ARTIFACT_OPEN);

    if (group_id && artifact_id) {
        /* Map: "com.myorg.myapp" → src/main/java directory */
        char pkg_name[PKGMAP_PATH_BUF];
        snprintf(pkg_name, sizeof(pkg_name), "%s.%s", group_id, artifact_id);
        char *dir = path_dirname(rel_path);
        char entry[PKGMAP_PATH_BUF];
        snprintf(entry, sizeof(entry), "%s%ssrc/main/java", dir[0] ? dir : "", dir[0] ? "/" : "");
        pkg_entries_push(entries, strdup(pkg_name), strdup(entry));

        /* Also register just the groupId for package-level imports */
        char grp_entry[PKGMAP_PATH_BUF];
        snprintf(grp_entry, sizeof(grp_entry), "%s%ssrc/main/java", dir[0] ? dir : "",
                 dir[0] ? "/" : "");
        pkg_entries_push(entries, strdup(group_id), strdup(grp_entry));
        free(dir);
    }

    free(group_id);
    free(artifact_id);
}

/* Gradle: build.gradle / build.gradle.kts — group = '...' */
static void parse_build_gradle(const char *source, int source_len, const char *rel_path,
                               cbm_pkg_entries_t *entries) {
    const char *end = source + source_len;
    /* Look for group = '...' or group '...' or group = "..." */
    const char *val = find_line_value(source, source_len, "group");
    if (!val) {
        return;
    }
    char *group = extract_quoted(val, end);
    if (!group) {
        return;
    }
    char *dir = path_dirname(rel_path);
    /* Check for src/main/java or src/main/kotlin */
    char entry[PKGMAP_PATH_BUF];
    snprintf(entry, sizeof(entry), "%s%ssrc/main/java", dir[0] ? dir : "", dir[0] ? "/" : "");
    pkg_entries_push(entries, group, strdup(entry));
    free(dir);
}

/* Elixir: mix.exs — app: :name */
static void parse_mix_exs(const char *source, int source_len, const char *rel_path,
                          cbm_pkg_entries_t *entries) {
    const char *end = source + source_len;
    /* Look for app: :app_name */
    const char *val = find_line_value(source, source_len, "app:");
    if (!val) {
        return;
    }
    while (val < end && (*val == ' ' || *val == '\t')) {
        val++;
    }
    if (val >= end || *val != ':') {
        return;
    }
    val++; /* skip : */
    const char *start = val;
    while (val < end && *val != ',' && *val != '\n' && *val != ' ' && *val != ')') {
        val++;
    }
    if (val <= start) {
        return;
    }
    char *app_name = cbm_strndup(start, (size_t)(val - start));
    char *dir = path_dirname(rel_path);
    char entry[PKGMAP_PATH_BUF];
    snprintf(entry, sizeof(entry), "%s%slib/%s", dir[0] ? dir : "", dir[0] ? "/" : "", app_name);
    /* Register with colon prefix as Elixir uses :atom syntax */
    char atom_name[PKGMAP_PATH_BUF];
    snprintf(atom_name, sizeof(atom_name), "%s", app_name);
    pkg_entries_push(entries, strdup(atom_name), strdup(entry));
    free(app_name);
    free(dir);
}

/* Ruby: *.gemspec — spec.name = '...' */
static void parse_gemspec(const char *source, int source_len, const char *rel_path,
                          cbm_pkg_entries_t *entries) {
    const char *end = source + source_len;
    /* Try spec.name, s.name, gem.name patterns */
    static const char *patterns[] = {".name", NULL};
    for (int i = 0; patterns[i]; i++) {
        const char *p = source;
        while (p < end) {
            const char *found = strstr(p, patterns[i]);
            if (!found || found >= end) {
                break;
            }
            char *name = extract_quoted(found + strlen(patterns[i]), end);
            if (name) {
                char *dir = path_dirname(rel_path);
                char entry[PKGMAP_PATH_BUF];
                snprintf(entry, sizeof(entry), "%s%slib/%s", dir[0] ? dir : "", dir[0] ? "/" : "",
                         name);
                pkg_entries_push(entries, name, strdup(entry));
                free(dir);
                return;
            }
            p = found + SKIP_ONE;
        }
    }
}

/* Swift: Package.swift — SwiftPM manifest.
 *
 * Package.swift is executable Swift, not declarative, so this is a
 * hand-rolled literal pattern-extractor (same spirit as parse_cargo_toml),
 * not a Swift evaluator: it locates `.target(...)` call expressions via a
 * comment/string-aware token scan and pulls only their quoted-string-literal
 * `name:` / `path:` arguments. Anything computed or concatenated is
 * skipped, not guessed — fail-closed, like every other parser here.
 *
 * Only a manifest's OWN `.target(...)` declarations self-register — never
 * `.library(...)` products (a product name is not generally an importable
 * module: SwiftPM lets it alias multiple targets, or none sharing its
 * name), and never `.package(url:)` / `.package(path:)` dependencies or
 * target-to-target dependency references. A dependency resolves because
 * the DEPENDENCY's own Package.swift registers itself when the repo-wide
 * manifest walk (cbm_pkgmap_scan_repo) reaches it, exactly like a JS
 * workspace sibling's package.json (see repro_issue408.c).
 *
 * Deliberately out of scope (matches the item-1 authorization): evaluating
 * `#if`/`#endif` conditional-compilation blocks. A `.target(...)` inside
 * one is scanned like any other — teaching the extractor which platform
 * conditions are "active" would need a Swift semantic tier, which this PR
 * was explicitly asked not to add. */

/* One step of comment/string-aware scanning, shared by swift_find_code_token
 * and swift_match_paren below. If `*pp` sits inside, or is entering, a `//`
 * line comment, a nesting-aware slash-star block comment (continued across
 * calls via `*block_depth`), or a "..." string literal (escape aware,
 * tracked via `*in_str`), advances `*pp` past that one step and returns
 * true. Otherwise leaves `*pp` untouched and returns false, so the caller
 * handles the "real code" character itself (paren tracking, needle
 * matching, ...). */
static bool swift_skip_comment_or_string(const char **pp, const char *end, int *block_depth,
                                         bool *in_str) {
    const char *p = *pp;
    if (*block_depth > 0) {
        if (p + SKIP_ONE < end && p[0] == '/' && p[SKIP_ONE] == '*') {
            (*block_depth)++;
            *pp = p + PAIR_LEN;
        } else if (p + SKIP_ONE < end && p[0] == '*' && p[SKIP_ONE] == '/') {
            (*block_depth)--;
            *pp = p + PAIR_LEN;
        } else {
            *pp = p + SKIP_ONE;
        }
        return true;
    }
    if (*in_str) {
        if (*p == '\\' && p + SKIP_ONE < end) {
            *pp = p + PAIR_LEN;
        } else {
            if (*p == '"') {
                *in_str = false;
            }
            *pp = p + SKIP_ONE;
        }
        return true;
    }
    if (p + SKIP_ONE < end && p[0] == '/' && p[SKIP_ONE] == '/') {
        while (p < end && *p != '\n') {
            p++;
        }
        *pp = p;
        return true;
    }
    if (p + SKIP_ONE < end && p[0] == '/' && p[SKIP_ONE] == '*') {
        *block_depth = SKIP_ONE;
        *pp = p + PAIR_LEN;
        return true;
    }
    if (*p == '"') {
        *in_str = true;
        *pp = p + SKIP_ONE;
        return true;
    }
    return false;
}

/* Scans [start, end) for the next occurrence of `needle` that is not inside
 * a `//` line comment, a nesting-aware slash-star block comment, or a "..."
 * string literal (backslash-escapes honored). This is the single source of
 * truth for "real code" scanning below — a `.target(`, `name:`, or `path:`
 * spelled inside a comment or a string constant must never be mistaken for
 * a live declaration. Returns a pointer to the match, or NULL. */
static const char *swift_find_code_token(const char *start, const char *end, const char *needle) {
    size_t nlen = strlen(needle);
    int block_depth = 0;
    bool in_str = false;
    const char *p = start;
    while (p < end) {
        if (swift_skip_comment_or_string(&p, end, &block_depth, &in_str)) {
            continue;
        }
        if ((size_t)(end - p) >= nlen && memcmp(p, needle, nlen) == 0) {
            return p;
        }
        p++;
    }
    return NULL;
}

/* Find the matching ')' for the '(' at `open`, scanning forward to `end`.
 * Delegates comment/string spans to swift_skip_comment_or_string — matching
 * swift_find_code_token — so a ')', '(', or comment delimiter inside a
 * quoted argument value or a comment never perturbs the depth count.
 * Returns NULL for an unbalanced/unterminated call — the caller treats
 * that span as unparseable and skips it (fail-closed). */
static const char *swift_match_paren(const char *open, const char *end) {
    int depth = 0;
    int block_depth = 0;
    bool in_str = false;
    const char *p = open;
    while (p < end) {
        if (swift_skip_comment_or_string(&p, end, &block_depth, &in_str)) {
            continue;
        }
        if (*p == '(') {
            depth++;
        } else if (*p == ')') {
            depth--;
            if (depth == 0) {
                return p;
            }
        }
        p++;
    }
    return NULL;
}

/* Extract a bare double-quoted string-literal value at `p` (after skipping
 * leading whitespace and honoring backslash-escapes inside the literal),
 * requiring the closing quote be immediately followed by a comma, or by
 * `end` — rejects `name: "Foo" + suffix`-style concatenation, which a plain
 * quote-scan alone cannot tell apart from a true literal. Every caller here
 * passes the enclosing call's own closing ')' position as `end`, so landing
 * exactly on it after the closing quote correctly means "immediately
 * followed by the close-paren", not just "ran off the end of the buffer".
 * Returns heap string, or NULL (fail-closed). */
static char *swift_quoted_literal(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    if (p >= end || *p != '"') {
        return NULL;
    }
    p++;
    const char *start = p;
    while (p < end && *p != '"' && *p != '\n') {
        if (*p == '\\' && p + SKIP_ONE < end) {
            p += PAIR_LEN;
            continue;
        }
        p++;
    }
    if (p >= end || *p != '"') {
        return NULL;
    }
    char *value = cbm_strndup(start, (size_t)(p - start));
    p++; /* past closing quote */
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    if (p >= end || *p == ',') {
        return value;
    }
    free(value);
    return NULL;
}

/* Search [start, end) for `needle` via swift_find_code_token (skipping
 * comments/strings), then extract the bare quoted-literal argument
 * immediately following it via swift_quoted_literal. Bounded to `end` so a
 * match can never leak past the enclosing call's own argument list into a
 * later, unrelated declaration. When `out_found` is non-NULL, it is set to
 * whether `needle` was located at all — independent of whether its value
 * parsed as a bare literal — so callers can tell "argument absent" (fine,
 * apply a default) apart from "argument present but not a literal"
 * (unknowable, fail closed). Returns heap string or NULL. */
static char *swift_extract_after(const char *start, const char *end, const char *needle,
                                 bool *out_found) {
    if (out_found) {
        *out_found = false;
    }
    const char *hit = swift_find_code_token(start, end, needle);
    if (!hit) {
        return NULL;
    }
    if (out_found) {
        *out_found = true;
    }
    return swift_quoted_literal(hit + strlen(needle), end);
}

/* Register `target_name` → its resolved source directory: the literal
 * `path:` argument the target declared, if any, else the conventional
 * `Sources/<target_name>` (fixed-convention, same approach parse_cargo_toml
 * takes for `src/lib`). `literal_path` is borrowed; caller retains
 * ownership. */
static void swift_register_target(const char *rel_path, const char *target_name,
                                  const char *literal_path, cbm_pkg_entries_t *entries) {
    if (!target_name || !target_name[0]) {
        return;
    }
    char suffix_buf[PKGMAP_PATH_BUF];
    const char *suffix;
    if (literal_path && literal_path[0]) {
        suffix = literal_path;
    } else {
        snprintf(suffix_buf, sizeof(suffix_buf), "Sources/%s", target_name);
        suffix = suffix_buf;
    }
    char *entry = build_entry_path(rel_path, suffix);
    if (entry) {
        pkg_entries_push(entries, strdup(target_name), entry);
    }
}

/* Scan for `.target(name: "Foo", ...)` declarations, skipping any
 * `.target(` spelling that falls inside a comment or string literal.
 * Non-overlapping: the scan resumes AFTER each matched close paren, so a
 * `dependencies: [.target(name: "Bar")]` reference nested inside Foo's own
 * argument list is never re-visited as a second top-level target.
 *
 * A target with a `path:` argument that isn't a bare literal (computed,
 * concatenated, ...) is skipped entirely, even though its `name:` may be a
 * valid literal: SwiftPM would use the computed path, not the
 * `Sources/<name>` convention, and guessing that convention anyway would
 * mint a location that is not just unconfirmed but actively likely wrong. */
static void swift_scan_targets(const char *source, const char *end, const char *rel_path,
                               cbm_pkg_entries_t *entries) {
    static const char prefix[] = ".target(";
    const char *cursor = source;
    while (cursor < end) {
        const char *hit = swift_find_code_token(cursor, end, prefix);
        if (!hit) {
            return;
        }
        const char *open = hit + strlen(prefix) - SKIP_ONE;
        const char *close = swift_match_paren(open, end);
        if (!close) {
            return; /* unbalanced — nothing further here is trustworthy */
        }
        char *name = swift_extract_after(open, close, "name:", NULL);
        if (name) {
            bool path_present = false;
            char *literal_path = swift_extract_after(open, close, "path:", &path_present);
            if (literal_path || !path_present) {
                swift_register_target(rel_path, name, literal_path, entries);
            }
            free(literal_path);
            free(name);
        }
        cursor = close + SKIP_ONE;
    }
}

/* SwiftPM: Package.swift — targets → Sources/<name> (or their literal
 * `path:`). Products deliberately do not self-register: see the file
 * comment above swift_find_code_token. */
static void parse_package_swift(const char *source, int source_len, const char *rel_path,
                                cbm_pkg_entries_t *entries) {
    const char *end = source + source_len;
    swift_scan_targets(source, end, rel_path, entries);
}

/* ── Public: manifest detection + parsing ──────────────────────── */

bool cbm_pkgmap_try_parse(const char *basename, const char *rel_path, const char *source,
                          int source_len, cbm_pkg_entries_t *entries) {
    if (!basename || !source || source_len <= 0) {
        return false;
    }

    if (strcmp(basename, "package.json") == 0) {
        parse_package_json(source, source_len, rel_path, entries);
        return true;
    }
    if (strcmp(basename, "go.mod") == 0) {
        parse_go_mod(source, source_len, rel_path, entries);
        return true;
    }
    if (strcmp(basename, "Cargo.toml") == 0) {
        parse_cargo_toml(source, source_len, rel_path, entries);
        return true;
    }
    if (strcmp(basename, "pyproject.toml") == 0) {
        parse_pyproject_toml(source, source_len, rel_path, entries);
        return true;
    }
    if (strcmp(basename, "composer.json") == 0) {
        parse_composer_json(source, source_len, rel_path, entries);
        return true;
    }
    if (strcmp(basename, "pubspec.yaml") == 0) {
        parse_pubspec_yaml(source, source_len, rel_path, entries);
        return true;
    }
    if (strcmp(basename, "pom.xml") == 0) {
        parse_pom_xml(source, source_len, rel_path, entries);
        return true;
    }
    if (strcmp(basename, "build.gradle") == 0 || strcmp(basename, "build.gradle.kts") == 0) {
        parse_build_gradle(source, source_len, rel_path, entries);
        return true;
    }
    if (strcmp(basename, "mix.exs") == 0) {
        parse_mix_exs(source, source_len, rel_path, entries);
        return true;
    }
    if (ends_with(basename, ".gemspec")) {
        parse_gemspec(source, source_len, rel_path, entries);
        return true;
    }
    if (strcmp(basename, "Package.swift") == 0) {
        parse_package_swift(source, source_len, rel_path, entries);
        return true;
    }
    return false;
}

/* ── Merge: per-worker entries → hash table ────────────────────── */

CBMHashTable *cbm_pkgmap_build(cbm_pkg_entries_t *worker_entries, int worker_count,
                               const char *project_name) {
    /* Count total entries */
    int total = 0;
    for (int w = 0; w < worker_count; w++) {
        total += worker_entries[w].count;
    }
    if (total == 0) {
        return NULL;
    }

    CBMHashTable *map = cbm_ht_create(PKGMAP_HT_INIT);
    int merged = 0;

    for (int w = 0; w < worker_count; w++) {
        cbm_pkg_entries_t *we = &worker_entries[w];
        for (int i = 0; i < we->count; i++) {
            /* Convert entry_rel to QN: project.dir.parts */
            char *qn = cbm_pipeline_fqn_module(project_name, we->items[i].entry_rel);
            if (!qn) {
                continue;
            }

            /* Check for duplicate — first wins */
            if (cbm_ht_has(map, we->items[i].pkg_name)) {
                free(qn);
                continue;
            }

            /* Transfer ownership: key = strdup'd pkg_name, value = qn */
            char *key = strdup(we->items[i].pkg_name);
            cbm_ht_set(map, key, qn);
            merged++;
        }
    }

    if (merged == 0) {
        cbm_ht_free(map);
        return NULL;
    }
    cbm_log_info("pkgmap.build", "entries", pkgmap_itoa(merged));
    return map;
}

/* Returns true if basename is a package manifest we know how to parse.
 * Used by the filesystem walker; cbm_pkgmap_try_parse is the source of
 * truth for which basenames produce entries. */
static bool is_pkgmap_manifest_basename(const char *basename) {
    if (!basename) {
        return false;
    }
    if (strcmp(basename, "package.json") == 0 || strcmp(basename, "go.mod") == 0 ||
        strcmp(basename, "Cargo.toml") == 0 || strcmp(basename, "pyproject.toml") == 0 ||
        strcmp(basename, "composer.json") == 0 || strcmp(basename, "pubspec.yaml") == 0 ||
        strcmp(basename, "pom.xml") == 0 || strcmp(basename, "build.gradle") == 0 ||
        strcmp(basename, "build.gradle.kts") == 0 || strcmp(basename, "mix.exs") == 0 ||
        strcmp(basename, "Package.swift") == 0) {
        return true;
    }
    return ends_with(basename, ".gemspec");
}

/* Stat a path, skipping symlinks. Returns 0 on success, -1 to skip.
 * On POSIX, lstat + S_ISLNK avoids following symlink cycles. On Windows
 * we use the UTF-8-safe wide stat (mirroring discover.c's wide_stat);
 * reparse points (junctions/symlinks) are detected separately by
 * pkgmap_is_reparse_point below before we descend. Mirrors discover.c's
 * safe_stat. */
static int pkgmap_safe_stat(const char *abs_path, struct stat *st) {
#ifdef _WIN32
    wchar_t *wpath = cbm_path_to_wide(abs_path);
    if (!wpath) {
        return CBM_NOT_FOUND;
    }
    struct _stat64 wst;
    int ret = _wstat64(wpath, &wst);
    free(wpath);
    if (ret != 0) {
        return CBM_NOT_FOUND;
    }
    st->st_mode = wst.st_mode;
    st->st_size = wst.st_size;
    st->st_mtime = wst.st_mtime;
    return 0;
#else
    if (lstat(abs_path, st) != 0) {
        return CBM_NOT_FOUND;
    }
    if (S_ISLNK(st->st_mode)) {
        return CBM_NOT_FOUND;
    }
    return 0;
#endif
}

/* True if abs_path is a Windows reparse point (directory junction or
 * symlink). Following these is the documented cause of the historic CI
 * hang, so we skip them before recursing. On POSIX this is a no-op
 * (symlinks are already filtered by pkgmap_safe_stat's S_ISLNK check).
 * Note: the PKGMAP_WALK_MAX_DEPTH bound below is the hard termination
 * guarantee; this check is a best-effort early skip on top of it. */
#ifdef _WIN32
static bool pkgmap_is_reparse_point(const char *abs_path) {
    wchar_t *wpath = cbm_path_to_wide(abs_path);
    if (!wpath) {
        return false;
    }
    DWORD attrs = GetFileAttributesW(wpath);
    free(wpath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}
#endif

typedef struct {
    char *absolute;
    char *relative;
    int depth;
    cbm_dir_t *handle;
} pkgmap_walk_directory_t;

typedef struct {
    pkgmap_walk_directory_t *items;
    int count;
    int capacity;
} pkgmap_walk_stack_t;

static void pkgmap_walk_stack_free(pkgmap_walk_stack_t *stack) {
    for (int index = 0; index < stack->count; ++index) {
        if (stack->items[index].handle) {
            cbm_closedir(stack->items[index].handle);
        }
        free(stack->items[index].absolute);
        free(stack->items[index].relative);
    }
    free(stack->items);
}

static bool pkgmap_walk_stack_push(pkgmap_walk_stack_t *stack, const char *absolute,
                                   const char *relative, int depth) {
    if (stack->count == stack->capacity) {
        int capacity = stack->capacity == 0 ? PKGMAP_INIT_CAP : stack->capacity * PAIR_LEN;
        pkgmap_walk_directory_t *items =
            realloc(stack->items, (size_t)capacity * sizeof(*stack->items));
        if (!items) {
            return false;
        }
        stack->items = items;
        stack->capacity = capacity;
    }
    char *absolute_copy = strdup(absolute);
    char *relative_copy = strdup(relative);
    if (!absolute_copy || !relative_copy) {
        free(absolute_copy);
        free(relative_copy);
        return false;
    }
    stack->items[stack->count++] = (pkgmap_walk_directory_t){
        .absolute = absolute_copy, .relative = relative_copy, .depth = depth, .handle = NULL};
    return true;
}

static void pkgmap_walk_stack_drop_top(pkgmap_walk_stack_t *stack) {
    if (stack->count == 0) {
        return;
    }
    pkgmap_walk_directory_t *directory = &stack->items[--stack->count];
    if (directory->handle) {
        cbm_closedir(directory->handle);
    }
    free(directory->absolute);
    free(directory->relative);
}

static bool pkgmap_walk_is_dot_entry(const char *name) {
    return name[0] == '.' && (name[SKIP_ONE] == '\0' ||
                              (name[SKIP_ONE] == '.' && name[PKGMAP_DOT_ENTRY_COMPONENTS] == '\0'));
}

static bool pkgmap_walk_should_descend(const char *name, const char *absolute, const char *relative,
                                       char **excluded_dirs, int excluded_count) {
    if (cbm_should_skip_dir(name, CBM_MODE_FULL) ||
        cbm_pipeline_relpath_is_excluded(relative, excluded_dirs, excluded_count)) {
        return false;
    }
#ifdef _WIN32
    if (pkgmap_is_reparse_point(absolute)) {
        return false;
    }
#else
    (void)absolute;
#endif
    return true;
}

static int pkgmap_walk_parse_manifest(const char *absolute, const char *relative, const char *name,
                                      cbm_pkg_entries_t *entries) {
    if (!is_pkgmap_manifest_basename(name)) {
        return 0;
    }
    int source_length = 0;
    char *source = pkgmap_read_file(absolute, &source_length);
    if (!source) {
        return 0;
    }
    bool parsed = cbm_pkgmap_try_parse(name, relative, source, source_length, entries);
    free(source);
    return parsed ? SKIP_ONE : 0;
}

static int pkgmap_walk_process_entry(const pkgmap_walk_directory_t *directory,
                                     const cbm_dirent_t *entry, pkgmap_walk_stack_t *stack,
                                     cbm_pkg_entries_t *entries, char **excluded_dirs,
                                     int excluded_count) {
    const char *name = entry->name;
    if (pkgmap_walk_is_dot_entry(name)) {
        return 0;
    }
    char absolute[PKGMAP_PATH_BUF];
    char relative[PKGMAP_PATH_BUF];
    snprintf(absolute, sizeof(absolute), "%s/%s", directory->absolute, name);
    snprintf(relative, sizeof(relative), "%s%s%s", directory->relative,
             directory->relative[0] ? "/" : "", name);
    struct stat status;
    if (pkgmap_safe_stat(absolute, &status) != 0) {
        return 0;
    }
    if (S_ISDIR(status.st_mode)) {
        if (pkgmap_walk_should_descend(name, absolute, relative, excluded_dirs, excluded_count)) {
            (void)pkgmap_walk_stack_push(stack, absolute, relative, directory->depth + SKIP_ONE);
        }
        return 0;
    }
    return S_ISREG(status.st_mode) ? pkgmap_walk_parse_manifest(absolute, relative, name, entries)
                                   : 0;
}

/* Iterative filesystem walker that finds and parses package manifests independently
 * of the main discovery filter. A depth-bounded owned-path worklist prevents
 * symlink or junction cycles without using recursive calls. */
static int pkgmap_walk_dir(const char *abs_dir, const char *rel_dir, cbm_pkg_entries_t *entries,
                           int depth, char **excluded_dirs, int excluded_count) {
    pkgmap_walk_stack_t stack = {0};
    (void)pkgmap_walk_stack_push(&stack, abs_dir, rel_dir ? rel_dir : "", depth);
    int parsed = 0;
    while (stack.count > 0) {
        pkgmap_walk_directory_t *directory = &stack.items[stack.count - SKIP_ONE];
        if (directory->depth >= PKGMAP_WALK_MAX_DEPTH) {
            cbm_log_info("pkgmap.walk", "depth_cap",
                         directory->relative[0] ? directory->relative : ".");
            pkgmap_walk_stack_drop_top(&stack);
            continue;
        }
        if (!directory->handle) {
            directory->handle = cbm_opendir(directory->absolute);
            if (!directory->handle) {
                pkgmap_walk_stack_drop_top(&stack);
                continue;
            }
        }
        cbm_dirent_t *entry = cbm_readdir(directory->handle);
        if (!entry) {
            pkgmap_walk_stack_drop_top(&stack);
            continue;
        }
        parsed += pkgmap_walk_process_entry(directory, entry, &stack, entries, excluded_dirs,
                                            excluded_count);
    }
    pkgmap_walk_stack_free(&stack);
    return parsed;
}

/* Scan a repository for package manifest files via the filesystem
 * walker above. Always-available companion to the parallel path's
 * per-worker manifest parsing, which is bound to whatever `files[]`
 * the discoverer produces and therefore misses ignored manifests like
 * package.json. NULL-safe; returns 0 entries when repo_path is unset.
 *
 * Cross-platform: the walk runs on every platform via pkgmap_walk_dir,
 * which is depth-bounded (PKGMAP_WALK_MAX_DEPTH) and skips symlinks /
 * Windows reparse points, so it cannot hang on directory junctions.
 * This is what lets bare workspace imports (e.g. "@org/pkg" declared in
 * an ignored package.json) resolve on Windows as well as POSIX. */
int cbm_pkgmap_scan_repo(const char *repo_path, cbm_pkg_entries_t *entries, char **excluded_dirs,
                         int excluded_count) {
    if (!repo_path || !entries) {
        return 0;
    }
    int parsed = pkgmap_walk_dir(repo_path, "", entries, 0, excluded_dirs, excluded_count);
    cbm_log_info("pkgmap.scan_repo", "manifests", pkgmap_itoa(parsed));
    return parsed;
}

/* Build pkgmap for sequential path (reads manifest files directly) */
CBMHashTable *cbm_pkgmap_build_from_files(const cbm_file_info_t *files, int file_count,
                                          const char *project_name) {
    cbm_pkg_entries_t entries;
    cbm_pkg_entries_init(&entries);

    for (int i = 0; i < file_count; i++) {
        const char *basename = path_basename(files[i].rel_path);
        if (!is_pkgmap_manifest_basename(basename)) {
            continue;
        }

        /* Read file */
        int source_len = 0;
        char *source = pkgmap_read_file(files[i].path, &source_len);
        if (!source) {
            continue;
        }
        cbm_pkgmap_try_parse(basename, files[i].rel_path, source, source_len, &entries);
        free(source);
    }

    CBMHashTable *map = cbm_pkgmap_build(&entries, SKIP_ONE, project_name);
    cbm_pkg_entries_free(&entries);
    return map;
}

/* Variant of cbm_pkgmap_build_from_files that ALSO walks the repo
 * filesystem to pick up manifests filtered out by the main discoverer
 * (the canonical case: package.json, which is in IGNORED_JSON_FILES).
 * Falls back to the files[]-only behaviour if repo_path is NULL. */
CBMHashTable *cbm_pkgmap_build_from_repo(const char *repo_path, const cbm_file_info_t *files,
                                         int file_count, const char *project_name,
                                         char **excluded_dirs, int excluded_count) {
    cbm_pkg_entries_t entries;
    cbm_pkg_entries_init(&entries);

    /* Manifests already visible through discovery (Cargo.toml, go.mod,
     * pyproject.toml, ...). package.json typically isn't, but we still
     * harvest whatever the discovery filter exposed in case downstream
     * filters change. */
    int from_files = 0;
    for (int i = 0; i < file_count; i++) {
        const char *basename = path_basename(files[i].rel_path);
        if (!is_pkgmap_manifest_basename(basename)) {
            continue;
        }
        from_files++;
        int source_len = 0;
        char *source = pkgmap_read_file(files[i].path, &source_len);
        if (!source) {
            continue;
        }
        cbm_pkgmap_try_parse(basename, files[i].rel_path, source, source_len, &entries);
        free(source);
    }

    int from_walk = cbm_pkgmap_scan_repo(repo_path, &entries, excluded_dirs, excluded_count);
    cbm_log_info("pkgmap.scan", "manifests_from_files", pkgmap_itoa(from_files),
                 "manifests_from_walk", pkgmap_itoa(from_walk), "entries",
                 pkgmap_itoa(entries.count));
    CBMHashTable *map = cbm_pkgmap_build(&entries, SKIP_ONE, project_name);
    cbm_pkg_entries_free(&entries);
    return map;
}

static void pkgmap_free_entry(const char *key, void *value, void *userdata) {
    (void)userdata;
    safe_str_free(&key);
    free(value);
}

void cbm_pkgmap_free(CBMHashTable *pkgmap) {
    if (!pkgmap) {
        return;
    }
    cbm_ht_foreach(pkgmap, pkgmap_free_entry, NULL);
    cbm_ht_free(pkgmap);
}

/* ── Resolver ──────────────────────────────────────────────────── */

/* Try slash-based prefix matching (Go: github.com/foo/bar/pkg/utils).
 * Returns heap QN or NULL. */
static char *resolve_slash_prefix(CBMHashTable *map, const char *module_path) {
    char *buf = strdup(module_path);
    if (!buf) {
        return NULL;
    }
    for (char *slash = buf + strlen(buf) - SKIP_ONE; slash > buf; slash--) {
        if (*slash != '/') {
            continue;
        }
        *slash = '\0';
        const char *base_qn = (const char *)cbm_ht_get(map, buf);
        if (!base_qn) {
            continue;
        }
        const char *subpath = module_path + (size_t)(slash - buf) + SKIP_ONE;
        char result[PKGMAP_PATH_BUF];
        snprintf(result, sizeof(result), "%s.%s", base_qn, subpath);
        /* Replace / with . in the appended part */
        for (char *c = result + strlen(base_qn) + SKIP_ONE; *c; c++) {
            if (*c == '/') {
                *c = '.';
            }
        }
        free(buf);
        return strdup(result);
    }
    free(buf);
    return NULL;
}

/* Try dot-based prefix matching (Java: com.myorg.pkg.Foo).
 * Returns heap QN or NULL. */
static char *resolve_dot_prefix(CBMHashTable *map, const char *module_path,
                                const char *project_name) {
    char *buf = strdup(module_path);
    if (!buf) {
        return NULL;
    }
    for (char *dot = buf + strlen(buf) - SKIP_ONE; dot > buf; dot--) {
        if (*dot != '.') {
            continue;
        }
        *dot = '\0';
        const char *base_qn = (const char *)cbm_ht_get(map, buf);
        if (!base_qn) {
            continue;
        }
        const char *subpath = module_path + (size_t)(dot - buf) + SKIP_ONE;
        char subpath_slashed[PKGMAP_PATH_BUF];
        snprintf(subpath_slashed, sizeof(subpath_slashed), "%s", subpath);
        for (char *c = subpath_slashed; *c; c++) {
            if (*c == '.') {
                *c = '/';
            }
        }
        char result[PKGMAP_PATH_BUF];
        snprintf(result, sizeof(result), "%s/%s", base_qn, subpath_slashed);
        free(buf);
        return cbm_pipeline_fqn_module(project_name, result);
    }
    free(buf);
    return NULL;
}

/* Try backslash-based prefix matching (PHP PSR-4: App\\Controllers\\Foo).
 * Returns heap QN or NULL. */
static char *resolve_backslash_prefix(CBMHashTable *map, const char *module_path,
                                      const char *project_name) {
    char *buf = strdup(module_path);
    if (!buf) {
        return NULL;
    }
    for (char *bs = buf + strlen(buf) - SKIP_ONE; bs > buf; bs--) {
        if (*bs != '\\') {
            continue;
        }
        *bs = '\0';
        char prefix[PKGMAP_PATH_BUF];
        snprintf(prefix, sizeof(prefix), "%s\\", buf);
        const char *base_dir = (const char *)cbm_ht_get(map, prefix);
        if (!base_dir) {
            continue;
        }
        const char *subpath = module_path + (size_t)(bs - buf) + SKIP_ONE;
        char path_result[PKGMAP_PATH_BUF];
        snprintf(path_result, sizeof(path_result), "%s/%s", base_dir, subpath);
        for (char *c = path_result; *c; c++) {
            if (*c == '\\') {
                *c = '/';
            }
        }
        free(buf);
        return cbm_pipeline_fqn_module(project_name, path_result);
    }
    free(buf);
    return NULL;
}

char *cbm_pipeline_resolve_module(const cbm_pipeline_ctx_t *ctx, const char *source_rel,
                                  const char *module_path) {
    if (!ctx || !module_path) {
        return cbm_pipeline_fqn_module(ctx ? ctx->project_name : NULL, module_path);
    }

    /* 1. Try relative import resolution (existing logic) */
    char *resolved = cbm_pipeline_resolve_relative_import(source_rel, module_path);
    if (resolved) {
        char *qn = cbm_pipeline_fqn_module(ctx->project_name, resolved);
        free(resolved);
        return qn;
    }

    /* 1b. Try build-tool path aliases (tsconfig/jsconfig paths today;
     *     other loaders can register here later). Independent of pkgmap. */
    if (ctx->path_aliases && source_rel) {
        const cbm_path_alias_map_t *amap =
            cbm_path_alias_find_for_file(ctx->path_aliases, source_rel);
        if (amap) {
            char *aliased = cbm_path_alias_resolve(amap, module_path);
            if (aliased) {
                char *qn = cbm_pipeline_fqn_module(ctx->project_name, aliased);
                free(aliased);
                return qn;
            }
        }
    }

    /* 2. No pkgmap → fall through immediately */
    CBMHashTable *pkgmap = cbm_pipeline_get_pkgmap();
    if (!pkgmap) {
        return cbm_pipeline_fqn_module(ctx->project_name, module_path);
    }

    /* 3. Exact lookup */
    const char *mapped_qn = (const char *)cbm_ht_get(pkgmap, module_path);
    if (mapped_qn) {
        return strdup(mapped_qn);
    }

    /* 4. Prefix matching by separator type */
    char *result = resolve_slash_prefix(pkgmap, module_path);
    if (!result) {
        result = resolve_dot_prefix(pkgmap, module_path, ctx->project_name);
    }
    if (!result) {
        result = resolve_backslash_prefix(pkgmap, module_path, ctx->project_name);
    }
    if (result) {
        return result;
    }

    /* 5. Fallthrough to default resolution */
    return cbm_pipeline_fqn_module(ctx->project_name, module_path);
}

/* ── Import-target node resolver ─────────────────────────────────── */

/* Return the last path segment of an import string, recognizing the separators
 * used across languages: '.', '/', '\\', and "::".  Returns a pointer into
 * `path` (no allocation). */
static const char *import_last_segment(const char *path) {
    const char *seg = path;
    for (const char *p = path; *p; p++) {
        if (*p == '.' || *p == '/' || *p == '\\' || *p == ':') {
            seg = p + SKIP_ONE;
        }
    }
    return seg;
}

static bool import_candidate_group_symbol(char *path, char *out, size_t out_size) {
    char *brace = strchr(path, '{');
    if (!brace) {
        return false;
    }
    char *first = brace + SKIP_ONE;
    char *end = first;
    while (*end && *end != ',' && *end != '}') {
        ++end;
    }
    *end = '\0';
    while (*first == ' ' || *first == '\t') {
        ++first;
    }
    char *trimmed_end = first + strlen(first);
    while (trimmed_end > first &&
           (trimmed_end[-SKIP_ONE] == ' ' || trimmed_end[-SKIP_ONE] == '\t')) {
        *--trimmed_end = '\0';
    }
    if (first[0] && strcmp(first, "self") != 0) {
        snprintf(out, out_size, "%s", first);
        return true;
    }
    *brace = '\0';
    return false;
}

static void import_candidate_strip_decorations(char *path) {
    char *alias = strstr(path, " as ");
    if (alias) {
        *alias = '\0';
    }
    size_t length = strlen(path);
    while (length > 0 && (path[length - SKIP_ONE] == '*' || path[length - SKIP_ONE] == ':' ||
                          path[length - SKIP_ONE] == '.' || path[length - SKIP_ONE] == '/' ||
                          path[length - SKIP_ONE] == '\\' || path[length - SKIP_ONE] == ' ')) {
        path[--length] = '\0';
    }
}

/* Derive a representative imported symbol name from a raw module/use path,
 * removing aliases, globs, and grouped-use decorations. */
static const char *import_candidate_symbol(const char *module_path, char *out, size_t outsz) {
    if (!module_path || !module_path[0]) {
        return NULL;
    }
    char buf[PKGMAP_IMPORT_PATH_BUF];
    snprintf(buf, sizeof(buf), "%s", module_path);
    if (import_candidate_group_symbol(buf, out, outsz)) {
        return out;
    }
    import_candidate_strip_decorations(buf);
    if (!buf[0]) {
        return NULL;
    }
    const char *seg = import_last_segment(buf);
    if (!seg || !seg[0] || strcmp(seg, "*") == 0) {
        return NULL;
    }
    snprintf(out, outsz, "%s", seg);
    return out;
}

/* True for node labels that represent an importable definition (so a symbol-name
 * fallback does not link to, e.g., a Variable or Field). */
static bool import_targetable_label(const char *label) {
    if (!label) {
        return false;
    }
    static const char *ok[] = {"Class", "Interface", "Function", "Method", "Module", "Struct",
                               "Enum",  "Trait",     "Type",     "File",   NULL};
    for (const char **l = ok; *l; l++) {
        if (strcmp(*l, label) == 0) {
            return true;
        }
    }
    return false;
}

static const char *path_leaf(const char *path) {
    const char *leaf = path;
    for (const char *p = path; p && *p; p++) {
        if (*p == '/' || *p == '\\') {
            leaf = p + SKIP_ONE;
        }
    }
    return leaf;
}

static bool is_header_include(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    static const char *header_exts[] = {".h", ".hh", ".hpp", ".hxx", ".inc", ".inl", ".ipp", NULL};
    for (const char **ext = header_exts; *ext; ext++) {
        size_t path_len = strlen(path);
        size_t ext_len = strlen(*ext);
        if (path_len > ext_len && strcmp(path + path_len - ext_len, *ext) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_c_family_source(const char *source_rel) {
    if (!source_rel || !source_rel[0]) {
        return false;
    }
    static const char *exts[] = {".c", ".cc", ".cpp", ".cxx", ".c++",
                                 ".h", ".hh", ".hpp", ".hxx", NULL};
    for (const char **ext = exts; *ext; ext++) {
        size_t path_len = strlen(source_rel);
        size_t ext_len = strlen(*ext);
        if (path_len > ext_len && strcmp(source_rel + path_len - ext_len, *ext) == 0) {
            return true;
        }
    }
    return false;
}

static bool resolve_exact_file_candidate_matches(const cbm_gbuf_node_t *candidate,
                                                 const char *file_path,
                                                 const char *source_file_qn) {
    if (!candidate || !candidate->file_path || !ends_with(candidate->file_path, file_path)) {
        return false;
    }
    if (!candidate->label || !import_targetable_label(candidate->label)) {
        return false;
    }
    return !source_file_qn || !candidate->qualified_name ||
           strcmp(candidate->qualified_name, source_file_qn) != 0;
}

static const cbm_gbuf_node_t *resolve_exact_file_name(const cbm_pipeline_ctx_t *ctx,
                                                      const char *name, const char *file_path,
                                                      const char *source_file_qn) {
    if (!name || !name[0]) {
        return NULL;
    }
    const cbm_gbuf_node_t **hits = NULL;
    int hit_count = 0;
    if (cbm_gbuf_find_by_name(ctx->gbuf, name, &hits, &hit_count) != 0 || !hits) {
        return NULL;
    }
    const cbm_gbuf_node_t *best = NULL;
    for (int index = 0; index < hit_count; ++index) {
        const cbm_gbuf_node_t *candidate = hits[index];
        if (!resolve_exact_file_candidate_matches(candidate, file_path, source_file_qn)) {
            continue;
        }
        if (strcmp(candidate->label, "File") == 0) {
            return candidate;
        }
        if (!best) {
            best = candidate;
        }
    }
    return best;
}

static const cbm_gbuf_node_t *resolve_exact_file_node(const cbm_pipeline_ctx_t *ctx,
                                                      const char *file_path,
                                                      const char *source_file_qn) {
    if (!ctx || !file_path || !file_path[0]) {
        return NULL;
    }

    const char *leaf = path_leaf(file_path);
    if (!leaf || !leaf[0]) {
        return NULL;
    }

    char stem[PKGMAP_PATH_BUF];
    snprintf(stem, sizeof(stem), "%s", leaf);
    char *last_dot = strrchr(stem, '.');
    if (last_dot && last_dot != stem) {
        *last_dot = '\0';
    }

    const char *names[PKGMAP_EXACT_FILE_NAME_CANDIDATES] = {stem[0] ? stem : NULL, leaf};
    for (int index = 0; index < PKGMAP_EXACT_FILE_NAME_CANDIDATES; ++index) {
        const cbm_gbuf_node_t *target =
            resolve_exact_file_name(ctx, names[index], file_path, source_file_qn);
        if (target) {
            return target;
        }
    }
    return NULL;
}

static const cbm_gbuf_node_t *resolve_header_include(const cbm_pipeline_ctx_t *ctx,
                                                     const char *source_rel,
                                                     const char *source_file_qn,
                                                     const char *module_path) {
    if (!is_c_family_source(source_rel) || !is_header_include(module_path)) {
        return NULL;
    }

    const char *base = module_path;
    if (base[0] == '.' && base[SKIP_ONE] == '/') {
        base += PKGMAP_RELATIVE_PREFIX_LEN;
    }

    const cbm_gbuf_node_t *exact = resolve_exact_file_node(ctx, base, source_file_qn);
    if (exact) {
        return exact;
    }

    if (source_rel && source_rel[0]) {
        char *dir = path_dirname(source_rel);
        if (dir) {
            char candidate[PKGMAP_PATH_BUF];
            if (dir[0]) {
                snprintf(candidate, sizeof(candidate), "%s/%s", dir, base);
            } else {
                snprintf(candidate, sizeof(candidate), "%s", base);
            }
            free(dir);
            exact = resolve_exact_file_node(ctx, candidate, source_file_qn);
            if (exact) {
                return exact;
            }
        }
    }

    return NULL;
}

typedef struct {
    char paths[PKGMAP_SIBLING_FILE_CANDIDATES][PKGMAP_PATH_BUF];
    int count;
} pkgmap_sibling_candidates_t;

static void pkgmap_sibling_add(pkgmap_sibling_candidates_t *candidates, const char *format,
                               const char *directory, const char *base) {
    if (candidates->count >= PKGMAP_SIBLING_FILE_CANDIDATES) {
        return;
    }
    snprintf(candidates->paths[candidates->count++], PKGMAP_PATH_BUF, format, directory,
             directory[0] ? "/" : "", base);
}

static void pkgmap_sibling_add_partial(pkgmap_sibling_candidates_t *candidates,
                                       const char *directory, const char *base) {
    const char *slash = strrchr(base, '/');
    const char *basename = slash ? slash + SKIP_ONE : base;
    char *path_prefix = slash ? cbm_strndup(base, (size_t)(slash - base)) : strdup("");
    if (path_prefix && basename[0] != '_' && candidates->count < PKGMAP_SIBLING_FILE_CANDIDATES) {
        snprintf(candidates->paths[candidates->count++], PKGMAP_PATH_BUF, "%s%s%s%s_%s.scss",
                 directory, directory[0] ? "/" : "", path_prefix[0] ? path_prefix : "",
                 path_prefix[0] ? "/" : "", basename);
    }
    free(path_prefix);
}

static void pkgmap_sibling_add_basename(pkgmap_sibling_candidates_t *candidates,
                                        const char *directory, const char *base) {
    const char *slash = strrchr(base, '/');
    if (!slash || !slash[SKIP_ONE]) {
        return;
    }
    pkgmap_sibling_add(candidates, "%s%s%s", directory, slash + SKIP_ONE);
}

static pkgmap_sibling_candidates_t pkgmap_sibling_candidates(const char *directory,
                                                             const char *module_path) {
    const char *base = module_path[0] == '.' && module_path[SKIP_ONE] == '/'
                           ? module_path + PKGMAP_RELATIVE_PREFIX_LEN
                           : module_path;
    pkgmap_sibling_candidates_t candidates = {0};
    pkgmap_sibling_add(&candidates, "%s%s%s", directory, base);
    pkgmap_sibling_add_partial(&candidates, directory, base);
    pkgmap_sibling_add(&candidates, "%s%s%s/meson.build", directory, base);
    pkgmap_sibling_add_basename(&candidates, directory, base);
    return candidates;
}

static const cbm_gbuf_node_t *pkgmap_find_sibling_candidate(
    const cbm_pipeline_ctx_t *ctx, const char *source_file_qn,
    const pkgmap_sibling_candidates_t *candidates) {
    for (int index = 0; index < candidates->count; ++index) {
        char *qualified_name = cbm_pipeline_fqn_module(ctx->project_name, candidates->paths[index]);
        const cbm_gbuf_node_t *node =
            qualified_name ? cbm_gbuf_find_by_qn(ctx->gbuf, qualified_name) : NULL;
        free(qualified_name);
        if (node && import_targetable_label(node->label) &&
            (!source_file_qn || !node->qualified_name ||
             strcmp(node->qualified_name, source_file_qn) != 0)) {
            return node;
        }
    }
    return NULL;
}

/* Resolve a sibling-file import through direct, SCSS partial, Meson, and basename
 * conventions relative to the importing file. */
static const cbm_gbuf_node_t *resolve_sibling_file(const cbm_pipeline_ctx_t *ctx,
                                                   const char *source_rel,
                                                   const char *source_file_qn,
                                                   const char *module_path) {
    if (!module_path || !module_path[0]) {
        return NULL;
    }
    /* Directory of the importing file (empty for repo-root files). */
    char *dir = path_dirname(source_rel ? source_rel : "");
    if (!dir) {
        return NULL;
    }
    pkgmap_sibling_candidates_t candidates = pkgmap_sibling_candidates(dir, module_path);
    const cbm_gbuf_node_t *found = pkgmap_find_sibling_candidate(ctx, source_file_qn, &candidates);
    free(dir);
    return found;
}

static const cbm_gbuf_node_t *resolve_import_initial(const cbm_pipeline_ctx_t *ctx,
                                                     const char *source_rel,
                                                     const char *source_file_qn,
                                                     const char *module_path) {
    const cbm_gbuf_node_t *header =
        resolve_header_include(ctx, source_rel, source_file_qn, module_path);
    if (header) {
        return header;
    }
    char *qualified_name = cbm_pipeline_resolve_module(ctx, source_rel, module_path);
    const cbm_gbuf_node_t *target =
        qualified_name ? cbm_gbuf_find_by_qn(ctx->gbuf, qualified_name) : NULL;
    free(qualified_name);
    return target ? target : resolve_sibling_file(ctx, source_rel, source_file_qn, module_path);
}

static void normalize_namespace_path(char *path) {
    char *brace = strchr(path, '{');
    if (brace) {
        *brace = '\0';
    }
    char *alias = strstr(path, " as ");
    if (alias) {
        *alias = '\0';
    }
    for (char *cursor = path; *cursor; ++cursor) {
        if (*cursor == '\\' || *cursor == ':' || *cursor == '/') {
            *cursor = '.';
        }
    }
    size_t length = strlen(path);
    while (length > 0 && (path[length - SKIP_ONE] == '*' || path[length - SKIP_ONE] == '.' ||
                          path[length - SKIP_ONE] == ' ')) {
        path[--length] = '\0';
    }
    for (char *repeated = strstr(path, ".."); repeated; repeated = strstr(path, "..")) {
        memmove(repeated, repeated + SKIP_ONE, strlen(repeated + SKIP_ONE) + SKIP_ONE);
    }
}

static const cbm_gbuf_node_t *namespace_map_find_nonself(const cbm_pipeline_ctx_t *ctx,
                                                         const char *source_file_qn,
                                                         const char *qualified_names) {
    for (const char *segment = qualified_names; segment && *segment;) {
        const char *line_end = strchr(segment, '\n');
        size_t length = line_end ? (size_t)(line_end - segment) : strlen(segment);
        if (length > 0 && length < PKGMAP_IMPORT_PATH_BUF) {
            char qualified_name[PKGMAP_IMPORT_PATH_BUF];
            memcpy(qualified_name, segment, length);
            qualified_name[length] = '\0';
            const cbm_gbuf_node_t *node = cbm_gbuf_find_by_qn(ctx->gbuf, qualified_name);
            if (node && (!source_file_qn || strcmp(node->qualified_name, source_file_qn) != 0)) {
                return node;
            }
        }
        segment = line_end ? line_end + SKIP_ONE : NULL;
    }
    return NULL;
}

static const cbm_gbuf_node_t *resolve_namespace_import(const cbm_pipeline_ctx_t *ctx,
                                                       const char *source_file_qn,
                                                       const char *module_path,
                                                       CBMHashTable *namespace_map) {
    if (!namespace_map) {
        return NULL;
    }
    char normalized[PKGMAP_IMPORT_PATH_BUF];
    snprintf(normalized, sizeof(normalized), "%s", module_path);
    normalize_namespace_path(normalized);
    for (;;) {
        const char *qualified_names = (const char *)cbm_ht_get(namespace_map, normalized);
        const cbm_gbuf_node_t *target =
            namespace_map_find_nonself(ctx, source_file_qn, qualified_names);
        if (target) {
            return target;
        }
        char *dot = strrchr(normalized, '.');
        if (!dot) {
            return NULL;
        }
        *dot = '\0';
    }
}

typedef struct {
    char path[PKGMAP_IMPORT_PATH_BUF];
    char symbol[PKGMAP_IMPORT_SYMBOL_BUF];
    const char *names[PKGMAP_IMPORT_SYMBOL_CANDIDATES];
    int count;
} pkgmap_symbol_candidates_t;

static void pkgmap_symbol_candidate_add(pkgmap_symbol_candidates_t *candidates, const char *name) {
    if (!name || !name[0] || strcmp(name, "*") == 0 ||
        candidates->count >= PKGMAP_IMPORT_SYMBOL_CANDIDATES) {
        return;
    }
    for (int index = 0; index < candidates->count; ++index) {
        if (strcmp(candidates->names[index], name) == 0) {
            return;
        }
    }
    candidates->names[candidates->count++] = name;
}

static pkgmap_symbol_candidates_t pkgmap_symbol_candidates_build(const CBMImport *imported) {
    pkgmap_symbol_candidates_t candidates = {0};
    const char *symbol = import_candidate_symbol(imported->module_path, candidates.symbol,
                                                 sizeof(candidates.symbol));
    pkgmap_symbol_candidate_add(&candidates, symbol);
    if (!symbol) {
        pkgmap_symbol_candidate_add(&candidates, imported->local_name);
    }
    snprintf(candidates.path, sizeof(candidates.path), "%s", imported->module_path);
    normalize_namespace_path(candidates.path);
    for (char *end = candidates.path + strlen(candidates.path); end > candidates.path;) {
        char *dot = strrchr(candidates.path, '.');
        pkgmap_symbol_candidate_add(&candidates, dot ? dot + SKIP_ONE : candidates.path);
        if (!dot) {
            break;
        }
        *dot = '\0';
        end = dot;
    }
    return candidates;
}

static const cbm_gbuf_node_t *pkgmap_find_named_import_target(const cbm_pipeline_ctx_t *ctx,
                                                              const char *source_file_qn,
                                                              const char *name) {
    const cbm_gbuf_node_t **hits = NULL;
    int count = 0;
    if (cbm_gbuf_find_by_name(ctx->gbuf, name, &hits, &count) != 0 || !hits) {
        return NULL;
    }
    const cbm_gbuf_node_t *best = NULL;
    for (int index = 0; index < count; ++index) {
        const cbm_gbuf_node_t *candidate = hits[index];
        if (!candidate || !import_targetable_label(candidate->label) ||
            (source_file_qn && candidate->qualified_name &&
             strcmp(candidate->qualified_name, source_file_qn) == 0)) {
            continue;
        }
        if (!best || (candidate->qualified_name && best->qualified_name &&
                      strcmp(candidate->qualified_name, best->qualified_name) < 0)) {
            best = candidate;
        }
    }
    return best;
}

static const cbm_gbuf_node_t *resolve_symbol_import(const cbm_pipeline_ctx_t *ctx,
                                                    const char *source_file_qn,
                                                    const CBMImport *imported) {
    pkgmap_symbol_candidates_t candidates = pkgmap_symbol_candidates_build(imported);
    for (int index = 0; index < candidates.count; ++index) {
        const cbm_gbuf_node_t *target =
            pkgmap_find_named_import_target(ctx, source_file_qn, candidates.names[index]);
        if (target) {
            return target;
        }
    }
    return NULL;
}

static void pkgmap_crate_path_strip_prefix(char *path) {
    static const char *const prefixes[] = {"crate/", "self/", "super/", NULL};
    for (const char *const *prefix = prefixes; *prefix; ++prefix) {
        size_t length = strlen(*prefix);
        if (strlen(path) >= length && strncmp(path, *prefix, length) == 0) {
            memmove(path, path + length, strlen(path + length) + SKIP_ONE);
            return;
        }
    }
}

static void normalize_crate_path(char *output, size_t output_size, const char *module_path) {
    if (output_size == 0) {
        return;
    }
    output[0] = '\0';
    char path[PKGMAP_IMPORT_PATH_BUF];
    snprintf(path, sizeof(path), "%s", module_path);
    normalize_namespace_path(path);
    size_t output_length = 0;
    for (const char *cursor = path; *cursor && output_length + SKIP_ONE < output_size; ++cursor) {
        if (*cursor == '.') {
            output[output_length++] = '/';
        } else {
            output[output_length++] = *cursor;
        }
    }
    output[output_length] = '\0';
}

static const cbm_gbuf_node_t *resolve_crate_import(const cbm_pipeline_ctx_t *ctx,
                                                   const char *source_rel,
                                                   const char *source_file_qn,
                                                   const char *module_path) {
    char normalized[PKGMAP_IMPORT_PATH_BUF];
    normalize_crate_path(normalized, sizeof(normalized), module_path);
    pkgmap_crate_path_strip_prefix(normalized);
    if (!normalized[0]) {
        return NULL;
    }
    char work[PKGMAP_IMPORT_PATH_BUF];
    snprintf(work, sizeof(work), "%s", normalized);
    for (;;) {
        char *qualified_name = cbm_pipeline_resolve_module(ctx, source_rel, work);
        const cbm_gbuf_node_t *target =
            qualified_name ? cbm_gbuf_find_by_qn(ctx->gbuf, qualified_name) : NULL;
        free(qualified_name);
        if (target && import_targetable_label(target->label) &&
            (!source_file_qn || !target->qualified_name ||
             strcmp(target->qualified_name, source_file_qn) != 0)) {
            return target;
        }
        char *slash = strrchr(work, '/');
        if (!slash) {
            return NULL;
        }
        *slash = '\0';
    }
}

const cbm_gbuf_node_t *cbm_pipeline_resolve_import_node(const cbm_pipeline_ctx_t *ctx,
                                                        const char *source_rel,
                                                        const char *source_file_qn,
                                                        const CBMImport *imp,
                                                        CBMHashTable *namespace_map) {
    if (!ctx || !imp || !imp->module_path) {
        return NULL;
    }
    const cbm_gbuf_node_t *target =
        resolve_import_initial(ctx, source_rel, source_file_qn, imp->module_path);
    if (target) {
        return target;
    }
    target = resolve_namespace_import(ctx, source_file_qn, imp->module_path, namespace_map);
    if (target) {
        return target;
    }
    target = resolve_symbol_import(ctx, source_file_qn, imp);
    return target ? target
                  : resolve_crate_import(ctx, source_rel, source_file_qn, imp->module_path);
}

/* ── Namespace map ───────────────────────────────────────────────── */

static void pkgmap_normalize_namespace_key(char *key) {
    for (char *cursor = key; *cursor; ++cursor) {
        if (*cursor == '\\' || *cursor == ':' || *cursor == '/') {
            *cursor = '.';
        }
    }
}

static void pkgmap_namespace_map_append(CBMHashTable *map, const char *key, char *file_qn) {
    const char *stored_key = cbm_ht_get_key(map, key);
    const char *current = (const char *)cbm_ht_get(map, key);
    if (!stored_key || !current) {
        free(file_qn);
        return;
    }
    size_t size = strlen(current) + SKIP_ONE + strlen(file_qn) + SKIP_ONE;
    char *combined = malloc(size);
    if (combined) {
        snprintf(combined, size, "%s\n%s", current, file_qn);
        void *previous = cbm_ht_set(map, stored_key, combined);
        free(previous);
    }
    free(file_qn);
}

static void pkgmap_namespace_map_add(CBMHashTable *map, const char *project_name,
                                     const CBMFileResult *result, const char *relative_path) {
    char *file_qn = cbm_pipeline_fqn_compute(project_name, relative_path, "__file__");
    char *key = strdup(result->namespace_name);
    if (!file_qn || !key) {
        free(file_qn);
        free(key);
        return;
    }
    pkgmap_normalize_namespace_key(key);
    if (!cbm_ht_has(map, key)) {
        cbm_ht_set(map, key, file_qn);
        return;
    }
    pkgmap_namespace_map_append(map, key, file_qn);
    free(key);
}

CBMHashTable *cbm_pipeline_namespace_map_build(const char *project_name,
                                               CBMFileResult *const *results,
                                               const char *const *rels, int count) {
    CBMHashTable *map = NULL;
    for (int index = 0; index < count; ++index) {
        const CBMFileResult *result = results[index];
        if (!result || !result->namespace_name || !result->namespace_name[0] || !rels[index]) {
            continue;
        }
        if (!map) {
            map = cbm_ht_create(CBM_SZ_64);
            if (!map) {
                return NULL;
            }
        }
        pkgmap_namespace_map_add(map, project_name, result, rels[index]);
    }
    return map;
}

static void ns_map_free_entry(const char *key, void *value, void *ud) {
    (void)ud;
    safe_str_free(&key); /* strdup'd in cbm_pipeline_namespace_map_build */
    free(value);
}

void cbm_pipeline_namespace_map_free(CBMHashTable *map) {
    if (!map) {
        return;
    }
    cbm_ht_foreach(map, ns_map_free_entry, NULL);
    cbm_ht_free(map);
}
