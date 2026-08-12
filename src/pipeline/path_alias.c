/*
 * path_alias.c — Resolve build-tool path aliases.
 *
 * Builds a directory-scoped collection of alias maps from per-language
 * config files (currently tsconfig.json / jsconfig.json) so the import
 * resolver can turn "@/lib/auth"-style imports into repo-relative paths.
 *
 * Design notes:
 *   - Public types and functions are language-agnostic. Adding a Vite /
 *     Webpack / Python loader means writing a new load_*_file() helper
 *     and registering it in find_alias_files. The resolver, the
 *     collection, and the pipeline integration do not change.
 *   - Sorting uses qsort (n log n). The bubble-sorts that the original
 *     Layer 1b draft used were O(n^2); with up to 256 alias entries
 *     and 256 scoped maps per repo, qsort is the right ceiling.
 *   - The repo walk caps recursion depth and total file count and emits
 *     a warning when either cap fires, so silent truncation on
 *     pathological monorepos shows up in the index log.
 */

#include "pipeline/path_alias.h"

#include "pipeline/pipeline_internal.h"

#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/log.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson/yyjson.h>

/* Resource ceilings. Chosen to comfortably cover real-world monorepos
 * (Next.js Skyline, large nx workspaces) while bounding worst-case
 * memory and walk time. Cap hits are logged. */
enum {
    CBM_PATH_ALIAS_MAX_ENTRIES = 256, /* per single config file       */
    CBM_PATH_ALIAS_MAX_FILES = 256,   /* config files per repo walk   */
    CBM_PATH_ALIAS_MAX_FILE_BYTES = 64 * 1024,
    CBM_PATH_ALIAS_MAX_DEPTH = 32, /* directory recursion depth    */
    CBM_PATH_ALIAS_TS_EXTENSION_WIDTH = 3,
    CBM_PATH_ALIAS_TSX_EXTENSION_WIDTH = 4,
    CBM_PATH_ALIAS_TS_DOT_OFFSET = 3,
    CBM_PATH_ALIAS_TS_LANGUAGE_OFFSET = 2,
    CBM_PATH_ALIAS_TS_SUFFIX_OFFSET = 1,
    CBM_PATH_ALIAS_TSX_DOT_OFFSET = 4,
    CBM_PATH_ALIAS_TSX_LANGUAGE_OFFSET = 3,
    CBM_PATH_ALIAS_TSX_SUFFIX_OFFSET = 2,
    CBM_PATH_ALIAS_TSX_VARIANT_OFFSET = 1,
    CBM_PATH_ALIAS_PATH_JOIN_EXTRA_BYTES = 2,
    CBM_PATH_ALIAS_FINAL_CHAR_OFFSET = 1,
    CBM_PATH_ALIAS_DOT_SEGMENT_LENGTH = 1,
    CBM_PATH_ALIAS_PARENT_SEGMENT_LENGTH = 2,
    CBM_PATH_ALIAS_PARENT_SEGMENT_DOT_OFFSET = 1,
    CBM_PATH_ALIAS_STRING_TERMINATOR_BYTES = 1,
    CBM_PATH_ALIAS_COMPARE_GREATER = 1,
    CBM_PATH_ALIAS_COMPARE_LESS = -1,
    CBM_PATH_ALIAS_SINGLE_READ_BLOCK = 1,
    CBM_PATH_ALIAS_SINGLE_OBJECT = 1,
    CBM_PATH_ALIAS_WILDCARD_WIDTH = 1,
    CBM_PATH_ALIAS_DEPTH_STEP = 1,
    CBM_PATH_ALIAS_PATH_SEPARATOR_BYTES = 1,
    CBM_PATH_ALIAS_STACK_TOP_OFFSET = 1,
};

/* ── Helpers ───────────────────────────────────────────────────── */

/* Strip .ts/.tsx/.js/.jsx in place. Returns its argument. */
static char *strip_resolved_ext(char *path) {
    if (!path) {
        return path;
    }
    size_t len = strlen(path);
    if (len > CBM_PATH_ALIAS_TS_EXTENSION_WIDTH &&
        path[len - CBM_PATH_ALIAS_TS_DOT_OFFSET] == '.' &&
        (path[len - CBM_PATH_ALIAS_TS_LANGUAGE_OFFSET] == 't' ||
         path[len - CBM_PATH_ALIAS_TS_LANGUAGE_OFFSET] == 'j') &&
        path[len - CBM_PATH_ALIAS_TS_SUFFIX_OFFSET] == 's') {
        path[len - CBM_PATH_ALIAS_TS_DOT_OFFSET] = '\0';
        return path;
    }
    if (len > CBM_PATH_ALIAS_TSX_EXTENSION_WIDTH &&
        path[len - CBM_PATH_ALIAS_TSX_DOT_OFFSET] == '.' &&
        (path[len - CBM_PATH_ALIAS_TSX_LANGUAGE_OFFSET] == 't' ||
         path[len - CBM_PATH_ALIAS_TSX_LANGUAGE_OFFSET] == 'j') &&
        path[len - CBM_PATH_ALIAS_TSX_SUFFIX_OFFSET] == 's' &&
        path[len - CBM_PATH_ALIAS_TSX_VARIANT_OFFSET] == 'x') {
        path[len - CBM_PATH_ALIAS_TSX_DOT_OFFSET] = '\0';
    }
    return path;
}

/* Join dir_prefix with target, collapsing "." and ".." segments so aliases
 * that climb out of their tsconfig's directory (the common monorepo
 * pattern: a tsconfig at apps/web/tsconfig.json pointing an alias at a
 * wildcard target like "../../packages/shared/src/" + wildcard) resolve
 * to a real repo-relative path. Naive concatenation left literal ".."
 * components in the target, which never match a module's FQN since
 * cbm_pipeline_fqn_module tokenizes on '/' without collapsing them
 * (#730). A trailing '/' on target (the usual case right before a
 * wildcard) is preserved so the caller's later wildcard-substring
 * concat still lines up. Returns heap-allocated
 * repo-relative target. */
static bool is_current_path_segment(const char *segment, size_t length) {
    return length == CBM_PATH_ALIAS_DOT_SEGMENT_LENGTH && segment[0] == '.';
}

static bool is_parent_path_segment(const char *segment, size_t length) {
    return length == CBM_PATH_ALIAS_PARENT_SEGMENT_LENGTH && segment[0] == '.' &&
           segment[CBM_PATH_ALIAS_PARENT_SEGMENT_DOT_OFFSET] == '.';
}

static void remove_last_path_segment(char *path) {
    char *last_separator = strrchr(path, '/');
    if (last_separator) {
        *last_separator = '\0';
        return;
    }
    path[0] = '\0';
}

static void append_path_segment(char *path, const char *segment, size_t length) {
    size_t current_length = strlen(path);
    if (current_length > 0) {
        path[current_length++] = '/';
    }
    memcpy(path + current_length, segment, length);
    path[current_length + length] = '\0';
}

static void append_normalized_path_segment(char *path, const char *segment, size_t length) {
    if (is_current_path_segment(segment, length)) {
        return;
    }
    if (is_parent_path_segment(segment, length)) {
        remove_last_path_segment(path);
        return;
    }
    append_path_segment(path, segment, length);
}

static char *resolve_target_relative(const char *dir_prefix, const char *target) {
    if (!target) {
        return NULL;
    }
    size_t dp_len = (dir_prefix && dir_prefix[0] != '\0') ? strlen(dir_prefix) : 0;
    size_t t_len = strlen(target);
    char *buf = malloc(dp_len + t_len + CBM_PATH_ALIAS_PATH_JOIN_EXTRA_BYTES);
    if (!buf) {
        return NULL;
    }
    buf[0] = '\0';
    if (dp_len > 0) {
        memcpy(buf, dir_prefix, dp_len);
        buf[dp_len] = '\0';
    }

    bool trailing_slash = t_len > 0 && target[t_len - CBM_PATH_ALIAS_FINAL_CHAR_OFFSET] == '/';

    const char *p = target;
    while (*p) {
        while (*p == '/') {
            p++;
        }
        if (!*p) {
            break;
        }
        const char *seg_start = p;
        while (*p && *p != '/') {
            p++;
        }
        size_t seg_len = (size_t)(p - seg_start);
        append_normalized_path_segment(buf, seg_start, seg_len);
    }

    if (trailing_slash) {
        size_t cur = strlen(buf);
        buf[cur] = '/';
        buf[cur + CBM_PATH_ALIAS_STRING_TERMINATOR_BYTES] = '\0';
    }
    return buf;
}

/* qsort comparator: alias entries by alias_prefix length, descending. */
static int cmp_alias_entry_by_specificity(const void *a, const void *b) {
    const cbm_path_alias_t *ea = a;
    const cbm_path_alias_t *eb = b;
    size_t la = strlen(ea->alias_prefix);
    size_t lb = strlen(eb->alias_prefix);
    if (lb > la) {
        return CBM_PATH_ALIAS_COMPARE_GREATER;
    }
    if (lb < la) {
        return CBM_PATH_ALIAS_COMPARE_LESS;
    }
    return 0;
}

/* qsort comparator: scopes by dir_prefix length, descending. */
static int cmp_scope_by_specificity(const void *a, const void *b) {
    const cbm_path_alias_scope_t *sa = a;
    const cbm_path_alias_scope_t *sb = b;
    size_t la = strlen(sa->dir_prefix);
    size_t lb = strlen(sb->dir_prefix);
    if (lb > la) {
        return CBM_PATH_ALIAS_COMPARE_GREATER;
    }
    if (lb < la) {
        return CBM_PATH_ALIAS_COMPARE_LESS;
    }
    return 0;
}

/* ── tsconfig.json / jsconfig.json loader ──────────────────────── */

static void free_alias_map(cbm_path_alias_map_t *map);

static bool config_file_size(FILE *file, size_t *size) {
    if (fseek(file, 0, SEEK_END) != 0) {
        return false;
    }
    long length = ftell(file);
    if (length <= 0 || length > CBM_PATH_ALIAS_MAX_FILE_BYTES) {
        return false;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        return false;
    }
    *size = (size_t)length;
    return true;
}

static char *read_config_file(const char *abs_path, size_t *size) {
    FILE *file = cbm_fopen(abs_path, "r");
    if (!file) {
        return NULL;
    }

    size_t file_size = 0;
    bool valid_size = config_file_size(file, &file_size);
    char *buffer = valid_size ? malloc(file_size + CBM_PATH_ALIAS_STRING_TERMINATOR_BYTES) : NULL;
    size_t bytes_read = 0;
    if (buffer) {
        bytes_read = fread(buffer, CBM_PATH_ALIAS_SINGLE_READ_BLOCK, file_size, file);
    }
    bool closed = fclose(file) == 0;
    if (!buffer || bytes_read != file_size || !closed) {
        free(buffer);
        return NULL;
    }
    buffer[bytes_read] = '\0';
    *size = bytes_read;
    return buffer;
}

static yyjson_doc *read_alias_config_document(const char *abs_path) {
    size_t length = 0;
    char *buffer = read_config_file(abs_path, &length);
    if (!buffer) {
        return NULL;
    }
    yyjson_read_flag flags = YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_TRAILING_COMMAS;
    yyjson_doc *document = yyjson_read(buffer, length, flags);
    free(buffer);
    return document;
}

static void set_alias_base_url(cbm_path_alias_map_t *map, const char *base_url,
                               const char *dir_prefix) {
    if (!base_url || base_url[0] == '\0') {
        return;
    }
    if (strcmp(base_url, ".") == 0) {
        if (dir_prefix && dir_prefix[0] != '\0') {
            map->base_url = strdup(dir_prefix);
        }
        return;
    }
    map->base_url = resolve_target_relative(dir_prefix, base_url);
}

static void set_alias_pattern(char **prefix, char **suffix, const char *pattern,
                              const char *wildcard) {
    if (wildcard) {
        *prefix = cbm_strndup(pattern, (size_t)(wildcard - pattern));
        *suffix = strdup(wildcard + CBM_PATH_ALIAS_WILDCARD_WIDTH);
        return;
    }
    *prefix = strdup(pattern);
    *suffix = strdup("");
}

static void set_path_alias_entry(cbm_path_alias_t *entry, const char *alias_pattern,
                                 const char *target_pattern, const char *dir_prefix) {
    const char *alias_wildcard = strchr(alias_pattern, '*');
    entry->has_wildcard = alias_wildcard != NULL;
    set_alias_pattern(&entry->alias_prefix, &entry->alias_suffix, alias_pattern, alias_wildcard);

    const char *target_wildcard = strchr(target_pattern, '*');
    char *target_prefix =
        cbm_strndup(target_pattern, target_wildcard ? (size_t)(target_wildcard - target_pattern)
                                                    : strlen(target_pattern));
    entry->target_prefix = resolve_target_relative(dir_prefix, target_prefix);
    free(target_prefix);
    entry->target_suffix =
        strdup(target_wildcard ? target_wildcard + CBM_PATH_ALIAS_WILDCARD_WIDTH : "");
}

static bool load_path_alias_entries(cbm_path_alias_map_t *map, yyjson_val *paths,
                                    const char *abs_path, const char *dir_prefix) {
    if (!paths || !yyjson_is_obj(paths)) {
        return true;
    }

    size_t object_size = yyjson_obj_size(paths);
    bool capped = object_size > CBM_PATH_ALIAS_MAX_ENTRIES;
    int capacity = (int)(capped ? (size_t)CBM_PATH_ALIAS_MAX_ENTRIES : object_size);
    if (capacity == 0) {
        return true;
    }

    map->entries = calloc((size_t)capacity, sizeof(cbm_path_alias_t));
    if (!map->entries) {
        return false;
    }

    yyjson_val *key;
    yyjson_obj_iter iterator = yyjson_obj_iter_with(paths);
    while ((key = yyjson_obj_iter_next(&iterator)) != NULL && map->count < capacity) {
        yyjson_val *value = yyjson_obj_iter_get_val(key);
        const char *alias_pattern = yyjson_get_str(key);
        const char *target_pattern = yyjson_is_arr(value) && yyjson_arr_size(value) > 0
                                         ? yyjson_get_str(yyjson_arr_get_first(value))
                                         : NULL;
        if (!alias_pattern || !target_pattern) {
            continue;
        }
        set_path_alias_entry(&map->entries[map->count], alias_pattern, target_pattern, dir_prefix);
        map->count++;
    }
    if (capped) {
        cbm_log_warn("path_alias.entries.cap_hit", "config", abs_path, "kept", "256_of_more");
    }
    qsort(map->entries, (size_t)map->count, sizeof(cbm_path_alias_t),
          cmp_alias_entry_by_specificity);
    return true;
}

/* Parse compilerOptions.paths and compilerOptions.baseUrl into an alias map.
 * dir_prefix is the directory of the config file relative to the repo root
 * (e.g. "apps/manager", or "" for repo root). Returns NULL if the file is
 * missing, malformed, or has neither a usable paths block nor a baseUrl. */
static cbm_path_alias_map_t *load_tsconfig_file(const char *abs_path, const char *dir_prefix) {
    yyjson_doc *doc = read_alias_config_document(abs_path);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *compiler_opts = yyjson_obj_get(root, "compilerOptions");
    if (!compiler_opts) {
        yyjson_doc_free(doc);
        return NULL;
    }
    yyjson_val *base_url_val = yyjson_obj_get(compiler_opts, "baseUrl");
    const char *base_url_str = base_url_val ? yyjson_get_str(base_url_val) : NULL;
    yyjson_val *paths_obj = yyjson_obj_get(compiler_opts, "paths");
    if (!paths_obj && !base_url_str) {
        yyjson_doc_free(doc);
        return NULL;
    }

    cbm_path_alias_map_t *map = calloc(CBM_PATH_ALIAS_SINGLE_OBJECT, sizeof(*map));
    if (!map) {
        yyjson_doc_free(doc);
        return NULL;
    }

    set_alias_base_url(map, base_url_str, dir_prefix);
    bool entries_loaded = load_path_alias_entries(map, paths_obj, abs_path, dir_prefix);
    yyjson_doc_free(doc);
    if (!entries_loaded) {
        free_alias_map(map);
        return NULL;
    }
    return map;
}

/* ── Public API ────────────────────────────────────────────────── */

static void free_alias_map(cbm_path_alias_map_t *map) {
    if (!map) {
        return;
    }
    for (int j = 0; j < map->count; j++) {
        free(map->entries[j].alias_prefix);
        free(map->entries[j].alias_suffix);
        free(map->entries[j].target_prefix);
        free(map->entries[j].target_suffix);
    }
    free(map->entries);
    free(map->base_url);
    free(map);
}

void cbm_path_alias_collection_free(cbm_path_alias_collection_t *coll) {
    if (!coll) {
        return;
    }
    for (int i = 0; i < coll->count; i++) {
        free(coll->scopes[i].dir_prefix);
        free(coll->scopes[i].source_rel_path);
        free_alias_map(coll->scopes[i].map);
    }
    free(coll->scopes);
    free(coll);
}

static bool wildcard_alias_matches(const cbm_path_alias_t *entry, const char *module_path,
                                   size_t module_length) {
    size_t prefix_length = strlen(entry->alias_prefix);
    size_t suffix_length = strlen(entry->alias_suffix);
    if (module_length < prefix_length + suffix_length) {
        return false;
    }
    if (strncmp(module_path, entry->alias_prefix, prefix_length) != 0) {
        return false;
    }
    return suffix_length == 0 ||
           strcmp(module_path + module_length - suffix_length, entry->alias_suffix) == 0;
}

static char *resolve_wildcard_alias(const cbm_path_alias_t *entry, const char *module_path,
                                    size_t module_length) {
    size_t prefix_length = strlen(entry->alias_prefix);
    size_t suffix_length = strlen(entry->alias_suffix);
    size_t wildcard_length = module_length - prefix_length - suffix_length;
    size_t target_prefix_length = strlen(entry->target_prefix);
    size_t target_suffix_length = strlen(entry->target_suffix);
    char *result = malloc(target_prefix_length + wildcard_length + target_suffix_length +
                          CBM_PATH_ALIAS_STRING_TERMINATOR_BYTES);
    if (!result) {
        return NULL;
    }
    memcpy(result, entry->target_prefix, target_prefix_length);
    memcpy(result + target_prefix_length, module_path + prefix_length, wildcard_length);
    memcpy(result + target_prefix_length + wildcard_length, entry->target_suffix,
           target_suffix_length);
    result[target_prefix_length + wildcard_length + target_suffix_length] = '\0';
    return strip_resolved_ext(result);
}

static char *resolve_alias_entry(const cbm_path_alias_t *entry, const char *module_path,
                                 size_t module_length) {
    if (!entry->has_wildcard) {
        return strcmp(module_path, entry->alias_prefix) == 0
                   ? strip_resolved_ext(strdup(entry->target_prefix))
                   : NULL;
    }
    if (!wildcard_alias_matches(entry, module_path, module_length)) {
        return NULL;
    }
    return resolve_wildcard_alias(entry, module_path, module_length);
}

char *cbm_path_alias_resolve(const cbm_path_alias_map_t *map, const char *module_path) {
    if (!map || !module_path) {
        return NULL;
    }
    size_t mod_len = strlen(module_path);

    for (int i = 0; i < map->count; i++) {
        const cbm_path_alias_t *entry = &map->entries[i];
        char *resolved = resolve_alias_entry(entry, module_path, mod_len);
        if (resolved) {
            return resolved;
        }
    }

    /* baseUrl fallback. Apply only to non-relative imports that look
     * sub-path-ish (contain '/' but don't start with '.' or '@'); skips
     * obvious package names like "react" or "lodash". */
    if (map->base_url && module_path[0] != '.' && module_path[0] != '@' &&
        strchr(module_path, '/') != NULL) {
        size_t bu_len = strlen(map->base_url);
        size_t need = bu_len + CBM_PATH_ALIAS_PATH_SEPARATOR_BYTES + mod_len +
                      CBM_PATH_ALIAS_STRING_TERMINATOR_BYTES;
        char *result = malloc(need);
        if (!result) {
            return NULL;
        }
        snprintf(result, need, "%s/%s", map->base_url, module_path);
        return strip_resolved_ext(result);
    }
    return NULL;
}

/* ── Repo walk ─────────────────────────────────────────────────── */

typedef struct {
    char abs[CBM_SZ_512];
    char rel[CBM_SZ_256];
} alias_config_hit_t;

typedef struct {
    cbm_dir_t *directory;
    char abs[CBM_SZ_512];
    char rel[CBM_SZ_256];
    int depth;
} alias_walk_frame_t;

static const char *const TS_CONFIG_NAMES[] = {"tsconfig.json", "jsconfig.json"};
enum { TS_CONFIG_NAMES_COUNT = 2 };

static const char *const ignored_alias_directories[] = {
    "node_modules", "dist", "build", ".next", "coverage", "target",
};

static bool directory_is_ignored_for_aliases(const char *name) {
    if (name[0] == '.') {
        return true;
    }
    for (size_t i = 0; i < sizeof(ignored_alias_directories) / sizeof(*ignored_alias_directories);
         i++) {
        if (strcmp(name, ignored_alias_directories[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void find_alias_config_in_directory(const char *abs_dir, const char *rel_dir,
                                           alias_config_hit_t *out, int *count, int max_count) {
    /* One config file per directory: prefer tsconfig.json over jsconfig.json. */
    for (int i = 0; i < TS_CONFIG_NAMES_COUNT && *count < max_count; i++) {
        char check[CBM_SZ_512];
        snprintf(check, sizeof(check), "%s/%s", abs_dir, TS_CONFIG_NAMES[i]);
        FILE *file = cbm_fopen(check, "r");
        if (!file) {
            continue;
        }
        bool closed = fclose(file) == 0;
        if (!closed) {
            continue;
        }
        snprintf(out[*count].abs, sizeof(out[*count].abs), "%s", check);
        snprintf(out[*count].rel, sizeof(out[*count].rel), "%s", rel_dir);
        (*count)++;
        return;
    }
}

static bool open_alias_walk_frame(alias_walk_frame_t *frame, const char *abs_dir,
                                  const char *rel_dir, int depth, alias_config_hit_t *out,
                                  int *count, int max_count) {
    cbm_dir_t *directory = cbm_opendir(abs_dir);
    if (!directory) {
        return false;
    }
    frame->directory = directory;
    snprintf(frame->abs, sizeof(frame->abs), "%s", abs_dir);
    snprintf(frame->rel, sizeof(frame->rel), "%s", rel_dir);
    frame->depth = depth;
    find_alias_config_in_directory(frame->abs, frame->rel, out, count, max_count);
    return true;
}

static void create_alias_child_path(const alias_walk_frame_t *parent, const char *name,
                                    char *child_abs, char *child_rel) {
    snprintf(child_abs, CBM_SZ_512, "%s/%s", parent->abs, name);
    if (parent->rel[0] == '\0') {
        snprintf(child_rel, CBM_SZ_256, "%s", name);
        return;
    }
    snprintf(child_rel, CBM_SZ_256, "%s/%s", parent->rel, name);
}

static void close_alias_walk_frames(alias_walk_frame_t *frames, int frame_count) {
    for (int i = 0; i < frame_count; i++) {
        cbm_closedir(frames[i].directory);
    }
}

static void find_alias_files(const char *abs_dir, const char *rel_dir, alias_config_hit_t *out,
                             int *count, int max_count, char **excluded_dirs, int excluded_count) {
    enum { CBM_PATH_ALIAS_WALK_FRAME_CAPACITY = CBM_PATH_ALIAS_MAX_DEPTH + 1 };
    alias_walk_frame_t frames[CBM_PATH_ALIAS_WALK_FRAME_CAPACITY];
    int frame_count = 0;
    if (!open_alias_walk_frame(&frames[frame_count], abs_dir, rel_dir, 0, out, count, max_count)) {
        return;
    }
    frame_count++;

    while (frame_count > 0 && *count < max_count) {
        alias_walk_frame_t *frame = &frames[frame_count - CBM_PATH_ALIAS_STACK_TOP_OFFSET];
        cbm_dirent_t *entry = cbm_readdir(frame->directory);
        if (!entry) {
            cbm_closedir(frame->directory);
            frame_count--;
            continue;
        }
        if (!entry->is_dir || directory_is_ignored_for_aliases(entry->name)) {
            continue;
        }
        char child_abs[CBM_SZ_512];
        char child_rel[CBM_SZ_256];
        create_alias_child_path(frame, entry->name, child_abs, child_rel);
        if (cbm_pipeline_relpath_is_excluded(child_rel, excluded_dirs, excluded_count)) {
            continue;
        }
        if (frame->depth >= CBM_PATH_ALIAS_MAX_DEPTH ||
            frame_count == CBM_PATH_ALIAS_WALK_FRAME_CAPACITY) {
            continue;
        }
        if (open_alias_walk_frame(&frames[frame_count], child_abs, child_rel,
                                  frame->depth + CBM_PATH_ALIAS_DEPTH_STEP, out, count,
                                  max_count)) {
            frame_count++;
        }
    }
    close_alias_walk_frames(frames, frame_count);
}

cbm_path_alias_collection_t *cbm_load_path_aliases_excluded(const char *repo_path,
                                                            char **excluded_dirs,
                                                            int excluded_count) {
    if (!repo_path) {
        return NULL;
    }
    alias_config_hit_t *hits = calloc(CBM_PATH_ALIAS_MAX_FILES, sizeof(*hits));
    if (!hits) {
        return NULL;
    }
    int count = 0;
    find_alias_files(repo_path, "", hits, &count, CBM_PATH_ALIAS_MAX_FILES, excluded_dirs,
                     excluded_count);
    if (count >= CBM_PATH_ALIAS_MAX_FILES) {
        cbm_log_warn("path_alias.files.cap_hit", "repo", repo_path, "kept", "256_of_more");
    }
    if (count == 0) {
        free(hits);
        return NULL;
    }

    cbm_path_alias_collection_t *coll = calloc(CBM_PATH_ALIAS_SINGLE_OBJECT, sizeof(*coll));
    if (!coll) {
        free(hits);
        return NULL;
    }
    coll->scopes = calloc((size_t)count, sizeof(cbm_path_alias_scope_t));
    if (!coll->scopes) {
        free(coll);
        free(hits);
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        cbm_path_alias_map_t *map = load_tsconfig_file(hits[i].abs, hits[i].rel);
        if (!map) {
            continue;
        }
        const char *base = strrchr(hits[i].abs, '/');
        base = base ? base + CBM_PATH_ALIAS_PATH_SEPARATOR_BYTES : hits[i].abs;
        char selected_rel[CBM_SZ_512];
        if (hits[i].rel[0]) {
            snprintf(selected_rel, sizeof(selected_rel), "%s/%s", hits[i].rel, base);
        } else {
            snprintf(selected_rel, sizeof(selected_rel), "%s", base);
        }
        char *dir_prefix = strdup(hits[i].rel);
        char *source_rel_path = strdup(selected_rel);
        if (!dir_prefix || !source_rel_path) {
            free(dir_prefix);
            free(source_rel_path);
            free_alias_map(map);
            continue;
        }
        coll->scopes[coll->count].dir_prefix = dir_prefix;
        coll->scopes[coll->count].source_rel_path = source_rel_path;
        coll->scopes[coll->count].map = map;
        coll->count++;
    }
    free(hits);

    if (coll->count == 0) {
        free(coll->scopes);
        free(coll);
        return NULL;
    }

    qsort(coll->scopes, (size_t)coll->count, sizeof(cbm_path_alias_scope_t),
          cmp_scope_by_specificity);
    return coll;
}

cbm_path_alias_collection_t *cbm_load_path_aliases(const char *repo_path) {
    return cbm_load_path_aliases_excluded(repo_path, NULL, 0);
}

const cbm_path_alias_map_t *cbm_path_alias_find_for_file(const cbm_path_alias_collection_t *coll,
                                                         const char *rel_path) {
    if (!coll || !rel_path) {
        return NULL;
    }
    for (int i = 0; i < coll->count; i++) {
        const char *prefix = coll->scopes[i].dir_prefix;
        size_t plen = strlen(prefix);
        if (plen == 0) {
            return coll->scopes[i].map;
        }
        if (strncmp(rel_path, prefix, plen) == 0 &&
            (rel_path[plen] == '/' || rel_path[plen] == '\0')) {
            return coll->scopes[i].map;
        }
    }
    return NULL;
}
