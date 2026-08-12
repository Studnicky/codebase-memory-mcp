/*
 * integration_assets.c — Verified access to the shipped integration templates.
 *
 * See integration_assets.h for the architecture (why the bodies live in a
 * data file, the integrity model, and the ownership-reference role of the
 * stored copy under <home>/.cbm/assets/<version>/).
 */
#include "cli/integration_assets.h"

#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/platform.h"
#include "foundation/sha256.h"
#include "yyjson/yyjson.h"

#include "cbm_integrations_hash.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#ifndef CBM_VERSION
#define CBM_VERSION "dev"
#endif

enum {
    ASSETS_DIR_PERM = 0755,
    ASSETS_FORMAT_VERSION = 1,
    /* The shipped file is ~8 KB; the cap only bounds a corrupted candidate. */
    ASSETS_MAX_BYTES = CBM_SZ_64K * CBM_SZ_16,
};

/* The one actionable failure message: every "cannot use the templates" path
 * reports the same recovery, because the recovery is always the same. */
static const char assets_error_message[] =
    "integration assets missing or modified - reinstall from the release archive "
    "(expected " CBM_INTEGRATIONS_ASSET_NAME " next to the binary, in $CBM_ASSETS_DIR, "
    "or under ~/.cbm/assets/" CBM_VERSION ")";

typedef struct {
    const char *id;
    cbm_integration_template_t tpl;
    cbm_integration_body_t *released_storage;
} asset_entry_t;

/* Success-only cache: a failed resolve is re-attempted on every call so one
 * bad candidate never poisons a later call that could succeed. */
static struct {
    bool ok;
    char *bytes;
    size_t length;
    yyjson_doc *doc;
    asset_entry_t *entries;
    size_t entry_count;
} g_assets;

static void assets_fill_error(char *err, size_t err_sz) {
    if (err && err_sz > 0U) {
        (void)snprintf(err, err_sz, "%s", assets_error_message);
    }
}

static bool assets_exe_dir(char *out, size_t out_sz) {
    if (out_sz < CBM_SZ_2) {
        return false;
    }
#ifdef _WIN32
    DWORD length = GetModuleFileNameA(NULL, out, (DWORD)out_sz);
    if (length == 0 || (size_t)length >= out_sz) {
        return false;
    }
    cbm_normalize_path_sep(out);
#elif defined(__APPLE__)
    uint32_t self_sz = (uint32_t)out_sz;
    if (_NSGetExecutablePath(out, &self_sz) != 0) {
        return false;
    }
#else
    ssize_t length = readlink("/proc/self/exe", out, out_sz - SKIP_ONE);
    if (length <= 0 || (size_t)length >= out_sz - SKIP_ONE) {
        return false;
    }
    out[length] = '\0';
#endif
    char *slash = strrchr(out, '/');
    if (!slash || slash == out) {
        return false;
    }
    *slash = '\0';
    return true;
}

static bool assets_stored_copy_path(const char *home, char *out, size_t out_sz) {
    if (!home || !home[0]) {
        return false;
    }
    int written = snprintf(out, out_sz, "%s/.cbm/assets/%s/%s", home, CBM_VERSION,
                           CBM_INTEGRATIONS_ASSET_NAME);
    return written > 0 && (size_t)written < out_sz;
}

/* Read a candidate fully. Returns false for missing/unreadable/oversized. */
static bool assets_read_file(const char *path, char **out_bytes, size_t *out_length) {
    *out_bytes = NULL;
    *out_length = 0U;
    FILE *file = cbm_fopen(path, "rb");
    if (!file) {
        return false;
    }
    if (fseek(file, 0L, SEEK_END) != 0) {
        (void)fclose(file);
        return false;
    }
    long size = ftell(file);
    if (size <= 0 || size > (long)ASSETS_MAX_BYTES || fseek(file, 0L, SEEK_SET) != 0) {
        (void)fclose(file);
        return false;
    }
    char *bytes = malloc((size_t)size + SKIP_ONE);
    if (!bytes) {
        (void)fclose(file);
        return false;
    }
    size_t got = fread(bytes, sizeof(*bytes), (size_t)size, file);
    (void)fclose(file);
    if (got != (size_t)size) {
        free(bytes);
        return false;
    }
    bytes[got] = '\0';
    *out_bytes = bytes;
    *out_length = got;
    return true;
}

static bool assets_bytes_verified(const char *bytes, size_t length) {
    char hex[CBM_SHA256_HEX_LEN + SKIP_ONE];
    cbm_sha256_hex(bytes, length, hex);
    return strcmp(hex, CBM_INTEGRATIONS_SHA256) == 0;
}

static bool assets_parse_body(yyjson_val *value, cbm_integration_body_t *body) {
    yyjson_val *text = yyjson_is_obj(value) ? yyjson_obj_get(value, "text") : NULL;
    yyjson_val *bin = yyjson_is_obj(value) ? yyjson_obj_get(value, "bin") : NULL;
    if (!text || !yyjson_is_str(text) || (bin && !yyjson_is_str(bin))) {
        return false;
    }
    body->text = yyjson_get_str(text);
    body->bin_mode = bin ? yyjson_get_str(bin) : NULL;
    return true;
}

static void assets_entries_free(asset_entry_t *entries, size_t entry_count) {
    for (size_t index = 0U; index < entry_count; index++) {
        free(entries[index].released_storage);
    }
    free(entries);
}

static yyjson_val *assets_platform_variant(yyjson_val *template_value) {
#ifdef _WIN32
    static const char platform_variant[] = "windows";
#else
    static const char platform_variant[] = "posix";
#endif
    yyjson_val *variant = yyjson_obj_get(template_value, platform_variant);
    return variant ? variant : yyjson_obj_get(template_value, "all");
}

static bool assets_parse_released(yyjson_val *released, asset_entry_t *entry) {
    if (!released) {
        return true;
    }
    if (!yyjson_is_arr(released)) {
        return false;
    }
    size_t released_count = yyjson_arr_size(released);
    if (released_count == 0U) {
        return true;
    }
    entry->released_storage = calloc(released_count, sizeof(*entry->released_storage));
    if (!entry->released_storage) {
        return false;
    }
    size_t index;
    size_t max;
    yyjson_val *value;
    size_t stored = 0U;
    yyjson_arr_foreach(released, index, max, value) {
        if (!assets_parse_body(value, &entry->released_storage[stored])) {
            return false;
        }
        stored++;
    }
    entry->tpl.released = entry->released_storage;
    entry->tpl.released_count = stored;
    return true;
}

static bool assets_parse_entry(yyjson_val *key, yyjson_val *template_value, asset_entry_t *entry,
                               bool *included) {
    *included = false;
    if (!yyjson_is_str(key) || !yyjson_is_obj(template_value)) {
        return false;
    }
    yyjson_val *variant = assets_platform_variant(template_value);
    if (!variant) {
        return true;
    }
    entry->id = yyjson_get_str(key);
    if (!assets_parse_body(variant, &entry->tpl.current)) {
        return false;
    }
    yyjson_val *tool_line = yyjson_obj_get(template_value, "tool_line");
    if (tool_line && !yyjson_is_str(tool_line)) {
        return false;
    }
    entry->tpl.tool_line = tool_line ? yyjson_get_str(tool_line) : NULL;
    if (!assets_parse_released(yyjson_obj_get(template_value, "released"), entry)) {
        return false;
    }
    *included = true;
    return true;
}

static bool assets_parse_entries(yyjson_val *templates, asset_entry_t *entries,
                                 size_t *entry_count_out) {
    size_t index;
    size_t max;
    yyjson_val *key;
    yyjson_val *value;
    *entry_count_out = 0U;
    yyjson_obj_foreach(templates, index, max, key, value) {
        asset_entry_t *entry = &entries[*entry_count_out];
        bool included = false;
        if (!assets_parse_entry(key, value, entry, &included)) {
            free(entry->released_storage);
            return false;
        }
        if (included) {
            (*entry_count_out)++;
        }
    }
    return true;
}

static yyjson_doc *assets_parse_document(char *bytes, size_t length, yyjson_val **templates_out) {
    yyjson_doc *doc = yyjson_read(bytes, length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    if (!root || !yyjson_is_obj(root)) {
        if (doc) {
            yyjson_doc_free(doc);
        }
        return NULL;
    }
    yyjson_val *format = yyjson_obj_get(root, "format");
    yyjson_val *templates = yyjson_obj_get(root, "templates");
    if (!format || !yyjson_is_int(format) || yyjson_get_int(format) != ASSETS_FORMAT_VERSION ||
        !templates || !yyjson_is_obj(templates)) {
        yyjson_doc_free(doc);
        return NULL;
    }
    *templates_out = templates;
    return doc;
}

/* Parse verified bytes into the template table. The variant picked here is
 * the platform's ("windows" on _WIN32, else "posix", with "all" accepted for
 * platform-independent templates such as the JS adapters). */
static bool assets_adopt_bytes(char *bytes, size_t length) {
    yyjson_val *templates = NULL;
    yyjson_doc *doc = assets_parse_document(bytes, length, &templates);
    if (!doc) {
        return false;
    }
    size_t template_count = yyjson_obj_size(templates);
    asset_entry_t *entries = calloc(template_count ? template_count : SKIP_ONE, sizeof(*entries));
    if (!entries) {
        yyjson_doc_free(doc);
        return false;
    }
    size_t entry_count = 0U;
    if (!assets_parse_entries(templates, entries, &entry_count)) {
        assets_entries_free(entries, entry_count);
        yyjson_doc_free(doc);
        return false;
    }
    g_assets.bytes = bytes;
    g_assets.length = length;
    g_assets.doc = doc;
    g_assets.entries = entries;
    g_assets.entry_count = entry_count;
    g_assets.ok = true;
    return true;
}

/* Try one candidate path: read + hash-verify + parse. On success the bytes
 * are adopted into the cache (ownership transferred). */
static bool assets_try_candidate(const char *path) {
    char *bytes = NULL;
    size_t length = 0U;
    if (!assets_read_file(path, &bytes, &length)) {
        return false;
    }
    if (!assets_bytes_verified(bytes, length) || !assets_adopt_bytes(bytes, length)) {
        free(bytes);
        return false;
    }
    return true;
}

static bool assets_resolve(const char *home) {
    if (g_assets.ok) {
        return true;
    }
    /* CBM_ASSETS_DIR set = authoritative: an explicit override that is
     * missing or modified FAILS; silently falling back would hide exactly
     * the tampering the hash check exists to surface. */
    static const char env_missing[] = "\x1f"
                                      "CBM_ASSETS_DIR_MISSING"
                                      "\x1f";
    char env_buf[CBM_SZ_4K];
    char candidate[CBM_SZ_4K];
    const char *assets_dir =
        cbm_safe_getenv("CBM_ASSETS_DIR", env_buf, sizeof(env_buf), env_missing);
    if (!assets_dir) {
        return false; /* present but unrepresentable: fail, do not fall back */
    }
    if (strcmp(assets_dir, env_missing) != 0 && assets_dir[0]) {
        int written = snprintf(candidate, sizeof(candidate), "%s/%s", assets_dir,
                               CBM_INTEGRATIONS_ASSET_NAME);
        return written > 0 && (size_t)written < sizeof(candidate) &&
               assets_try_candidate(candidate);
    }
    char exe_dir[CBM_SZ_4K];
    if (assets_exe_dir(exe_dir, sizeof(exe_dir))) {
        int written =
            snprintf(candidate, sizeof(candidate), "%s/%s", exe_dir, CBM_INTEGRATIONS_ASSET_NAME);
        if (written > 0 && (size_t)written < sizeof(candidate) && assets_try_candidate(candidate)) {
            return true;
        }
        /* Source-tree layout: build/c/<binary> with assets/ at the root. */
        written = snprintf(candidate, sizeof(candidate), "%s/../../assets/%s", exe_dir,
                           CBM_INTEGRATIONS_ASSET_NAME);
        if (written > 0 && (size_t)written < sizeof(candidate) && assets_try_candidate(candidate)) {
            return true;
        }
    }
    return assets_stored_copy_path(home, candidate, sizeof(candidate)) &&
           assets_try_candidate(candidate);
}

bool cbm_integration_assets_require(const char *home, char *err, size_t err_sz) {
    if (assets_resolve(home)) {
        return true;
    }
    assets_fill_error(err, err_sz);
    return false;
}

static void assets_fill_install_error(char *err, size_t err_sz, const char *format,
                                      const char *path) {
    if (err && err_sz > 0U) {
        (void)snprintf(err, err_sz, format, path, CBM_INTEGRATIONS_ASSET_NAME);
    }
}

static bool assets_prepare_storage(const char *home, char stored[CBM_SZ_4K], char parent[CBM_SZ_4K],
                                   char *err, size_t err_sz) {
    if (!assets_stored_copy_path(home, stored, CBM_SZ_4K)) {
        assets_fill_error(err, err_sz);
        return false;
    }
    (void)snprintf(parent, CBM_SZ_4K, "%s", stored);
    char *slash = strrchr(parent, '/');
    if (!slash) {
        assets_fill_error(err, err_sz);
        return false;
    }
    *slash = '\0';
    if (!cbm_mkdir_p(parent, ASSETS_DIR_PERM)) {
        assets_fill_install_error(err, err_sz, "cannot create %s to store the verified %s copy",
                                  parent);
        return false;
    }
    return true;
}

static bool assets_publish_stored_copy(const char *stored, char *err, size_t err_sz) {
    /* Publish by rename so a concurrent reader never sees a torn copy. */
    char temp_path[CBM_SZ_4K];
    int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", stored);
    if (written <= 0 || (size_t)written >= sizeof(temp_path)) {
        assets_fill_error(err, err_sz);
        return false;
    }
    FILE *file = cbm_fopen(temp_path, "wb");
    bool wrote = file && fwrite(g_assets.bytes, sizeof(*g_assets.bytes), g_assets.length, file) ==
                             g_assets.length;
    int close_result = file ? fclose(file) : EOF;
    if (!wrote || close_result != 0 || cbm_rename_replace(temp_path, stored) != 0) {
        (void)cbm_unlink(temp_path);
        if (err && err_sz > 0U) {
            (void)snprintf(err, err_sz, "cannot write the verified %s copy to %s",
                           CBM_INTEGRATIONS_ASSET_NAME, stored);
        }
        return false;
    }
    return true;
}

bool cbm_integration_assets_install(const char *home, bool dry_run, char *err, size_t err_sz) {
    if (!home || !home[0]) {
        assets_fill_error(err, err_sz);
        return false;
    }
    if (!cbm_integration_assets_require(home, err, err_sz)) {
        return false;
    }
    if (dry_run) {
        return true;
    }
    char stored[CBM_SZ_4K];
    char parent[CBM_SZ_4K];
    return assets_prepare_storage(home, stored, parent, err, err_sz) &&
           assets_publish_stored_copy(stored, err, err_sz);
}

const cbm_integration_template_t *cbm_integration_template(const char *id) {
    if (!id || !assets_resolve(NULL)) {
        return NULL;
    }
    for (size_t i = 0U; i < g_assets.entry_count; i++) {
        if (strcmp(g_assets.entries[i].id, id) == 0) {
            return &g_assets.entries[i].tpl;
        }
    }
    return NULL;
}

#ifdef CBM_CLI_ENABLE_TEST_API
void cbm_integration_assets_reset_for_testing(void) {
    for (size_t i = 0U; i < g_assets.entry_count; i++) {
        free(g_assets.entries[i].released_storage);
    }
    free(g_assets.entries);
    g_assets.entries = NULL;
    g_assets.entry_count = 0U;
    if (g_assets.doc) {
        yyjson_doc_free(g_assets.doc);
        g_assets.doc = NULL;
    }
    free(g_assets.bytes);
    g_assets.bytes = NULL;
    g_assets.length = 0U;
    g_assets.ok = false;
}
#endif
