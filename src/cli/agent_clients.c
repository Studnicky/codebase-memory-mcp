/*
 * agent_clients.c — Table-driven MCP adapters for agent clients.
 *
 * Resolution is deliberately separate from mutation. Callers decide which
 * detected clients are in scope, then pass the exact resolved config path to
 * the ownership-preserving editor.
 */
#include "agent_clients.h"

#include "config_json_like.h"
#include "config_text_edit.h"
#include "config_yaml_edit.h"
#include "foundation/compat_fs.h"
#include "foundation/platform.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AGENT_ENTRY_KEY "codebase-memory-mcp"
#define AGENT_MAX_CONFIG_BYTES ((size_t)8U * 1024U * 1024U)
#define AGENT_JSON_MAX_DEPTH 64U
#define AGENT_RESULT_ERROR (-1)
#define AGENT_RESULT_OK 0
#define AGENT_RESULT_ABSENT 1
#define AGENT_UNIT_COUNT 1U
#define AGENT_PAIR_COUNT 2U
#define AGENT_TRIPLE_COUNT 3U
#define AGENT_QUAD_COUNT 4U
#define AGENT_SECOND_INDEX AGENT_UNIT_COUNT
#define AGENT_THIRD_INDEX AGENT_PAIR_COUNT
#define AGENT_PREVIOUS_INDEX (-1)
#define AGENT_SECTION_PATH_DEPTH AGENT_UNIT_COUNT
#define AGENT_CONFIG_PATH_CAPACITY 1024U
#define AGENT_HEX_RADIX 16U
#define AGENT_HEX_ALPHA_OFFSET 10U
#define AGENT_ASCII_CONTROL_LIMIT 0x20U
#define AGENT_ASCII_MAX 0x7fU
#define AGENT_UTF8_BOM_FIRST_BYTE 0xefU
#define AGENT_UTF8_BOM_SECOND_BYTE 0xbbU
#define AGENT_UTF8_BOM_THIRD_BYTE 0xbfU
#define AGENT_JSON_ESCAPE_LENGTH 6U
#define AGENT_JSON_CANONICAL_OVERHEAD 64U
#define AGENT_CONTINUE_CANONICAL_OVERHEAD 96U

static int agent_install_callback(cbm_agent_client_id_t id, const char *config_path,
                                  const char *binary_path);
static int agent_remove_callback(cbm_agent_client_id_t id, const char *config_path,
                                 const char *binary_path);

static const cbm_agent_client_profile_t agent_profiles[CBM_AGENT_CLIENT_COUNT] = {
    {CBM_AGENT_CLIENT_QODER, "qoder", "Qoder CLI", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_SKILL | CBM_AGENT_CAP_AGENT | CBM_AGENT_CAP_HOOK, "qodercli",
     agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_KIMI, "kimi", "Kimi Code CLI", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_INSTRUCTIONS | CBM_AGENT_CAP_SKILL | CBM_AGENT_CAP_HOOK,
     "kimi", agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_GITLAB_DUO, "gitlab-duo", "GitLab Duo CLI", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_HOOK, "duo", agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_ROVO_DEV, "rovo-dev", "Rovo Dev CLI", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_INSTRUCTIONS | CBM_AGENT_CAP_SKILL | CBM_AGENT_CAP_AGENT,
     "rovodev", agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_AMP, "amp", "Amp", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_INSTRUCTIONS | CBM_AGENT_CAP_SKILL, "amp",
     agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_DEVIN, "devin", "Devin CLI / Local", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_INSTRUCTIONS | CBM_AGENT_CAP_SKILL | CBM_AGENT_CAP_HOOK,
     "devin", agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_TABNINE, "tabnine", "Tabnine", CBM_AGENT_STABLE, CBM_AGENT_CAP_MCP, "tabnine",
     agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_CONTINUE, "continue", "Continue / cn", CBM_AGENT_CONDITIONAL,
     CBM_AGENT_CAP_MCP, "cn", agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_VISUAL_STUDIO, "visual-studio", "Visual Studio", CBM_AGENT_CONDITIONAL,
     CBM_AGENT_CAP_MCP, "devenv", agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_TRAE, "trae", "TRAE", CBM_AGENT_CONDITIONAL, CBM_AGENT_CAP_MCP, NULL,
     agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_ROO_CODE, "roo-code", "Roo Code", CBM_AGENT_CONDITIONAL, CBM_AGENT_CAP_MCP,
     NULL, agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_AMAZON_Q, "amazon-q", "Amazon Q Developer IDE", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP, NULL, agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_CODEBUDDY, "codebuddy", "CodeBuddy Code CLI", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_INSTRUCTIONS | CBM_AGENT_CAP_SKILL | CBM_AGENT_CAP_AGENT,
     "codebuddy", agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_IBM_BOB_IDE, "ibm-bob-ide", "IBM Bob IDE", CBM_AGENT_CONDITIONAL,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_INSTRUCTIONS | CBM_AGENT_CAP_SKILL, NULL,
     agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_IBM_BOB_SHELL, "ibm-bob-shell", "IBM Bob Shell", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_INSTRUCTIONS, "bob", agent_install_callback,
     agent_remove_callback},
    {CBM_AGENT_CLIENT_POCHI, "pochi", "Pochi", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_MCP | CBM_AGENT_CAP_INSTRUCTIONS | CBM_AGENT_CAP_SKILL | CBM_AGENT_CAP_AGENT,
     "pochi", agent_install_callback, agent_remove_callback},
    {CBM_AGENT_CLIENT_PI, "pi", "Pi", CBM_AGENT_STABLE,
     CBM_AGENT_CAP_INSTRUCTIONS | CBM_AGENT_CAP_SKILL, "pi", NULL, NULL},
    {CBM_AGENT_CLIENT_SOURCEGRAPH_CODY, "sourcegraph-cody", "Sourcegraph Cody", CBM_AGENT_OPT_IN,
     CBM_AGENT_CAP_MCP, NULL, agent_install_callback, agent_remove_callback},
};

size_t cbm_agent_client_count(void) {
    return CBM_AGENT_CLIENT_COUNT;
}

const cbm_agent_client_profile_t *cbm_agent_client_at(size_t index) {
    return index < CBM_AGENT_CLIENT_COUNT ? &agent_profiles[index] : NULL;
}

const cbm_agent_client_profile_t *cbm_agent_client_by_id(cbm_agent_client_id_t id) {
    return (unsigned)id < CBM_AGENT_CLIENT_COUNT ? &agent_profiles[id] : NULL;
}

const cbm_agent_client_profile_t *cbm_agent_client_by_stable_id(const char *stable_id) {
    if (!stable_id || stable_id[0] == '\0') {
        return NULL;
    }
    for (size_t i = 0U; i < CBM_AGENT_CLIENT_COUNT; i++) {
        if (strcmp(agent_profiles[i].stable_id, stable_id) == 0) {
            return &agent_profiles[i];
        }
    }
    return NULL;
}

static bool agent_path_exists(const cbm_agent_client_resolve_options_t *options, const char *path) {
    return options->path_exists ? options->path_exists(path, options->probe_context)
                                : cbm_file_exists(path);
}

static bool agent_command_exists(const cbm_agent_client_resolve_options_t *options,
                                 const char *command) {
    return command && options->command_exists &&
           options->command_exists(command, options->probe_context);
}

static int agent_join_path(char *output, size_t output_size, const char *base, const char *suffix) {
    if (!output || output_size == 0U || !base || base[0] == '\0' || !suffix || suffix[0] == '\0') {
        return AGENT_RESULT_ERROR;
    }
    size_t base_len = strlen(base);
    const char *separator =
        base[base_len - AGENT_UNIT_COUNT] == '/' || base[base_len - AGENT_UNIT_COUNT] == '\\' ? ""
                                                                                              : "/";
    int written = snprintf(output, output_size, "%s%s%s", base, separator, suffix);
    return written >= 0 && (size_t)written < output_size ? 0 : AGENT_RESULT_ERROR;
}

static bool agent_path_separator(char value, bool windows) {
    return value == '/' || (windows && value == '\\');
}

/* Lexically normalizes an absolute path without consulting the filesystem.
 * Rovo may point at a config file that does not exist yet, so realpath-style
 * canonicalization is not available. Traversal is rejected rather than
 * resolved, and Windows aliases that trim trailing dots/spaces are rejected. */
static int agent_normalize_windows_prefix(const char *input, char *output, size_t output_size,
                                          size_t *read_out, size_t *written_out, bool *unc_out) {
    if (isalpha((unsigned char)input[0]) && input[AGENT_SECOND_INDEX] == ':' &&
        agent_path_separator(input[AGENT_THIRD_INDEX], true)) {
        if (output_size < AGENT_QUAD_COUNT) {
            return AGENT_RESULT_ERROR;
        }
        output[0] = (char)toupper((unsigned char)input[0]);
        output[AGENT_UNIT_COUNT] = ':';
        output[AGENT_PAIR_COUNT] = '/';
        *read_out = AGENT_TRIPLE_COUNT;
        *written_out = AGENT_TRIPLE_COUNT;
        *unc_out = false;
        return AGENT_RESULT_OK;
    }
    if (!agent_path_separator(input[0], true) ||
        !agent_path_separator(input[AGENT_SECOND_INDEX], true) ||
        output_size < AGENT_TRIPLE_COUNT) {
        return AGENT_RESULT_ERROR;
    }
    output[0] = '/';
    output[AGENT_UNIT_COUNT] = '/';
    *read_out = AGENT_PAIR_COUNT;
    *written_out = AGENT_PAIR_COUNT;
    *unc_out = true;
    return AGENT_RESULT_OK;
}

static int agent_normalize_posix_prefix(const char *input, char *output, size_t output_size,
                                        size_t *read_out, size_t *written_out, bool *unc_out) {
    if (input[0] != '/' || output_size < AGENT_PAIR_COUNT) {
        return AGENT_RESULT_ERROR;
    }
    output[0] = '/';
    *read_out = AGENT_UNIT_COUNT;
    *written_out = AGENT_UNIT_COUNT;
    *unc_out = false;
    return AGENT_RESULT_OK;
}

static bool agent_windows_component_valid(const char *input, size_t start, size_t length) {
    char final = input[start + length - AGENT_UNIT_COUNT];
    if (final == '.' || final == ' ') {
        return false;
    }
    for (size_t i = 0U; i < length; i++) {
        if (input[start + i] == ':') {
            return false;
        }
    }
    return true;
}

static int agent_normalize_component(const char *input, size_t start, size_t length, bool windows,
                                     char *output, size_t output_size, size_t *written_out) {
    if (length == AGENT_UNIT_COUNT && input[start] == '.') {
        return AGENT_RESULT_ABSENT;
    }
    if (length == AGENT_PAIR_COUNT && input[start] == '.' &&
        input[start + AGENT_UNIT_COUNT] == '.') {
        return AGENT_RESULT_ERROR;
    }
    if (windows && !agent_windows_component_valid(input, start, length)) {
        return AGENT_RESULT_ERROR;
    }
    size_t written = *written_out;
    bool needs_separator = written > 0U && output[written - AGENT_UNIT_COUNT] != '/';
    if (length > output_size - written - AGENT_UNIT_COUNT ||
        (needs_separator && written + AGENT_UNIT_COUNT >= output_size)) {
        return AGENT_RESULT_ERROR;
    }
    if (needs_separator) {
        output[written++] = '/';
    }
    memcpy(output + written, input + start, length);
    *written_out = written + length;
    return AGENT_RESULT_OK;
}

static int agent_normalize_absolute_path(const char *input, bool windows, char *output,
                                         size_t output_size) {
    if (!input || !input[0] || !output || output_size == 0U) {
        return AGENT_RESULT_ERROR;
    }
    size_t read = 0U;
    size_t written = 0U;
    bool unc = false;
    int prefix_result =
        windows ? agent_normalize_windows_prefix(input, output, output_size, &read, &written, &unc)
                : agent_normalize_posix_prefix(input, output, output_size, &read, &written, &unc);
    if (prefix_result != AGENT_RESULT_OK) {
        return prefix_result;
    }
    size_t components = 0U;
    while (input[read]) {
        while (input[read] && agent_path_separator(input[read], windows)) {
            read++;
        }
        if (!input[read]) {
            break;
        }
        size_t start = read;
        while (input[read] && !agent_path_separator(input[read], windows)) {
            read++;
        }
        size_t length = read - start;
        int component_result =
            agent_normalize_component(input, start, length, windows, output, output_size, &written);
        if (component_result == AGENT_RESULT_ERROR) {
            return component_result;
        }
        components += component_result == AGENT_RESULT_OK ? AGENT_UNIT_COUNT : 0U;
    }
    if (unc && components < AGENT_PAIR_COUNT) {
        return AGENT_RESULT_ERROR;
    }
    output[written] = '\0';
    return 0;
}

static bool agent_path_prefix_equal(const char *candidate, const char *root, size_t length,
                                    bool windows) {
    for (size_t i = 0U; i < length; i++) {
        unsigned char left = (unsigned char)candidate[i];
        unsigned char right = (unsigned char)root[i];
        if (windows) {
            left = (unsigned char)tolower(left);
            right = (unsigned char)tolower(right);
        }
        if (left != right) {
            return false;
        }
    }
    return true;
}

static int agent_rovo_safe_override(const char *configured_path, const char *home_dir, bool windows,
                                    char *path_out, size_t path_out_size) {
    size_t home_length = strlen(home_dir);
    size_t configured_length = strlen(configured_path);
    static const char root_suffix[] = ".rovodev";
    if (home_length > SIZE_MAX - sizeof(root_suffix) - AGENT_UNIT_COUNT) {
        return AGENT_RESULT_ERROR;
    }
    size_t root_capacity = home_length + sizeof(root_suffix) + AGENT_UNIT_COUNT;
    char *root = (char *)malloc(root_capacity);
    if (!root || agent_join_path(root, root_capacity, home_dir, root_suffix) != 0) {
        free(root);
        return AGENT_RESULT_ERROR;
    }

    bool tilde_path = configured_path[0] == '~';
    if (tilde_path && !agent_path_separator(configured_path[AGENT_SECOND_INDEX], windows)) {
        free(root);
        return AGENT_RESULT_ERROR;
    }
    size_t candidate_capacity = configured_length + AGENT_UNIT_COUNT;
    if (tilde_path) {
        size_t suffix_length = configured_length - AGENT_PAIR_COUNT;
        if (home_length > SIZE_MAX - suffix_length - AGENT_PAIR_COUNT) {
            free(root);
            return AGENT_RESULT_ERROR;
        }
        candidate_capacity = home_length + suffix_length + AGENT_PAIR_COUNT;
    }
    char *candidate = (char *)malloc(candidate_capacity);
    if (!candidate) {
        free(root);
        return AGENT_RESULT_ERROR;
    }
    int candidate_written = tilde_path
                                ? snprintf(candidate, candidate_capacity, "%s/%s", home_dir,
                                           configured_path + AGENT_PAIR_COUNT)
                                : snprintf(candidate, candidate_capacity, "%s", configured_path);
    if (candidate_written < 0 || (size_t)candidate_written >= candidate_capacity) {
        free(candidate);
        free(root);
        return AGENT_RESULT_ERROR;
    }

    char *normalized_root = (char *)calloc(root_capacity, AGENT_UNIT_COUNT);
    char *normalized_candidate = (char *)calloc(candidate_capacity, AGENT_UNIT_COUNT);
    if (!normalized_root || !normalized_candidate ||
        agent_normalize_absolute_path(root, windows, normalized_root, root_capacity) != 0 ||
        agent_normalize_absolute_path(candidate, windows, normalized_candidate,
                                      candidate_capacity) != 0) {
        free(normalized_candidate);
        free(normalized_root);
        free(candidate);
        free(root);
        return AGENT_RESULT_ERROR;
    }
    size_t root_length = strlen(normalized_root);
    size_t candidate_length = strlen(normalized_candidate);
    bool contained =
        candidate_length > root_length && normalized_candidate[root_length] == '/' &&
        agent_path_prefix_equal(normalized_candidate, normalized_root, root_length, windows);
    int result = AGENT_RESULT_ERROR;
    if (contained && candidate_length < path_out_size) {
        memcpy(path_out, normalized_candidate, candidate_length + AGENT_UNIT_COUNT);
        result = 0;
    }
    free(normalized_candidate);
    free(normalized_root);
    free(candidate);
    free(root);
    return result;
}

static char *agent_trim_copy(const char *start, size_t length) {
    while (length > 0U && isspace((unsigned char)*start)) {
        start++;
        length--;
    }
    while (length > 0U && isspace((unsigned char)start[length - AGENT_UNIT_COUNT])) {
        length--;
    }
    if (length >= AGENT_PAIR_COUNT &&
        ((start[0] == '"' && start[length - AGENT_UNIT_COUNT] == '"') ||
         (start[0] == '\'' && start[length - AGENT_UNIT_COUNT] == '\''))) {
        start++;
        length -= AGENT_PAIR_COUNT;
    }
    char *copy = (char *)malloc(length + AGENT_UNIT_COUNT);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, start, length);
    copy[length] = '\0';
    return copy;
}

static int agent_read_config_file(const char *config_path, char **text_out) {
    FILE *file = cbm_fopen(config_path, "rb");
    if (!file) {
        return AGENT_RESULT_ABSENT;
    }
    if (fseek(file, 0L, SEEK_END) != 0) {
        if (fclose(file) != 0) {
            return AGENT_RESULT_ERROR;
        }
        return AGENT_RESULT_ERROR;
    }
    long size = ftell(file);
    if (size < 0L || (size_t)size > AGENT_MAX_CONFIG_BYTES || fseek(file, 0L, SEEK_SET) != 0) {
        if (fclose(file) != 0) {
            return AGENT_RESULT_ERROR;
        }
        return AGENT_RESULT_ERROR;
    }
    char *text = (char *)malloc((size_t)size + AGENT_UNIT_COUNT);
    if (!text) {
        if (fclose(file) != 0) {
            return AGENT_RESULT_ERROR;
        }
        return AGENT_RESULT_ERROR;
    }
    size_t read_count = fread(text, AGENT_UNIT_COUNT, (size_t)size, file);
    int close_rc = fclose(file);
    if (read_count != (size_t)size || close_rc != 0) {
        free(text);
        return AGENT_RESULT_ERROR;
    }
    text[read_count] = '\0';
    *text_out = text;
    return AGENT_RESULT_OK;
}

static int agent_rovo_read_path_line(const char *line, size_t length, bool *in_mcp, char **found) {
    static const char key[] = "mcpConfigPath:";
    size_t indent = 0U;
    while (indent < length && line[indent] == ' ') {
        indent++;
    }
    if (indent < length && line[indent] == '\t') {
        return AGENT_RESULT_ERROR;
    }
    if (indent == 0U && length == strlen("mcp:") && memcmp(line, "mcp:", length) == 0) {
        *in_mcp = true;
        return AGENT_RESULT_OK;
    }
    if (indent == 0U && length > 0U && line[0] != '#') {
        *in_mcp = false;
        return AGENT_RESULT_OK;
    }
    if (!*in_mcp || indent == 0U || length - indent < sizeof(key) - AGENT_UNIT_COUNT ||
        memcmp(line + indent, key, sizeof(key) - AGENT_UNIT_COUNT) != 0) {
        return AGENT_RESULT_OK;
    }
    const char *value = line + indent + sizeof(key) - AGENT_UNIT_COUNT;
    size_t value_len = length - indent - (sizeof(key) - AGENT_UNIT_COUNT);
    if (*found || value_len == 0U || value[0] == '|' || value[0] == '>') {
        return AGENT_RESULT_ERROR;
    }
    *found = agent_trim_copy(value, value_len);
    return *found && (*found)[0] != '\0' ? AGENT_RESULT_OK : AGENT_RESULT_ERROR;
}

/* Reads only the documented `mcp.mcpConfigPath` scalar. Unsupported aliases,
 * block scalars, duplicates, or malformed indentation fail closed. */
static int agent_rovo_override(const char *config_path, const char *home_dir, bool windows,
                               char *path_out, size_t path_out_size) {
    char *text = NULL;
    int read_result = agent_read_config_file(config_path, &text);
    if (read_result != AGENT_RESULT_OK) {
        return read_result;
    }

    bool in_mcp = false;
    char *found = NULL;
    const char *cursor = text;
    while (*cursor) {
        const char *line = cursor;
        const char *end = strchr(cursor, '\n');
        if (!end) {
            end = cursor + strlen(cursor);
        }
        size_t length = (size_t)(end - line);
        if (length > 0U && line[length - AGENT_UNIT_COUNT] == '\r') {
            length--;
        }
        int line_result = agent_rovo_read_path_line(line, length, &in_mcp, &found);
        if (line_result != AGENT_RESULT_OK) {
            free(found);
            free(text);
            return line_result;
        }
        cursor = *end ? end + AGENT_UNIT_COUNT : end;
    }
    free(text);
    if (!found) {
        return AGENT_RESULT_ABSENT;
    }
    int result = agent_rovo_safe_override(found, home_dir, windows, path_out, path_out_size);
    free(found);
    return result;
}

static int agent_copy_path(char *path_out, size_t path_out_size, const char *path) {
    int written = snprintf(path_out, path_out_size, "%s", path);
    return written >= 0 && (size_t)written < path_out_size ? AGENT_RESULT_OK : AGENT_RESULT_ERROR;
}

static int agent_resolve_gitlab_duo(const cbm_agent_client_resolve_options_t *options,
                                    const char *config_home, char *path_out, size_t path_out_size) {
    if (options->glab_config_dir && options->glab_config_dir[0]) {
        return agent_join_path(path_out, path_out_size, options->glab_config_dir, "duo/mcp.json");
    }
    if (options->is_windows && options->appdata_dir && options->appdata_dir[0]) {
        return agent_join_path(path_out, path_out_size, options->appdata_dir,
                               "GitLab/duo/mcp.json");
    }
    return config_home
               ? agent_join_path(path_out, path_out_size, config_home, "gitlab/duo/mcp.json")
               : agent_join_path(path_out, path_out_size, options->home_dir,
                                 ".gitlab/duo/mcp.json");
}

static int agent_resolve_rovo_dev(const cbm_agent_client_resolve_options_t *options, char *path_out,
                                  size_t path_out_size) {
    char config_path[AGENT_CONFIG_PATH_CAPACITY];
    if (agent_join_path(config_path, sizeof(config_path), options->home_dir,
                        ".rovodev/config.yml") != AGENT_RESULT_OK) {
        return AGENT_RESULT_ERROR;
    }
    if (agent_path_exists(options, config_path)) {
        int override_result = agent_rovo_override(config_path, options->home_dir,
                                                  options->is_windows, path_out, path_out_size);
        if (override_result <= AGENT_RESULT_OK) {
            return override_result;
        }
    }
    char dedicated_path[AGENT_CONFIG_PATH_CAPACITY];
    char reference_path[AGENT_CONFIG_PATH_CAPACITY];
    if (agent_join_path(dedicated_path, sizeof(dedicated_path), options->home_dir,
                        ".rovodev/mcp.json") != AGENT_RESULT_OK ||
        agent_join_path(reference_path, sizeof(reference_path), options->home_dir,
                        ".rovodev/mcp_config.json") != AGENT_RESULT_OK) {
        return AGENT_RESULT_ERROR;
    }
    const char *selected =
        agent_path_exists(options, dedicated_path) || !agent_path_exists(options, reference_path)
            ? dedicated_path
            : reference_path;
    return agent_copy_path(path_out, path_out_size, selected);
}

static int agent_resolve_continue(const cbm_agent_client_resolve_options_t *options, char *path_out,
                                  size_t path_out_size) {
    const char *configured_path = options->continue_config_path;
    if (configured_path && configured_path[0]) {
        return agent_path_exists(options, configured_path)
                   ? agent_copy_path(path_out, path_out_size, configured_path)
                   : AGENT_RESULT_ABSENT;
    }
    char default_path[AGENT_CONFIG_PATH_CAPACITY];
    if (agent_join_path(default_path, sizeof(default_path), options->home_dir,
                        ".continue/config.yaml") != AGENT_RESULT_OK) {
        return AGENT_RESULT_ERROR;
    }
    return agent_path_exists(options, default_path)
               ? agent_copy_path(path_out, path_out_size, default_path)
               : AGENT_RESULT_ABSENT;
}

static int agent_resolve_amazon_q(const cbm_agent_client_resolve_options_t *options, char *path_out,
                                  size_t path_out_size) {
    char recommended[AGENT_CONFIG_PATH_CAPACITY];
    char overview[AGENT_CONFIG_PATH_CAPACITY];
    char legacy[AGENT_CONFIG_PATH_CAPACITY];
    if (agent_join_path(recommended, sizeof(recommended), options->home_dir,
                        ".aws/amazonq/default.json") != AGENT_RESULT_OK ||
        agent_join_path(overview, sizeof(overview), options->home_dir,
                        ".aws/amazonq/agents/default.json") != AGENT_RESULT_OK ||
        agent_join_path(legacy, sizeof(legacy), options->home_dir, ".aws/amazonq/mcp.json") !=
            AGENT_RESULT_OK) {
        return AGENT_RESULT_ERROR;
    }
    const char *selected = recommended;
    if (!agent_path_exists(options, selected)) {
        if (agent_path_exists(options, overview)) {
            selected = overview;
        } else if (agent_path_exists(options, legacy)) {
            selected = legacy;
        }
    }
    return agent_copy_path(path_out, path_out_size, selected);
}

static int agent_resolve_codebuddy(const cbm_agent_client_resolve_options_t *options,
                                   char *path_out, size_t path_out_size) {
    char recommended[AGENT_CONFIG_PATH_CAPACITY];
    char deprecated[AGENT_CONFIG_PATH_CAPACITY];
    char legacy[AGENT_CONFIG_PATH_CAPACITY];
    if (agent_join_path(recommended, sizeof(recommended), options->home_dir,
                        ".codebuddy/.mcp.json") != AGENT_RESULT_OK ||
        agent_join_path(deprecated, sizeof(deprecated), options->home_dir, ".codebuddy/mcp.json") !=
            AGENT_RESULT_OK ||
        agent_join_path(legacy, sizeof(legacy), options->home_dir, ".codebuddy.json") !=
            AGENT_RESULT_OK) {
        return AGENT_RESULT_ERROR;
    }
    const char *selected = recommended;
    if (!agent_path_exists(options, selected)) {
        if (agent_path_exists(options, deprecated)) {
            selected = deprecated;
        } else if (agent_path_exists(options, legacy)) {
            selected = legacy;
        }
    }
    return agent_copy_path(path_out, path_out_size, selected);
}

static int agent_resolve_kimi(const cbm_agent_client_resolve_options_t *options, char *path_out,
                              size_t path_out_size) {
    if (options->kimi_code_home && options->kimi_code_home[0]) {
        return agent_join_path(path_out, path_out_size, options->kimi_code_home, "mcp.json");
    }
    return agent_join_path(path_out, path_out_size, options->home_dir, ".kimi-code/mcp.json");
}

static int agent_resolve_devin(const cbm_agent_client_resolve_options_t *options, char *path_out,
                               size_t path_out_size) {
    if (options->is_windows && options->appdata_dir && options->appdata_dir[0]) {
        return agent_join_path(path_out, path_out_size, options->appdata_dir, "devin/config.json");
    }
    return agent_join_path(path_out, path_out_size, options->home_dir, ".config/devin/config.json");
}

static int agent_resolve_existing_path(const cbm_agent_client_resolve_options_t *options,
                                       const char *configured_path, char *path_out,
                                       size_t path_out_size) {
    if (!configured_path || configured_path[0] == '\0' ||
        !agent_path_exists(options, configured_path)) {
        return AGENT_RESULT_ABSENT;
    }
    return agent_copy_path(path_out, path_out_size, configured_path);
}

int cbm_agent_client_resolve_path(cbm_agent_client_id_t id,
                                  const cbm_agent_client_resolve_options_t *options, char *path_out,
                                  size_t path_out_size) {
    if (!cbm_agent_client_by_id(id) || !options || !path_out || path_out_size == 0U ||
        !options->home_dir || options->home_dir[0] == '\0') {
        return AGENT_RESULT_ERROR;
    }
    const char *config_home =
        options->xdg_config_home && options->xdg_config_home[0] ? options->xdg_config_home : NULL;
    switch (id) {
    case CBM_AGENT_CLIENT_QODER:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".qoder/settings.json");
    case CBM_AGENT_CLIENT_KIMI:
        return agent_resolve_kimi(options, path_out, path_out_size);
    case CBM_AGENT_CLIENT_GITLAB_DUO:
        return agent_resolve_gitlab_duo(options, config_home, path_out, path_out_size);
    case CBM_AGENT_CLIENT_ROVO_DEV:
        return agent_resolve_rovo_dev(options, path_out, path_out_size);
    case CBM_AGENT_CLIENT_AMP:
        /* Amp documents literal $HOME/.config locations and does not
         * advertise XDG_CONFIG_HOME support. Keep its bundled skill MCP
         * next to SKILL.md under the documented global skill root. */
        return agent_join_path(path_out, path_out_size, options->home_dir,
                               ".config/agents/skills/codebase-memory/mcp.json");
    case CBM_AGENT_CLIENT_DEVIN:
        return agent_resolve_devin(options, path_out, path_out_size);
    case CBM_AGENT_CLIENT_TABNINE:
        return agent_join_path(path_out, path_out_size, options->home_dir,
                               ".tabnine/mcp_servers.json");
    case CBM_AGENT_CLIENT_CONTINUE:
        return agent_resolve_continue(options, path_out, path_out_size);
    case CBM_AGENT_CLIENT_VISUAL_STUDIO:
        if (!options->is_windows) {
            return AGENT_RESULT_ABSENT;
        }
        return agent_join_path(path_out, path_out_size, options->home_dir, ".mcp.json");
    case CBM_AGENT_CLIENT_TRAE:
        return agent_resolve_existing_path(options, options->trae_config_path, path_out,
                                           path_out_size);
    case CBM_AGENT_CLIENT_ROO_CODE:
        return agent_resolve_existing_path(options, options->roo_config_path, path_out,
                                           path_out_size);
    case CBM_AGENT_CLIENT_AMAZON_Q:
        return agent_resolve_amazon_q(options, path_out, path_out_size);
    case CBM_AGENT_CLIENT_CODEBUDDY:
        return agent_resolve_codebuddy(options, path_out, path_out_size);
    case CBM_AGENT_CLIENT_IBM_BOB_IDE:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".bob/mcp.json");
    case CBM_AGENT_CLIENT_IBM_BOB_SHELL:
        return agent_join_path(path_out, path_out_size, options->home_dir,
                               ".bob/mcp_settings.json");
    case CBM_AGENT_CLIENT_POCHI:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".pochi/config.jsonc");
    case CBM_AGENT_CLIENT_PI:
        return AGENT_RESULT_ABSENT;
    case CBM_AGENT_CLIENT_SOURCEGRAPH_CODY:
        return agent_resolve_existing_path(options, options->cody_config_path, path_out,
                                           path_out_size);
    default:
        return AGENT_RESULT_ERROR;
    }
}

/* Resolve only client-specific installation directories. These markers prove
 * the client is present before its MCP file exists; shared editor/config roots
 * are deliberately excluded. Returns AGENT_RESULT_ABSENT for clients without
 * a safe marker. */
static int agent_client_marker_path(cbm_agent_client_id_t id,
                                    const cbm_agent_client_resolve_options_t *options,
                                    char *path_out, size_t path_out_size) {
    const char *config_home =
        options->xdg_config_home && options->xdg_config_home[0] ? options->xdg_config_home : NULL;
    switch (id) {
    case CBM_AGENT_CLIENT_QODER:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".qoder");
    case CBM_AGENT_CLIENT_KIMI:
        if (options->kimi_code_home && options->kimi_code_home[0]) {
            int written = snprintf(path_out, path_out_size, "%s", options->kimi_code_home);
            return written >= 0 && (size_t)written < path_out_size ? 0 : AGENT_RESULT_ERROR;
        }
        return agent_join_path(path_out, path_out_size, options->home_dir, ".kimi-code");
    case CBM_AGENT_CLIENT_GITLAB_DUO:
        if (options->glab_config_dir && options->glab_config_dir[0]) {
            return agent_join_path(path_out, path_out_size, options->glab_config_dir, "duo");
        }
        if (options->is_windows && options->appdata_dir && options->appdata_dir[0]) {
            return agent_join_path(path_out, path_out_size, options->appdata_dir, "GitLab/duo");
        }
        if (config_home) {
            return agent_join_path(path_out, path_out_size, config_home, "gitlab/duo");
        }
        return agent_join_path(path_out, path_out_size, options->home_dir, ".gitlab/duo");
    case CBM_AGENT_CLIENT_ROVO_DEV:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".rovodev");
    case CBM_AGENT_CLIENT_AMP:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".config/amp");
    case CBM_AGENT_CLIENT_DEVIN:
        if (options->is_windows && options->appdata_dir && options->appdata_dir[0]) {
            return agent_join_path(path_out, path_out_size, options->appdata_dir, "devin");
        }
        return agent_join_path(path_out, path_out_size, options->home_dir, ".config/devin");
    case CBM_AGENT_CLIENT_TABNINE:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".tabnine");
    case CBM_AGENT_CLIENT_AMAZON_Q:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".aws/amazonq");
    case CBM_AGENT_CLIENT_CODEBUDDY:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".codebuddy");
    case CBM_AGENT_CLIENT_IBM_BOB_IDE:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".bob/mcp.json");
    case CBM_AGENT_CLIENT_IBM_BOB_SHELL:
        return AGENT_RESULT_ABSENT;
    case CBM_AGENT_CLIENT_POCHI:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".pochi");
    case CBM_AGENT_CLIENT_PI:
        return agent_join_path(path_out, path_out_size, options->home_dir, ".pi/agent");
    default:
        return AGENT_RESULT_ABSENT;
    }
}

bool cbm_agent_client_detect(cbm_agent_client_id_t id,
                             const cbm_agent_client_resolve_options_t *options) {
    const cbm_agent_client_profile_t *profile = cbm_agent_client_by_id(id);
    if (!profile || !options) {
        return false;
    }
    char path[AGENT_CONFIG_PATH_CAPACITY];
    int resolved = cbm_agent_client_resolve_path(id, options, path, sizeof(path));
    if (id == CBM_AGENT_CLIENT_CONTINUE || id == CBM_AGENT_CLIENT_TRAE ||
        id == CBM_AGENT_CLIENT_ROO_CODE || id == CBM_AGENT_CLIENT_SOURCEGRAPH_CODY) {
        return resolved == 0 && agent_path_exists(options, path);
    }
    if (id == CBM_AGENT_CLIENT_VISUAL_STUDIO) {
        return options->is_windows && agent_command_exists(options, profile->detection_command);
    }
    char marker_path[AGENT_CONFIG_PATH_CAPACITY];
    int marker_resolved = agent_client_marker_path(id, options, marker_path, sizeof(marker_path));
    return (marker_resolved == 0 && agent_path_exists(options, marker_path)) ||
           (resolved == 0 && agent_path_exists(options, path)) ||
           agent_command_exists(options, profile->detection_command);
}

bool cbm_agent_client_cleanup_candidate(cbm_agent_client_id_t id,
                                        const cbm_agent_client_resolve_options_t *options) {
    if (cbm_agent_client_detect(id, options)) {
        return true;
    }
    if (id != CBM_AGENT_CLIENT_VISUAL_STUDIO || !options || !options->is_windows) {
        return false;
    }
    char path[AGENT_CONFIG_PATH_CAPACITY];
    return cbm_agent_client_resolve_path(id, options, path, sizeof(path)) == 0 &&
           agent_path_exists(options, path);
}

typedef struct {
    const char *data;
    size_t length;
    size_t position;
} agent_json_scanner_t;

static int agent_json_skip_space(agent_json_scanner_t *scanner) {
    for (;;) {
        while (scanner->position < scanner->length &&
               isspace((unsigned char)scanner->data[scanner->position])) {
            scanner->position++;
        }
        if (scanner->position + AGENT_UNIT_COUNT >= scanner->length ||
            scanner->data[scanner->position] != '/') {
            return 0;
        }
        if (scanner->data[scanner->position + AGENT_UNIT_COUNT] == '/') {
            scanner->position += AGENT_PAIR_COUNT;
            while (scanner->position < scanner->length &&
                   scanner->data[scanner->position] != '\n') {
                scanner->position++;
            }
        } else if (scanner->data[scanner->position + AGENT_UNIT_COUNT] == '*') {
            scanner->position += AGENT_PAIR_COUNT;
            while (scanner->position + AGENT_UNIT_COUNT < scanner->length &&
                   !(scanner->data[scanner->position] == '*' &&
                     scanner->data[scanner->position + AGENT_UNIT_COUNT] == '/')) {
                scanner->position++;
            }
            if (scanner->position + AGENT_UNIT_COUNT >= scanner->length) {
                return AGENT_RESULT_ERROR;
            }
            scanner->position += AGENT_PAIR_COUNT;
        } else {
            return 0;
        }
    }
}

static int agent_json_scan_string(agent_json_scanner_t *scanner, size_t *start_out,
                                  size_t *end_out) {
    if (scanner->position >= scanner->length ||
        (scanner->data[scanner->position] != '"' && scanner->data[scanner->position] != '\'')) {
        return AGENT_RESULT_ERROR;
    }
    char quote = scanner->data[scanner->position++];
    size_t start = scanner->position;
    bool escaped = false;
    while (scanner->position < scanner->length) {
        char current = scanner->data[scanner->position++];
        if (escaped) {
            escaped = false;
        } else if (current == '\\') {
            escaped = true;
        } else if (current == quote) {
            if (start_out) {
                *start_out = start;
            }
            if (end_out) {
                *end_out = scanner->position - AGENT_UNIT_COUNT;
            }
            return 0;
        } else if ((unsigned char)current < AGENT_ASCII_CONTROL_LIMIT) {
            return AGENT_RESULT_ERROR;
        }
    }
    return AGENT_RESULT_ERROR;
}

typedef enum {
    AGENT_JSON_EXPECT_OBJECT_KEY_OR_END,
    AGENT_JSON_EXPECT_OBJECT_COLON,
    AGENT_JSON_EXPECT_VALUE,
    AGENT_JSON_EXPECT_ARRAY_VALUE_OR_END,
    AGENT_JSON_EXPECT_SEPARATOR,
} agent_json_state_t;

typedef struct {
    char close;
    agent_json_state_t state;
} agent_json_container_t;

static int agent_json_push_container(agent_json_container_t *containers, size_t *count,
                                     unsigned depth, char open) {
    if (depth + *count >= AGENT_JSON_MAX_DEPTH) {
        return AGENT_RESULT_ERROR;
    }
    containers[*count] = (agent_json_container_t){
        .close = open == '{' ? '}' : ']',
        .state = open == '{' ? AGENT_JSON_EXPECT_OBJECT_KEY_OR_END
                             : AGENT_JSON_EXPECT_ARRAY_VALUE_OR_END,
    };
    (*count)++;
    return AGENT_RESULT_OK;
}

static int agent_json_scan_bare_key(agent_json_scanner_t *scanner) {
    size_t start = scanner->position;
    while (scanner->position < scanner->length &&
           (isalnum((unsigned char)scanner->data[scanner->position]) ||
            strchr("_$-", scanner->data[scanner->position]))) {
        scanner->position++;
    }
    return scanner->position > start ? AGENT_RESULT_OK : AGENT_RESULT_ERROR;
}

static int agent_json_scan_scalar(agent_json_scanner_t *scanner) {
    if (scanner->position >= scanner->length) {
        return AGENT_RESULT_ERROR;
    }
    char first = scanner->data[scanner->position];
    if (first == '"' || first == '\'') {
        return agent_json_scan_string(scanner, NULL, NULL);
    }
    size_t start = scanner->position;
    while (scanner->position < scanner->length &&
           !isspace((unsigned char)scanner->data[scanner->position]) &&
           !strchr(",]}", scanner->data[scanner->position])) {
        scanner->position++;
    }
    return scanner->position > start ? AGENT_RESULT_OK : AGENT_RESULT_ERROR;
}

static int agent_json_scan_object_key(agent_json_scanner_t *scanner,
                                      agent_json_container_t *container, char current,
                                      size_t *count) {
    if (current == container->close) {
        scanner->position++;
        (*count)--;
        return AGENT_RESULT_OK;
    }
    int result = (current == '"' || current == '\'') ? agent_json_scan_string(scanner, NULL, NULL)
                                                     : agent_json_scan_bare_key(scanner);
    if (result == AGENT_RESULT_OK) {
        container->state = AGENT_JSON_EXPECT_OBJECT_COLON;
    }
    return result;
}

static int agent_json_scan_container_value(agent_json_scanner_t *scanner,
                                           agent_json_container_t *containers, size_t *count,
                                           unsigned depth, char current) {
    agent_json_container_t *container = &containers[*count - AGENT_UNIT_COUNT];
    container->state = AGENT_JSON_EXPECT_SEPARATOR;
    if (current != '{' && current != '[') {
        return agent_json_scan_scalar(scanner);
    }
    int result = agent_json_push_container(containers, count, depth, current);
    if (result == AGENT_RESULT_OK) {
        scanner->position++;
    }
    return result;
}

static int agent_json_scan_separator(agent_json_scanner_t *scanner,
                                     agent_json_container_t *container, char current,
                                     size_t *count) {
    if (current == container->close) {
        scanner->position++;
        (*count)--;
        return AGENT_RESULT_OK;
    }
    if (current != ',') {
        return AGENT_RESULT_ERROR;
    }
    scanner->position++;
    container->state = container->close == '}' ? AGENT_JSON_EXPECT_OBJECT_KEY_OR_END
                                               : AGENT_JSON_EXPECT_ARRAY_VALUE_OR_END;
    return AGENT_RESULT_OK;
}

static int agent_json_scan_step(agent_json_scanner_t *scanner, agent_json_container_t *containers,
                                size_t *count, unsigned depth) {
    agent_json_container_t *container = &containers[*count - AGENT_UNIT_COUNT];
    if (agent_json_skip_space(scanner) != 0 || scanner->position >= scanner->length) {
        return AGENT_RESULT_ERROR;
    }
    char current = scanner->data[scanner->position];
    if (container->state == AGENT_JSON_EXPECT_OBJECT_KEY_OR_END) {
        return agent_json_scan_object_key(scanner, container, current, count);
    }
    if (container->state == AGENT_JSON_EXPECT_OBJECT_COLON) {
        if (current != ':') {
            return AGENT_RESULT_ERROR;
        }
        scanner->position++;
        container->state = AGENT_JSON_EXPECT_VALUE;
        return AGENT_RESULT_OK;
    }
    if (container->state == AGENT_JSON_EXPECT_ARRAY_VALUE_OR_END && current == container->close) {
        scanner->position++;
        (*count)--;
        return AGENT_RESULT_OK;
    }
    if (container->state == AGENT_JSON_EXPECT_VALUE ||
        container->state == AGENT_JSON_EXPECT_ARRAY_VALUE_OR_END) {
        return agent_json_scan_container_value(scanner, containers, count, depth, current);
    }
    return agent_json_scan_separator(scanner, container, current, count);
}

static int agent_json_scan_value(agent_json_scanner_t *scanner, unsigned depth) {
    agent_json_container_t containers[AGENT_JSON_MAX_DEPTH];
    size_t count = 0U;
    if (depth > AGENT_JSON_MAX_DEPTH || agent_json_skip_space(scanner) != 0 ||
        scanner->position >= scanner->length) {
        return AGENT_RESULT_ERROR;
    }
    char first = scanner->data[scanner->position];
    if (first != '{' && first != '[') {
        return agent_json_scan_scalar(scanner);
    }
    if (agent_json_push_container(containers, &count, depth, first) != AGENT_RESULT_OK) {
        return AGENT_RESULT_ERROR;
    }
    scanner->position++;
    while (count > 0U) {
        if (agent_json_scan_step(scanner, containers, &count, depth) != AGENT_RESULT_OK) {
            return AGENT_RESULT_ERROR;
        }
    }
    return AGENT_RESULT_OK;
}

static bool agent_json_hex_digit(unsigned char digit, unsigned *value_out) {
    if (digit >= '0' && digit <= '9') {
        *value_out = (unsigned)(digit - '0');
        return true;
    }
    if (digit >= 'a' && digit <= 'f') {
        *value_out = (unsigned)(digit - 'a' + AGENT_HEX_ALPHA_OFFSET);
        return true;
    }
    if (digit >= 'A' && digit <= 'F') {
        *value_out = (unsigned)(digit - 'A' + AGENT_HEX_ALPHA_OFFSET);
        return true;
    }
    return false;
}

static bool agent_json_decode_hex(const char *data, size_t end, size_t *cursor, size_t digits,
                                  unsigned *value_out) {
    if (end - *cursor < digits) {
        return false;
    }
    unsigned value = 0U;
    for (size_t i = 0U; i < digits; i++) {
        unsigned digit = 0U;
        if (!agent_json_hex_digit((unsigned char)data[*cursor], &digit)) {
            return false;
        }
        (*cursor)++;
        value = (value * AGENT_HEX_RADIX) + digit;
    }
    *value_out = value;
    return true;
}

static bool agent_json_decode_key_char(const char *data, size_t end, size_t *cursor,
                                       unsigned *value_out) {
    unsigned value = (unsigned char)data[(*cursor)++];
    if (value != '\\') {
        *value_out = value;
        return true;
    }
    if (*cursor >= end) {
        return false;
    }
    char escape = data[(*cursor)++];
    if (escape == 'u' || escape == 'x') {
        size_t digits = escape == 'u' ? AGENT_QUAD_COUNT : AGENT_PAIR_COUNT;
        return agent_json_decode_hex(data, end, cursor, digits, value_out);
    }
    if (!strchr("\\/\"'", escape)) {
        return false;
    }
    *value_out = (unsigned char)escape;
    return true;
}

static bool agent_json_key_equals(const char *data, size_t start, size_t end, const char *key) {
    if (end < start) {
        return false;
    }
    size_t key_offset = 0U;
    size_t key_len = strlen(key);
    for (size_t cursor = start; cursor < end;) {
        unsigned value = 0U;
        if (!agent_json_decode_key_char(data, end, &cursor, &value) || value > AGENT_ASCII_MAX ||
            key_offset >= key_len || (unsigned char)key[key_offset] != value) {
            return false;
        }
        key_offset++;
    }
    return key_offset == key_len;
}

/* Returns AGENT_RESULT_OK when found, AGENT_RESULT_ABSENT when absent, and
 * AGENT_RESULT_ERROR when malformed, ambiguous, or not an object. */
static int agent_json_open_object(agent_json_scanner_t *scanner, size_t object_end) {
    if (agent_json_skip_space(scanner) != 0 || scanner->position >= object_end ||
        scanner->data[scanner->position] != '{') {
        return AGENT_RESULT_ERROR;
    }
    scanner->position++;
    return agent_json_skip_space(scanner);
}

static int agent_json_scan_member_key(agent_json_scanner_t *scanner, size_t object_end,
                                      size_t *key_start, size_t *key_end) {
    if (scanner->position >= object_end) {
        return AGENT_RESULT_ERROR;
    }
    if (scanner->data[scanner->position] == '}') {
        scanner->position++;
        return AGENT_RESULT_ABSENT;
    }
    if (scanner->data[scanner->position] == '"' || scanner->data[scanner->position] == '\'') {
        return agent_json_scan_string(scanner, key_start, key_end);
    }
    *key_start = scanner->position;
    if (agent_json_scan_bare_key(scanner) != 0) {
        return AGENT_RESULT_ERROR;
    }
    *key_end = scanner->position;
    return AGENT_RESULT_OK;
}

static int agent_json_scan_member_value(agent_json_scanner_t *scanner, size_t object_end,
                                        size_t *value_start, size_t *value_end) {
    if (agent_json_skip_space(scanner) != 0 || scanner->position >= object_end ||
        scanner->data[scanner->position] != ':') {
        return AGENT_RESULT_ERROR;
    }
    scanner->position++;
    if (agent_json_skip_space(scanner) != 0) {
        return AGENT_RESULT_ERROR;
    }
    *value_start = scanner->position;
    if (agent_json_scan_value(scanner, AGENT_UNIT_COUNT) != 0) {
        return AGENT_RESULT_ERROR;
    }
    *value_end = scanner->position;
    return AGENT_RESULT_OK;
}

static int agent_json_member_separator(agent_json_scanner_t *scanner, size_t object_end) {
    if (agent_json_skip_space(scanner) != 0 || scanner->position >= object_end) {
        return AGENT_RESULT_ERROR;
    }
    char separator = scanner->data[scanner->position];
    scanner->position++;
    if (separator == '}') {
        return AGENT_RESULT_ABSENT;
    }
    if (separator != ',') {
        return AGENT_RESULT_ERROR;
    }
    return agent_json_skip_space(scanner);
}

static int agent_json_find_member(const char *data, size_t object_start, size_t object_end,
                                  const char *key, size_t *value_start, size_t *value_end) {
    agent_json_scanner_t scanner = {.data = data, .length = object_end, .position = object_start};
    if (agent_json_open_object(&scanner, object_end) != 0) {
        return AGENT_RESULT_ERROR;
    }
    bool found = false;
    for (;;) {
        size_t key_start = 0U;
        size_t key_end = 0U;
        int key_result = agent_json_scan_member_key(&scanner, object_end, &key_start, &key_end);
        if (key_result == AGENT_RESULT_ABSENT) {
            return found ? AGENT_RESULT_OK : AGENT_RESULT_ABSENT;
        }
        if (key_result != AGENT_RESULT_OK) {
            return AGENT_RESULT_ERROR;
        }
        size_t start;
        size_t end;
        if (agent_json_scan_member_value(&scanner, object_end, &start, &end) != 0) {
            return AGENT_RESULT_ERROR;
        }
        if (agent_json_key_equals(data, key_start, key_end, key)) {
            if (found) {
                return AGENT_RESULT_ERROR;
            }
            found = true;
            *value_start = start;
            *value_end = end;
        }
        int separator_result = agent_json_member_separator(&scanner, object_end);
        if (separator_result == AGENT_RESULT_ABSENT) {
            return found ? AGENT_RESULT_OK : AGENT_RESULT_ABSENT;
        }
        if (separator_result != AGENT_RESULT_OK) {
            return AGENT_RESULT_ERROR;
        }
    }
}

static int agent_json_find_entry(const char *document, size_t length, const char *section,
                                 size_t *entry_start, size_t *entry_end) {
    size_t bom =
        length >= AGENT_TRIPLE_COUNT && (unsigned char)document[0] == AGENT_UTF8_BOM_FIRST_BYTE &&
                (unsigned char)document[AGENT_SECOND_INDEX] == AGENT_UTF8_BOM_SECOND_BYTE &&
                (unsigned char)document[AGENT_THIRD_INDEX] == AGENT_UTF8_BOM_THIRD_BYTE
            ? AGENT_TRIPLE_COUNT
            : 0U;
    agent_json_scanner_t scanner = {.data = document, .length = length, .position = bom};
    if (agent_json_skip_space(&scanner) != 0) {
        return AGENT_RESULT_ERROR;
    }
    size_t root_start = scanner.position;
    if (agent_json_scan_value(&scanner, 0U) != 0 || agent_json_skip_space(&scanner) != 0 ||
        scanner.position != length || document[root_start] != '{') {
        return AGENT_RESULT_ERROR;
    }
    size_t object_start = root_start;
    size_t object_end = scanner.position;
    if (section) {
        size_t section_start = 0U;
        size_t section_end = 0U;
        int section_result = agent_json_find_member(document, root_start, object_end, section,
                                                    &section_start, &section_end);
        if (section_result != 0) {
            return section_result;
        }
        if (document[section_start] != '{') {
            return AGENT_RESULT_ERROR;
        }
        object_start = section_start;
        object_end = section_end;
    }
    return agent_json_find_member(document, object_start, object_end, AGENT_ENTRY_KEY, entry_start,
                                  entry_end);
}

static char *agent_json_escape(const char *value) {
    size_t length = strlen(value);
    if (length > (SIZE_MAX - AGENT_UNIT_COUNT) / AGENT_JSON_ESCAPE_LENGTH) {
        return NULL;
    }
    char *escaped = (char *)malloc((length * AGENT_JSON_ESCAPE_LENGTH) + AGENT_UNIT_COUNT);
    if (!escaped) {
        return NULL;
    }
    size_t output = 0U;
    for (size_t i = 0U; i < length; i++) {
        unsigned char byte = (unsigned char)value[i];
        if (byte == '"' || byte == '\\') {
            escaped[output++] = '\\';
            escaped[output++] = (char)byte;
        } else if (byte == '\b') {
            escaped[output++] = '\\';
            escaped[output++] = 'b';
        } else if (byte == '\f') {
            escaped[output++] = '\\';
            escaped[output++] = 'f';
        } else if (byte == '\n') {
            escaped[output++] = '\\';
            escaped[output++] = 'n';
        } else if (byte == '\r') {
            escaped[output++] = '\\';
            escaped[output++] = 'r';
        } else if (byte == '\t') {
            escaped[output++] = '\\';
            escaped[output++] = 't';
        } else if (byte < AGENT_ASCII_CONTROL_LIMIT) {
            int written = snprintf(escaped + output, 7U, "\\u%04x", (unsigned)byte);
            if (written != (int)AGENT_JSON_ESCAPE_LENGTH) {
                free(escaped);
                return NULL;
            }
            output += AGENT_JSON_ESCAPE_LENGTH;
        } else {
            escaped[output++] = (char)byte;
        }
    }
    escaped[output] = '\0';
    return escaped;
}

static char *agent_json_canonical(cbm_agent_client_id_t id, const char *binary_path) {
    char *escaped = agent_json_escape(binary_path);
    if (!escaped) {
        return NULL;
    }
    const char *extra = "";
    if (id == CBM_AGENT_CLIENT_GITLAB_DUO || id == CBM_AGENT_CLIENT_VISUAL_STUDIO) {
        extra = ", \"type\": \"stdio\"";
    } else if (id == CBM_AGENT_CLIENT_ROVO_DEV) {
        extra = ", \"transport\": \"stdio\"";
    }
    size_t needed = strlen(escaped) + strlen(extra) + AGENT_JSON_CANONICAL_OVERHEAD;
    char *canonical = (char *)malloc(needed);
    if (canonical) {
        int written =
            snprintf(canonical, needed, "{ \"command\": \"%s\", \"args\": []%s }", escaped, extra);
        if (written < 0 || (size_t)written >= needed) {
            free(canonical);
            canonical = NULL;
        }
    }
    free(escaped);
    return canonical;
}

static char *agent_json_compact(const char *data, size_t length) {
    char *output = (char *)malloc(length + AGENT_UNIT_COUNT);
    if (!output) {
        return NULL;
    }
    size_t written = 0U;
    char quote = '\0';
    bool escaped = false;
    for (size_t i = 0U; i < length; i++) {
        char current = data[i];
        if (quote) {
            output[written++] = current;
            if (escaped) {
                escaped = false;
            } else if (current == '\\') {
                escaped = true;
            } else if (current == quote) {
                quote = '\0';
            }
        } else if (current == '"' || current == '\'') {
            quote = current;
            output[written++] = current;
        } else if (isspace((unsigned char)current)) {
            continue;
        } else if (current == '/' && i + AGENT_UNIT_COUNT < length &&
                   data[i + AGENT_UNIT_COUNT] == '/') {
            i += AGENT_PAIR_COUNT;
            while (i < length && data[i] != '\n') {
                i++;
            }
        } else if (current == '/' && i + AGENT_UNIT_COUNT < length &&
                   data[i + AGENT_UNIT_COUNT] == '*') {
            i += AGENT_PAIR_COUNT;
            while (i + AGENT_UNIT_COUNT < length &&
                   !(data[i] == '*' && data[i + AGENT_UNIT_COUNT] == '/')) {
                i++;
            }
            i++;
        } else {
            output[written++] = current;
        }
    }
    output[written] = '\0';
    return output;
}

static bool agent_json_owned(const char *document, size_t start, size_t end,
                             const char *canonical) {
    char *actual_compact = agent_json_compact(document + start, end - start);
    char *canonical_compact = agent_json_compact(canonical, strlen(canonical));
    bool equal =
        actual_compact && canonical_compact && strcmp(actual_compact, canonical_compact) == 0;
    free(actual_compact);
    free(canonical_compact);
    return equal;
}

static const char *agent_json_section(cbm_agent_client_id_t id) {
    if (id == CBM_AGENT_CLIENT_AMP) {
        return NULL;
    }
    if (id == CBM_AGENT_CLIENT_VISUAL_STUDIO) {
        return "servers";
    }
    if (id == CBM_AGENT_CLIENT_SOURCEGRAPH_CODY) {
        return "cody.mcpServers";
    }
    if (id == CBM_AGENT_CLIENT_POCHI) {
        return "mcp";
    }
    return "mcpServers";
}

static int agent_json_edit(cbm_agent_client_id_t id, const char *config_path,
                           const char *binary_path, bool remove) {
    char *canonical = agent_json_canonical(id, binary_path);
    if (!canonical) {
        return CBM_AGENT_EDIT_ERROR;
    }
    char *document = NULL;
    size_t length = 0U;
    int read_result = cbm_json_like_read_document(config_path, &document, &length);
    if (read_result < 0) {
        free(canonical);
        return CBM_AGENT_EDIT_ERROR;
    }
    size_t entry_start = 0U;
    size_t entry_end = 0U;
    int find_result = read_result == AGENT_RESULT_ABSENT
                          ? AGENT_RESULT_ABSENT
                          : agent_json_find_entry(document, length, agent_json_section(id),
                                                  &entry_start, &entry_end);
    if (find_result < 0) {
        free(document);
        free(canonical);
        return CBM_AGENT_EDIT_ERROR;
    }
    if (find_result == 0 && !agent_json_owned(document, entry_start, entry_end, canonical)) {
        free(document);
        free(canonical);
        return CBM_AGENT_EDIT_FOREIGN;
    }
    if ((remove && find_result == AGENT_RESULT_ABSENT) || (!remove && find_result == 0)) {
        free(document);
        free(canonical);
        return CBM_AGENT_EDIT_OK;
    }
    const char *section = agent_json_section(id);
    const char *path[AGENT_SECTION_PATH_DEPTH] = {section};
    int edit_result =
        remove ? cbm_json_like_remove_entry_if_unchanged(config_path, path,
                                                         section ? AGENT_UNIT_COUNT : 0U,
                                                         AGENT_ENTRY_KEY, document, length)
               : cbm_json_like_upsert_entry_if_unchanged(
                     config_path, path, section ? AGENT_UNIT_COUNT : 0U, AGENT_ENTRY_KEY, canonical,
                     read_result == AGENT_RESULT_ABSENT ? NULL : document, length);
    free(document);
    free(canonical);
    return edit_result == 0 ? CBM_AGENT_EDIT_OK : CBM_AGENT_EDIT_ERROR;
}

static size_t agent_next_line(const char *data, size_t length, size_t start, size_t *content_end) {
    size_t end = start;
    while (end < length && data[end] != '\n') {
        end++;
    }
    *content_end = end;
    return end < length ? end + AGENT_UNIT_COUNT : end;
}

static size_t agent_line_indent(const char *data, size_t line_start, size_t line_end) {
    size_t indent = 0U;
    while (line_start + indent < line_end && data[line_start + indent] == ' ') {
        indent++;
    }
    return indent;
}

static bool agent_yaml_top_level_key(const char *data, size_t start, size_t end, const char *key,
                                     bool *empty_value) {
    if (end > start && data[end - AGENT_UNIT_COUNT] == '\r') {
        end--;
    }
    size_t key_len = strlen(key);
    if (end - start < key_len + AGENT_UNIT_COUNT || memcmp(data + start, key, key_len) != 0 ||
        data[start + key_len] != ':') {
        return false;
    }
    size_t cursor = start + key_len + AGENT_UNIT_COUNT;
    while (cursor < end && data[cursor] == ' ') {
        cursor++;
    }
    *empty_value = cursor == end || data[cursor] == '#';
    return true;
}

static bool agent_yaml_named_item(const char *data, size_t start, size_t end,
                                  const char *expected_name) {
    if (end > start && data[end - AGENT_UNIT_COUNT] == '\r') {
        end--;
    }
    static const char prefix[] = "  - name:";
    if (end - start < sizeof(prefix) - AGENT_UNIT_COUNT ||
        memcmp(data + start, prefix, sizeof(prefix) - AGENT_UNIT_COUNT) != 0) {
        return false;
    }
    const char *value = data + start + sizeof(prefix) - AGENT_UNIT_COUNT;
    size_t value_len = end - start - (sizeof(prefix) - AGENT_UNIT_COUNT);
    char *decoded = agent_trim_copy(value, value_len);
    if (!decoded) {
        return false;
    }
    char *comment = strchr(decoded, '#');
    if (comment) {
        char *before = comment;
        while (before > decoded && isspace((unsigned char)before[AGENT_PREVIOUS_INDEX])) {
            before--;
        }
        *before = '\0';
    }
    bool matches = strcmp(decoded, expected_name) == 0;
    free(decoded);
    return matches;
}

static char *agent_splice(const char *document, size_t length, size_t start, size_t end,
                          const char *replacement) {
    size_t replacement_len = strlen(replacement);
    if (start > end || end > length ||
        replacement_len > SIZE_MAX - (length - (end - start)) - AGENT_UNIT_COUNT) {
        return NULL;
    }
    size_t new_length = length - (end - start) + replacement_len;
    char *updated = (char *)malloc(new_length + AGENT_UNIT_COUNT);
    if (!updated) {
        return NULL;
    }
    memcpy(updated, document, start);
    memcpy(updated + start, replacement, replacement_len);
    memcpy(updated + start + replacement_len, document + end, length - end);
    updated[new_length] = '\0';
    return updated;
}

typedef struct {
    size_t section_start;
    size_t section_body;
    size_t section_end;
    size_t sections;
    bool invalid;
} agent_continue_section_t;

typedef struct {
    size_t item_start;
    size_t item_end;
    size_t items;
} agent_continue_item_t;

static char *agent_continue_canonical(const char *binary_path, const char *eol) {
    char *quoted = NULL;
    if (cbm_yaml_encode_double_quoted_scalar(binary_path, &quoted) != 0) {
        return NULL;
    }
    size_t size =
        strlen(quoted) + (strlen(eol) * AGENT_TRIPLE_COUNT) + AGENT_CONTINUE_CANONICAL_OVERHEAD;
    char *canonical = (char *)malloc(size);
    if (!canonical) {
        free(quoted);
        return NULL;
    }
    int written = snprintf(canonical, size,
                           "  - name: codebase-memory-mcp%s    command: %s%s"
                           "    args: []%s",
                           eol, quoted, eol, eol);
    free(quoted);
    if (written < 0 || (size_t)written >= size) {
        free(canonical);
        return NULL;
    }
    return canonical;
}

static agent_continue_section_t agent_continue_find_section(const char *document, size_t length) {
    agent_continue_section_t result = {
        .section_start = SIZE_MAX,
        .section_body = SIZE_MAX,
        .section_end = length,
        .sections = 0U,
        .invalid = false,
    };
    for (size_t cursor = 0U; cursor < length;) {
        size_t line_end = 0U;
        size_t next = agent_next_line(document, length, cursor, &line_end);
        size_t indent = agent_line_indent(document, cursor, line_end);
        bool blank_or_comment = cursor + indent >= line_end || document[cursor + indent] == '#';
        bool empty_value = false;
        if (indent == 0U &&
            agent_yaml_top_level_key(document, cursor, line_end, "mcpServers", &empty_value)) {
            result.sections++;
            result.section_start = cursor;
            result.section_body = next;
            result.section_end = length;
            result.invalid = result.invalid || !empty_value;
        } else if (result.sections == AGENT_UNIT_COUNT && result.section_body != SIZE_MAX &&
                   cursor >= result.section_body && indent == 0U && !blank_or_comment) {
            result.section_end = cursor;
            result.section_body = SIZE_MAX;
        }
        cursor = next;
    }
    return result;
}

static size_t agent_continue_item_end(const char *document, size_t length, size_t start,
                                      size_t section_end) {
    size_t end_scan = start;
    while (end_scan < section_end) {
        size_t candidate_end = 0U;
        size_t candidate_next = agent_next_line(document, length, end_scan, &candidate_end);
        size_t indent = agent_line_indent(document, end_scan, candidate_end);
        if (indent <= AGENT_PAIR_COUNT && end_scan + indent < candidate_end &&
            document[end_scan + indent] == '-') {
            break;
        }
        end_scan = candidate_next;
    }
    return end_scan;
}

static agent_continue_item_t agent_continue_find_item(const char *document, size_t length,
                                                      const agent_continue_section_t *section) {
    agent_continue_item_t result = {.item_start = SIZE_MAX, .item_end = SIZE_MAX, .items = 0U};
    if (section->sections != AGENT_UNIT_COUNT) {
        return result;
    }
    size_t discarded_end = 0U;
    for (size_t scan = agent_next_line(document, length, section->section_start, &discarded_end);
         scan < section->section_end;) {
        size_t line_end = 0U;
        size_t next = agent_next_line(document, length, scan, &line_end);
        if (agent_yaml_named_item(document, scan, line_end, AGENT_ENTRY_KEY)) {
            result.items++;
            result.item_start = scan;
            result.item_end = agent_continue_item_end(document, length, next, section->section_end);
        }
        scan = next;
    }
    return result;
}

static char *agent_continue_insert_into_section(const char *document, size_t length,
                                                const agent_continue_section_t *section,
                                                const char *canonical, const char *eol) {
    const char *prefix =
        section->section_end > 0U && document[section->section_end - AGENT_UNIT_COUNT] != '\n' ? eol
                                                                                               : "";
    size_t size = strlen(prefix) + strlen(canonical) + AGENT_UNIT_COUNT;
    char *insertion = (char *)malloc(size);
    if (!insertion) {
        return NULL;
    }
    snprintf(insertion, size, "%s%s", prefix, canonical);
    char *updated =
        agent_splice(document, length, section->section_end, section->section_end, insertion);
    free(insertion);
    return updated;
}

static char *agent_continue_append_section(const char *document, size_t length,
                                           const char *canonical, const char *eol) {
    const char *prefix = length > 0U && document[length - AGENT_UNIT_COUNT] != '\n' ? eol : "";
    size_t size =
        strlen(prefix) + strlen("mcpServers:") + strlen(eol) + strlen(canonical) + AGENT_UNIT_COUNT;
    char *append = (char *)malloc(size);
    if (!append) {
        return NULL;
    }
    snprintf(append, size, "%smcpServers:%s%s", prefix, eol, canonical);
    char *updated = agent_splice(document, length, length, length, append);
    free(append);
    return updated;
}

static int agent_continue_edit(const char *config_path, const char *binary_path, bool remove) {
    char *document = NULL;
    size_t length = 0U;
    if (cbm_json_like_read_document(config_path, &document, &length) != 0 || !document) {
        free(document);
        return CBM_AGENT_EDIT_NOT_APPLICABLE;
    }
    const char *eol = strstr(document, "\r\n") ? "\r\n" : "\n";
    char *canonical = agent_continue_canonical(binary_path, eol);
    if (!canonical) {
        free(document);
        return CBM_AGENT_EDIT_ERROR;
    }
    agent_continue_section_t section = agent_continue_find_section(document, length);
    if (section.sections > AGENT_UNIT_COUNT || section.invalid) {
        free(canonical);
        free(document);
        return CBM_AGENT_EDIT_ERROR;
    }
    agent_continue_item_t item = agent_continue_find_item(document, length, &section);
    if (item.items > AGENT_UNIT_COUNT) {
        free(canonical);
        free(document);
        return CBM_AGENT_EDIT_ERROR;
    }
    if (item.items == AGENT_UNIT_COUNT) {
        size_t canonical_len = strlen(canonical);
        if (item.item_end - item.item_start != canonical_len ||
            memcmp(document + item.item_start, canonical, canonical_len) != 0) {
            free(canonical);
            free(document);
            return CBM_AGENT_EDIT_FOREIGN;
        }
        if (!remove) {
            free(canonical);
            free(document);
            return CBM_AGENT_EDIT_OK;
        }
    } else if (remove) {
        free(canonical);
        free(document);
        return CBM_AGENT_EDIT_OK;
    }

    char *updated = NULL;
    if (item.items == AGENT_UNIT_COUNT) {
        updated = agent_splice(document, length, item.item_start, item.item_end, "");
    } else if (section.sections == AGENT_UNIT_COUNT) {
        updated = agent_continue_insert_into_section(document, length, &section, canonical, eol);
    } else {
        updated = agent_continue_append_section(document, length, canonical, eol);
    }
    int result = updated && cbm_text_write_owned_document_if_unchanged(config_path, updated,
                                                                       document, length) == 0
                     ? CBM_AGENT_EDIT_OK
                     : CBM_AGENT_EDIT_ERROR;
    free(updated);
    free(canonical);
    free(document);
    return result;
}

static bool agent_json_client(cbm_agent_client_id_t id) {
    return (unsigned)id < CBM_AGENT_CLIENT_COUNT && id != CBM_AGENT_CLIENT_CONTINUE &&
           id != CBM_AGENT_CLIENT_PI;
}

int cbm_agent_client_install_mcp(cbm_agent_client_id_t id, const char *config_path,
                                 const char *binary_path) {
    if (!config_path || config_path[0] == '\0' || !binary_path || binary_path[0] == '\0' ||
        !cbm_agent_client_by_id(id)) {
        return CBM_AGENT_EDIT_ERROR;
    }
    if (id == CBM_AGENT_CLIENT_CONTINUE) {
        return agent_continue_edit(config_path, binary_path, false);
    }
    return agent_json_client(id) ? agent_json_edit(id, config_path, binary_path, false)
                                 : CBM_AGENT_EDIT_NOT_APPLICABLE;
}

int cbm_agent_client_remove_mcp(cbm_agent_client_id_t id, const char *config_path,
                                const char *binary_path) {
    if (!config_path || config_path[0] == '\0' || !binary_path || binary_path[0] == '\0' ||
        !cbm_agent_client_by_id(id)) {
        return CBM_AGENT_EDIT_ERROR;
    }
    if (id == CBM_AGENT_CLIENT_CONTINUE) {
        return agent_continue_edit(config_path, binary_path, true);
    }
    return agent_json_client(id) ? agent_json_edit(id, config_path, binary_path, true)
                                 : CBM_AGENT_EDIT_NOT_APPLICABLE;
}

static int agent_install_callback(cbm_agent_client_id_t id, const char *config_path,
                                  const char *binary_path) {
    return cbm_agent_client_install_mcp(id, config_path, binary_path);
}

static int agent_remove_callback(cbm_agent_client_id_t id, const char *config_path,
                                 const char *binary_path) {
    return cbm_agent_client_remove_mcp(id, config_path, binary_path);
}
