#include "git/git_context.h"

#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/subprocess.h"
#include "foundation/str_util.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

enum {
    GIT_OUTPUT_MAX = 4096,
};

static const char *const GIT_SHOW_TOPLEVEL[] = {"rev-parse", "--show-toplevel", NULL};
static const char *const GIT_GIT_DIR[] = {"rev-parse", "--git-dir", NULL};
static const char *const GIT_GIT_COMMON_DIR[] = {"rev-parse", "--git-common-dir", NULL};
static const char *const GIT_HEAD[] = {"rev-parse", "--verify", "HEAD", NULL};
static const char *const GIT_BRANCH[] = {"symbolic-ref", "--quiet", "--short", "HEAD", NULL};
static const char *const GIT_ABSOLUTE_COMMON_DIR[] = {
    "rev-parse", "--path-format=absolute", "--git-common-dir", NULL};
static const char *const GIT_UPSTREAM_BASE[] = {"merge-base", "HEAD", "@{upstream}", NULL};

static char *git_strdup(const char *s) {
    if (!s) {
        s = "";
    }
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (!out) {
        return NULL;
    }
    memcpy(out, s, n);
    return out;
}

static void trim_newlines(char *s) {
    if (!s) {
        return;
    }
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

static bool git_validate_repo_path(const char *repo_path) {
    return cbm_validate_shell_path_arg(repo_path);
}

static bool git_capture_output_create(char path[CBM_SZ_4K]) {
    int n = snprintf(path, CBM_SZ_4K, "%s/cbm-git-context-XXXXXX", cbm_tmpdir());
    if (n <= 0 || n >= CBM_SZ_4K) {
        path[0] = '\0';
        return false;
    }
    int descriptor = cbm_mkstemp(path);
    if (descriptor < 0) {
        path[0] = '\0';
        return false;
    }
#ifdef _WIN32
    bool closed = _close(descriptor) == 0;
#else
    bool closed = close(descriptor) == 0;
#endif
    if (!closed) {
        (void)cbm_unlink(path);
        path[0] = '\0';
    }
    return closed;
}

static bool git_capture_cancelled(const atomic_int *cancel_requested) {
    return cancel_requested &&
           atomic_load_explicit(cancel_requested, memory_order_acquire) != 0;
}

static int git_capture(const char *repo_path, const char *const *git_args,
                       const atomic_int *cancel_requested, char **out) {
    if (!out) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    if (!repo_path || !git_args || !git_args[0] || !git_validate_repo_path(repo_path) ||
        git_capture_cancelled(cancel_requested)) {
        return CBM_NOT_FOUND;
    }

    const char *argv[8] = {"git", "-C", repo_path, NULL, NULL, NULL, NULL, NULL};
    size_t index = 3;
    while (git_args[index - 3]) {
        if (index + 1 >= sizeof(argv) / sizeof(argv[0])) {
            return CBM_NOT_FOUND;
        }
        argv[index] = git_args[index - 3];
        index++;
    }

    char output_path[CBM_SZ_4K] = {0};
    if (!git_capture_output_create(output_path)) {
        return CBM_NOT_FOUND;
    }

    cbm_proc_opts_t options = {
        .bin = argv[0],
        .argv = argv,
        .log_file = output_path,
        .quiet_timeout_ms = 0,
        .cancel_grace_ms = CBM_SUBPROCESS_DEFAULT_CANCEL_GRACE_MS,
        .delete_log_on_exit = false,
    };
    cbm_subprocess_t *process = NULL;
    if (cbm_subprocess_spawn(&options, &process) != 0) {
        (void)cbm_unlink(output_path);
        return CBM_NOT_FOUND;
    }

    cbm_proc_result_t result = {0};
    for (;;) {
        if (git_capture_cancelled(cancel_requested)) {
            (void)cbm_subprocess_request_cancel(process);
        }
        cbm_proc_poll_t state = cbm_subprocess_poll(process, &result);
        if (state == CBM_PROC_POLL_TERMINAL) {
            break;
        }
        if (state == CBM_PROC_POLL_ERROR) {
            (void)cbm_subprocess_request_cancel(process);
        }
        cbm_usleep(10000);
    }
    cbm_subprocess_destroy(process);

    bool usable = result.tree_quiesced && !result.supervision_failed &&
                  !result.cancellation_requested && !git_capture_cancelled(cancel_requested) &&
                  result.outcome == CBM_PROC_CLEAN;
    FILE *fp = usable ? cbm_fopen(output_path, "rb") : NULL;
    char buf[GIT_OUTPUT_MAX];
    bool captured = false;
    if (fp) {
        captured = fgets(buf, sizeof(buf), fp) != NULL;
        captured = fclose(fp) == 0 && captured;
    }
    if (!captured) {
        (void)cbm_unlink(output_path);
        return CBM_NOT_FOUND;
    }

    trim_newlines(buf);
    (void)cbm_unlink(output_path);
    if (buf[0] == '\0') {
        return CBM_NOT_FOUND;
    }
    *out = git_strdup(buf);
    return *out ? 0 : CBM_NOT_FOUND;
}

static bool path_is_absolute(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    if (path[0] == '/') {
        return true;
    }
#ifdef _WIN32
    return isalpha((unsigned char)path[0]) && path[1] == ':';
#else
    return false;
#endif
}

static char *join_root_relative(const char *root, const char *rel) {
    if (!root || !root[0]) {
        return git_strdup(rel);
    }
    int n = snprintf(NULL, 0, "%s/%s", root, rel);
    if (n < 0) {
        return NULL;
    }
    char *out = (char *)malloc((size_t)n + 1);
    if (!out) {
        return NULL;
    }
    snprintf(out, (size_t)n + 1, "%s/%s", root, rel);
    return out;
}

/* Derive the canonical repo root.
 *
 * Preferred (git 2.31+): abs_common_dir is `git rev-parse --path-format=absolute
 * --git-common-dir` — git's OWN absolute, canonical common-dir. Because a main
 * repo and its linked worktree both ask the same git binary, they resolve to the
 * IDENTICAL path, so canonical_root is consistent across worktrees AND platforms
 * with no manual join or realpath/_fullpath — which diverged under msys vs native
 * path representations (#659 root cause, and the worktree==main-root breakage in
 * test_pipeline.c git_context_linked_worktree). git also resolves the relative
 * ".." internally, so the subdirectory case (#659) is fixed here too.
 *
 * Fallback (git < 2.31, no --path-format → abs_common_dir empty): the relative
 * --git-common-dir is relative to input_path (the -C dir), so join against it and
 * realpath-normalize the "..". Unix only — on Windows git emits an absolute
 * common-dir so this branch isn't reached in practice, and _fullpath there
 * reintroduces the msys divergence. */
static char *derive_canonical_root(const char *input_path, const char *worktree_root,
                                   const char *git_common_dir, const char *abs_common_dir) {
    char *root = NULL;
    if (abs_common_dir && abs_common_dir[0] && path_is_absolute(abs_common_dir)) {
        root = git_strdup(abs_common_dir);
        if (!root) {
            return NULL;
        }
    } else {
        const char *src = git_common_dir && git_common_dir[0] ? git_common_dir : worktree_root;
        if (!src) {
            return git_strdup("");
        }
#ifndef _WIN32
        root = path_is_absolute(src) ? git_strdup(src) : join_root_relative(input_path, src);
        if (!root) {
            return NULL;
        }
        {
            char resolved[4096];
            if (realpath(root, resolved) != NULL) {
                free(root);
                root = git_strdup(resolved);
                if (!root) {
                    return NULL;
                }
            }
        }
#else
        (void)input_path;
        root = path_is_absolute(src) ? git_strdup(src) : join_root_relative(worktree_root, src);
        if (!root) {
            return NULL;
        }
#endif
    }

    size_t len = strlen(root);
    while (len > 1 && (root[len - 1] == '/' || root[len - 1] == '\\')) {
        root[--len] = '\0';
    }

    if (len >= 5 && strcmp(root + len - 5, "/.git") == 0) {
        root[len - 5] = '\0';
    }
#ifdef _WIN32
    else if (len >= 5 && strcmp(root + len - 5, "\\.git") == 0) {
        root[len - 5] = '\0';
    }
#endif

    return root;
}

static char *slug_from_branch(const char *branch, bool detached) {
    const char *fallback = detached ? "detached" : "working-tree";
    const char *src = detached ? fallback : (branch && branch[0] ? branch : fallback);
    size_t len = strlen(src);
    char *slug = (char *)malloc(len + 1);
    if (!slug) {
        return NULL;
    }

    size_t j = 0;
    bool in_dash = false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.') {
            if (j == 0 && c == '-') {
                in_dash = true;
                continue;
            }
            slug[j++] = (char)c;
            in_dash = false;
        } else if (j > 0 && !in_dash) {
            slug[j++] = '-';
            in_dash = true;
        }
    }
    while (j > 0 && slug[j - 1] == '-') {
        j--;
    }
    slug[j] = '\0';

    if (slug[0] == '\0') {
        free(slug);
        return git_strdup(fallback);
    }
    return slug;
}

void cbm_git_context_free(cbm_git_context_t *ctx) {
    if (!ctx) {
        return;
    }
    free(ctx->input_path);
    free(ctx->worktree_root);
    free(ctx->git_dir);
    free(ctx->git_common_dir);
    free(ctx->canonical_root);
    free(ctx->branch);
    free(ctx->branch_slug);
    free(ctx->head_sha);
    free(ctx->base_sha);
    memset(ctx, 0, sizeof(*ctx));
}

int cbm_git_context_resolve_cancellable(const char *path, const atomic_int *cancel_requested,
                                        cbm_git_context_t *out) {
    if (!out) {
        return CBM_NOT_FOUND;
    }

    memset(out, 0, sizeof(*out));
    if (!path || !path[0]) {
        return CBM_NOT_FOUND;
    }

    out->input_path = git_strdup(path);
    if (!out->input_path) {
        return CBM_NOT_FOUND;
    }

    struct stat st;
    out->root_exists = (stat(path, &st) == 0);
    if (!out->root_exists) {
        return 0;
    }

    if (git_capture(path, GIT_SHOW_TOPLEVEL, cancel_requested, &out->worktree_root) != 0) {
        out->is_git = false;
        return 0;
    }
    out->is_git = true;

    if (git_capture(path, GIT_GIT_DIR, cancel_requested, &out->git_dir) != 0) {
        out->git_dir = git_strdup("");
    }
    if (git_capture(path, GIT_GIT_COMMON_DIR, cancel_requested, &out->git_common_dir) != 0) {
        out->git_common_dir = git_strdup("");
    }
    if (git_capture(path, GIT_HEAD, cancel_requested, &out->head_sha) != 0) {
        out->head_sha = git_strdup("");
    }

    if (git_capture(path, GIT_BRANCH, cancel_requested, &out->branch) != 0) {
        out->branch = git_strdup("DETACHED");
        out->is_detached = true;
    }

    out->is_worktree =
        out->git_dir && out->git_common_dir && strcmp(out->git_dir, out->git_common_dir) != 0;
    /* git 2.31+ canonical absolute common-dir (best-effort; NULL on older git,
     * where derive_canonical_root falls back to the relative common-dir). */
    char *abs_common_dir = NULL;
    (void)git_capture(path, GIT_ABSOLUTE_COMMON_DIR, cancel_requested, &abs_common_dir);
    out->canonical_root =
        derive_canonical_root(path, out->worktree_root, out->git_common_dir, abs_common_dir);
    free(abs_common_dir);
    out->branch_slug = slug_from_branch(out->branch, out->is_detached);
    if (git_capture(path, GIT_UPSTREAM_BASE, cancel_requested, &out->base_sha) != 0) {
        out->base_sha = git_strdup("");
    }

    if (!out->git_dir || !out->git_common_dir || !out->head_sha || !out->branch ||
        !out->canonical_root || !out->branch_slug || !out->base_sha) {
        cbm_git_context_free(out);
        return CBM_NOT_FOUND;
    }

    return 0;
}

int cbm_git_context_resolve(const char *path, cbm_git_context_t *out) {
    return cbm_git_context_resolve_cancellable(path, NULL, out);
}

char *cbm_git_context_branch_qn(const char *project_name, const cbm_git_context_t *ctx) {
    const char *project = project_name && project_name[0] ? project_name : "project";
    const char *slug = "working-tree";
    if (ctx) {
        if (ctx->is_detached) {
            slug = "detached";
        } else if (ctx->is_git && ctx->branch_slug && ctx->branch_slug[0]) {
            slug = ctx->branch_slug;
        }
    }

    int n = snprintf(NULL, 0, "%s.__branch__.%s", project, slug);
    if (n < 0) {
        return NULL;
    }
    char *out = (char *)malloc((size_t)n + 1);
    if (!out) {
        return NULL;
    }
    snprintf(out, (size_t)n + 1, "%s.__branch__.%s", project, slug);
    return out;
}

static bool append_fmt_checked(char *buf, int buf_size, int *off, const char *fmt, ...) {
    if (!buf || !off || buf_size <= 0 || *off < 0 || *off >= buf_size) {
        return false;
    }

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, (size_t)(buf_size - *off), fmt, ap);
    va_end(ap);
    if (n < 0 || n >= buf_size - *off) {
        buf[buf_size - 1] = '\0';
        return false;
    }
    *off += n;
    return true;
}

static int json_escaped_len(const char *src) {
    if (!src) {
        return 0;
    }
    int len = 0;
    for (int i = 0; src[i]; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') {
            len += 2;
        } else if (c < 0x20) {
            len += 6; /* \u00XX */
        } else {
            len++;
        }
    }
    return len;
}

static bool json_append_bool(char *buf, int buf_size, int *off, const char *name, bool value,
                             bool comma) {
    return append_fmt_checked(buf, buf_size, off, "\"%s\":%s%s", name, value ? "true" : "false",
                              comma ? "," : "");
}

static bool json_append_string(char *buf, int buf_size, int *off, const char *name,
                               const char *value, bool comma) {
    int needed = json_escaped_len(value ? value : "");
    char *escaped = malloc((size_t)needed + 1);
    if (!escaped) {
        return false;
    }
    int actual = cbm_json_escape(escaped, needed + 1, value ? value : "");
    bool ok = actual == needed && append_fmt_checked(buf, buf_size, off, "\"%s\":\"%s\"%s", name,
                                                     escaped, comma ? "," : "");
    free(escaped);
    return ok;
}

int cbm_git_context_props_json(const cbm_git_context_t *ctx, char *buf, int buf_size) {
    if (!ctx || !buf || buf_size <= 0) {
        return 0;
    }

    int off = 0;
    bool ok =
        append_fmt_checked(buf, buf_size, &off, "{") &&
        json_append_bool(buf, buf_size, &off, "is_git", ctx->is_git, true) &&
        json_append_bool(buf, buf_size, &off, "is_worktree", ctx->is_worktree, true) &&
        json_append_bool(buf, buf_size, &off, "is_detached", ctx->is_detached, true) &&
        json_append_bool(buf, buf_size, &off, "root_exists", ctx->root_exists, true) &&
        json_append_string(buf, buf_size, &off, "canonical_root", ctx->canonical_root, true) &&
        json_append_string(buf, buf_size, &off, "worktree_root", ctx->worktree_root, true) &&
        json_append_string(buf, buf_size, &off, "git_common_dir", ctx->git_common_dir, true) &&
        json_append_string(buf, buf_size, &off, "branch", ctx->branch, true) &&
        json_append_string(buf, buf_size, &off, "head_sha", ctx->head_sha, true) &&
        json_append_string(buf, buf_size, &off, "base_sha", ctx->base_sha, false) &&
        append_fmt_checked(buf, buf_size, &off, "}");
    if (!ok) {
        if (buf_size > 0) {
            buf[0] = '\0';
        }
        return 0;
    }
    return off;
}
