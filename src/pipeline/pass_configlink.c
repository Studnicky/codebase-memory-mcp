/*
 * pass_configlink.c — Config ↔ Code linking strategies (pre-dump pass).
 *
 * Three strategies link config files to code symbols:
 *   1. Key→Symbol: normalized config key matches code function/variable name
 *   2. Dep→Import: package manifest dependency matches IMPORTS edge target
 *   3. File→Ref: source code string literal references config file path
 *
 * Operates on the graph buffer before dump to .db file.
 */
#include "foundation/constants.h"
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/hash_table.h"
#include "foundation/log.h"
#include "foundation/compat.h"
#include "foundation/dyn_array.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "foundation/compat_regex.h"

/* ── Config link confidence scores ───────────────────────────────── */
/* Serialized decimal precision for a CONFIGURES edge's "confidence" prop. */
enum { CONFIGLINK_CONFIDENCE_DECIMALS = 2 };
/* Strategy 1: Key→Symbol matching */
#define CONF_KEY_EXACT 0.85
#define CONF_KEY_SUBSTRING 0.75
/* Strategy 2: Dep→Import matching */
#define CONF_DEP_EXACT 0.95
#define CONF_DEP_QN_SUBSTR 0.80
/* Strategy 3: File→Ref matching */
#define CONF_FILE_FULLPATH 0.90
#define CONF_FILE_BASENAME 0.70

/* ── Manifest / dep section tables ──────────────────────────────── */

static bool is_manifest_file(const char *basename) {
    static const char *names[] = {"Cargo.toml",       "package.json",  "go.mod",
                                  "requirements.txt", "Gemfile",       "build.gradle",
                                  "pom.xml",          "composer.json", NULL};
    for (int i = 0; names[i]; i++) {
        if (strcmp(basename, names[i]) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_dep_section(const char *s) {
    static const char *secs[] = {"dependencies",     "devdependencies",    "peerdependencies",
                                 "dev-dependencies", "build-dependencies", NULL};
    for (int i = 0; secs[i]; i++) {
        if (cbm_strcasestr(s, secs[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/* ── Strategy 1: Config Key → Code Symbol ───────────────────────── */

/* Canonical candidate order (determinism). The label indexes both collectors
 * below walk are gbuf insertion order = parallel-extraction merge order,
 * which varies run to run. Sorting by a pure content key first is what keeps
 * candidate and pattern-group iteration order — and therefore the emitted
 * CONFIGURES edges — a function of the inputs rather than of worker
 * scheduling. Tie-breaks stay content-only: node ids are handed out in merge
 * order, so an id tie-break belongs in no canonical comparator. */
enum {
    CANON_CMP_LESS = -1,  /* qsort: left sorts before right */
    CANON_CMP_GREATER = 1 /* qsort: left sorts after right */
};

/* Box a small non-negative integer as a hash-table value (memcpy avoids the
 * strict-aliasing UB of a bare int-to-pointer cast). */
static inline void *intptr_to_ptr(intptr_t v) {
    void *p;
    memcpy(&p, &v, sizeof(p));
    return p;
}

static int cmp_node_ptr_canonical(const void *pa, const void *pb) {
    const cbm_gbuf_node_t *a = *(const cbm_gbuf_node_t *const *)pa;
    const cbm_gbuf_node_t *b = *(const cbm_gbuf_node_t *const *)pb;
    const char *qa = a->qualified_name;
    const char *qb = b->qualified_name;
    int r = strcmp(qa, qb);
    if (r != 0) {
        return r;
    }
    const char *fa = a->file_path;
    const char *fb = b->file_path;
    r = strcmp(fa, fb);
    if (r != 0) {
        return r;
    }
    if (a->start_line != b->start_line) {
        return a->start_line < b->start_line ? CANON_CMP_LESS : CANON_CMP_GREATER;
    }
    const char *na = a->name;
    const char *nb = b->name;
    return strcmp(na, nb);
}

/* Heap copy of `nodes` sorted by cmp_node_ptr_canonical. Returns NULL (and
 * leaves the caller on the unsorted borrowed array) only on allocation
 * failure, which degrades determinism but never correctness. */
static const cbm_gbuf_node_t **canonical_node_copy(const cbm_gbuf_node_t *const *nodes, int count) {
    if (!nodes || count <= 0) {
        return NULL;
    }
    const cbm_gbuf_node_t **sorted = malloc((size_t)count * sizeof(*sorted));
    if (!sorted) {
        return NULL;
    }
    memcpy(sorted, nodes, (size_t)count * sizeof(*sorted));
    qsort(sorted, (size_t)count, sizeof(*sorted), cmp_node_ptr_canonical);
    return sorted;
}

typedef struct {
    cbm_node_id_t node_id;
    char normalized[CBM_SZ_256];
    char name[CBM_SZ_256];
} config_entry_t;

typedef CBM_DYN_ARRAY(config_entry_t) config_entry_list_t;

/* True when every underscore-separated token in `norm` is at least 3 chars. */
static bool all_tokens_long_enough(const char *norm) {
    const char *p = norm;
    while (*p) {
        const char *end = strchr(p, '_');
        size_t tlen = end ? (size_t)(end - p) : strlen(p);
        if (tlen < CBM_SZ_3) {
            return false;
        }
        p = end ? end + SKIP_ONE : p + tlen;
    }
    return true;
}

/* A config-side candidate: lives in a config file and normalizes to ≥2 tokens
 * of ≥3 chars each. Fills `norm_out` when it qualifies. */
static bool config_candidate_key(const cbm_gbuf_node_t *node, char *norm_out, size_t norm_sz) {
    if (!cbm_has_config_extension(node->file_path)) {
        return false;
    }
    if (cbm_normalize_config_key(node->name, norm_out, norm_sz) < PAIR_LEN) {
        return false;
    }
    return all_tokens_long_enough(norm_out);
}

/* Collect config Variable nodes with ≥2 tokens, each ≥3 chars. Unbounded —
 * grows to fit the repo instead of dropping candidates past a fixed cap. */
static config_entry_list_t collect_config_entries(const cbm_gbuf_node_t *const *vars,
                                                  int var_count) {
    config_entry_list_t out = {0};
    const cbm_gbuf_node_t **sorted = canonical_node_copy(vars, var_count);
    if (sorted) {
        vars = sorted;
    }
    for (int i = 0; i < var_count; i++) {
        char norm[CBM_SZ_256];
        if (!config_candidate_key(vars[i], norm, sizeof(norm))) {
            continue;
        }
        config_entry_t entry;
        entry.node_id = vars[i]->id;
        snprintf(entry.normalized, sizeof(entry.normalized), "%s", norm);
        snprintf(entry.name, sizeof(entry.name), "%s", vars[i]->name);
        cbm_da_push(&out, entry);
    }
    free((void *)sorted);
    return out;
}

/* Collect code nodes (Function/Variable/Class/Struct) not from config files. */
typedef struct {
    cbm_node_id_t node_id;
    char normalized[CBM_SZ_256];
} code_entry_t;

typedef CBM_DYN_ARRAY(code_entry_t) code_entry_list_t;

/* A code-side candidate: lives outside config files and normalizes to a
 * non-empty key. Fills `norm_out` when it qualifies. */
static bool code_candidate_key(const cbm_gbuf_node_t *node, char *norm_out, size_t norm_sz) {
    if (cbm_has_config_extension(node->file_path)) {
        return false;
    }
    int tokens = cbm_normalize_config_key(node->name, norm_out, norm_sz);
    return tokens != 0 && norm_out[0] != '\0';
}

/* Append every qualifying node of one label, in canonical order. */
static void collect_code_label(cbm_gbuf_t *gb, const char *label, code_entry_list_t *out) {
    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    if (cbm_gbuf_find_by_label(gb, label, &nodes, &count) != 0) {
        return;
    }

    /* Canonical order — see cmp_node_ptr_canonical. Emission order then stays
     * a pure function of content rather than of gbuf merge order. */
    const cbm_gbuf_node_t **sorted = canonical_node_copy(nodes, count);
    const cbm_gbuf_node_t *const *scan = sorted ? sorted : nodes;

    for (int i = 0; i < count; i++) {
        char norm[CBM_SZ_256];
        if (!code_candidate_key(scan[i], norm, sizeof(norm))) {
            continue;
        }
        code_entry_t entry;
        entry.node_id = scan[i]->id;
        snprintf(entry.normalized, sizeof(entry.normalized), "%s", norm);
        cbm_da_push(out, entry);
    }
    /* gbuf data is borrowed — only the sorted copy is owned */
    free((void *)sorted);
}

static code_entry_list_t collect_code_entries(cbm_gbuf_t *gb) {
    code_entry_list_t out = {0};
    /* "Struct" alongside "Class": a config key may name a Go/Rust/Swift/D struct
     * type, which is now labelled "Struct" — keep it linkable. */
    static const char *labels[] = {"Function", "Variable", "Class", "Struct", NULL};

    for (int li = 0; labels[li]; li++) {
        collect_code_label(gb, labels[li], &out);
    }
    return out;
}

/* ── Strategy 1: multi-pattern scan (Aho-Corasick) ──────────────────
 * Distinct config `normalized` strings are patterns; each code `normalized`
 * string is scanned once. This replaces an O(config × code) nested loop with
 * a linear (sum-of-pattern-lengths + sum-of-text-lengths) scan. */

typedef CBM_DYN_ARRAY(int) int_list_t;

typedef struct {
    const char *pattern;   /* borrowed: a config_entries[*].normalized buffer */
    int_list_t config_idx; /* indices into config_entries sharing this pattern */
} pattern_group_t;

typedef CBM_DYN_ARRAY(pattern_group_t) pattern_group_list_t;

enum { PATTERN_GROUP_NONE = -1 }; /* find_or_create_group: allocation failed, no group index */

/* Look up (or create) the pattern group for `norm` in `pattern_to_group`.
 * Returns the group index, or PATTERN_GROUP_NONE on allocation failure (OOM:
 * caller drops the entry rather than crash). */
static int find_or_create_group(pattern_group_list_t *groups, CBMHashTable *pattern_to_group,
                                const char *norm) {
    void *found = cbm_ht_get(pattern_to_group, norm);
    if (found) {
        return (int)((intptr_t)found - SKIP_ONE);
    }

    pattern_group_t group = {0};
    group.pattern = norm;
    int gi = groups->count;
    cbm_da_push(groups, group);
    if (groups->count <= gi) {
        return PATTERN_GROUP_NONE; /* OOM: push dropped silently, group not recorded */
    }
    cbm_ht_set(pattern_to_group, norm, intptr_to_ptr(gi + SKIP_ONE));
    return gi;
}

/* Group config entries by distinct normalized string, preserving both group
 * discovery order and, within a group, config_entries order — so pattern
 * iteration order stays a pure function of the (already canonical) input. */
static pattern_group_list_t build_pattern_groups(const config_entry_t *config_entries,
                                                 int config_count) {
    pattern_group_list_t groups = {0};
    CBMHashTable *pattern_to_group = cbm_ht_create((uint32_t)config_count);
    if (!pattern_to_group) {
        return groups;
    }

    for (int ci = 0; ci < config_count; ci++) {
        int gi = find_or_create_group(&groups, pattern_to_group, config_entries[ci].normalized);
        if (!groups.items || gi < 0 || gi >= groups.count) {
            continue;
        }
        cbm_da_push(&groups.items[gi].config_idx, ci);
    }

    cbm_ht_free(pattern_to_group);
    return groups;
}

static void free_pattern_groups(pattern_group_list_t *groups) {
    for (int i = 0; i < groups->count; i++) {
        cbm_da_free(&groups->items[i].config_idx);
    }
    cbm_da_free(groups);
}

enum {
    AC_ALPHABET_SIZE = 256, /* index children over the full byte range */
    AC_ROOT_STATE = 0,
    AC_NO_STATE = -1,
};

typedef struct {
    int32_t *trans;       /* [state * AC_ALPHABET_SIZE + byte] -> next state (goto function) */
    int32_t *fail;        /* [state] -> fail-link state */
    int32_t *match_group; /* [state] -> pattern group ending exactly here, or AC_NO_STATE */
    int32_t *output_link; /* [state] -> nearest ancestor state with a match, or AC_NO_STATE */
    int32_t state_count;
} ac_automaton_t;

/* Trie-insert one pattern (goto edges only — fail/output links come later). */
static void ac_insert(ac_automaton_t *ac, const char *pattern, int group_idx) {
    int32_t state = AC_ROOT_STATE;
    for (const unsigned char *p = (const unsigned char *)pattern; *p != '\0'; p++) {
        int32_t *edge = &ac->trans[((size_t)state * AC_ALPHABET_SIZE) + *p];
        if (*edge == AC_NO_STATE) {
            *edge = ac->state_count++;
        }
        state = *edge;
    }
    ac->match_group[state] = group_idx;
}

/* Finalize one BFS-frontier state: collapse missing trie edges into the
 * automaton's goto function via the fail link, and compute fail/output links
 * for its real children. Split out of ac_build_links to keep both under the
 * cognitive-complexity ceiling. */
static void ac_expand_state(ac_automaton_t *ac, int32_t u, int32_t *queue, int *qtail) {
    for (int c = 0; c < AC_ALPHABET_SIZE; c++) {
        int32_t *edge = &ac->trans[((size_t)u * AC_ALPHABET_SIZE) + (size_t)c];
        int32_t fail_edge = ac->trans[((size_t)ac->fail[u] * AC_ALPHABET_SIZE) + (size_t)c];
        if (*edge == AC_NO_STATE) {
            *edge = fail_edge;
        } else {
            ac->fail[*edge] = fail_edge;
            ac->output_link[*edge] =
                ac->match_group[fail_edge] != AC_NO_STATE ? fail_edge : ac->output_link[fail_edge];
            queue[(*qtail)++] = *edge;
        }
    }
}

/* BFS over the trie: converts trie-only goto edges into the full automaton
 * transition function and computes fail/output links for every state. */
static void ac_build_links(ac_automaton_t *ac, int32_t *queue) {
    int qhead = 0;
    int qtail = 0;

    /* Depth-1 states fail to the root; missing root edges self-loop so
     * goto(root, c) is defined for every byte. */
    for (int c = 0; c < AC_ALPHABET_SIZE; c++) {
        int32_t *edge = &ac->trans[((size_t)AC_ROOT_STATE * AC_ALPHABET_SIZE) + (size_t)c];
        if (*edge == AC_NO_STATE) {
            *edge = AC_ROOT_STATE;
        } else {
            ac->fail[*edge] = AC_ROOT_STATE;
            queue[qtail++] = *edge;
        }
    }

    while (qhead < qtail) {
        int32_t u = queue[qhead++];
        ac_expand_state(ac, u, queue, &qtail);
    }
}

/* Builds the automaton over every distinct pattern in `groups`. On any
 * allocation failure, frees everything allocated so far and returns a
 * zeroed automaton (ac.trans == NULL signals "unusable" to the caller). */
static ac_automaton_t ac_build(const pattern_group_list_t *groups) {
    ac_automaton_t ac = {0};
    int64_t max_states = SKIP_ONE; /* root */
    for (int i = 0; i < groups->count; i++) {
        max_states += (int64_t)strlen(groups->items[i].pattern);
    }

    ac.trans = malloc((size_t)max_states * AC_ALPHABET_SIZE * sizeof(*ac.trans));
    ac.fail = calloc((size_t)max_states, sizeof(*ac.fail));
    ac.match_group = malloc((size_t)max_states * sizeof(*ac.match_group));
    ac.output_link = malloc((size_t)max_states * sizeof(*ac.output_link));
    int32_t *queue = malloc((size_t)max_states * sizeof(*queue));

    if (!ac.trans || !ac.fail || !ac.match_group || !ac.output_link || !queue) {
        free(ac.trans);
        free(ac.fail);
        free(ac.match_group);
        free(ac.output_link);
        free(queue);
        return (ac_automaton_t){0};
    }

    /* 0xFF bytes give -1 in every int32_t lane: AC_NO_STATE. */
    memset(ac.trans, 0xFF, (size_t)max_states * AC_ALPHABET_SIZE * sizeof(*ac.trans));
    memset(ac.match_group, 0xFF, (size_t)max_states * sizeof(*ac.match_group));
    memset(ac.output_link, 0xFF, (size_t)max_states * sizeof(*ac.output_link));
    ac.state_count = SKIP_ONE;

    for (int i = 0; i < groups->count; i++) {
        ac_insert(&ac, groups->items[i].pattern, i);
    }
    ac_build_links(&ac, queue);
    free(queue);
    return ac;
}

static void ac_free(ac_automaton_t *ac) {
    free(ac->trans);
    free(ac->fail);
    free(ac->match_group);
    free(ac->output_link);
    *ac = (ac_automaton_t){0};
}

/* Emit one CONFIGURES edge per config entry in `group_idx`, at the confidence
 * dictated by whether the pattern spans the whole code string. */
static int emit_group_edges(cbm_gbuf_t *gb, const pattern_group_list_t *groups,
                            const config_entry_t *config_entries, const code_entry_t *code_entry,
                            int32_t group_idx, size_t code_norm_len) {
    const pattern_group_t *group = &groups->items[group_idx];
    double confidence =
        strlen(group->pattern) == code_norm_len ? CONF_KEY_EXACT : CONF_KEY_SUBSTRING;

    int edges = 0;
    for (int k = 0; k < group->config_idx.count; k++) {
        const config_entry_t *ce = &config_entries[group->config_idx.items[k]];
        cbm_gbuf_prop_t props[] = {
            {.key = "strategy", .kind = CBM_EDGE_PROP_STRING, .text = "key_symbol"},
            {.key = "confidence",
             .kind = CBM_EDGE_PROP_NUMBER,
             .number = confidence,
             .decimals = CONFIGLINK_CONFIDENCE_DECIMALS},
            {.key = "config_key", .kind = CBM_EDGE_PROP_STRING, .text = ce->name},
        };
        cbm_gbuf_insert_edge_props(
            gb, (cbm_edge_endpoints_t){.source = code_entry->node_id, .target = ce->node_id},
            "CONFIGURES", props, (int)(sizeof(props) / sizeof(props[0])));
        edges++;
    }
    return edges;
}

/* Scans one code entry's normalized name through the automaton once,
 * emitting edges for each distinct pattern group matched — deduped via
 * last_seen_code_idx so a pattern occurring twice in one name still yields
 * one edge per config entry. */
static int ac_scan_code_entry(cbm_gbuf_t *gb, const ac_automaton_t *ac,
                              const pattern_group_list_t *groups,
                              const config_entry_t *config_entries, const code_entry_t *code_entry,
                              int32_t *last_seen_code_idx, int co) {
    int edges = 0;
    size_t text_len = strlen(code_entry->normalized);
    int32_t state = AC_ROOT_STATE;

    for (const unsigned char *p = (const unsigned char *)code_entry->normalized; *p != '\0'; p++) {
        state = ac->trans[((size_t)state * AC_ALPHABET_SIZE) + *p];
        int32_t out = ac->match_group[state] != AC_NO_STATE ? state : ac->output_link[state];
        while (out != AC_NO_STATE) {
            int32_t gi = ac->match_group[out];
            if (last_seen_code_idx[gi] != co) {
                last_seen_code_idx[gi] = co;
                edges += emit_group_edges(gb, groups, config_entries, code_entry, gi, text_len);
            }
            out = ac->output_link[out];
        }
    }
    return edges;
}

static int strategy_key_symbols(cbm_gbuf_t *gb) {
    /* Get all Variable nodes */
    const cbm_gbuf_node_t **vars = NULL;
    int var_count = 0;
    if (cbm_gbuf_find_by_label(gb, "Variable", &vars, &var_count) != 0) {
        return 0;
    }

    config_entry_list_t config_entries = collect_config_entries(vars, var_count);
    if (config_entries.count == 0) {
        free(config_entries.items);
        return 0;
    }

    code_entry_list_t code_entries = collect_code_entries(gb);
    pattern_group_list_t groups = build_pattern_groups(config_entries.items, config_entries.count);
    ac_automaton_t ac = ac_build(&groups);

    int edge_count = 0;
    if (ac.trans && groups.count > 0) {
        int32_t *last_seen_code_idx = malloc((size_t)groups.count * sizeof(*last_seen_code_idx));
        if (last_seen_code_idx) {
            for (int i = 0; i < groups.count; i++) {
                last_seen_code_idx[i] = AC_NO_STATE;
            }
            for (int co = 0; co < code_entries.count; co++) {
                edge_count += ac_scan_code_entry(gb, &ac, &groups, config_entries.items,
                                                 &code_entries.items[co], last_seen_code_idx, co);
            }
            free(last_seen_code_idx);
        }
    }

    ac_free(&ac);
    free_pattern_groups(&groups);
    free(code_entries.items);
    free(config_entries.items);
    return edge_count;
}

/* ── Strategy 2: Dependency → Import ────────────────────────────── */

typedef struct {
    cbm_node_id_t node_id;
    char name[CBM_SZ_256];
} dep_entry_t;

/* Extract basename from a file path. */
static const char *path_basename(const char *path) {
    if (!path) {
        return "";
    }
    const char *slash = strrchr(path, '/');
    return slash ? slash + SKIP_ONE : path;
}

/* Check if a Cargo.toml QN contains a dependency section in any dotted part. */
static bool is_cargo_dep_section(const char *qn) {
    char qn_copy[CBM_SZ_512];
    snprintf(qn_copy, sizeof(qn_copy), "%s", qn);
    char *saveptr = NULL;
    char *part = strtok_r(qn_copy, ".", &saveptr);
    while (part) {
        char lower[CBM_SZ_128];
        size_t plen = strlen(part);
        if (plen >= sizeof(lower)) {
            plen = sizeof(lower) - SKIP_ONE;
        }
        for (size_t j = 0; j < plen; j++) {
            lower[j] = (char)tolower((unsigned char)part[j]);
        }
        lower[plen] = '\0';

        static const char *dep_secs[] = {"dependencies",       "devdependencies",
                                         "peerdependencies",   "dev-dependencies",
                                         "build-dependencies", NULL};
        for (int k = 0; dep_secs[k]; k++) {
            if (strcmp(lower, dep_secs[k]) == 0) {
                return true;
            }
        }
        part = strtok_r(NULL, ".", &saveptr);
    }
    return false;
}

static int collect_manifest_deps(const cbm_gbuf_node_t *const *vars, int var_count,
                                 dep_entry_t *out, int max_out) {
    int n = 0;
    for (int i = 0; i < var_count && n < max_out; i++) {
        const char *base = path_basename(vars[i]->file_path);
        if (!is_manifest_file(base)) {
            continue;
        }

        bool is_dep = vars[i]->qualified_name && is_dep_section(vars[i]->qualified_name);

        if (!is_dep && strcmp(base, "Cargo.toml") == 0 && vars[i]->qualified_name) {
            is_dep = is_cargo_dep_section(vars[i]->qualified_name);
        }

        if (is_dep) {
            out[n].node_id = vars[i]->id;
            snprintf(out[n].name, sizeof(out[n].name), "%s", vars[i]->name);
            n++;
        }
    }
    return n;
}

/* Lowercase a string into buf. */
static void lowercase_into(char *buf, size_t bufsize, const char *src) {
    size_t len = src ? strlen(src) : 0;
    for (size_t j = 0; j < len && j < bufsize - SKIP_ONE; j++) {
        buf[j] = (char)tolower((unsigned char)src[j]);
    }
    buf[len < bufsize ? len : bufsize - SKIP_ONE] = '\0';
}

/* Match a dep name (lowercased) against an import target node.
 * Returns confidence > 0 on match, 0 on no match. */
static double match_dep_to_import(const cbm_gbuf_node_t *target, const char *dep_lower) {
    char target_lower[CBM_SZ_256];
    lowercase_into(target_lower, sizeof(target_lower), target->name);

    if (strcmp(target_lower, dep_lower) == 0) {
        return CONF_DEP_EXACT;
    }
    if (target->qualified_name) {
        char qn_lower[CBM_SZ_512];
        lowercase_into(qn_lower, sizeof(qn_lower), target->qualified_name);
        if (strstr(qn_lower, dep_lower) != NULL) {
            return CONF_DEP_QN_SUBSTR;
        }
    }
    return 0.0;
}

static int strategy_dep_imports(cbm_gbuf_t *gb) {
    const cbm_gbuf_node_t **vars = NULL;
    int var_count = 0;
    if (cbm_gbuf_find_by_label(gb, "Variable", &vars, &var_count) != 0) {
        return 0;
    }

    dep_entry_t deps[CBM_SZ_2K];
    int dep_count = collect_manifest_deps(vars, var_count, deps, CBM_SZ_2K);

    if (dep_count == 0) {
        return 0;
    }

    /* Get all IMPORTS edges */
    const cbm_gbuf_edge_t **imports = NULL;
    int import_count = 0;
    if (cbm_gbuf_find_edges_by_type(gb, "IMPORTS", &imports, &import_count) != 0) {
        return 0;
    }

    int edge_count = 0;

    for (int di = 0; di < dep_count; di++) {
        char dep_lower[CBM_SZ_256];
        lowercase_into(dep_lower, sizeof(dep_lower), deps[di].name);

        for (int ii = 0; ii < import_count; ii++) {
            const cbm_gbuf_node_t *target = cbm_gbuf_find_by_id(gb, imports[ii]->target_id);
            if (!target) {
                continue;
            }

            const cbm_gbuf_node_t *source = cbm_gbuf_find_by_id(gb, imports[ii]->source_id);
            if (!source) {
                continue;
            }

            double confidence = match_dep_to_import(target, dep_lower);
            if (confidence > 0.0) {
                cbm_gbuf_prop_t props[] = {
                    {.key = "strategy", .kind = CBM_EDGE_PROP_STRING, .text = "dependency_import"},
                    {.key = "confidence",
                     .kind = CBM_EDGE_PROP_NUMBER,
                     .number = confidence,
                     .decimals = CONFIGLINK_CONFIDENCE_DECIMALS},
                    {.key = "dep_name", .kind = CBM_EDGE_PROP_STRING, .text = deps[di].name},
                };
                cbm_gbuf_insert_edge_props(
                    gb, (cbm_edge_endpoints_t){.source = source->id, .target = deps[di].node_id},
                    "CONFIGURES", props, (int)(sizeof(props) / sizeof(props[0])));
                edge_count++;
            }
        }
    }

    /* gbuf data is borrowed — no free */
    return edge_count;
}

/* ── Strategy 3: Config File Path → Code String Reference ───────── */

typedef struct {
    const char *key;
    cbm_node_id_t node_id;
} path_map_t;

/* Match a ref_path against config module maps. Returns target node_id (0 = no match). */

int cbm_pipeline_pass_configlink(cbm_pipeline_ctx_t *ctx) {
    cbm_gbuf_t *gb = ctx->gbuf;
    /* Early exit: check if any config files exist in the project. */
    bool has_config = false;

    const cbm_gbuf_node_t **vars_check = NULL;
    int var_check_count = 0;
    if (!has_config && cbm_gbuf_find_by_label(gb, "Variable", &vars_check, &var_check_count) == 0) {
        for (int i = 0; i < var_check_count; i++) {
            if (cbm_has_config_extension(vars_check[i]->file_path)) {
                has_config = true;
                break;
            }
        }
    }

    if (!has_config) {
        const cbm_gbuf_node_t **mods_check = NULL;
        int mod_check_count = 0;
        if (cbm_gbuf_find_by_label(gb, "Module", &mods_check, &mod_check_count) == 0) {
            for (int i = 0; i < mod_check_count; i++) {
                if (cbm_has_config_extension(mods_check[i]->file_path)) {
                    has_config = true;
                    break;
                }
            }
        }
    }

    if (!has_config) {
        cbm_log_info("configlinker.skip", "reason", "no_config_files");
        return 0;
    }

    char buf1[CBM_SZ_16];
    char buf2[CBM_SZ_16];
    char buf3[CBM_SZ_16];
    char buf4[CBM_SZ_16];

    int key_edges = strategy_key_symbols(gb);
    snprintf(buf1, sizeof(buf1), "%d", key_edges);
    cbm_log_info("configlinker.strategy", "name", "key_symbol", "edges", buf1);

    int dep_edges = strategy_dep_imports(gb);
    snprintf(buf2, sizeof(buf2), "%d", dep_edges);
    cbm_log_info("configlinker.strategy", "name", "dep_import", "edges", buf2);

    int ref_edges = 0;
    if (ctx->repo_path) {
        /* File refs: no longer reads from disk — config file path matching
         * is handled by CONFIGURES edges created during resolution. */
        ref_edges = 0;
    }
    snprintf(buf3, sizeof(buf3), "%d", ref_edges);
    cbm_log_info("configlinker.strategy", "name", "file_ref", "edges", buf3);

    snprintf(buf4, sizeof(buf4), "%d", key_edges + dep_edges + ref_edges);
    cbm_log_info("configlinker.done", "total", buf4);

    return key_edges + dep_edges + ref_edges;
}
