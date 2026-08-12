#include "extract_unified.h"
#include "arena.h" // cbm_arena_sprintf
#include "cbm.h"   // CBMExtractCtx
#include "helpers.h"
#include "lang_specs.h"      // CBMLangSpec, cbm_lang_spec, CBM_LANG_*
#include "tree_sitter/api.h" // TSNode, TSTreeCursor, ts_tree_cursor_*, ts_node_*
#include "foundation/constants.h"

enum {
    MAX_INFRA_BINDINGS = 8,
    MAX_AGDA_LHS_HEAD_DESCENT = 8,
    MAX_NASM_LABEL_ANCESTOR_LEVELS = 4,
    MAX_NASM_LABEL_WRAPPER_DESCENT = 2,
};

#include <limits.h> // INT_MAX
#include <stdint.h> // uint32_t, uint8_t
#include <string.h>

// --- Scope stack management ---

static bool ensure_scope_capacity(WalkState *state) {
    if (state->scope_top < state->scope_capacity) {
        return true;
    }
    /* scope_capacity is int (compared against int scope_top throughout this
     * module) — bound before doubling so the multiply cannot overflow. */
    if (state->scope_capacity > INT_MAX / PAIR_LEN) {
        return false;
    }
    int new_capacity = state->scope_capacity > 0 ? state->scope_capacity * PAIR_LEN : MAX_SCOPES;
    CBMWalkScope *grown =
        (CBMWalkScope *)cbm_arena_alloc(state->arena, (size_t)new_capacity * sizeof(*grown));
    if (!grown) {
        return false;
    }
    memcpy(grown, state->scopes, (size_t)state->scope_top * sizeof(*grown));
    state->scopes = grown;
    state->scope_capacity = new_capacity;
    return true;
}

static const CBMLexicalScope *lexical_scope_by_id(const WalkState *state, uint32_t id) {
    return state && id > 0 && id <= (uint32_t)state->lexical_scope_count
               ? &state->lexical_scopes[id - SKIP_ONE]
               : NULL;
}

static CBMLexicalScope *mutable_lexical_scope_by_id(WalkState *state, uint32_t id) {
    return state && id > 0 && id <= (uint32_t)state->lexical_scope_count
               ? &state->lexical_scopes[id - SKIP_ONE]
               : NULL;
}

static uint32_t current_lexical_scope_id(const WalkState *state) {
    if (!state) {
        return 0;
    }
    for (int i = state->scope_top - SKIP_ONE; i >= 0; i--) {
        if (state->scopes[i].lexical_scope_id != 0) {
            return state->scopes[i].lexical_scope_id;
        }
    }
    return state->root_lexical_scope_id;
}

static bool ensure_lexical_scope_capacity(WalkState *state) {
    if (state->lexical_scope_count < state->lexical_scope_capacity) {
        return true;
    }
    if (state->lexical_scope_capacity > INT32_MAX / PAIR_LEN) {
        state->lexical_binding_tracking_failed = true;
        return false;
    }
    int new_capacity = state->lexical_scope_capacity * PAIR_LEN;
    CBMLexicalScope *grown =
        (CBMLexicalScope *)cbm_arena_alloc(state->arena, (size_t)new_capacity * sizeof(*grown));
    if (!grown) {
        state->lexical_binding_tracking_failed = true;
        return false;
    }
    memcpy(grown, state->lexical_scopes, (size_t)state->lexical_scope_count * sizeof(*grown));
    state->lexical_scopes = grown;
    state->lexical_scope_capacity = new_capacity;
    return true;
}

static uint32_t python_function_lookup_parent(const WalkState *state,
                                              uint32_t structural_parent_id) {
    uint32_t id = structural_parent_id;
    int remaining = state ? state->lexical_scope_count : 0;
    while (id != 0 && remaining-- > 0) {
        const CBMLexicalScope *scope = lexical_scope_by_id(state, id);
        if (!scope) {
            return structural_parent_id;
        }
        if (scope->kind == CBM_LEXICAL_SCOPE_CLASS) {
            return scope->lookup_parent_id;
        }
        if (scope->kind == CBM_LEXICAL_SCOPE_FUNCTION ||
            scope->kind == CBM_LEXICAL_SCOPE_COMPREHENSION ||
            scope->kind == CBM_LEXICAL_SCOPE_MODULE) {
            return structural_parent_id;
        }
        id = scope->parent_id;
    }
    return structural_parent_id;
}

static uint32_t add_lexical_scope(WalkState *state, TSNode node, CBMLexicalScopeKind kind) {
    if (!state || ts_node_is_null(node) || !ensure_lexical_scope_capacity(state)) {
        return 0;
    }
    uint32_t parent_id = current_lexical_scope_id(state);
    uint32_t lookup_parent_id = parent_id;
    /* Python method/function lookup bypasses the containing class namespace;
     * class attributes require qualification (`self.x`/`Cls.x`). */
    if (kind == CBM_LEXICAL_SCOPE_FUNCTION && state->language == CBM_LANG_PYTHON) {
        lookup_parent_id = python_function_lookup_parent(state, parent_id);
    }
    CBMLexicalScope *scope = &state->lexical_scopes[state->lexical_scope_count];
    scope->id = (uint32_t)state->lexical_scope_count + SKIP_ONE;
    scope->parent_id = parent_id;
    scope->lookup_parent_id = lookup_parent_id;
    scope->start_byte = ts_node_start_byte(node);
    scope->end_byte = ts_node_end_byte(node);
    scope->kind = (uint8_t)kind;
    state->lexical_scope_count++;
    return scope->id;
}

static bool push_scope(WalkState *state, uint8_t kind, uint32_t depth, const char *qn) {
    if (!ensure_scope_capacity(state)) {
        return false;
    }
    CBMWalkScope *f = &state->scopes[state->scope_top];
    f->kind = kind;
    f->depth = depth;
    f->qn = qn;
    f->lexical_scope_id = 0;
    f->invocation_kind = CBM_INVOCATION_NONE;
    f->callee_expr = (TSNode){0};
    f->callee_leaf = (TSNode){0};
    /* Save the complete displaced tuple, then apply this frame's effect --
     * pop_expired_scopes restores verbatim. O(1) either way; see the
     * CBMWalkScope comment for the quadratic recompute this replaces. */
    f->prev_enclosing_func_qn = state->enclosing_func_qn;
    f->prev_enclosing_class_qn = state->enclosing_class_qn;
    f->prev_invocation_kind = state->invocation_kind;
    f->prev_callee_expr = state->callee_expr;
    f->prev_callee_leaf = state->callee_leaf;
    f->prev_inside_import = state->inside_import;
    f->prev_loop_depth = state->loop_depth;
    f->prev_branch_depth = state->branch_depth;
    switch (kind) {
    case SCOPE_FUNC:
        state->enclosing_func_qn = qn;
        break;
    case SCOPE_CLASS:
    case SCOPE_NAMESPACE:
        state->enclosing_class_qn = qn;
        break;
    case SCOPE_CALL:
        /* The invocation triple is applied by push_call_scope once the caller
         * has filled the frame fields. */
        break;
    case SCOPE_IMPORT:
        state->inside_import = true;
        break;
    case SCOPE_LOOP:
        state->loop_depth++;
        break;
    case SCOPE_BRANCH:
        state->branch_depth++;
        break;
    default:
        break;
    }
    state->scope_top++;
    return true;
}

static bool push_lexical_scope(WalkState *state, uint8_t walk_kind, uint32_t depth, const char *qn,
                               TSNode node, CBMLexicalScopeKind lexical_kind) {
    if (!push_scope(state, walk_kind, depth, qn)) {
        state->lexical_binding_tracking_failed = true;
        return false;
    }
    state->scopes[state->scope_top - SKIP_ONE].lexical_scope_id =
        add_lexical_scope(state, node, lexical_kind);
    return true;
}

static bool push_existing_lexical_scope(WalkState *state, uint8_t walk_kind, uint32_t depth,
                                        const char *qn, uint32_t lexical_scope_id, TSNode node) {
    CBMLexicalScope *scope = mutable_lexical_scope_by_id(state, lexical_scope_id);
    if (!scope || !push_scope(state, walk_kind, depth, qn)) {
        state->lexical_binding_tracking_failed = true;
        return false;
    }
    state->scopes[state->scope_top - SKIP_ONE].lexical_scope_id = lexical_scope_id;
    uint32_t end_byte = ts_node_end_byte(node);
    if (end_byte > scope->end_byte) {
        scope->end_byte = end_byte;
    }
    return true;
}

static uint32_t active_same_function_scope_id(const WalkState *state, const char *function_qn,
                                              TSNode node) {
    if (!state || !function_qn) {
        return 0;
    }
    uint32_t start = ts_node_start_byte(node);
    uint32_t end = ts_node_end_byte(node);
    for (int i = state->scope_top - SKIP_ONE; i >= 0; i--) {
        if (state->scopes[i].kind != SCOPE_FUNC || !state->scopes[i].qn ||
            strcmp(state->scopes[i].qn, function_qn) != 0) {
            continue;
        }
        const CBMLexicalScope *scope =
            lexical_scope_by_id(state, state->scopes[i].lexical_scope_id);
        if (scope && scope->start_byte <= start && end <= scope->end_byte) {
            return scope->id;
        }
    }
    return 0;
}

static bool push_function_scope(WalkState *state, uint32_t depth, const char *function_qn,
                                TSNode node) {
    uint32_t existing_id = active_same_function_scope_id(state, function_qn, node);
    return existing_id ? push_existing_lexical_scope(state, SCOPE_FUNC, depth, function_qn,
                                                     existing_id, node)
                       : push_lexical_scope(state, SCOPE_FUNC, depth, function_qn, node,
                                            CBM_LEXICAL_SCOPE_FUNCTION);
}

static void push_call_scope(WalkState *state, uint32_t depth,
                            const CBMInvocationDescriptor *invocation) {
    if (!invocation ||
        (invocation->kind != CBM_INVOCATION_CALLABLE_REFERENCE && !invocation->raw_call_emitted) ||
        (ts_node_is_null(invocation->callee_expr) && ts_node_is_null(invocation->callee_leaf))) {
        return;
    }
    if (!push_scope(state, SCOPE_CALL, depth, NULL)) {
        return;
    }
    state->scopes[state->scope_top - SKIP_ONE].invocation_kind = invocation->kind;
    state->scopes[state->scope_top - SKIP_ONE].callee_expr = invocation->callee_expr;
    state->scopes[state->scope_top - SKIP_ONE].callee_leaf = invocation->callee_leaf;
    /* Apply the CALL effect (push_scope saved the displaced tuple already;
     * the frame fields had to be filled first). */
    state->invocation_kind = invocation->kind;
    state->callee_expr = invocation->callee_expr;
    state->callee_leaf = invocation->callee_leaf;
}

// Pop scopes that we've ascended out of (depth >= current cursor depth),
// restoring the walk-state tuple each frame displaced. LIFO order keeps the
// restores exact; O(1) per frame.
static void pop_expired_scopes(WalkState *state, uint32_t cur_depth) {
    while (state->scope_top > 0 && state->scopes[state->scope_top - SKIP_ONE].depth >= cur_depth) {
        const CBMWalkScope *f = &state->scopes[--state->scope_top];
        state->enclosing_func_qn = f->prev_enclosing_func_qn;
        state->enclosing_class_qn = f->prev_enclosing_class_qn;
        state->invocation_kind = f->prev_invocation_kind;
        state->callee_expr = f->prev_callee_expr;
        state->callee_leaf = f->prev_callee_leaf;
        state->inside_import = f->prev_inside_import;
        state->loop_depth = f->prev_loop_depth;
        state->branch_depth = f->prev_branch_depth;
    }
}

// Try to resolve Wolfram function QN from set_delayed_top/set_top/set_delayed/set LHS.
static const char *compute_wolfram_func_qn(CBMExtractCtx *ctx, TSNode node) {
    const char *nk = ts_node_type(node);
    if (strcmp(nk, "set_delayed_top") != 0 && strcmp(nk, "set_top") != 0 &&
        strcmp(nk, "set_delayed") != 0 && strcmp(nk, "set") != 0) {
        return NULL; // not a Wolfram set node — signal caller to continue
    }
    if (ts_node_named_child_count(node) > 0) {
        TSNode lhs = ts_node_named_child(node, 0);
        if (strcmp(ts_node_type(lhs), "apply") == 0 && ts_node_named_child_count(lhs) > 0) {
            TSNode head = ts_node_named_child(lhs, 0);
            if (strcmp(ts_node_type(head), "user_symbol") == 0) {
                char *name = cbm_node_text(ctx->arena, head, ctx->source);
                if (name && name[0]) {
                    return cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, name);
                }
            }
        }
    }
    return NULL;
}

/* True for a Lisp def-form head symbol (defn/define/...). Mirrors
 * lisp_is_def_head() in extract_defs.c so the scope-stack walk pushes a
 * SCOPE_FUNC only for actual definitions, never for a plain call list such as
 * `(add x 1)` — otherwise every parenthesized form would shadow the enclosing
 * def and the in-body call would mis-source. */
static bool lisp_head_is_def(const char *t) {
    if (!t) {
        return false;
    }
    static const char *heads[] = {"defn",
                                  "defn-",
                                  "def",
                                  "defmacro",
                                  "defmulti",
                                  "defmethod",
                                  "defprotocol",
                                  "defrecord",
                                  "deftype",
                                  "definterface",
                                  "defonce",
                                  "define",
                                  "define-syntax",
                                  "define-values",
                                  "define-syntax-rule",
                                  "define-struct",
                                  "define-record-type",
                                  "define/contract",
                                  "struct",
                                  NULL};
    for (int i = 0; heads[i]; i++) {
        if (strcmp(t, heads[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* Resolve a Lisp (Clojure/Scheme/Racket) def-form's QN for scope tracking.
 * The def node is a list/list_lit whose head names the def kind and whose
 * second element is the name (a bare symbol) or a (name args...) nested list.
 * Returns NULL for any non-def list (calls, vectors of args, the +/- body
 * forms, ...), so push_boundary_scopes pushes no scope for them. Mirrors
 * extract_lisp_def() in extract_defs.c. */
static const char *compute_lisp_func_qn(CBMExtractCtx *ctx, TSNode node) {
    if (ts_node_named_child_count(node) < PAIR_LEN) {
        return NULL;
    }
    char *head = cbm_node_text(ctx->arena, ts_node_named_child(node, 0), ctx->source);
    if (!lisp_head_is_def(head)) {
        return NULL;
    }
    TSNode target = ts_node_named_child(node, SKIP_ONE);
    const char *tk = ts_node_type(target);
    TSNode name_node = target;
    /* (define (foo args) ...) — the name is the head symbol of the nested list. */
    if ((strcmp(tk, "list") == 0 || strcmp(tk, "list_lit") == 0) &&
        ts_node_named_child_count(target) > 0) {
        name_node = ts_node_named_child(target, 0);
    }
    if (ts_node_is_null(name_node)) {
        return NULL;
    }
    char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
    if (!name || !name[0]) {
        return NULL;
    }
    return cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, name);
}

/* Resolve an Elixir def/defp/defmacro's QN for scope tracking. The def is a
 * `call` node whose target (first child) is the def macro and whose first
 * argument is either the function head call `name(args)` or a bare identifier
 * (zero-arg). Returns NULL for a non-def `call` (e.g. the in-body `add(x,1)`
 * call, whose target is not a def macro) so only defs push a scope. Mirrors
 * extract_elixir_func_def() in extract_defs.c. */
static const char *compute_elixir_func_qn(CBMExtractCtx *ctx, TSNode node) {
    if (ts_node_child_count(node) == 0) {
        return NULL;
    }
    char *macro = cbm_node_text(ctx->arena, ts_node_child(node, 0), ctx->source);
    if (!macro || (strcmp(macro, "def") != 0 && strcmp(macro, "defp") != 0 &&
                   strcmp(macro, "defmacro") != 0)) {
        return NULL;
    }
    TSNode args = ts_node_child_by_field_name(node, TS_FIELD("arguments"));
    if (ts_node_is_null(args) && ts_node_child_count(node) > SKIP_ONE) {
        args = ts_node_child(node, SKIP_ONE);
    }
    if (ts_node_is_null(args) || ts_node_child_count(args) == 0) {
        return NULL;
    }
    TSNode first_arg = ts_node_child(args, 0);
    if (ts_node_is_null(first_arg)) {
        return NULL;
    }
    const char *fk = ts_node_type(first_arg);
    char *name = NULL;
    if (strcmp(fk, "call") == 0 && ts_node_child_count(first_arg) > 0) {
        name = cbm_node_text(ctx->arena, ts_node_child(first_arg, 0), ctx->source);
    } else if (strcmp(fk, "identifier") == 0) {
        name = cbm_node_text(ctx->arena, first_arg, ctx->source);
    }
    if (!name || !name[0]) {
        return NULL;
    }
    return cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, name);
}

/* Resolve a CFML tag-function's QN for scope tracking. A <cffunction name="foo">
 * is a `cf_function_tag`; the name lives in a `cf_attribute` child (name="foo"),
 * not on a `name` field, so the shared resolver (which has no source pointer to
 * read the attribute NAME and disambiguate) cannot name it. The def-extractor
 * extract_cfml_function_tag() does the same attribute walk; this mirrors it so
 * the in-body call sources to the cffunction Function rather than the Module. */
static const char *compute_cfml_func_qn(CBMExtractCtx *ctx, TSNode node) {
    if (strcmp(ts_node_type(node), "cf_function_tag") != 0) {
        return NULL;
    }
    char *name = NULL;
    uint32_t cc = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < cc && !name; i++) {
        TSNode ch = ts_node_named_child(node, i);
        if (strcmp(ts_node_type(ch), "cf_attribute") != 0) {
            continue;
        }
        TSNode an = cbm_find_child_by_kind(ch, "cf_attribute_name");
        if (ts_node_is_null(an)) {
            continue;
        }
        char *aname = cbm_node_text(ctx->arena, an, ctx->source);
        if (!aname || strcasecmp(aname, "name") != 0) {
            continue;
        }
        TSNode val = cbm_find_child_by_kind(ch, "quoted_cf_attribute_value");
        if (ts_node_is_null(val)) {
            val = cbm_find_child_by_kind(ch, "cf_attribute_value");
        }
        if (ts_node_is_null(val)) {
            continue;
        }
        TSNode inner = cbm_find_child_by_kind(val, "attribute_value");
        name = cbm_node_text(ctx->arena, ts_node_is_null(inner) ? val : inner, ctx->source);
    }
    if (!name || !name[0]) {
        return NULL;
    }
    return cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, name);
}

/* Resolve a Go-template named-template's QN for scope tracking. A
 * {{ define "greeting" }} ... {{ end }} is a `define_action` whose name is a
 * quoted `interpreted_string_literal` child, not a bare identifier on a `name`
 * field. The shared resolver can't strip the quotes (no source pointer), so the
 * gate lives here. Mirrors extract_gotemplate_define() so a {{ template }}/include
 * call inside the define body sources to the define's Function, not the Module. */
static const char *compute_gotemplate_func_qn(CBMExtractCtx *ctx, TSNode node) {
    if (strcmp(ts_node_type(node), "define_action") != 0) {
        return NULL;
    }
    TSNode s = cbm_find_child_by_kind(node, "interpreted_string_literal");
    if (ts_node_is_null(s)) {
        return NULL;
    }
    char *raw = cbm_node_text(ctx->arena, s, ctx->source);
    if (!raw) {
        return NULL;
    }
    size_t len = strlen(raw);
    if (len >= CBM_QUOTE_PAIR && (raw[0] == '"' || raw[0] == '`')) {
        raw = cbm_arena_strndup(ctx->arena, raw + CBM_QUOTE_OFFSET,
                                len - CBM_QUOTE_PAIR); // strip surrounding quotes
    }
    if (!raw || !raw[0]) {
        return NULL;
    }
    return cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, raw);
}

// --- ObjectScript variable type inference (instance_method_call resolution) ---

// Insert or update var_name -> class_name. Silent on overflow.
static void os_type_map_add(os_type_map_t *map, const char *var_name, const char *class_name) {
    if (map->count >= OS_TYPE_MAP_CAP || !var_name || !class_name) {
        return;
    }
    for (int i = 0; i < map->count; i++) {
        if (strcmp(map->entries[i].var_name, var_name) == 0) {
            map->entries[i].class_name = class_name;
            return;
        }
    }
    map->entries[map->count].var_name = var_name;
    map->entries[map->count].class_name = class_name;
    map->count++;
}

// Locate the class_method_call inside an RHS expression (peeking through a
// couple of common ObjectScript expression container node types).
static TSNode find_class_method_call(TSNode root, const char *end) {
    (void)end;
    if (strcmp(ts_node_type(root), "class_method_call") == 0) {
        return root;
    }
    static const char *containers[] = {"expression", "expr_atom", NULL};
    for (const char **c = containers; *c; c++) {
        TSNode inner = cbm_find_child_by_kind(root, *c);
        if (!ts_node_is_null(inner)) {
            TSNode hit = cbm_find_child_by_kind(inner, "class_method_call");
            if (!ts_node_is_null(hit)) {
                return hit;
            }
            TSNode inner2 = cbm_find_child_by_kind(inner, "expr_atom");
            if (!ts_node_is_null(inner2)) {
                hit = cbm_find_child_by_kind(inner2, "class_method_call");
                if (!ts_node_is_null(hit)) {
                    return hit;
                }
            }
        }
    }
    return cbm_find_child_by_kind(root, "class_method_call");
}

// On a `Set var = ##class(X).%New()` (or %OpenId/%Open, or a method whose
// return type is known) map var -> X. On a class `Property`/`Relationship`,
// map `..PropName -> typename` (surviving method-scope resets).
static void objectscript_map_property_type(CBMExtractCtx *ctx, TSNode node, WalkState *state) {
    TSNode prop_name_node = cbm_find_child_by_kind(node, "property_name");
    if (ts_node_is_null(prop_name_node)) {
        prop_name_node = cbm_find_child_by_kind(node, "relationship_name");
    }
    TSNode return_type = cbm_find_child_by_kind(node, "return_type");
    TSNode type_name = cbm_find_child_by_kind(return_type, "typename");
    if (ts_node_is_null(prop_name_node) || ts_node_is_null(type_name)) {
        return;
    }
    char *property_name = cbm_node_text(ctx->arena, prop_name_node, ctx->source);
    char *property_type = cbm_node_text(ctx->arena, type_name, ctx->source);
    if (!property_name || !property_name[0] || !property_type || !property_type[0]) {
        return;
    }
    char *dot_name = cbm_arena_sprintf(ctx->arena, "..%s", property_name);
    os_type_map_add(&state->os_type_map, dot_name, property_type);
    state->os_type_map.class_base_count = state->os_type_map.count;
}

static bool objectscript_set_assignment_nodes(TSNode set_argument, TSNode *lhs, TSNode *rhs) {
    *lhs = (TSNode){0};
    *rhs = (TSNode){0};
    for (uint32_t i = 0; i < ts_node_named_child_count(set_argument); i++) {
        TSNode child = ts_node_named_child(set_argument, i);
        const char *kind = ts_node_type(child);
        if (strcmp(kind, "set_target") == 0 || strcmp(kind, "lvn") == 0 ||
            strcmp(kind, "variable") == 0 || strcmp(kind, "glvn") == 0) {
            *lhs = child;
        } else if (strcmp(kind, "expression") == 0 || strcmp(kind, "expr_atom") == 0 ||
                   strcmp(kind, "class_method_call") == 0) {
            *rhs = child;
        }
    }
    return !ts_node_is_null(*lhs) && !ts_node_is_null(*rhs);
}

static char *objectscript_class_method_name(CBMExtractCtx *ctx, TSNode method_call) {
    TSNode method_name = cbm_find_child_by_kind(method_call, "method_name");
    if (ts_node_is_null(method_name) || ts_node_named_child_count(method_name) == 0) {
        return NULL;
    }
    return cbm_node_text(ctx->arena, ts_node_named_child(method_name, 0), ctx->source);
}

static char *objectscript_class_method_class(CBMExtractCtx *ctx, TSNode method_call) {
    TSNode class_ref = cbm_find_child_by_kind(method_call, "class_ref");
    if (ts_node_is_null(class_ref)) {
        return NULL;
    }
    TSNode class_name = cbm_find_child_by_kind(class_ref, "class_name");
    if (ts_node_is_null(class_name)) {
        return NULL;
    }
    return cbm_node_text(ctx->arena, class_name, ctx->source);
}

static bool objectscript_is_constructor_method(const char *method_name) {
    return strcasecmp(method_name, "%New") == 0 || strcasecmp(method_name, "%OpenId") == 0 ||
           strcasecmp(method_name, "%Open") == 0;
}

static const char *objectscript_return_type(CBMExtractCtx *ctx, const char *class_name,
                                            const char *method_name) {
    if (objectscript_is_constructor_method(method_name)) {
        return class_name;
    }
    if (!ctx->return_type_table) {
        return NULL;
    }
    char *method_qn = cbm_arena_sprintf(ctx->arena, "%s.%s", class_name, method_name);
    for (int i = 0; i < ctx->return_type_table->count; i++) {
        if (strcasecmp(ctx->return_type_table->entries[i].method_qn, method_qn) == 0) {
            return ctx->return_type_table->entries[i].return_type;
        }
    }
    return NULL;
}

static char *objectscript_assignment_variable(CBMExtractCtx *ctx, TSNode lhs) {
    TSNode variable = cbm_find_child_by_kind(lhs, "glvn");
    if (ts_node_is_null(variable)) {
        variable = lhs;
    }
    TSNode local_name = cbm_find_child_by_kind(variable, "lvn");
    if (!ts_node_is_null(local_name)) {
        variable = local_name;
    }
    return cbm_node_text(ctx->arena, variable, ctx->source);
}

static void objectscript_map_set_assignment(CBMExtractCtx *ctx, TSNode set_argument,
                                            WalkState *state) {
    TSNode lhs;
    TSNode rhs;
    if (!objectscript_set_assignment_nodes(set_argument, &lhs, &rhs)) {
        return;
    }
    TSNode method_call = find_class_method_call(rhs, NULL);
    if (ts_node_is_null(method_call)) {
        return;
    }
    char *method_name = objectscript_class_method_name(ctx, method_call);
    char *class_name = objectscript_class_method_class(ctx, method_call);
    if (!method_name || !class_name || !class_name[0]) {
        return;
    }
    const char *type_name = objectscript_return_type(ctx, class_name, method_name);
    char *variable = objectscript_assignment_variable(ctx, lhs);
    if (!type_name || !variable || !variable[0]) {
        return;
    }
    os_type_map_add(&state->os_type_map, variable, type_name);
}

static void objectscript_map_set_command(CBMExtractCtx *ctx, TSNode command, WalkState *state) {
    for (uint32_t i = 0; i < ts_node_named_child_count(command); i++) {
        TSNode argument = ts_node_named_child(command, i);
        const char *kind = ts_node_type(argument);
        if (strcmp(kind, "set_argument") == 0 || strcmp(kind, "assignment") == 0) {
            objectscript_map_set_assignment(ctx, argument, state);
        }
    }
}

static void handle_objectscript_type_map(CBMExtractCtx *ctx, TSNode node, WalkState *state) {
    if (ctx->language != CBM_LANG_OBJECTSCRIPT_UDL &&
        ctx->language != CBM_LANG_OBJECTSCRIPT_ROUTINE) {
        return;
    }

    const char *nk = ts_node_type(node);

    if (strcmp(nk, "command_set") == 0) {
        objectscript_map_set_command(ctx, node, state);
    }

    if (strcmp(nk, "property") == 0 || strcmp(nk, "relationship") == 0) {
        objectscript_map_property_type(ctx, node, state);
    }
}

// Resolve the FQN of an ObjectScript class_definition node (via its class_name).
static const char *objectscript_get_class_name(CBMExtractCtx *ctx, TSNode node) {
    for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
        TSNode child = ts_node_named_child(node, i);
        if (strcmp(ts_node_type(child), "class_name") == 0) {
            char *name = cbm_node_text(ctx->arena, child, ctx->source);
            if (name && name[0]) {
                return cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, name);
            }
        }
    }
    return NULL;
}

// Resolve the QN of an ObjectScript method/classmethod/query node for scope tracking.
static const char *objectscript_name_qn(CBMExtractCtx *ctx, TSNode name_node,
                                        const char *enclosing_class_qn) {
    if (ts_node_is_null(name_node)) {
        return NULL;
    }
    char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
    if (!name || !name[0]) {
        return NULL;
    }
    return enclosing_class_qn ? cbm_arena_sprintf(ctx->arena, "%s.%s", enclosing_class_qn, name)
                              : cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, name);
}

static TSNode objectscript_method_name_node(TSNode node) {
    TSNode definition = cbm_find_child_by_kind(node, "method_definition");
    if (ts_node_is_null(definition)) {
        return (TSNode){0};
    }
    TSNode method_name = cbm_find_child_by_kind(definition, "method_name");
    return ts_node_named_child_count(method_name) > 0 ? ts_node_named_child(method_name, 0)
                                                      : (TSNode){0};
}

static const char *objectscript_get_method_qn(CBMExtractCtx *ctx, TSNode node,
                                              const char *enclosing_class_qn) {
    const char *nk = ts_node_type(node);
    if (strcmp(nk, "query") == 0) {
        return objectscript_name_qn(ctx, cbm_find_child_by_kind(node, "query_name"),
                                    enclosing_class_qn);
    }
    if (strcmp(nk, "method") != 0 && strcmp(nk, "classmethod") != 0) {
        return NULL;
    }
    return objectscript_name_qn(ctx, objectscript_method_name_node(node), enclosing_class_qn);
}

static const char *compute_objectscript_routine_func_qn(CBMExtractCtx *ctx, TSNode node) {
    const char *kind = ts_node_type(node);
    TSNode tag = (TSNode){0};
    if (strcmp(kind, "procedure") == 0) {
        tag = cbm_find_child_by_kind(node, "tag");
    } else if (strcmp(kind, "tag") == 0) {
        TSNode parent = ts_node_parent(node);
        if (ts_node_is_null(parent) || strcmp(ts_node_type(parent), "procedure") != 0) {
            tag = node;
        }
    }
    if (ts_node_is_null(tag)) {
        return NULL;
    }
    char *name = cbm_node_text(ctx->arena, tag, ctx->source);
    return name && name[0] ? cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, name) : NULL;
}

static const char *compute_member_func_qn(CBMExtractCtx *ctx, TSNode name_node,
                                          const WalkState *state) {
    if (ts_node_is_null(name_node)) {
        return NULL;
    }
    char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
    if (!name || !name[0]) {
        return NULL;
    }
    if (state->enclosing_class_qn) {
        return cbm_arena_sprintf(ctx->arena, "%s.%s", state->enclosing_class_qn, name);
    }
    return cbm_fqn_compute_source_lang(ctx->arena, ctx->project, ctx->rel_path, name,
                                       ctx->language);
}

static const char *compute_objc_func_qn(CBMExtractCtx *ctx, TSNode node, const WalkState *state) {
    if (strcmp(ts_node_type(node), "method_definition") != 0) {
        return NULL;
    }
    return compute_member_func_qn(ctx, cbm_find_child_by_kind(node, "identifier"), state);
}

static const char *compute_dart_func_qn(CBMExtractCtx *ctx, TSNode node, const WalkState *state) {
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "function_signature") != 0 && strcmp(kind, "method_signature") != 0) {
        return NULL;
    }
    TSNode signature = cbm_find_child_by_kind(node, "function_signature");
    if (ts_node_is_null(signature)) {
        signature = node;
    }
    return compute_member_func_qn(ctx, cbm_find_child_by_kind(signature, "identifier"), state);
}

static TSNode agda_function_name_node(TSNode node) {
    TSNode lhs = cbm_find_child_by_kind(node, "lhs");
    if (ts_node_is_null(lhs)) {
        return (TSNode){0};
    }
    TSNode name = cbm_find_child_by_kind(lhs, "function_name");
    if (!ts_node_is_null(name)) {
        return name;
    }
    TSNode current = lhs;
    for (int i = 0; i < MAX_AGDA_LHS_HEAD_DESCENT && !ts_node_is_null(current) &&
                    ts_node_named_child_count(current) > 0;
         i++) {
        current = ts_node_named_child(current, 0);
    }
    return current;
}

static const char *compute_agda_func_qn(CBMExtractCtx *ctx, TSNode node) {
    if (strcmp(ts_node_type(node), "function") != 0) {
        return NULL;
    }
    TSNode name_node = agda_function_name_node(node);
    if (ts_node_is_null(name_node)) {
        return NULL;
    }
    char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
    return name && name[0] ? cbm_fqn_compute_source_lang(ctx->arena, ctx->project, ctx->rel_path,
                                                         name, ctx->language)
                           : NULL;
}

static const char *compute_cpp_method_qn(CBMExtractCtx *ctx, TSNode node, const char *name) {
    if ((ctx->language != CBM_LANG_CPP && ctx->language != CBM_LANG_CUDA) ||
        strcmp(ts_node_type(node), "function_definition") != 0) {
        return NULL;
    }
    char *scope_name = cbm_cpp_out_of_line_parent_class(ctx->arena, node, ctx->source);
    if (!scope_name || !scope_name[0]) {
        return NULL;
    }
    const char *class_qn = cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, scope_name);
    return cbm_arena_sprintf(ctx->arena, "%s.%s", class_qn, name);
}

static const char *compute_shared_func_qn(CBMExtractCtx *ctx, TSNode node, const WalkState *state) {
    TSNode name_node = cbm_resolve_func_name(node, ctx->language);
    if (ts_node_is_null(name_node)) {
        return NULL;
    }
    char *name = cbm_func_name_node_text(ctx->arena, name_node, ctx->source, ctx->language);
    if (!name || !name[0]) {
        return NULL;
    }
    const char *cpp_qn = compute_cpp_method_qn(ctx, node, name);
    if (cpp_qn) {
        return cpp_qn;
    }
    const char *qn_name = name;
    if (ctx->language == CBM_LANG_NIX) {
        qn_name = cbm_nix_qn_name(ctx->arena, node, ctx->source, name);
        if (!qn_name || !qn_name[0]) {
            return NULL;
        }
    }
    return state->enclosing_class_qn
               ? cbm_arena_sprintf(ctx->arena, "%s.%s", state->enclosing_class_qn, qn_name)
               : cbm_fqn_compute_source_lang(ctx->arena, ctx->project, ctx->rel_path, qn_name,
                                             ctx->language);
}

// Compute function QN for scope tracking (mirrors cbm_enclosing_func_qn logic).
static const char *compute_func_qn(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                   WalkState *state) {
    (void)spec;
    if (ctx->language == CBM_LANG_WOLFRAM) {
        return compute_wolfram_func_qn(ctx, node);
    }
    if (ctx->language == CBM_LANG_OBJECTSCRIPT_UDL) {
        return objectscript_get_method_qn(ctx, node, state->enclosing_class_qn);
    }
    if (ctx->language == CBM_LANG_OBJECTSCRIPT_ROUTINE) {
        return compute_objectscript_routine_func_qn(ctx, node);
    }

    /* CFML tag dialect: <cffunction name="foo"> is a cf_function_tag whose name
     * lives in a cf_attribute, not a `name` field — gate here where ctx->source
     * is available to read the attribute. Other CFML func nodes (embedded
     * CFScript function_declaration/_expression) fall through to the shared
     * resolver below. */
    if (ctx->language == CBM_LANG_CFML && strcmp(ts_node_type(node), "cf_function_tag") == 0) {
        return compute_cfml_func_qn(ctx, node);
    }

    /* Go templates: {{ define "x" }} is a define_action whose name is a quoted
     * string literal — strip the quotes here (the shared resolver has no source). */
    if (ctx->language == CBM_LANG_GOTEMPLATE) {
        return compute_gotemplate_func_qn(ctx, node);
    }

    /* Lisp family (Clojure/Scheme/Racket): the def node is a list/list_lit, a
     * very general kind that also matches plain call forms. The shared resolver
     * has no source pointer to read the head symbol, so the def-vs-call gate
     * lives here (we have ctx->source). Non-def lists return NULL → no scope
     * pushed → the in-body call sources to the enclosing def, not the Module. */
    if (ctx->language == CBM_LANG_CLOJURE || ctx->language == CBM_LANG_SCHEME ||
        ctx->language == CBM_LANG_RACKET) {
        return compute_lisp_func_qn(ctx, node);
    }

    /* Elixir: def/defp/defmacro are `call` nodes (so is every in-body call).
     * Gate on the def-macro target text so only definitions push a scope. */
    if (ctx->language == CBM_LANG_ELIXIR) {
        return compute_elixir_func_qn(ctx, node);
    }

    if (ctx->language == CBM_LANG_OBJC && strcmp(ts_node_type(node), "method_definition") == 0) {
        return compute_objc_func_qn(ctx, node, state);
    }

    /* Dart: function_signature / method_signature have no `name` field; the name
     * is an `identifier` child (method_signature wraps a function_signature). The
     * shared resolver doesn't cover them, so resolve here for call-scope so an
     * in-body call sources to the function, not the Module. */
    if (ctx->language == CBM_LANG_DART && (strcmp(ts_node_type(node), "function_signature") == 0 ||
                                           strcmp(ts_node_type(node), "method_signature") == 0)) {
        return compute_dart_func_qn(ctx, node, state);
    }

    /* Agda: a definition is two `function` nodes — the type signature
     * (`compute : Nat -> Nat`, lhs has a `function_name` child that names the
     * def) and the body clause (`compute x = add x 1`, lhs has no function_name).
     * The shared resolver deliberately returns NULL for the body clause to avoid
     * a duplicate def, so an in-body call would source to the Module. Resolve the
     * body clause's name here (call-scope only) from the lhs head identifier so
     * the call attributes to the function. */
    if (ctx->language == CBM_LANG_AGDA && strcmp(ts_node_type(node), "function") == 0) {
        return compute_agda_func_qn(ctx, node);
    }
    return compute_shared_func_qn(ctx, node, state);
}

// Compute class QN for scope tracking.
static const char *compute_class_qn(CBMExtractCtx *ctx, TSNode node, const WalkState *state) {
    if (ctx->language == CBM_LANG_OBJECTSCRIPT_UDL) {
        return objectscript_get_class_name(ctx, node);
    }
    /* Nix: an attrset-valued `binding` is a named scope. Same shared helper the def
     * extractor's compute_class_qn uses — these are two separate functions, and a
     * one-segment disagreement between them drops every CALLS edge sourced from a
     * nested binding. */
    if (ctx->language == CBM_LANG_NIX) {
        return cbm_nix_binding_scope_qn(ctx, node, state ? state->enclosing_class_qn : NULL);
    }
    TSNode name_node = ts_node_child_by_field_name(node, TS_FIELD("name"));
    /* Newer tree-sitter-kotlin: class/object name is a type_identifier child. */
    if (ts_node_is_null(name_node) && ctx->language == CBM_LANG_KOTLIN) {
        name_node = cbm_find_child_by_kind(node, "type_identifier");
    }
    /* Objective-C: class_interface / class_implementation have no `name` field;
     * the class name is a plain `identifier` child. Without this the walk pushes
     * no class scope, so a method body's calls source to the Module and the
     * method itself is mis-extracted as a top-level Function (not a Method). */
    if (ts_node_is_null(name_node) && ctx->language == CBM_LANG_OBJC) {
        name_node = cbm_find_child_by_kind(node, "identifier");
    }
    /* Rust: impl_item has no `name` field; the implementing type is in the `type`
     * field (`impl Calc {...}` / `impl Trait for Calc {...}` both -> Calc). The
     * dedicated impl handler in push_boundary_scopes is dead code (impl_item is in
     * rust_class_types, so the class branch runs first and lands here), so resolve
     * the type here. Without a class scope, an impl method's QN drops the type
     * (proj.file.method) and no longer matches the class-qualified def-side Method
     * node, so in-body calls fall back to the Module. */
    if (ts_node_is_null(name_node) && ctx->language == CBM_LANG_RUST &&
        strcmp(ts_node_type(node), "impl_item") == 0) {
        name_node = ts_node_child_by_field_name(node, TS_FIELD("type"));
    }
    if (ts_node_is_null(name_node)) {
        return NULL;
    }

    char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
    if (!name || !name[0]) {
        return NULL;
    }

    /* Nested class: prefix with the enclosing class QN (Outer.Inner) so this
     * scope QN matches the def-side class QN (extract_defs.c compute_class_qn /
     * extract_class_def), which the lsp_resolve join requires for nested types. */
    if (state && state->enclosing_class_qn) {
        return cbm_arena_sprintf(ctx->arena, "%s.%s", state->enclosing_class_qn, name);
    }

    /* Java/Go: directory-based module (see compute_func_qn). */
    return cbm_fqn_compute_source_lang(ctx->arena, ctx->project, ctx->rel_path, name,
                                       ctx->language);
}

/* Forward declaration */
static bool is_string_node(const char *kind);

// --- Module-level constant collection ---

static void handle_string_constants(CBMExtractCtx *ctx, TSNode node, const WalkState *state) {
    /* Only collect at module level (not inside functions/classes) */
    if (state->enclosing_func_qn != NULL && state->enclosing_func_qn != ctx->module_qn) {
        return;
    }

    const char *kind = ts_node_type(node);

    /* Python: expression_statement → assignment → identifier = string */
    /* Go: short_var_declaration, const_spec */
    /* JS/TS: variable_declarator, lexical_declaration */
    if (strcmp(kind, "assignment") != 0 && strcmp(kind, "expression_statement") != 0 &&
        strcmp(kind, "short_var_declaration") != 0 && strcmp(kind, "const_spec") != 0 &&
        strcmp(kind, "variable_declarator") != 0) {
        return;
    }

    /* Find name (left side) and value (right side) */
    TSNode name_node = ts_node_child_by_field_name(node, TS_FIELD("left"));
    TSNode value_node = ts_node_child_by_field_name(node, TS_FIELD("right"));

    /* Some grammars use "name" + "value" fields */
    if (ts_node_is_null(name_node)) {
        name_node = ts_node_child_by_field_name(node, TS_FIELD("name"));
    }
    if (ts_node_is_null(value_node)) {
        value_node = ts_node_child_by_field_name(node, TS_FIELD("value"));
    }

    if (ts_node_is_null(name_node) || ts_node_is_null(value_node)) {
        return;
    }

    /* Name must be an identifier */
    const char *name_kind = ts_node_type(name_node);
    if (strcmp(name_kind, "identifier") != 0 && strcmp(name_kind, "constant") != 0) {
        return;
    }

    /* Value must be a string literal (template literals flatten to "{}" form) */
    const char *value_kind = ts_node_type(value_node);
    const char *flat_value = NULL;
    if (strcmp(value_kind, "template_string") == 0) {
        flat_value = cbm_template_string_text(ctx->arena, value_node, ctx->source);
        if (!flat_value) {
            return;
        }
    } else if (!is_string_node(value_kind)) {
        return;
    }

    char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
    const char *value =
        flat_value ? flat_value : cbm_node_text(ctx->arena, value_node, ctx->source);
    if (!name || !name[0] || !value || !value[0]) {
        return;
    }

    /* Strip quotes from value (template values are already unquoted) */
    int vlen = (int)strlen(value);
    if (!flat_value && vlen >= CBM_QUOTE_PAIR && (value[0] == '"' || value[0] == '\'')) {
        value = cbm_arena_strndup(ctx->arena, value + SKIP_ONE, (size_t)(vlen - PAIR_LEN));
        if (!value) {
            return;
        }
    }

    /* Add to constant map */
    CBMStringConstantMap *map = &ctx->string_constants;
    if (map->count < CBM_MAX_STRING_CONSTANTS) {
        map->names[map->count] = name;
        map->values[map->count] = value;
        map->count++;
    }
}

// --- String literal collection ---

static bool is_string_node(const char *kind) {
    /* Common string literal node types across tree-sitter grammars */
    return (strcmp(kind, "string_literal") == 0 || strcmp(kind, "string") == 0 ||
            strcmp(kind, "string_content") == 0 ||
            strcmp(kind, "interpreted_string_literal") == 0 ||
            strcmp(kind, "raw_string_literal") == 0 || strcmp(kind, "string_value") == 0 ||
            /* YAML string types */
            strcmp(kind, "double_quote_scalar") == 0 || strcmp(kind, "single_quote_scalar") == 0);
}

static void handle_string_refs(CBMExtractCtx *ctx, TSNode node, const WalkState *state) {
    const char *kind = ts_node_type(node);
    /* JS/TS template literals: flatten ${...} substitutions to "{}" so URL-ish
     * template strings become string_refs with the canonical placeholder shape
     * shared with server route paths (issue #1006). */
    if (strcmp(kind, "template_string") == 0) {
        const char *flat = cbm_template_string_text(ctx->arena, node, ctx->source);
        if (!flat) {
            return;
        }
        int kind_val = cbm_classify_string(flat, (int)strlen(flat));
        if (kind_val < 0) {
            return;
        }
        CBMStringRef ref = {
            .value = flat,
            .enclosing_func_qn =
                state->enclosing_func_qn ? state->enclosing_func_qn : ctx->module_qn,
            .kind = (CBMStringRefKind)kind_val,
        };
        cbm_stringref_push(&ctx->result->string_refs, ctx->arena, ref);
        return;
    }
    if (!is_string_node(kind)) {
        return;
    }

    /* Extract string content */
    char *text = cbm_node_text(ctx->arena, node, ctx->source);
    if (!text || !text[0]) {
        return;
    }

    /* Strip quotes if present */
    int len = (int)strlen(text);
    const char *content = text;
    if (len >= CBM_QUOTE_PAIR && (text[0] == '"' || text[0] == '\'')) {
        content = text + SKIP_ONE;
        len -= PAIR_LEN;
        if (len <= 0) {
            return;
        }
    }

    /* Classify */
    int kind_val = cbm_classify_string(content, len);
    if (kind_val < 0) {
        return;
    }

    /* Build null-terminated content string in arena */
    char *val = cbm_arena_strndup(ctx->arena, content, (size_t)len);
    if (!val) {
        return;
    }

    CBMStringRef ref = {
        .value = val,
        .enclosing_func_qn = state->enclosing_func_qn ? state->enclosing_func_qn : ctx->module_qn,
        .kind = (CBMStringRefKind)kind_val,
    };
    cbm_stringref_push(&ctx->result->string_refs, ctx->arena, ref);
}

// --- YAML nested field extraction (D2) ---

/* Recursively walk YAML block_mapping_pair nodes, building dotted key paths.
 * Emits string_refs with key_path for leaf values that are URLs or config values.
 * Example: body.operational_info.post_url → "https://..." */
// Classify and emit a YAML leaf value as a string_ref with key_path.
static void emit_yaml_leaf_value(CBMExtractCtx *ctx, TSNode val, const char *path) {
    char *val_text = cbm_node_text(ctx->arena, val, ctx->source);
    if (!val_text || !val_text[0]) {
        return;
    }

    int vlen = (int)strlen(val_text);
    const char *content = val_text;
    if (vlen >= CBM_QUOTE_PAIR && (val_text[0] == '"' || val_text[0] == '\'')) {
        content = val_text + SKIP_ONE;
        vlen -= PAIR_LEN;
        if (vlen <= 0) {
            return;
        }
    }

    int kind_val = cbm_classify_string(content, vlen);
    if (kind_val < 0) {
        return;
    }

    char *stored = cbm_arena_strndup(ctx->arena, content, (size_t)vlen);
    if (!stored) {
        return;
    }

    CBMStringRef ref = {
        .value = stored,
        .enclosing_func_qn = ctx->module_qn,
        .key_path = path,
        .kind = (CBMStringRefKind)kind_val,
    };
    cbm_stringref_push(&ctx->result->string_refs, ctx->arena, ref);
}

typedef struct {
    TSNode node;
    const char *prefix;
} yaml_walk_frame_t;
#define YAML_WALK_STACK_CAP CBM_SZ_256

/* Push block_mapping children of a block_node/block_mapping value onto the walk stack. */
static void push_yaml_block_children(TSNode val, const char *path, yaml_walk_frame_t *stack,
                                     int *top) {
    uint32_t vnc = ts_node_named_child_count(val);
    for (int vi = (int)vnc - SKIP_ONE; vi >= 0 && *top < YAML_WALK_STACK_CAP; vi--) {
        TSNode vc = ts_node_named_child(val, (uint32_t)vi);
        const char *vctype = ts_node_type(vc);
        if (strcmp(vctype, "block_mapping") == 0 || strcmp(vctype, "block_mapping_pair") == 0) {
            stack[(*top)++] = (yaml_walk_frame_t){vc, path};
        }
    }
}

static void walk_yaml_mapping(CBMExtractCtx *ctx, TSNode root, const char *root_prefix) {
    yaml_walk_frame_t stack[YAML_WALK_STACK_CAP];
    int top = 0;
    stack[top++] = (yaml_walk_frame_t){root, root_prefix};

    while (top > 0) {
        yaml_walk_frame_t frame = stack[--top];
        TSNode node = frame.node;
        const char *prefix = frame.prefix;
        uint32_t nc = ts_node_named_child_count(node);
        for (uint32_t i = 0; i < nc; i++) {
            TSNode child = ts_node_named_child(node, i);
            if (strcmp(ts_node_type(child), "block_mapping_pair") != 0) {
                continue;
            }
            TSNode key = ts_node_child_by_field_name(child, TS_FIELD("key"));
            if (ts_node_is_null(key)) {
                continue;
            }
            char *key_text = cbm_node_text(ctx->arena, key, ctx->source);
            if (!key_text || !key_text[0]) {
                continue;
            }
            const char *path =
                prefix ? cbm_arena_sprintf(ctx->arena, "%s.%s", prefix, key_text) : key_text;
            TSNode val = ts_node_child_by_field_name(child, TS_FIELD("value"));
            if (ts_node_is_null(val)) {
                continue;
            }
            const char *vk = ts_node_type(val);
            if (strcmp(vk, "block_node") == 0 || strcmp(vk, "block_mapping") == 0) {
                push_yaml_block_children(val, path, stack, &top);
                continue;
            }
            emit_yaml_leaf_value(ctx, val, path);
        }
    }
}

/* ── Infrastructure binding extraction ─────────────────────────────
 * Scan YAML/JSON/HCL list items for topic→URL pairs.
 * Patterns detected:
 *   YAML: {topic: X, config: {push_endpoint: URL}} (Pub/Sub subscription)
 *   YAML: {uri: URL, body: ...} (Cloud Scheduler)
 *   YAML: {queue: X, uri: URL} (Cloud Tasks)
 *   HCL: resource "google_pubsub_subscription" { topic=X, push_config{push_endpoint=URL} }
 *
 * Works by collecting key-value pairs in each mapping, then checking for
 * known source+target patterns. Language-agnostic: the key names are the signal. */

/* Source key names (topic/queue/schedule identifier) */
static int is_source_key(const char *key) {
    return (strcmp(key, "topic") == 0 || strcmp(key, "queue") == 0 ||
            strcmp(key, "queue_name") == 0 || strcmp(key, "subscription") == 0 ||
            strcmp(key, "subject") == 0 || strcmp(key, "channel") == 0 ||
            strcmp(key, "stream") == 0);
}

/* Target key names (endpoint URL) */
static int is_target_key(const char *key) {
    return (strcmp(key, "push_endpoint") == 0 || strcmp(key, "uri") == 0 ||
            strcmp(key, "url") == 0 || strcmp(key, "endpoint") == 0 ||
            strcmp(key, "http_target") == 0 || strcmp(key, "target_url") == 0 ||
            strcmp(key, "webhook_url") == 0 || strcmp(key, "callback_url") == 0);
}

/* Infer broker type from surrounding context */
static const char *infer_broker(const char *file_path, const char *source_key) {
    if (strstr(file_path, "pubsub") || strstr(file_path, "pub-sub") ||
        strstr(file_path, "pub_sub")) {
        return "pubsub";
    }
    if (strstr(file_path, "scheduler") || strstr(file_path, "schedule") ||
        strstr(file_path, "cron")) {
        return "cloud_scheduler";
    }
    if (strstr(file_path, "task") || strcmp(source_key, "queue") == 0 ||
        strcmp(source_key, "queue_name") == 0) {
        return "cloud_tasks";
    }
    if (strstr(file_path, "kafka") || strcmp(source_key, "stream") == 0) {
        return "kafka";
    }
    if (strstr(file_path, "sqs") || strstr(file_path, "sns")) {
        return "sqs";
    }
    return "async";
}

/* Scan a YAML mapping for source+target key pairs.
 * Collects all key-value pairs at this level and one level deep (for nested config:). */
// Strip quotes from a YAML scalar value.
static char *strip_yaml_quotes(CBMArena *a, char *v) {
    if (!v || !v[0]) {
        return v;
    }
    int vlen = (int)strlen(v);
    if (vlen >= CBM_QUOTE_PAIR && (v[0] == '"' || v[0] == '\'')) {
        return cbm_arena_strndup(a, v + SKIP_ONE, (size_t)(vlen - PAIR_LEN));
    }
    return v;
}

// Scan a nested YAML block_mapping for target keys (push_endpoint, uri, etc.).
static void scan_nested_mapping_targets(CBMExtractCtx *ctx, TSNode val, const char **targets,
                                        int *n_targets) {
    uint32_t vnc = ts_node_named_child_count(val);
    for (uint32_t vi = 0; vi < vnc; vi++) {
        TSNode vc = ts_node_named_child(val, vi);
        if (strcmp(ts_node_type(vc), "block_mapping") != 0) {
            continue;
        }
        uint32_t mnc = ts_node_named_child_count(vc);
        for (uint32_t mi = 0; mi < mnc; mi++) {
            TSNode mp = ts_node_named_child(vc, mi);
            if (strcmp(ts_node_type(mp), "block_mapping_pair") != 0) {
                continue;
            }
            TSNode mk = ts_node_child_by_field_name(mp, TS_FIELD("key"));
            TSNode mv = ts_node_child_by_field_name(mp, TS_FIELD("value"));
            if (ts_node_is_null(mk) || ts_node_is_null(mv)) {
                continue;
            }
            char *mktext = cbm_node_text(ctx->arena, mk, ctx->source);
            if (mktext && is_target_key(mktext) && *n_targets < MAX_INFRA_BINDINGS) {
                char *mvtext =
                    strip_yaml_quotes(ctx->arena, cbm_node_text(ctx->arena, mv, ctx->source));
                if (mvtext && strstr(mvtext, "://")) {
                    targets[(*n_targets)++] = mvtext;
                }
            }
        }
    }
}

// Emit infra bindings for each source × target pair combination.
static void emit_infra_bindings(CBMExtractCtx *ctx, const char **sources, const char **source_keys,
                                int n_sources, const char **targets, int n_targets) {
    for (int si = 0; si < n_sources; si++) {
        for (int ti = 0; ti < n_targets; ti++) {
            if (!sources[si] || !targets[ti]) {
                continue;
            }
            CBMInfraBinding ib = {
                .source_name = sources[si],
                .target_url = targets[ti],
                .broker = infer_broker(ctx->rel_path, source_keys[si]),
            };
            cbm_infrabinding_push(&ctx->result->infra_bindings, ctx->arena, ib);
        }
    }
}

static void scan_mapping_for_bindings(CBMExtractCtx *ctx, TSNode mapping) {
    const char *sources[MAX_INFRA_BINDINGS] = {NULL};
    const char *source_keys[MAX_INFRA_BINDINGS] = {NULL};
    int n_sources = 0;
    const char *targets[MAX_INFRA_BINDINGS] = {NULL};
    int n_targets = 0;

    uint32_t nc = ts_node_named_child_count(mapping);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode pair = ts_node_named_child(mapping, i);
        if (strcmp(ts_node_type(pair), "block_mapping_pair") != 0) {
            continue;
        }
        TSNode key = ts_node_child_by_field_name(pair, TS_FIELD("key"));
        TSNode val = ts_node_child_by_field_name(pair, TS_FIELD("value"));
        if (ts_node_is_null(key) || ts_node_is_null(val)) {
            continue;
        }
        char *k = cbm_node_text(ctx->arena, key, ctx->source);
        if (!k) {
            continue;
        }

        const char *vtype = ts_node_type(val);
        if (strcmp(vtype, "block_node") != 0 && strcmp(vtype, "block_mapping") != 0) {
            char *v = strip_yaml_quotes(ctx->arena, cbm_node_text(ctx->arena, val, ctx->source));
            if (is_source_key(k) && n_sources < MAX_INFRA_BINDINGS) {
                sources[n_sources] = v;
                source_keys[n_sources] = k;
                n_sources++;
            }
            if (is_target_key(k) && n_targets < MAX_INFRA_BINDINGS && v && strstr(v, "://")) {
                targets[n_targets++] = v;
            }
        } else {
            scan_nested_mapping_targets(ctx, val, targets, &n_targets);
        }
    }

    emit_infra_bindings(ctx, sources, source_keys, n_sources, targets, n_targets);
}

#define INFRA_SCAN_STACK_CAP CBM_SZ_512
static void scan_yaml_for_infra_bindings(CBMExtractCtx *ctx, TSNode root) {
    TSNode stack[INFRA_SCAN_STACK_CAP];
    int top = 0;
    stack[top++] = root;
    while (top > 0) {
        TSNode node = stack[--top];
        if (strcmp(ts_node_type(node), "block_mapping") == 0) {
            scan_mapping_for_bindings(ctx, node);
        }
        uint32_t nc = ts_node_named_child_count(node);
        for (int i = (int)nc - SKIP_ONE; i >= 0 && top < INFRA_SCAN_STACK_CAP; i--) {
            stack[top++] = ts_node_named_child(node, (uint32_t)i);
        }
    }
}

/* ── HCL infrastructure binding extraction ───────────────────────────
 * Scan HCL block nodes (resource, dynamic) for attribute pairs
 * where one is a source key (topic, queue_name) and another is a
 * target key (uri, push_endpoint). Handles nested blocks like
 * push_config { push_endpoint = "..." }. */
// Extract a string value from an HCL attribute value node.  The tree-sitter-hcl
// grammar wraps the literal: attribute → (identifier)(expression → literal_value
// → string_lit → template_literal).  Descend through the expression/literal_value
// wrappers to reach the actual string token before reading it.
static char *extract_hcl_string_val(CBMArena *a, TSNode val_node, const char *source) {
    enum { HCL_MAX_UNWRAP = 5 };
    for (int depth = 0; depth < HCL_MAX_UNWRAP; depth++) {
        const char *vk = ts_node_type(val_node);
        if (strcmp(vk, "expression") == 0 || strcmp(vk, "literal_value") == 0) {
            if (ts_node_named_child_count(val_node) == 0) {
                return NULL;
            }
            val_node = ts_node_named_child(val_node, 0);
            continue;
        }
        if (strcmp(vk, "quoted_template") == 0 || strcmp(vk, "template_literal") == 0 ||
            strcmp(vk, "string_lit") == 0) {
            char *val = cbm_node_text(a, val_node, source);
            return strip_yaml_quotes(a, val);
        }
        return NULL;
    }
    return NULL;
}

// The tree-sitter-hcl grammar nests a block's attributes/sub-blocks inside a
// `body` child rather than directly under the block. Return that body node so
// scanners iterate the right level; fall back to the block itself if no body.
static TSNode hcl_block_body(TSNode block) {
    TSNode body = cbm_find_child_by_kind(block, "body");
    return ts_node_is_null(body) ? block : body;
}

// Scan a nested HCL block for target keys (push_endpoint, uri, etc.).
static void scan_hcl_nested_block_targets(CBMExtractCtx *ctx, TSNode block, const char **targets,
                                          int *n_targets) {
    TSNode body = hcl_block_body(block);
    uint32_t bnc = ts_node_named_child_count(body);
    for (uint32_t bi = 0; bi < bnc; bi++) {
        TSNode bchild = ts_node_named_child(body, bi);
        if (strcmp(ts_node_type(bchild), "attribute") != 0) {
            continue;
        }
        TSNode bkey = ts_node_named_child(bchild, 0);
        TSNode bval = ts_node_named_child(bchild, SKIP_ONE);
        if (ts_node_is_null(bkey) || ts_node_is_null(bval)) {
            continue;
        }
        char *bk = cbm_node_text(ctx->arena, bkey, ctx->source);
        if (!bk || !is_target_key(bk)) {
            continue;
        }
        char *bv = extract_hcl_string_val(ctx->arena, bval, ctx->source);
        if (bv && strstr(bv, "://") && *n_targets < MAX_INFRA_BINDINGS) {
            targets[(*n_targets)++] = bv;
        }
    }
}

/* A scheduler/cron job has no topic/queue source key — its identity is the
 * resource itself, and the binding target is the job's invocation endpoint
 * (uri / http_target / pubsub_target).  Detect such a block by its first label
 * (resource type, e.g. "google_cloud_scheduler_job") and return the job's
 * synthetic source name (its second label / resource name), or NULL if the
 * block is not a scheduler job.  Sets *broker_out to the scheduler broker id. */
static const char *hcl_scheduler_source(CBMExtractCtx *ctx, TSNode block, const char **broker_out) {
    const char *first_label = NULL;
    const char *last_label = NULL;
    uint32_t cc = ts_node_named_child_count(block);
    for (uint32_t i = 0; i < cc; i++) {
        TSNode ch = ts_node_named_child(block, i);
        if (strcmp(ts_node_type(ch), "string_lit") != 0) {
            continue;
        }
        TSNode lit = cbm_find_child_by_kind(ch, "template_literal");
        if (ts_node_is_null(lit)) {
            continue;
        }
        char *label = cbm_node_text(ctx->arena, lit, ctx->source);
        if (!label || !label[0]) {
            continue;
        }
        if (!first_label) {
            first_label = label;
        }
        last_label = label;
    }
    if (!first_label) {
        return NULL;
    }
    /* google_cloud_scheduler_job, aws_cloudwatch_event_rule (cron), etc. */
    if (strstr(first_label, "scheduler") || strstr(first_label, "schedule") ||
        strstr(first_label, "cron")) {
        if (broker_out) {
            *broker_out = "cloud_scheduler";
        }
        return last_label ? last_label : first_label;
    }
    return NULL;
}

static void collect_hcl_binding_values(CBMExtractCtx *ctx, TSNode body, const char **sources,
                                       const char **source_keys, int *source_count,
                                       const char **targets, int *target_count) {
    uint32_t child_count = ts_node_named_child_count(body);
    for (uint32_t index = 0; index < child_count; index++) {
        TSNode child = ts_node_named_child(body, index);
        const char *kind = ts_node_type(child);
        if (strcmp(kind, "block") == 0) {
            scan_hcl_nested_block_targets(ctx, child, targets, target_count);
            continue;
        }
        if (strcmp(kind, "attribute") != 0) {
            continue;
        }
        TSNode key_node = ts_node_named_child(child, 0);
        TSNode value_node = ts_node_named_child(child, SKIP_ONE);
        if (ts_node_is_null(key_node) || ts_node_is_null(value_node)) {
            continue;
        }
        char *key = cbm_node_text(ctx->arena, key_node, ctx->source);
        char *value = extract_hcl_string_val(ctx->arena, value_node, ctx->source);
        if (!key || !value || !value[0]) {
            continue;
        }
        if (is_source_key(key) && *source_count < MAX_INFRA_BINDINGS) {
            sources[*source_count] = value;
            source_keys[*source_count] = key;
            (*source_count)++;
        }
        if (is_target_key(key) && *target_count < MAX_INFRA_BINDINGS && strstr(value, "://")) {
            targets[(*target_count)++] = value;
        }
    }
}

static bool emit_hcl_scheduler_bindings(CBMExtractCtx *ctx, TSNode block, const char **targets,
                                        int target_count) {
    const char *broker = NULL;
    const char *source = hcl_scheduler_source(ctx, block, &broker);
    if (!source) {
        return false;
    }
    for (int index = 0; index < target_count; index++) {
        if (targets[index]) {
            CBMInfraBinding binding = {
                .source_name = source,
                .target_url = targets[index],
                .broker = broker ? broker : "cloud_scheduler",
            };
            cbm_infrabinding_push(&ctx->result->infra_bindings, ctx->arena, binding);
        }
    }
    return true;
}

static void scan_hcl_block_for_bindings(CBMExtractCtx *ctx, TSNode block) {
    const char *sources[MAX_INFRA_BINDINGS] = {NULL};
    const char *source_keys[MAX_INFRA_BINDINGS] = {NULL};
    int n_sources = 0;
    const char *targets[MAX_INFRA_BINDINGS] = {NULL};
    int n_targets = 0;

    TSNode body = hcl_block_body(block);
    collect_hcl_binding_values(ctx, body, sources, source_keys, &n_sources, targets, &n_targets);

    /* Scheduler/cron jobs carry no topic/queue source key — the resource itself
     * is the source. If we found an invocation target (uri/http_target) but no
     * explicit source key, synthesize the source from the scheduler resource so
     * the job→endpoint binding (INFRA_MAPS) still forms. */
    if (n_sources == 0 && n_targets > 0) {
        if (emit_hcl_scheduler_bindings(ctx, block, targets, n_targets)) {
            return;
        }
    }

    emit_infra_bindings(ctx, sources, source_keys, n_sources, targets, n_targets);
}

/* Handle YAML files: walk top-level block_mapping recursively */
static void handle_yaml_nested(CBMExtractCtx *ctx, TSNode node) {
    if (ctx->language != CBM_LANG_YAML) {
        return;
    }
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "block_mapping") != 0) {
        return;
    }
    /* Only process root-level block_mapping (depth 0 or 1) */
    TSNode parent = ts_node_parent(node);
    if (ts_node_is_null(parent)) {
        walk_yaml_mapping(ctx, node, NULL);
    } else {
        const char *pk = ts_node_type(parent);
        if (strcmp(pk, "stream") == 0 || strcmp(pk, "document") == 0 ||
            strcmp(pk, "block_node") == 0) {
            walk_yaml_mapping(ctx, node, NULL);
        }
    }
}

// --- Main unified cursor walk ---

// Scan infra bindings for YAML/JSON/HCL languages.
static void scan_infra_bindings(CBMExtractCtx *ctx, TSNode node) {
    if (ctx->language == CBM_LANG_YAML || ctx->language == CBM_LANG_JSON) {
        const char *nk = ts_node_type(node);
        if (strcmp(nk, "block_sequence") == 0 || strcmp(nk, "block_mapping") == 0 ||
            strcmp(nk, "array") == 0 || strcmp(nk, "document") == 0) {
            scan_yaml_for_infra_bindings(ctx, node);
        }
    } else if (ctx->language == CBM_LANG_HCL) {
        if (strcmp(ts_node_type(node), "block") == 0) {
            scan_hcl_block_for_bindings(ctx, node);
        }
    }
}

/* Extra nodes are grammar-declared trivia (most commonly comments). They still
 * participate in cursor traversal and scope expiry, but none of the unified
 * semantic handlers consumes their contents; documentation is collected by
 * the definition/LSP passes. The grammar predicate covers every language
 * without confusing structured syntax such as SQL COMMENT statements. */
static bool is_unified_trivia_node(TSNode node) {
    return ts_node_is_extra(node);
}

// JS/TS `export_statement` appears in import_node_types so re-exports
// (`export { X } from './m'`) are treated as an import boundary.  But it also
// wraps exported *declarations* (`export function f(cfg: Config) {}`), and
// treating those as an import boundary wrongly suppresses USAGE edges for type
// references inside the exported declaration's signature.  Return true when the
// node is an export that contains a declaration child (i.e. NOT a bare re-export),
// so the caller skips the import-scope push for it.
static bool is_export_of_declaration(TSNode node) {
    if (strcmp(ts_node_type(node), "export_statement") != 0) {
        return false;
    }
    uint32_t n = ts_node_child_count(node);
    for (uint32_t i = 0; i < n; i++) {
        const char *ck = ts_node_type(ts_node_child(node, i));
        if (strcmp(ck, "function_declaration") == 0 || strcmp(ck, "class_declaration") == 0 ||
            strcmp(ck, "lexical_declaration") == 0 ||
            strcmp(ck, "abstract_class_declaration") == 0 ||
            strcmp(ck, "interface_declaration") == 0 || strcmp(ck, "enum_declaration") == 0 ||
            strcmp(ck, "type_alias_declaration") == 0 || strcmp(ck, "variable_declaration") == 0 ||
            strcmp(ck, "generator_function_declaration") == 0) {
            return true;
        }
    }
    return false;
}

// Some languages encode imports with the same generic AST node used by every
// ordinary invocation. Static node-kind membership is therefore not enough to
// make the whole subtree an import scope.
static TSNode import_boundary_head(TSNode node) {
    static const char *const field_names[] = {"function", "method", "command_name", "name"};
    for (size_t i = 0; i < sizeof(field_names) / sizeof(field_names[0]); i++) {
        const char *field_name = field_names[i];
        TSNode head = ts_node_child_by_field_name(node, field_name, (uint32_t)strlen(field_name));
        if (!ts_node_is_null(head)) {
            return head;
        }
    }
    return ts_node_named_child_count(node) > 0 ? ts_node_named_child(node, 0) : (TSNode){0};
}

static bool is_actual_import_boundary(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec) {
    bool direct_import = spec->import_node_types && cbm_kind_in_set(node, spec->import_node_types);
    bool from_import = spec->import_from_types && cbm_kind_in_set(node, spec->import_from_types);
    if (!direct_import && !from_import) {
        return false;
    }

    const char *kind = ts_node_type(node);
    TSNode head = import_boundary_head(node);
    char *name = ts_node_is_null(head) ? NULL : cbm_node_text(ctx->arena, head, ctx->source);

    switch (ctx->language) {
    case CBM_LANG_ELIXIR:
        return strcmp(kind, "call") != 0 ||
               (name && (strcmp(name, "import") == 0 || strcmp(name, "alias") == 0 ||
                         strcmp(name, "require") == 0 || strcmp(name, "use") == 0));
    case CBM_LANG_LUA:
        return strcmp(kind, "function_call") != 0 || (name && strcmp(name, "require") == 0);
    case CBM_LANG_RUBY:
        return strcmp(kind, "call") != 0 ||
               (name && (strcmp(name, "require") == 0 || strcmp(name, "require_relative") == 0));
    case CBM_LANG_BASH:
        return strcmp(kind, "command") != 0 ||
               (name && (strcmp(name, "source") == 0 || strcmp(name, ".") == 0));
    case CBM_LANG_R:
        if (strcmp(kind, "call") != 0 || !name) {
            return strcmp(kind, "call") != 0;
        }
        return strcmp(name, "library") == 0 || strcmp(name, "require") == 0 ||
               strcmp(name, "requireNamespace") == 0 || strcmp(name, "loadNamespace") == 0 ||
               strcmp(name, "source") == 0 || strcmp(name, "box::use") == 0;
    case CBM_LANG_ZIG: {
        if (strcmp(kind, "builtin_function") != 0) {
            return true;
        }
        char *text = cbm_node_text(ctx->arena, node, ctx->source);
        return text && (strncmp(text, "@import", sizeof("@import") - SKIP_ONE) == 0 ||
                        strncmp(text, "@cImport", sizeof("@cImport") - SKIP_ONE) == 0);
    }
    case CBM_LANG_SCSS:
        /* `@include` is an executable mixin invocation, not a module import. */
        return strcmp(kind, "include_statement") != 0;
    default:
        return true;
    }
}

/* NASM labels and instructions are flat siblings. For an actual instruction,
 * find the nearest preceding label at the first ancestor level that has one.
 * This is structural scope recovery; the instruction mnemonic is not used. */
static TSNode nasm_wrapped_label(TSNode node) {
    if (ts_node_is_null(node)) {
        return (TSNode){0};
    }
    if (strcmp(ts_node_type(node), "label") == 0) {
        return node;
    }
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "instruction") != 0 && strcmp(kind, "source_line") != 0) {
        return (TSNode){0};
    }
    uint32_t child_count = ts_node_named_child_count(node);
    for (uint32_t child_index = 0; child_index < child_count; ++child_index) {
        TSNode child = ts_node_named_child(node, child_index);
        if (strcmp(ts_node_type(child), "label") == 0) {
            return child;
        }
        uint32_t grandchild_count = ts_node_named_child_count(child);
        for (uint32_t grandchild_index = 0; grandchild_index < grandchild_count;
             ++grandchild_index) {
            TSNode grandchild = ts_node_named_child(child, grandchild_index);
            if (strcmp(ts_node_type(grandchild), "label") == 0) {
                return grandchild;
            }
        }
    }
    return (TSNode){0};
}

static TSNode nasm_preceding_label(TSNode node) {
    TSNode current = node;
    for (int level = 0; level < MAX_NASM_LABEL_ANCESTOR_LEVELS && !ts_node_is_null(current);
         level++) {
        TSNode previous = ts_node_prev_named_sibling(current);
        while (!ts_node_is_null(previous)) {
            TSNode label = nasm_wrapped_label(previous);
            if (!ts_node_is_null(label)) {
                return label;
            }
            previous = ts_node_prev_named_sibling(previous);
        }
        TSNode parent = ts_node_parent(current);
        if (ts_node_is_null(parent) || strcmp(ts_node_type(current), "source_file") == 0) {
            break;
        }
        current = parent;
    }
    return (TSNode){0};
}

/* Traditional ObjectScript routines are flat: a tag statement is followed by
 * sibling command statements until the next tag. Re-anchor each top-level
 * command statement to its nearest preceding tag, just as NASM instructions
 * are re-anchored to flat labels. Braced `procedure` nodes already provide a
 * real lexical boundary and deliberately bypass this recovery path. */
static TSNode objectscript_routine_statement_tag(TSNode statement) {
    TSNode tag_statement = cbm_find_child_by_kind(statement, "tag_statement");
    return ts_node_is_null(tag_statement) ? (TSNode){0}
                                          : cbm_find_child_by_kind(tag_statement, "tag");
}

static TSNode objectscript_routine_preceding_tag(TSNode node) {
    if (strcmp(ts_node_type(node), "statement") != 0) {
        return (TSNode){0};
    }
    TSNode parent = ts_node_parent(node);
    if (ts_node_is_null(parent) || strcmp(ts_node_type(parent), "source_file") != 0 ||
        !ts_node_is_null(cbm_find_child_by_kind(node, "tag_statement")) ||
        !ts_node_is_null(cbm_find_child_by_kind(node, "procedure"))) {
        return (TSNode){0};
    }
    for (TSNode previous = ts_node_prev_named_sibling(node); !ts_node_is_null(previous);
         previous = ts_node_prev_named_sibling(previous)) {
        TSNode tag = objectscript_routine_statement_tag(previous);
        if (!ts_node_is_null(tag)) {
            return tag;
        }
    }
    return (TSNode){0};
}

static bool push_pre_node_scope(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                WalkState *state, uint32_t depth) {
    for (int i = 0; i < state->scope_top; i++) {
        if (state->scopes[i].kind == SCOPE_FUNC) {
            return false;
        }
    }

    TSNode label = {0};
    if (ctx->language == CBM_LANG_NASM && strcmp(ts_node_type(node), "actual_instruction") == 0) {
        label = nasm_preceding_label(node);
    } else if (ctx->language == CBM_LANG_OBJECTSCRIPT_ROUTINE) {
        if (strcmp(ts_node_type(node), "tag_statement") == 0) {
            /* A parameterized flat tag owns its header as well as the following
             * sibling command statements. Anchor before descending so its
             * parameter_list records lexical bindings under the same tag QN. */
            label = cbm_find_child_by_kind(node, "tag");
        } else {
            label = objectscript_routine_preceding_tag(node);
        }
    }
    if (ts_node_is_null(label)) {
        return false;
    }
    const char *fqn = compute_func_qn(ctx, label, spec, state);
    if (!fqn) {
        return false;
    }
    uint32_t anchor_start = ts_node_start_byte(label);
    uint32_t anchor_end = ts_node_end_byte(label);
    bool same_flat_callable = state->flat_function_scope_id != 0 &&
                              state->flat_anchor_start_byte == anchor_start &&
                              state->flat_anchor_end_byte == anchor_end &&
                              state->flat_function_qn && strcmp(state->flat_function_qn, fqn) == 0;
    bool pushed = same_flat_callable
                      ? push_existing_lexical_scope(state, SCOPE_FUNC, depth, fqn,
                                                    state->flat_function_scope_id, node)
                      : push_function_scope(state, depth, fqn, node);
    if (pushed && !same_flat_callable) {
        state->flat_function_scope_id = state->scopes[state->scope_top - SKIP_ONE].lexical_scope_id;
        state->flat_anchor_start_byte = anchor_start;
        state->flat_anchor_end_byte = anchor_end;
        state->flat_function_qn = fqn;
    }
    return pushed;
}

static bool unified_kind_in_set(const char *kind, const char *const *set) {
    for (int i = 0; kind && set && set[i]; i++) {
        if (strcmp(kind, set[i]) == 0) {
            return true;
        }
    }
    return false;
}

static bool lexical_boundary_kind(TSNode node, CBMLexicalScopeKind *out_kind) {
    const char *kind = ts_node_type(node);
    static const char *const block_kinds[] = {"block",
                                              "statement_block",
                                              "compound_statement",
                                              "switch_body",
                                              "catch_clause",
                                              "except_clause",
                                              "finally_clause",
                                              "for_statement",
                                              "for_in_statement",
                                              "for_of_statement",
                                              "enhanced_for_statement",
                                              "foreach_statement",
                                              "foreach_clause",
                                              "loop_expression",
                                              "match_block",
                                              "case_block",
                                              "script_block",
                                              "do_block",
                                              NULL};
    static const char *const comprehension_kinds[] = {
        "list_comprehension",   "set_comprehension",        "dictionary_comprehension",
        "generator_expression", "comprehension_expression", NULL};
    static const char *const anonymous_function_kinds[] = {"lambda",
                                                           "lambda_expression",
                                                           "anonymous_function",
                                                           "anonymous_function_creation_expression",
                                                           "anonymous_method_expression",
                                                           "arrow_function",
                                                           "closure_expression",
                                                           "func_literal",
                                                           "function_expression",
                                                           "function_literal",
                                                           NULL};
    /* Rust inline modules own independent item/import namespaces. Without a
     * concrete module scope, `mod inner { use ... as x; }` leaks x into every
     * sibling function in the file. */
    if (strcmp(kind, "mod_item") == 0) {
        *out_kind = CBM_LEXICAL_SCOPE_MODULE;
        return true;
    }
    if (unified_kind_in_set(kind, comprehension_kinds)) {
        *out_kind = CBM_LEXICAL_SCOPE_COMPREHENSION;
        return true;
    }
    if (unified_kind_in_set(kind, anonymous_function_kinds)) {
        *out_kind = CBM_LEXICAL_SCOPE_FUNCTION;
        return true;
    }
    if (unified_kind_in_set(kind, block_kinds)) {
        *out_kind = CBM_LEXICAL_SCOPE_BLOCK;
        return true;
    }
    return false;
}

static bool node_already_has_lexical_scope(const WalkState *state, TSNode node) {
    uint32_t start = ts_node_start_byte(node);
    uint32_t end = ts_node_end_byte(node);
    for (int i = state->scope_top - SKIP_ONE; i >= 0; i--) {
        const CBMLexicalScope *scope =
            lexical_scope_by_id(state, state->scopes[i].lexical_scope_id);
        if (scope && scope->start_byte == start && scope->end_byte == end) {
            return true;
        }
    }
    return false;
}

static void push_lexical_boundary(TSNode node, WalkState *state, uint32_t depth) {
    CBMLexicalScopeKind kind;
    if (!node_already_has_lexical_scope(state, node) && lexical_boundary_kind(node, &kind)) {
        (void)push_lexical_scope(state, SCOPE_LEXICAL, depth, NULL, node, kind);
    }
}

static bool has_function_scope(const WalkState *state) {
    for (int i = 0; i < state->scope_top; i++) {
        if (state->scopes[i].kind == SCOPE_FUNC) {
            return true;
        }
    }
    return false;
}

static bool is_objectscript_language(CBMLanguage language) {
    return language == CBM_LANG_OBJECTSCRIPT_UDL || language == CBM_LANG_OBJECTSCRIPT_ROUTINE;
}

static void objectscript_map_method_argument(CBMExtractCtx *ctx, TSNode argument,
                                             WalkState *state) {
    if (strcmp(ts_node_type(argument), "argument") != 0) {
        return;
    }
    TSNode parameter = (TSNode){0};
    TSNode type_name = (TSNode){0};
    for (uint32_t i = 0; i < ts_node_named_child_count(argument); i++) {
        TSNode child = ts_node_named_child(argument, i);
        const char *kind = ts_node_type(child);
        if (strcmp(kind, "method_arg") == 0) {
            parameter = child;
        } else if (strcmp(kind, "return_type") == 0) {
            type_name = cbm_find_child_by_kind(child, "typename");
        }
    }
    if (ts_node_is_null(parameter) || ts_node_is_null(type_name)) {
        return;
    }
    TSNode local_name = cbm_find_child_by_kind(parameter, "expr_atom");
    if (ts_node_is_null(local_name)) {
        local_name = parameter;
    }
    char *name = cbm_node_text(ctx->arena, local_name, ctx->source);
    char *type = cbm_node_text(ctx->arena, type_name, ctx->source);
    if (name && name[0] && type && type[0]) {
        os_type_map_add(&state->os_type_map, name, type);
    }
}

static void objectscript_seed_method_argument_types(CBMExtractCtx *ctx, TSNode node,
                                                    WalkState *state) {
    state->os_type_map.count = state->os_type_map.class_base_count;
    TSNode definition = cbm_find_child_by_kind(node, "method_definition");
    TSNode arguments =
        cbm_find_child_by_kind(ts_node_is_null(definition) ? node : definition, "arguments");
    for (uint32_t i = 0; !ts_node_is_null(arguments) && i < ts_node_named_child_count(arguments);
         i++) {
        objectscript_map_method_argument(ctx, ts_node_named_child(arguments, i), state);
    }
}

static void remember_split_function_scope(WalkState *state, TSNode node, const char *fqn) {
    state->split_function_scope_id = state->scopes[state->scope_top - SKIP_ONE].lexical_scope_id;
    state->split_signature_start_byte = ts_node_start_byte(node);
    state->split_signature_end_byte = ts_node_end_byte(node);
    state->split_function_qn = fqn;
}

static bool is_split_function_signature(CBMLanguage language, TSNode node) {
    const char *kind = ts_node_type(node);
    if (language == CBM_LANG_DART) {
        return strcmp(kind, "function_signature") == 0 || strcmp(kind, "method_signature") == 0;
    }
    return language == CBM_LANG_LLVM_IR && strcmp(kind, "function_header") == 0;
}

static bool push_function_boundary(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                   WalkState *state, uint32_t depth) {
    if (!spec->function_node_types || !cbm_kind_in_set(node, spec->function_node_types)) {
        return false;
    }
    if (ctx->language == CBM_LANG_OCAML && has_function_scope(state)) {
        return true;
    }
    const char *fqn = compute_func_qn(ctx, node, spec, state);
    if (!fqn || !push_function_scope(state, depth, fqn, node)) {
        return true;
    }
    if (is_split_function_signature(ctx->language, node)) {
        remember_split_function_scope(state, node, fqn);
    }
    if (is_objectscript_language(ctx->language)) {
        objectscript_seed_method_argument_types(ctx, node, state);
    }
    return true;
}

static bool push_namespace_boundary(CBMExtractCtx *ctx, TSNode node, WalkState *state,
                                    uint32_t depth) {
    if (!cbm_is_namespace_scope_kind(ctx->language, ts_node_type(node))) {
        return false;
    }
    const char *namespace_qn = compute_class_qn(ctx, node, state);
    if (namespace_qn) {
        (void)push_lexical_scope(state, SCOPE_NAMESPACE, depth, namespace_qn, node,
                                 CBM_LEXICAL_SCOPE_MODULE);
    }
    return true;
}

static bool push_class_boundary(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                WalkState *state, uint32_t depth) {
    if (!spec->class_node_types || !cbm_kind_in_set(node, spec->class_node_types)) {
        return false;
    }
    const char *class_qn = compute_class_qn(ctx, node, state);
    if (!class_qn) {
        return true;
    }
    (void)push_lexical_scope(state, SCOPE_CLASS, depth, class_qn, node, CBM_LEXICAL_SCOPE_CLASS);
    if (is_objectscript_language(ctx->language)) {
        state->os_type_map.count = 0;
        state->os_type_map.class_base_count = 0;
    }
    return true;
}

static bool push_nix_attrset_boundary(CBMExtractCtx *ctx, TSNode node, WalkState *state,
                                      uint32_t depth) {
    if (ctx->language != CBM_LANG_NIX || strcmp(ts_node_type(node), "binding") != 0 ||
        !cbm_nix_binding_is_attrset_scope(node)) {
        return false;
    }
    const char *class_qn = compute_class_qn(ctx, node, state);
    if (class_qn) {
        (void)push_scope(state, SCOPE_CLASS, depth, class_qn);
    }
    return true;
}

static bool push_rust_impl_boundary(CBMExtractCtx *ctx, TSNode node, WalkState *state,
                                    uint32_t depth) {
    if (ctx->language != CBM_LANG_RUST || strcmp(ts_node_type(node), "impl_item") != 0) {
        return false;
    }
    TSNode type_node = ts_node_child_by_field_name(node, TS_FIELD("type"));
    if (ts_node_is_null(type_node)) {
        return true;
    }
    char *type_name = cbm_node_text(ctx->arena, type_node, ctx->source);
    if (type_name && type_name[0]) {
        const char *type_qn = cbm_fqn_compute(ctx->arena, ctx->project, ctx->rel_path, type_name);
        (void)push_lexical_scope(state, SCOPE_CLASS, depth, type_qn, node, CBM_LEXICAL_SCOPE_CLASS);
    }
    return true;
}

static TSNode preceding_split_signature(TSNode body, const char *const *signature_kinds) {
    for (TSNode previous = ts_node_prev_sibling(body); !ts_node_is_null(previous);
         previous = ts_node_prev_sibling(previous)) {
        if (unified_kind_in_set(ts_node_type(previous), signature_kinds)) {
            return previous;
        }
    }
    return (TSNode){0};
}

static bool is_pending_split_function(const WalkState *state, TSNode signature, const char *fqn) {
    return state->split_function_scope_id != 0 && state->split_function_qn &&
           strcmp(state->split_function_qn, fqn) == 0 &&
           state->split_signature_start_byte == ts_node_start_byte(signature) &&
           state->split_signature_end_byte == ts_node_end_byte(signature);
}

static void push_split_function_body(CBMExtractCtx *ctx, TSNode body, const CBMLangSpec *spec,
                                     WalkState *state, uint32_t depth,
                                     const char *const *signature_kinds) {
    TSNode signature = preceding_split_signature(body, signature_kinds);
    if (ts_node_is_null(signature)) {
        return;
    }
    const char *fqn = compute_func_qn(ctx, signature, spec, state);
    if (!fqn) {
        return;
    }
    if (is_pending_split_function(state, signature, fqn)) {
        (void)push_existing_lexical_scope(state, SCOPE_FUNC, depth, fqn,
                                          state->split_function_scope_id, body);
    } else {
        (void)push_function_scope(state, depth, fqn, body);
    }
    state->split_function_scope_id = 0;
    state->split_function_qn = NULL;
}

static bool push_dart_function_body(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                    WalkState *state, uint32_t depth) {
    static const char *const signature_kinds[] = {"function_signature", "method_signature", NULL};
    if (ctx->language != CBM_LANG_DART || strcmp(ts_node_type(node), "function_body") != 0) {
        return false;
    }
    push_split_function_body(ctx, node, spec, state, depth, signature_kinds);
    return true;
}

static bool push_llvm_function_body(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                    WalkState *state, uint32_t depth) {
    static const char *const signature_kinds[] = {"function_header", NULL};
    if (ctx->language != CBM_LANG_LLVM_IR || strcmp(ts_node_type(node), "function_body") != 0) {
        return false;
    }
    push_split_function_body(ctx, node, spec, state, depth, signature_kinds);
    return true;
}

static void push_primary_boundary(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                  WalkState *state, uint32_t depth) {
    if (push_function_boundary(ctx, node, spec, state, depth) ||
        push_namespace_boundary(ctx, node, state, depth) ||
        push_class_boundary(ctx, node, spec, state, depth) ||
        push_nix_attrset_boundary(ctx, node, state, depth) ||
        push_rust_impl_boundary(ctx, node, state, depth) ||
        push_dart_function_body(ctx, node, spec, state, depth)) {
        return;
    }
    (void)push_llvm_function_body(ctx, node, spec, state, depth);
}

static void push_metric_boundary(TSNode node, const CBMLangSpec *spec, WalkState *state,
                                 uint32_t depth) {
    if (ts_node_is_named(node) && cbm_is_loop_node_type(ts_node_type(node))) {
        (void)push_scope(state, SCOPE_LOOP, depth, NULL);
    } else if (spec->branching_node_types && cbm_kind_in_set(node, spec->branching_node_types)) {
        (void)push_scope(state, SCOPE_BRANCH, depth, NULL);
    }
}

// Push scope markers for function, class, call, and import boundary nodes.
static void push_boundary_scopes(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                 WalkState *state, uint32_t depth,
                                 const CBMInvocationDescriptor *invocation) {
    push_primary_boundary(ctx, node, spec, state, depth);
    push_lexical_boundary(node, state, depth);
    push_call_scope(state, depth, invocation);
    if (is_actual_import_boundary(ctx, node, spec) && !is_export_of_declaration(node)) {
        (void)push_scope(state, SCOPE_IMPORT, depth, NULL);
    }
    push_metric_boundary(node, spec, state, depth);
}

void cbm_extract_unified(CBMExtractCtx *ctx) {
    const CBMLangSpec *spec = cbm_lang_spec(ctx->language);
    if (!spec) {
        return;
    }

    TSTreeCursor cursor = ts_tree_cursor_new(ctx->root);
    TSTreeCursor occurrence_cursor = ts_tree_cursor_copy(&cursor);
    WalkState state;
    memset(&state, 0, sizeof(state));
    state.current_cursor = &cursor;
    state.occurrence_cursor = &occurrence_cursor;
    state.arena = ctx->arena;
    state.language = ctx->language;
    state.scopes = state.inline_scopes;
    state.scope_capacity = MAX_SCOPES;
    state.lexical_scopes = state.inline_lexical_scopes;
    state.lexical_scope_capacity = INLINE_LEXICAL_SCOPES;
    state.usage_start_index = ctx->result->usages.count;
    state.root_lexical_scope_id = add_lexical_scope(&state, ctx->root, CBM_LEXICAL_SCOPE_MODULE);
    /* Base walk-state tuple (previously established by the first
     * recompute_state call): module scope, nothing else active. */
    state.enclosing_func_qn = ctx->module_qn;
    state.enclosing_class_qn = NULL;
    state.invocation_kind = CBM_INVOCATION_NONE;
    state.callee_expr = (TSNode){0};
    state.callee_leaf = (TSNode){0};
    state.inside_import = false;
    state.loop_depth = 0;
    state.branch_depth = 0;

    uint32_t depth = 0;

    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        bool trivia = is_unified_trivia_node(node);
        if (!trivia) {
            /* Trivia consumes no semantic state. Scope expiry may be deferred
             * until the next code-bearing node; pop restores the displaced
             * tuple and push applies the new frame's effect, both O(1) --
             * the old whole-stack recompute here was O(depth) per node and
             * quadratic on the deep-nesting torture tests. */
            pop_expired_scopes(&state, depth);
            (void)push_pre_node_scope(ctx, node, spec, &state, depth);

            handle_string_constants(ctx, node, &state);
            handle_objectscript_type_map(ctx, node, &state);
            CBMInvocationDescriptor invocation = handle_calls(ctx, node, spec, &state);
            handle_usages(ctx, node, spec, &state);
            handle_throws(ctx, node, spec, &state);
            handle_readwrites(ctx, node, spec, &state);
            handle_type_refs(ctx, node, spec, &state);
            handle_env_accesses(ctx, node, spec, &state);
            handle_type_assigns(ctx, node, spec, &state);
            handle_string_refs(ctx, node, &state);
            handle_yaml_nested(ctx, node);
            scan_infra_bindings(ctx, node);

            push_boundary_scopes(ctx, node, spec, &state, depth, &invocation);
        }

        /* Lexer-terminal trivia has no semantic work and no descendants. Avoid
         * asking the cursor to construct a child iterator for every one of
         * hundreds of thousands of flat comment siblings. Structured extras
         * still descend normally. */
        if ((!trivia || ts_node_child_count(node) > 0) &&
            ts_tree_cursor_goto_first_child(&cursor)) {
            depth++;
            continue;
        }
        if (ts_tree_cursor_goto_next_sibling(&cursor)) {
            continue;
        }
        bool found = false;
        while (ts_tree_cursor_goto_parent(&cursor)) {
            depth--;
            if (ts_tree_cursor_goto_next_sibling(&cursor)) {
                found = true;
                break;
            }
        }
        if (!found) {
            break;
        }
    }

    cbm_finalize_lexical_usages(ctx, &state);
    ts_tree_cursor_delete(&occurrence_cursor);
    ts_tree_cursor_delete(&cursor);
}
