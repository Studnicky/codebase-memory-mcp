#include "cbm.h"
#include "arena.h" // CBMArena
#include "helpers.h"
#include "lang_specs.h"
#include "extract_unified.h"
#include "tree_sitter/api.h" // TSNode, ts_node_*
#include "foundation/constants.h"
#include "extract_node_stack.h"
#include <stdint.h> // uint32_t
#include <string.h>

enum {
    TYPE_ASSIGN_FACTORY_PREFIX_LEN = 3,
    TYPE_ASSIGN_CLIENT_SUFFIX_LEN = 6,
    TYPE_ASSIGN_STUB_SUFFIX_LEN = 4,
    TYPE_ASSIGN_STACK_INITIAL_CAPACITY = 4096,
};
#include <ctype.h>

// Extract type from new_expression / object_creation_expression.
static const char *extract_new_expr_type(CBMArena *a, TSNode rhs, const char *source) {
    TSNode type_node = ts_node_child_by_field_name(rhs, TS_FIELD("type"));
    if (!ts_node_is_null(type_node)) {
        const char *tk = ts_node_type(type_node);
        if (strcmp(tk, "type_identifier") == 0 || strcmp(tk, "identifier") == 0 ||
            strcmp(tk, "simple_identifier") == 0) {
            return cbm_node_text(a, type_node, source);
        }
        if (strcmp(tk, "generic_type") == 0 && ts_node_child_count(type_node) > 0) {
            return cbm_node_text(a, ts_node_child(type_node, 0), source);
        }
        return cbm_node_text(a, type_node, source);
    }
    // Fallback: first identifier child
    for (uint32_t i = 0; i < ts_node_child_count(rhs); i++) {
        TSNode child = ts_node_child(rhs, i);
        const char *ck = ts_node_type(child);
        if (strcmp(ck, "identifier") == 0 || strcmp(ck, "type_identifier") == 0 ||
            strcmp(ck, "simple_identifier") == 0) {
            return cbm_node_text(a, child, source);
        }
    }
    return NULL;
}

static bool constructor_factory_name(const char *name) {
    if (!name || !name[0]) {
        return false;
    }
    const char *last = strrchr(name, '.');
    last = last ? last + SKIP_ONE : name;
    bool prefixed = (strncmp(last, "New", TYPE_ASSIGN_FACTORY_PREFIX_LEN) == 0 ||
                     strncmp(last, "new", TYPE_ASSIGN_FACTORY_PREFIX_LEN) == 0) &&
                    last[TYPE_ASSIGN_FACTORY_PREFIX_LEN];
    if (!prefixed) {
        return false;
    }
    size_t length = strlen(last);
    return (length > TYPE_ASSIGN_CLIENT_SUFFIX_LEN &&
            strcmp(last + length - TYPE_ASSIGN_CLIENT_SUFFIX_LEN, "Client") == 0) ||
           (length > TYPE_ASSIGN_STUB_SUFFIX_LEN &&
            strcmp(last + length - TYPE_ASSIGN_STUB_SUFFIX_LEN, "Stub") == 0);
}

static const char *extract_call_constructor_type(CBMArena *arena, TSNode rhs, const char *source) {
    TSNode function = ts_node_child_by_field_name(rhs, TS_FIELD("function"));
    if (ts_node_is_null(function) && ts_node_child_count(rhs) > 0) {
        function = ts_node_child(rhs, 0);
    }
    if (ts_node_is_null(function)) {
        return NULL;
    }
    char *name = cbm_node_text(arena, function, source);
    if (name && ((name[0] >= 'A' && name[0] <= 'Z') || constructor_factory_name(name))) {
        return name;
    }
    return NULL;
}

static const char *extract_field_constructor_type(CBMArena *arena, TSNode rhs, const char *source,
                                                  const char *field, uint32_t field_length) {
    TSNode type = ts_node_child_by_field_name(rhs, field, field_length);
    return ts_node_is_null(type) ? NULL : cbm_node_text(arena, type, source);
}

// Extract class/type name from a constructor expression.
// e.g., new Foo() -> "Foo", Foo() -> "Foo" (if uppercase), Foo{} -> "Foo"
static const char *extract_constructor_type(CBMArena *a, TSNode rhs, const char *source,
                                            CBMLanguage lang) {
    const char *kind = ts_node_type(rhs);

    if (strcmp(kind, "new_expression") == 0 || strcmp(kind, "object_creation_expression") == 0) {
        return extract_new_expr_type(a, rhs, source);
    }

    if (strcmp(kind, "call") == 0 || strcmp(kind, "call_expression") == 0) {
        return extract_call_constructor_type(a, rhs, source);
    }

    if (strcmp(kind, "composite_literal") == 0) {
        return extract_field_constructor_type(a, rhs, source, TS_FIELD("type"));
    }

    if (lang == CBM_LANG_RUST && strcmp(kind, "struct_expression") == 0) {
        return extract_field_constructor_type(a, rhs, source, TS_FIELD("name"));
    }

    return NULL;
}

// Emit a type assignment if var_name and constructor type are valid.
static void try_emit_type_assign(CBMExtractCtx *ctx, TSNode var_node, TSNode rhs_node,
                                 const char *func_qn) {
    char *var_name = cbm_node_text(ctx->arena, var_node, ctx->source);
    const char *type_name =
        extract_constructor_type(ctx->arena, rhs_node, ctx->source, ctx->language);
    if (var_name && var_name[0] && type_name && type_name[0]) {
        CBMTypeAssign ta;
        ta.var_name = var_name;
        ta.type_name = type_name;
        ta.enclosing_func_qn = func_qn;
        cbm_typeassign_push(&ctx->result->type_assigns, ctx->arena, ta);
    }
}

// Process assignment-type nodes (left/right fields with identifier check).
static void process_assignment_type_assign(CBMExtractCtx *ctx, TSNode node, const char *func_qn) {
    TSNode left = ts_node_child_by_field_name(node, TS_FIELD("left"));
    TSNode right = ts_node_child_by_field_name(node, TS_FIELD("right"));
    if (ts_node_is_null(right)) {
        right = ts_node_child_by_field_name(node, TS_FIELD("value"));
    }
    if (!ts_node_is_null(left) && !ts_node_is_null(right)) {
        const char *lk = ts_node_type(left);
        if (strcmp(lk, "identifier") == 0 || strcmp(lk, "simple_identifier") == 0) {
            try_emit_type_assign(ctx, left, right, func_qn);
        }
    }
}

// Process Go short_var_declaration/var_spec nodes.
static void process_go_var_type_assign(CBMExtractCtx *ctx, TSNode node, const char *func_qn) {
    TSNode left = ts_node_child_by_field_name(node, TS_FIELD("name"));
    if (ts_node_is_null(left)) {
        left = ts_node_child_by_field_name(node, TS_FIELD("left"));
    }
    TSNode right = ts_node_child_by_field_name(node, TS_FIELD("value"));
    if (ts_node_is_null(right)) {
        right = ts_node_child_by_field_name(node, TS_FIELD("right"));
    }
    if (!ts_node_is_null(left) && !ts_node_is_null(right)) {
        try_emit_type_assign(ctx, left, right, func_qn);
    }
}

// Process JS/TS variable_declarator nodes (name + value with identifier check).
static void process_declarator_type_assign(CBMExtractCtx *ctx, TSNode node, const char *func_qn) {
    TSNode name_node = ts_node_child_by_field_name(node, TS_FIELD("name"));
    TSNode value_node = ts_node_child_by_field_name(node, TS_FIELD("value"));
    if (!ts_node_is_null(name_node) && !ts_node_is_null(value_node)) {
        const char *nk = ts_node_type(name_node);
        if (strcmp(nk, "identifier") == 0 || strcmp(nk, "simple_identifier") == 0) {
            try_emit_type_assign(ctx, name_node, value_node, func_qn);
        }
    }
}

// Process Rust let_declaration nodes (pattern + value).
static void process_rust_let_type_assign(CBMExtractCtx *ctx, TSNode node, const char *func_qn) {
    TSNode pat = ts_node_child_by_field_name(node, TS_FIELD("pattern"));
    TSNode val = ts_node_child_by_field_name(node, TS_FIELD("value"));
    if (!ts_node_is_null(pat) && !ts_node_is_null(val)) {
        if (strcmp(ts_node_type(pat), "identifier") == 0) {
            try_emit_type_assign(ctx, pat, val, func_qn);
        }
    }
}

// Process assignment nodes (assignment, short_var_declaration, variable_declarator,
// let_declaration).
static void process_type_assign_node(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                     const char *func_qn) {
    const char *kind = ts_node_type(node);

    if (cbm_kind_in_set(node, spec->assignment_node_types)) {
        process_assignment_type_assign(ctx, node, func_qn);
    }
    if (strcmp(kind, "short_var_declaration") == 0 || strcmp(kind, "var_spec") == 0) {
        process_go_var_type_assign(ctx, node, func_qn);
    }
    if (strcmp(kind, "variable_declarator") == 0) {
        process_declarator_type_assign(ctx, node, func_qn);
    }
    if (strcmp(kind, "let_declaration") == 0 && ctx->language == CBM_LANG_RUST) {
        process_rust_let_type_assign(ctx, node, func_qn);
    }
}

// Walk AST for assignment patterns where RHS is a constructor call.
static void walk_type_assigns(CBMExtractCtx *ctx, TSNode root, const CBMLangSpec *spec) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, TYPE_ASSIGN_STACK_INITIAL_CAPACITY);
    ts_nstack_push(&stack, ctx->arena, root);
    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        process_type_assign_node(ctx, node, spec, cbm_enclosing_func_qn_cached(ctx, node));
        ts_nstack_push_children(&stack, ctx->arena, node);
    }
}

void cbm_extract_type_assigns(CBMExtractCtx *ctx) {
    const CBMLangSpec *spec = cbm_lang_spec(ctx->language);
    if (!spec) {
        return;
    }

    walk_type_assigns(ctx, ctx->root, spec);
}

// --- Unified handler ---

void handle_type_assigns(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                         WalkState *state) {
    process_type_assign_node(ctx, node, spec, state->enclosing_func_qn);
}
