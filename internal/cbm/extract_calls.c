#include "cbm.h"
#include "arena.h" // CBMArena, cbm_arena_sprintf
#include "helpers.h"
#include "lang_specs.h"
#include "macro_table.h"
#include "extract_unified.h"
#include "foundation/constants.h"
#include "extract_node_stack.h"
#include "service_patterns.h" // cbm_service_pattern_route_method (#952)
#include "tree_sitter/api.h"  // TSNode, ts_node_*
#include <stdint.h>           // uint32_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#if defined(CBM_KOTLIN_DEDUP_TEST_API) && CBM_KOTLIN_DEDUP_TEST_API
#include <stdatomic.h>
#endif

/* Max ancestor depth for Lean type-position check. */
enum { LEAN_MAX_PARENT_DEPTH = 20 };
/* Max positional args to scan for URL/string. */
enum { MAX_POSITIONAL_SCAN = 3 };
/* Max positional args to scan for handler ref. */
enum { MAX_HANDLER_SCAN = 4 };
/* Max string arg length before rejection. */
enum { MAX_STRING_ARG_LEN = CBM_SZ_512 };
/* Min printable ASCII (space). */
enum { MIN_PRINTABLE = 0x20 };
/* Handler arg scan start index (skip first positional). */
enum { HANDLER_START_IDX = 1 };
/* AST positions, byte offsets, and bounded traversal depths used by call extraction. */
enum {
    CBM_AST_SECOND_CHILD_INDEX = 1,
    CBM_CALL_NEXT_CHARACTER_OFFSET = 1,
    CBM_CALL_THIRD_CHARACTER_OFFSET = 2,
    CBM_CALL_PREVIOUS_INDEX_OFFSET = 1,
    CBM_CALL_MIN_UNARY_OPERAND_COUNT = 1,
    CBM_CALL_MIN_BINARY_OPERAND_COUNT = 2,
    CBM_CALL_MAX_SOLIDITY_WRAPPER_DEPTH = 4,
    CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH = 8,
    CBM_CALL_OBJECTSCRIPT_IDENTIFIER_DEPTH = 4,
    CBM_CALL_SHELL_NAME_LENGTH = 5,
    CBM_CALL_PUPPET_INCLUDE_NAME_LENGTH = 7,
    CBM_CALL_MACRO_SIGIL_LENGTH = 3,
    CBM_CALL_PHP_QUOTE_PAIR_LENGTH = 2,
    CBM_CALL_PATH_SEPARATOR_LENGTH = 1,
    CBM_CALL_PATH_APPEND_RESERVATION = 2,
};

/* Look up a module-level string constant by name. */
static const char *lookup_string_constant(const CBMExtractCtx *ctx, const char *name) {
    if (!name || !name[0]) {
        return NULL;
    }
    const CBMStringConstantMap *map = &ctx->string_constants;
    for (int i = 0; i < map->count; i++) {
        if (strcmp(map->names[i], name) == 0) {
            return map->values[i];
        }
    }
    return NULL;
}

/* Check if a node type is a string literal */
static int is_string_like(const char *kind) {
    return (strcmp(kind, "string") == 0 || strcmp(kind, "string_literal") == 0 ||
            strcmp(kind, "interpreted_string_literal") == 0 ||
            strcmp(kind, "raw_string_literal") == 0 || strcmp(kind, "string_content") == 0);
}

/* Strip surrounding quotes from a string, return arena-allocated copy */
static const char *strip_quotes(CBMArena *a, const char *text) {
    if (!text || !text[0]) {
        return NULL;
    }
    int len = (int)strlen(text);
    if (len >= CBM_QUOTE_PAIR && (text[0] == '"' || text[0] == '\'')) {
        return cbm_arena_strndup(a, text + CBM_QUOTE_OFFSET, (size_t)(len - CBM_QUOTE_PAIR));
    }
    return text;
}

// Callee suffixes for IRIS Python interop string-dispatch. Kept at file scope
// (not inside the function) to satisfy cppcheck variableScope.
static const char *s_py_dispatch_suffixes[] = {".classMethodValue", ".classMethodVoid",
                                               ".classMethodBoolean", ".classMethodObject", NULL};

// Per-language callee-suffix dispatch table — returns a NULL-terminated list of
// method-name suffixes whose calls should be resolved by extracting class+method
// from the first two string arguments (e.g. IRIS Python interop). Kept here
// rather than in CBMLangSpec to avoid -Wmissing-field-initializers across 155
// language rows.
const char **cbm_string_dispatch_suffixes(CBMLanguage lang) {
    if (lang == CBM_LANG_PYTHON) {
        return s_py_dispatch_suffixes;
    }
    return NULL;
}

// Forward declarations
static char *extract_callee_name(CBMArena *a, TSNode node, const char *source, CBMLanguage lang);
static char *gotemplate_callee(CBMArena *a, TSNode node, const char *source);
static char *strip_and_validate_string_arg(CBMArena *a, char *text);

// Lean 4: check if an apply node is inside a type annotation.
// Strategy: walk up to the nearest declaration boundary; if the apply falls
// inside that declaration's explicit_binder/implicit_binder, or before the
// body field, it's a type annotation. We check byte ranges: a call is valid
// only if it overlaps the body range of the enclosing declaration.
static bool lean_is_in_type_position(TSNode node) {
    TSNode cur = ts_node_parent(node);
    for (int depth = 0; depth < LEAN_MAX_PARENT_DEPTH; depth++) {
        if (ts_node_is_null(cur)) {
            return false;
        }
        const char *pk = ts_node_type(cur);
        // Inside a binder — definitely type position
        if (strcmp(pk, "explicit_binder") == 0 || strcmp(pk, "implicit_binder") == 0 ||
            strcmp(pk, "instance_binder") == 0) {
            return true;
        }
        // At a declaration boundary: check if apply is inside the body field
        if (strcmp(pk, "def") == 0 || strcmp(pk, "theorem") == 0 || strcmp(pk, "instance") == 0 ||
            strcmp(pk, "abbrev") == 0 || strcmp(pk, "structure") == 0 ||
            strcmp(pk, "inductive") == 0) {
            // Check if apply comes after the type annotation.
            // Strategy: if the node starts after the end of the "type" field, it's in value
            // position. If there's no "type" field, allow the call (no annotation to filter).
            TSNode type_field = ts_node_child_by_field_name(cur, TS_FIELD("type"));
            if (ts_node_is_null(type_field)) {
                return false; // no type annotation → allow call
            }
            uint32_t type_end = ts_node_end_byte(type_field);
            uint32_t node_start = ts_node_start_byte(node);
            // If apply starts after the type annotation ends, it's a value (call)
            if (node_start > type_end) {
                return false;
            }
            return true; // apply is within or before type annotation → type position
        }
        cur = ts_node_parent(cur);
    }
    return false;
}

/* Resolve a selector_expression that may chain through call_expressions.
 * Go pattern: pb.NewFooClient(conn).GetBar → "pb.NewFooClient.GetBar"
 * Without this, cbm_node_text returns full text including args/parens.
 * Iteratively walks the chain: selector → operand(call) → function(selector) → ... */
static char *resolve_chained_selector(CBMArena *a, TSNode sel, const char *source) {
    TSNode operand = ts_node_child_by_field_name(sel, TS_FIELD("operand"));
    TSNode field = ts_node_child_by_field_name(sel, TS_FIELD("field"));
    if (ts_node_is_null(operand) || ts_node_is_null(field) ||
        strcmp(ts_node_type(operand), "call_expression") != 0) {
        return cbm_node_text(a, sel, source);
    }

    /* Operand is a call_expression — extract its callee iteratively.
     * Walk: call_expression → function field → if selector_expression, repeat. */
    char *method = cbm_node_text(a, field, source);
    TSNode inner = operand;
    enum { MAX_CHAIN_DEPTH = 4 };
    for (int depth = 0; depth < MAX_CHAIN_DEPTH; depth++) {
        TSNode fn = ts_node_child_by_field_name(inner, TS_FIELD("function"));
        if (ts_node_is_null(fn)) {
            break;
        }
        const char *fnk = ts_node_type(fn);
        if (strcmp(fnk, "selector_expression") == 0) {
            /* Check if this selector also chains through a call */
            TSNode inner_op = ts_node_child_by_field_name(fn, TS_FIELD("operand"));
            if (!ts_node_is_null(inner_op) &&
                strcmp(ts_node_type(inner_op), "call_expression") == 0) {
                inner = inner_op;
                continue;
            }
        }
        /* Reached a non-chained callee — extract its text */
        char *base = cbm_node_text(a, fn, source);
        if (base && method) {
            return cbm_arena_sprintf(a, "%s.%s", base, method);
        }
        return method;
    }

    /* Fallback: just return the method name */
    return method;
}

// Strip a trailing generic argument list ("<...>" / "[...]") from a type name,
// returning the bare type identifier. Mutates an arena-owned copy in place.
static char *strip_generic_args(char *t) {
    if (!t) {
        return NULL;
    }
    char *angle = strchr(t, '<');
    if (angle) {
        *angle = '\0';
    }
    char *brack = strchr(t, '[');
    if (brack) {
        *brack = '\0';
    }
    return t;
}

// Pull the constructed type name out of a constructor/instantiation node:
//   new_expression               (TS/JS)  -> `constructor`/`type` field or first type child
//   object_creation_expression   (Java/C#/PHP) -> `type` field or first type child
//   instance_expression          (Scala)  -> nested type in the wrapped type/call
// Returns the bare type name (generic args stripped) or NULL if not a
// constructor node / no type found. Constructor calls resolve to the class's
// constructor (or the class node) downstream, producing a CALLS edge.
static char *extract_constructor_callee(CBMArena *a, TSNode node, const char *source,
                                        const char *nk) {
    if (strcmp(nk, "new_expression") != 0 && strcmp(nk, "object_creation_expression") != 0 &&
        strcmp(nk, "instance_expression") != 0) {
        return NULL;
    }

    // Preferred: explicit fields used by the various grammars.
    static const char *type_fields[] = {"constructor", "type", "name", NULL};
    for (const char **f = type_fields; *f; f++) {
        TSNode tn = ts_node_child_by_field_name(node, *f, (uint32_t)strlen(*f));
        if (!ts_node_is_null(tn)) {
            const char *tk = ts_node_type(tn);
            // For a generic_type wrapper, descend to the bare name child.
            if (strcmp(tk, "generic_type") == 0 && ts_node_named_child_count(tn) > 0) {
                tn = ts_node_named_child(tn, 0);
            }
            char *t = strip_generic_args(cbm_node_text(a, tn, source));
            if (t && t[0]) {
                return t;
            }
        }
    }

    // Fallback: first type-like named child (covers grammars that don't expose
    // a field, e.g. Scala's instance_expression wraps the type directly).
    uint32_t nc = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode child = ts_node_named_child(node, i);
        const char *ck = ts_node_type(child);
        if (strcmp(ck, "type_identifier") == 0 || strcmp(ck, "identifier") == 0 ||
            strcmp(ck, "qualified_name") == 0 || strcmp(ck, "scoped_type_identifier") == 0 ||
            strcmp(ck, "qualified_identifier") == 0 || strcmp(ck, "name") == 0 ||
            strcmp(ck, "type") == 0 || strcmp(ck, "generic_type") == 0 ||
            strcmp(ck, "simple_type") == 0 || strcmp(ck, "stable_type_identifier") == 0 ||
            strcmp(ck, "user_type") == 0) {
            // Descend through a generic_type wrapper to the bare name.
            if (strcmp(ck, "generic_type") == 0 && ts_node_named_child_count(child) > 0) {
                child = ts_node_named_child(child, 0);
            }
            char *t = strip_generic_args(cbm_node_text(a, child, source));
            if (t && t[0]) {
                return t;
            }
        }
    }
    return NULL;
}

static bool callee_function_kind(const char *kind) {
    return strcmp(kind, "identifier") == 0 || strcmp(kind, "simple_identifier") == 0 ||
           strcmp(kind, "attribute") == 0 || strcmp(kind, "member_expression") == 0 ||
           strcmp(kind, "field_expression") == 0 || strcmp(kind, "dot") == 0 ||
           strcmp(kind, "function") == 0 || strcmp(kind, "dotted_identifier") == 0 ||
           strcmp(kind, "member_access_expression") == 0 ||
           strcmp(kind, "scoped_identifier") == 0 || strcmp(kind, "qualified_identifier") == 0 ||
           strcmp(kind, "value_identifier") == 0 || strcmp(kind, "value_identifier_path") == 0;
}

static char *extract_function_field_callee(CBMArena *a, TSNode node, const char *source) {
    TSNode func_node = ts_node_child_by_field_name(node, TS_FIELD("function"));
    if (!ts_node_is_null(func_node)) {
        const char *fk = ts_node_type(func_node);
        if (strcmp(fk, "selector_expression") == 0) {
            return resolve_chained_selector(a, func_node, source);
        }
        if (callee_function_kind(fk)) {
            return cbm_node_text(a, func_node, source);
        }
        // C++ explicit template call f<T>(args): the `function` field is a
        // template_function whose `name` child is the bare callee (identifier
        // "identity" or qualified_identifier "ns::f"). Without this the whole
        // "identity<int>" text would never be produced as a textual callee, so
        // no CALLS edge — and the LSP's lsp_template resolution has nothing to
        // attach to. Return the name child so the join recovers the bare method.
        if (strcmp(fk, "template_function") == 0) {
            TSNode tname = ts_node_child_by_field_name(func_node, TS_FIELD("name"));
            if (!ts_node_is_null(tname)) {
                return cbm_node_text(a, tname, source);
            }
        }
        // R member call: module$fn() — function node is an extract_operator
        // with lhs (object) and rhs (method). Emit "module.fn" so it resolves
        // like other member calls (#219). Previously dropped → no CALLS edge.
        if (strcmp(fk, "extract_operator") == 0) {
            TSNode lhs = ts_node_child_by_field_name(func_node, TS_FIELD("lhs"));
            TSNode rhs = ts_node_child_by_field_name(func_node, TS_FIELD("rhs"));
            if (!ts_node_is_null(rhs)) {
                char *rt = cbm_node_text(a, rhs, source);
                if (!ts_node_is_null(lhs)) {
                    char *lt = cbm_node_text(a, lhs, source);
                    if (lt && lt[0] && rt && rt[0]) {
                        return cbm_arena_sprintf(a, "%s.%s", lt, rt);
                    }
                }
                return rt;
            }
        }
    }
    return NULL;
}

static char *extract_named_field_callee(CBMArena *a, TSNode node, const char *source,
                                        const char *field_name, uint32_t field_name_length,
                                        const char *receiver_field,
                                        uint32_t receiver_field_length) {
    TSNode name_node = ts_node_child_by_field_name(node, field_name, field_name_length);
    if (ts_node_is_null(name_node)) {
        return NULL;
    }
    char *name = cbm_node_text(a, name_node, source);
    TSNode receiver = ts_node_child_by_field_name(node, receiver_field, receiver_field_length);
    if (!ts_node_is_null(receiver) && name) {
        char *receiver_text = cbm_node_text(a, receiver, source);
        if (receiver_text && receiver_text[0]) {
            return cbm_arena_sprintf(a, "%s.%s", receiver_text, name);
        }
    }
    return name;
}

// Try common field-based callee resolution (function, name, method fields).
static char *extract_callee_from_fields(CBMArena *a, TSNode node, const char *source) {
    char *callee = extract_function_field_callee(a, node, source);
    if (callee) {
        return callee;
    }

    // Try "name" field (Java method_invocation)
    callee = extract_named_field_callee(a, node, source, TS_FIELD("name"), TS_FIELD("object"));
    if (callee) {
        return callee;
    }

    // Ruby: "method" + "receiver" fields
    return extract_named_field_callee(a, node, source, TS_FIELD("method"), TS_FIELD("receiver"));
}

// Haskell/OCaml: extract callee from apply/infix nodes.
/* Apply-style node kinds whose function head can nest another application. */
static bool fp_is_apply_kind(const char *kind) {
    return strcmp(kind, "apply") == 0 || strcmp(kind, "application_expression") == 0 ||
           strcmp(kind, "exp_apply") == 0;
}

static char *extract_fp_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    /* Curried application `f a b …` nests one apply node per argument on the
     * function head. Walk that left spine iteratively: recursing once per
     * application makes stack use follow the parse-tree depth of the indexed
     * file, and a long enough chain runs out. The other descendant finders in
     * this tree are already depth-bounded.
     *
     * Reassigning node/nk before continuing leaves the fall-through below
     * operating on the innermost apply node — where the recursive form left it. */
    while (fp_is_apply_kind(nk) && ts_node_child_count(node) > 0) {
        TSNode callee = ts_node_child(node, 0);
        const char *ck = ts_node_type(callee);
        if (strcmp(ck, "identifier") == 0 || strcmp(ck, "variable") == 0 ||
            strcmp(ck, "constructor") == 0 || strcmp(ck, "value_path") == 0 ||
            /* PureScript: exp_apply's function head is an `exp_name` whose
             * text is the (possibly qualified) function name. */
            strcmp(ck, "exp_name") == 0) {
            return cbm_node_text(a, callee, source);
        }
        if (!fp_is_apply_kind(ck)) {
            break;
        }
        node = callee;
        nk = ck;
    }
    if (strcmp(nk, "infix") == 0 || strcmp(nk, "infix_expression") == 0) {
        TSNode op = ts_node_child_by_field_name(node, TS_FIELD("operator"));
        if (!ts_node_is_null(op)) {
            return cbm_node_text(a, op, source);
        }
        enum { INFIX_MIN_CHILDREN = 3, INFIX_OP_IDX = 1 };
        if (ts_node_child_count(node) >= INFIX_MIN_CHILDREN) {
            return cbm_node_text(a, ts_node_child(node, INFIX_OP_IDX), source);
        }
    }
    return NULL;
}

// Wolfram: extract callee from apply, skipping LHS of set definitions.
static char *extract_wolfram_callee(CBMArena *a, TSNode node, const char *source) {
    TSNode parent = ts_node_parent(node);
    if (!ts_node_is_null(parent)) {
        const char *pk = ts_node_type(parent);
        if ((strcmp(pk, "set_delayed_top") == 0 || strcmp(pk, "set_top") == 0 ||
             strcmp(pk, "set_delayed") == 0 || strcmp(pk, "set") == 0) &&
            ts_node_named_child_count(parent) > 0 &&
            ts_node_eq(ts_node_named_child(parent, 0), node)) {
            return NULL;
        }
    }
    if (ts_node_named_child_count(node) > 0) {
        TSNode head = ts_node_named_child(node, 0);
        const char *hk = ts_node_type(head);
        if (strcmp(hk, "user_symbol") == 0 || strcmp(hk, "builtin_symbol") == 0) {
            return cbm_node_text(a, head, source);
        }
    }
    return NULL;
}

// Language-specific callee extraction for FP and niche languages.
// Swift callee extraction from call/constructor expressions.
static char *extract_swift_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "call_expression") != 0 && strcmp(nk, "constructor_expression") != 0) {
        return NULL;
    }
    if (ts_node_named_child_count(node) > 0) {
        TSNode callee = ts_node_named_child(node, 0);
        const char *ck = ts_node_type(callee);
        if (strcmp(ck, "simple_identifier") == 0 || strcmp(ck, "navigation_expression") == 0) {
            return cbm_node_text(a, callee, source);
        }
    }
    return NULL;
}

// A Perl sub/method name is an identifier: it starts with a letter or '_',
// contains only [A-Za-z0-9_] plus the '::' package separator, and is never a
// string/config literal. tree-sitter-perl mis-parses config lines in .cgi /
// heredoc-heavy files into call-shaped nodes whose "callee" is a dotted config
// token (e.g. "log4perl.appender.File.utf8"); rejecting non-identifier text
// here stops those from becoming bogus CALLS edges. Any '.', whitespace, quote,
// or '/' disqualifies the token.
static bool perl_is_identifier_callee(const char *name) {
    if (!name || !name[0]) {
        return false;
    }
    unsigned char c0 = (unsigned char)name[0];
    if (!(isalpha(c0) || c0 == '_')) {
        return false;
    }
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (isalnum(c) || c == '_') {
            continue;
        }
        if (c == ':') {
            // Only the '::' package separator is allowed: require an adjacent
            // pair, and reject a lone ':', ':::', or a trailing '::'.
            if (p[CBM_CALL_NEXT_CHARACTER_OFFSET] != ':' ||
                p[CBM_CALL_THIRD_CHARACTER_OFFSET] == ':' ||
                p[CBM_CALL_THIRD_CHARACTER_OFFSET] == '\0') {
                return false;
            }
            p++; // consume the second ':'; the loop's p++ moves past the pair
            continue;
        }
        return false; // '.', space, quote, '/', etc. → not a sub/method name
    }
    return true;
}

static bool elixir_operator_is_callable(const char *operator_name) {
    return operator_name && strcmp(operator_name, "=") != 0 && strcmp(operator_name, "<-") != 0 &&
           strcmp(operator_name, "->") != 0 && strcmp(operator_name, "\\\\") != 0 &&
           strcmp(operator_name, "::") != 0 && strcmp(operator_name, "when") != 0;
}

static char *extract_elixir_scripting_callee(CBMArena *a, TSNode node, const char *source,
                                             const char *nk) {
    if (strcmp(nk, "binary_operator") == 0) {
        TSNode op = ts_node_child_by_field_name(node, TS_FIELD("operator"));
        char *operator_name = ts_node_is_null(op) ? NULL : cbm_node_text(a, op, source);
        return elixir_operator_is_callable(operator_name) ? operator_name : NULL;
    }
    if (strcmp(nk, "call") != 0 || ts_node_child_count(node) == 0) {
        return NULL;
    }
    TSNode first = ts_node_child(node, 0);
    const char *kind = ts_node_type(first);
    return strcmp(kind, "identifier") == 0 || strcmp(kind, "dot") == 0
               ? cbm_node_text(a, first, source)
               : NULL;
}

static char *extract_perl_scripting_callee(CBMArena *a, TSNode node, const char *source) {
    if (ts_node_child_count(node) == 0) {
        return NULL;
    }
    TSNode name_node = ts_node_child_by_field_name(node, TS_FIELD("method"));
    if (ts_node_is_null(name_node)) {
        name_node = ts_node_child_by_field_name(node, TS_FIELD("function"));
    }
    if (ts_node_is_null(name_node)) {
        name_node = ts_node_child(node, 0);
    }
    char *name = cbm_node_text(a, name_node, source);
    return perl_is_identifier_callee(name) ? name : NULL;
}

static char *extract_php_scripting_callee(CBMArena *a, TSNode node, const char *source) {
    TSNode function = ts_node_child_by_field_name(node, TS_FIELD("function"));
    if (ts_node_is_null(function)) {
        function = ts_node_child_by_field_name(node, TS_FIELD("name"));
    }
    return ts_node_is_null(function) ? NULL : cbm_node_text(a, function, source);
}

static char *extract_first_child_callee(CBMArena *a, TSNode node, const char *source) {
    return ts_node_child_count(node) > 0 ? cbm_node_text(a, ts_node_child(node, 0), source) : NULL;
}

// Callee extraction for scripting languages (Elixir, Perl, PHP, Kotlin, MATLAB).
static char *extract_scripting_callee(CBMArena *a, TSNode node, const char *source,
                                      CBMLanguage lang, const char *nk) {
    switch (lang) {
    case CBM_LANG_ELIXIR:
        return extract_elixir_scripting_callee(a, node, source, nk);
    case CBM_LANG_PERL:
        return extract_perl_scripting_callee(a, node, source);
    case CBM_LANG_PHP:
        return extract_php_scripting_callee(a, node, source);
    case CBM_LANG_KOTLIN:
        return extract_first_child_callee(a, node, source);
    case CBM_LANG_MATLAB:
        return strcmp(nk, "command") == 0 ? extract_first_child_callee(a, node, source) : NULL;
    default:
        return NULL;
    }
}

// ObjC: extract callee from message_expression selector.
static char *extract_objc_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "message_expression") != 0) {
        return NULL;
    }
    TSNode selector = ts_node_child_by_field_name(node, TS_FIELD("selector"));
    return ts_node_is_null(selector) ? NULL : cbm_node_text(a, selector, source);
}

// Erlang: extract callee from call node's first child.
static char *extract_erlang_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "call") != 0 || ts_node_child_count(node) == 0) {
        return NULL;
    }
    return cbm_node_text(a, ts_node_child(node, 0), source);
}

static bool call_node_contains(TSNode outer, TSNode inner) {
    return !ts_node_is_null(outer) && !ts_node_is_null(inner) &&
           ts_node_start_byte(outer) <= ts_node_start_byte(inner) &&
           ts_node_end_byte(outer) >= ts_node_end_byte(inner);
}

static bool call_node_text_equals(const char *source, TSNode node, const char *expected) {
    if (!source || ts_node_is_null(node) || !expected) {
        return false;
    }
    uint32_t start = ts_node_start_byte(node);
    uint32_t end = ts_node_end_byte(node);
    size_t expected_len = strlen(expected);
    return end >= start && (size_t)(end - start) == expected_len &&
           memcmp(source + start, expected, expected_len) == 0;
}

static bool call_node_text_in(TSNode node, const char *source, const char *const *values) {
    for (const char *const *value = values; *value; value++) {
        if (call_node_text_equals(source, node, *value)) {
            return true;
        }
    }
    return false;
}

static bool lisp_definition_head(CBMLanguage lang, TSNode head, const char *source) {
    static const char *const clojure_scheme_racket_heads[] = {"defn",
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
    static const char *const common_lisp_heads[] = {
        "defun",       "defmacro", "defgeneric", "defmethod", "defvar", "defparameter",
        "defconstant", "deftype",  "defstruct",  "defclass",  NULL};

    return call_node_text_in(head, source,
                             lang == CBM_LANG_COMMONLISP ? common_lisp_heads
                                                         : clojure_scheme_racket_heads);
}

static bool lisp_list_is_definition_role(CBMLanguage lang, TSNode node, const char *source) {
    uint32_t count = ts_node_named_child_count(node);
    if (count > 0 && lisp_definition_head(lang, ts_node_named_child(node, 0), source)) {
        return true;
    }

    for (TSNode parent = ts_node_parent(node); !ts_node_is_null(parent);
         parent = ts_node_parent(parent)) {
        const char *parent_kind = ts_node_type(parent);
        if (lang == CBM_LANG_COMMONLISP &&
            (strcmp(parent_kind, "defun_header") == 0 || strcmp(parent_kind, "lambda_list") == 0)) {
            return true;
        }
        if (lang == CBM_LANG_EMACSLISP && (strcmp(parent_kind, "function_definition") == 0 ||
                                           strcmp(parent_kind, "macro_definition") == 0)) {
            TSNode parameters = ts_node_child_by_field_name(parent, TS_FIELD("parameters"));
            return call_node_contains(parameters, node);
        }
        if ((strcmp(parent_kind, "list") == 0 || strcmp(parent_kind, "list_lit") == 0) &&
            ts_node_named_child_count(parent) >= CBM_CALL_MIN_BINARY_OPERAND_COUNT &&
            lisp_definition_head(lang, ts_node_named_child(parent, 0), source)) {
            /* `(define (name args) body)` nests the signature list in the
             * definition's second form. Body lists remain genuine calls. */
            return call_node_contains(ts_node_named_child(parent, CBM_AST_SECOND_CHILD_INDEX),
                                      node);
        }
    }
    return false;
}

static bool call_node_has_direct_token(TSNode node, const char *token) {
    uint32_t count = ts_node_child_count(node);
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(ts_node_type(ts_node_child(node, i)), token) == 0) {
            return true;
        }
    }
    return false;
}

static bool julia_call_is_definition_head(TSNode node) {
    for (TSNode parent = ts_node_parent(node); !ts_node_is_null(parent);
         parent = ts_node_parent(parent)) {
        const char *kind = ts_node_type(parent);
        if (strcmp(kind, "assignment") == 0 || strcmp(kind, "function_definition") == 0 ||
            strcmp(kind, "short_function_definition") == 0) {
            return ts_node_named_child_count(parent) > 0 &&
                   call_node_contains(ts_node_named_child(parent, 0), node);
        }
    }
    return false;
}

static bool typst_call_is_let_pattern(TSNode node) {
    for (TSNode parent = ts_node_parent(node); !ts_node_is_null(parent);
         parent = ts_node_parent(parent)) {
        if (strcmp(ts_node_type(parent), "let") == 0) {
            TSNode pattern = ts_node_child_by_field_name(parent, TS_FIELD("pattern"));
            return call_node_contains(pattern, node);
        }
    }
    return false;
}

static bool agda_expr_is_definition_role(TSNode node) {
    for (TSNode parent = ts_node_parent(node); !ts_node_is_null(parent);
         parent = ts_node_parent(parent)) {
        const char *kind = ts_node_type(parent);
        if (strcmp(kind, "lhs") == 0 || strcmp(kind, "typed_binding") == 0 ||
            strcmp(kind, "signature") == 0 || strcmp(kind, "type_signature") == 0 ||
            strcmp(kind, "data_signature") == 0 || strcmp(kind, "record_signature") == 0) {
            return true;
        }
        if (strcmp(kind, "function") == 0) {
            /* A ':' function line is a type signature. In an '=' definition,
             * lhs expressions were rejected above and rhs applications remain
             * executable calls. */
            return call_node_has_direct_token(parent, ":");
        }
    }
    return false;
}

static TSNode elixir_call_arguments(TSNode call) {
    TSNode arguments = ts_node_child_by_field_name(call, TS_FIELD("arguments"));
    if (ts_node_is_null(arguments) && ts_node_child_count(call) > CBM_AST_SECOND_CHILD_INDEX) {
        arguments = ts_node_child(call, CBM_AST_SECOND_CHILD_INDEX);
    }
    return arguments;
}

static bool elixir_call_head_in(TSNode call, const char *source, const char *const *heads) {
    return ts_node_child_count(call) > 0 &&
           call_node_text_in(ts_node_child(call, 0), source, heads);
}

static bool elixir_call_is_definition_role(TSNode node, const char *source) {
    static const char *const structural_heads[] = {"def", "defp", "defmacro", "defmodule", NULL};
    static const char *const function_heads[] = {"def", "defp", "defmacro", NULL};
    if (elixir_call_head_in(node, source, structural_heads)) {
        return true;
    }

    for (TSNode parent = ts_node_parent(node); !ts_node_is_null(parent);
         parent = ts_node_parent(parent)) {
        if (strcmp(ts_node_type(parent), "call") != 0 ||
            !elixir_call_head_in(parent, source, function_heads)) {
            continue;
        }
        TSNode arguments = elixir_call_arguments(parent);
        TSNode signature = ts_node_named_child_count(arguments) > 0
                               ? ts_node_named_child(arguments, 0)
                               : arguments;
        return ts_node_eq(signature, node);
    }
    return false;
}

static bool call_node_is_definition_container(CBMLanguage lang, TSNode node, const char *source) {
    const char *kind = ts_node_type(node);
    if ((lang == CBM_LANG_CLOJURE || lang == CBM_LANG_SCHEME || lang == CBM_LANG_RACKET ||
         lang == CBM_LANG_COMMONLISP || lang == CBM_LANG_EMACSLISP) &&
        (strcmp(kind, "list") == 0 || strcmp(kind, "list_lit") == 0)) {
        return lisp_list_is_definition_role(lang, node, source);
    }
    if (lang == CBM_LANG_JULIA &&
        (strcmp(kind, "call_expression") == 0 || strcmp(kind, "broadcast_call_expression") == 0)) {
        return julia_call_is_definition_head(node);
    }
    if (lang == CBM_LANG_TYPST && strcmp(kind, "call") == 0) {
        return typst_call_is_let_pattern(node);
    }
    if (lang == CBM_LANG_AGDA && strcmp(kind, "expr") == 0) {
        return agda_expr_is_definition_role(node);
    }
    return lang == CBM_LANG_ELIXIR && strcmp(kind, "call") == 0 &&
           elixir_call_is_definition_role(node, source);
}

// Lisp dialects: a call is a list (`list` / `list_lit`) whose head (first named
// child) is the function symbol (`symbol` / `sym_lit`). Generic field/first-child
// extraction misses it because the head is not an `identifier` node.
static char *extract_lisp_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "list") != 0 && strcmp(nk, "list_lit") != 0) {
        return NULL;
    }
    if (ts_node_named_child_count(node) > 0) {
        TSNode head = ts_node_named_child(node, 0);
        const char *hk = ts_node_type(head);
        if (strcmp(hk, "symbol") == 0 || strcmp(hk, "sym_lit") == 0 ||
            strcmp(hk, "identifier") == 0) {
            return cbm_node_text(a, head, source);
        }
    }
    return NULL;
}

// F#: application_expression head is a long_identifier_or_op wrapper, not a bare
// identifier, so extract_fp_callee's accepted-type list would miss it.
static char *extract_fsharp_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "application_expression") != 0 || ts_node_named_child_count(node) == 0) {
        return NULL;
    }
    TSNode head = ts_node_named_child(node, 0);
    const char *hk = ts_node_type(head);
    if (strcmp(hk, "long_identifier_or_op") == 0 || strcmp(hk, "long_identifier") == 0 ||
        strcmp(hk, "identifier") == 0) {
        return cbm_node_text(a, head, source);
    }
    return NULL;
}

// CSS: a `call_expression` (e.g. `url(...)`, `calc(...)`) carries its callee on a
// plain `function_name` child rather than a `function`/`name` field, so generic
// field/first-child resolution misses it.
static char *extract_css_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "call_expression") != 0) {
        return NULL;
    }
    TSNode fn = cbm_find_child_by_kind(node, "function_name");
    return ts_node_is_null(fn) ? NULL : cbm_node_text(a, fn, source);
}

// Linker scripts expose the builtin in the exact `function:` field as a
// `symbol`. Keep the `arguments:` subtree separate so symbols passed to the
// builtin remain value usages.
static char *extract_linkerscript_callee(CBMArena *a, TSNode node, const char *source,
                                         const char *nk) {
    if (strcmp(nk, "call_expression") != 0) {
        return NULL;
    }
    TSNode function = ts_node_child_by_field_name(node, TS_FIELD("function"));
    if (ts_node_is_null(function) || strcmp(ts_node_type(function), "symbol") != 0) {
        return NULL;
    }
    return cbm_node_text(a, function, source);
}

// PowerShell: a `command` node's callee is its `command_name` child.
static char *extract_powershell_callee(CBMArena *a, TSNode node, const char *source,
                                       const char *nk) {
    if (strcmp(nk, "command") != 0) {
        return NULL;
    }
    uint32_t n = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < n; i++) {
        TSNode c = ts_node_named_child(node, i);
        if (strcmp(ts_node_type(c), "command_name") == 0) {
            return cbm_node_text(a, c, source);
        }
    }
    return NULL;
}

// Ada: procedure_call_statement / function_call carry the callee in a `name` field.
static char *extract_ada_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "procedure_call_statement") != 0 && strcmp(nk, "function_call") != 0) {
        return NULL;
    }
    TSNode name = ts_node_child_by_field_name(node, TS_FIELD("name"));
    if (!ts_node_is_null(name)) {
        return cbm_node_text(a, name, source);
    }
    if (ts_node_named_child_count(node) > 0) {
        TSNode head = ts_node_named_child(node, 0);
        const char *hk = ts_node_type(head);
        if (strcmp(hk, "name") == 0 || strcmp(hk, "identifier") == 0) {
            return cbm_node_text(a, head, source);
        }
    }
    return NULL;
}

// Solidity: a call_expression's callee is on the `function` field, wrapped in an
// `expression` node (call_expression -> function:expression -> identifier). Descend
// left-most through expression wrappers until we reach the identifier/member.
static char *extract_solidity_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "call_expression") != 0 && strcmp(nk, "call") != 0) {
        return NULL;
    }
    TSNode head = ts_node_child_by_field_name(node, TS_FIELD("function"));
    if (ts_node_is_null(head) && ts_node_named_child_count(node) > 0) {
        head = ts_node_named_child(node, 0);
    }
    // Unwrap nested `expression` wrappers down to the callee identifier/member.
    for (int depth = 0; depth < CBM_CALL_MAX_SOLIDITY_WRAPPER_DEPTH && !ts_node_is_null(head);
         depth++) {
        const char *hk = ts_node_type(head);
        if (strcmp(hk, "identifier") == 0 || strcmp(hk, "member_expression") == 0 ||
            strcmp(hk, "member_access") == 0) {
            return cbm_node_text(a, head, source);
        }
        if (strcmp(hk, "expression") == 0 && ts_node_named_child_count(head) > 0) {
            head = ts_node_named_child(head, 0);
            continue;
        }
        break;
    }
    return NULL;
}

// Groovy: function_call's first named child is the callee identifier (the generic
// first-child fallback misses it because child 0 is anonymous).
static char *extract_groovy_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "function_call") != 0 && strcmp(nk, "juxt_function_call") != 0) {
        return NULL;
    }
    if (ts_node_named_child_count(node) > 0) {
        TSNode head = ts_node_named_child(node, 0);
        if (!ts_node_is_null(head) && strcmp(ts_node_type(head), "identifier") == 0) {
            return cbm_node_text(a, head, source);
        }
    }
    return NULL;
}

// WGSL: callee is nested type_constructor_or_function_call_expression ->
// type_declaration -> identifier. Descend left-most until an identifier.
static char *extract_wgsl_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "type_constructor_or_function_call_expression") != 0) {
        return NULL;
    }
    TSNode head = node;
    while (ts_node_named_child_count(head) > 0 && strcmp(ts_node_type(head), "identifier") != 0) {
        head = ts_node_named_child(head, 0);
    }
    if (strcmp(ts_node_type(head), "identifier") == 0) {
        return cbm_node_text(a, head, source);
    }
    return NULL;
}

// Dart: the invocation `selector` (the `(...)` part) follows the callee
// identifier as a sibling; `new_expression`'s first named child is the type.
static char *extract_dart_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "selector") == 0) {
        TSNode prev = ts_node_prev_named_sibling(node);
        if (!ts_node_is_null(prev) && strcmp(ts_node_type(prev), "identifier") == 0) {
            return cbm_node_text(a, prev, source);
        }
        return NULL;
    }
    if (strcmp(nk, "new_expression") == 0 && ts_node_named_child_count(node) > 0) {
        TSNode head = ts_node_named_child(node, 0);
        const char *hk = ts_node_type(head);
        if (strcmp(hk, "identifier") == 0 || strcmp(hk, "type_identifier") == 0) {
            return cbm_node_text(a, head, source);
        }
    }
    return NULL;
}

// SCSS: an `@include foo;` is an include_statement whose callee is its
// `identifier` child (the mixin name).
static char *extract_scss_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "include_statement") == 0) {
        TSNode id = cbm_find_child_by_kind(node, "identifier");
        return ts_node_is_null(id) ? NULL : cbm_node_text(a, id, source);
    }
    /* SCSS @function call `double($x)` is a call_expression whose callee is a
     * `function_name` child (there is no `function` field), so the generic
     * field-based resolver returns NULL and the call is dropped — no CALLS edge
     * to the in-file @function. */
    if (strcmp(nk, "call_expression") == 0) {
        TSNode fn = cbm_find_child_by_kind(node, "function_name");
        if (!ts_node_is_null(fn)) {
            return cbm_node_text(a, fn, source);
        }
    }
    return NULL;
}

// SQL: an `invocation` node's callee is nested object_reference > `name` field
// (the same shape as a create_function's name).
static char *extract_sql_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "invocation") != 0) {
        return NULL;
    }
    TSNode oref = cbm_find_child_by_kind(node, "object_reference");
    if (ts_node_is_null(oref)) {
        return NULL;
    }
    TSNode nm = ts_node_child_by_field_name(oref, TS_FIELD("name"));
    return ts_node_is_null(nm) ? NULL : cbm_node_text(a, nm, source);
}

// COBOL: a `CALL 'HELPER'` is a call_statement whose `x` field is a string
// literal naming the called program; the callee is that string sans quotes.
static char *extract_cobol_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "call_statement") != 0) {
        return NULL;
    }
    TSNode x = ts_node_child_by_field_name(node, TS_FIELD("x"));
    if (ts_node_is_null(x)) {
        x = cbm_find_child_by_kind(node, "string");
    }
    if (ts_node_is_null(x)) {
        return NULL;
    }
    char *text = cbm_node_text(a, x, source);
    return strip_and_validate_string_arg(a, text);
}

// Elm: a `function_call_expr` has a `target` field; the callee identifier is
// target > value_expr > `name` field (value_qid) > lower_case_identifier.
static char *extract_elm_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "function_call_expr") != 0) {
        return NULL;
    }
    TSNode target = ts_node_child_by_field_name(node, TS_FIELD("target"));
    if (ts_node_is_null(target)) {
        return NULL;
    }
    TSNode ve = strcmp(ts_node_type(target), "value_expr") == 0
                    ? target
                    : cbm_find_child_by_kind(target, "value_expr");
    if (ts_node_is_null(ve)) {
        return NULL;
    }
    TSNode qid = ts_node_child_by_field_name(ve, TS_FIELD("name"));
    if (ts_node_is_null(qid)) {
        qid = cbm_find_child_by_kind(ve, "value_qid");
    }
    if (ts_node_is_null(qid)) {
        return NULL;
    }
    TSNode id = cbm_find_child_by_kind(qid, "lower_case_identifier");
    if (ts_node_is_null(id)) {
        // module-qualified call: emit the whole qualified id text
        return cbm_node_text(a, qid, source);
    }
    return cbm_node_text(a, id, source);
}

// Jsonnet: a `functioncall` node's callee is its first `id` child (the called
// binding name); the generic field path misses it (no `function`/`name` field).
static char *extract_jsonnet_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "functioncall") != 0) {
        return NULL;
    }
    TSNode id = cbm_find_child_by_kind(node, "id");
    return ts_node_is_null(id) ? NULL : cbm_node_text(a, id, source);
}

// Nickel: function application is `applicative` and curries left-associatively:
// `f x y` parses as `(applicative t1:(applicative t1:f t2:x) t2:y)`. A real call
// node carries a `t2` (argument) field; a bare value (`applicative
// (record_operand (atom (ident))))` wraps every expression and has no `t2`, so it
// is NOT a call. We also skip applicatives whose parent is itself an applicative
// (the inner partial-application nodes) so a curried call emits exactly one edge,
// keyed on the leftmost ident reached by descending the `t1` chain.
// (`infix_expr` is binary operator application, not a call, and is excluded from
// nickel_call_types.)
static char *extract_nickel_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "applicative") != 0) {
        return NULL;
    }
    // Not an application unless it has an argument (`t2`).
    if (ts_node_is_null(ts_node_child_by_field_name(node, TS_FIELD("t2")))) {
        return NULL;
    }
    // Emit only at the outermost applicative of a curried chain.
    TSNode parent = ts_node_parent(node);
    if (!ts_node_is_null(parent) && strcmp(ts_node_type(parent), "applicative") == 0) {
        return NULL;
    }
    enum { NICKEL_APPLY_DEPTH = 8 };
    TSNode cur = node;
    for (int depth = 0; depth < NICKEL_APPLY_DEPTH && !ts_node_is_null(cur); depth++) {
        const char *ck = ts_node_type(cur);
        if (strcmp(ck, "ident") == 0) {
            return cbm_node_text(a, cur, source);
        }
        // Descend the function side: the `t1` field for curried applicatives, or
        // the wrapper's first named child (record_operand -> atom -> ident).
        TSNode next = ts_node_child_by_field_name(cur, TS_FIELD("t1"));
        if (ts_node_is_null(next) && ts_node_named_child_count(cur) > 0) {
            next = ts_node_named_child(cur, 0);
        }
        if (ts_node_is_null(next) || ts_node_eq(next, cur)) {
            break;
        }
        cur = next;
    }
    return NULL;
}

// Typst: a `call` node's callee is its `item` field (an ident), matching the
// def-side resolution of `#let greet(name) = ...`.
static char *extract_typst_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "call") != 0) {
        return NULL;
    }
    TSNode item = ts_node_child_by_field_name(node, TS_FIELD("item"));
    return ts_node_is_null(item) ? NULL : cbm_node_text(a, item, source);
}

// Meson: a builtin invocation (`executable(...)`, `dependency(...)`) is a
// `normal_command` whose `command` field is the called identifier.
static char *extract_meson_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "normal_command") != 0) {
        return NULL;
    }
    TSNode cmd = ts_node_child_by_field_name(node, TS_FIELD("command"));
    return ts_node_is_null(cmd) ? NULL : cbm_node_text(a, cmd, source);
}

// Descend left-most through wrapper nodes to the first identifier-bearing leaf.
// Used by HDL call nodes whose callee identifier is nested under one or more
// grammar wrappers (Verilog tf_call -> simple_identifier; SystemVerilog
// tf_call -> hierarchical_identifier -> simple_identifier).
static char *first_leaf_identifier(CBMArena *a, TSNode node, const char *source) {
    TSNode cur = node;
    for (int depth = 0; depth < CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH && !ts_node_is_null(cur);
         depth++) {
        const char *k = ts_node_type(cur);
        if (strcmp(k, "simple_identifier") == 0 || strcmp(k, "identifier") == 0 ||
            strcmp(k, "word") == 0 || strcmp(k, "name") == 0 || strcmp(k, "qid") == 0) {
            char *t = cbm_node_text(a, cur, source);
            return (t && t[0]) ? t : NULL;
        }
        if (ts_node_named_child_count(cur) == 0) {
            return NULL;
        }
        cur = ts_node_named_child(cur, 0);
    }
    return NULL;
}

// Verilog / SystemVerilog: a function_subroutine_call wraps
// subroutine_call -> tf_call -> [hierarchical_identifier ->] simple_identifier.
// Descend to the first identifier leaf to name the callee.
static char *extract_hdl_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "function_subroutine_call") != 0 && strcmp(nk, "subroutine_call") != 0 &&
        strcmp(nk, "tf_call") != 0 && strcmp(nk, "system_tf_call") != 0) {
        return NULL;
    }
    return first_leaf_identifier(a, node, source);
}

// VHDL: `add(x, 1)` parses as `(name (library_function) (parenthesis_group ...))`
// inside a `simple_expression` (the function-call / indexed-name ambiguity). The
// call_node_types set targets `parenthesis_group`; the callee is its immediately
// preceding named sibling (a `library_function`/`identifier`/`name` token).
static char *extract_vhdl_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "parenthesis_group") != 0) {
        return NULL;
    }
    TSNode prev = ts_node_prev_named_sibling(node);
    if (ts_node_is_null(prev)) {
        return NULL;
    }
    const char *pk = ts_node_type(prev);
    if (strcmp(pk, "library_function") == 0 || strcmp(pk, "identifier") == 0 ||
        strcmp(pk, "name") == 0 || strcmp(pk, "simple_name") == 0) {
        char *t = cbm_node_text(a, prev, source);
        return (t && t[0]) ? t : NULL;
    }
    return NULL;
}

// NASM: a `call`/`jmp`-style instruction is an `actual_instruction` whose
// `instruction:` field is the mnemonic word and whose first operand word is the
// target label. Only treat call/jump mnemonics as calls; everything else (add,
// mov, ret, ...) is plain data-flow, not a call.
static char *extract_nasm_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "call_syntax_expression") == 0) {
        TSNode base = ts_node_child_by_field_name(node, TS_FIELD("base"));
        return ts_node_is_null(base) ? NULL : first_leaf_identifier(a, base, source);
    }
    if (strcmp(nk, "actual_instruction") != 0) {
        return NULL;
    }
    TSNode mnem = ts_node_child_by_field_name(node, TS_FIELD("instruction"));
    if (ts_node_is_null(mnem)) {
        return NULL;
    }
    char *m = cbm_node_text(a, mnem, source);
    if (!m || (strcmp(m, "call") != 0 && strcmp(m, "jmp") != 0 && strcmp(m, "je") != 0 &&
               strcmp(m, "jne") != 0 && strcmp(m, "jz") != 0 && strcmp(m, "jnz") != 0)) {
        return NULL;
    }
    TSNode ops = ts_node_child_by_field_name(node, TS_FIELD("operands"));
    if (ts_node_is_null(ops) || ts_node_named_child_count(ops) == 0) {
        return NULL;
    }
    return first_leaf_identifier(a, ts_node_named_child(ops, 0), source);
}

// LLVM-IR: a `call`/`invoke` is an `instruction_call` whose `callee:` field is a
// `value -> var -> global_var` chain (e.g. `@inner`). Strip the leading sigil.
static char *extract_llvm_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "instruction_call") != 0) {
        return NULL;
    }
    TSNode callee = ts_node_child_by_field_name(node, TS_FIELD("callee"));
    if (ts_node_is_null(callee)) {
        return NULL;
    }
    char *t = first_leaf_identifier(a, callee, source);
    if (!t) {
        t = cbm_node_text(a, callee, source);
    }
    if (t && (t[0] == '@' || t[0] == '%')) {
        return t + CBM_CALL_NEXT_CHARACTER_OFFSET;
    }
    return t;
}

// FunC: a `function_application` carries the callee on its `function:` field.
static char *extract_func_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "function_application") != 0) {
        return NULL;
    }
    TSNode fn = ts_node_child_by_field_name(node, TS_FIELD("function"));
    return ts_node_is_null(fn) ? NULL : cbm_node_text(a, fn, source);
}

// Nix: an `apply_expression` (`f x`) carries the applied function on its
// `function:` field. The head is a `variable_expression` whose `name` is the
// callee identifier; curried application (`f x y`) nests apply_expressions, so
// descend the `function` chain to the head variable_expression. The generic
// field resolver does not recognise `variable_expression`, so without this the
// call to `addOne` would never be captured.
static char *extract_nix_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "apply_expression") != 0) {
        return NULL;
    }
    TSNode fn = ts_node_child_by_field_name(node, TS_FIELD("function"));
    for (int depth = 0; depth < CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH && !ts_node_is_null(fn);
         depth++) {
        const char *fk = ts_node_type(fn);
        if (strcmp(fk, "apply_expression") == 0) {
            fn = ts_node_child_by_field_name(fn, TS_FIELD("function"));
            continue;
        }
        if (strcmp(fk, "variable_expression") == 0) {
            TSNode nm = ts_node_child_by_field_name(fn, TS_FIELD("name"));
            return ts_node_is_null(nm) ? NULL : cbm_node_text(a, nm, source);
        }
        if (strcmp(fk, "identifier") == 0) {
            return cbm_node_text(a, fn, source);
        }
        return NULL;
    }
    return NULL;
}

// Agda has no fields. A plain application is the exact adjacency shape
// `expr(atom, atom, ...)`; operator/type expressions also have multiple named
// children, but include an anonymous operator token and must not become calls.
static TSNode agda_application_head_atom(TSNode node) {
    if (strcmp(ts_node_type(node), "expr") != 0 ||
        ts_node_named_child_count(node) < CBM_CALL_MIN_BINARY_OPERAND_COUNT ||
        ts_node_child_count(node) != ts_node_named_child_count(node)) {
        return (TSNode){0};
    }
    uint32_t count = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(ts_node_type(ts_node_named_child(node, i)), "atom") != 0) {
            return (TSNode){0};
        }
    }
    return ts_node_named_child(node, 0);
}

static TSNode agda_head_qid(TSNode head) {
    TSNode current = head;
    for (int depth = 0; depth < CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH && !ts_node_is_null(current);
         depth++) {
        if (strcmp(ts_node_type(current), "qid") == 0) {
            return current;
        }
        if (ts_node_named_child_count(current) == 0) {
            break;
        }
        current = ts_node_named_child(current, 0);
    }
    return (TSNode){0};
}

static char *extract_agda_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "expr") != 0) {
        return NULL;
    }
    TSNode qid = agda_head_qid(agda_application_head_atom(node));
    return ts_node_is_null(qid) ? NULL : cbm_node_text(a, qid, source);
}

// Make: `$(shell ...)` is a `shell_function` node; the callee is the literal
// `shell` keyword. tree-sitter-make also exposes `function_call` for other
// builtins ($(wildcard ...), $(patsubst ...)).
static char *extract_make_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "shell_function") == 0) {
        return cbm_arena_strndup(a, "shell", CBM_CALL_SHELL_NAME_LENGTH);
    }
    if (strcmp(nk, "function_call") == 0) {
        TSNode fn = ts_node_child_by_field_name(node, TS_FIELD("function"));
        if (ts_node_is_null(fn) && ts_node_named_child_count(node) > 0) {
            fn = ts_node_named_child(node, 0);
        }
        return ts_node_is_null(fn) ? NULL : cbm_node_text(a, fn, source);
    }
    return NULL;
}

// Just: a recipe dependency `recipe: dep` is a `dependency` node whose `name:`
// field is the referenced recipe.
static char *extract_just_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "dependency") != 0) {
        return NULL;
    }
    TSNode name = ts_node_child_by_field_name(node, TS_FIELD("name"));
    if (ts_node_is_null(name) && ts_node_named_child_count(node) > 0) {
        name = ts_node_named_child(node, 0);
    }
    return ts_node_is_null(name) ? NULL : cbm_node_text(a, name, source);
}

// Puppet: `include foo` is an `include_statement`; the callee is the literal
// `include` keyword (the class/identifier args are resolved as separate refs).
static char *extract_puppet_callee(CBMArena *a, TSNode node, const char *source, const char *nk) {
    if (strcmp(nk, "include_statement") == 0) {
        return cbm_arena_strndup(a, "include", CBM_CALL_PUPPET_INCLUDE_NAME_LENGTH);
    }
    if (strcmp(nk, "function_call") == 0) {
        if (ts_node_named_child_count(node) > 0) {
            TSNode head = ts_node_named_child(node, 0);
            if (strcmp(ts_node_type(head), "identifier") == 0) {
                return cbm_node_text(a, head, source);
            }
        }
    }
    return NULL;
}

typedef char *(*callee_language_extractor_fn)(CBMArena *a, TSNode node, const char *source,
                                              const char *node_kind);

typedef struct {
    CBMLanguage language;
    callee_language_extractor_fn extractor;
} callee_language_extractor_t;

static char *extract_wolfram_apply_callee(CBMArena *a, TSNode node, const char *source,
                                          const char *node_kind) {
    return strcmp(node_kind, "apply") == 0 ? extract_wolfram_callee(a, node, source) : NULL;
}

static const callee_language_extractor_t *find_callee_extractor(
    const callee_language_extractor_t *extractors, size_t count, CBMLanguage language) {
    for (size_t i = 0; i < count; i++) {
        if (extractors[i].language == language) {
            return &extractors[i];
        }
    }
    return NULL;
}

static char *extract_fortran_subroutine_callee(CBMArena *a, TSNode node, const char *source,
                                               const char *node_kind) {
    if (strcmp(node_kind, "subroutine_call") != 0) {
        return NULL;
    }
    TSNode subroutine = ts_node_child_by_field_name(node, TS_FIELD("subroutine"));
    return ts_node_is_null(subroutine) ? NULL : cbm_node_text(a, subroutine, source);
}

static char *extract_python_dict_dispatch_callee(CBMArena *a, TSNode node, const char *source,
                                                 const char *node_kind) {
    if (strcmp(node_kind, "call") != 0) {
        return NULL;
    }
    TSNode function = ts_node_child_by_field_name(node, TS_FIELD("function"));
    if (ts_node_is_null(function) || strcmp(ts_node_type(function), "subscript") != 0) {
        return NULL;
    }
    TSNode value = ts_node_child_by_field_name(function, TS_FIELD("value"));
    TSNode index = ts_node_child_by_field_name(function, TS_FIELD("subscript"));
    if (ts_node_is_null(value) || ts_node_is_null(index) ||
        strcmp(ts_node_type(value), "identifier") != 0 ||
        strcmp(ts_node_type(index), "string") != 0) {
        return NULL;
    }
    return cbm_node_text(a, value, source);
}

static char *extract_objectscript_class_method_callee(CBMArena *a, TSNode node,
                                                      const char *source) {
    TSNode class_ref = cbm_find_child_by_kind(node, "class_ref");
    TSNode method_name = cbm_find_child_by_kind(node, "method_name");
    if (ts_node_is_null(class_ref) || ts_node_is_null(method_name)) {
        return NULL;
    }
    TSNode class_name = cbm_find_child_by_kind(class_ref, "class_name");
    char *class_text = ts_node_is_null(class_name) ? NULL : cbm_node_text(a, class_name, source);
    if (!class_text || !class_text[0]) {
        return NULL;
    }
    TSNode method = ts_node_named_child_count(method_name) > 0 ? ts_node_named_child(method_name, 0)
                                                               : (TSNode){0};
    char *method_text = ts_node_is_null(method) ? NULL : cbm_node_text(a, method, source);
    return method_text && method_text[0] ? cbm_arena_sprintf(a, "%s.%s", class_text, method_text)
                                         : class_text;
}

static char *extract_objectscript_macro_callee(CBMArena *a, TSNode node, const char *source) {
    char *raw = cbm_node_text(a, node, source);
    if (!raw || raw[0] != '$' || raw[CBM_CALL_NEXT_CHARACTER_OFFSET] != '$' ||
        raw[CBM_CALL_THIRD_CHARACTER_OFFSET] != '$') {
        return NULL;
    }
    char *name = raw + CBM_CALL_MACRO_SIGIL_LENGTH;
    char *paren = strchr(name, '(');
    if (paren) {
        *paren = '\0';
    }
    return name[0] ? cbm_arena_sprintf(a, "$$$%s", name) : NULL;
}

static char *extract_objectscript_lang_callee(CBMArena *a, TSNode node, const char *source,
                                              const char *node_kind) {
    if (strcmp(node_kind, "class_method_call") == 0) {
        return extract_objectscript_class_method_callee(a, node, source);
    }
    if (strcmp(node_kind, "extrinsic_function") == 0 ||
        strcmp(node_kind, "routine_tag_call") == 0) {
        TSNode line_ref = cbm_find_child_by_kind(node, "line_ref");
        return ts_node_is_null(line_ref) ? NULL : cbm_node_text(a, line_ref, source);
    }
    return strcmp(node_kind, "macro") == 0 ? extract_objectscript_macro_callee(a, node, source)
                                           : NULL;
}

static char *extract_callee_lang_specific(CBMArena *a, TSNode node, const char *source,
                                          CBMLanguage lang) {
    static const callee_language_extractor_t fallback_extractors[] = {
        {CBM_LANG_JSONNET, extract_jsonnet_callee},
        {CBM_LANG_NICKEL, extract_nickel_callee},
        {CBM_LANG_TYPST, extract_typst_callee},
        {CBM_LANG_MESON, extract_meson_callee},
        {CBM_LANG_SCSS, extract_scss_callee},
        {CBM_LANG_CSS, extract_css_callee},
        {CBM_LANG_LINKERSCRIPT, extract_linkerscript_callee},
        {CBM_LANG_SQL, extract_sql_callee},
        {CBM_LANG_COBOL, extract_cobol_callee},
        {CBM_LANG_ELM, extract_elm_callee},
        {CBM_LANG_VERILOG, extract_hdl_callee},
        {CBM_LANG_SYSTEMVERILOG, extract_hdl_callee},
        {CBM_LANG_VHDL, extract_vhdl_callee},
        {CBM_LANG_NASM, extract_nasm_callee},
        {CBM_LANG_LLVM_IR, extract_llvm_callee},
        {CBM_LANG_FUNC, extract_func_callee},
        {CBM_LANG_AGDA, extract_agda_callee},
        {CBM_LANG_NIX, extract_nix_callee},
        {CBM_LANG_MAKEFILE, extract_make_callee},
        {CBM_LANG_JUST, extract_just_callee},
        {CBM_LANG_PUPPET, extract_puppet_callee},
    };
    static const callee_language_extractor_t direct_extractors[] = {
        {CBM_LANG_CLOJURE, extract_lisp_callee},  {CBM_LANG_COMMONLISP, extract_lisp_callee},
        {CBM_LANG_SCHEME, extract_lisp_callee},   {CBM_LANG_FENNEL, extract_lisp_callee},
        {CBM_LANG_RACKET, extract_lisp_callee},   {CBM_LANG_EMACSLISP, extract_lisp_callee},
        {CBM_LANG_FSHARP, extract_fsharp_callee}, {CBM_LANG_POWERSHELL, extract_powershell_callee},
        {CBM_LANG_ADA, extract_ada_callee},       {CBM_LANG_SOLIDITY, extract_solidity_callee},
        {CBM_LANG_GROOVY, extract_groovy_callee}, {CBM_LANG_WGSL, extract_wgsl_callee},
        {CBM_LANG_DART, extract_dart_callee},     {CBM_LANG_OBJC, extract_objc_callee},
        {CBM_LANG_ERLANG, extract_erlang_callee}, {CBM_LANG_HASKELL, extract_fp_callee},
        {CBM_LANG_OCAML, extract_fp_callee},      {CBM_LANG_PURESCRIPT, extract_fp_callee},
        {CBM_LANG_SCALA, extract_fp_callee},      {CBM_LANG_WOLFRAM, extract_wolfram_apply_callee},
        {CBM_LANG_SWIFT, extract_swift_callee},
    };
    const char *node_kind = ts_node_type(node);
    char *callee = lang == CBM_LANG_FORTRAN
                       ? extract_fortran_subroutine_callee(a, node, source, node_kind)
                       : extract_python_dict_dispatch_callee(a, node, source, node_kind);
    if (callee) {
        return callee;
    }
    const callee_language_extractor_t *extractor = find_callee_extractor(
        fallback_extractors, sizeof(fallback_extractors) / sizeof(fallback_extractors[0]), lang);
    if (extractor) {
        callee = extractor->extractor(a, node, source, node_kind);
        return callee ? callee : extract_scripting_callee(a, node, source, lang, node_kind);
    }
    extractor = find_callee_extractor(
        direct_extractors, sizeof(direct_extractors) / sizeof(direct_extractors[0]), lang);
    if (extractor) {
        return extractor->extractor(a, node, source, node_kind);
    }
    if (lang == CBM_LANG_OBJECTSCRIPT_UDL || lang == CBM_LANG_OBJECTSCRIPT_ROUTINE) {
        return extract_objectscript_lang_callee(a, node, source, node_kind);
    }
    return extract_scripting_callee(a, node, source, lang, node_kind);
}

// Extract callee name from a call node
/* #952: compose Laravel group prefixes into a route path. Walks UP from a
 * route-registration call: every enclosing anonymous function that is the
 * argument of a `->group(...)` member call contributes the `prefix('...')`
 * (or `Route::prefix('...')`) found on that group call's receiver chain.
 * Chain methods that don't shape the path (middleware, name, as, domain)
 * are skipped. Outer groups accumulate before inner ones; nested groups
 * compose left-to-right. Returns the composed path (arena) or NULL when no
 * enclosing group carries a prefix. */
enum { PHP_GROUP_WALK_MAX = 64, PHP_PREFIX_PARTS_MAX = 8 };

static const char *php_chain_prefix_arg(CBMArena *a, TSNode call_node, const char *source) {
    /* call_node is a member_call_expression / scoped_call_expression whose
     * name is `prefix`; return its first string argument (unquoted). */
    TSNode args = ts_node_child_by_field_name(call_node, TS_FIELD("arguments"));
    if (ts_node_is_null(args)) {
        return NULL;
    }
    uint32_t nc = ts_node_named_child_count(args);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode arg = ts_node_named_child(args, i);
        TSNode inner = arg;
        if (strcmp(ts_node_type(arg), "argument") == 0 && ts_node_named_child_count(arg) > 0) {
            inner = ts_node_named_child(arg, 0);
        }
        if (strcmp(ts_node_type(inner), "string") == 0 ||
            strcmp(ts_node_type(inner), "encapsed_string") == 0) {
            char *txt = cbm_node_text(a, inner, source);
            if (txt && txt[0]) {
                size_t len = strlen(txt);
                if (len >= CBM_CALL_PHP_QUOTE_PAIR_LENGTH && (txt[0] == '\'' || txt[0] == '"')) {
                    txt[len - CBM_CALL_PREVIOUS_INDEX_OFFSET] = '\0';
                    txt++;
                }
                return txt[0] ? txt : NULL;
            }
        }
    }
    return NULL;
}

static TSNode php_group_call_for_closure(TSNode closure) {
    TSNode parent = ts_node_parent(closure);
    for (int depth = 0; depth < PHP_GROUP_WALK_MAX && !ts_node_is_null(parent); depth++) {
        const char *kind = ts_node_type(parent);
        if (strcmp(kind, "member_call_expression") == 0 ||
            strcmp(kind, "scoped_call_expression") == 0) {
            return parent;
        }
        if (strcmp(kind, "statement") == 0 || strcmp(kind, "expression_statement") == 0) {
            break;
        }
        parent = ts_node_parent(parent);
    }
    return (TSNode){0};
}

static bool php_is_group_call(CBMArena *a, TSNode call_node, const char *source) {
    TSNode name = ts_node_child_by_field_name(call_node, TS_FIELD("name"));
    char *text = ts_node_is_null(name) ? NULL : cbm_node_text(a, name, source);
    return text && strcmp(text, "group") == 0;
}

static const char *php_group_receiver_prefix(CBMArena *a, TSNode group_call, const char *source) {
    TSNode receiver = ts_node_child_by_field_name(group_call, TS_FIELD("object"));
    for (int hops = 0; hops < PHP_GROUP_WALK_MAX && !ts_node_is_null(receiver); hops++) {
        const char *kind = ts_node_type(receiver);
        bool member_call = strcmp(kind, "member_call_expression") == 0 ||
                           strcmp(kind, "scoped_call_expression") == 0;
        if (!member_call) {
            return NULL;
        }
        TSNode name = ts_node_child_by_field_name(receiver, TS_FIELD("name"));
        char *text = ts_node_is_null(name) ? NULL : cbm_node_text(a, name, source);
        if (text && strcmp(text, "prefix") == 0) {
            return php_chain_prefix_arg(a, receiver, source);
        }
        receiver = ts_node_child_by_field_name(receiver, TS_FIELD("object"));
    }
    return NULL;
}

static const char *php_compose_group_prefix(CBMArena *a, const char *const *parts, int part_count) {
    char buffer[CBM_SZ_256];
    size_t position = 0;
    for (int i = part_count - CBM_CALL_PREVIOUS_INDEX_OFFSET; i >= 0; i--) {
        const char *segment = parts[i];
        while (*segment == '/') {
            segment++;
        }
        size_t length = strlen(segment);
        if (length == 0) {
            continue;
        }
        if (position + length + CBM_CALL_PATH_APPEND_RESERVATION >= sizeof(buffer)) {
            return NULL;
        }
        buffer[position++] = '/';
        memcpy(buffer + position, segment, length);
        position += length;
        while (position > CBM_CALL_PATH_SEPARATOR_LENGTH &&
               buffer[position - CBM_CALL_PREVIOUS_INDEX_OFFSET] == '/') {
            position--;
        }
    }
    buffer[position] = '\0';
    return position > 0 ? cbm_arena_strndup(a, buffer, position) : NULL;
}

static const char *php_group_prefix_for_call(CBMArena *a, TSNode node, const char *source) {
    const char *parts[PHP_PREFIX_PARTS_MAX];
    int part_count = 0;
    TSNode cur = ts_node_parent(node);
    for (int depth = 0; depth < PHP_GROUP_WALK_MAX && !ts_node_is_null(cur); depth++) {
        const char *kind = ts_node_type(cur);
        if (strcmp(kind, "anonymous_function") == 0 || strcmp(kind, "arrow_function") == 0) {
            TSNode group_call = php_group_call_for_closure(cur);
            const char *prefix = php_is_group_call(a, group_call, source)
                                     ? php_group_receiver_prefix(a, group_call, source)
                                     : NULL;
            if (prefix && part_count < PHP_PREFIX_PARTS_MAX) {
                parts[part_count++] = prefix;
            }
        }
        cur = ts_node_parent(cur);
    }
    if (part_count == 0) {
        return NULL;
    }
    return php_compose_group_prefix(a, parts, part_count);
}

static bool is_nested_verilog_call_wrapper(CBMLanguage lang, TSNode node) {
    if (lang != CBM_LANG_VERILOG || strcmp(ts_node_type(node), "subroutine_call") != 0) {
        return false;
    }

    TSNode parent = ts_node_parent(node);
    return !ts_node_is_null(parent) &&
           strcmp(ts_node_type(parent), "function_subroutine_call") == 0;
}

static bool call_node_is_excluded(CBMLanguage lang, TSNode node, const char *source) {
    if (call_node_is_definition_container(lang, node, source) ||
        is_nested_verilog_call_wrapper(lang, node)) {
        return true;
    }
    return lang == CBM_LANG_LEAN && strcmp(ts_node_type(node), "apply") == 0 &&
           lean_is_in_type_position(node);
}

static char *extract_ruby_constructor_callee(CBMArena *a, TSNode node, const char *source,
                                             CBMLanguage lang) {
    if (lang != CBM_LANG_RUBY) {
        return NULL;
    }
    TSNode method = ts_node_child_by_field_name(node, TS_FIELD("method"));
    TSNode receiver = ts_node_child_by_field_name(node, TS_FIELD("receiver"));
    if (ts_node_is_null(method) || ts_node_is_null(receiver) ||
        strcmp(ts_node_type(receiver), "constant") != 0) {
        return NULL;
    }
    char *method_text = cbm_node_text(a, method, source);
    char *receiver_text =
        method_text && strcmp(method_text, "new") == 0 ? cbm_node_text(a, receiver, source) : NULL;
    return receiver_text && receiver_text[0] ? receiver_text : NULL;
}

static char *extract_php_route_callee(CBMArena *a, TSNode node, const char *source,
                                      CBMLanguage lang) {
    if (lang != CBM_LANG_PHP || strcmp(ts_node_type(node), "scoped_call_expression") != 0) {
        return NULL;
    }
    TSNode scope = ts_node_child_by_field_name(node, TS_FIELD("scope"));
    TSNode method = ts_node_child_by_field_name(node, TS_FIELD("name"));
    if (ts_node_is_null(scope) || ts_node_is_null(method)) {
        return NULL;
    }
    char *scope_text = cbm_node_text(a, scope, source);
    char *method_text = cbm_node_text(a, method, source);
    if (!scope_text || !method_text || strcmp(scope_text, "Route") != 0) {
        return NULL;
    }
    char *qualified = cbm_arena_sprintf(a, "%s::%s", scope_text, method_text);
    return qualified && cbm_service_pattern_route_method(qualified) != NULL ? qualified : NULL;
}

static char *extract_first_identifier_callee(CBMArena *a, TSNode node, const char *source) {
    if (ts_node_child_count(node) == 0) {
        return NULL;
    }
    TSNode first = ts_node_child(node, 0);
    return strcmp(ts_node_type(first), "identifier") == 0 ? cbm_node_text(a, first, source) : NULL;
}

static char *extract_callee_name(CBMArena *a, TSNode node, const char *source, CBMLanguage lang) {
    if (call_node_is_excluded(lang, node, source)) {
        return NULL;
    }
    char *name = lang == CBM_LANG_GOTEMPLATE ? gotemplate_callee(a, node, source) : NULL;
    if (name) {
        return name;
    }
    name = extract_constructor_callee(a, node, source, ts_node_type(node));
    if (name) {
        return name;
    }
    name = extract_ruby_constructor_callee(a, node, source, lang);
    if (name) {
        return name;
    }
    name = extract_php_route_callee(a, node, source, lang);
    if (name) {
        return name;
    }
    name = extract_callee_from_fields(a, node, source);
    if (name) {
        return name;
    }
    name = extract_callee_lang_specific(a, node, source, lang);
    return name ? name : extract_first_identifier_callee(a, node, source);
}

// Strip quotes and validate a string arg. Returns validated text or NULL.
// Never writes through text; returns char* (not const) since text is always
// caller-owned arena memory, never a view into the read-only source buffer.
static char *strip_and_validate_string_arg(CBMArena *a, char *text) {
    if (!text || !text[0]) {
        return NULL;
    }
    int len = (int)strlen(text);
    if (len >= CBM_QUOTE_PAIR && (text[0] == '"' || text[0] == '\'')) {
        text = cbm_arena_strndup(a, text + CBM_QUOTE_OFFSET, (size_t)(len - CBM_QUOTE_PAIR));
        len -= CBM_QUOTE_PAIR;
    }
    if (!text || len <= 0 || len >= MAX_STRING_ARG_LEN) {
        return NULL;
    }
    for (int vi = 0; vi < len; vi++) {
        if ((unsigned char)text[vi] < MIN_PRINTABLE && text[vi] != '\t') {
            return NULL;
        }
    }
    return text;
}

// Return the (dequoted) first string-literal child of a node, or NULL.
static char *gotemplate_string_child(CBMArena *a, TSNode parent, const char *source) {
    TSNode s = cbm_find_child_by_kind(parent, "interpreted_string_literal");
    if (ts_node_is_null(s)) {
        return NULL;
    }
    char *text = cbm_node_text(a, s, source);
    return strip_and_validate_string_arg(a, text);
}

// Resolve a Go-template / Helm call to the referenced named template:
//   {{ template "x" . }}            -> template_action, name is a string child
//   {{ include "x" . }}             -> function_call(include), name is first string arg
// Returns NULL for any other node so generic resolution names the function.
static char *gotemplate_callee(CBMArena *a, TSNode node, const char *source) {
    const char *k = ts_node_type(node);
    if (strcmp(k, "template_action") == 0) {
        return gotemplate_string_child(a, node, source);
    }
    if (strcmp(k, "function_call") == 0) {
        TSNode fn = cbm_find_child_by_kind(node, "identifier");
        if (ts_node_is_null(fn)) {
            return NULL;
        }
        char *fname = cbm_node_text(a, fn, source);
        if (!fname || (strcmp(fname, "include") != 0 && strcmp(fname, "template") != 0 &&
                       strcmp(fname, "tpl") != 0)) {
            return NULL;
        }
        TSNode args = ts_node_child_by_field_name(node, TS_FIELD("arguments"));
        if (ts_node_is_null(args)) {
            args = cbm_find_child_by_kind(node, "argument_list");
        }
        if (ts_node_is_null(args)) {
            return NULL;
        }
        return gotemplate_string_child(a, args, source);
    }
    return NULL;
}

static const char *extract_nth_string_arg(CBMExtractCtx *ctx, TSNode args, uint32_t n) {
    uint32_t nc = ts_node_named_child_count(args);
    uint32_t found = 0;
    for (uint32_t ai = 0; ai < nc && ai < MAX_POSITIONAL_SCAN + n; ai++) {
        TSNode arg = ts_node_named_child(args, ai);
        const char *ak = ts_node_type(arg);
        if (is_string_like(ak)) {
            if (found == n) {
                char *text = cbm_node_text(ctx->arena, arg, ctx->source);
                return strip_and_validate_string_arg(ctx->arena, text);
            }
            found++;
        }
    }
    return NULL;
}

// --- Unified handler: called once per node by the cursor walk ---

// Process a keyword argument (keyword_argument or pair node).
static void process_keyword_arg(CBMExtractCtx *ctx, TSNode arg_node, CBMCallArg *ca) {
    TSNode key_n = ts_node_child_by_field_name(arg_node, TS_FIELD("name"));
    TSNode val_n = ts_node_child_by_field_name(arg_node, TS_FIELD("value"));
    if (ts_node_is_null(key_n)) {
        key_n = ts_node_child_by_field_name(arg_node, TS_FIELD("key"));
    }
    if (!ts_node_is_null(key_n)) {
        ca->keyword = cbm_node_text(ctx->arena, key_n, ctx->source);
    }
    if (!ts_node_is_null(val_n)) {
        ca->expr = cbm_node_text(ctx->arena, val_n, ctx->source);
        if (strcmp(ts_node_type(val_n), "identifier") == 0 && ca->expr) {
            ca->value = lookup_string_constant(ctx, ca->expr);
        } else if (is_string_like(ts_node_type(val_n)) && ca->expr) {
            ca->value = strip_quotes(ctx->arena, ca->expr);
        }
    }
}

/* Extract all arguments from a call expression into call->args[]. */
static void extract_call_args(CBMExtractCtx *ctx, TSNode args, CBMCall *call) {
    uint32_t argc = ts_node_named_child_count(args);
    int positional_idx = 0;
    for (uint32_t ai = 0; ai < argc && call->arg_count < CBM_MAX_CALL_ARGS; ai++) {
        TSNode arg_node = ts_node_named_child(args, ai);
        const char *ak = ts_node_type(arg_node);
        CBMCallArg *ca = &call->args[call->arg_count];
        memset(ca, 0, sizeof(*ca));

        if (strcmp(ak, "keyword_argument") == 0 || strcmp(ak, "pair") == 0) {
            process_keyword_arg(ctx, arg_node, ca);
            ca->index = positional_idx++;
            call->arg_count++;
        } else if (strcmp(ak, "list_splat") == 0 || strcmp(ak, "dictionary_splat") == 0 ||
                   strcmp(ak, "spread_element") == 0) {
            positional_idx++;
        } else {
            ca->expr = cbm_node_text(ctx->arena, arg_node, ctx->source);
            ca->index = positional_idx++;
            if (is_string_like(ak) && ca->expr) {
                ca->value = strip_quotes(ctx->arena, ca->expr);
            } else if (strcmp(ak, "identifier") == 0 && ca->expr) {
                ca->value = lookup_string_constant(ctx, ca->expr);
            }
            call->arg_count++;
        }
    }
}

// Check if a keyword name matches URL or topic patterns.
static bool is_url_or_topic_keyword(const char *key) {
    static const char *url_keywords[] = {"url",        "endpoint", "path", "uri",
                                         "target_url", "base_url", NULL};
    static const char *topic_keywords[] = {"topic",   "topic_id",   "topic_name",
                                           "queue",   "queue_name", "queue_id",
                                           "subject", "channel",    NULL};
    for (int i = 0; url_keywords[i]; i++) {
        if (strcmp(key, url_keywords[i]) == 0) {
            return true;
        }
    }
    for (int i = 0; topic_keywords[i]; i++) {
        if (strcmp(key, topic_keywords[i]) == 0) {
            return true;
        }
    }
    return false;
}

// Check if a struct-field name identifies a queue/topic target.  Cloud SDKs pass
// the destination via a composite-literal input struct rather than a bare string
// arg (e.g. Go `SendMessageInput{QueueUrl: ...}`, `PublishInput{TopicArn: ...}`).
// Case-insensitive so QueueUrl/QueueURL/queue_url all match.
static bool is_queue_topic_field(const char *key) {
    static const char *fields[] = {"QueueUrl",  "QueueURL", "TopicArn", "TopicARN",    "QueueName",
                                   "TopicName", "QueueArn", "QueueARN", "Destination", NULL};
    if (!key || !key[0]) {
        return false;
    }
    for (int i = 0; fields[i]; i++) {
        if (strcasecmp(key, fields[i]) == 0) {
            return true;
        }
    }
    return false;
}

// Extract string value from a node (literal or constant reference).
static const char *extract_string_value(CBMExtractCtx *ctx, TSNode val_node) {
    const char *vk = ts_node_type(val_node);
    if (strcmp(vk, "template_string") == 0) {
        return cbm_template_string_text(ctx->arena, val_node, ctx->source);
    }
    if (is_string_like(vk)) {
        char *text = cbm_node_text(ctx->arena, val_node, ctx->source);
        if (text && text[0]) {
            return strip_quotes(ctx->arena, text);
        }
    } else if (strcmp(vk, "identifier") == 0) {
        char *const_name = cbm_node_text(ctx->arena, val_node, ctx->source);
        if (const_name) {
            return lookup_string_constant(ctx, const_name);
        }
    }
    return NULL;
}

// Recover a queue/topic identity from a Go composite-literal input struct, e.g.
//   &sqs.SendMessageInput{QueueUrl: queueUrl, MessageBody: body}
//   sns.PublishInput{TopicArn: "arn:aws:sns:..."}
// The dispatch target is carried by a struct field (QueueUrl/TopicArn/...), not a
// bare string arg, so the async edge would otherwise degrade to a plain CALLS.
// Returns the field's value: the string-literal content when present, else the
// referenced identifier text (which still names the queue/topic for edge formation).
static const char *extract_composite_queue_field(CBMExtractCtx *ctx, TSNode node) {
    // Unwrap a pointer-of-composite: `&Type{...}` is a unary_expression whose
    // operand is the composite_literal.
    if (strcmp(ts_node_type(node), "unary_expression") == 0) {
        TSNode operand = ts_node_child_by_field_name(node, TS_FIELD("operand"));
        if (ts_node_is_null(operand)) {
            return NULL;
        }
        node = operand;
    }
    if (strcmp(ts_node_type(node), "composite_literal") != 0) {
        return NULL;
    }
    TSNode body = ts_node_child_by_field_name(node, TS_FIELD("body"));
    if (ts_node_is_null(body)) {
        body = cbm_find_child_by_kind(node, "literal_value");
    }
    if (ts_node_is_null(body)) {
        return NULL;
    }
    uint32_t nc = ts_node_named_child_count(body);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode el = ts_node_named_child(body, i);
        if (strcmp(ts_node_type(el), "keyed_element") != 0) {
            continue;
        }
        // keyed_element children: key then value. Each side may be wrapped in a
        // literal_element; unwrap to the underlying identifier/literal.
        uint32_t ec = ts_node_named_child_count(el);
        if (ec < PAIR_LEN) {
            continue;
        }
        TSNode key_n = ts_node_named_child(el, 0);
        TSNode val_n = ts_node_named_child(el, CBM_AST_SECOND_CHILD_INDEX);
        if (strcmp(ts_node_type(key_n), "literal_element") == 0 &&
            ts_node_named_child_count(key_n) > 0) {
            key_n = ts_node_named_child(key_n, 0);
        }
        if (strcmp(ts_node_type(val_n), "literal_element") == 0 &&
            ts_node_named_child_count(val_n) > 0) {
            val_n = ts_node_named_child(val_n, 0);
        }
        char *key = cbm_node_text(ctx->arena, key_n, ctx->source);
        if (!is_queue_topic_field(key)) {
            continue;
        }
        const char *resolved = extract_string_value(ctx, val_n);
        if (resolved && resolved[0]) {
            return resolved;
        }
        // Value is a variable/expression (no constant value); use its source text
        // as the queue/topic identity so the async edge still forms.
        char *raw = cbm_node_text(ctx->arena, val_n, ctx->source);
        if (raw && raw[0]) {
            return raw;
        }
    }
    return NULL;
}

// Try to extract URL/topic from a keyword_argument or pair node.
static const char *extract_keyword_url(CBMExtractCtx *ctx, TSNode arg) {
    TSNode key_node = ts_node_child_by_field_name(arg, TS_FIELD("name"));
    TSNode val_node = ts_node_child_by_field_name(arg, TS_FIELD("value"));
    if (ts_node_is_null(key_node)) {
        key_node = ts_node_child_by_field_name(arg, TS_FIELD("key"));
    }
    if (ts_node_is_null(key_node) || ts_node_is_null(val_node)) {
        return NULL;
    }
    char *key = cbm_node_text(ctx->arena, key_node, ctx->source);
    if (!key || !is_url_or_topic_keyword(key)) {
        return NULL;
    }
    return extract_string_value(ctx, val_node);
}

// Try to extract URL/topic from a positional argument (string or constant).
static const char *extract_positional_url(CBMExtractCtx *ctx, TSNode arg, const char *ak) {
    /* JS/TS template literals: `/things/${id}` normalizes to "/things/{}" so the
     * client URL joins the server route's canonical placeholder (issue #1006). */
    if (strcmp(ak, "template_string") == 0) {
        const char *flat = cbm_template_string_text(ctx->arena, arg, ctx->source);
        if (flat) {
            /* cbm_template_string_text always hands back freshly arena-built
             * text, never a view into the read-only source buffer, so the
             * const in its shared signature is stricter than the data needs.
             * memcpy the pointer value rather than cast away const. */
            char *mut_flat;
            memcpy(&mut_flat, &flat, sizeof(mut_flat));
            return strip_and_validate_string_arg(ctx->arena, mut_flat);
        }
    }
    if (is_string_like(ak)) {
        char *text = cbm_node_text(ctx->arena, arg, ctx->source);
        const char *validated = strip_and_validate_string_arg(ctx->arena, text);
        if (validated) {
            return validated;
        }
    }
    if (strcmp(ak, "identifier") == 0) {
        char *const_name = cbm_node_text(ctx->arena, arg, ctx->source);
        if (const_name) {
            return lookup_string_constant(ctx, const_name);
        }
    }
    return NULL;
}

// Extract URL/topic from keyword or positional args.
static const char *extract_url_or_topic_arg(CBMExtractCtx *ctx, TSNode args) {
    uint32_t nc = ts_node_named_child_count(args);
    for (uint32_t ai = 0; ai < nc; ai++) {
        TSNode arg = ts_node_named_child(args, ai);
        /* PHP and C# wrap each positional argument in an `argument` node;
         * unwrap to the underlying value so the URL string is reachable. */
        if (strcmp(ts_node_type(arg), "argument") == 0 && ts_node_named_child_count(arg) > 0) {
            arg = ts_node_named_child(arg, 0);
        }
        const char *ak = ts_node_type(arg);

        if (strcmp(ak, "keyword_argument") == 0 || strcmp(ak, "pair") == 0) {
            const char *val = extract_keyword_url(ctx, arg);
            if (val) {
                return val;
            }
            continue;
        }

        /* Cloud SDK dispatch via input struct: the queue/topic target is a field
         * of a composite literal (Go `&sqs.SendMessageInput{QueueUrl: ...}`), not
         * a bare string arg. Recover it so the async edge forms. */
        if (strcmp(ak, "composite_literal") == 0 || strcmp(ak, "unary_expression") == 0) {
            const char *val = extract_composite_queue_field(ctx, arg);
            if (val) {
                return val;
            }
        }

        if (ai < MAX_POSITIONAL_SCAN) {
            const char *val = extract_positional_url(ctx, arg, ak);
            if (val) {
                return val;
            }
        }
    }
    return NULL;
}

// Extract second argument name (handler ref for route registrations).
/* Normalize a string-form route handler to a resolvable handler name.
 *   'showUsers'              → showUsers
 *   'UserController@show'    → show   (Laravel "Controller@method")
 * The method segment after '@' is the resolvable function/method name. */
static const char *normalize_string_handler(CBMArena *a, const char *raw) {
    const char *unq = strip_quotes(a, raw);
    if (!unq || !unq[0]) {
        return NULL;
    }
    const char *at = strchr(unq, '@');
    if (at && at[CBM_CALL_NEXT_CHARACTER_OFFSET]) {
        return cbm_arena_strdup(a, at + CBM_CALL_NEXT_CHARACTER_OFFSET);
    }
    return unq;
}

static const char *extract_handler_arg(CBMExtractCtx *ctx, TSNode args) {
    uint32_t nc = ts_node_named_child_count(args);
    for (uint32_t ai = HANDLER_START_IDX; ai < nc && ai < MAX_HANDLER_SCAN; ai++) {
        TSNode arg2 = ts_node_named_child(args, ai);
        /* PHP wraps each argument in an `argument` node — unwrap to the value. */
        if (strcmp(ts_node_type(arg2), "argument") == 0 && ts_node_named_child_count(arg2) > 0) {
            arg2 = ts_node_named_child(arg2, 0);
        }
        const char *ak2 = ts_node_type(arg2);
        /* `name` = PHP bare identifier handler; string = Laravel string handler
         * ('showUsers' or 'Controller@method'). */
        if (strcmp(ak2, "identifier") == 0 || strcmp(ak2, "member_expression") == 0 ||
            strcmp(ak2, "selector_expression") == 0 || strcmp(ak2, "attribute") == 0 ||
            strcmp(ak2, "field_expression") == 0 || strcmp(ak2, "name") == 0) {
            return cbm_node_text(ctx->arena, arg2, ctx->source);
        }
        if (is_string_like(ak2)) {
            const char *h =
                normalize_string_handler(ctx->arena, cbm_node_text(ctx->arena, arg2, ctx->source));
            if (h && h[0]) {
                return h;
            }
        }
    }
    return NULL;
}

// Extract JSX component refs (uppercase tags) as CALLS edges.
static void extract_jsx_component_ref(CBMExtractCtx *ctx, TSNode node, const char *kind,
                                      const char *enclosing_func_qn) {
    if (strcmp(kind, "jsx_self_closing_element") != 0 && strcmp(kind, "jsx_opening_element") != 0) {
        return;
    }
    TSNode name_node = ts_node_child_by_field_name(node, TS_FIELD("name"));
    if (ts_node_is_null(name_node)) {
        return;
    }
    char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
    if (name && name[0] >= 'A' && name[0] <= 'Z') {
        CBMCall call = {0};
        call.callee_name = name;
        call.enclosing_func_qn = enclosing_func_qn;
        call.site_start_byte = ts_node_start_byte(node);
        call.site_end_byte = ts_node_end_byte(node);
        /* An uppercase tag is only a component invocation when the TS resolver
         * proves which lexical value owns it.  In particular, a parameter or
         * local named like a module component must not fall through to the
         * textual call resolver. */
        call.requires_lsp_resolution = true;
        cbm_calls_push(&ctx->result->calls, ctx->arena, call);
    }
}

static bool kotlin_direct_unnamed_token(TSNode node, const char *token) {
    uint32_t count = ts_node_child_count(node);
    for (uint32_t i = 0; i < count; i++) {
        TSNode child = ts_node_child(node, i);
        if (!ts_node_is_named(child) && strcmp(ts_node_type(child), token) == 0) {
            return true;
        }
    }
    return false;
}

static const char *kotlin_binary_operator_method(TSNode node) {
    if (kotlin_direct_unnamed_token(node, "===") || kotlin_direct_unnamed_token(node, "!==")) {
        return NULL; /* identity comparison has no operator method */
    }
    if (kotlin_direct_unnamed_token(node, "==") || kotlin_direct_unnamed_token(node, "!=")) {
        return "equals";
    }
    if (kotlin_direct_unnamed_token(node, "..<")) {
        return "rangeUntil";
    }
    if (kotlin_direct_unnamed_token(node, "..")) {
        return "rangeTo";
    }
    if (kotlin_direct_unnamed_token(node, "<=") || kotlin_direct_unnamed_token(node, ">=") ||
        kotlin_direct_unnamed_token(node, "<") || kotlin_direct_unnamed_token(node, ">")) {
        return "compareTo";
    }
    if (kotlin_direct_unnamed_token(node, "+")) {
        return "plus";
    }
    if (kotlin_direct_unnamed_token(node, "-")) {
        return "minus";
    }
    if (kotlin_direct_unnamed_token(node, "*")) {
        return "times";
    }
    if (kotlin_direct_unnamed_token(node, "/")) {
        return "div";
    }
    if (kotlin_direct_unnamed_token(node, "%")) {
        return "rem";
    }
    return NULL;
}

static const char *kotlin_unary_operator_method(TSNode node, const char *kind) {
    if (strcmp(kind, "postfix_expression") == 0) {
        if (kotlin_direct_unnamed_token(node, "++")) {
            return "inc";
        }
        if (kotlin_direct_unnamed_token(node, "--")) {
            return "dec";
        }
        return NULL; /* `!!` and call/navigation suffixes are not operator calls */
    }
    if (kotlin_direct_unnamed_token(node, "++")) {
        return "inc";
    }
    if (kotlin_direct_unnamed_token(node, "--")) {
        return "dec";
    }
    if (kotlin_direct_unnamed_token(node, "!")) {
        return "not";
    }
    if (kotlin_direct_unnamed_token(node, "-")) {
        return "unaryMinus";
    }
    if (kotlin_direct_unnamed_token(node, "+")) {
        return "unaryPlus";
    }
    return NULL;
}

static bool kotlin_node_is_update(TSNode node) {
    const char *kind = ts_node_type(node);
    return (strcmp(kind, "prefix_expression") == 0 || strcmp(kind, "postfix_expression") == 0 ||
            strcmp(kind, "unary_expression") == 0) &&
           (kotlin_direct_unnamed_token(node, "++") || kotlin_direct_unnamed_token(node, "--"));
}

static bool kotlin_index_is_write_lhs(TSNode index) {
    for (TSNode parent = ts_node_parent(index); !ts_node_is_null(parent);
         parent = ts_node_parent(parent)) {
        const char *kind = ts_node_type(parent);
        if (strcmp(kind, "assignment") == 0) {
            TSNode lhs = ts_node_child_by_field_name(parent, TS_FIELD("left"));
            if (ts_node_is_null(lhs) && ts_node_named_child_count(parent) > 0) {
                lhs = ts_node_named_child(parent, 0);
            }
            return call_node_contains(lhs, index);
        }
        if (kotlin_node_is_update(parent)) {
            return call_node_contains(parent, index);
        }
        if (strcmp(kind, "parenthesized_expression") != 0 &&
            strcmp(kind, "directly_assignable_expression") != 0 &&
            strcmp(kind, "assignable_expression") != 0 &&
            strcmp(kind, "parenthesized_directly_assignable_expression") != 0 &&
            strcmp(kind, "expression") != 0) {
            break;
        }
    }
    return false;
}

static bool kotlin_same_call_owner(const char *left, const char *right) {
    return left == right || (left && right && strcmp(left, right) == 0);
}

#if defined(CBM_KOTLIN_DEDUP_TEST_API) && CBM_KOTLIN_DEDUP_TEST_API
static _Atomic uint64_t g_kotlin_operator_dedup_comparisons = 0;

void cbm_kotlin_operator_dedup_test_reset(void) {
    atomic_store_explicit(&g_kotlin_operator_dedup_comparisons, 0, memory_order_relaxed);
}

uint64_t cbm_kotlin_operator_dedup_test_comparisons(void) {
    return atomic_load_explicit(&g_kotlin_operator_dedup_comparisons, memory_order_relaxed);
}

static void count_kotlin_operator_dedup_comparison(void) {
    atomic_fetch_add_explicit(&g_kotlin_operator_dedup_comparisons, 1, memory_order_relaxed);
}
#else
static void count_kotlin_operator_dedup_comparison(void) {}
#endif

static bool kotlin_operator_call_matches(const CBMCall *existing, const char *callee_name,
                                         const char *enclosing_func_qn, uint32_t start,
                                         uint32_t end) {
    count_kotlin_operator_dedup_comparison();
    return existing->callee_name && strcmp(existing->callee_name, callee_name) == 0 &&
           kotlin_same_call_owner(existing->enclosing_func_qn, enclosing_func_qn) &&
           existing->site_start_byte == start && existing->site_end_byte == end;
}

static void push_kotlin_operator_call(CBMExtractCtx *ctx, TSNode node, const char *callee_name,
                                      const char *enclosing_func_qn) {
    if (!callee_name || !callee_name[0]) {
        return;
    }
    uint32_t start = ts_node_start_byte(node);
    uint32_t end = ts_node_end_byte(node);
    /* Equal-span Kotlin grammar wrappers are visited consecutively by the
     * unified preorder walk. Only the last emitted carrier can therefore be
     * the wrapper duplicate for this node; scanning every prior call made a
     * file with N operator expressions perform O(N^2) comparisons. */
    if (ctx->result->calls.count > 0) {
        const CBMCall *existing = &ctx->result->calls.items[ctx->result->calls.count - SKIP_ONE];
        if (kotlin_operator_call_matches(existing, callee_name, enclosing_func_qn, start, end)) {
            return;
        }
    }
    CBMCall call = {0};
    call.callee_name = callee_name;
    call.enclosing_func_qn = enclosing_func_qn;
    call.start_line = (int)ts_node_start_point(node).row + TS_LINE_OFFSET;
    call.site_start_byte = start;
    call.site_end_byte = end;
    call.requires_lsp_resolution = true;
    cbm_calls_push(&ctx->result->calls, ctx->arena, call);
}

// Kotlin operator syntax desugars to method calls, but these expressions are
// not call_expression nodes. Emit an exact-span, LSP-guarded carrier whose bare
// name can join only the semantic row for the same expression. Operator tokens
// come from direct unnamed AST children, so comments/operand text cannot alter
// the mapping. Writes through an index stay fail-closed until set/compound-set
// semantics are implemented.
static void extract_kotlin_operator_call(CBMExtractCtx *ctx, TSNode node, const char *kind,
                                         const char *enclosing_func_qn) {
    const char *op_method = NULL;
    if (strcmp(kind, "binary_expression") == 0 || strcmp(kind, "additive_expression") == 0 ||
        strcmp(kind, "multiplicative_expression") == 0 ||
        strcmp(kind, "comparison_expression") == 0 || strcmp(kind, "equality_expression") == 0 ||
        strcmp(kind, "range_expression") == 0) {
        if (ts_node_named_child_count(node) < CBM_CALL_MIN_BINARY_OPERAND_COUNT) {
            return;
        }
        op_method = kotlin_binary_operator_method(node);
    } else if (strcmp(kind, "unary_expression") == 0 || strcmp(kind, "prefix_expression") == 0 ||
               strcmp(kind, "postfix_expression") == 0) {
        if (ts_node_named_child_count(node) < CBM_CALL_MIN_UNARY_OPERAND_COUNT) {
            return;
        }
        op_method = kotlin_unary_operator_method(node, kind);
    } else if (strcmp(kind, "in_expression") == 0 || strcmp(kind, "check_expression") == 0) {
        if (ts_node_named_child_count(node) < CBM_CALL_MIN_BINARY_OPERAND_COUNT ||
            (!kotlin_direct_unnamed_token(node, "in") &&
             !kotlin_direct_unnamed_token(node, "!in")) ||
            kotlin_direct_unnamed_token(node, "is")) {
            return;
        }
        op_method = "contains";
    } else if (strcmp(kind, "index_expression") == 0 || strcmp(kind, "indexing_expression") == 0) {
        if (ts_node_named_child_count(node) < CBM_CALL_MIN_UNARY_OPERAND_COUNT ||
            kotlin_index_is_write_lhs(node)) {
            return;
        }
        op_method = "get";
    } else {
        return;
    }
    push_kotlin_operator_call(ctx, node, op_method, enclosing_func_qn);
}

// Kotlin convention-desugared calls that the call walk never sees as
// call_expressions: `val (a,b) = e` -> e.component1()/e.component2(); and
// `for (x in e)` -> e.iterator()/hasNext()/next(). Record textual calls to those
// operator-convention method names so the LSP's lsp_kt_destructure /
// lsp_kt_iterator resolutions have a call site to join (names match the LSP's).
static void kt_push_implicit_call(CBMExtractCtx *ctx, TSNode node, const char *callee,
                                  const char *enclosing_func_qn) {
    CBMCall call = {0};
    call.callee_name = callee;
    call.enclosing_func_qn = enclosing_func_qn;
    call.start_line = (int)ts_node_start_point(node).row + TS_LINE_OFFSET;
    call.site_start_byte = ts_node_start_byte(node);
    call.site_end_byte = ts_node_end_byte(node);
    call.requires_lsp_resolution = true;
    cbm_calls_push(&ctx->result->calls, ctx->arena, call);
}

static void push_cpp_semantic_call_candidate(CBMExtractCtx *ctx, TSNode node,
                                             const char *callee_name,
                                             const char *enclosing_func_qn) {
    if (!callee_name || !callee_name[0] || !enclosing_func_qn) {
        return;
    }
    CBMCall call = {0};
    call.callee_name = callee_name;
    call.enclosing_func_qn = enclosing_func_qn;
    call.start_line = (int)ts_node_start_point(node).row + TS_LINE_OFFSET;
    call.site_start_byte = ts_node_start_byte(node);
    call.site_end_byte = ts_node_end_byte(node);
    call.requires_lsp_resolution = true;
    cbm_calls_push(&ctx->result->calls, ctx->arena, call);
}

static const char *cpp_operator_token(CBMExtractCtx *ctx, TSNode node) {
    for (uint32_t i = 0; i < ts_node_child_count(node); i++) {
        TSNode child = ts_node_child(node, i);
        if (!ts_node_is_named(child)) {
            const char *token = cbm_node_text(ctx->arena, child, ctx->source);
            if (token && token[0]) {
                return token;
            }
        }
    }
    return NULL;
}

static bool cpp_is_compound_assignment_token(const char *token) {
    return token &&
           (strcmp(token, "+=") == 0 || strcmp(token, "-=") == 0 || strcmp(token, "*=") == 0 ||
            strcmp(token, "/=") == 0 || strcmp(token, "%=") == 0 || strcmp(token, "<<=") == 0 ||
            strcmp(token, ">>=") == 0 || strcmp(token, "&=") == 0 || strcmp(token, "|=") == 0 ||
            strcmp(token, "^=") == 0);
}

// C++ operators represented by expression nodes are real invocations only when
// overload resolution finds a concrete function. Emit exact-occurrence raw
// candidates here; requires_lsp_resolution keeps primitive/pointer syntax from
// falling through to textual registry lookup and fabricating CALLS edges.
static void extract_cpp_subscript_operator(CBMExtractCtx *ctx, TSNode node,
                                           const char *enclosing_func_qn) {
    TSNode receiver = ts_node_child_by_field_name(node, TS_FIELD("argument"));
    TSNode index = ts_node_child_by_field_name(node, TS_FIELD("index"));
    if (ts_node_is_null(receiver) && ts_node_named_child_count(node) > 0) {
        receiver = ts_node_named_child(node, 0);
    }
    if (ts_node_is_null(index) && ts_node_named_child_count(node) > CBM_AST_SECOND_CHILD_INDEX) {
        index = ts_node_named_child(node, CBM_AST_SECOND_CHILD_INDEX);
    }
    if (!ts_node_is_null(receiver) && !ts_node_is_null(index)) {
        push_cpp_semantic_call_candidate(ctx, node, "operator[]", enclosing_func_qn);
    }
}

static void extract_cpp_unary_operator(CBMExtractCtx *ctx, TSNode node, const char *kind,
                                       const char *enclosing_func_qn) {
    TSNode operand = ts_node_child_by_field_name(node, TS_FIELD("argument"));
    if (ts_node_is_null(operand)) {
        operand = ts_node_child_by_field_name(node, TS_FIELD("operand"));
    }
    if (ts_node_is_null(operand) && ts_node_named_child_count(node) > 0) {
        operand = ts_node_named_child(node, 0);
    }
    const char *token = cpp_operator_token(ctx, node);
    bool unary_token =
        token && (strcmp(token, "-") == 0 || strcmp(token, "*") == 0 || strcmp(token, "!") == 0);
    bool update_token = token && (strcmp(token, "++") == 0 || strcmp(token, "--") == 0);
    bool dereferences_this = !ts_node_is_null(operand) && token && strcmp(token, "*") == 0 &&
                             strcmp(ts_node_type(operand), "this") == 0;
    bool is_update = strcmp(kind, "update_expression") == 0;
    if (!dereferences_this && !ts_node_is_null(operand) &&
        ((is_update && update_token) || (!is_update && unary_token))) {
        push_cpp_semantic_call_candidate(
            ctx, node, cbm_arena_sprintf(ctx->arena, "operator%s", token), enclosing_func_qn);
    }
}

static void extract_cpp_arrow_operator(CBMExtractCtx *ctx, TSNode node,
                                       const char *enclosing_func_qn) {
    TSNode receiver = ts_node_child_by_field_name(node, TS_FIELD("argument"));
    TSNode member = ts_node_child_by_field_name(node, TS_FIELD("field"));
    const char *token = cpp_operator_token(ctx, node);
    if (!ts_node_is_null(receiver) && !ts_node_is_null(member) && token &&
        strcmp(token, "->") == 0) {
        push_cpp_semantic_call_candidate(ctx, node, "operator->", enclosing_func_qn);
    }
}

static void extract_cpp_binary_operator(CBMExtractCtx *ctx, TSNode node,
                                        const char *enclosing_func_qn) {
    TSNode lhs = ts_node_child_by_field_name(node, TS_FIELD("left"));
    TSNode rhs = ts_node_child_by_field_name(node, TS_FIELD("right"));
    const char *token = cpp_operator_token(ctx, node);
    if (!ts_node_is_null(lhs) && !ts_node_is_null(rhs) && token) {
        push_cpp_semantic_call_candidate(
            ctx, node, cbm_arena_sprintf(ctx->arena, "operator%s", token), enclosing_func_qn);
    }
}

static void extract_cpp_operator_call(CBMExtractCtx *ctx, TSNode node, const char *kind,
                                      const char *enclosing_func_qn) {
    if (strcmp(kind, "subscript_expression") == 0) {
        extract_cpp_subscript_operator(ctx, node, enclosing_func_qn);
        return;
    }

    if (strcmp(kind, "unary_expression") == 0 || strcmp(kind, "pointer_expression") == 0 ||
        strcmp(kind, "update_expression") == 0) {
        extract_cpp_unary_operator(ctx, node, kind, enclosing_func_qn);
        return;
    }

    if (strcmp(kind, "field_expression") == 0) {
        extract_cpp_arrow_operator(ctx, node, enclosing_func_qn);
        return;
    }

    if (strcmp(kind, "assignment_expression") == 0) {
        TSNode lhs = ts_node_child_by_field_name(node, TS_FIELD("left"));
        TSNode rhs = ts_node_child_by_field_name(node, TS_FIELD("right"));
        const char *token = cpp_operator_token(ctx, node);
        if (!ts_node_is_null(lhs) && !ts_node_is_null(rhs) &&
            cpp_is_compound_assignment_token(token)) {
            push_cpp_semantic_call_candidate(
                ctx, node, cbm_arena_sprintf(ctx->arena, "operator%s", token), enclosing_func_qn);
        }
        return;
    }

    if (strcmp(kind, "binary_expression") != 0) {
        return;
    }
    extract_cpp_binary_operator(ctx, node, enclosing_func_qn);
}

// C++ implicit calls that produce no textual call node: the destructor
// (`delete p`), the copy/move constructor (`T a = b;` copy-init), and the
// conversion operator (`if (obj)` where obj has `operator bool`). The c-LSP
// resolves each to the corresponding member but there is no call site to join
// to (callable=0). Synthesize a textual call sourced to the enclosing function
// so the lsp_{destructor,copy_constructor,conversion} resolution binds.
//
//   - destructor: the callee QN embeds the type (`T.~T`), which is not textually
//     available from `delete p`. Use a non-textual destructor marker; the exact
//     occurrence is joined only to an LSP-proved, materialized destructor and is
//     rewritten to `~T` when the same-file pass can prove it.
//   - copy constructor: the callee short-name is the constructed type (`T`),
//     which IS textually present as the declaration's type — join by short-name.
//   - conversion: the callee short-name is the type-independent `operator bool`.
//
// Spurious synthesis (a condition/operand that has no such member) resolves to
// nothing and is dropped, so no extra edge is produced.
static const char *cpp_implicit_delete_callee(TSNode node) {
    TSNode operand = ts_node_child_by_field_name(node, TS_FIELD("argument"));
    if (ts_node_is_null(operand) && ts_node_named_child_count(node) > 0) {
        operand = ts_node_named_child(node, 0);
    }
    return ts_node_is_null(operand) ? NULL : "~";
}

static const char *cpp_implicit_conversion_callee(TSNode node) {
    TSNode condition = ts_node_child_by_field_name(node, TS_FIELD("condition"));
    if (ts_node_is_null(condition)) {
        return NULL;
    }
    TSNode inner = condition;
    if (strcmp(ts_node_type(condition), "condition_clause") == 0 &&
        ts_node_named_child_count(condition) == CBM_CALL_MIN_UNARY_OPERAND_COUNT) {
        inner = ts_node_named_child(condition, 0);
    }
    return strcmp(ts_node_type(inner), "identifier") == 0 ? "operator bool" : NULL;
}

static const char *cpp_implicit_copy_callee(CBMExtractCtx *ctx, TSNode node) {
    TSNode type = ts_node_child_by_field_name(node, TS_FIELD("type"));
    TSNode declarator = ts_node_child_by_field_name(node, TS_FIELD("declarator"));
    if (ts_node_is_null(type) || ts_node_is_null(declarator) ||
        strcmp(ts_node_type(declarator), "init_declarator") != 0) {
        return NULL;
    }
    TSNode value = ts_node_child_by_field_name(declarator, TS_FIELD("value"));
    if (ts_node_is_null(value) || strcmp(ts_node_type(value), "identifier") != 0) {
        return NULL;
    }
    char *type_name = cbm_node_text(ctx->arena, type, ctx->source);
    if (!type_name) {
        return NULL;
    }
    const char *colon = strrchr(type_name, ':');
    return colon ? colon + CBM_CALL_NEXT_CHARACTER_OFFSET : type_name;
}

static void extract_cpp_implicit_calls(CBMExtractCtx *ctx, TSNode node, const char *kind,
                                       const char *enclosing_func_qn) {
    const char *callee = NULL;
    if (strcmp(kind, "delete_expression") == 0) {
        callee = cpp_implicit_delete_callee(node);
    } else if (strcmp(kind, "if_statement") == 0 || strcmp(kind, "while_statement") == 0 ||
               strcmp(kind, "do_statement") == 0) {
        // `if (obj)` invokes obj's `operator bool`. Only a lone-identifier
        // condition triggers it; comparisons/logical exprs evaluate to bool.
        callee = cpp_implicit_conversion_callee(node);
    } else if (strcmp(kind, "declaration") == 0) {
        // `T a = b;` — copy-init from an identifier invokes T's copy constructor.
        callee = cpp_implicit_copy_callee(ctx, node);
    }
    if (callee && callee[0]) {
        push_cpp_semantic_call_candidate(ctx, node, callee, enclosing_func_qn);
    }
}

static void extract_kotlin_desugared_calls(CBMExtractCtx *ctx, TSNode node, const char *kind,
                                           const char *enclosing_func_qn) {
    if (strcmp(kind, "property_declaration") == 0) {
        uint32_t nc = ts_node_named_child_count(node);
        for (uint32_t i = 0; i < nc; i++) {
            TSNode c = ts_node_named_child(node, i);
            if (strcmp(ts_node_type(c), "multi_variable_declaration") != 0) {
                continue;
            }
            // One componentN() call per destructured variable.
            uint32_t vc = ts_node_named_child_count(c);
            uint32_t comp = 0;
            for (uint32_t j = 0; j < vc; j++) {
                TSNode v = ts_node_named_child(c, j);
                if (strcmp(ts_node_type(v), "variable_declaration") != 0) {
                    continue;
                }
                comp++;
                kt_push_implicit_call(ctx, node, cbm_arena_sprintf(ctx->arena, "component%u", comp),
                                      enclosing_func_qn);
            }
            break;
        }
    } else if (strcmp(kind, "for_statement") == 0) {
        kt_push_implicit_call(ctx, node, "iterator", enclosing_func_qn);
        kt_push_implicit_call(ctx, node, "hasNext", enclosing_func_qn);
        kt_push_implicit_call(ctx, node, "next", enclosing_func_qn);
    }
}

static bool php_is_first_class_callable(TSNode node) {
    TSNode args = ts_node_child_by_field_name(node, TS_FIELD("arguments"));
    if (ts_node_is_null(args)) {
        return false;
    }
    if (strcmp(ts_node_type(args), "variadic_placeholder") == 0) {
        return true;
    }
    uint32_t count = ts_node_named_child_count(args);
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(ts_node_type(ts_node_named_child(args, i)), "variadic_placeholder") == 0) {
            return true;
        }
    }
    return false;
}

// ObjectScript: resolve `var.Method(...)` / `..Property.Method(...)` instance
// calls against the per-method variable type map. Returns arena "Class.Method"
// or NULL if the receiver's type is unknown.
typedef struct {
    TSNode receiver;
    TSNode method;
    bool relative_property;
} objectscript_instance_parts_t;

static objectscript_instance_parts_t objectscript_instance_parts(TSNode node) {
    objectscript_instance_parts_t parts = {0};
    for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
        TSNode child = ts_node_named_child(node, i);
        const char *kind = ts_node_type(child);
        if (strcmp(kind, "lvn") == 0 || strcmp(kind, "variable") == 0) {
            parts.receiver = child;
        } else if (strcmp(kind, "relative_dot_property") == 0) {
            parts.receiver = child;
            parts.relative_property = true;
        } else if (strcmp(kind, "oref_method") == 0) {
            parts.method = child;
        }
    }
    return parts;
}

static char *objectscript_instance_method(CBMArena *a, TSNode oref, const char *source) {
    if (ts_node_is_null(oref)) {
        return NULL;
    }
    TSNode method_name = cbm_find_child_by_kind(oref, "method_name");
    TSNode identifier = ts_node_named_child_count(method_name) > 0
                            ? ts_node_named_child(method_name, 0)
                            : (TSNode){0};
    return ts_node_is_null(identifier) ? NULL : cbm_node_text(a, identifier, source);
}

static char *objectscript_instance_receiver(CBMArena *a, TSNode receiver, bool relative_property,
                                            const char *source) {
    if (!relative_property) {
        return cbm_node_text(a, receiver, source);
    }
    TSNode property = cbm_find_child_by_kind(receiver, "member_name");
    char *name = ts_node_is_null(property) ? NULL : cbm_node_text(a, property, source);
    return name && name[0] ? cbm_arena_sprintf(a, "..%s", name)
                           : cbm_node_text(a, receiver, source);
}

static const char *objectscript_type_class(const os_type_map_t *type_map, const char *variable) {
    for (int i = 0; i < type_map->count; i++) {
        if (strcasecmp(type_map->entries[i].var_name, variable) == 0) {
            return type_map->entries[i].class_name;
        }
    }
    return NULL;
}

static char *resolve_objectscript_instance_call(CBMArena *a, TSNode node, const char *source,
                                                os_type_map_t *type_map) {
    objectscript_instance_parts_t parts = objectscript_instance_parts(node);
    if (ts_node_is_null(parts.method) || ts_node_is_null(parts.receiver)) {
        return NULL;
    }
    char *method = objectscript_instance_method(a, parts.method, source);
    if (!method || !method[0]) {
        return NULL;
    }
    char *var_text =
        objectscript_instance_receiver(a, parts.receiver, parts.relative_property, source);
    if (!var_text || !var_text[0]) {
        return NULL;
    }
    const char *class_name = objectscript_type_class(type_map, var_text);
    return class_name ? cbm_arena_sprintf(a, "%s.%s", class_name, method) : NULL;
}

static bool is_objectscript_language(CBMLanguage language) {
    return language == CBM_LANG_OBJECTSCRIPT_UDL || language == CBM_LANG_OBJECTSCRIPT_ROUTINE;
}

static const char *resolve_objectscript_relative_method(CBMExtractCtx *ctx, TSNode node,
                                                        const WalkState *state) {
    if (!state->enclosing_class_qn || !state->enclosing_class_qn[0]) {
        return NULL;
    }
    TSNode oref = cbm_find_child_by_kind(node, "oref_method");
    char *method = objectscript_instance_method(ctx->arena, oref, ctx->source);
    return method && method[0]
               ? cbm_arena_sprintf(ctx->arena, "%s.%s", state->enclosing_class_qn, method)
               : NULL;
}

static const char *resolve_objectscript_macro(CBMExtractCtx *ctx, const char *callee) {
    if (!callee || strncmp(callee, "$$$", CBM_CALL_MACRO_SIGIL_LENGTH) != 0 || !ctx->macro_table) {
        return callee;
    }
    const CBMMacroEntry *entry =
        cbm_macro_table_find(ctx->macro_table, callee + CBM_CALL_MACRO_SIGIL_LENGTH);
    if (!entry) {
        return callee;
    }
    if (entry->resolved_callee) {
        return cbm_arena_strdup(ctx->arena, entry->resolved_callee);
    }
    return entry->expansion ? cbm_macro_extract_callee(ctx->arena, entry->expansion) : NULL;
}

// Preserve ObjectScript's grammar/type-map resolution while feeding the
// invocation descriptor used by the exact callee-usage suppression pass.
static const char *resolve_objectscript_callee(CBMExtractCtx *ctx, TSNode node, WalkState *state,
                                               const char *callee) {
    if (!is_objectscript_language(ctx->language)) {
        return callee;
    }

    const char *kind = ts_node_type(node);
    if ((!callee || !callee[0]) && strcmp(kind, "method_call") == 0) {
        callee =
            resolve_objectscript_instance_call(ctx->arena, node, ctx->source, &state->os_type_map);
    }

    if ((!callee || !callee[0]) && strcmp(kind, "relative_dot_method") == 0) {
        callee = resolve_objectscript_relative_method(ctx, node, state);
    }

    return resolve_objectscript_macro(ctx, callee);
}

static TSNode objectscript_call_args(TSNode node) {
    TSNode oref = cbm_find_child_by_kind(node, "oref_method");
    if (!ts_node_is_null(oref)) {
        TSNode args = cbm_find_child_by_kind(oref, "method_args");
        if (!ts_node_is_null(args)) {
            return args;
        }
    }

    TSNode args = cbm_find_child_by_kind(node, "method_args");
    if (!ts_node_is_null(args)) {
        return args;
    }

    /* A macro's optional arguments live below macro_function rather than as a
     * direct child of macro. Keep them as call arguments/data-flow inputs; the
     * macro name is an unnamed token and is handled separately. */
    TSNode macro_function = cbm_find_child_by_kind(node, "macro_function");
    return ts_node_is_null(macro_function) ? (TSNode){0}
                                           : cbm_find_child_by_kind(macro_function, "method_args");
}

static bool node_has_token(TSNode node, const char *token) {
    uint32_t count = ts_node_child_count(node);
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(ts_node_type(ts_node_child(node, i)), token) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_callable_reference_value(CBMLanguage language, TSNode node) {
    const char *kind = ts_node_type(node);
    if (language == CBM_LANG_JAVA && strcmp(kind, "method_reference") == 0) {
        return true;
    }
    if (language == CBM_LANG_KOTLIN && strcmp(kind, "callable_reference") == 0) {
        // `Type::class` shares the callable-reference grammar node but denotes
        // a class literal, not a reference to executable code.
        return !node_has_token(node, "class");
    }
    return language == CBM_LANG_PHP && php_is_first_class_callable(node);
}

static TSNode first_present_field(TSNode node, const char *const *fields) {
    for (const char *const *field = fields; *field; field++) {
        TSNode child = ts_node_child_by_field_name(node, *field, (uint32_t)strlen(*field));
        if (!ts_node_is_null(child)) {
            return child;
        }
    }
    return (TSNode){0};
}

static bool is_constructor_kind(const char *kind) {
    return strcmp(kind, "new_expression") == 0 || strcmp(kind, "object_creation_expression") == 0 ||
           strcmp(kind, "instance_expression") == 0 || strcmp(kind, "constructor_expression") == 0;
}

static bool is_dynamic_callee_expr(const CBMExtractCtx *ctx, TSNode expr) {
    if (ts_node_is_null(expr)) {
        return false;
    }
    const char *kind = ts_node_type(expr);
    if (strstr(kind, "subscript") || strstr(kind, "element_access") ||
        strstr(kind, "index_expression") || strstr(kind, "computed")) {
        return true;
    }

    // JS/TS use member_expression for both `obj.method` and `obj[key]`.
    // A bracketed property is an evaluated value, not a static terminal name.
    static const char *const terminal_fields[] = {"property", "field",  "attribute",
                                                  "name",     "method", NULL};
    TSNode terminal = first_present_field(expr, terminal_fields);
    if (!ts_node_is_null(terminal)) {
        uint32_t start = ts_node_start_byte(terminal);
        uint32_t expr_start = ts_node_start_byte(expr);
        while (start > expr_start &&
               isspace((unsigned char)ctx->source[start - CBM_CALL_PREVIOUS_INDEX_OFFSET])) {
            start--;
        }
        if (start > expr_start && ctx->source[start - CBM_CALL_PREVIOUS_INDEX_OFFSET] == '[') {
            return true;
        }
    }
    return false;
}

static TSNode primary_callee_expr(TSNode node) {
    const char *kind = ts_node_type(node);
    if (is_constructor_kind(kind)) {
        static const char *const constructor_fields[] = {"constructor", "type", "name", NULL};
        TSNode constructor = first_present_field(node, constructor_fields);
        if (!ts_node_is_null(constructor)) {
            return constructor;
        }
    }

    static const char *const callee_fields[] = {"function", "name",       "method", "target",
                                                "macro",    "subroutine", NULL};
    TSNode callee = first_present_field(node, callee_fields);
    if (!ts_node_is_null(callee)) {
        return callee;
    }
    if (ts_node_named_child_count(node) > 0) {
        return ts_node_named_child(node, 0);
    }
    return (TSNode){0};
}

static TSNode terminal_callee_leaf(const CBMExtractCtx *ctx, TSNode expr) {
    static const char *const terminal_fields[] = {"property", "field", "attribute",
                                                  "method",   "name",  NULL};
    for (int depth = 0; depth < CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH; depth++) {
        if (ts_node_is_null(expr) || is_dynamic_callee_expr(ctx, expr)) {
            return (TSNode){0};
        }
        TSNode terminal = first_present_field(expr, terminal_fields);
        if (!ts_node_is_null(terminal)) {
            expr = terminal;
            continue;
        }
        const char *kind = ts_node_type(expr);
        if (strcmp(kind, "identifier") == 0 || strcmp(kind, "simple_identifier") == 0 ||
            strcmp(kind, "type_identifier") == 0 || strcmp(kind, "field_identifier") == 0 ||
            strcmp(kind, "property_identifier") == 0 || strcmp(kind, "name") == 0 ||
            strcmp(kind, "variable_name") == 0 || strcmp(kind, "attribute") == 0 ||
            strcmp(kind, "symbol") == 0 || strcmp(kind, "sym_lit") == 0 ||
            strcmp(kind, "user_symbol") == 0) {
            return expr;
        }
        uint32_t count = ts_node_named_child_count(expr);
        if (count == 0) {
            return (TSNode){0};
        }
        bool terminal_is_last = strstr(kind, "qualified") || strstr(kind, "scoped") ||
                                strstr(kind, "member") || strstr(kind, "selector") ||
                                strstr(kind, "navigation") || strstr(kind, "field_expression");
        expr = ts_node_named_child(expr,
                                   terminal_is_last ? count - CBM_CALL_PREVIOUS_INDEX_OFFSET : 0);
    }
    return (TSNode){0};
}

typedef struct {
    const char *name;
    TSNode expr;
    TSNode leaf;
} CBMPrimaryCalleeSelection;

static bool node_kind_is_one_of(TSNode node, const char *const *kinds) {
    const char *kind = ts_node_type(node);
    for (const char *const *candidate = kinds; *candidate; candidate++) {
        if (strcmp(kind, *candidate) == 0) {
            return true;
        }
    }
    return false;
}

typedef struct {
    TSNode node;
    int remaining_depth;
    bool examine_after_children;
} callee_descendant_frame_t;

static bool callee_descendant_push(callee_descendant_frame_t **frames, size_t *count,
                                   size_t *capacity, callee_descendant_frame_t frame) {
    if (*count == *capacity) {
        size_t next_capacity = *capacity * PAIR_LEN;
        callee_descendant_frame_t *grown = realloc(*frames, next_capacity * sizeof(*grown));
        if (!grown) {
            return false;
        }
        *frames = grown;
        *capacity = next_capacity;
    }
    (*frames)[(*count)++] = frame;
    return true;
}

static TSNode first_named_descendant_of_kind(TSNode node, const char *const *kinds,
                                             int remaining_depth) {
    size_t capacity = CBM_SZ_16;
    size_t count = 0;
    callee_descendant_frame_t *frames = calloc(capacity, sizeof(*frames));
    if (!frames ||
        !callee_descendant_push(&frames, &count, &capacity,
                                (callee_descendant_frame_t){node, remaining_depth, false})) {
        free(frames);
        return (TSNode){0};
    }
    while (count > 0) {
        callee_descendant_frame_t frame = frames[--count];
        if (ts_node_is_null(frame.node) || frame.remaining_depth < 0) {
            continue;
        }
        if (node_kind_is_one_of(frame.node, kinds)) {
            free(frames);
            return frame.node;
        }
        uint32_t child_count = ts_node_named_child_count(frame.node);
        for (uint32_t i = child_count; i > 0; i--) {
            if (!callee_descendant_push(
                    &frames, &count, &capacity,
                    (callee_descendant_frame_t){
                        ts_node_named_child(frame.node, i - CBM_CALL_PREVIOUS_INDEX_OFFSET),
                        frame.remaining_depth - CBM_CALL_PREVIOUS_INDEX_OFFSET, false})) {
                free(frames);
                return (TSNode){0};
            }
        }
    }
    free(frames);
    return (TSNode){0};
}

static TSNode last_named_descendant_of_kind(TSNode node, const char *const *kinds,
                                            int remaining_depth) {
    size_t capacity = CBM_SZ_16;
    size_t count = 0;
    callee_descendant_frame_t *frames = calloc(capacity, sizeof(*frames));
    if (!frames ||
        !callee_descendant_push(&frames, &count, &capacity,
                                (callee_descendant_frame_t){node, remaining_depth, false})) {
        free(frames);
        return (TSNode){0};
    }
    while (count > 0) {
        callee_descendant_frame_t frame = frames[--count];
        if (ts_node_is_null(frame.node) || frame.remaining_depth < 0) {
            continue;
        }
        if (frame.examine_after_children) {
            if (node_kind_is_one_of(frame.node, kinds)) {
                free(frames);
                return frame.node;
            }
            continue;
        }
        if (!callee_descendant_push(
                &frames, &count, &capacity,
                (callee_descendant_frame_t){frame.node, frame.remaining_depth, true})) {
            free(frames);
            return (TSNode){0};
        }
        uint32_t child_count = ts_node_named_child_count(frame.node);
        for (uint32_t i = 0; i < child_count; i++) {
            if (!callee_descendant_push(&frames, &count, &capacity,
                                        (callee_descendant_frame_t){
                                            ts_node_named_child(frame.node, i),
                                            frame.remaining_depth - CBM_CALL_PREVIOUS_INDEX_OFFSET,
                                            false})) {
                free(frames);
                return (TSNode){0};
            }
        }
    }
    free(frames);
    return (TSNode){0};
}

/* ObjectScript call nodes do not expose generic `function`/`name` fields. Keep
 * the descriptor on the grammar-proven callee occurrence instead of falling
 * back to the first named child (which is a receiver for method_call and an
 * argument container for macro). The macro spelling itself is unnamed, so it
 * intentionally has no named callee occurrence to consume. */
static TSNode objectscript_callee_expr(TSNode node) {
    const char *kind = ts_node_type(node);

    if (strcmp(kind, "class_method_call") == 0) {
        return cbm_find_child_by_kind(node, "method_name");
    }
    if (strcmp(kind, "method_call") == 0 || strcmp(kind, "relative_dot_method") == 0) {
        TSNode oref = cbm_find_child_by_kind(node, "oref_method");
        return ts_node_is_null(oref) ? (TSNode){0} : cbm_find_child_by_kind(oref, "method_name");
    }
    if (strcmp(kind, "extrinsic_function") == 0 || strcmp(kind, "routine_tag_call") == 0) {
        return cbm_find_child_by_kind(node, "line_ref");
    }
    return (TSNode){0};
}

static TSNode objectscript_callee_leaf(TSNode expr) {
    if (ts_node_is_null(expr)) {
        return (TSNode){0};
    }
    const char *kind = ts_node_type(expr);
    if (strcmp(kind, "method_name") == 0 && ts_node_named_child_count(expr) > 0) {
        return ts_node_named_child(expr, 0);
    }
    if (strcmp(kind, "line_ref") == 0) {
        static const char *const identifier_kinds[] = {"objectscript_identifier",
                                                       "objectscript_identifier_special", NULL};
        return first_named_descendant_of_kind(expr, identifier_kinds,
                                              CBM_CALL_OBJECTSCRIPT_IDENTIFIER_DEPTH);
    }
    return (TSNode){0};
}

static TSNode dart_callee_expr(TSNode node) {
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "new_expression") == 0) {
        return primary_callee_expr(node);
    }
    if (strcmp(kind, "selector") != 0) {
        return primary_callee_expr(node);
    }
    TSNode previous = ts_node_prev_named_sibling(node);
    return !ts_node_is_null(previous) && strcmp(ts_node_type(previous), "identifier") == 0
               ? previous
               : (TSNode){0};
}

static TSNode vhdl_callee_expr(TSNode node) {
    if (strcmp(ts_node_type(node), "parenthesis_group") != 0) {
        return primary_callee_expr(node);
    }
    static const char *const callable_kinds[] = {"library_function", "identifier", "name",
                                                 "simple_name", NULL};
    TSNode previous = ts_node_prev_named_sibling(node);
    return node_kind_is_one_of(previous, callable_kinds) ? previous : (TSNode){0};
}

static TSNode nasm_callee_expr(TSNode node) {
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "call_syntax_expression") == 0) {
        return ts_node_child_by_field_name(node, TS_FIELD("base"));
    }
    if (strcmp(kind, "actual_instruction") != 0) {
        return primary_callee_expr(node);
    }
    TSNode operands = ts_node_child_by_field_name(node, TS_FIELD("operands"));
    return !ts_node_is_null(operands) && ts_node_named_child_count(operands) > 0
               ? ts_node_named_child(operands, 0)
               : (TSNode){0};
}

static TSNode ada_callee_expr(TSNode node) {
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "procedure_call_statement") != 0 && strcmp(kind, "function_call") != 0) {
        return primary_callee_expr(node);
    }
    TSNode name = ts_node_child_by_field_name(node, TS_FIELD("name"));
    if (!ts_node_is_null(name)) {
        return name;
    }
    TSNode head = ts_node_named_child_count(node) > 0 ? ts_node_named_child(node, 0) : (TSNode){0};
    const char *head_kind = ts_node_is_null(head) ? "" : ts_node_type(head);
    return strcmp(head_kind, "name") == 0 || strcmp(head_kind, "identifier") == 0 ? head
                                                                                  : (TSNode){0};
}

static TSNode makefile_callee_expr(TSNode node) {
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "shell_function") == 0) {
        return (TSNode){0};
    }
    if (strcmp(kind, "function_call") != 0) {
        return primary_callee_expr(node);
    }
    TSNode function = ts_node_child_by_field_name(node, TS_FIELD("function"));
    return ts_node_is_null(function) && ts_node_named_child_count(node) > 0
               ? ts_node_named_child(node, 0)
               : function;
}

static TSNode language_specific_callee_expr(CBMLanguage language, TSNode node) {
    switch (language) {
    case CBM_LANG_OBJECTSCRIPT_UDL:
    case CBM_LANG_OBJECTSCRIPT_ROUTINE:
        return objectscript_callee_expr(node);
    case CBM_LANG_SCALA:
        return strcmp(ts_node_type(node), "infix_expression") == 0
                   ? ts_node_child_by_field_name(node, TS_FIELD("operator"))
                   : primary_callee_expr(node);
    case CBM_LANG_DART:
        return dart_callee_expr(node);
    case CBM_LANG_VHDL:
        return vhdl_callee_expr(node);
    case CBM_LANG_CSS:
        return strcmp(ts_node_type(node), "call_expression") == 0
                   ? cbm_find_child_by_kind(node, "function_name")
                   : primary_callee_expr(node);
    case CBM_LANG_NASM:
        return nasm_callee_expr(node);
    case CBM_LANG_LLVM_IR:
        return ts_node_child_by_field_name(node, TS_FIELD("callee"));
    case CBM_LANG_AGDA:
        return strcmp(ts_node_type(node), "expr") == 0 ? agda_application_head_atom(node)
                                                       : primary_callee_expr(node);
    case CBM_LANG_ADA:
        return ada_callee_expr(node);
    case CBM_LANG_MAKEFILE:
        return makefile_callee_expr(node);
    case CBM_LANG_JUST:
        return strcmp(ts_node_type(node), "dependency") == 0 ? (TSNode){0}
                                                             : primary_callee_expr(node);
    case CBM_LANG_PUPPET:
        return strcmp(ts_node_type(node), "include_statement") == 0 ? (TSNode){0}
                                                                    : primary_callee_expr(node);
    default:
        return primary_callee_expr(node);
    }
}

static TSNode language_specific_callee_leaf(CBMLanguage language, TSNode expr,
                                            const CBMExtractCtx *ctx) {
    if (ts_node_is_null(expr)) {
        return (TSNode){0};
    }

    if (language == CBM_LANG_LLVM_IR) {
        static const char *const llvm_leaf_kinds[] = {"global_var", "local_var", NULL};
        return first_named_descendant_of_kind(expr, llvm_leaf_kinds,
                                              CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH);
    }
    if (is_objectscript_language(language)) {
        return objectscript_callee_leaf(expr);
    }
    if (language == CBM_LANG_CSS && strcmp(ts_node_type(expr), "function_name") == 0) {
        return expr;
    }
    if (language == CBM_LANG_NASM) {
        static const char *const nasm_leaf_kinds[] = {"word", NULL};
        return first_named_descendant_of_kind(expr, nasm_leaf_kinds,
                                              CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH);
    }
    if (language == CBM_LANG_AGDA) {
        return agda_head_qid(expr);
    }
    if (language == CBM_LANG_ELM) {
        static const char *const elm_leaf_kinds[] = {"lower_case_identifier", NULL};
        return first_named_descendant_of_kind(expr, elm_leaf_kinds,
                                              CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH);
    }
    if (language == CBM_LANG_PURESCRIPT) {
        static const char *const purescript_leaf_kinds[] = {"variable", NULL};
        return first_named_descendant_of_kind(expr, purescript_leaf_kinds,
                                              CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH);
    }
    if (language == CBM_LANG_NICKEL) {
        static const char *const nickel_leaf_kinds[] = {"ident", NULL};
        return first_named_descendant_of_kind(expr, nickel_leaf_kinds,
                                              CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH);
    }
    if (language == CBM_LANG_ADA) {
        static const char *const ada_leaf_kinds[] = {"identifier", "simple_identifier", NULL};
        TSNode leaf = last_named_descendant_of_kind(expr, ada_leaf_kinds,
                                                    CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH);
        if (!ts_node_is_null(leaf)) {
            return leaf;
        }
    }
    if (language == CBM_LANG_VHDL) {
        static const char *const vhdl_leaf_kinds[] = {"identifier", "simple_identifier", NULL};
        TSNode leaf = last_named_descendant_of_kind(expr, vhdl_leaf_kinds,
                                                    CBM_CALL_MAX_IDENTIFIER_DESCENT_DEPTH);
        if (!ts_node_is_null(leaf)) {
            return leaf;
        }
    }
    return terminal_callee_leaf(ctx, expr);
}

// Produce the textual callee and the AST occurrence from one operation. The
// generic fallback retains the former field/terminal behavior, while grammars
// whose extractor uses a sibling, a special field, or a synthetic literal are
// selected explicitly above. This prevents the descriptor from independently
// guessing that the first named child is the callee (often an argument).
static CBMPrimaryCalleeSelection select_primary_callee(CBMExtractCtx *ctx, TSNode node,
                                                       WalkState *state) {
    CBMPrimaryCalleeSelection selection = {0};
    selection.name = extract_callee_name(ctx->arena, node, ctx->source, ctx->language);
    selection.name = resolve_objectscript_callee(ctx, node, state, selection.name);
    if (!selection.name || !selection.name[0]) {
        return selection;
    }

    const char *site_kind = ts_node_type(node);
    bool scala_named_infix =
        ctx->language == CBM_LANG_SCALA && strcmp(site_kind, "infix_expression") == 0;
    if (!scala_named_infix && (strstr(site_kind, "binary") || strstr(site_kind, "infix"))) {
        return selection;
    }

    selection.expr = language_specific_callee_expr(ctx->language, node);
    if (is_dynamic_callee_expr(ctx, selection.expr)) {
        selection.expr = (TSNode){0};
        return selection;
    }
    selection.leaf = language_specific_callee_leaf(ctx->language, selection.expr, ctx);
    return selection;
}

static bool primary_callee_name_is_allowed(const CBMExtractCtx *ctx,
                                           const CBMPrimaryCalleeSelection *callee) {
    if (!callee->name || !callee->name[0]) {
        return false;
    }
    if (!cbm_is_keyword(callee->name, ctx->language) ||
        cbm_is_resolvable_builtin(callee->name, ctx->language)) {
        return true;
    }
    /* CSS function names occupy a grammar-proven callable role. Generic keyword
     * vocabulary includes `var`, but that must not erase `var(...)`. */
    return ctx->language == CBM_LANG_CSS && !ts_node_is_null(callee->expr) &&
           strcmp(ts_node_type(callee->expr), "function_name") == 0;
}

static bool php_callable_reference_has_dynamic_member_name(TSNode call, TSNode callee_expr) {
    if (ts_node_is_null(callee_expr)) {
        return false;
    }

    const char *call_kind = ts_node_type(call);
    if (strcmp(call_kind, "member_call_expression") != 0 &&
        strcmp(call_kind, "nullsafe_member_call_expression") != 0 &&
        strcmp(call_kind, "scoped_call_expression") != 0) {
        return false;
    }

    const char *callee_kind = ts_node_type(callee_expr);
    return strcmp(callee_kind, "variable_name") == 0 ||
           strcmp(callee_kind, "dynamic_variable_name") == 0;
}

/* A callable-reference token inside a branch expression names a possible value,
 * not one statically selected value at that occurrence. Do not consume its leaf
 * as explicit CALL_REFERENCE syntax; the usage walker will retain each named
 * alternative as ordinary USAGE. */
static bool callable_reference_is_branch_alternative(TSNode reference) {
    for (TSNode parent = ts_node_parent(reference); !ts_node_is_null(parent);
         parent = ts_node_parent(parent)) {
        const char *kind = ts_node_type(parent);
        if (strcmp(kind, "ternary_expression") == 0 ||
            strcmp(kind, "conditional_expression") == 0 || strcmp(kind, "if_expression") == 0) {
            return true;
        }
        if (strcmp(kind, "arguments") == 0 || strcmp(kind, "argument_list") == 0 ||
            strcmp(kind, "assignment_expression") == 0 || strcmp(kind, "assignment") == 0 ||
            strcmp(kind, "variable_declarator") == 0) {
            return false;
        }
    }
    return false;
}

static CBMInvocationDescriptor describe_callable_reference(CBMExtractCtx *ctx, TSNode node) {
    CBMInvocationDescriptor descriptor = {0};
    descriptor.kind = CBM_INVOCATION_CALLABLE_REFERENCE;
    descriptor.site = node;

    if (callable_reference_is_branch_alternative(node)) {
        return descriptor;
    }

    uint32_t count = ts_node_named_child_count(node);
    if (ctx->language == CBM_LANG_JAVA && count > 0) {
        // In `Type::new`, `new` is an unnamed token, so the referenced
        // constructor is represented by the left-hand type. For ordinary
        // method references, the final named child is the referenced method.
        descriptor.callee_expr = ts_node_named_child(
            node, node_has_token(node, "new") ? 0 : count - CBM_CALL_PREVIOUS_INDEX_OFFSET);
    } else if (ctx->language == CBM_LANG_KOTLIN && count > 0) {
        descriptor.callee_expr = ts_node_named_child(node, count - CBM_CALL_PREVIOUS_INDEX_OFFSET);
    } else if (ctx->language == CBM_LANG_PHP) {
        descriptor.callee_expr = primary_callee_expr(node);
        /* `$obj->$method(...)` and its nullsafe/static equivalents evaluate the
         * member-name variable; the syntax alone does not prove a callable
         * target. Leave the terminal unconsumed so the usage pass records it as
         * an ordinary value instead of a CALL_REFERENCE. A bare typed
         * `$handler(...)` remains eligible for PHP-LSP `__invoke` resolution. */
        if (php_callable_reference_has_dynamic_member_name(node, descriptor.callee_expr)) {
            descriptor.callee_expr = (TSNode){0};
            return descriptor;
        }
    }

    if (is_dynamic_callee_expr(ctx, descriptor.callee_expr)) {
        descriptor.callee_expr = (TSNode){0};
        return descriptor;
    }
    descriptor.callee_leaf = terminal_callee_leaf(ctx, descriptor.callee_expr);
    TSNode name_node =
        !ts_node_is_null(descriptor.callee_leaf) ? descriptor.callee_leaf : descriptor.callee_expr;
    if (!ts_node_is_null(name_node)) {
        descriptor.callee_name = cbm_node_text(ctx->arena, name_node, ctx->source);
    }
    return descriptor;
}

static CBMInvocationDescriptor describe_emitted_primary_call(
    TSNode node, const CBMPrimaryCalleeSelection *callee) {
    CBMInvocationDescriptor descriptor = {0};
    descriptor.kind = CBM_INVOCATION_PRIMARY;
    descriptor.site = node;
    descriptor.callee_name = callee->name;
    descriptor.raw_call_emitted = true;
    descriptor.callee_expr = callee->expr;
    descriptor.callee_leaf = callee->leaf;
    return descriptor;
}

static bool is_primary_call_node(const CBMLangSpec *spec, TSNode node) {
    return spec->call_node_types && spec->call_node_types[0] &&
           cbm_kind_in_set(node, spec->call_node_types);
}

static CBMCall make_primary_call(const CBMPrimaryCalleeSelection *callee, TSNode node,
                                 const WalkState *state) {
    CBMCall call = {0};
    call.callee_name = callee->name;
    call.enclosing_func_qn = state->enclosing_func_qn;
    call.loop_depth = state->loop_depth;
    call.branch_depth = state->branch_depth;
    call.start_line = (int)ts_node_start_point(node).row + TS_LINE_OFFSET;
    call.site_start_byte = ts_node_start_byte(node);
    call.site_end_byte = ts_node_end_byte(node);
    return call;
}

static bool is_javascript_member_call(CBMExtractCtx *ctx, TSNode node) {
    if ((ctx->language != CBM_LANG_JAVASCRIPT && ctx->language != CBM_LANG_TYPESCRIPT &&
         ctx->language != CBM_LANG_TSX) ||
        strcmp(ts_node_type(node), "call_expression") != 0) {
        return false;
    }
    TSNode function = ts_node_child_by_field_name(node, TS_FIELD("function"));
    if (ts_node_is_null(function) || strcmp(ts_node_type(function), "member_expression") != 0) {
        return false;
    }
    TSNode object = ts_node_child_by_field_name(function, TS_FIELD("object"));
    if (ts_node_is_null(object)) {
        return false;
    }
    const char *object_kind = ts_node_type(object);
    return strcmp(object_kind, "this") != 0 && strcmp(object_kind, "super") != 0;
}

static void mark_method_call(CBMExtractCtx *ctx, TSNode node, CBMCall *call) {
    if (ctx->language == CBM_LANG_PERL &&
        strcmp(ts_node_type(node), "method_call_expression") == 0) {
        call->is_method = true;
    }
    if (is_javascript_member_call(ctx, node)) {
        call->is_method = true;
    }
}

static void prepend_php_group_prefix(CBMExtractCtx *ctx, TSNode node, CBMCall *call) {
    if (ctx->language != CBM_LANG_PHP || !call->first_string_arg ||
        call->first_string_arg[0] != '/' || !call->callee_name ||
        cbm_service_pattern_route_method(call->callee_name) == NULL) {
        return;
    }
    const char *prefix = php_group_prefix_for_call(ctx->arena, node, ctx->source);
    if (!prefix || !prefix[0]) {
        return;
    }
    const char *relative = call->first_string_arg;
    while (*relative == '/') {
        relative++;
    }
    call->first_string_arg = relative[0] ? cbm_arena_sprintf(ctx->arena, "%s/%s", prefix, relative)
                                         : cbm_arena_strndup(ctx->arena, prefix, strlen(prefix));
}

static void extract_objectscript_call_args(CBMExtractCtx *ctx, TSNode args, CBMCall *call) {
    uint32_t count = ts_node_named_child_count(args);
    for (uint32_t index = 0; index < count && call->arg_count < CBM_MAX_CALL_ARGS; index++) {
        TSNode argument = ts_node_named_child(args, index);
        if (strcmp(ts_node_type(argument), "method_arg") != 0) {
            continue;
        }
        CBMCallArg *call_arg = &call->args[call->arg_count];
        memset(call_arg, 0, sizeof(*call_arg));
        call_arg->index = call->arg_count;
        call_arg->expr = cbm_node_text(ctx->arena, argument, ctx->source);
        if (call_arg->expr && call_arg->expr[0]) {
            call->arg_count++;
        }
    }
}

static TSNode extract_primary_call_args(CBMExtractCtx *ctx, TSNode node, CBMCall *call) {
    TSNode args = ts_node_child_by_field_name(node, TS_FIELD("arguments"));
    if (ts_node_is_null(args) && is_objectscript_language(ctx->language)) {
        args = objectscript_call_args(node);
    }
    if (ts_node_is_null(args)) {
        return args;
    }
    call->first_string_arg = extract_url_or_topic_arg(ctx, args);
    prepend_php_group_prefix(ctx, node, call);
    if (call->first_string_arg && call->first_string_arg[0] == '/') {
        call->second_arg_name = extract_handler_arg(ctx, args);
    }
    if (is_objectscript_language(ctx->language)) {
        extract_objectscript_call_args(ctx, args, call);
    } else {
        extract_call_args(ctx, args, call);
    }
    return args;
}

static void emit_string_dispatch_call(CBMExtractCtx *ctx, TSNode args, const CBMCall *call) {
    const char **suffixes = cbm_string_dispatch_suffixes(ctx->language);
    if (!suffixes || ts_node_is_null(args) || !call->callee_name) {
        return;
    }
    size_t callee_length = strlen(call->callee_name);
    for (const char **suffix = suffixes; *suffix; suffix++) {
        size_t suffix_length = strlen(*suffix);
        if (callee_length < suffix_length ||
            strcmp(call->callee_name + callee_length - suffix_length, *suffix) != 0) {
            continue;
        }
        const char *class_name = extract_nth_string_arg(ctx, args, 0);
        const char *method_name = extract_nth_string_arg(ctx, args, CBM_AST_SECOND_CHILD_INDEX);
        if (class_name && method_name) {
            CBMCall dispatch_call = {0};
            dispatch_call.callee_name =
                cbm_arena_sprintf(ctx->arena, "%s.%s", class_name, method_name);
            dispatch_call.enclosing_func_qn = call->enclosing_func_qn;
            dispatch_call.site_start_byte = call->site_start_byte;
            dispatch_call.site_end_byte = call->site_end_byte;
            cbm_calls_push(&ctx->result->calls, ctx->arena, dispatch_call);
        }
        return;
    }
}

static CBMInvocationDescriptor handle_primary_call(CBMExtractCtx *ctx, TSNode node,
                                                   const CBMLangSpec *spec, WalkState *state) {
    CBMInvocationDescriptor invocation = {0};
    if (!is_primary_call_node(spec, node)) {
        return invocation;
    }
    CBMPrimaryCalleeSelection callee = select_primary_callee(ctx, node, state);
    if (!primary_callee_name_is_allowed(ctx, &callee)) {
        return invocation;
    }
    CBMCall call = make_primary_call(&callee, node, state);
    mark_method_call(ctx, node, &call);
    TSNode args = extract_primary_call_args(ctx, node, &call);
    cbm_calls_push(&ctx->result->calls, ctx->arena, call);
    emit_string_dispatch_call(ctx, args, &call);
    return describe_emitted_primary_call(node, &callee);
}

static void extract_language_implicit_calls(CBMExtractCtx *ctx, TSNode node, WalkState *state) {
    const char *kind = ts_node_type(node);
    switch (ctx->language) {
    case CBM_LANG_TSX:
    case CBM_LANG_JAVASCRIPT:
        extract_jsx_component_ref(ctx, node, kind, state->enclosing_func_qn);
        break;
    case CBM_LANG_KOTLIN:
        extract_kotlin_operator_call(ctx, node, kind, state->enclosing_func_qn);
        extract_kotlin_desugared_calls(ctx, node, kind, state->enclosing_func_qn);
        break;
    case CBM_LANG_CPP:
    case CBM_LANG_CUDA:
        extract_cpp_operator_call(ctx, node, kind, state->enclosing_func_qn);
        extract_cpp_implicit_calls(ctx, node, kind, state->enclosing_func_qn);
        break;
    default:
        break;
    }
}

CBMInvocationDescriptor handle_calls(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                                     WalkState *state) {
    bool callable_reference = is_callable_reference_value(ctx->language, node);
    CBMInvocationDescriptor invocation = callable_reference
                                             ? describe_callable_reference(ctx, node)
                                             : handle_primary_call(ctx, node, spec, state);
    extract_language_implicit_calls(ctx, node, state);
    return invocation;
}
