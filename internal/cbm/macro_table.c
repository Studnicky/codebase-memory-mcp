#include "macro_table.h"
#include "arena.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

enum {
    CBM_MACRO_DEFINE_DIRECTIVE_LENGTH = 7,
    CBM_MACRO_DEFINE_CONTENT_OFFSET = 8,
    CBM_MACRO_NAME_CAPACITY = 256,
    CBM_MACRO_VARIABLE_PARAM_COUNT = -1,
    CBM_MACRO_PARAM_NAME_CAPACITY = 64,
    CBM_MACRO_PARAM_NAME_MAX_LENGTH = CBM_MACRO_PARAM_NAME_CAPACITY - 1,
    CBM_MACRO_EXPANSION_CAPACITY = 1024,
    CBM_MACRO_CLASS_PREFIX_LENGTH = 8,
    CBM_MACRO_ROUTINE_PREFIX_LENGTH = 2,
    CBM_MACRO_FIRST_STOP_INDEX = 0,
    CBM_MACRO_SECOND_STOP_INDEX = 1,
};

static const struct {
    const char *name;
    int param_count;
    const char *callee;
} SYSTEM_MACROS[] = {{"OK", 0, NULL},
                     {"ISERR", 1, "%SYSTEM.Status.IsError"},
                     {"ISOK", 1, "%SYSTEM.Status.IsOK"},
                     {"GETERRORTEXT", 1, "%SYSTEM.Status.GetErrorText"},
                     {"ADDSC", 2, "%SYSTEM.Status.AppendStatus"},
                     {"ThrowStatus", 1, "%SYSTEM.Status.ThrowStatus"},
                     {"ThrowOnError", 1, "%SYSTEM.Status.ThrowStatus"},
                     {"ERROR", 2, "%SYSTEM.Status.Error"},
                     {"NULLOREF", 0, NULL},
                     {"LISTBUILD", -1, NULL},
                     {"LISTGET", 2, NULL},
                     {"LISTNEXT", 3, NULL},
                     {"LISTLENGTH", 1, NULL},
                     {"SORTBEGIN", 1, NULL},
                     {"SORTEND", 0, NULL},
                     {"AUDITSTART", 3, "%SYSTEM.Audit.Event"},
                     {"logoutput", 1, NULL},
                     {"objExists", 1, NULL},
                     {"traceStatus", 1, NULL},
                     {NULL, 0, NULL}};

void cbm_macro_table_free(CBMMacroTable *t) {
    if (!t) {
        return;
    }
    cbm_arena_destroy(&t->arena);
    free(t);
}

void cbm_macro_table_init_system(CBMMacroTable *t) {
    t->count = 0;
    for (int i = 0; SYSTEM_MACROS[i].name; i++) {
        if (t->count >= CBM_MACRO_TABLE_CAP) {
            break;
        }
        CBMMacroEntry *e = &t->entries[t->count++];
        e->name = SYSTEM_MACROS[i].name;
        e->param_count = SYSTEM_MACROS[i].param_count;
        e->expansion = NULL;
        e->resolved_callee = SYSTEM_MACROS[i].callee;
        for (int p = 0; p < CBM_MACRO_MAX_PARAMS; p++) {
            e->param_names[p] = NULL;
        }
    }
}

void cbm_macro_table_add(CBMMacroTable *t, CBMArena *arena, const char *name, int param_count,
                         const char **param_names, const char *expansion,
                         const char *resolved_callee) {
    if (t->count >= CBM_MACRO_TABLE_CAP || !name) {
        return;
    }
    for (int i = 0; i < t->count; i++) {
        if (strcasecmp(t->entries[i].name, name) == 0) {
            return;
        }
    }
    CBMMacroEntry *e = &t->entries[t->count++];
    e->name = cbm_arena_strdup(arena, name);
    e->param_count = param_count;
    e->expansion = expansion ? cbm_arena_strdup(arena, expansion) : NULL;
    e->resolved_callee = resolved_callee ? cbm_arena_strdup(arena, resolved_callee) : NULL;
    for (int p = 0; p < CBM_MACRO_MAX_PARAMS; p++) {
        e->param_names[p] =
            (param_names && p < param_count) ? cbm_arena_strdup(arena, param_names[p]) : NULL;
    }
}

const CBMMacroEntry *cbm_macro_table_find(const CBMMacroTable *t, const char *name) {
    if (!t || !name) {
        return NULL;
    }
    for (int i = 0; i < t->count; i++) {
        if (strcasecmp(t->entries[i].name, name) == 0) {
            return &t->entries[i];
        }
    }
    return NULL;
}

typedef struct {
    char name[CBM_MACRO_NAME_CAPACITY];
    int param_count;
    char param_names[CBM_MACRO_MAX_PARAMS][CBM_MACRO_PARAM_NAME_CAPACITY];
    const char *param_name_ptrs[CBM_MACRO_MAX_PARAMS];
} CBMMacroDefinition;

static const char *macro_skip_horizontal_space(const char *cursor) {
    while (*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    return cursor;
}

static bool macro_is_define(const char *line) {
    return strncmp(line, "#define", CBM_MACRO_DEFINE_DIRECTIVE_LENGTH) == 0 &&
           (line[CBM_MACRO_DEFINE_DIRECTIVE_LENGTH] == ' ' ||
            line[CBM_MACRO_DEFINE_DIRECTIVE_LENGTH] == '\t');
}

static bool macro_parse_name(const char **cursor, const char *end, CBMMacroDefinition *definition) {
    const char *start = *cursor;
    while (*cursor < end && **cursor && **cursor != '(' && **cursor != ' ' && **cursor != '\t') {
        (*cursor)++;
    }
    size_t length = (size_t)(*cursor - start);
    if (length == 0 || length >= sizeof(definition->name)) {
        return false;
    }
    memcpy(definition->name, start, length);
    definition->name[length] = '\0';
    return true;
}

static void macro_append_parameter(CBMMacroDefinition *definition, const char *start,
                                   size_t length) {
    while (length > 0 &&
           (start[length - sizeof(*start)] == ' ' || start[length - sizeof(*start)] == '\t')) {
        length--;
    }
    if (length == 0 || definition->param_count >= CBM_MACRO_MAX_PARAMS) {
        return;
    }
    size_t copied =
        length < CBM_MACRO_PARAM_NAME_MAX_LENGTH ? length : CBM_MACRO_PARAM_NAME_MAX_LENGTH;
    char *name = definition->param_names[definition->param_count];
    memcpy(name, start, copied);
    name[copied] = '\0';
    definition->param_name_ptrs[definition->param_count] = name;
    definition->param_count++;
}

static void macro_parse_parameters(const char **cursor, const char *end,
                                   CBMMacroDefinition *definition) {
    if (**cursor != '(') {
        definition->param_count = CBM_MACRO_VARIABLE_PARAM_COUNT;
        return;
    }
    definition->param_count = 0;
    (*cursor)++;
    while (*cursor < end && **cursor && **cursor != ')') {
        *cursor = macro_skip_horizontal_space(*cursor);
        if (*cursor >= end || **cursor == ')') {
            break;
        }
        const char *start = *cursor;
        while (*cursor < end && **cursor && **cursor != ',' && **cursor != ')') {
            (*cursor)++;
        }
        macro_append_parameter(definition, start, (size_t)(*cursor - start));
        if (**cursor == ',') {
            (*cursor)++;
        }
    }
    if (**cursor == ')') {
        (*cursor)++;
    }
}

static char *macro_parse_expansion(CBMArena *arena, const char **cursor, const char *end) {
    *cursor = macro_skip_horizontal_space(*cursor);
    size_t length = (size_t)(end - *cursor);
    while (length > 0 && ((*cursor)[length - sizeof(**cursor)] == '\r' ||
                          (*cursor)[length - sizeof(**cursor)] == ' ' ||
                          (*cursor)[length - sizeof(**cursor)] == '\t')) {
        length--;
    }
    return length > 0 ? cbm_arena_strndup(arena, *cursor, length) : NULL;
}

static void macro_parse_define(CBMMacroTable *table, CBMArena *arena, const char *line,
                               const char *end) {
    const char *cursor = macro_skip_horizontal_space(line);
    if (!macro_is_define(cursor)) {
        return;
    }
    cursor = macro_skip_horizontal_space(cursor + CBM_MACRO_DEFINE_CONTENT_OFFSET);
    CBMMacroDefinition definition = {0};
    if (!macro_parse_name(&cursor, end, &definition)) {
        return;
    }
    macro_parse_parameters(&cursor, end, &definition);
    char *expansion = macro_parse_expansion(arena, &cursor, end);
    const char **parameters = definition.param_count > 0 ? definition.param_name_ptrs : NULL;
    cbm_macro_table_add(table, arena, definition.name, definition.param_count, parameters,
                        expansion, NULL);
}

void cbm_parse_inc_file(CBMMacroTable *t, CBMArena *arena, const char *content) {
    if (!content) {
        return;
    }
    const char *line = content;
    while (*line) {
        const char *end = strchr(line, '\n');
        if (!end) {
            end = line + strlen(line);
        }
        macro_parse_define(t, arena, line, end);
        if (!*end) {
            break;
        }
        line = end + sizeof(*end);
    }
}

static bool macro_append(char *buffer, int *out, const char *text, size_t length) {
    size_t capacity = sizeof((char[CBM_MACRO_EXPANSION_CAPACITY]){0}) - sizeof(buffer[0]);
    if ((size_t)*out + length >= capacity) {
        return false;
    }
    memcpy(buffer + *out, text, length);
    *out += (int)length;
    return true;
}

static const char *macro_argument_at(const char **args, int index, int arg_count) {
    return args && index < arg_count ? args[index] : "";
}

static bool macro_expand_parameter(const CBMMacroEntry *entry, const char **args, int arg_count,
                                   const char **cursor, char *buffer, int *out) {
    for (int index = 0; index < entry->param_count && index < CBM_MACRO_MAX_PARAMS; index++) {
        const char *name = entry->param_names[index];
        if (!name) {
            continue;
        }
        size_t name_length = strlen(name);
        if (strncasecmp(*cursor, name, name_length) != 0) {
            continue;
        }
        const char *argument = macro_argument_at(args, index, arg_count);
        (void)macro_append(buffer, out, argument, strlen(argument));
        *cursor += name_length;
        return true;
    }
    return false;
}

char *cbm_macro_expand(CBMArena *arena, const CBMMacroEntry *entry, const char **args,
                       int arg_count) {
    if (!entry || !entry->expansion) {
        return NULL;
    }
    const char *tmpl = entry->expansion;
    char buf[CBM_MACRO_EXPANSION_CAPACITY];
    int out = 0;
    const char *p = tmpl;
    while (*p && out < (int)(sizeof(buf) - sizeof(buf[0]))) {
        if (*p != '%' || !macro_expand_parameter(entry, args, arg_count, &p, buf, &out)) {
            buf[out++] = *p++;
        }
    }
    buf[out] = '\0';
    return cbm_arena_strdup(arena, buf);
}

static const char *macro_symbol_end(const char *symbol, const char *stop) {
    while (*symbol && *symbol != stop[CBM_MACRO_FIRST_STOP_INDEX] &&
           *symbol != stop[CBM_MACRO_SECOND_STOP_INDEX]) {
        symbol++;
    }
    return symbol;
}

static char *macro_extract_class_callee(CBMArena *arena, const char *class_prefix) {
    const char *class_name = class_prefix + CBM_MACRO_CLASS_PREFIX_LENGTH;
    const char *class_end = strchr(class_name, ')');
    if (!class_end || class_end[sizeof(*class_end)] != '.') {
        return NULL;
    }
    const char *method_name = class_end + CBM_MACRO_ROUTINE_PREFIX_LENGTH;
    const char method_stops[] = {'(', ' ', '\0'};
    const char *method_end = macro_symbol_end(method_name, method_stops);
    int class_length = (int)(class_end - class_name);
    int method_length = (int)(method_end - method_name);
    if (class_length <= 0 || method_length <= 0) {
        return NULL;
    }
    return cbm_arena_sprintf(arena, "%.*s.%.*s", class_length, class_name, method_length,
                             method_name);
}

static char *macro_extract_routine_callee(CBMArena *arena, const char *routine_prefix) {
    if (!routine_prefix || routine_prefix[CBM_MACRO_ROUTINE_PREFIX_LENGTH] == '$') {
        return NULL;
    }
    const char *tag_name = routine_prefix + CBM_MACRO_ROUTINE_PREFIX_LENGTH;
    const char tag_stops[] = {'^', '(', ' ', '\0'};
    const char *tag_end = macro_symbol_end(tag_name, tag_stops);
    if (*tag_end != '^') {
        return NULL;
    }
    const char *routine_name = tag_end + sizeof(*tag_end);
    const char routine_stops[] = {'(', ' ', '\0'};
    const char *routine_end = macro_symbol_end(routine_name, routine_stops);
    int tag_length = (int)(tag_end - tag_name);
    int routine_length = (int)(routine_end - routine_name);
    if (tag_length <= 0 || routine_length <= 0) {
        return NULL;
    }
    return cbm_arena_sprintf(arena, "%.*s^%.*s", tag_length, tag_name, routine_length,
                             routine_name);
}

char *cbm_macro_extract_callee(CBMArena *arena, const char *expansion) {
    if (!expansion) {
        return NULL;
    }

    const char *class_prefix = strstr(expansion, "##class(");
    if (class_prefix) {
        return macro_extract_class_callee(arena, class_prefix);
    }
    return macro_extract_routine_callee(arena, strstr(expansion, "$$"));
}
