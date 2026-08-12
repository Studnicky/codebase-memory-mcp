/*
 * config_json_like.c — Structure-preserving edits for JSON, JSONC, and JSON5.
 *
 * This deliberately does not round-trip through a DOM. Agent configuration
 * files are user-owned and often contain comments or hand formatting, so the
 * parser validates the complete document and the editor changes only the
 * selected member bytes (plus an adjacent comma when required).
 */
#include "cli/config_json_like.h"

#include "foundation/compat.h"
#include "foundation/compat_fs.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include "foundation/win_utf8.h"

#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
#define JL_SYNC _commit
#define JL_PROCESS_ID _getpid
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define JL_SYNC fsync
#define JL_PROCESS_ID getpid
#endif

#define JL_MAX_DEPTH 64U
#define JL_MAX_KEY_BYTES 4096U
#define JL_MAX_FILE_BYTES ((size_t)16U * 1024U * 1024U)

enum {
    JL_STATUS_FAILURE = -1,
    JL_STATUS_NO_MATCH = 1,
    JL_BYTE_WIDTH = 1U,
    JL_TWO_BYTES = 2U,
    JL_THREE_BYTES = 3U,
    JL_FOUR_BYTES = 4U,
    JL_UNICODE_ESCAPE_BYTES = 6U,
    JL_BUFFER_INITIAL_CAPACITY = 128U,
    JL_BUFFER_GROWTH_FACTOR = JL_TWO_BYTES,
    JL_TEMP_SUFFIX_CAPACITY = 80U,
    JL_TEMP_WRITE_ATTEMPTS = 64U,
    JL_EDIT_PAIR_CAPACITY = 2U,
    JL_PARENT_DIRECTORY_MODE = 0755,
    JL_TEMP_FILE_MODE = 0600U,
    JL_PERMISSION_MASK = 0777U,
    JL_TRUE_LITERAL_BYTES = JL_FOUR_BYTES,
    JL_FALSE_LITERAL_BYTES = 5U,
    JL_INFINITY_LITERAL_BYTES = 8U,
    JL_HEX_RADIX = 10U,
    JL_UTF8_ASCII_MAX = 0x7FU,
    JL_UTF8_TWO_BYTE_LEAD_MIN = 0xC2U,
    JL_UTF8_TWO_BYTE_LEAD_MAX = 0xDFU,
    JL_UTF8_TWO_BYTE_MAX = 0x7FFU,
    JL_UTF8_THREE_BYTE_LEAD_MAX = 0xEFU,
    JL_UTF8_THREE_BYTE_MAX = 0xFFFFU,
    JL_UTF8_FOUR_BYTE_LEAD_MAX = 0xF4U,
    JL_UTF8_CODEPOINT_MAX = 0x10FFFFU,
    JL_UTF8_TWO_BYTE_LEAD = 0xC0U,
    JL_UTF8_THREE_BYTE_LEAD = 0xE0U,
    JL_UTF8_FOUR_BYTE_LEAD = 0xF0U,
    JL_UTF8_PAYLOAD_MASK = 0x3FU,
    JL_UTF8_TWO_BYTE_PAYLOAD_MASK = 0x1FU,
    JL_UTF8_FOUR_BYTE_PAYLOAD_MASK = 0x07U,
    JL_HEX_NIBBLE_MASK = 0x0FU,
    JL_UTF8_TWO_BYTE_SHIFT = JL_UNICODE_ESCAPE_BYTES,
    JL_UTF8_THREE_BYTE_LEAD_SHIFT = 12U,
    JL_UTF8_FOUR_BYTE_LEAD_SHIFT = 18U,
    JL_UNICODE_SUPPLEMENTARY_BASE = 0x10000U,
    JL_JSON_CONTROL_CODEPOINT_LIMIT = 0x20U,
    JL_UTF8_CONTINUATION_BYTE = 0x80U,
    JL_UTF8_NON_BREAKING_SPACE_LEAD = 0xC2U,
    JL_UTF8_NON_BREAKING_SPACE_TAIL = 0xA0U,
    JL_UTF8_LINE_SEPARATOR_LEAD = 0xE2U,
    JL_UTF8_LINE_SEPARATOR_TAIL = 0xA8U,
    JL_UTF8_PARAGRAPH_SEPARATOR_TAIL = 0xA9U,
    JL_UTF8_BOM_LEAD = 0xEFU,
    JL_UTF8_BOM_MIDDLE = 0xBBU,
    JL_UTF8_BOM_TAIL = 0xBFU,
    JL_UTF16_SURROGATE_MIN = 0xD800U,
    JL_UTF16_HIGH_SURROGATE_MAX = 0xDBFFU,
    JL_UTF16_LOW_SURROGATE_MIN = 0xDC00U,
    JL_UTF16_SURROGATE_MAX = 0xDFFFU,
    JL_UTF16_SURROGATE_PAIR_SHIFT = 10U,
    JL_UTF8_C1_CONTROL_MAX = 0x9FU,
};

static atomic_uint jl_temp_sequence = ATOMIC_VAR_INIT(0);
#ifdef CBM_JSON_LIKE_ENABLE_TEST_API
static CBM_TLS cbm_json_like_precommit_test_hook_t jl_precommit_test_hook = NULL;
static CBM_TLS void *jl_precommit_test_context = NULL;
static CBM_TLS cbm_json_like_precommit_test_hook_t jl_prepublish_test_hook = NULL;
static CBM_TLS void *jl_prepublish_test_context = NULL;
#endif

typedef struct {
    bool exists;
#ifdef _WIN32
    DWORD volume_serial;
    DWORD file_index_high;
    DWORD file_index_low;
    DWORD attributes;
    DWORD link_count;
    FILETIME creation_time;
    FILETIME write_time;
    uint64_t size;
#else
    dev_t device;
    ino_t inode;
    mode_t mode;
    nlink_t link_count;
    uid_t owner;
    gid_t group;
    off_t size;
    int64_t modified_sec;
    long modified_nsec;
    int64_t changed_sec;
    long changed_nsec;
#endif
} jl_file_snapshot_t;

typedef struct {
    const char *text;
    size_t length;
    size_t pos;
    bool strict;
} jl_parser_t;

typedef struct {
    size_t key_start;
    size_t key_end;
    size_t value_start;
    size_t value_end;
    size_t comma_pos;
    size_t previous_comma_pos;
} jl_member_t;

typedef struct {
    size_t close_pos;
    size_t first_key_start;
    size_t last_value_end;
    size_t last_comma_pos;
    size_t member_count;
    size_t match_count;
    bool trailing_comma;
    jl_member_t match;
} jl_object_t;

typedef struct {
    size_t close_pos;
    size_t first_value_start;
    size_t last_value_end;
    size_t last_comma_pos;
    size_t element_count;
    size_t match_count;
    bool trailing_comma;
    jl_member_t match;
} jl_array_t;

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} jl_buffer_t;

typedef struct {
    size_t start;
    size_t end;
    const char *replacement;
    size_t replacement_length;
} jl_edit_t;

typedef struct {
    const char *data;
    size_t length;
} jl_slice_t;

static uint32_t jl_decode_hex4(const char *text);
static int jl_validate_utf8(const char *text, size_t length);

static bool jl_is_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

static size_t jl_line_terminator_width(const char *text, size_t length, size_t pos) {
    if (pos >= length) {
        return 0U;
    }
    unsigned char c = (unsigned char)text[pos];
    if (c == '\n' || c == '\r') {
        return JL_BYTE_WIDTH;
    }
    if (length - pos >= JL_THREE_BYTES && c == JL_UTF8_LINE_SEPARATOR_LEAD &&
        (unsigned char)text[pos + JL_BYTE_WIDTH] == JL_UTF8_CONTINUATION_BYTE &&
        ((unsigned char)text[pos + JL_TWO_BYTES] == JL_UTF8_LINE_SEPARATOR_TAIL ||
         (unsigned char)text[pos + JL_TWO_BYTES] == JL_UTF8_PARAGRAPH_SEPARATOR_TAIL)) {
        return JL_THREE_BYTES;
    }
    return 0U;
}

static size_t jl_whitespace_width(const jl_parser_t *parser) {
    if (parser->pos >= parser->length) {
        return 0U;
    }
    unsigned char c = (unsigned char)parser->text[parser->pos];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
        return JL_BYTE_WIDTH;
    }
    if (parser->strict) {
        return 0U;
    }
    if (c == '\f' || c == '\v') {
        return JL_BYTE_WIDTH;
    }
    if (parser->length - parser->pos >= JL_TWO_BYTES && c == JL_UTF8_NON_BREAKING_SPACE_LEAD &&
        (unsigned char)parser->text[parser->pos + JL_BYTE_WIDTH] ==
            JL_UTF8_NON_BREAKING_SPACE_TAIL) {
        return JL_TWO_BYTES;
    }
    if (parser->length - parser->pos >= JL_THREE_BYTES && c == JL_UTF8_LINE_SEPARATOR_LEAD &&
        (unsigned char)parser->text[parser->pos + JL_BYTE_WIDTH] == JL_UTF8_CONTINUATION_BYTE &&
        ((unsigned char)parser->text[parser->pos + JL_TWO_BYTES] == JL_UTF8_LINE_SEPARATOR_TAIL ||
         (unsigned char)parser->text[parser->pos + JL_TWO_BYTES] ==
             JL_UTF8_PARAGRAPH_SEPARATOR_TAIL)) {
        return JL_THREE_BYTES;
    }
    if (parser->length - parser->pos >= JL_THREE_BYTES && c == JL_UTF8_BOM_LEAD &&
        (unsigned char)parser->text[parser->pos + JL_BYTE_WIDTH] == JL_UTF8_BOM_MIDDLE &&
        (unsigned char)parser->text[parser->pos + JL_TWO_BYTES] == JL_UTF8_BOM_TAIL) {
        return JL_THREE_BYTES;
    }
    return 0U;
}

static bool jl_is_hex(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static unsigned jl_hex_value(unsigned char c) {
    if (c >= '0' && c <= '9') {
        return (unsigned)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (unsigned)(c - 'a') + JL_HEX_RADIX;
    }
    return (unsigned)(c - 'A') + JL_HEX_RADIX;
}

static bool jl_is_identifier_start(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$' ||
           c >= JL_UTF8_CONTINUATION_BYTE;
}

static bool jl_is_identifier_continue(unsigned char c) {
    return jl_is_identifier_start(c) || (c >= '0' && c <= '9');
}

static bool jl_has_json5_line_separator(const char *text, size_t remaining) {
    return remaining >= JL_TWO_BYTES && (unsigned char)text[0] == JL_UTF8_CONTINUATION_BYTE &&
           ((unsigned char)text[JL_BYTE_WIDTH] == JL_UTF8_LINE_SEPARATOR_TAIL ||
            (unsigned char)text[JL_BYTE_WIDTH] == JL_UTF8_PARAGRAPH_SEPARATOR_TAIL);
}

static bool jl_has_hex_digits(const char *text, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (!jl_is_hex((unsigned char)text[i])) {
            return false;
        }
    }
    return true;
}

static bool jl_is_json5_decimal_escape(const jl_parser_t *parser, unsigned char escaped) {
    if (escaped >= '1' && escaped <= '9') {
        return true;
    }
    return escaped == '0' && parser->pos < parser->length && parser->text[parser->pos] >= '0' &&
           parser->text[parser->pos] <= '9';
}

static int jl_parse_string_escape(jl_parser_t *parser) {
    if (parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    unsigned char escaped = (unsigned char)parser->text[parser->pos++];
    if (escaped == 'u') {
        if (parser->length - parser->pos < JL_FOUR_BYTES ||
            !jl_has_hex_digits(parser->text + parser->pos, JL_FOUR_BYTES)) {
            return JL_STATUS_FAILURE;
        }
        parser->pos += JL_FOUR_BYTES;
        return 0;
    }
    if (!parser->strict && escaped == 'x') {
        if (parser->length - parser->pos < JL_TWO_BYTES ||
            !jl_has_hex_digits(parser->text + parser->pos, JL_TWO_BYTES)) {
            return JL_STATUS_FAILURE;
        }
        parser->pos += JL_TWO_BYTES;
        return 0;
    }
    if (!parser->strict && (escaped == '\n' || escaped == '\r')) {
        if (escaped == '\r' && parser->pos < parser->length && parser->text[parser->pos] == '\n') {
            parser->pos++;
        }
        return 0;
    }
    if (!parser->strict && escaped == JL_UTF8_LINE_SEPARATOR_LEAD &&
        jl_has_json5_line_separator(parser->text + parser->pos, parser->length - parser->pos)) {
        parser->pos += JL_TWO_BYTES;
        return 0;
    }
    if (!parser->strict && jl_is_json5_decimal_escape(parser, escaped)) {
        return JL_STATUS_FAILURE;
    }
    if ((parser->strict && !strchr("\"\\/bfnrt", (int)escaped)) ||
        escaped < JL_JSON_CONTROL_CODEPOINT_LIMIT) {
        return JL_STATUS_FAILURE;
    }
    return 0;
}

static int jl_skip_trivia(jl_parser_t *parser) {
    while (parser->pos < parser->length) {
        unsigned char c = (unsigned char)parser->text[parser->pos];
        size_t whitespace_width = jl_whitespace_width(parser);
        if (whitespace_width > 0U) {
            parser->pos += whitespace_width;
            continue;
        }
        if (parser->strict || c != '/' || parser->pos + JL_BYTE_WIDTH >= parser->length) {
            return 0;
        }

        unsigned char next = (unsigned char)parser->text[parser->pos + JL_BYTE_WIDTH];
        if (next == '/') {
            parser->pos += JL_TWO_BYTES;
            while (parser->pos < parser->length &&
                   jl_line_terminator_width(parser->text, parser->length, parser->pos) == 0U) {
                parser->pos++;
            }
            continue;
        }
        if (next == '*') {
            parser->pos += JL_TWO_BYTES;
            bool closed = false;
            while (parser->pos + JL_BYTE_WIDTH < parser->length) {
                if (parser->text[parser->pos] == '*' &&
                    parser->text[parser->pos + JL_BYTE_WIDTH] == '/') {
                    parser->pos += JL_TWO_BYTES;
                    closed = true;
                    break;
                }
                parser->pos++;
            }
            if (!closed) {
                return JL_STATUS_FAILURE;
            }
            continue;
        }
        return 0;
    }
    return 0;
}

static int jl_parse_string(jl_parser_t *parser, size_t *start_out, size_t *end_out) {
    if (parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    unsigned char quote = (unsigned char)parser->text[parser->pos];
    if (quote != '"' && (parser->strict || quote != '\'')) {
        return JL_STATUS_FAILURE;
    }

    size_t start = parser->pos++;
    while (parser->pos < parser->length) {
        unsigned char c = (unsigned char)parser->text[parser->pos++];
        if (c == quote) {
            if (start_out) {
                *start_out = start;
            }
            if (end_out) {
                *end_out = parser->pos;
            }
            return 0;
        }
        if (c < JL_JSON_CONTROL_CODEPOINT_LIMIT) {
            return JL_STATUS_FAILURE;
        }
        if (c != '\\') {
            if (!parser->strict && c == JL_UTF8_LINE_SEPARATOR_LEAD &&
                jl_has_json5_line_separator(parser->text + parser->pos,
                                            parser->length - parser->pos)) {
                return JL_STATUS_FAILURE;
            }
            continue;
        }
        if (jl_parse_string_escape(parser) != 0) {
            return JL_STATUS_FAILURE;
        }
    }
    return JL_STATUS_FAILURE;
}

static bool jl_is_identifier_codepoint(uint32_t codepoint, bool first) {
    if (codepoint >= JL_UTF16_SURROGATE_MIN && codepoint <= JL_UTF16_SURROGATE_MAX) {
        return false;
    }
    return codepoint >= JL_UTF8_CONTINUATION_BYTE ||
           (first ? jl_is_identifier_start((unsigned char)codepoint)
                  : jl_is_identifier_continue((unsigned char)codepoint));
}

static bool jl_parse_identifier_escape(jl_parser_t *parser, bool first) {
    if (parser->length - parser->pos < JL_UNICODE_ESCAPE_BYTES ||
        parser->text[parser->pos] != '\\' || parser->text[parser->pos + JL_BYTE_WIDTH] != 'u') {
        return false;
    }
    const char *digits = parser->text + parser->pos + JL_TWO_BYTES;
    for (size_t i = 0; i < JL_FOUR_BYTES; i++) {
        if (!jl_is_hex((unsigned char)digits[i])) {
            return false;
        }
    }
    if (!jl_is_identifier_codepoint(jl_decode_hex4(digits), first)) {
        return false;
    }
    parser->pos += JL_UNICODE_ESCAPE_BYTES;
    return true;
}

static int jl_parse_identifier(jl_parser_t *parser, size_t *start_out, size_t *end_out) {
    size_t start = parser->pos;
    bool first = true;
    while (parser->pos < parser->length) {
        unsigned char c = (unsigned char)parser->text[parser->pos];
        bool accepted = first ? jl_is_identifier_start(c) : jl_is_identifier_continue(c);
        if (accepted) {
            parser->pos++;
        } else if (!jl_parse_identifier_escape(parser, first)) {
            break;
        }
        first = false;
    }
    if (first) {
        return JL_STATUS_FAILURE;
    }
    if (start_out) {
        *start_out = start;
    }
    if (end_out) {
        *end_out = parser->pos;
    }
    return 0;
}

static int jl_parse_key(jl_parser_t *parser, size_t *start_out, size_t *end_out) {
    if (parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    unsigned char c = (unsigned char)parser->text[parser->pos];
    if (c == '"' || (!parser->strict && c == '\'')) {
        return jl_parse_string(parser, start_out, end_out);
    }
    if (!parser->strict) {
        return jl_parse_identifier(parser, start_out, end_out);
    }
    return JL_STATUS_FAILURE;
}

static bool jl_has_prefix(const jl_parser_t *parser, const char *word) {
    size_t word_length = strlen(word);
    return parser->length - parser->pos >= word_length &&
           memcmp(parser->text + parser->pos, word, word_length) == 0;
}

static bool jl_is_digit(unsigned char c) {
    return c >= '0' && c <= '9';
}

static size_t jl_consume_digits(const jl_parser_t *parser, size_t pos) {
    while (pos < parser->length && jl_is_digit((unsigned char)parser->text[pos])) {
        pos++;
    }
    return pos;
}

static int jl_parse_number_special(jl_parser_t *parser, size_t pos) {
    if (parser->strict) {
        return JL_STATUS_NO_MATCH;
    }
    if (parser->length - pos >= JL_INFINITY_LITERAL_BYTES &&
        memcmp(parser->text + pos, "Infinity", JL_INFINITY_LITERAL_BYTES) == 0) {
        parser->pos = pos + JL_INFINITY_LITERAL_BYTES;
        return 0;
    }
    if (parser->length - pos >= JL_THREE_BYTES &&
        memcmp(parser->text + pos, "NaN", JL_THREE_BYTES) == 0) {
        parser->pos = pos + JL_THREE_BYTES;
        return 0;
    }
    if (parser->length - pos >= JL_TWO_BYTES && parser->text[pos] == '0' &&
        (parser->text[pos + JL_BYTE_WIDTH] == 'x' || parser->text[pos + JL_BYTE_WIDTH] == 'X')) {
        size_t digits = pos + JL_TWO_BYTES;
        size_t end = digits;
        while (end < parser->length && jl_is_hex((unsigned char)parser->text[end])) {
            end++;
        }
        if (end == digits) {
            return JL_STATUS_FAILURE;
        }
        parser->pos = end;
        return 0;
    }
    return JL_STATUS_NO_MATCH;
}

static int jl_parse_number_integer(const jl_parser_t *parser, size_t *pos, bool *has_digits) {
    if (*pos < parser->length && parser->text[*pos] == '0') {
        *has_digits = true;
        (*pos)++;
        if (parser->strict && *pos < parser->length &&
            jl_is_digit((unsigned char)parser->text[*pos])) {
            return JL_STATUS_FAILURE;
        }
        return 0;
    }
    size_t end = jl_consume_digits(parser, *pos);
    *has_digits = end != *pos;
    *pos = end;
    return 0;
}

static int jl_parse_number_fraction(const jl_parser_t *parser, size_t *pos, bool *has_digits) {
    if (*pos >= parser->length || parser->text[*pos] != '.') {
        return 0;
    }
    size_t digits = jl_consume_digits(parser, *pos + JL_BYTE_WIDTH);
    *has_digits = digits != *pos + JL_BYTE_WIDTH;
    *pos = digits;
    return parser->strict && !*has_digits ? JL_STATUS_FAILURE : 0;
}

static int jl_parse_number_exponent(const jl_parser_t *parser, size_t *pos) {
    if (*pos >= parser->length || (parser->text[*pos] != 'e' && parser->text[*pos] != 'E')) {
        return 0;
    }
    (*pos)++;
    if (*pos < parser->length && (parser->text[*pos] == '+' || parser->text[*pos] == '-')) {
        (*pos)++;
    }
    size_t digits = jl_consume_digits(parser, *pos);
    if (digits == *pos) {
        return JL_STATUS_FAILURE;
    }
    *pos = digits;
    return 0;
}

static int jl_parse_number(jl_parser_t *parser) {
    size_t pos = parser->pos;
    if (pos < parser->length &&
        (parser->text[pos] == '-' || (!parser->strict && parser->text[pos] == '+'))) {
        pos++;
    }
    int special = jl_parse_number_special(parser, pos);
    if (special != JL_STATUS_NO_MATCH) {
        return special;
    }
    bool integer_digits = false;
    bool fraction_digits = false;
    if (jl_parse_number_integer(parser, &pos, &integer_digits) != 0 ||
        (parser->strict && !integer_digits) ||
        jl_parse_number_fraction(parser, &pos, &fraction_digits) != 0 ||
        (!integer_digits && !fraction_digits) || jl_parse_number_exponent(parser, &pos) != 0) {
        return JL_STATUS_FAILURE;
    }
    parser->pos = pos;
    return 0;
}

typedef struct {
    unsigned char close;
    bool object;
    bool needs_item;
    bool after_comma;
} jl_parse_frame_t;

static int jl_parse_literal(jl_parser_t *parser) {
    static const struct {
        const char *text;
        size_t length;
    } literals[] = {{"true", JL_TRUE_LITERAL_BYTES},
                    {"false", JL_FALSE_LITERAL_BYTES},
                    {"null", JL_TRUE_LITERAL_BYTES}};
    for (size_t i = 0; i < sizeof(literals) / sizeof(literals[0]); i++) {
        if (jl_has_prefix(parser, literals[i].text)) {
            parser->pos += literals[i].length;
            return 0;
        }
    }
    return JL_STATUS_FAILURE;
}

static int jl_parse_scalar(jl_parser_t *parser) {
    unsigned char c = (unsigned char)parser->text[parser->pos];
    if (c == '"' || (!parser->strict && c == '\'')) {
        return jl_parse_string(parser, NULL, NULL);
    }
    return jl_parse_literal(parser) == 0 ? 0 : jl_parse_number(parser);
}

static int jl_push_container(jl_parser_t *parser, jl_parse_frame_t *frames, size_t *count,
                             unsigned depth) {
    if (*count + depth >= JL_MAX_DEPTH || parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    unsigned char open = (unsigned char)parser->text[parser->pos];
    if (open != '{' && open != '[') {
        return JL_STATUS_FAILURE;
    }
    frames[*count] = (jl_parse_frame_t){.close = open == '{' ? '}' : ']',
                                        .object = open == '{',
                                        .needs_item = true,
                                        .after_comma = false};
    (*count)++;
    parser->pos++;
    return jl_skip_trivia(parser);
}

static int jl_parse_container_item(jl_parser_t *parser, jl_parse_frame_t *frame,
                                   jl_parse_frame_t *frames, size_t *count, unsigned depth) {
    if (parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    if ((unsigned char)parser->text[parser->pos] == frame->close) {
        if (frame->after_comma && parser->strict) {
            return JL_STATUS_FAILURE;
        }
        parser->pos++;
        (*count)--;
        return 0;
    }
    if (frame->object) {
        if (jl_parse_key(parser, NULL, NULL) != 0 || jl_skip_trivia(parser) != 0 ||
            parser->pos >= parser->length || parser->text[parser->pos] != ':') {
            return JL_STATUS_FAILURE;
        }
        parser->pos++;
        if (jl_skip_trivia(parser) != 0 || parser->pos >= parser->length) {
            return JL_STATUS_FAILURE;
        }
    }
    frame->needs_item = false;
    frame->after_comma = false;
    unsigned char c = (unsigned char)parser->text[parser->pos];
    return (c == '{' || c == '[') ? jl_push_container(parser, frames, count, depth)
                                  : jl_parse_scalar(parser);
}

static int jl_parse_value(jl_parser_t *parser, unsigned depth, size_t *start_out, size_t *end_out) {
    if (depth > JL_MAX_DEPTH || parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    size_t start = parser->pos;
    jl_parse_frame_t frames[JL_MAX_DEPTH];
    size_t frame_count = 0;
    unsigned char first = (unsigned char)parser->text[parser->pos];
    if (first == '{' || first == '[') {
        if (jl_push_container(parser, frames, &frame_count, depth) != 0) {
            return JL_STATUS_FAILURE;
        }
    } else if (jl_parse_scalar(parser) != 0) {
        return JL_STATUS_FAILURE;
    }
    while (frame_count > 0) {
        jl_parse_frame_t *frame = &frames[frame_count - JL_BYTE_WIDTH];
        if (frame->needs_item) {
            if (jl_parse_container_item(parser, frame, frames, &frame_count, depth) != 0) {
                return JL_STATUS_FAILURE;
            }
            continue;
        }
        if (jl_skip_trivia(parser) != 0 || parser->pos >= parser->length) {
            return JL_STATUS_FAILURE;
        }
        if ((unsigned char)parser->text[parser->pos] == frame->close) {
            parser->pos++;
            frame_count--;
            continue;
        }
        if (parser->text[parser->pos] != ',') {
            return JL_STATUS_FAILURE;
        }
        parser->pos++;
        if (jl_skip_trivia(parser) != 0) {
            return JL_STATUS_FAILURE;
        }
        frame->needs_item = true;
        frame->after_comma = true;
    }
    if (start_out) {
        *start_out = start;
    }
    if (end_out) {
        *end_out = parser->pos;
    }
    return 0;
}

static int jl_validate_document(const char *text, size_t length, size_t *root_out) {
    if (jl_validate_utf8(text, length) != 0) {
        return JL_STATUS_FAILURE;
    }
    jl_parser_t parser = {.text = text, .length = length, .pos = 0, .strict = false};
    if (jl_skip_trivia(&parser) != 0 || parser.pos >= parser.length ||
        parser.text[parser.pos] != '{') {
        return JL_STATUS_FAILURE;
    }
    size_t root = parser.pos;
    if (jl_parse_value(&parser, 0, NULL, NULL) != 0 || jl_skip_trivia(&parser) != 0 ||
        parser.pos != parser.length) {
        return JL_STATUS_FAILURE;
    }
    *root_out = root;
    return 0;
}

static int jl_validate_entry(const char *entry_json, size_t *start_out, size_t *length_out) {
    size_t length = strlen(entry_json);
    if (length == 0 || length > JL_MAX_FILE_BYTES || jl_validate_utf8(entry_json, length) != 0) {
        return JL_STATUS_FAILURE;
    }
    jl_parser_t parser = {
        .text = entry_json,
        .length = length,
        .pos = 0,
        .strict = true,
    };
    if (jl_skip_trivia(&parser) != 0 || parser.pos >= parser.length) {
        return JL_STATUS_FAILURE;
    }
    size_t value_start = 0;
    size_t value_end = 0;
    if (jl_parse_value(&parser, 0, &value_start, &value_end) != 0 || jl_skip_trivia(&parser) != 0 ||
        parser.pos != parser.length) {
        return JL_STATUS_FAILURE;
    }
    *start_out = value_start;
    *length_out = value_end - value_start;
    return 0;
}

static size_t jl_encode_utf8(uint32_t codepoint, unsigned char output[JL_FOUR_BYTES]) {
    if (codepoint <= JL_UTF8_ASCII_MAX) {
        output[0] = (unsigned char)codepoint;
        return JL_BYTE_WIDTH;
    }
    if (codepoint <= JL_UTF8_TWO_BYTE_MAX) {
        output[0] = (unsigned char)(JL_UTF8_TWO_BYTE_LEAD | (codepoint >> JL_UTF8_TWO_BYTE_SHIFT));
        output[JL_BYTE_WIDTH] =
            (unsigned char)(JL_UTF8_CONTINUATION_BYTE | (codepoint & JL_UTF8_PAYLOAD_MASK));
        return JL_TWO_BYTES;
    }
    if (codepoint <= JL_UTF8_THREE_BYTE_MAX) {
        output[0] =
            (unsigned char)(JL_UTF8_THREE_BYTE_LEAD | (codepoint >> JL_UTF8_THREE_BYTE_LEAD_SHIFT));
        output[JL_BYTE_WIDTH] =
            (unsigned char)(JL_UTF8_CONTINUATION_BYTE |
                            ((codepoint >> JL_UTF8_TWO_BYTE_SHIFT) & JL_UTF8_PAYLOAD_MASK));
        output[JL_TWO_BYTES] =
            (unsigned char)(JL_UTF8_CONTINUATION_BYTE | (codepoint & JL_UTF8_PAYLOAD_MASK));
        return JL_THREE_BYTES;
    }
    output[0] =
        (unsigned char)(JL_UTF8_FOUR_BYTE_LEAD | (codepoint >> JL_UTF8_FOUR_BYTE_LEAD_SHIFT));
    output[JL_BYTE_WIDTH] =
        (unsigned char)(JL_UTF8_CONTINUATION_BYTE |
                        ((codepoint >> JL_UTF8_THREE_BYTE_LEAD_SHIFT) & JL_UTF8_PAYLOAD_MASK));
    output[JL_TWO_BYTES] =
        (unsigned char)(JL_UTF8_CONTINUATION_BYTE |
                        ((codepoint >> JL_UTF8_TWO_BYTE_SHIFT) & JL_UTF8_PAYLOAD_MASK));
    output[JL_THREE_BYTES] =
        (unsigned char)(JL_UTF8_CONTINUATION_BYTE | (codepoint & JL_UTF8_PAYLOAD_MASK));
    return JL_FOUR_BYTES;
}

static uint32_t jl_decode_hex4(const char *text) {
    uint32_t value = 0;
    for (size_t i = 0; i < JL_FOUR_BYTES; i++) {
        value = (value << JL_FOUR_BYTES) | jl_hex_value((unsigned char)text[i]);
    }
    return value;
}

static bool jl_match_output(const unsigned char *bytes, size_t byte_count, const char *target,
                            size_t target_length, size_t *target_pos) {
    if (target_length - *target_pos < byte_count ||
        memcmp(target + *target_pos, bytes, byte_count) != 0) {
        return false;
    }
    *target_pos += byte_count;
    return true;
}

static bool jl_decode_key_escape(const char *text, size_t *pos, size_t limit,
                                 uint32_t *codepoint_out, bool *skip_out) {
    *skip_out = false;
    if (*pos >= limit) {
        return false;
    }
    unsigned char escaped = (unsigned char)text[(*pos)++];
    if (escaped == '\n' || escaped == '\r') {
        if (escaped == '\r' && *pos < limit && text[*pos] == '\n') {
            (*pos)++;
        }
        *skip_out = true;
        return true;
    }
    static const struct {
        unsigned char escaped;
        uint32_t codepoint;
    } mapped[] = {{'b', '\b'}, {'f', '\f'}, {'n', '\n'}, {'r', '\r'},
                  {'t', '\t'}, {'v', '\v'}, {'0', 0U}};
    for (size_t i = 0; i < sizeof(mapped) / sizeof(mapped[0]); i++) {
        if (escaped == mapped[i].escaped) {
            *codepoint_out = mapped[i].codepoint;
            return true;
        }
    }
    if (escaped == 'x') {
        if (limit - *pos < JL_TWO_BYTES) {
            return false;
        }
        *codepoint_out = (jl_hex_value((unsigned char)text[*pos]) << JL_FOUR_BYTES) |
                         jl_hex_value((unsigned char)text[*pos + JL_BYTE_WIDTH]);
        *pos += JL_TWO_BYTES;
        return true;
    }
    if (escaped != 'u' || limit - *pos < JL_FOUR_BYTES) {
        *codepoint_out = escaped;
        return escaped != 'u';
    }
    *codepoint_out = jl_decode_hex4(text + *pos);
    *pos += JL_FOUR_BYTES;
    if (*codepoint_out >= JL_UTF16_SURROGATE_MIN && *codepoint_out <= JL_UTF16_HIGH_SURROGATE_MAX &&
        limit - *pos >= JL_UNICODE_ESCAPE_BYTES && text[*pos] == '\\' &&
        text[*pos + JL_BYTE_WIDTH] == 'u') {
        uint32_t low = jl_decode_hex4(text + *pos + JL_TWO_BYTES);
        if (low >= JL_UTF16_LOW_SURROGATE_MIN && low <= JL_UTF16_SURROGATE_MAX) {
            *codepoint_out =
                JL_UNICODE_SUPPLEMENTARY_BASE +
                ((*codepoint_out - JL_UTF16_SURROGATE_MIN) << JL_UTF16_SURROGATE_PAIR_SHIFT) +
                (low - JL_UTF16_LOW_SURROGATE_MIN);
            *pos += JL_UNICODE_ESCAPE_BYTES;
        }
    }
    return true;
}

static bool jl_key_equals(const char *text, size_t start, size_t end, const char *target) {
    size_t target_length = strlen(target);
    size_t target_pos = 0;
    bool quoted = end > start + JL_BYTE_WIDTH && (text[start] == '"' || text[start] == '\'');
    size_t pos = quoted ? start + JL_BYTE_WIDTH : start;
    size_t limit = quoted ? end - JL_BYTE_WIDTH : end;

    while (pos < limit) {
        unsigned char c = (unsigned char)text[pos++];
        if (c != '\\') {
            if (!jl_match_output(&c, JL_BYTE_WIDTH, target, target_length, &target_pos)) {
                return false;
            }
            continue;
        }
        uint32_t codepoint = 0;
        bool skip = false;
        if (!jl_decode_key_escape(text, &pos, limit, &codepoint, &skip)) {
            return false;
        }
        if (skip) {
            continue;
        }
        unsigned char encoded[JL_FOUR_BYTES];
        size_t encoded_length = jl_encode_utf8(codepoint, encoded);
        if (!jl_match_output(encoded, encoded_length, target, target_length, &target_pos)) {
            return false;
        }
    }
    return target_pos == target_length;
}

static int jl_scan_object_member(jl_parser_t *parser, const char *lookup_key, jl_object_t *object,
                                 size_t previous_comma, bool *matches_out) {
    size_t key_start = 0;
    size_t key_end = 0;
    if (jl_parse_key(parser, &key_start, &key_end) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (object->first_key_start == SIZE_MAX) {
        object->first_key_start = key_start;
    }
    if (jl_skip_trivia(parser) != 0 || parser->pos >= parser->length ||
        parser->text[parser->pos] != ':') {
        return JL_STATUS_FAILURE;
    }
    parser->pos++;
    if (jl_skip_trivia(parser) != 0 || parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    size_t value_start = 0;
    size_t value_end = 0;
    if (jl_parse_value(parser, JL_BYTE_WIDTH, &value_start, &value_end) != 0 ||
        jl_skip_trivia(parser) != 0 || parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    bool matches = jl_key_equals(parser->text, key_start, key_end, lookup_key);
    if (matches) {
        object->match_count++;
        if (object->match_count == JL_BYTE_WIDTH) {
            object->match = (jl_member_t){.key_start = key_start,
                                          .key_end = key_end,
                                          .value_start = value_start,
                                          .value_end = value_end,
                                          .comma_pos = SIZE_MAX,
                                          .previous_comma_pos = previous_comma};
        }
    }
    object->member_count++;
    object->last_value_end = value_end;
    *matches_out = matches;
    return 0;
}

static int jl_scan_object_delimiter(jl_parser_t *parser, jl_object_t *object, bool matches,
                                    size_t *previous_comma) {
    if (parser->text[parser->pos] == '}') {
        object->close_pos = parser->pos;
        return 0;
    }
    if (parser->text[parser->pos] != ',') {
        return JL_STATUS_FAILURE;
    }
    size_t comma = parser->pos++;
    object->last_comma_pos = comma;
    if (matches && object->match_count == JL_BYTE_WIDTH) {
        object->match.comma_pos = comma;
    }
    *previous_comma = comma;
    if (jl_skip_trivia(parser) != 0 || parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    if (parser->text[parser->pos] == '}') {
        object->close_pos = parser->pos;
        object->trailing_comma = true;
        return 0;
    }
    return JL_STATUS_NO_MATCH;
}

static int jl_scan_object(const char *text, size_t length, size_t object_start,
                          const char *lookup_key, jl_object_t *object) {
    memset(object, 0, sizeof(*object));
    object->first_key_start = SIZE_MAX;
    object->last_value_end = SIZE_MAX;
    object->last_comma_pos = SIZE_MAX;
    object->match.comma_pos = SIZE_MAX;
    object->match.previous_comma_pos = SIZE_MAX;

    if (object_start >= length || text[object_start] != '{') {
        return JL_STATUS_FAILURE;
    }
    jl_parser_t parser = {
        .text = text, .length = length, .pos = object_start + JL_BYTE_WIDTH, .strict = false};
    if (jl_skip_trivia(&parser) != 0 || parser.pos >= parser.length) {
        return JL_STATUS_FAILURE;
    }
    if (text[parser.pos] == '}') {
        object->close_pos = parser.pos;
        return 0;
    }

    size_t previous_comma = SIZE_MAX;
    while (parser.pos < parser.length) {
        bool matches = false;
        if (jl_scan_object_member(&parser, lookup_key, object, previous_comma, &matches) != 0) {
            return JL_STATUS_FAILURE;
        }
        int delimiter = jl_scan_object_delimiter(&parser, object, matches, &previous_comma);
        if (delimiter == 0) {
            return 0;
        }
        if (delimiter != JL_STATUS_NO_MATCH) {
            return JL_STATUS_FAILURE;
        }
    }
    return JL_STATUS_FAILURE;
}

static int jl_scan_array_value(jl_parser_t *parser, const char *lookup_string, jl_array_t *array,
                               size_t previous_comma, bool *matches_out) {
    size_t value_start = 0;
    size_t value_end = 0;
    if (jl_parse_value(parser, JL_BYTE_WIDTH, &value_start, &value_end) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (array->first_value_start == SIZE_MAX) {
        array->first_value_start = value_start;
    }
    bool string_value = parser->text[value_start] == '"' || parser->text[value_start] == '\'';
    bool matches =
        string_value && jl_key_equals(parser->text, value_start, value_end, lookup_string);
    if (matches) {
        array->match_count++;
        if (array->match_count == JL_BYTE_WIDTH) {
            array->match = (jl_member_t){.value_start = value_start,
                                         .value_end = value_end,
                                         .comma_pos = SIZE_MAX,
                                         .previous_comma_pos = previous_comma};
        }
    }
    array->element_count++;
    array->last_value_end = value_end;
    *matches_out = matches;
    return jl_skip_trivia(parser);
}

static int jl_scan_array_delimiter(jl_parser_t *parser, jl_array_t *array, bool matches,
                                   size_t *previous_comma) {
    if (parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    if (parser->text[parser->pos] == ']') {
        array->close_pos = parser->pos;
        return 0;
    }
    if (parser->text[parser->pos] != ',') {
        return JL_STATUS_FAILURE;
    }
    size_t comma = parser->pos++;
    array->last_comma_pos = comma;
    if (matches && array->match_count == JL_BYTE_WIDTH) {
        array->match.comma_pos = comma;
    }
    *previous_comma = comma;
    if (jl_skip_trivia(parser) != 0 || parser->pos >= parser->length) {
        return JL_STATUS_FAILURE;
    }
    if (parser->text[parser->pos] == ']') {
        array->close_pos = parser->pos;
        array->trailing_comma = true;
        return 0;
    }
    return JL_STATUS_NO_MATCH;
}

static int jl_scan_array(const char *text, size_t length, size_t array_start,
                         const char *lookup_string, jl_array_t *array) {
    memset(array, 0, sizeof(*array));
    array->first_value_start = SIZE_MAX;
    array->last_value_end = SIZE_MAX;
    array->last_comma_pos = SIZE_MAX;
    array->match.comma_pos = SIZE_MAX;
    array->match.previous_comma_pos = SIZE_MAX;

    if (array_start >= length || text[array_start] != '[') {
        return JL_STATUS_FAILURE;
    }
    jl_parser_t parser = {
        .text = text,
        .length = length,
        .pos = array_start + JL_BYTE_WIDTH,
        .strict = false,
    };
    if (jl_skip_trivia(&parser) != 0 || parser.pos >= parser.length) {
        return JL_STATUS_FAILURE;
    }
    if (text[parser.pos] == ']') {
        array->close_pos = parser.pos;
        return 0;
    }

    size_t previous_comma = SIZE_MAX;
    while (parser.pos < parser.length) {
        bool matches = false;
        if (jl_scan_array_value(&parser, lookup_string, array, previous_comma, &matches) != 0) {
            return JL_STATUS_FAILURE;
        }
        int delimiter = jl_scan_array_delimiter(&parser, array, matches, &previous_comma);
        if (delimiter == 0) {
            return 0;
        }
        if (delimiter != JL_STATUS_NO_MATCH) {
            return JL_STATUS_FAILURE;
        }
    }
    return JL_STATUS_FAILURE;
}

static int jl_buffer_reserve(jl_buffer_t *buffer, size_t additional) {
    if (additional > SIZE_MAX - buffer->length - JL_BYTE_WIDTH) {
        return JL_STATUS_FAILURE;
    }
    size_t needed = buffer->length + additional + JL_BYTE_WIDTH;
    if (needed <= buffer->capacity) {
        return 0;
    }
    size_t capacity = buffer->capacity ? buffer->capacity : JL_BUFFER_INITIAL_CAPACITY;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / JL_BUFFER_GROWTH_FACTOR) {
            capacity = needed;
            break;
        }
        capacity *= JL_BUFFER_GROWTH_FACTOR;
    }
    char *grown = realloc(buffer->data, capacity);
    if (!grown) {
        return JL_STATUS_FAILURE;
    }
    buffer->data = grown;
    buffer->capacity = capacity;
    return 0;
}

static int jl_buffer_append(jl_buffer_t *buffer, const char *data, size_t length) {
    if (jl_buffer_reserve(buffer, length) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (length > 0) {
        memcpy(buffer->data + buffer->length, data, length);
    }
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
    return 0;
}

static int jl_buffer_char(jl_buffer_t *buffer, char c) {
    return jl_buffer_append(buffer, &c, JL_BYTE_WIDTH);
}

static int jl_buffer_string(jl_buffer_t *buffer, const char *text) {
    return jl_buffer_append(buffer, text, strlen(text));
}

static char jl_simple_escape(unsigned char value) {
    static const struct {
        unsigned char value;
        char escaped;
    } escapes[] = {{'\b', 'b'}, {'\f', 'f'}, {'\n', 'n'}, {'\r', 'r'}, {'\t', 't'}};
    for (size_t i = 0; i < sizeof(escapes) / sizeof(escapes[0]); i++) {
        if (value == escapes[i].value) {
            return escapes[i].escaped;
        }
    }
    return '\0';
}

static int jl_append_control_escape(jl_buffer_t *buffer, unsigned char value) {
    static const char hex[] = "0123456789abcdef";
    char escaped = jl_simple_escape(value);
    if (escaped) {
        return jl_buffer_char(buffer, '\\') == 0 && jl_buffer_char(buffer, escaped) == 0
                   ? 0
                   : JL_STATUS_FAILURE;
    }
    char unicode[JL_UNICODE_ESCAPE_BYTES] = {
        '\\', 'u', '0', '0', hex[value >> JL_FOUR_BYTES], hex[value & JL_HEX_NIBBLE_MASK]};
    return jl_buffer_append(buffer, unicode, sizeof(unicode));
}

static int jl_append_quoted_byte(jl_buffer_t *buffer, unsigned char value) {
    if (value == '"' || value == '\\') {
        return jl_buffer_char(buffer, '\\') == 0 && jl_buffer_char(buffer, (char)value) == 0
                   ? 0
                   : JL_STATUS_FAILURE;
    }
    if (value < JL_JSON_CONTROL_CODEPOINT_LIMIT) {
        return jl_append_control_escape(buffer, value);
    }
    return jl_buffer_char(buffer, (char)value);
}

static int jl_append_quoted_string(jl_buffer_t *buffer, const char *value) {
    if (jl_buffer_char(buffer, '"') != 0) {
        return JL_STATUS_FAILURE;
    }
    for (const unsigned char *pos = (const unsigned char *)value; *pos; pos++) {
        if (jl_append_quoted_byte(buffer, *pos) != 0) {
            return JL_STATUS_FAILURE;
        }
    }
    return jl_buffer_char(buffer, '"');
}

static int jl_append_quoted_key(jl_buffer_t *buffer, const char *key) {
    return jl_append_quoted_string(buffer, key);
}

static int jl_append_repeated(jl_buffer_t *buffer, const char *data, size_t length, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (jl_buffer_append(buffer, data, length) != 0) {
            return JL_STATUS_FAILURE;
        }
    }
    return 0;
}

static int jl_append_styled_indent(jl_buffer_t *buffer, jl_slice_t base, jl_slice_t unit,
                                   size_t unit_count) {
    return jl_buffer_append(buffer, base.data, base.length) == 0 &&
                   jl_append_repeated(buffer, unit.data, unit.length, unit_count) == 0
               ? 0
               : JL_STATUS_FAILURE;
}

static int jl_build_member(jl_buffer_t *buffer, const char *const *object_path, size_t path_len,
                           size_t missing_path_index, const char *entry_key, const char *entry_json,
                           size_t entry_length, const char *newline, jl_slice_t base_indent,
                           jl_slice_t indent_unit) {
    if (missing_path_index == SIZE_MAX) {
        if (jl_append_quoted_key(buffer, entry_key) != 0 || jl_buffer_string(buffer, ": ") != 0 ||
            jl_buffer_append(buffer, entry_json, entry_length) != 0) {
            return JL_STATUS_FAILURE;
        }
        return 0;
    }

    if (jl_append_quoted_key(buffer, object_path[missing_path_index]) != 0 ||
        jl_buffer_string(buffer, ": {") != 0 || jl_buffer_string(buffer, newline) != 0) {
        return JL_STATUS_FAILURE;
    }
    size_t level = JL_BYTE_WIDTH;
    for (size_t i = missing_path_index + JL_BYTE_WIDTH; i < path_len; i++) {
        if (jl_append_styled_indent(buffer, base_indent, indent_unit, level + JL_BYTE_WIDTH) != 0 ||
            jl_append_quoted_key(buffer, object_path[i]) != 0 ||
            jl_buffer_string(buffer, ": {") != 0 || jl_buffer_string(buffer, newline) != 0) {
            return JL_STATUS_FAILURE;
        }
        level++;
    }
    if (jl_append_styled_indent(buffer, base_indent, indent_unit, level + JL_BYTE_WIDTH) != 0 ||
        jl_append_quoted_key(buffer, entry_key) != 0 || jl_buffer_string(buffer, ": ") != 0 ||
        jl_buffer_append(buffer, entry_json, entry_length) != 0) {
        return JL_STATUS_FAILURE;
    }
    while (level > 0U) {
        if (jl_buffer_string(buffer, newline) != 0 ||
            jl_append_styled_indent(buffer, base_indent, indent_unit, level) != 0 ||
            jl_buffer_char(buffer, '}') != 0) {
            return JL_STATUS_FAILURE;
        }
        level--;
    }
    return 0;
}

static bool jl_line_indent(const char *text, size_t pos, jl_slice_t *indent) {
    size_t line_start = pos;
    while (line_start > 0U && text[line_start - JL_BYTE_WIDTH] != '\n' &&
           text[line_start - JL_BYTE_WIDTH] != '\r') {
        line_start--;
    }
    for (size_t i = line_start; i < pos; i++) {
        if (text[i] != ' ' && text[i] != '\t') {
            indent->data = text + pos;
            indent->length = 0;
            return false;
        }
    }
    indent->data = text + line_start;
    indent->length = pos - line_start;
    return true;
}

static const char *jl_newline_style(const char *text, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (text[i] == '\n') {
            return i > 0U && text[i - JL_BYTE_WIDTH] == '\r' ? "\r\n" : "\n";
        }
        if (text[i] == '\r') {
            return i + JL_BYTE_WIDTH < length && text[i + JL_BYTE_WIDTH] == '\n' ? "\r\n" : "\n";
        }
    }
    return "\n";
}

static bool jl_range_has_newline(const char *text, size_t start, size_t end) {
    for (size_t i = start; i < end; i++) {
        if (text[i] == '\n' || text[i] == '\r') {
            return true;
        }
    }
    return false;
}

static size_t jl_leading_whitespace_start(const char *text, size_t token_start) {
    while (token_start > 0U && (text[token_start - JL_BYTE_WIDTH] == ' ' ||
                                text[token_start - JL_BYTE_WIDTH] == '\t')) {
        token_start--;
    }
    size_t newline_start = token_start;
    if (newline_start > 0U && text[newline_start - JL_BYTE_WIDTH] == '\n') {
        newline_start--;
        if (newline_start > 0U && text[newline_start - JL_BYTE_WIDTH] == '\r') {
            newline_start--;
        }
    } else if (newline_start > 0U && text[newline_start - JL_BYTE_WIDTH] == '\r') {
        newline_start--;
    }
    if (newline_start < token_start && newline_start > 0U) {
        char preceding = text[newline_start - JL_BYTE_WIDTH];
        if (preceding == '{' || preceding == '[' || preceding == ',') {
            return newline_start;
        }
    }
    return token_start;
}

static void jl_detect_indent(const char *text, const jl_object_t *object, jl_slice_t *base,
                             jl_slice_t *unit, bool *close_indent_only) {
    static const char spaces[] = "  ";
    static const char tab[] = "\t";
    *close_indent_only = jl_line_indent(text, object->close_pos, base);
    unit->data = spaces;
    unit->length = JL_TWO_BYTES;

    if (object->first_key_start == SIZE_MAX) {
        if (base->length > 0U && base->data[base->length - JL_BYTE_WIDTH] == '\t') {
            unit->data = tab;
            unit->length = JL_BYTE_WIDTH;
        }
        return;
    }
    jl_slice_t member_indent;
    if (!jl_line_indent(text, object->first_key_start, &member_indent)) {
        return;
    }
    if (member_indent.length > base->length &&
        (base->length == 0U || memcmp(member_indent.data, base->data, base->length) == 0)) {
        unit->data = member_indent.data + base->length;
        unit->length = member_indent.length - base->length;
    } else if (member_indent.length > 0U &&
               member_indent.data[member_indent.length - JL_BYTE_WIDTH] == '\t') {
        unit->data = tab;
        unit->length = JL_BYTE_WIDTH;
    }
}

static int jl_make_tight_insertion(jl_buffer_t *insertion, const jl_buffer_t *member,
                                   const char *newline, jl_slice_t base, jl_slice_t unit) {
    if (jl_buffer_string(insertion, newline) != 0 ||
        jl_append_styled_indent(insertion, base, unit, JL_BYTE_WIDTH) != 0 ||
        jl_buffer_append(insertion, member->data, member->length) != 0 ||
        jl_buffer_string(insertion, newline) != 0 ||
        jl_buffer_append(insertion, base.data, base.length) != 0) {
        return JL_STATUS_FAILURE;
    }
    return 0;
}

static int jl_make_multiline_insertion(jl_buffer_t *insertion, const jl_object_t *object,
                                       const jl_buffer_t *member, const char *newline,
                                       jl_slice_t base, jl_slice_t unit, bool close_indent_only) {
    if (!close_indent_only && jl_buffer_string(insertion, newline) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (jl_buffer_append(insertion, unit.data, unit.length) != 0 ||
        jl_buffer_append(insertion, member->data, member->length) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (object->trailing_comma && jl_buffer_char(insertion, ',') != 0) {
        return JL_STATUS_FAILURE;
    }
    return jl_buffer_string(insertion, newline) == 0 &&
                   jl_buffer_append(insertion, base.data, base.length) == 0
               ? 0
               : JL_STATUS_FAILURE;
}

static int jl_make_insertion(const char *text, size_t length, size_t object_start,
                             const jl_object_t *object, const jl_buffer_t *member,
                             jl_buffer_t *insertion) {
    jl_slice_t base;
    jl_slice_t unit;
    bool close_indent_only = false;
    jl_detect_indent(text, object, &base, &unit, &close_indent_only);
    const char *newline = jl_newline_style(text, length);

    size_t gap_start = object_start + JL_BYTE_WIDTH;
    if (object->member_count > 0U) {
        gap_start = object->trailing_comma ? object->last_comma_pos + JL_BYTE_WIDTH
                                           : object->last_value_end;
    }
    bool multiline = jl_range_has_newline(text, gap_start, object->close_pos);
    bool empty_tight = object->member_count == 0U && gap_start == object->close_pos;

    if (empty_tight) {
        return jl_make_tight_insertion(insertion, member, newline, base, unit);
    }

    if (multiline) {
        return jl_make_multiline_insertion(insertion, object, member, newline, base, unit,
                                           close_indent_only);
    }

    if (object->close_pos == gap_start ||
        !jl_is_space((unsigned char)text[object->close_pos - JL_BYTE_WIDTH])) {
        if (jl_buffer_char(insertion, ' ') != 0) {
            return JL_STATUS_FAILURE;
        }
    }
    if (jl_buffer_append(insertion, member->data, member->length) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (object->trailing_comma && jl_buffer_char(insertion, ',') != 0) {
        return JL_STATUS_FAILURE;
    }
    return jl_buffer_char(insertion, ' ');
}

static int jl_apply_edits(const char *source, size_t source_length, jl_edit_t *edits,
                          size_t edit_count, char **result_out, size_t *result_length_out) {
    if (edit_count == JL_TWO_BYTES && edits[JL_BYTE_WIDTH].start < edits[0].start) {
        jl_edit_t swap = edits[0];
        edits[0] = edits[JL_BYTE_WIDTH];
        edits[JL_BYTE_WIDTH] = swap;
    }
    size_t result_length = source_length;
    size_t previous_end = 0;
    for (size_t i = 0; i < edit_count; i++) {
        if (edits[i].start < previous_end || edits[i].end < edits[i].start ||
            edits[i].end > source_length) {
            return JL_STATUS_FAILURE;
        }
        size_t removed = edits[i].end - edits[i].start;
        if (removed > result_length) {
            return JL_STATUS_FAILURE;
        }
        result_length -= removed;
        if (edits[i].replacement_length > SIZE_MAX - result_length) {
            return JL_STATUS_FAILURE;
        }
        result_length += edits[i].replacement_length;
        previous_end = edits[i].end;
    }
    if (result_length > JL_MAX_FILE_BYTES || result_length == SIZE_MAX) {
        return JL_STATUS_FAILURE;
    }

    char *result = malloc(result_length + JL_BYTE_WIDTH);
    if (!result) {
        return JL_STATUS_FAILURE;
    }
    size_t source_pos = 0;
    size_t result_pos = 0;
    for (size_t i = 0; i < edit_count; i++) {
        size_t prefix_length = edits[i].start - source_pos;
        memcpy(result + result_pos, source + source_pos, prefix_length);
        result_pos += prefix_length;
        if (edits[i].replacement_length > 0U) {
            memcpy(result + result_pos, edits[i].replacement, edits[i].replacement_length);
            result_pos += edits[i].replacement_length;
        }
        source_pos = edits[i].end;
    }
    memcpy(result + result_pos, source + source_pos, source_length - source_pos);
    result_pos += source_length - source_pos;
    result[result_pos] = '\0';
    *result_out = result;
    *result_length_out = result_pos;
    return 0;
}

static bool jl_snapshot_state_equal(const jl_file_snapshot_t *left,
                                    const jl_file_snapshot_t *right) {
    if (left->exists != right->exists) {
        return false;
    }
    if (!left->exists) {
        return true;
    }
#ifdef _WIN32
    return left->volume_serial == right->volume_serial &&
           left->file_index_high == right->file_index_high &&
           left->file_index_low == right->file_index_low && left->attributes == right->attributes &&
           left->link_count == right->link_count &&
           left->creation_time.dwLowDateTime == right->creation_time.dwLowDateTime &&
           left->creation_time.dwHighDateTime == right->creation_time.dwHighDateTime &&
           left->write_time.dwLowDateTime == right->write_time.dwLowDateTime &&
           left->write_time.dwHighDateTime == right->write_time.dwHighDateTime &&
           left->size == right->size;
#else
    return left->device == right->device && left->inode == right->inode &&
           left->mode == right->mode && left->link_count == right->link_count &&
           left->owner == right->owner && left->group == right->group &&
           left->size == right->size && left->modified_sec == right->modified_sec &&
           left->modified_nsec == right->modified_nsec && left->changed_sec == right->changed_sec &&
           left->changed_nsec == right->changed_nsec;
#endif
}

#ifdef _WIN32
static int jl_snapshot_from_handle(HANDLE handle, jl_file_snapshot_t *snapshot) {
    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        info.nNumberOfLinks != JL_BYTE_WIDTH ||
        (info.nFileIndexHigh == 0U && info.nFileIndexLow == 0U)) {
        return JL_STATUS_FAILURE;
    }
    enum { JL_WIN32_HIGH_DWORD_SHIFT = 32U };
    uint64_t size =
        ((uint64_t)info.nFileSizeHigh << JL_WIN32_HIGH_DWORD_SHIFT) | (uint64_t)info.nFileSizeLow;
    if (size > JL_MAX_FILE_BYTES) {
        return JL_STATUS_FAILURE;
    }
    *snapshot = (jl_file_snapshot_t){
        .exists = true,
        .volume_serial = info.dwVolumeSerialNumber,
        .file_index_high = info.nFileIndexHigh,
        .file_index_low = info.nFileIndexLow,
        .attributes = info.dwFileAttributes,
        .link_count = info.nNumberOfLinks,
        .creation_time = info.ftCreationTime,
        .write_time = info.ftLastWriteTime,
        .size = size,
    };
    return 0;
}
#else
static int jl_snapshot_from_stat(const struct stat *state, jl_file_snapshot_t *snapshot) {
    if (!S_ISREG(state->st_mode) || state->st_ino == 0 || state->st_nlink != JL_BYTE_WIDTH ||
        state->st_size < 0 || (uint64_t)state->st_size > JL_MAX_FILE_BYTES ||
        (state->st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0) {
        return JL_STATUS_FAILURE;
    }
    *snapshot = (jl_file_snapshot_t){
        .exists = true,
        .device = state->st_dev,
        .inode = state->st_ino,
        .mode = state->st_mode,
        .link_count = state->st_nlink,
        .owner = state->st_uid,
        .group = state->st_gid,
        .size = state->st_size,
#ifdef __APPLE__
        .modified_sec = state->st_mtimespec.tv_sec,
        .modified_nsec = state->st_mtimespec.tv_nsec,
        .changed_sec = state->st_ctimespec.tv_sec,
        .changed_nsec = state->st_ctimespec.tv_nsec,
#else
        .modified_sec = state->st_mtim.tv_sec,
        .modified_nsec = state->st_mtim.tv_nsec,
        .changed_sec = state->st_ctim.tv_sec,
        .changed_nsec = state->st_ctim.tv_nsec,
#endif
    };
    return 0;
}
#endif

static int jl_read_file(const char *path, char **content_out, size_t *length_out, bool *missing_out,
                        jl_file_snapshot_t *snapshot_out) {
    *content_out = NULL;
    *length_out = 0;
    *missing_out = false;
    memset(snapshot_out, 0, sizeof(*snapshot_out));
#ifdef _WIN32
    wchar_t *wide_path = cbm_utf8_to_wide(path);
    if (!wide_path) {
        return JL_STATUS_FAILURE;
    }
    HANDLE handle = CreateFileW(
        wide_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wide_path);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            *missing_out = true;
            return 0;
        }
        return JL_STATUS_FAILURE;
    }
    jl_file_snapshot_t before;
    if (jl_snapshot_from_handle(handle, &before) != 0) {
        CloseHandle(handle);
        return JL_STATUS_FAILURE;
    }
    size_t length = (size_t)before.size;
    char *content = malloc(length + JL_BYTE_WIDTH);
    if (!content) {
        CloseHandle(handle);
        return JL_STATUS_FAILURE;
    }
    DWORD read_count = 0U;
    BOOL read_ok = ReadFile(handle, content, (DWORD)length, &read_count, NULL);
    jl_file_snapshot_t after;
    int after_result = jl_snapshot_from_handle(handle, &after);
    BOOL close_ok = CloseHandle(handle);
    if (!read_ok || read_count != (DWORD)length || after_result != 0 || !close_ok ||
        !jl_snapshot_state_equal(&before, &after)) {
        free(content);
        return JL_STATUS_FAILURE;
    }
#else
#ifndef O_NOFOLLOW
    (void)path;
    return JL_STATUS_FAILURE;
#else
    int flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int descriptor = open(path, flags);
    if (descriptor < 0) {
        if (errno == ENOENT) {
            struct stat path_state;
            if (lstat(path, &path_state) == 0 || errno != ENOENT) {
                return JL_STATUS_FAILURE;
            }
            *missing_out = true;
            return 0;
        }
        return JL_STATUS_FAILURE;
    }
    struct stat before_state;
    jl_file_snapshot_t before;
    if (fstat(descriptor, &before_state) != 0 ||
        jl_snapshot_from_stat(&before_state, &before) != 0) {
        close(descriptor);
        return JL_STATUS_FAILURE;
    }
    FILE *file = fdopen(descriptor, "rb");
    if (!file) {
        close(descriptor);
        return JL_STATUS_FAILURE;
    }
    size_t length = (size_t)before.size;
    char *content = malloc(length + JL_BYTE_WIDTH);
    if (!content) {
        if (fclose(file) != 0) {
            return JL_STATUS_FAILURE;
        }
        return JL_STATUS_FAILURE;
    }
    size_t read_count = fread(content, JL_BYTE_WIDTH, length, file);
    int read_failed = ferror(file);
    struct stat after_state;
    jl_file_snapshot_t after;
    int after_result = fstat(cbm_fileno(file), &after_state) == 0
                           ? jl_snapshot_from_stat(&after_state, &after)
                           : JL_STATUS_FAILURE;
    int close_failed = fclose(file);
    if (read_count != length || read_failed || after_result != 0 || close_failed != 0 ||
        !jl_snapshot_state_equal(&before, &after)) {
        free(content);
        return JL_STATUS_FAILURE;
    }
#endif
#endif
    content[length] = '\0';
    *content_out = content;
    *length_out = length;
    *snapshot_out = before;
    return 0;
}

static char *jl_parent_directory(const char *path) {
    const char *separator = strrchr(path, '/');
#ifdef _WIN32
    const char *backslash = strrchr(path, '\\');
    if (!separator || (backslash && backslash > separator)) {
        separator = backslash;
    }
#endif
    if (!separator) {
        return cbm_strdup(".");
    }
    if (separator == path) {
        return cbm_strdup("/");
    }
    return cbm_strndup(path, (size_t)(separator - path));
}

static int jl_ensure_parent(const char *path) {
    char *parent = jl_parent_directory(path);
    if (!parent) {
        return JL_STATUS_FAILURE;
    }
    int result = strcmp(parent, ".") == 0 || cbm_mkdir_p(parent, JL_PARENT_DIRECTORY_MODE)
                     ? 0
                     : JL_STATUS_FAILURE;
    free(parent);
    return result;
}

static int jl_snapshot_matches_path(const char *path, const char *expected_content,
                                    size_t expected_length,
                                    const jl_file_snapshot_t *expected_snapshot) {
    char *current_content = NULL;
    size_t current_length = 0U;
    bool missing = false;
    jl_file_snapshot_t current_snapshot;
    if (jl_read_file(path, &current_content, &current_length, &missing, &current_snapshot) != 0) {
        return JL_STATUS_FAILURE;
    }
    bool matches = false;
    if (!expected_snapshot->exists) {
        matches = missing;
    } else {
        matches = !missing && current_length == expected_length &&
                  jl_snapshot_state_equal(expected_snapshot, &current_snapshot) &&
                  (expected_length == 0U ||
                   memcmp(current_content, expected_content, expected_length) == 0);
    }
    free(current_content);
    return matches ? 0 : JL_STATUS_FAILURE;
}

#ifndef _WIN32
static int jl_sync_parent_directory(const char *path) {
    char *parent = jl_parent_directory(path);
    if (!parent) {
        return JL_STATUS_FAILURE;
    }
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int descriptor = open(parent, flags);
    free(parent);
    if (descriptor < 0) {
        return JL_STATUS_FAILURE;
    }
    struct stat state;
    int result = fstat(descriptor, &state) == 0 && S_ISDIR(state.st_mode) && fsync(descriptor) == 0
                     ? 0
                     : JL_STATUS_FAILURE;
    if (close(descriptor) != 0) {
        result = JL_STATUS_FAILURE;
    }
    return result;
}
#endif

static int jl_replace_atomic(const char *temp_path, const char *path, bool destination_exists) {
#ifdef _WIN32
    wchar_t *wide_temp = cbm_utf8_to_wide(temp_path);
    wchar_t *wide_path = cbm_utf8_to_wide(path);
    if (!wide_temp || !wide_path) {
        free(wide_temp);
        free(wide_path);
        return JL_STATUS_FAILURE;
    }
    /* ReplaceFileW retains the destination's ACL and other mergeable metadata;
     * refusing merge errors is safer than silently dropping that metadata. */
    BOOL replaced = destination_exists ? ReplaceFileW(wide_path, wide_temp, NULL,
                                                      REPLACEFILE_WRITE_THROUGH, NULL, NULL)
                                       : MoveFileExW(wide_temp, wide_path, MOVEFILE_WRITE_THROUGH);
    free(wide_temp);
    free(wide_path);
    return replaced ? 0 : JL_STATUS_FAILURE;
#else
    if (!destination_exists) {
        if (link(temp_path, path) != 0) {
            return JL_STATUS_FAILURE;
        }
        if (cbm_unlink(temp_path) != 0) {
            return JL_STATUS_FAILURE;
        }
        return jl_sync_parent_directory(path);
    }
    if (rename(temp_path, path) != 0) {
        return JL_STATUS_FAILURE;
    }
    return jl_sync_parent_directory(path);
#endif
}

static FILE *jl_open_temp_file(const char *path, char *temp_path, size_t temp_capacity) {
    for (unsigned attempt = 0; attempt < JL_TEMP_WRITE_ATTEMPTS; attempt++) {
        unsigned sequence =
            atomic_fetch_add_explicit(&jl_temp_sequence, JL_BYTE_WIDTH, memory_order_relaxed);
        int written = snprintf(temp_path, temp_capacity, "%s.cbm.tmp.%ld.%u", path,
                               (long)JL_PROCESS_ID(), sequence);
        if (written < 0 || (size_t)written >= temp_capacity) {
            return NULL;
        }
        errno = 0;
#ifdef _WIN32
        FILE *file = cbm_fopen(temp_path, "wbx");
#else
#ifndef O_NOFOLLOW
        return NULL;
#else
        int flags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        int descriptor = open(temp_path, flags, JL_TEMP_FILE_MODE);
        FILE *file = descriptor >= 0 ? fdopen(descriptor, "wb") : NULL;
        if (descriptor >= 0 && !file) {
            int saved_error = errno;
            close(descriptor);
            (void)cbm_unlink(temp_path);
            errno = saved_error;
        }
#endif
#endif
        if (file || errno != EEXIST) {
            return file;
        }
    }
    return NULL;
}

static int jl_write_temp_file(FILE *file, const char *content, size_t length,
                              const jl_file_snapshot_t *snapshot) {
    bool failed = fwrite(content, JL_BYTE_WIDTH, length, file) != length || fflush(file) != 0;
#ifndef _WIN32
    mode_t mode = snapshot->exists ? snapshot->mode & JL_PERMISSION_MASK : JL_TEMP_FILE_MODE;
    if (!failed && snapshot->exists &&
        fchown(cbm_fileno(file), snapshot->owner, snapshot->group) != 0) {
        failed = true;
    }
    if (!failed && fchmod(cbm_fileno(file), mode) != 0) {
        failed = true;
    }
#endif
    if (!failed && JL_SYNC(cbm_fileno(file)) != 0) {
        failed = true;
    }
    if (fclose(file) != 0) {
        failed = true;
    }
    return failed ? JL_STATUS_FAILURE : 0;
}

static int jl_verify_temp_file(const char *temp_path, const char *content, size_t length,
                               jl_file_snapshot_t *snapshot) {
    char *temp_content = NULL;
    size_t temp_length = 0U;
    bool temp_missing = false;
    int result = jl_read_file(temp_path, &temp_content, &temp_length, &temp_missing, snapshot);
    bool valid = result == 0 && !temp_missing && temp_length == length &&
                 (length == 0U || memcmp(temp_content, content, length) == 0);
    free(temp_content);
    return valid ? 0 : JL_STATUS_FAILURE;
}

static int jl_write_atomic(const char *path, const char *content, size_t length,
                           const char *expected_content, size_t expected_length,
                           const jl_file_snapshot_t *expected_snapshot) {
    if (jl_ensure_parent(path) != 0) {
        return JL_STATUS_FAILURE;
    }
    size_t path_length = strlen(path);
    if (path_length > SIZE_MAX - JL_TEMP_SUFFIX_CAPACITY) {
        return JL_STATUS_FAILURE;
    }
    size_t temp_capacity = path_length + JL_TEMP_SUFFIX_CAPACITY;
    char *temp_path = malloc(temp_capacity);
    if (!temp_path) {
        return JL_STATUS_FAILURE;
    }

    FILE *file = jl_open_temp_file(path, temp_path, temp_capacity);
    if (!file) {
        free(temp_path);
        return JL_STATUS_FAILURE;
    }
    if (jl_write_temp_file(file, content, length, expected_snapshot) != 0) {
        cbm_unlink(temp_path);
        free(temp_path);
        return JL_STATUS_FAILURE;
    }
    jl_file_snapshot_t temp_snapshot;
    if (jl_verify_temp_file(temp_path, content, length, &temp_snapshot) != 0) {
        cbm_unlink(temp_path);
        free(temp_path);
        return JL_STATUS_FAILURE;
    }
#ifdef CBM_JSON_LIKE_ENABLE_TEST_API
    if (jl_precommit_test_hook) {
        jl_precommit_test_hook(path, jl_precommit_test_context);
    }
#endif
    if (jl_snapshot_matches_path(path, expected_content, expected_length, expected_snapshot) != 0) {
        cbm_unlink(temp_path);
        free(temp_path);
        return JL_STATUS_FAILURE;
    }
#ifdef CBM_JSON_LIKE_ENABLE_TEST_API
    if (jl_prepublish_test_hook) {
        jl_prepublish_test_hook(path, jl_prepublish_test_context);
    }
#endif
    if (jl_snapshot_matches_path(path, expected_content, expected_length, expected_snapshot) != 0 ||
        jl_snapshot_matches_path(temp_path, content, length, &temp_snapshot) != 0 ||
        jl_replace_atomic(temp_path, path, expected_snapshot->exists) != 0) {
        cbm_unlink(temp_path);
        free(temp_path);
        return JL_STATUS_FAILURE;
    }
    free(temp_path);
    return 0;
}

static int jl_decode_utf8(const unsigned char *text, size_t remaining, uint32_t *codepoint,
                          size_t *byte_count) {
    if (remaining == 0U) {
        return JL_STATUS_FAILURE;
    }
    unsigned char first = text[0];
    if (first < JL_UTF8_CONTINUATION_BYTE) {
        *codepoint = first;
        *byte_count = JL_BYTE_WIDTH;
        return 0;
    }
    size_t count = 0;
    uint32_t value = 0;
    uint32_t minimum = 0;
    if (first >= JL_UTF8_TWO_BYTE_LEAD_MIN && first <= JL_UTF8_TWO_BYTE_LEAD_MAX) {
        count = JL_TWO_BYTES;
        value = first & JL_UTF8_TWO_BYTE_PAYLOAD_MASK;
        minimum = JL_UTF8_CONTINUATION_BYTE;
    } else if (first >= JL_UTF8_THREE_BYTE_LEAD && first <= JL_UTF8_THREE_BYTE_LEAD_MAX) {
        count = JL_THREE_BYTES;
        value = first & JL_HEX_NIBBLE_MASK;
        minimum = JL_UTF8_TWO_BYTE_MAX + JL_BYTE_WIDTH;
    } else if (first >= JL_UTF8_FOUR_BYTE_LEAD && first <= JL_UTF8_FOUR_BYTE_LEAD_MAX) {
        count = JL_FOUR_BYTES;
        value = first & JL_UTF8_FOUR_BYTE_PAYLOAD_MASK;
        minimum = JL_UNICODE_SUPPLEMENTARY_BASE;
    } else {
        return JL_STATUS_FAILURE;
    }
    if (remaining < count) {
        return JL_STATUS_FAILURE;
    }
    for (size_t i = JL_BYTE_WIDTH; i < count; i++) {
        if ((text[i] & JL_UTF8_TWO_BYTE_LEAD) != JL_UTF8_CONTINUATION_BYTE) {
            return JL_STATUS_FAILURE;
        }
        value = (value << JL_UTF8_TWO_BYTE_SHIFT) | (text[i] & JL_UTF8_PAYLOAD_MASK);
    }
    if (value < minimum || value > JL_UTF8_CODEPOINT_MAX ||
        (value >= JL_UTF16_SURROGATE_MIN && value <= JL_UTF16_SURROGATE_MAX)) {
        return JL_STATUS_FAILURE;
    }
    *codepoint = value;
    *byte_count = count;
    return 0;
}

static int jl_validate_utf8(const char *text, size_t length) {
    size_t pos = 0;
    while (pos < length) {
        uint32_t codepoint = 0;
        size_t byte_count = 0;
        if (jl_decode_utf8((const unsigned char *)text + pos, length - pos, &codepoint,
                           &byte_count) != 0) {
            return JL_STATUS_FAILURE;
        }
        pos += byte_count;
    }
    return 0;
}

static int jl_validate_key(const char *key) {
    if (!key) {
        return JL_STATUS_FAILURE;
    }
    size_t length = strlen(key);
    if (length > JL_MAX_KEY_BYTES) {
        return JL_STATUS_FAILURE;
    }
    size_t pos = 0;
    while (pos < length) {
        uint32_t codepoint = 0;
        size_t byte_count = 0;
        if (jl_decode_utf8((const unsigned char *)key + pos, length - pos, &codepoint,
                           &byte_count) != 0 ||
            codepoint < JL_JSON_CONTROL_CODEPOINT_LIMIT ||
            (codepoint >= JL_UTF8_ASCII_MAX && codepoint <= JL_UTF8_C1_CONTROL_MAX)) {
            return JL_STATUS_FAILURE;
        }
        pos += byte_count;
    }
    return 0;
}

static int jl_validate_string_value(const char *value) {
    if (!value) {
        return JL_STATUS_FAILURE;
    }
    size_t length = strlen(value);
    return length <= JL_MAX_FILE_BYTES && jl_validate_utf8(value, length) == 0 ? 0
                                                                               : JL_STATUS_FAILURE;
}

static int jl_validate_arguments(const char *file_path, const char *const *object_path,
                                 size_t path_len, const char *entry_key) {
    if (!file_path || !*file_path || !object_path || !entry_key || path_len >= JL_MAX_DEPTH) {
        return JL_STATUS_FAILURE;
    }
    if (jl_validate_key(entry_key) != 0) {
        return JL_STATUS_FAILURE;
    }
    for (size_t i = 0; i < path_len; i++) {
        if (jl_validate_key(object_path[i]) != 0) {
            return JL_STATUS_FAILURE;
        }
    }
    return 0;
}

static int jl_build_fresh(const char *const *object_path, size_t path_len, const char *entry_key,
                          const char *entry_json, size_t entry_length, char **result_out,
                          size_t *result_length_out) {
    jl_buffer_t result = {0};
    static const char indent[] = "  ";
    if (jl_buffer_string(&result, "{\n") != 0) {
        free(result.data);
        return JL_STATUS_FAILURE;
    }
    for (size_t i = 0; i < path_len; i++) {
        if (jl_append_repeated(&result, indent, JL_TWO_BYTES, i + JL_BYTE_WIDTH) != 0 ||
            jl_append_quoted_key(&result, object_path[i]) != 0 ||
            jl_buffer_string(&result, ": {\n") != 0) {
            free(result.data);
            return JL_STATUS_FAILURE;
        }
    }
    if (jl_append_repeated(&result, indent, JL_TWO_BYTES, path_len + JL_BYTE_WIDTH) != 0 ||
        jl_append_quoted_key(&result, entry_key) != 0 || jl_buffer_string(&result, ": ") != 0 ||
        jl_buffer_append(&result, entry_json, entry_length) != 0 ||
        jl_buffer_char(&result, '\n') != 0) {
        free(result.data);
        return JL_STATUS_FAILURE;
    }
    for (size_t depth = path_len; depth > 0U; depth--) {
        if (jl_append_repeated(&result, indent, JL_TWO_BYTES, depth) != 0 ||
            jl_buffer_string(&result, "}\n") != 0) {
            free(result.data);
            return JL_STATUS_FAILURE;
        }
    }
    if (jl_buffer_string(&result, "}\n") != 0) {
        free(result.data);
        return JL_STATUS_FAILURE;
    }
    *result_out = result.data;
    *result_length_out = result.length;
    return 0;
}

static int jl_insert_member(const char *source, size_t source_length, size_t object_start,
                            const jl_object_t *object, const char *const *object_path,
                            size_t path_len, size_t missing_path_index, const char *entry_key,
                            const char *entry_json, size_t entry_length, char **result_out,
                            size_t *result_length_out) {
    jl_slice_t base;
    jl_slice_t unit;
    bool close_indent_only = false;
    jl_detect_indent(source, object, &base, &unit, &close_indent_only);
    (void)close_indent_only;

    jl_buffer_t member = {0};
    jl_buffer_t insertion = {0};
    const char *newline = jl_newline_style(source, source_length);
    int result = jl_build_member(&member, object_path, path_len, missing_path_index, entry_key,
                                 entry_json, entry_length, newline, base, unit);
    if (result == 0) {
        result =
            jl_make_insertion(source, source_length, object_start, object, &member, &insertion);
    }
    if (result != 0) {
        free(member.data);
        free(insertion.data);
        return JL_STATUS_FAILURE;
    }

    jl_edit_t edits[JL_EDIT_PAIR_CAPACITY];
    size_t edit_count = 0;
    if (object->member_count > 0U && !object->trailing_comma) {
        edits[edit_count++] = (jl_edit_t){
            .start = object->last_value_end,
            .end = object->last_value_end,
            .replacement = ",",
            .replacement_length = JL_BYTE_WIDTH,
        };
    }
    edits[edit_count++] = (jl_edit_t){
        .start = object->close_pos,
        .end = object->close_pos,
        .replacement = insertion.data,
        .replacement_length = insertion.length,
    };
    result =
        jl_apply_edits(source, source_length, edits, edit_count, result_out, result_length_out);
    free(member.data);
    free(insertion.data);
    return result;
}

static int jl_insert_array_string(const char *source, size_t source_length, size_t array_start,
                                  const jl_array_t *array, const char *string_value,
                                  char **result_out, size_t *result_length_out) {
    jl_buffer_t element = {0};
    jl_buffer_t insertion = {0};
    if (jl_append_quoted_string(&element, string_value) != 0) {
        free(element.data);
        return JL_STATUS_FAILURE;
    }

    jl_object_t style = {
        .close_pos = array->close_pos,
        .first_key_start = array->first_value_start,
        .last_value_end = array->last_value_end,
        .last_comma_pos = array->last_comma_pos,
        .member_count = array->element_count,
        .trailing_comma = array->trailing_comma,
    };
    int result =
        jl_make_insertion(source, source_length, array_start, &style, &element, &insertion);
    if (result != 0) {
        free(element.data);
        free(insertion.data);
        return JL_STATUS_FAILURE;
    }

    jl_edit_t edits[JL_EDIT_PAIR_CAPACITY];
    size_t edit_count = 0;
    if (array->element_count > 0U && !array->trailing_comma) {
        edits[edit_count++] = (jl_edit_t){
            .start = array->last_value_end,
            .end = array->last_value_end,
            .replacement = ",",
            .replacement_length = JL_BYTE_WIDTH,
        };
    }
    edits[edit_count++] = (jl_edit_t){
        .start = array->close_pos,
        .end = array->close_pos,
        .replacement = insertion.data,
        .replacement_length = insertion.length,
    };
    result =
        jl_apply_edits(source, source_length, edits, edit_count, result_out, result_length_out);
    free(element.data);
    free(insertion.data);
    return result;
}

static int jl_write_document(const char *path, const char *content, size_t length,
                             const char *expected_content, size_t expected_length,
                             const jl_file_snapshot_t *expected_snapshot) {
    size_t root = 0;
    if (jl_validate_document(content, length, &root) != 0) {
        return JL_STATUS_FAILURE;
    }
    return jl_write_atomic(path, content, length, expected_content, expected_length,
                           expected_snapshot);
}

#ifdef CBM_JSON_LIKE_ENABLE_TEST_API
void cbm_json_like_set_precommit_hook_for_testing(cbm_json_like_precommit_test_hook_t hook,
                                                  void *context) {
    jl_precommit_test_hook = hook;
    jl_precommit_test_context = context;
}

void cbm_json_like_set_prepublish_hook_for_testing(cbm_json_like_precommit_test_hook_t hook,
                                                   void *context) {
    jl_prepublish_test_hook = hook;
    jl_prepublish_test_context = context;
}
#endif

int cbm_json_like_read_document(const char *file_path, char **content_out, size_t *length_out) {
    if (!file_path || !content_out || !length_out) {
        return JL_STATUS_FAILURE;
    }
    bool missing = false;
    jl_file_snapshot_t snapshot;
    if (jl_read_file(file_path, content_out, length_out, &missing, &snapshot) != 0) {
        return JL_STATUS_FAILURE;
    }
    return missing ? JL_STATUS_NO_MATCH : 0;
}

int cbm_json_like_get_raw_entry(const char *file_path, const char *const *object_path,
                                size_t path_len, const char *entry_key, char **value_json_out,
                                size_t *value_length_out) {
    if (!value_json_out || !value_length_out) {
        return JL_STATUS_FAILURE;
    }
    *value_json_out = NULL;
    *value_length_out = 0U;
    if (jl_validate_arguments(file_path, object_path, path_len, entry_key) != 0) {
        return JL_STATUS_FAILURE;
    }

    char *source = NULL;
    size_t source_length = 0U;
    bool missing = false;
    jl_file_snapshot_t snapshot;
    if (jl_read_file(file_path, &source, &source_length, &missing, &snapshot) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (missing || source_length == 0U) {
        free(source);
        return JL_STATUS_NO_MATCH;
    }

    size_t object_start = 0U;
    if (jl_validate_document(source, source_length, &object_start) != 0) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    for (size_t i = 0U; i < path_len; ++i) {
        jl_object_t parent;
        if (jl_scan_object(source, source_length, object_start, object_path[i], &parent) != 0 ||
            parent.match_count > JL_BYTE_WIDTH) {
            free(source);
            return JL_STATUS_FAILURE;
        }
        if (parent.match_count == 0U) {
            free(source);
            return JL_STATUS_NO_MATCH;
        }
        if (source[parent.match.value_start] != '{') {
            free(source);
            return JL_STATUS_FAILURE;
        }
        object_start = parent.match.value_start;
    }

    jl_object_t object;
    if (jl_scan_object(source, source_length, object_start, entry_key, &object) != 0 ||
        object.match_count > JL_BYTE_WIDTH) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    if (object.match_count == 0U) {
        free(source);
        return JL_STATUS_NO_MATCH;
    }
    size_t value_length = object.match.value_end - object.match.value_start;
    char *value = (char *)malloc(value_length + JL_BYTE_WIDTH);
    if (!value) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    memcpy(value, source + object.match.value_start, value_length);
    value[value_length] = '\0';
    free(source);
    *value_json_out = value;
    *value_length_out = value_length;
    return 0;
}

static int jl_insert_and_write(const char *file_path, const char *source, size_t source_length,
                               const jl_file_snapshot_t *snapshot, size_t object_start,
                               const jl_object_t *object, const char *const *object_path,
                               size_t path_len, size_t missing_path_index, const char *entry_key,
                               const char *entry_value, size_t entry_length) {
    char *updated = NULL;
    size_t updated_length = 0;
    int result = jl_insert_member(source, source_length, object_start, object, object_path,
                                  path_len, missing_path_index, entry_key, entry_value,
                                  entry_length, &updated, &updated_length);
    if (result == 0) {
        result =
            jl_write_document(file_path, updated, updated_length, source, source_length, snapshot);
    }
    free(updated);
    return result;
}

static bool jl_expected_content_matches(bool missing, const char *source, size_t source_length,
                                        const char *expected, size_t expected_length) {
    if (!expected) {
        return missing;
    }
    return !missing && source_length == expected_length &&
           (expected_length == 0U || memcmp(source, expected, expected_length) == 0);
}

static int jl_write_fresh_entry(const char *file_path, const char *const *object_path,
                                size_t path_len, const char *entry_key, const char *entry_value,
                                size_t entry_length, const char *source, size_t source_length,
                                const jl_file_snapshot_t *snapshot) {
    char *fresh = NULL;
    size_t fresh_length = 0;
    int result = jl_build_fresh(object_path, path_len, entry_key, entry_value, entry_length, &fresh,
                                &fresh_length);
    if (result == 0) {
        result = jl_write_document(file_path, fresh, fresh_length, source, source_length, snapshot);
    }
    free(fresh);
    return result;
}

static int jl_upsert_entry(const char *file_path, const char *const *object_path, size_t path_len,
                           const char *entry_key, const char *entry_json, bool enforce_expected,
                           const char *expected_content, size_t expected_length) {
    if (jl_validate_arguments(file_path, object_path, path_len, entry_key) != 0 || !entry_json) {
        return JL_STATUS_FAILURE;
    }
    size_t entry_start = 0;
    size_t entry_length = 0;
    if (jl_validate_entry(entry_json, &entry_start, &entry_length) != 0) {
        return JL_STATUS_FAILURE;
    }
    const char *entry_value = entry_json + entry_start;

    char *source = NULL;
    size_t source_length = 0;
    bool missing = false;
    jl_file_snapshot_t snapshot;
    if (jl_read_file(file_path, &source, &source_length, &missing, &snapshot) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (enforce_expected && !jl_expected_content_matches(missing, source, source_length,
                                                         expected_content, expected_length)) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    if (missing || source_length == 0U) {
        int result = jl_write_fresh_entry(file_path, object_path, path_len, entry_key, entry_value,
                                          entry_length, source, source_length, &snapshot);
        free(source);
        return result;
    }

    size_t object_start = 0;
    if (jl_validate_document(source, source_length, &object_start) != 0) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    for (size_t i = 0; i < path_len; i++) {
        jl_object_t object;
        if (jl_scan_object(source, source_length, object_start, object_path[i], &object) != 0 ||
            object.match_count > JL_BYTE_WIDTH) {
            free(source);
            return JL_STATUS_FAILURE;
        }
        if (object.match_count == 0U) {
            int result = jl_insert_and_write(file_path, source, source_length, &snapshot,
                                             object_start, &object, object_path, path_len, i,
                                             entry_key, entry_value, entry_length);
            free(source);
            return result;
        }
        if (source[object.match.value_start] != '{') {
            free(source);
            return JL_STATUS_FAILURE;
        }
        object_start = object.match.value_start;
    }

    jl_object_t object;
    if (jl_scan_object(source, source_length, object_start, entry_key, &object) != 0 ||
        object.match_count > JL_BYTE_WIDTH) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    if (object.match_count == 0U) {
        int result = jl_insert_and_write(file_path, source, source_length, &snapshot, object_start,
                                         &object, object_path, path_len, SIZE_MAX, entry_key,
                                         entry_value, entry_length);
        free(source);
        return result;
    }

    size_t old_length = object.match.value_end - object.match.value_start;
    if (old_length == entry_length &&
        memcmp(source + object.match.value_start, entry_value, entry_length) == 0) {
        free(source);
        return 0;
    }
    jl_edit_t edit = {
        .start = object.match.value_start,
        .end = object.match.value_end,
        .replacement = entry_value,
        .replacement_length = entry_length,
    };
    char *updated = NULL;
    size_t updated_length = 0;
    int result =
        jl_apply_edits(source, source_length, &edit, JL_BYTE_WIDTH, &updated, &updated_length);
    if (result == 0) {
        result =
            jl_write_document(file_path, updated, updated_length, source, source_length, &snapshot);
    }
    free(updated);
    free(source);
    return result;
}

int cbm_json_like_upsert_entry(const char *file_path, const char *const *object_path,
                               size_t path_len, const char *entry_key, const char *entry_json) {
    return jl_upsert_entry(file_path, object_path, path_len, entry_key, entry_json, false, NULL,
                           0U);
}

int cbm_json_like_upsert_entry_if_unchanged(const char *file_path, const char *const *object_path,
                                            size_t path_len, const char *entry_key,
                                            const char *entry_json, const char *expected_content,
                                            size_t expected_length) {
    return jl_upsert_entry(file_path, object_path, path_len, entry_key, entry_json, true,
                           expected_content, expected_length);
}

static int jl_resolve_object_path(const char *source, size_t source_length,
                                  const char *const *object_path, size_t path_len,
                                  size_t *object_start) {
    if (jl_validate_document(source, source_length, object_start) != 0) {
        return JL_STATUS_FAILURE;
    }
    for (size_t i = 0; i < path_len; i++) {
        jl_object_t object;
        if (jl_scan_object(source, source_length, *object_start, object_path[i], &object) != 0 ||
            object.match_count > JL_BYTE_WIDTH) {
            return JL_STATUS_FAILURE;
        }
        if (object.match_count == 0U) {
            return JL_STATUS_NO_MATCH;
        }
        if (source[object.match.value_start] != '{') {
            return JL_STATUS_FAILURE;
        }
        *object_start = object.match.value_start;
    }
    return 0;
}

static int jl_remove_entry(const char *file_path, const char *const *object_path, size_t path_len,
                           const char *entry_key, bool enforce_expected,
                           const char *expected_content, size_t expected_length) {
    if (jl_validate_arguments(file_path, object_path, path_len, entry_key) != 0) {
        return JL_STATUS_FAILURE;
    }
    char *source = NULL;
    size_t source_length = 0;
    bool missing = false;
    jl_file_snapshot_t snapshot;
    if (jl_read_file(file_path, &source, &source_length, &missing, &snapshot) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (enforce_expected) {
        bool expected_missing = expected_content == NULL;
        bool content_matches = expected_missing
                                   ? missing
                                   : !missing && source_length == expected_length &&
                                         (expected_length == 0U ||
                                          memcmp(source, expected_content, expected_length) == 0);
        if (!content_matches) {
            free(source);
            return JL_STATUS_FAILURE;
        }
    }
    if (missing || source_length == 0U) {
        free(source);
        return 0;
    }

    size_t object_start = 0;
    int path_result =
        jl_resolve_object_path(source, source_length, object_path, path_len, &object_start);
    if (path_result != 0) {
        free(source);
        return path_result == JL_STATUS_NO_MATCH ? 0 : JL_STATUS_FAILURE;
    }

    jl_object_t object;
    if (jl_scan_object(source, source_length, object_start, entry_key, &object) != 0 ||
        object.match_count > JL_BYTE_WIDTH) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    if (object.match_count == 0U) {
        free(source);
        return 0;
    }

    jl_edit_t edits[JL_EDIT_PAIR_CAPACITY];
    size_t edit_count = 0;
    edits[edit_count++] = (jl_edit_t){
        .start = jl_leading_whitespace_start(source, object.match.key_start),
        .end = object.match.value_end,
        .replacement = NULL,
        .replacement_length = 0,
    };
    if (object.match.comma_pos != SIZE_MAX) {
        edits[edit_count++] = (jl_edit_t){
            .start = object.match.comma_pos,
            .end = object.match.comma_pos + JL_BYTE_WIDTH,
            .replacement = NULL,
            .replacement_length = 0,
        };
    } else if (object.match.previous_comma_pos != SIZE_MAX) {
        edits[edit_count++] = (jl_edit_t){
            .start = object.match.previous_comma_pos,
            .end = object.match.previous_comma_pos + JL_BYTE_WIDTH,
            .replacement = NULL,
            .replacement_length = 0,
        };
    }

    char *updated = NULL;
    size_t updated_length = 0;
    int result =
        jl_apply_edits(source, source_length, edits, edit_count, &updated, &updated_length);
    if (result == 0) {
        result =
            jl_write_document(file_path, updated, updated_length, source, source_length, &snapshot);
    }
    free(updated);
    free(source);
    return result;
}

int cbm_json_like_remove_entry(const char *file_path, const char *const *object_path,
                               size_t path_len, const char *entry_key) {
    return jl_remove_entry(file_path, object_path, path_len, entry_key, false, NULL, 0U);
}

int cbm_json_like_remove_entry_if_unchanged(const char *file_path, const char *const *object_path,
                                            size_t path_len, const char *entry_key,
                                            const char *expected_content, size_t expected_length) {
    return jl_remove_entry(file_path, object_path, path_len, entry_key, true, expected_content,
                           expected_length);
}

static int jl_build_single_string_array(const char *string_value, jl_buffer_t *array_json) {
    jl_buffer_t built = {0};
    if (jl_buffer_char(&built, '[') == 0 && jl_append_quoted_string(&built, string_value) == 0 &&
        jl_buffer_char(&built, ']') == 0) {
        *array_json = built;
        return 0;
    }
    free(built.data);
    return JL_STATUS_FAILURE;
}

static int jl_add_unique_existing(const char *file_path, const char *const *object_path,
                                  size_t path_len, const char *array_key, const char *string_value,
                                  const jl_buffer_t *array_json, char *source, size_t source_length,
                                  const jl_file_snapshot_t *snapshot) {
    size_t object_start = 0;
    if (jl_validate_document(source, source_length, &object_start) != 0) {
        return JL_STATUS_FAILURE;
    }
    for (size_t i = 0; i < path_len; i++) {
        jl_object_t parent;
        if (jl_scan_object(source, source_length, object_start, object_path[i], &parent) != 0 ||
            parent.match_count > JL_BYTE_WIDTH) {
            return JL_STATUS_FAILURE;
        }
        if (parent.match_count == 0U) {
            return jl_insert_and_write(file_path, source, source_length, snapshot, object_start,
                                       &parent, object_path, path_len, i, array_key,
                                       array_json->data, array_json->length);
        }
        if (source[parent.match.value_start] != '{') {
            return JL_STATUS_FAILURE;
        }
        object_start = parent.match.value_start;
    }
    jl_object_t object;
    if (jl_scan_object(source, source_length, object_start, array_key, &object) != 0 ||
        object.match_count > JL_BYTE_WIDTH) {
        return JL_STATUS_FAILURE;
    }
    if (object.match_count == 0U) {
        return jl_insert_and_write(file_path, source, source_length, snapshot, object_start,
                                   &object, object_path, path_len, SIZE_MAX, array_key,
                                   array_json->data, array_json->length);
    }
    if (source[object.match.value_start] != '[') {
        return JL_STATUS_FAILURE;
    }
    jl_array_t array;
    if (jl_scan_array(source, source_length, object.match.value_start, string_value, &array) != 0 ||
        array.match_count > JL_BYTE_WIDTH) {
        return JL_STATUS_FAILURE;
    }
    if (array.match_count == JL_BYTE_WIDTH) {
        return 0;
    }
    char *updated = NULL;
    size_t updated_length = 0;
    int result = jl_insert_array_string(source, source_length, object.match.value_start, &array,
                                        string_value, &updated, &updated_length);
    if (result == 0) {
        result =
            jl_write_document(file_path, updated, updated_length, source, source_length, snapshot);
    }
    free(updated);
    return result;
}

int cbm_json_like_add_unique_string_at_path(const char *file_path, const char *const *object_path,
                                            size_t path_len, const char *array_key,
                                            const char *string_value) {
    if (jl_validate_arguments(file_path, object_path, path_len, array_key) != 0 ||
        jl_validate_string_value(string_value) != 0) {
        return JL_STATUS_FAILURE;
    }
    jl_buffer_t array_json = {0};
    if (jl_build_single_string_array(string_value, &array_json) != 0) {
        return JL_STATUS_FAILURE;
    }

    char *source = NULL;
    size_t source_length = 0;
    bool missing = false;
    jl_file_snapshot_t snapshot;
    if (jl_read_file(file_path, &source, &source_length, &missing, &snapshot) != 0) {
        free(array_json.data);
        return JL_STATUS_FAILURE;
    }
    if (missing || source_length == 0U) {
        int result =
            jl_write_fresh_entry(file_path, object_path, path_len, array_key, array_json.data,
                                 array_json.length, source, source_length, &snapshot);
        free(source);
        free(array_json.data);
        return result;
    }
    int result = jl_add_unique_existing(file_path, object_path, path_len, array_key, string_value,
                                        &array_json, source, source_length, &snapshot);
    free(source);
    free(array_json.data);
    return result;
}

int cbm_json_like_remove_string_at_path(const char *file_path, const char *const *object_path,
                                        size_t path_len, const char *array_key,
                                        const char *string_value) {
    if (jl_validate_arguments(file_path, object_path, path_len, array_key) != 0 ||
        jl_validate_string_value(string_value) != 0) {
        return JL_STATUS_FAILURE;
    }
    char *source = NULL;
    size_t source_length = 0;
    bool missing = false;
    jl_file_snapshot_t snapshot;
    if (jl_read_file(file_path, &source, &source_length, &missing, &snapshot) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (missing || source_length == 0U) {
        free(source);
        return 0;
    }

    size_t object_start = 0;
    if (jl_validate_document(source, source_length, &object_start) != 0) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    for (size_t i = 0; i < path_len; i++) {
        jl_object_t parent;
        if (jl_scan_object(source, source_length, object_start, object_path[i], &parent) != 0 ||
            parent.match_count > JL_BYTE_WIDTH) {
            free(source);
            return JL_STATUS_FAILURE;
        }
        if (parent.match_count == 0U) {
            free(source);
            return 0;
        }
        if (source[parent.match.value_start] != '{') {
            free(source);
            return JL_STATUS_FAILURE;
        }
        object_start = parent.match.value_start;
    }

    jl_object_t object;
    if (jl_scan_object(source, source_length, object_start, array_key, &object) != 0 ||
        object.match_count > JL_BYTE_WIDTH) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    if (object.match_count == 0U) {
        free(source);
        return 0;
    }
    if (source[object.match.value_start] != '[') {
        free(source);
        return JL_STATUS_FAILURE;
    }

    jl_array_t array;
    if (jl_scan_array(source, source_length, object.match.value_start, string_value, &array) != 0 ||
        array.match_count > JL_BYTE_WIDTH) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    if (array.match_count == 0U) {
        free(source);
        return 0;
    }

    jl_edit_t edits[JL_EDIT_PAIR_CAPACITY];
    size_t edit_count = 0;
    edits[edit_count++] = (jl_edit_t){
        .start = jl_leading_whitespace_start(source, array.match.value_start),
        .end = array.match.value_end,
        .replacement = NULL,
        .replacement_length = 0,
    };
    if (array.match.comma_pos != SIZE_MAX) {
        edits[edit_count++] = (jl_edit_t){
            .start = array.match.comma_pos,
            .end = array.match.comma_pos + JL_BYTE_WIDTH,
            .replacement = NULL,
            .replacement_length = 0,
        };
    } else if (array.match.previous_comma_pos != SIZE_MAX) {
        edits[edit_count++] = (jl_edit_t){
            .start = array.match.previous_comma_pos,
            .end = array.match.previous_comma_pos + JL_BYTE_WIDTH,
            .replacement = NULL,
            .replacement_length = 0,
        };
    }

    char *updated = NULL;
    size_t updated_length = 0;
    int result =
        jl_apply_edits(source, source_length, edits, edit_count, &updated, &updated_length);
    if (result == 0) {
        result =
            jl_write_document(file_path, updated, updated_length, source, source_length, &snapshot);
    }
    free(updated);
    free(source);
    return result;
}

static int jl_append_decoded_codepoint(jl_buffer_t *decoded, uint32_t codepoint) {
    if (codepoint == 0U || codepoint > JL_UTF8_CODEPOINT_MAX ||
        (codepoint >= JL_UTF16_SURROGATE_MIN && codepoint <= JL_UTF16_SURROGATE_MAX)) {
        return JL_STATUS_FAILURE;
    }
    unsigned char encoded[JL_FOUR_BYTES];
    size_t encoded_length = jl_encode_utf8(codepoint, encoded);
    return jl_buffer_append(decoded, (const char *)encoded, encoded_length);
}

static int jl_decode_string_value(const char *text, size_t start, size_t end, char **value_out) {
    *value_out = NULL;
    if (end <= start + JL_BYTE_WIDTH || (text[start] != '"' && text[start] != '\'') ||
        text[end - JL_BYTE_WIDTH] != text[start]) {
        return JL_STATUS_FAILURE;
    }

    jl_buffer_t decoded = {0};
    size_t pos = start + JL_BYTE_WIDTH;
    size_t limit = end - JL_BYTE_WIDTH;
    while (pos < limit) {
        unsigned char current = (unsigned char)text[pos++];
        if (current != '\\') {
            if (jl_buffer_char(&decoded, (char)current) != 0) {
                free(decoded.data);
                return JL_STATUS_FAILURE;
            }
            continue;
        }
        if (pos < limit && (unsigned char)text[pos] == JL_UTF8_LINE_SEPARATOR_LEAD &&
            limit - pos >= JL_THREE_BYTES &&
            (unsigned char)text[pos + JL_BYTE_WIDTH] == JL_UTF8_CONTINUATION_BYTE &&
            ((unsigned char)text[pos + JL_TWO_BYTES] == JL_UTF8_LINE_SEPARATOR_TAIL ||
             (unsigned char)text[pos + JL_TWO_BYTES] == JL_UTF8_PARAGRAPH_SEPARATOR_TAIL)) {
            pos += JL_THREE_BYTES;
            continue;
        }
        uint32_t codepoint = 0;
        bool skip = false;
        if (!jl_decode_key_escape(text, &pos, limit, &codepoint, &skip)) {
            free(decoded.data);
            return JL_STATUS_FAILURE;
        }
        if (skip) {
            continue;
        }
        if (jl_append_decoded_codepoint(&decoded, codepoint) != 0) {
            free(decoded.data);
            return JL_STATUS_FAILURE;
        }
    }

    if (!decoded.data) {
        decoded.data = malloc(JL_BYTE_WIDTH);
        if (!decoded.data) {
            return JL_STATUS_FAILURE;
        }
        decoded.data[0] = '\0';
    }
    *value_out = decoded.data;
    return 0;
}

static int jl_decode_field_string(const char *text, size_t start, size_t end,
                                  cbm_json_like_value_shape_t shape, char **value_out) {
    *value_out = NULL;
    if (shape == CBM_JSON_LIKE_VALUE_STRING) {
        if (start >= end || (text[start] != '"' && text[start] != '\'')) {
            return JL_STATUS_NO_MATCH;
        }
        return jl_decode_string_value(text, start, end, value_out) == 0 ? 0 : JL_STATUS_NO_MATCH;
    }
    if (shape != CBM_JSON_LIKE_VALUE_SINGLE_STRING_ARRAY || start >= end || text[start] != '[') {
        return JL_STATUS_NO_MATCH;
    }

    jl_parser_t parser = {
        .text = text, .length = end, .pos = start + JL_BYTE_WIDTH, .strict = false};
    if (jl_skip_trivia(&parser) != 0 || parser.pos >= end || text[parser.pos] == ']') {
        return JL_STATUS_NO_MATCH;
    }
    size_t value_start = 0U;
    size_t value_end = 0U;
    if (jl_parse_value(&parser, JL_BYTE_WIDTH, &value_start, &value_end) != 0 ||
        (text[value_start] != '"' && text[value_start] != '\'') || jl_skip_trivia(&parser) != 0 ||
        parser.pos >= end) {
        return JL_STATUS_NO_MATCH;
    }
    if (text[parser.pos] == ',') {
        parser.pos++;
        if (jl_skip_trivia(&parser) != 0 || parser.pos >= end) {
            return JL_STATUS_NO_MATCH;
        }
    }
    if (text[parser.pos] != ']' || parser.pos + JL_BYTE_WIDTH != end) {
        return JL_STATUS_NO_MATCH;
    }
    return jl_decode_string_value(text, value_start, value_end, value_out) == 0
               ? 0
               : JL_STATUS_NO_MATCH;
}

static bool jl_field_shape_matches(const char *text, const jl_member_t *member,
                                   cbm_json_like_value_shape_t shape, char **decoded_out) {
    *decoded_out = NULL;
    if (shape == CBM_JSON_LIKE_VALUE_EMPTY_ARRAY) {
        if (member->value_start >= member->value_end || text[member->value_start] != '[') {
            return false;
        }
        jl_parser_t parser = {
            .text = text,
            .length = member->value_end,
            .pos = member->value_start + JL_BYTE_WIDTH,
            .strict = false,
        };
        return jl_skip_trivia(&parser) == 0 && parser.pos < member->value_end &&
               text[parser.pos] == ']' && parser.pos + JL_BYTE_WIDTH == member->value_end;
    }
    return jl_decode_field_string(text, member->value_start, member->value_end, shape,
                                  decoded_out) == 0;
}

static bool jl_match_arguments_valid(const char *document, size_t document_length,
                                     const char *const *object_path, size_t path_len,
                                     const char *entry_key,
                                     const cbm_json_like_object_field_t *fields, size_t field_count,
                                     size_t *capture_count) {
    if (!document || document_length > JL_MAX_FILE_BYTES || !entry_key || entry_key[0] == '\0' ||
        !fields || field_count == 0U || (path_len > 0U && !object_path)) {
        return false;
    }
    *capture_count = 0U;
    for (size_t i = 0; i < path_len; i++) {
        if (!object_path[i] || object_path[i][0] == '\0') {
            return false;
        }
    }
    for (size_t i = 0; i < field_count; i++) {
        unsigned flags = fields[i].flags;
        if (!fields[i].key || fields[i].key[0] == '\0' ||
            fields[i].shape > CBM_JSON_LIKE_VALUE_SINGLE_STRING_ARRAY ||
            (flags & ~(unsigned)(CBM_JSON_LIKE_FIELD_REQUIRED |
                                 CBM_JSON_LIKE_FIELD_CAPTURE_STRING)) != 0U ||
            ((flags & CBM_JSON_LIKE_FIELD_CAPTURE_STRING) != 0U &&
             fields[i].shape == CBM_JSON_LIKE_VALUE_EMPTY_ARRAY)) {
            return false;
        }
        *capture_count += (flags & CBM_JSON_LIKE_FIELD_CAPTURE_STRING) != 0U ? JL_BYTE_WIDTH : 0U;
        for (size_t j = 0; j < i; j++) {
            if (strcmp(fields[i].key, fields[j].key) == 0) {
                return false;
            }
        }
    }
    return *capture_count == JL_BYTE_WIDTH;
}

static int jl_match_child_object(const char *document, size_t length, size_t *object_start,
                                 const char *key) {
    jl_object_t parent;
    if (jl_scan_object(document, length, *object_start, key, &parent) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (parent.match_count == 0U) {
        return CBM_JSON_LIKE_OBJECT_MISSING;
    }
    if (parent.match_count != JL_BYTE_WIDTH || document[parent.match.value_start] != '{') {
        return CBM_JSON_LIKE_OBJECT_MISMATCH;
    }
    *object_start = parent.match.value_start;
    return 0;
}

static int jl_match_fields(const char *document, size_t length, size_t entry_start,
                           const cbm_json_like_object_field_t *fields, size_t field_count,
                           char **captured_out) {
    size_t found_count = 0U;
    size_t member_count = 0U;
    char *captured = NULL;
    for (size_t i = 0; i < field_count; i++) {
        jl_object_t entry;
        if (jl_scan_object(document, length, entry_start, fields[i].key, &entry) != 0) {
            free(captured);
            return JL_STATUS_FAILURE;
        }
        member_count = entry.member_count;
        bool required = (fields[i].flags & CBM_JSON_LIKE_FIELD_REQUIRED) != 0U;
        if (entry.match_count > JL_BYTE_WIDTH || (entry.match_count == 0U && required)) {
            free(captured);
            return CBM_JSON_LIKE_OBJECT_MISMATCH;
        }
        if (entry.match_count == 0U) {
            continue;
        }
        found_count++;
        char *decoded = NULL;
        if (!jl_field_shape_matches(document, &entry.match, fields[i].shape, &decoded) ||
            (fields[i].expected_string &&
             (!decoded || strcmp(decoded, fields[i].expected_string) != 0))) {
            free(decoded);
            free(captured);
            return CBM_JSON_LIKE_OBJECT_MISMATCH;
        }
        if ((fields[i].flags & CBM_JSON_LIKE_FIELD_CAPTURE_STRING) != 0U) {
            captured = decoded;
        } else {
            free(decoded);
        }
    }
    if (member_count != found_count || !captured) {
        free(captured);
        return CBM_JSON_LIKE_OBJECT_MISMATCH;
    }
    *captured_out = captured;
    return CBM_JSON_LIKE_OBJECT_MATCH;
}

int cbm_json_like_match_object_entry(const char *document, size_t document_length,
                                     const char *const *object_path, size_t path_len,
                                     const char *entry_key,
                                     const cbm_json_like_object_field_t *fields, size_t field_count,
                                     char **captured_string_out) {
    if (!captured_string_out) {
        return JL_STATUS_FAILURE;
    }
    *captured_string_out = NULL;
    size_t capture_count = 0U;
    if (!jl_match_arguments_valid(document, document_length, object_path, path_len, entry_key,
                                  fields, field_count, &capture_count)) {
        return JL_STATUS_FAILURE;
    }
    if (document_length == 0U) {
        return CBM_JSON_LIKE_OBJECT_MISSING;
    }

    size_t object_start = 0U;
    if (jl_validate_document(document, document_length, &object_start) != 0) {
        return JL_STATUS_FAILURE;
    }
    for (size_t i = 0U; i < path_len; ++i) {
        int matched =
            jl_match_child_object(document, document_length, &object_start, object_path[i]);
        if (matched != 0) {
            return matched;
        }
    }
    int entry_result = jl_match_child_object(document, document_length, &object_start, entry_key);
    if (entry_result != 0) {
        return entry_result;
    }
    return jl_match_fields(document, document_length, object_start, fields, field_count,
                           captured_string_out);
}

int cbm_json_like_get_string_at_path(const char *file_path, const char *const *object_path,
                                     size_t path_len, const char *string_key, char **value_out) {
    if (!value_out) {
        return JL_STATUS_FAILURE;
    }
    *value_out = NULL;
    if (jl_validate_arguments(file_path, object_path, path_len, string_key) != 0) {
        return JL_STATUS_FAILURE;
    }

    char *source = NULL;
    size_t source_length = 0U;
    bool missing = false;
    jl_file_snapshot_t snapshot;
    if (jl_read_file(file_path, &source, &source_length, &missing, &snapshot) != 0) {
        return JL_STATUS_FAILURE;
    }
    if (missing || source_length == 0U) {
        free(source);
        return JL_STATUS_NO_MATCH;
    }

    size_t object_start = 0U;
    if (jl_validate_document(source, source_length, &object_start) != 0) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    for (size_t i = 0; i < path_len; i++) {
        jl_object_t parent;
        if (jl_scan_object(source, source_length, object_start, object_path[i], &parent) != 0 ||
            parent.match_count > JL_BYTE_WIDTH) {
            free(source);
            return JL_STATUS_FAILURE;
        }
        if (parent.match_count == 0U) {
            free(source);
            return JL_STATUS_NO_MATCH;
        }
        if (source[parent.match.value_start] != '{') {
            free(source);
            return JL_STATUS_FAILURE;
        }
        object_start = parent.match.value_start;
    }

    jl_object_t object;
    if (jl_scan_object(source, source_length, object_start, string_key, &object) != 0 ||
        object.match_count > JL_BYTE_WIDTH) {
        free(source);
        return JL_STATUS_FAILURE;
    }
    if (object.match_count == 0U) {
        free(source);
        return JL_STATUS_NO_MATCH;
    }
    if (source[object.match.value_start] != '"' && source[object.match.value_start] != '\'') {
        free(source);
        return JL_STATUS_FAILURE;
    }

    int result =
        jl_decode_string_value(source, object.match.value_start, object.match.value_end, value_out);
    free(source);
    return result;
}

int cbm_json_like_add_unique_string(const char *file_path, const char *array_key,
                                    const char *string_value) {
    const char *root_path[] = {NULL};
    return cbm_json_like_add_unique_string_at_path(file_path, root_path, 0U, array_key,
                                                   string_value);
}

int cbm_json_like_remove_string(const char *file_path, const char *array_key,
                                const char *string_value) {
    const char *root_path[] = {NULL};
    return cbm_json_like_remove_string_at_path(file_path, root_path, 0U, array_key, string_value);
}
