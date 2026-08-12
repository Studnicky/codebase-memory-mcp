/* compact_out.c — tree-format emission helpers. See compact_out.h for the contract. */
#include "mcp/compact_out.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    SB_INITIAL_CAP = 1024,
    SB_GROWTH_FACTOR = 2,
    TEXT_TERMINATOR_BYTES = 1,
    EMPTY_STRING_CAPACITY_BYTES = 1,
    UTF8_ASCII_LIMIT = 0x80,
    UTF8_TWO_BYTE_LEAD_MIN = 0xC2,
    UTF8_THREE_BYTE_LEAD_MIN = 0xE0,
    UTF8_FOUR_BYTE_LEAD_MIN = 0xF0,
    UTF8_FOUR_BYTE_LEAD_LIMIT = 0xF5,
    UTF8_THREE_BYTE_E0_LEAD = 0xE0,
    UTF8_THREE_BYTE_ED_LEAD = 0xED,
    UTF8_FOUR_BYTE_F0_LEAD = 0xF0,
    UTF8_FOUR_BYTE_F4_LEAD = 0xF4,
    UTF8_CONTINUATION_MASK = 0xC0,
    UTF8_CONTINUATION_TAG = 0x80,
    UTF8_THREE_BYTE_E0_MIN = 0xA0,
    UTF8_THREE_BYTE_ED_MAX = 0x9F,
    UTF8_BYTE_MAX = 0xBF,
    UTF8_FOUR_BYTE_F0_MIN = 0x90,
    UTF8_FOUR_BYTE_F4_MAX = 0x8F,
    UTF8_TWO_BYTE_LENGTH = 2,
    UTF8_THREE_BYTE_LENGTH = 3,
    UTF8_FOUR_BYTE_LENGTH = 4,
    UTF8_TRAILING_BYTES_TO_SKIP = 1,
    ASCII_CONTROL_LIMIT = 0x20,
    ASCII_DELETE = 0x7F,
    JSON_CONTROL_ESCAPE_CAPACITY = 8,
    UTF8_REPLACEMENT_BYTES = 3,
    TREE_KEY_SEPARATOR_BYTES = 2,
    TREE_NEWLINE_BYTES = 1,
    TREE_TABLE_CLOSE_BYTES = 2,
    TREE_INDENT_BYTES = 2,
    TREE_CELL_SEPARATOR_BYTES = 1,
    TREE_INT_TEXT_CAPACITY = 32,
    TREE_REAL_TEXT_CAPACITY = 48,
};

void cbm_sb_init(cbm_sb_t *sb) {
    sb->buf = NULL;
    sb->len = 0;
    sb->cap = 0;
    sb->oom = false;
}

static bool sb_reserve(cbm_sb_t *sb, size_t extra) {
    if (sb->oom) {
        return false;
    }
    if (sb->len + extra + TEXT_TERMINATOR_BYTES <= sb->cap) {
        return true;
    }
    size_t ncap = sb->cap ? sb->cap : SB_INITIAL_CAP;
    while (ncap < sb->len + extra + TEXT_TERMINATOR_BYTES) {
        ncap *= SB_GROWTH_FACTOR;
    }
    char *nbuf = (char *)realloc(sb->buf, ncap);
    if (!nbuf) {
        sb->oom = true;
        return false;
    }
    sb->buf = nbuf;
    sb->cap = ncap;
    return true;
}

void cbm_sb_append_n(cbm_sb_t *sb, const char *s, size_t n) {
    if (!s || n == 0 || !sb_reserve(sb, n)) {
        return;
    }
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
}

void cbm_sb_append(cbm_sb_t *sb, const char *s) {
    if (s) {
        cbm_sb_append_n(sb, s, strlen(s));
    }
}

char *cbm_sb_finish(cbm_sb_t *sb) {
    if (sb->oom) {
        free(sb->buf);
        cbm_sb_init(sb);
        return NULL;
    }
    if (!sb->buf) {
        /* Empty but valid: return an owned empty string. */
        char *empty = (char *)calloc(EMPTY_STRING_CAPACITY_BYTES, sizeof *empty);
        return empty;
    }
    char *out = sb->buf;
    cbm_sb_init(sb);
    return out;
}

void cbm_sb_free(cbm_sb_t *sb) {
    free(sb->buf);
    cbm_sb_init(sb);
}

/* ── Tree quoting ────────────────────────────────────────────────── */

/* True when `s` parses as an integer or real literal (sign, digits, one dot). */
static bool looks_numeric(const char *s) {
    if (!s || !*s) {
        return false;
    }
    const char *p = s;
    if (*p == '-' || *p == '+') {
        p++;
    }
    bool digit = false;
    bool dot = false;
    for (; *p; p++) {
        if (isdigit((unsigned char)*p)) {
            digit = true;
        } else if (*p == '.' && !dot) {
            dot = true;
        } else {
            return false;
        }
    }
    return digit;
}

/* UTF-8 sequence length starting at p, validating continuation bytes and the
 * lead-byte ranges (RFC 3629: no overlongs, no surrogates, max U+10FFFF);
 * 0 = not a valid sequence start. Reads stop at the first invalid byte, so a
 * terminating NUL is never overrun. */
static size_t utf8_sequence_length(const unsigned char *p) {
    unsigned char c = p[0];
    if (c < UTF8_ASCII_LIMIT) {
        return TEXT_TERMINATOR_BYTES;
    }
    if (c < UTF8_TWO_BYTE_LEAD_MIN) {
        return 0; /* bare continuation byte or overlong lead */
    }
    if (c < UTF8_THREE_BYTE_LEAD_MIN) {
        return (p[TEXT_TERMINATOR_BYTES] & UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_TAG
                   ? UTF8_TWO_BYTE_LENGTH
                   : 0;
    }
    if (c < UTF8_FOUR_BYTE_LEAD_MIN) {
        unsigned char lo =
            c == UTF8_THREE_BYTE_E0_LEAD ? UTF8_THREE_BYTE_E0_MIN : UTF8_CONTINUATION_TAG;
        unsigned char hi = c == UTF8_THREE_BYTE_ED_LEAD ? UTF8_THREE_BYTE_ED_MAX : UTF8_BYTE_MAX;
        if (p[TEXT_TERMINATOR_BYTES] < lo || p[TEXT_TERMINATOR_BYTES] > hi ||
            (p[UTF8_TWO_BYTE_LENGTH] & UTF8_CONTINUATION_MASK) != UTF8_CONTINUATION_TAG) {
            return 0;
        }
        return UTF8_THREE_BYTE_LENGTH;
    }
    if (c < UTF8_FOUR_BYTE_LEAD_LIMIT) {
        unsigned char lo =
            c == UTF8_FOUR_BYTE_F0_LEAD ? UTF8_FOUR_BYTE_F0_MIN : UTF8_CONTINUATION_TAG;
        unsigned char hi = c == UTF8_FOUR_BYTE_F4_LEAD ? UTF8_FOUR_BYTE_F4_MAX : UTF8_BYTE_MAX;
        if (p[TEXT_TERMINATOR_BYTES] < lo || p[TEXT_TERMINATOR_BYTES] > hi ||
            (p[UTF8_TWO_BYTE_LENGTH] & UTF8_CONTINUATION_MASK) != UTF8_CONTINUATION_TAG ||
            (p[UTF8_THREE_BYTE_LENGTH] & UTF8_CONTINUATION_MASK) != UTF8_CONTINUATION_TAG) {
            return 0;
        }
        return UTF8_FOUR_BYTE_LENGTH;
    }
    return 0;
}

static bool needs_quotes(const char *s) {
    if (!s || !*s) {
        return false; /* empty cells emit as the "-" placeholder, not quotes */
    }
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        /* Space-delimited rows: any internal whitespace or quote forces
         * quoting so column positions stay parseable. Control bytes and
         * invalid UTF-8 force the quoted path too, which sanitizes them —
         * one raw byte otherwise makes line-oriented consumers (BSD grep)
         * treat the ENTIRE tool output as unmatchable binary. */
        if (isspace(c) || *p == '"' || *p == '\r' || c < ASCII_CONTROL_LIMIT || c == ASCII_DELETE) {
            return true;
        }
        if (c >= UTF8_ASCII_LIMIT) {
            size_t len = utf8_sequence_length((const unsigned char *)p);
            if (!len) {
                return true;
            }
            p += len - UTF8_TRAILING_BYTES_TO_SKIP;
        }
    }
    if (strcmp(s, "true") == 0 || strcmp(s, "false") == 0 || strcmp(s, "null") == 0 ||
        strcmp(s, "-") == 0) {
        return true;
    }
    return looks_numeric(s);
}

static void append_quoted(cbm_sb_t *sb, const char *s) {
    cbm_sb_append_n(sb, "\"", TEXT_TERMINATOR_BYTES);
    for (const char *p = s ? s : ""; *p; p++) {
        switch (*p) {
        case '"':
            cbm_sb_append_n(sb, "\\\"", TREE_KEY_SEPARATOR_BYTES);
            break;
        case '\\':
            cbm_sb_append_n(sb, "\\\\", TREE_KEY_SEPARATOR_BYTES);
            break;
        case '\n':
            cbm_sb_append_n(sb, "\\n", TREE_KEY_SEPARATOR_BYTES);
            break;
        case '\r':
            cbm_sb_append_n(sb, "\\r", TREE_KEY_SEPARATOR_BYTES);
            break;
        default: {
            unsigned char c = (unsigned char)*p;
            if (c >= ASCII_CONTROL_LIMIT && c != ASCII_DELETE && c < UTF8_ASCII_LIMIT) {
                cbm_sb_append_n(sb, p, TEXT_TERMINATOR_BYTES);
            } else if (c < ASCII_CONTROL_LIMIT || c == ASCII_DELETE) {
                /* JSON-style escape: the value stays one printable line. */
                char esc[JSON_CONTROL_ESCAPE_CAPACITY];
                snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
                cbm_sb_append(sb, esc);
            } else {
                size_t len = utf8_sequence_length((const unsigned char *)p);
                if (len) {
                    cbm_sb_append_n(sb, p, len);
                    p += len - UTF8_TRAILING_BYTES_TO_SKIP;
                } else {
                    /* Invalid byte → U+FFFD: output is valid UTF-8 by
                     * construction, and the corruption stays visible. */
                    cbm_sb_append_n(sb, "\xEF\xBF\xBD", UTF8_REPLACEMENT_BYTES);
                }
            }
            break;
        }
        }
    }
    cbm_sb_append_n(sb, "\"", TEXT_TERMINATOR_BYTES);
}

static void append_value(cbm_sb_t *sb, const char *s) {
    if (!s || !*s) {
        cbm_sb_append_n(sb, "-", TEXT_TERMINATOR_BYTES); /* stable column positions for empties */
        return;
    }
    if (needs_quotes(s)) {
        append_quoted(sb, s);
    } else {
        cbm_sb_append(sb, s);
    }
}

/* ── Scalars ────────────────────────────────────────────────────── */

void cbm_tree_scalar_str(cbm_sb_t *sb, const char *key, const char *val) {
    cbm_sb_append(sb, key);
    cbm_sb_append_n(sb, ": ", TREE_KEY_SEPARATOR_BYTES);
    append_value(sb, val);
    cbm_sb_append_n(sb, "\n", TREE_NEWLINE_BYTES);
}

void cbm_tree_scalar_int(cbm_sb_t *sb, const char *key, long long v) {
    char num[TREE_INT_TEXT_CAPACITY];
    snprintf(num, sizeof(num), "%lld", v);
    cbm_sb_append(sb, key);
    cbm_sb_append_n(sb, ": ", TREE_KEY_SEPARATOR_BYTES);
    cbm_sb_append(sb, num);
    cbm_sb_append_n(sb, "\n", TREE_NEWLINE_BYTES);
}

void cbm_tree_scalar_bool(cbm_sb_t *sb, const char *key, bool v) {
    cbm_sb_append(sb, key);
    cbm_sb_append_n(sb, ": ", TREE_KEY_SEPARATOR_BYTES);
    cbm_sb_append(sb, v ? "true" : "false");
    cbm_sb_append_n(sb, "\n", TREE_NEWLINE_BYTES);
}

/* ── Tables ─────────────────────────────────────────────────────── */

/* Tree-syntax table header: `key: N  (cols: a b c)` — count first (agents
 * read scale before rows), column names once, rows indented beneath. */
void cbm_tree_table_header(cbm_sb_t *sb, const char *key, int n, const char *const *cols,
                           int ncols) {
    char num[TREE_INT_TEXT_CAPACITY];
    snprintf(num, sizeof(num), ": %d  (cols:", n);
    cbm_sb_append(sb, key);
    cbm_sb_append(sb, num);
    for (int i = 0; i < ncols; i++) {
        cbm_sb_append_n(sb, " ", TREE_CELL_SEPARATOR_BYTES);
        cbm_sb_append(sb, cols[i]);
    }
    cbm_sb_append_n(sb, ")\n", TREE_TABLE_CLOSE_BYTES);
}

void cbm_tree_row_begin(cbm_sb_t *sb) {
    cbm_sb_append_n(sb, "  ", TREE_INDENT_BYTES);
}

void cbm_tree_cell_str(cbm_sb_t *sb, const char *val, bool first) {
    if (!first) {
        cbm_sb_append_n(sb, " ", TREE_CELL_SEPARATOR_BYTES);
    }
    append_value(sb, val ? val : "");
}

void cbm_tree_cell_int(cbm_sb_t *sb, long long v, bool first) {
    char num[TREE_INT_TEXT_CAPACITY];
    snprintf(num, sizeof(num), "%lld", v);
    if (!first) {
        cbm_sb_append_n(sb, " ", TREE_CELL_SEPARATOR_BYTES);
    }
    cbm_sb_append(sb, num);
}

void cbm_tree_cell_real(cbm_sb_t *sb, double v, bool first) {
    char num[TREE_REAL_TEXT_CAPACITY];
    snprintf(num, sizeof(num), "%.4g", v);
    if (!first) {
        cbm_sb_append_n(sb, " ", TREE_CELL_SEPARATOR_BYTES);
    }
    cbm_sb_append(sb, num);
}

void cbm_tree_cell_bool(cbm_sb_t *sb, bool v, bool first) {
    if (!first) {
        cbm_sb_append_n(sb, " ", TREE_CELL_SEPARATOR_BYTES);
    }
    cbm_sb_append(sb, v ? "true" : "false");
}

void cbm_tree_row_end(cbm_sb_t *sb) {
    cbm_sb_append_n(sb, "\n", TREE_NEWLINE_BYTES);
}
