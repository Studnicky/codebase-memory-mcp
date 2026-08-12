#include "iris_export_xml.h"
#include "arena.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#define EXPORT_MARKER "<Export generator="
#define MAX_NAME 256
#define MAX_PARAMS 32
#define MAX_CLASSES 64
#define BUF_CAP ((size_t)1024U * 64U)

enum {
    IRIS_XML_TAG_CLOSE_WIDTH = 1,
    IRIS_XML_NULL_TERMINATOR_WIDTH = 1,
    IRIS_XML_ATTRIBUTE_ASSIGNMENT_WIDTH = 1,
    IRIS_XML_CDATA_OPEN_WIDTH = 9,
    IRIS_XML_CDATA_CLOSE_WIDTH = 3,
    IRIS_XML_OPEN_TAG_FORMAT_EXTRA = 2,
    IRIS_XML_CLOSE_TAG_FORMAT_EXTRA = 4,
    IRIS_XML_BOOLEAN_VALUE_CAPACITY = 8,
    IRIS_XML_PRAGMA_CAPACITY = 64,
    IRIS_XML_SUPERTYPE_CAPACITY_MULTIPLIER = 4,
    IRIS_XML_FORMAL_SPEC_CAPACITY = 1024,
    IRIS_XML_DESCRIPTION_CAPACITY = 4096,
    IRIS_XML_INLINE_CHARACTER_CAPACITY = 2,
    IRIS_XML_IMPLEMENTATION_CAPACITY = 32768,
    IRIS_XML_RESULT_TERMINATOR_SLOTS = 1,
    IRIS_XML_TRAILING_COMMA_WIDTH = 1,
};

typedef struct {
    char param_name[MAX_NAME];
    char param_value[MAX_NAME];
} PropParam;

typedef struct {
    char *buf;
    int pos;
    int cap;
} UdlBuf;

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
    }
    return p;
}
static bool sw(const char *p, const char *end, const char *tag) {
    size_t n = strlen(tag);
    return (size_t)(end - p) >= n && memcmp(p, tag, n) == 0;
}
static const char *find_s(const char *p, const char *end, const char *needle) {
    size_t n = strlen(needle);
    while (p + n <= end) {
        if (memcmp(p, needle, n) == 0) {
            return p;
        }
        p++;
    }
    return NULL;
}
static const char *skip_tag(const char *p, const char *end) {
    while (p < end && *p != '>') {
        p++;
    }
    return p < end ? p + IRIS_XML_TAG_CLOSE_WIDTH : end;
}
static bool is_self_closing(const char *start, const char *gt) {
    const char *p = gt - IRIS_XML_TAG_CLOSE_WIDTH;
    while (p > start && (*p == ' ' || *p == '\t')) {
        p--;
    }
    return *p == '/';
}
static void extract_attr(const char *ts, const char *te, const char *attr, char *out, size_t sz) {
    out[0] = '\0';
    size_t an = strlen(attr);
    for (const char *p = ts; p < te - an; p++) {
        if (memcmp(p, attr, an) == 0 && p[an] == '=') {
            p += an + IRIS_XML_ATTRIBUTE_ASSIGNMENT_WIDTH;
            char q = *p;
            if (q != '"' && q != '\'') {
                return;
            }
            p++;
            const char *v = p;
            while (p < te && *p != q) {
                p++;
            }
            size_t vl = (size_t)(p - v);
            if (vl >= sz) {
                vl = sz - IRIS_XML_NULL_TERMINATOR_WIDTH;
            }
            memcpy(out, v, vl);
            out[vl] = '\0';
            return;
        }
    }
}
static const char *elem_content(const char *p, const char *end, const char *tag, char *buf,
                                size_t bufsz) {
    buf[0] = '\0';
    char open[MAX_NAME + IRIS_XML_OPEN_TAG_FORMAT_EXTRA];
    snprintf(open, sizeof(open), "<%s", tag);
    const char *start = find_s(p, end, open);
    if (!start) {
        return NULL;
    }
    const char *gt = find_s(start, end, ">");
    if (!gt) {
        return NULL;
    }
    if (is_self_closing(start, gt)) {
        return gt + IRIS_XML_TAG_CLOSE_WIDTH;
    }
    const char *cs = gt + IRIS_XML_TAG_CLOSE_WIDTH;
    if (sw(cs, end, "<![CDATA[")) {
        cs += IRIS_XML_CDATA_OPEN_WIDTH;
        const char *ce = find_s(cs, end, "]]>");
        if (!ce) {
            return NULL;
        }
        size_t l = (size_t)(ce - cs);
        if (l >= bufsz) {
            l = bufsz - IRIS_XML_NULL_TERMINATOR_WIDTH;
        }
        memcpy(buf, cs, l);
        buf[l] = '\0';
        return ce + IRIS_XML_CDATA_CLOSE_WIDTH;
    }
    char close[MAX_NAME + IRIS_XML_CLOSE_TAG_FORMAT_EXTRA];
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *cl = find_s(cs, end, close);
    if (!cl) {
        return NULL;
    }
    size_t l = (size_t)(cl - cs);
    if (l >= bufsz) {
        l = bufsz - IRIS_XML_NULL_TERMINATOR_WIDTH;
    }
    memcpy(buf, cs, l);
    buf[l] = '\0';
    return cl + strlen(close);
}
static bool tag_is_one(const char *p, const char *end, const char *tag) {
    char buf[IRIS_XML_BOOLEAN_VALUE_CAPACITY];
    return elem_content(p, end, tag, buf, sizeof(buf)) && strcmp(buf, "1") == 0;
}

static void ub_init(UdlBuf *b, CBMArena *arena) {
    b->buf = (char *)cbm_arena_alloc(arena, BUF_CAP);
    b->pos = 0;
    b->cap = BUF_CAP;
    if (b->buf) {
        b->buf[0] = '\0';
    }
}
static void ub_app(UdlBuf *b, const char *s) {
    if (!b->buf || !s) {
        return;
    }
    size_t n = strlen(s);
    if (b->pos + (int)n + IRIS_XML_NULL_TERMINATOR_WIDTH >= b->cap) {
        return;
    }
    memcpy(b->buf + b->pos, s, n);
    b->pos += (int)n;
    b->buf[b->pos] = '\0';
}

static void emit_header(UdlBuf *b, const char *cs, const char *ce) {
    char name[MAX_NAME];
    extract_attr(cs, ce, "name", name, sizeof(name));
    if (!name[0]) {
        return;
    }
    ub_app(b, "Class ");
    ub_app(b, name);
    char sup[MAX_NAME * IRIS_XML_SUPERTYPE_CAPACITY_MULTIPLIER] = "";
    elem_content(cs, ce, "Super", sup, sizeof(sup));
    if (sup[0]) {
        if (strchr(sup, ',')) {
            ub_app(b, " Extends (");
            ub_app(b, sup);
            ub_app(b, ")");
        } else {
            ub_app(b, " Extends ");
            ub_app(b, sup);
        }
    }
    char pragma[IRIS_XML_PRAGMA_CAPACITY] = "";
    if (tag_is_one(cs, ce, "Abstract")) {
        strncat(pragma, "Abstract,", sizeof(pragma) - strlen(pragma) - 1);
    }
    if (tag_is_one(cs, ce, "Final")) {
        strncat(pragma, "Final,", sizeof(pragma) - strlen(pragma) - 1);
    }
    if (pragma[0]) {
        pragma[strlen(pragma) - IRIS_XML_TRAILING_COMMA_WIDTH] = '\0';
        ub_app(b, " [ ");
        ub_app(b, pragma);
        ub_app(b, " ]");
    }
    ub_app(b, "\n{\n\n");
}

static void emit_method(UdlBuf *b, const char *ms, const char *me) {
    char mn[MAX_NAME];
    extract_attr(ms, me, "name", mn, sizeof(mn));
    if (!mn[0]) {
        return;
    }
    bool cm = tag_is_one(ms, me, "ClassMethod");
    char formal[IRIS_XML_FORMAL_SPEC_CAPACITY] = "";
    elem_content(ms, me, "FormalSpec", formal, sizeof(formal));
    char ret[MAX_NAME] = "";
    elem_content(ms, me, "ReturnType", ret, sizeof(ret));
    char desc[IRIS_XML_DESCRIPTION_CAPACITY] = "";
    elem_content(ms, me, "Description", desc, sizeof(desc));
    if (desc[0]) {
        ub_app(b, "/// ");
        for (char *c = desc; *c; c++) {
            if (*c == '\n') {
                ub_app(b, "\n/// ");
            } else {
                char t[IRIS_XML_INLINE_CHARACTER_CAPACITY] = {*c, 0};
                ub_app(b, t);
            }
        }
        ub_app(b, "\n");
    }
    ub_app(b, cm ? "ClassMethod " : "Method ");
    ub_app(b, mn);
    ub_app(b, "(");
    ub_app(b, formal);
    ub_app(b, ")");
    if (ret[0]) {
        ub_app(b, " As ");
        ub_app(b, ret);
    }
    ub_app(b, "\n{\n");
    char impl[IRIS_XML_IMPLEMENTATION_CAPACITY] = "";
    elem_content(ms, me, "Implementation", impl, sizeof(impl));
    ub_app(b, impl);
    ub_app(b, "}\n\n");
}

static int collect_property_params(const char *start, const char *end,
                                   PropParam params[MAX_PARAMS]) {
    int count = 0;
    const char *cursor = start;
    while (cursor < end && count < MAX_PARAMS) {
        const char *parameter = find_s(cursor, end, "<Parameter ");
        if (!parameter) {
            break;
        }
        const char *tag_end = find_s(parameter, end, ">");
        if (!tag_end) {
            break;
        }
        extract_attr(parameter, tag_end, "name", params[count].param_name, MAX_NAME);
        extract_attr(parameter, tag_end, "value", params[count].param_value, MAX_NAME);
        if (!params[count].param_value[0]) {
            char body[MAX_NAME];
            const char *after = elem_content(parameter, end, "Parameter", body, sizeof(body));
            if (after && body[0]) {
                strncpy(params[count].param_value, body, MAX_NAME - IRIS_XML_NULL_TERMINATOR_WIDTH);
            }
        }
        if (params[count].param_name[0]) {
            count++;
        }
        cursor = tag_end + IRIS_XML_TAG_CLOSE_WIDTH;
    }
    return count;
}

static void emit_property_params(UdlBuf *b, const PropParam params[MAX_PARAMS], int count) {
    if (count <= 0) {
        return;
    }
    ub_app(b, "(");
    for (int i = 0; i < count; i++) {
        if (i > 0) {
            ub_app(b, ", ");
        }
        ub_app(b, params[i].param_name);
        if (params[i].param_value[0]) {
            ub_app(b, " = ");
            ub_app(b, params[i].param_value);
        }
    }
    ub_app(b, ")");
}

static void emit_property(UdlBuf *b, const char *ps, const char *pe) {
    char pn[MAX_NAME];
    extract_attr(ps, pe, "name", pn, sizeof(pn));
    if (!pn[0]) {
        return;
    }
    char pt[MAX_NAME] = "";
    elem_content(ps, pe, "Type", pt, sizeof(pt));
    PropParam params[MAX_PARAMS];
    int np = collect_property_params(ps, pe, params);
    ub_app(b, "Property ");
    ub_app(b, pn);
    if (pt[0]) {
        ub_app(b, " As ");
        ub_app(b, pt);
    }
    emit_property_params(b, params, np);
    ub_app(b, ";\n\n");
}

static void emit_parameter(UdlBuf *b, const char *ps, const char *pe) {
    char pn[MAX_NAME];
    extract_attr(ps, pe, "name", pn, sizeof(pn));
    if (!pn[0]) {
        return;
    }
    char dv[MAX_NAME] = "";
    elem_content(ps, pe, "Default", dv, sizeof(dv));
    ub_app(b, "Parameter ");
    ub_app(b, pn);
    if (dv[0]) {
        ub_app(b, " = \"");
        ub_app(b, dv);
        ub_app(b, "\"");
    }
    ub_app(b, ";\n\n");
}

static void emit_index(UdlBuf *b, const char *is_, const char *ie) {
    char in_[MAX_NAME];
    extract_attr(is_, ie, "name", in_, sizeof(in_));
    if (!in_[0]) {
        return;
    }
    char props[MAX_NAME * IRIS_XML_SUPERTYPE_CAPACITY_MULTIPLIER] = "";
    elem_content(is_, ie, "Properties", props, sizeof(props));
    bool uniq = tag_is_one(is_, ie, "Unique");
    bool pkey = tag_is_one(is_, ie, "PrimaryKey");
    ub_app(b, "Index ");
    ub_app(b, in_);
    if (props[0]) {
        ub_app(b, " On ");
        ub_app(b, props);
    }
    if (uniq || pkey) {
        ub_app(b, " [ ");
        if (pkey) {
            ub_app(b, "PrimaryKey, ");
        }
        if (uniq) {
            ub_app(b, "Unique");
        }
        ub_app(b, " ]");
    }
    ub_app(b, ";\n\n");
}

static void emit_xdata(UdlBuf *b, const char *xs, const char *xe) {
    char xn[MAX_NAME];
    extract_attr(xs, xe, "name", xn, sizeof(xn));
    if (!xn[0]) {
        return;
    }
    char data[IRIS_XML_IMPLEMENTATION_CAPACITY] = "";
    elem_content(xs, xe, "Data", data, sizeof(data));
    ub_app(b, "XData ");
    ub_app(b, xn);
    ub_app(b, "\n{\n");
    ub_app(b, data);
    ub_app(b, "\n}\n\n");
}

typedef void (*IrisXmlRecordEmitter)(UdlBuf *buffer, const char *start, const char *end);

typedef struct {
    const char *open_with_attributes;
    const char *open_without_attributes;
    const char *close;
    bool ignore_self_closing;
    IrisXmlRecordEmitter emit;
} IrisXmlRecordRenderer;

static const IrisXmlRecordRenderer IRIS_XML_RECORD_RENDERERS[] = {
    {.open_with_attributes = "<Method ",
     .open_without_attributes = "<Method>",
     .close = "</Method>",
     .ignore_self_closing = false,
     .emit = emit_method},
    {.open_with_attributes = "<Property ",
     .open_without_attributes = NULL,
     .close = "</Property>",
     .ignore_self_closing = false,
     .emit = emit_property},
    {.open_with_attributes = "<Parameter ",
     .open_without_attributes = NULL,
     .close = "</Parameter>",
     .ignore_self_closing = true,
     .emit = emit_parameter},
    {.open_with_attributes = "<Index ",
     .open_without_attributes = "<Index>",
     .close = "</Index>",
     .ignore_self_closing = false,
     .emit = emit_index},
    {.open_with_attributes = "<XData ",
     .open_without_attributes = "<XData>",
     .close = "</XData>",
     .ignore_self_closing = false,
     .emit = emit_xdata},
};

static const IrisXmlRecordRenderer *xml_record_renderer(const char *cursor, const char *end) {
    size_t renderer_count =
        sizeof(IRIS_XML_RECORD_RENDERERS) / sizeof(IRIS_XML_RECORD_RENDERERS[0]);
    for (size_t i = 0; i < renderer_count; i++) {
        const IrisXmlRecordRenderer *renderer = &IRIS_XML_RECORD_RENDERERS[i];
        if (sw(cursor, end, renderer->open_with_attributes) ||
            (renderer->open_without_attributes &&
             sw(cursor, end, renderer->open_without_attributes))) {
            return renderer;
        }
    }
    return NULL;
}

static bool xml_render_record(const IrisXmlRecordRenderer *renderer, UdlBuf *buffer,
                              const char *start, const char *class_end, const char **next_out) {
    const char *tag_end = find_s(start, class_end, ">");
    if (!tag_end) {
        return false;
    }
    *next_out = tag_end + IRIS_XML_TAG_CLOSE_WIDTH;
    if (renderer->ignore_self_closing && is_self_closing(start, tag_end)) {
        return true;
    }
    const char *record_end = find_s(*next_out, class_end, renderer->close);
    if (!record_end) {
        return true;
    }
    *next_out = record_end + strlen(renderer->close);
    renderer->emit(buffer, start, *next_out);
    return true;
}

static char *transcode_class(CBMArena *arena, const char *cs, const char *ce) {
    UdlBuf b;
    ub_init(&b, arena);
    if (!b.buf) {
        return NULL;
    }
    emit_header(&b, cs, ce);
    const char *p = cs;
    while (p < ce) {
        p = skip_ws(p, ce);
        if (p >= ce || *p != '<') {
            if (p < ce) {
                p++;
            }
            continue;
        }
        const IrisXmlRecordRenderer *renderer = xml_record_renderer(p, ce);
        if (renderer) {
            const char *next = NULL;
            if (!xml_render_record(renderer, &b, p, ce, &next)) {
                break;
            }
            p = next;
            continue;
        }
        p = skip_tag(p, ce);
    }
    ub_app(&b, "}\n");
    return b.buf;
}

char **cbm_iris_export_to_udl(CBMArena *arena, const char *xml, int xml_len, int *class_count) {
    if (class_count) {
        *class_count = 0;
    }
    if (!arena || !xml || xml_len <= 0) {
        return NULL;
    }
    const char *end = xml + xml_len;
    if (!find_s(xml, end, EXPORT_MARKER)) {
        return NULL;
    }
    char *results[MAX_CLASSES];
    int count = 0;
    const char *p = xml;
    while (p < end && count < MAX_CLASSES) {
        const char *co = find_s(p, end, "<Class ");
        if (!co) {
            break;
        }
        const char *gt = find_s(co, end, ">");
        if (!gt) {
            break;
        }
        const char *cc = find_s(gt + IRIS_XML_TAG_CLOSE_WIDTH, end, "</Class>");
        if (!cc) {
            break;
        }
        char *udl = transcode_class(arena, co, cc);
        if (udl && udl[0]) {
            results[count++] = udl;
        }
        p = cc + strlen("</Class>");
    }
    if (!count) {
        return NULL;
    }
    char **arr = (char **)cbm_arena_alloc(
        arena, (size_t)(count + IRIS_XML_RESULT_TERMINATOR_SLOTS) * sizeof(char *));
    if (!arr) {
        return NULL;
    }
    for (int i = 0; i < count; i++) {
        arr[i] = results[i];
    }
    arr[count] = NULL;
    if (class_count) {
        *class_count = count;
    }
    return arr;
}
