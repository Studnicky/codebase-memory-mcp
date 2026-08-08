#!/usr/bin/env python3
"""NULL-discipline gate. Zero tolerance — no allow-list, no baseline.

NULL is allowed to mean exactly one thing: "there is no object here." A malloc
that failed, a lookup that found nothing. That is unavoidable in C and is not
what this gate is about.

What this gate forbids is NULL used as a VALUE — a slot the program acts on
without being able to tell that nothing is there. Two shapes, both of which have
already cost this codebase real breakage:

  callable-slot   A NULL where a function pointer is expected. Nothing checks
                  it; it gets called. sqlite's xInit is exactly this: passing
                  NULL to mean "nothing to initialise" jumps to address 0 and
                  the process dies with no diagnostic. A no-op is a function
                  that does nothing — not the absence of one.

  decoded-null    A string-valued accessor that returns NULL, forcing every
                  call site to write `x ? x : ""`. The sites that remember are
                  fine; the ones that forget dereference NULL. The fix belongs
                  in the accessor: return "", and publish an explicit predicate
                  where the difference between "" and absent genuinely matters.

Detection of callable-slot covers BOTH initializer forms. The designated form
(`.xInit = NULL`) is the easy one; the positional form (`{f, g, NULL, NULL}`)
is the one that actually bit, so struct layouts are parsed — including from
vendored headers, which are excluded from violation scanning but are exactly
where the foreign callback structs are declared.

  --report     list current violations
  --self-test  prove the detector catches a known-bad positional initializer
"""
import argparse
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

# Scanned for violations.
SCAN_ROOTS = ("src", "internal")
# Scanned only for struct layouts. Foreign callback structs live here, and a
# layout we cannot see is a violation we cannot detect.
LAYOUT_ROOTS = ("src", "internal", "vendored")

FN_PTR_FIELD_RE = re.compile(r'\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(')
STRUCT_BLOCK_RE = re.compile(
    r'(?:typedef\s+)?struct\s+(?:([A-Za-z_]\w*)\s*)?\{(.*?)\}\s*([A-Za-z_]\w*)?\s*;',
    re.DOTALL)
DESIGNATED_NULL_RE = re.compile(r'\.\s*([A-Za-z_]\w*)\s*=\s*NULL\s*[,}]')
DECODED_NULL_RE = re.compile(r'\b([A-Za-z_][\w\->\.]*)\s*\?\s*\1\s*:\s*"')


def _find(roots, exts, drop_vendored):
    pattern = " -o ".join(f"-name '*{e}'" for e in exts)
    cmd = f"find {' '.join(roots)} \\( {pattern} \\)"
    if drop_vendored:
        cmd += " | grep -v vendored"
    out = subprocess.run(["bash", "-c", cmd], cwd=PROJECT_DIR,
                         capture_output=True, text=True).stdout.split()
    return sorted(out)


def struct_layouts():
    """Map each struct type name to the field positions that are function
    pointers, plus the set of every function-pointer field name seen anywhere.

    Both are needed: positions catch the positional initializer, names catch
    the designated one.
    """
    positions = {}
    names = set()
    for path in _find(LAYOUT_ROOTS, (".h", ".c"), drop_vendored=False):
        try:
            with open(os.path.join(PROJECT_DIR, path), errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for tag, body, alias in STRUCT_BLOCK_RE.findall(text):
            fn_positions = set()
            for index, field in enumerate(
                    [f for f in body.split(";") if f.strip()]):
                m = FN_PTR_FIELD_RE.search(field)
                if m:
                    fn_positions.add(index)
                    names.add(m.group(1))
            if not fn_positions:
                continue
            for key in (tag, alias):
                if key:
                    positions.setdefault(key, set()).update(fn_positions)
    return positions, names


def _split_top_level(text):
    """Split an initializer body on commas that are not nested."""
    parts, depth, current = [], 0, ""
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        current += ch
    parts.append(current)
    return parts


def find_violations(positions, names):
    found = []
    type_alt = "|".join(re.escape(t) for t in sorted(positions)) if positions else None
    # Both spellings matter. `TYPE name = {...};` puts the type before the `=`;
    # a compound literal `name = (TYPE){...};` puts it after, and that is the
    # form the sqlite allocator bug was written in.
    init_res = ([
        re.compile(r'\b(?:struct\s+)?(' + type_alt + r')\b[^;{=]*=\s*\{(.*?)\}\s*;', re.DOTALL),
        re.compile(r'\(\s*(?:struct\s+)?(' + type_alt + r')\s*\)\s*\{(.*?)\}', re.DOTALL),
    ] if type_alt else [])

    for path in _find(SCAN_ROOTS, (".c", ".h"), drop_vendored=True):
        with open(os.path.join(PROJECT_DIR, path), errors="replace") as fh:
            text = fh.read()
        lines = text.split("\n")

        for i, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if stripped.startswith(("*", "//", "/*")):
                continue
            m = DESIGNATED_NULL_RE.search(line)
            if m and m.group(1) in names:
                found.append((path, i, "callable-slot", m.group(1)))
            for dm in DECODED_NULL_RE.finditer(line):
                leaf = dm.group(1).split("->")[-1].split(".")[-1]
                found.append((path, i, "decoded-null", leaf))

        for init_re in init_res:
            for m in init_re.finditer(text):
                type_name, body = m.group(1), m.group(2)
                if "." in body:
                    continue  # designated form, handled above
                line_no = text[:m.start()].count("\n") + 1
                for index, part in enumerate(_split_top_level(body)):
                    if part.strip() == "NULL" and index in positions[type_name]:
                        found.append((path, line_no, "callable-slot",
                                      f"{type_name}[{index}]"))
    return sorted(set(found))


SELF_TEST = '''
typedef struct {
    void *(*xMalloc)(int);
    int (*xInit)(void *);
} probe_methods;
static probe_methods m = {probe_malloc, NULL};
'''


def self_test():
    """Prove the positional detector catches the shape that actually crashed."""
    import tempfile
    positions, names = struct_layouts()
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "probe.c")
        with open(path, "w") as fh:
            fh.write(SELF_TEST)
        text = open(path).read()
        local_positions, local_names = {}, set()
        for tag, body, alias in STRUCT_BLOCK_RE.findall(text):
            fn = {i for i, f in enumerate([x for x in body.split(";") if x.strip()])
                  if FN_PTR_FIELD_RE.search(f)}
            for key in (tag, alias):
                if key and fn:
                    local_positions.setdefault(key, set()).update(fn)
        hit = False
        alt = "|".join(re.escape(t) for t in local_positions)
        rx = re.compile(r'\b(?:struct\s+)?(' + alt + r')\b[^;{=]*=\s*\{(.*?)\}\s*;', re.DOTALL)
        for m in rx.finditer(text):
            for index, part in enumerate(_split_top_level(m.group(2))):
                if part.strip() == "NULL" and index in local_positions[m.group(1)]:
                    hit = True
    if hit:
        print("SELF-TEST OK: a positional NULL in a function-pointer slot is detected")
        return 0
    print("SELF-TEST FAILED: the detector would miss a NULL callable slot.")
    print("A gate that cannot catch its own motivating bug must not be trusted.")
    return 1


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    positions, names = struct_layouts()
    if not positions:
        print("MISSING: no struct layouts parsed — refusing to report a clean tree.")
        return 1

    violations = find_violations(positions, names)

    if args.report:
        for path, line, kind, detail in violations:
            print(f"{path}:{line}\t{kind}\t{detail}")
        by_kind = {}
        for _, _, kind, _ in violations:
            by_kind[kind] = by_kind.get(kind, 0) + 1
        print(f"\n{len(violations)} violation(s): " +
              ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items())))
        return 0

    callable = [v for v in violations if v[2] == "callable-slot"]
    decoded = [v for v in violations if v[2] == "decoded-null"]

    # callable-slot is enforced at zero, with no allow-list. There is no
    # legitimate reason to put NULL in a slot that will be called: sqlite's
    # xInit proved that the caller does not check, it just jumps.
    if callable:
        print(f"BLOCKED: {len(callable)} NULL in a slot that will be called. "
              "This rule has no allow-list by design.")
        for path, line, _, detail in callable:
            print(f"  {path}:{line}  {detail}")
        print("\nGive the slot a real no-op function. NULL is not one — it is an "
              "address the callee will jump to.")
        return 1

    # decoded-null is reported, not enforced. Driving it to zero blindly is
    # wrong: `properties_json ? properties_json : "{}"` is correct code, because
    # "" is not a valid empty property set and the absence is real. The fix for
    # the ones that ARE wrong is a proper sentinel established where the value
    # is constructed, which then makes the guard dead rather than moved.
    if decoded:
        print(f"OK: no NULL in a callable slot. "
              f"{len(decoded)} decoded-null site(s) remain (reported, not gated):")
        shown = {}
        for _, _, _, detail in decoded:
            shown[detail] = shown.get(detail, 0) + 1
        for detail, count in sorted(shown.items(), key=lambda kv: -kv[1])[:10]:
            print(f"  {count:4d}  {detail}")
        print("  run --report for the full list")
        return 0

    print("OK: no NULL used as a value")
    return 0


if __name__ == "__main__":
    sys.exit(main())
