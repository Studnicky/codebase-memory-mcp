#!/usr/bin/env python3
"""Architecture gate over the C include graph.

Walks every source file under src/ and internal/ (excluding vendored/ trees),
parses each #include, and enforces two policies:

  module layering  — an edge is (from_module -> to_module) where the two
                     modules differ, checked against layering.allow.
  trust boundaries — an edge is (module -> third-party library) for any
                     include reaching a vendored or linked library, checked
                     against externals.allow. A module on that list holds a
                     foreign API's types and error conventions directly
                     rather than consuming an adapter that normalizes them
                     once at the edge.

Both gates ratchet in BOTH directions. A source edge with no entry is a new
violation. An entry with no source edge is a permission outliving the code it
described, which would let a removed edge grow back unnoticed. Both fail.

  --report              print the module edge set and exit 0
  --report-externals    print the third-party edge set and exit 0
  --allow <path>        default: layering.allow at repo root
  --allow-externals <path>  default: externals.allow at repo root

Usage:
    scripts/check-layering.py --report > layering.allow    # (plus header)
    scripts/check-layering.py --report-externals           # third-party set
    scripts/check-layering.py                              # gate, exit 0/1
"""
import argparse
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

SCAN_ROOTS = ("src", "internal")
INCLUDE_ROOTS = ("src", os.path.join("internal", "cbm"), "")
VENDORED_COMPONENT = "vendored"
# Every extension the build compiles or includes. internal/cbm/preprocessor.cpp
# is a first-party compiled translation unit; leaving C++ out would exempt it
# from the gate entirely.
SOURCE_EXTENSIONS = (".c", ".h", ".cpp", ".cc", ".hpp", ".hh")

# `#include SOME_MACRO` names a header the gate cannot resolve without running
# the preprocessor. Rather than skip the line and pass, the gate refuses: an
# unresolvable include is the one construct that could hide an edge on purpose.
MACRO_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+(?![<"])(\S+)')

# Third-party headers, named by the library behind them. Every one is a trust
# boundary: the foreign API's types, error conventions and lifetime rules stop
# being ours the moment a module includes it directly. sqlite3 returns int and
# uses negatives for errors; lz4/zstd return negative lengths; POSIX regex uses
# -1 for an unmatched group; posix_spawn takes a non-const argv it does not
# write; zlib's next_in is non-const without ZLIB_CONST. Each of those has cost
# this codebase a real defect, and each is invisible to callers once an adapter
# normalizes it once, at the edge, into our own types.
#
# src/foundation/compat_regex.h is the reference adapter: it owns <regex.h>,
# publishes cbm_regex_t / cbm_regmatch_t / CBM_REG_NOMATCH, and states the rule
# outright — "callers never include <regex.h> directly".
#
# An include is also treated as external when it resolves into a vendored/
# tree, so a new vendored library is covered without editing this table.
EXTERNAL_HEADERS = {
    "sqlite3.h": "sqlite3",
    "sqlite3/sqlite3.h": "sqlite3",
    "yyjson/yyjson.h": "yyjson",
    "xxhash/xxhash.h": "xxhash",
    "mimalloc.h": "mimalloc",
    "verstable.h": "verstable",
    "lz4.h": "lz4",
    "lz4hc.h": "lz4",
    "zstd.h": "zstd",
    "tree_sitter/api.h": "tree-sitter",
    "zlib.h": "zlib",
    "git2.h": "libgit2",
    "regex.h": "tre",
}

QUOTED_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"')
# Angle-bracket includes reach first-party headers too: -Isrc is on the command
# line, so `#include <store/store.h>` names src/store/store.h exactly as the
# quoted form does. Matching only the quoted form would let any edge hide behind
# a bracket, which is the one way to defeat this gate without touching it.
ANGLE_INCLUDE_RE = re.compile(r"^\s*#\s*include\s*<([^>]+)>")


def is_vendored(rel_path):
    return VENDORED_COMPONENT in rel_path.split(os.sep)


def iter_source_files():
    """Yield repo-relative paths of every source file under SCAN_ROOTS, minus vendored/."""
    for scan_root in SCAN_ROOTS:
        abs_root = os.path.join(PROJECT_DIR, scan_root)
        for dirpath, dirnames, filenames in os.walk(abs_root):
            dirnames[:] = [d for d in dirnames if d != VENDORED_COMPONENT]
            for name in filenames:
                if not name.endswith(SOURCE_EXTENSIONS):
                    continue
                abs_path = os.path.join(dirpath, name)
                rel_path = os.path.relpath(abs_path, PROJECT_DIR)
                if is_vendored(rel_path):
                    continue
                yield rel_path


def module_of(rel_path):
    """First path component below src/ or internal/; src/main.c -> module 'main'."""
    parts = rel_path.split(os.sep)
    if parts[0] == "src":
        if len(parts) == 2:
            return "main"
        return parts[1]
    if parts[0] == "internal":
        return parts[1]
    return None


def resolve_include(including_rel_path, target, local_first):
    """Resolve an #include target to a repo-relative path, or None.

    local_first mirrors the compiler: the quoted form searches the including
    file's own directory before the -I roots, the angle form searches only the
    -I roots."""
    candidates = []
    if local_first:
        including_dir = os.path.dirname(including_rel_path)
        candidates.append(os.path.normpath(os.path.join(including_dir, target)))
    for root in INCLUDE_ROOTS:
        candidates.append(os.path.normpath(os.path.join(root, target)))

    for candidate in candidates:
        # Reject anything that escapes the repo root.
        abs_candidate = os.path.normpath(os.path.join(PROJECT_DIR, candidate))
        if not abs_candidate.startswith(PROJECT_DIR + os.sep):
            continue
        if os.path.isfile(abs_candidate):
            rel = os.path.relpath(abs_candidate, PROJECT_DIR)
            top = rel.split(os.sep)[0]
            if top in SCAN_ROOTS:
                return rel
    return None


def external_library(raw_include, resolved):
    """Name the third-party library an include reaches, or None if it is ours.

    Matches the include as written (so <sqlite3.h> and "xxhash/xxhash.h" are
    both caught) and, failing that, anything resolving into a vendored/ tree —
    which covers a newly vendored library with no table entry."""
    normalized = raw_include.replace(os.sep, "/")
    if normalized in EXTERNAL_HEADERS:
        return EXTERNAL_HEADERS[normalized]
    for header, library in EXTERNAL_HEADERS.items():
        if normalized.endswith("/" + header):
            return library
    if resolved is not None and is_vendored(resolved):
        parts = resolved.split(os.sep)
        index = parts.index(VENDORED_COMPONENT)
        if index + 1 < len(parts):
            return parts[index + 1]
    return None


def collect_edges():
    """Return (edges, edge_sites, unresolvable).

    edge_sites maps an edge to its first file:line. unresolvable lists include
    directives the gate cannot statically resolve; they are reported as
    failures, never skipped."""
    edges = set()
    edge_sites = {}
    unresolvable = []
    external_edges = set()
    external_sites = {}
    for rel_path in sorted(iter_source_files()):
        from_module = module_of(rel_path)
        if from_module is None:
            continue
        abs_path = os.path.join(PROJECT_DIR, rel_path)
        with open(abs_path, encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                m = QUOTED_INCLUDE_RE.match(line)
                local_first = m is not None
                if m is None:
                    m = ANGLE_INCLUDE_RE.match(line)
                if m is None:
                    macro = MACRO_INCLUDE_RE.match(line)
                    if macro:
                        unresolvable.append(f"{rel_path}:{lineno}: #include {macro.group(1)}")
                    continue
                raw = m.group(1)
                target = resolve_include(rel_path, raw, local_first)
                library = external_library(raw, target)
                if library is not None:
                    edge = (from_module, library)
                    external_edges.add(edge)
                    external_sites.setdefault(edge, f"{rel_path}:{lineno}")
                if target is None or is_vendored(target):
                    continue
                to_module = module_of(target)
                if to_module is None or to_module == from_module:
                    continue
                edge = (from_module, to_module)
                edges.add(edge)
                edge_sites.setdefault(edge, f"{rel_path}:{lineno}")
    return edges, edge_sites, unresolvable, external_edges, external_sites


def load_allowlist(path):
    """Return (allowed, malformed). A line that does not parse is reported, not
    dropped: a typo'd entry would otherwise read as a missing permission and
    send someone chasing a violation that is really a spelling mistake."""
    allowed = set()
    malformed = []
    if not os.path.isfile(path):
        return allowed, malformed
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r"^(\S+)\s*->\s*(\S+)$", line)
            if not m:
                malformed.append(f"{path}:{lineno}: {line}")
                continue
            allowed.add((m.group(1), m.group(2)))
    return allowed, malformed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true",
                         help="print the full sorted edge set and exit 0")
    parser.add_argument("--allow", default=os.path.join(PROJECT_DIR, "layering.allow"),
                         help="allow-list path (default: layering.allow at repo root)")
    parser.add_argument("--report-externals", action="store_true",
                         help="print the module -> third-party-library edge set and exit 0")
    parser.add_argument("--allow-externals",
                         default=os.path.join(PROJECT_DIR, "externals.allow"),
                         help="third-party allow-list (default: externals.allow at repo root)")
    args = parser.parse_args()

    edges, edge_sites, unresolvable, external_edges, external_sites = collect_edges()

    if args.report:
        for from_module, to_module in sorted(edges):
            print(f"{from_module} -> {to_module}")
        return 0

    if args.report_externals:
        for from_module, library in sorted(external_edges):
            print(f"{from_module} -> {library}")
        return 0

    allowed, malformed = load_allowlist(args.allow)
    external_allowed, external_malformed = load_allowlist(args.allow_externals)
    malformed += external_malformed
    status = 0

    if unresolvable:
        print(f"UNRESOLVABLE: {len(unresolvable)} include(s) the gate cannot follow.")
        print("Name the header directly so the edge is visible to the gate:")
        for site in unresolvable:
            print(f"  {site}")
        status = 1

    if malformed:
        print(f"MALFORMED: {len(malformed)} unparseable line(s) in {args.allow}:")
        for site in malformed:
            print(f"  {site}")
        status = 1

    violations = sorted(edges - allowed)
    if violations:
        print(f"BLOCKED: {len(violations)} module-layering edge(s) not in {args.allow}:")
        for from_module, to_module in violations:
            site = edge_sites.get((from_module, to_module), "?")
            print(f"  {from_module} -> {to_module}  (introduced at {site})")
        status = 1

    # The allow-list is an exact snapshot, not a ceiling. An entry with no
    # matching edge means the edge was removed from the source but its
    # permission was left behind, which would let the same edge grow back
    # unnoticed and silently undo the work that removed it. Deleting the line
    # is what turns a one-off cleanup into a permanent constraint.
    stale = sorted(allowed - edges)
    if stale:
        print(f"STALE: {len(stale)} allow-list entry(s) in {args.allow} with no such edge.")
        print("These edges are gone from the source. Delete the lines to lock them out:")
        for from_module, to_module in stale:
            print(f"  {from_module} -> {to_module}")
        status = 1

    # Third-party gate. Each edge is a module reaching across a trust boundary
    # directly rather than through an adapter that normalizes the foreign API's
    # types and error conventions once. New ones fail; an entry whose edge is
    # gone also fails, so retiring a direct dependency is permanent.
    external_violations = sorted(external_edges - external_allowed)
    if external_violations:
        print(f"BLOCKED: {len(external_violations)} module(s) reaching a third-party "
              f"library directly, not in {args.allow_externals}:")
        for from_module, library in external_violations:
            site = external_sites.get((from_module, library), "?")
            print(f"  {from_module} -> {library}  (introduced at {site})")
        print("Wrap the library in an adapter that owns its header and publishes our")
        print("own types, as src/foundation/compat_regex.h does for <regex.h>.")
        status = 1

    external_stale = sorted(external_allowed - external_edges)
    if external_stale:
        print(f"STALE: {len(external_stale)} entry(s) in {args.allow_externals} "
              f"with no such dependency.")
        print("The module no longer reaches that library. Delete the lines to lock it out:")
        for from_module, library in external_stale:
            print(f"  {from_module} -> {library}")
        status = 1

    if status == 0:
        print(f"OK: {len(edges)} module edge(s) and {len(external_edges)} "
              f"third-party edge(s), all allow-listed")
    return status


if __name__ == "__main__":
    sys.exit(main())
