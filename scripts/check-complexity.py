#!/usr/bin/env python3
"""Complexity ratchet over the graph the product itself builds.

`src/pipeline/pass_complexity.c` computes `complexity` for every Function
node and writes it into the graph. Nothing reads it for any decision, so the
number grows unobserved. This gate makes it load-bearing: it queries the
LIVE graph — built and indexed by the very binary under test — and checks
every function's complexity against complexity.allow.

The gate ratchets in BOTH directions, exactly like check-layering.py:

  new violation — a function over THRESHOLD not in complexity.allow fails.
  stale entry   — an allow-list line naming a function that no longer exists,
                  or is no longer over THRESHOLD, fails. This is what makes
                  it a ratchet instead of a ceiling: fixing a function's
                  complexity is worthless if the excuse for it lives on, so
                  the allow-list cannot silently outlive the debt it excused.

A malformed allow-list line is a hard error, not a silent skip — a typo'd
line would otherwise drop out of the set and read as a missing permission.

Unlike check-layering.py this gate is not pure static analysis: it needs a
built binary and a current index, so an empty result is ambiguous between
"the tree is clean" and "the index is missing or stale". The gate refuses
to treat empty as clean — it always checks the graph actually holds Function
nodes before trusting a query result.

  --report                     print the current over-threshold population
  --allow <path>                default: complexity.allow at repo root
  --binary <path>               default: build/c/codebase-memory-mcp(.exe)
  --project <key>                default: derived from the repo path
  --query-output <path|->       read the population query's CLI output from
                                 a file (or stdin with `-`) instead of
                                 invoking the binary. Testing seam only: it
                                 replaces the DATA SOURCE for the population
                                 query alone — allow-list loading, the
                                 ratchet comparison, and the live index
                                 sanity check all still run unchanged, so the
                                 seam cannot be used to weaken a real run
                                 (which never passes this flag).
  --sanity-query-output <path|->
                                read the Function-node sanity query's CLI
                                output from a file (or stdin with `-`). This
                                testing seam is paired with --query-output so
                                the comparison contract can exercise clean,
                                violation, stale, malformed, and empty-index
                                cases without indexing a worktree. Normal
                                gate invocations never pass either seam.

Usage:
    scripts/check-complexity.py --report        # current over-threshold set
    scripts/check-complexity.py                 # gate, exit 0/1
"""
import argparse
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

THRESHOLD = 60

# Generated code is a code generator's complexity, not ours — java_stdlib_data.c
# and the tree-sitter parsers top the raw list at 869/509/368/328 and would
# swamp every real finding if counted.
EXCLUDED_PATH_SUBSTRINGS = ("tools/tree-sitter", "generated")

POPULATION_QUERY = (
    "MATCH (n:Function) WHERE n.complexity > {threshold} "
    "AND NOT n.file_path CONTAINS 'tools/tree-sitter' "
    "AND NOT n.file_path CONTAINS 'generated' "
    "RETURN n.qualified_name, n.file_path, n.complexity "
    "ORDER BY n.complexity DESC"
).format(threshold=THRESHOLD)

SANITY_QUERY = "MATCH (n:Function) RETURN count(n) AS c"

DEFAULT_BINARY = os.path.join(
    PROJECT_DIR, "build", "c",
    "codebase-memory-mcp.exe" if os.name == "nt" else "codebase-memory-mcp")

ROWS_HEADER_RE = re.compile(r"^rows:\s*(\d+)\s*\(cols:.*\)\s*$")
TOTAL_RE = re.compile(r"^total:\s*(\d+)\s*$")


def project_key_from_path(repo_path):
    """Derive the project key the same way the binary does: canonicalize,
    normalize separators, keep [A-Za-z0-9._-], turn every other byte into
    '-' (non-ASCII bytes become two lowercase hex digits instead), collapse
    repeats, and trim leading '-'/'.' and trailing '-'.

    This mirrors cbm_project_name_from_path (src/pipeline/fqn.c) closely
    enough for any real filesystem path this gate will ever see. It does not
    reproduce the >200-byte truncation-and-hash fallback — no path this gate
    runs against gets remotely close to that length, and a mismatch here
    fails loudly at the sanity check below rather than silently misindexing."""
    canonical = os.path.realpath(repo_path)
    normalized = canonical.replace("\\", "/")
    out = []
    for ch in normalized:
        code = ord(ch)
        if ch.isascii() and (ch.isalnum() or ch in "._-"):
            out.append(ch)
        elif code >= 0x80:
            for b in ch.encode("utf-8"):
                out.append("{:02x}".format(b))
        else:
            out.append("-")
    key = "".join(out)
    key = re.sub(r"-+", "-", key)
    key = re.sub(r"\.+", ".", key)
    key = key.strip("-.")
    key = key.rstrip("-")
    return key or "root"


def run_cli(binary, args):
    """Run the binary's CLI, returning (stdout, stderr, returncode)."""
    result = subprocess.run(
        [binary] + args, cwd=PROJECT_DIR,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout, result.stderr, result.returncode


def parse_query_graph_output(text):
    """Parse `cli query_graph` stdout into a list of row token-lists.

    Format: a `rows: N  (cols: ...)` header, N indented rows of
    whitespace-separated tokens (numeric columns quoted, string columns
    not), a `total: N` footer, and an optional trailing hint line. Anything
    that doesn't fit this shape is a hard parse error — never silently
    treated as zero rows, which is exactly the "empty means missing" trap
    this gate exists to avoid."""
    lines = text.splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if ROWS_HEADER_RE.match(line):
            header_idx = i
            break
    if header_idx is None:
        raise ValueError("no 'rows: N (cols: ...)' header found in query_graph output")

    expected_rows = int(ROWS_HEADER_RE.match(lines[header_idx]).group(1))
    rows = []
    total = None
    i = header_idx + 1
    while i < len(lines):
        line = lines[i]
        m = TOTAL_RE.match(line)
        if m:
            total = int(m.group(1))
            i += 1
            break
        stripped = line.strip()
        if stripped:
            rows.append(stripped.split())
        i += 1

    if total is None:
        raise ValueError("no 'total: N' footer found in query_graph output")
    if len(rows) != expected_rows:
        raise ValueError(
            f"header promised {expected_rows} row(s), parsed {len(rows)}")
    if total != expected_rows:
        raise ValueError(
            f"header rows ({expected_rows}) and total ({total}) disagree")
    return rows


def query_graph(binary, project, query):
    """Run one query_graph call and return its parsed rows, or raise."""
    stdout, stderr, rc = run_cli(
        binary, ["cli", "query_graph", "--project", project, "--query", query])
    if rc != 0:
        raise ValueError(
            f"query_graph exited {rc} for query: {query!r}\n{stderr.strip()}")
    try:
        return parse_query_graph_output(stdout)
    except ValueError as exc:
        raise ValueError(f"{exc}\n--- raw stdout ---\n{stdout}") from exc


def read_query_output_override(path):
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    return parse_query_graph_output(text)


def rows_to_population(rows):
    """3-column rows (qualified_name, file_path, complexity) -> set of
    (file_path, function_name, complexity). The function name is the last
    dot-separated segment of the qualified name; file_path is already
    project-relative, straight from the graph, no derivation needed."""
    population = set()
    for row in rows:
        if len(row) < 3:
            raise ValueError(f"expected 3+ columns, got {row!r}")
        qualified_name = row[0]
        complexity_raw = row[-1]
        file_path = " ".join(row[1:-1])
        function_name = qualified_name.rsplit(".", 1)[-1]
        complexity = int(complexity_raw.strip('"'))
        population.add((file_path, function_name, complexity))
    return population


ALLOW_LINE_RE = re.compile(r"^(\S+):(\S+)$")


def load_allowlist(path):
    """Return (allowed, malformed). allowed maps (file_path, function_name)
    to nothing but membership — mirrors check-layering.py's load_allowlist:
    an unparseable line is reported, never dropped, since a silently-skipped
    typo reads as a missing permission rather than what it is."""
    allowed = set()
    malformed = []
    if not os.path.isfile(path):
        return allowed, malformed
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = ALLOW_LINE_RE.match(line)
            if not m:
                malformed.append(f"{path}:{lineno}: {line}")
                continue
            allowed.add((m.group(1), m.group(2)))
    return allowed, malformed


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", action="store_true",
                         help="print the current over-threshold population and exit 0")
    parser.add_argument("--allow", default=os.path.join(PROJECT_DIR, "complexity.allow"),
                         help="allow-list path (default: complexity.allow at repo root)")
    parser.add_argument("--binary", default=DEFAULT_BINARY,
                         help="codebase-memory-mcp binary (default: %(default)s)")
    parser.add_argument("--project", default=None,
                         help="project key (default: derived from the repo path)")
    parser.add_argument("--query-output", default=None,
                         help="testing seam: read the population query's CLI output "
                              "from this file (or '-' for stdin) instead of invoking "
                              "the binary")
    parser.add_argument("--sanity-query-output", default=None,
                         help="testing seam: read the Function-node sanity-query output "
                              "from this file (or '-' for stdin) instead of invoking "
                              "the binary")
    args = parser.parse_args()

    # The population-output seam only replaces the second query's data.  It
    # never makes the live binary or its indexed Function population optional:
    # accepting a missing binary here would make a synthetic report look like
    # a successful gate run.
    if not os.path.isfile(args.binary):
        print(f"MISSING: no binary at {args.binary}.")
        print("Build it first — this gate measures the graph the product builds, "
              "it does not reimplement complexity measurement.")
        return 1

    project = args.project or project_key_from_path(PROJECT_DIR)

    # Sanity check: the graph must actually hold Function nodes, or every
    # query below returning zero rows is indistinguishable from "the index
    # is missing/stale" — and THAT must never read as "clean tree". The
    # paired fixture seam exists only to test this branch without indexing a
    # worktree; ordinary invocations always execute the live query.
    try:
        if args.sanity_query_output is not None:
            sanity_rows = read_query_output_override(args.sanity_query_output)
        else:
            sanity_rows = query_graph(args.binary, project, SANITY_QUERY)
    except ValueError as exc:
        print(f"MISSING: could not query the graph — {exc}")
        print("Index the repo first (cli index_repository) before running this gate.")
        return 1
    function_count = int(sanity_rows[0][-1].strip('"')) if sanity_rows else 0
    if function_count == 0:
        print(f"MISSING: graph for project '{project}' has zero Function nodes.")
        print("Index the repo first (cli index_repository) — an empty graph is "
              "'could not measure', never 'clean'.")
        return 1

    try:
        if args.query_output is not None:
            pop_rows = read_query_output_override(args.query_output)
        else:
            pop_rows = query_graph(args.binary, project, POPULATION_QUERY)
        population = rows_to_population(pop_rows)
    except ValueError as exc:
        print(f"MALFORMED: could not parse the population query's output — {exc}")
        return 1

    if args.report:
        for file_path, function_name, complexity in sorted(population):
            print(f"{complexity:4d}  {file_path}  {function_name}")
        return 0

    allowed, malformed = load_allowlist(args.allow)
    status = 0

    if malformed:
        print(f"MALFORMED: {len(malformed)} unparseable line(s) in {args.allow}:")
        for site in malformed:
            print(f"  {site}")
        status = 1

    current = {(file_path, function_name) for file_path, function_name, _ in population}
    complexity_of = {(file_path, function_name): complexity
                      for file_path, function_name, complexity in population}

    violations = sorted(current - allowed)
    if violations:
        print(f"BLOCKED: {len(violations)} function(s) over complexity {THRESHOLD} "
              f"not in {args.allow}:")
        for file_path, function_name in violations:
            complexity = complexity_of[(file_path, function_name)]
            print(f"  {file_path}:{function_name}  (complexity {complexity})")
        status = 1

    # The allow-list is an exact snapshot, not a ceiling. An entry with no
    # matching over-threshold function means the function was removed, or
    # reduced back under THRESHOLD, and its permission was left behind —
    # which would let the same debt grow back unnoticed. Deleting the line
    # is what turns a one-off cleanup into a permanent constraint.
    stale = sorted(allowed - current)
    if stale:
        print(f"STALE: {len(stale)} allow-list entry(s) in {args.allow} no longer "
              f"over complexity {THRESHOLD} (or gone).")
        print("Delete the lines to lock the improvement in:")
        for file_path, function_name in stale:
            print(f"  {file_path}:{function_name}")
        status = 1

    if status == 0:
        print(f"OK: {len(current)} function(s) over complexity {THRESHOLD} "
              f"allow-listed, none stale")
    return status


if __name__ == "__main__":
    sys.exit(main())
