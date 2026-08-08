#!/usr/bin/env bash
# Contract: scripts/check-complexity.py must ratchet in BOTH directions and
# never read "found nothing" as "clean".
#
# Requires a built binary and a current index for THIS repo (build/c/
# codebase-memory-mcp indexed as itself) — this gate is not pure static
# analysis, unlike check-layering.py, so this test skips rather than fails
# when that prerequisite is missing (a fresh checkout with no build yet is
# not a gate regression).
#
# The negative probes use --query-output to inject a synthetic population
# query result instead of re-indexing per case (~30s each). The seam only
# ever substitutes the DATA for the population query; the sanity check that
# the graph holds Function nodes at all still hits the real binary, so the
# probes prove the comparison LOGIC without weakening what a real
# (flag-less) run does.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GATE="$ROOT/scripts/check-complexity.py"
BINARY="$ROOT/build/c/codebase-memory-mcp"
[ -x "$BINARY" ] || BINARY="$ROOT/build/c/codebase-memory-mcp.exe"

if [ ! -x "$BINARY" ]; then
    echo "SKIP: no built binary at build/c/codebase-memory-mcp — build first" >&2
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

# ---- 0. Live population, captured once, reused by the injection probes ----
REAL_POP="$WORK/real_pop.txt"
python3 "$GATE" --binary "$BINARY" --report >/dev/null 2>"$WORK/report_stderr.txt" \
    || fail "baseline --report failed (index missing? see $WORK/report_stderr.txt)"

# Recover the raw query_graph rows the gate itself would have queried, by
# asking the same binary/project the gate resolves internally.
PROJECT="$(python3 - "$GATE" "$ROOT" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("gate", sys.argv[1])
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
print(gate.project_key_from_path(sys.argv[2]))
PY
)"
"$BINARY" cli query_graph --project "$PROJECT" --query \
    "MATCH (n:Function) WHERE n.complexity > 60 AND NOT n.file_path CONTAINS 'tools/tree-sitter' AND NOT n.file_path CONTAINS 'generated' RETURN n.qualified_name, n.file_path, n.complexity ORDER BY n.complexity DESC" \
    2>/dev/null > "$REAL_POP"
grep -q "^rows:" "$REAL_POP" || fail "could not capture the live population (is the repo indexed?)"

# ---- 1. Clean tree passes ----
if ! python3 "$GATE" --binary "$BINARY" >/dev/null 2>"$WORK/clean_stderr.txt"; then
    fail "clean tree did not exit 0 (see $WORK/clean_stderr.txt)"
fi
echo "PASS: clean tree exits 0"

# ---- 2. New violation: a function over threshold absent from the allow-list ----
python3 - "$REAL_POP" "$WORK/injected.txt" <<'PY'
import re, sys
lines = open(sys.argv[1]).read().splitlines()
m = re.match(r"^rows:\s*(\d+)\s*\(cols:(.*)\)\s*$", lines[0])
n, cols = int(m.group(1)), m.group(2)
body = lines[1:1 + n]
body.append('  fake-project.fake_module.fake_over_threshold_fn fake_module.c "999"')
n2 = n + 1
out = [f"rows: {n2}  (cols:{cols})"] + body + [f"total: {n2}"]
open(sys.argv[2], "w").write("\n".join(out) + "\n")
PY
if python3 "$GATE" --binary "$BINARY" --query-output "$WORK/injected.txt" \
        >"$WORK/new_violation_out.txt" 2>&1; then
    fail "a function over threshold not in the allow-list did not fail the gate"
fi
grep -q "fake_module.c:fake_over_threshold_fn" "$WORK/new_violation_out.txt" \
    || fail "new-violation failure did not name the offending function"
echo "PASS: new violation over threshold, absent from allow-list, fails the gate"

# ---- 3. Stale entry: allow-list line survives after its function drops out
#         of the over-threshold population (deleted, or fixed below 60 —
#         both look identical to the gate: the row is simply gone) ----
python3 - "$REAL_POP" "$WORK/one_dropped.txt" <<'PY'
import re, sys
lines = open(sys.argv[1]).read().splitlines()
m = re.match(r"^rows:\s*(\d+)\s*\(cols:(.*)\)\s*$", lines[0])
n, cols = int(m.group(1)), m.group(2)
body = lines[1:1 + n]
before = len(body)
body = [l for l in body if "cs_eval_expr_type" not in l]
if len(body) != before - 1:
    sys.exit("fixture error: expected to drop exactly one row (cs_eval_expr_type)")
n2 = len(body)
out = [f"rows: {n2}  (cols:{cols})"] + body + [f"total: {n2}"]
open(sys.argv[2], "w").write("\n".join(out) + "\n")
PY
if python3 "$GATE" --binary "$BINARY" --query-output "$WORK/one_dropped.txt" \
        >"$WORK/stale_out.txt" 2>&1; then
    fail "an allow-list entry whose function dropped below threshold did not fail the gate"
fi
grep -q "STALE" "$WORK/stale_out.txt" || fail "stale-entry failure did not report STALE"
grep -q "cs_lsp.c:cs_eval_expr_type" "$WORK/stale_out.txt" \
    || fail "stale-entry failure did not name the surviving-but-unneeded line"
echo "PASS: allow-list entry outliving its function (deleted OR fixed below threshold) fails the gate"

# ---- 4. Deleting a still-over-threshold line from the real allow-list fails ----
cp "$ROOT/complexity.allow" "$WORK/complexity.allow.orig"
grep -v ":c_eval_expr_type_inner" "$ROOT/complexity.allow" > "$WORK/complexity.allow.trimmed"
if python3 "$GATE" --binary "$BINARY" --allow "$WORK/complexity.allow.trimmed" \
        >"$WORK/deleted_line_out.txt" 2>&1; then
    fail "deleting a still-over-threshold allow-list line did not fail the gate"
fi
grep -q "c_lsp.c:c_eval_expr_type_inner" "$WORK/deleted_line_out.txt" \
    || fail "deleted-line failure did not name the now-unlisted function"
echo "PASS: deleting a still-over-threshold allow-list line fails the gate"

# ---- 5. A malformed allow-list line fails, not a silent skip ----
cp "$ROOT/complexity.allow" "$WORK/complexity.allow.malformed"
echo "this-line-has-no-colon-separator" >> "$WORK/complexity.allow.malformed"
if python3 "$GATE" --binary "$BINARY" --allow "$WORK/complexity.allow.malformed" \
        >"$WORK/malformed_out.txt" 2>&1; then
    fail "a malformed allow-list line did not fail the gate"
fi
grep -q "MALFORMED" "$WORK/malformed_out.txt" || fail "malformed-line failure did not report MALFORMED"
echo "PASS: a malformed allow-list line fails the gate rather than being silently skipped"

# ---- 6. Missing binary fails loudly, never exits 0 on 'nothing to check' ----
if python3 "$GATE" --binary "$WORK/no-such-binary" >"$WORK/missing_binary_out.txt" 2>&1; then
    fail "a missing binary did not fail the gate"
fi
grep -q "MISSING" "$WORK/missing_binary_out.txt" || fail "missing-binary failure did not report MISSING"
echo "PASS: a missing binary fails the gate loudly"

# ---- 7. Missing/empty index fails loudly, never exits 0 on 'nothing to check' ----
if python3 "$GATE" --binary "$BINARY" --project "definitely-not-an-indexed-project-xyz" \
        >"$WORK/missing_index_out.txt" 2>&1; then
    fail "a missing/unindexed project did not fail the gate"
fi
grep -q "MISSING" "$WORK/missing_index_out.txt" || fail "missing-index failure did not report MISSING"
echo "PASS: a missing/unindexed project fails the gate loudly rather than reading empty as clean"

echo "PASS: complexity gate contract — ratchets both directions, malformed lines are hard errors, empty is never clean"
