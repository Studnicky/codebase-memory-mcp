#!/usr/bin/env bash
# Contract: scripts/check-complexity.py ratchets in both directions and never
# reads an empty or unavailable index as a clean graph. Fixtures replace both
# query responses, so this unit contract needs neither a built binary nor an
# indexed checkout; pr.yml separately runs the real post-build live gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GATE="$ROOT/scripts/check-complexity.py"
# The checker validates that a binary path exists before accepting either test
# seam. Its own source file is a stable existing path while fixtures prevent
# any subprocess invocation; the missing-binary probes below cover rejection.
FIXTURE_BINARY="$GATE"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

python3 - "$WORK" <<'PY'
from pathlib import Path
import sys

work = Path(sys.argv[1])
(work / "sanity.txt").write_text('rows: 1  (cols: c)\n  "1"\ntotal: 1\n')
(work / "empty-index.txt").write_text('rows: 0  (cols: c)\ntotal: 0\n')
(work / "clean.txt").write_text(
    'rows: 0  (cols: qualified_name file_path complexity)\ntotal: 0\n')
(work / "violation.txt").write_text(
    'rows: 1  (cols: qualified_name file_path complexity)\n'
    '  fixture.module.very_complex fixture.c "999"\n'
    'total: 1\n')
(work / "allowed.allow").write_text('fixture.c:very_complex\n')
(work / "stale.allow").write_text('fixture.c:removed_complexity\n')
(work / "malformed.allow").write_text('not-a-valid-allow-entry\n')
PY

SANITY="$WORK/sanity.txt"
EMPTY_INDEX="$WORK/empty-index.txt"
CLEAN="$WORK/clean.txt"
VIOLATION="$WORK/violation.txt"
EMPTY_ALLOW="$WORK/empty.allow"
ALLOWED="$WORK/allowed.allow"
STALE="$WORK/stale.allow"
MALFORMED="$WORK/malformed.allow"

# The changes job must route every file that can weaken this gate through the
# post-build PR smoke leg. Pull the exact ERE from the workflow and exercise
# it rather than keeping a second classifier in this contract.
PRODUCT_PATTERN="$(sed -n "s/.*grep -qE '\\(.*\\)'; then/\\1/p" .github/workflows/pr.yml)"
[ -n "$PRODUCT_PATTERN" ] || fail "could not extract product-change pattern from .github/workflows/pr.yml"
for control in \
    complexity.allow \
    scripts/check-complexity.py \
    scripts/test.sh \
    tests/test_complexity_gate_contract.sh \
    .github/workflows/pr.yml; do
    printf '%s\n' "$control" | grep -qE "$PRODUCT_PATTERN" \
        || fail "product-change classifier does not route $control through pr-smoke"
done
echo "PASS: every complexity-gate control triggers product PR smoke"

# The real, flag-less gate stays after the Ubuntu production build and current
# repository index command. The fixture seams above are absent from this step.
python3 - "$ROOT/.github/workflows/pr.yml" <<'PY' || fail "workflow does not run the live complexity gate after build and index"
import sys

workflow = open(sys.argv[1], encoding="utf-8").read()
build = workflow.index('scripts/build.sh CC=gcc CXX=g++')
index = workflow.index('cli index_repository --repo-path "$(pwd)" --mode full')
gate = workflow.index('python3 scripts/check-complexity.py --binary "$BIN"')
if not build < index < gate:
    raise SystemExit('complexity gate is not ordered after build and index')
PY
echo "PASS: PR workflow indexes the post-build live binary before complexity comparison"

# Missing binary is always fatal, including when both fixture seams are set.
if python3 "$GATE" --binary "$WORK/no-such-binary" \
        --sanity-query-output "$SANITY" --query-output "$CLEAN" \
        >"$WORK/missing-binary.out" 2>&1; then
    fail "a missing binary did not fail the gate"
fi
grep -q "MISSING" "$WORK/missing-binary.out" \
    || fail "missing-binary failure did not report MISSING"
echo "PASS: missing binary fails before either fixture seam can bypass it"

# Clean graph: the Function-node sanity result is nonzero and no function
# exceeds the threshold, so an empty allow-list passes.
if ! python3 "$GATE" --binary "$FIXTURE_BINARY" \
        --sanity-query-output "$SANITY" --query-output "$CLEAN" \
        --allow "$EMPTY_ALLOW" >"$WORK/clean.out" 2>&1; then
    fail "clean fixture did not pass the gate"
fi
grep -q "OK: 0 function(s)" "$WORK/clean.out" \
    || fail "clean fixture did not report the successful comparison"
echo "PASS: clean population passes"

# New violation: an over-threshold function without an allow-list entry fails.
if python3 "$GATE" --binary "$FIXTURE_BINARY" \
        --sanity-query-output "$SANITY" --query-output "$VIOLATION" \
        --allow "$EMPTY_ALLOW" >"$WORK/new.out" 2>&1; then
    fail "unauthorized over-threshold function did not fail the gate"
fi
grep -q "fixture.c:very_complex" "$WORK/new.out" \
    || fail "new-violation failure did not name the function"
echo "PASS: unauthorized new violation fails"

# The exact same population succeeds when its one allowed exception is present.
if ! python3 "$GATE" --binary "$FIXTURE_BINARY" \
        --sanity-query-output "$SANITY" --query-output "$VIOLATION" \
        --allow "$ALLOWED" >"$WORK/allowed.out" 2>&1; then
    fail "allow-listed population did not pass the gate"
fi
grep -q "OK: 1 function(s)" "$WORK/allowed.out" \
    || fail "allow-listed population did not report successful comparison"
echo "PASS: matching allow-list entry passes"

# A permission with no corresponding over-threshold row is stale and fails.
if python3 "$GATE" --binary "$FIXTURE_BINARY" \
        --sanity-query-output "$SANITY" --query-output "$CLEAN" \
        --allow "$STALE" >"$WORK/stale.out" 2>&1; then
    fail "stale allow-list entry did not fail the gate"
fi
grep -q "STALE" "$WORK/stale.out" || fail "stale failure did not report STALE"
grep -q "fixture.c:removed_complexity" "$WORK/stale.out" \
    || fail "stale failure did not name the entry"
echo "PASS: stale allow-list entry fails"

# A malformed entry is a hard error even when the population is otherwise clean.
if python3 "$GATE" --binary "$FIXTURE_BINARY" \
        --sanity-query-output "$SANITY" --query-output "$CLEAN" \
        --allow "$MALFORMED" >"$WORK/malformed.out" 2>&1; then
    fail "malformed allow-list entry did not fail the gate"
fi
grep -q "MALFORMED" "$WORK/malformed.out" \
    || fail "malformed failure did not report MALFORMED"
echo "PASS: malformed allow-list entry fails"

# Empty Function-node sanity output models an absent or empty index. It must
# fail before the clean population can be mistaken for a clean graph.
if python3 "$GATE" --binary "$FIXTURE_BINARY" \
        --sanity-query-output "$EMPTY_INDEX" --query-output "$CLEAN" \
        --allow "$EMPTY_ALLOW" >"$WORK/empty-index.out" 2>&1; then
    fail "empty index did not fail the gate"
fi
grep -q "MISSING" "$WORK/empty-index.out" \
    || fail "empty-index failure did not report MISSING"
echo "PASS: empty or missing index fails rather than reading clean"

echo "PASS: complexity gate contract — clean, new, allowed, stale, malformed, and empty-index cases covered"
