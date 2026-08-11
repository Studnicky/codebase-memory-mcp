#!/usr/bin/env bash
# Contract: the embedded binary and standalone UI share exactly one ordered
# frontend prerequisite: install dependencies, run Vitest, then bundle.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAKEFILE="$ROOT/Makefile.cbm"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

UI_DIR="$WORK/graph-ui"
LOG="$WORK/npm.log"
FAKE_NPM="$WORK/npm"
mkdir -p "$UI_DIR"

cat >"$FAKE_NPM" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FRONTEND_GATE_LOG:?}"
case "$*" in
  ci) exit 0 ;;
  'run test') exit "${FRONTEND_GATE_TEST_STATUS:-0}" ;;
  'run build') exit 0 ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$FAKE_NPM"

assert_log() {
  local expected="$1"
  local actual
  actual="$(cat "$LOG")"
  [ "$actual" = "$expected" ] || fail "expected npm sequence '$expected', got '$actual'"
}

# Successful standalone builds execute every stage once and in order.
: >"$LOG"
FRONTEND_GATE_LOG="$LOG" FRONTEND_GATE_TEST_STATUS=0 \
  make --no-print-directory -f "$MAKEFILE" frontend \
  GRAPH_UI_DIR="$UI_DIR" NPM="$FAKE_NPM" >"$WORK/frontend.out" 2>&1 \
  || fail "frontend target failed when the UI test passed"
assert_log $'ci\nrun test\nrun build'
echo "PASS: frontend installs once, tests, then builds"

# A failing Vitest command stops the standalone bundle before its build stage.
: >"$LOG"
if FRONTEND_GATE_LOG="$LOG" FRONTEND_GATE_TEST_STATUS=23 \
  make --no-print-directory -f "$MAKEFILE" frontend \
  GRAPH_UI_DIR="$UI_DIR" NPM="$FAKE_NPM" >"$WORK/frontend-failure.out" 2>&1; then
  fail "frontend target accepted a failed UI test"
fi
assert_log $'ci\nrun test'
echo "PASS: frontend test failure blocks its build"

# The embedded binary target must use that same prerequisite; a UI test
# failure therefore halts before the UI bundle and final embedded binary.
: >"$LOG"
if FRONTEND_GATE_LOG="$LOG" FRONTEND_GATE_TEST_STATUS=23 \
  make --no-print-directory -f "$MAKEFILE" cbm-with-ui \
  GRAPH_UI_DIR="$UI_DIR" NPM="$FAKE_NPM" >"$WORK/embedded-failure.out" 2>&1; then
  fail "cbm-with-ui accepted a failed UI test"
fi
assert_log $'ci\nrun test'
echo "PASS: cbm-with-ui test failure blocks embedding"
