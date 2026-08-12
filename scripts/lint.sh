#!/usr/bin/env bash
# lint.sh — Run all linters (clang-tidy + cppcheck + clang-format).
#
# Usage:
#   scripts/lint.sh                                    # All 3 linters
#   scripts/lint.sh CLANG_FORMAT=clang-format-20       # Override formatter
#   scripts/lint.sh --ci                               # CI mode (skip clang-tidy)
#
# This script is the SINGLE source of truth for linting.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# shellcheck source=env.sh
source "$ROOT/scripts/env.sh"

usage() {
    cat <<'EOF'
Usage: scripts/lint.sh [--ci] [VAR=VAL ...]

The canonical lint entry: CI (_lint.yml) calls this script; it drives the same
Makefile.cbm lint targets `make lint`/`make lint-ci` run, plus the no-skips
policy check. Runs clang-tidy + cppcheck + clang-format by default.

Options:
  --ci            CI mode: cppcheck + clang-format only (no clang-tidy) —
                  exactly what _lint.yml gates on. `make lint-ci` uses this.
  VAR=VAL         Forwarded to make, e.g. CLANG_FORMAT=clang-format-20.
                  NOTE: the project formatter is the Homebrew LLVM build; a
                  standalone clang-format-20 produces false whole-file drift.
  -h, --help      This text.
EOF
}

# Check for --ci flag (skip clang-tidy for platforms without it)
CI_ONLY=false
MAKE_ARGS=()
for arg in "$@"; do
    if [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
        usage; exit 0
    elif [ "$arg" = "--ci" ]; then
        CI_ONLY=true
    else
        # STRICT: only VAR=VAL make passthrough beyond the known flags.
        case "$arg" in
        *=*) MAKE_ARGS+=("$arg") ;;
        *)
            echo "lint.sh: unknown argument '$arg'. Please consult --help." >&2
            exit 2
            ;;
        esac
    fi
done

print_env "lint.sh"

# No-skips policy: every test must pass or fail. The only tolerable skip is a
# genuinely platform-specific test (SKIP_PLATFORM / #ifdef). Runs in both modes.
echo "=== no-skips policy (tests pass or fail) ==="
bash "$ROOT/scripts/check-no-test-skips.sh"

# Architecture policy over the include graph, two gates in one pass:
#   layering.allow  — the inter-module edge set
#   externals.allow — which modules reach a third-party library directly,
#                     i.e. cross a trust boundary without an adapter
# Both ratchet in both directions: a new edge fails, and an allow-list entry
# outliving the edge it described fails, so cleanup is permanent. Runs in
# both modes.
echo "=== architecture policy (module + third-party include graph) ==="
python3 "$ROOT/scripts/check-layering.py"

# NULL may mean "no object here". It may never be a value something acts on
# without checking — a NULL in a slot that gets called is a jump to address 0,
# which is how the sqlite allocator bind killed the daemon with no diagnostic.
# The callable-slot rule is enforced at zero with no allow-list; decoded-null
# sites are reported so the trend is visible without gating on a number that
# includes correct code.
echo "=== NULL discipline ==="
python3 "$ROOT/scripts/check-null-discipline.py" --self-test
python3 "$ROOT/scripts/check-null-discipline.py"

# Complexity ratchet over pass_complexity.c's own numbers, checked against
# complexity.allow. Unlike the gates above this one is not static analysis —
# it queries the graph the product itself builds, using the binary under
# test, so it needs both a build and a current index of THIS repo. lint.sh
# has no build step of its own (`make lint`/`lint-ci` don't depend on the
# cbm binary), so this runs only when a binary is already sitting at
# build/c/codebase-memory-mcp; CI enforces it unconditionally in pr.yml's
# pr-smoke job, right after that job builds the binary.
CBM_BIN="$ROOT/build/c/codebase-memory-mcp"
[ -x "$CBM_BIN" ] || CBM_BIN="$ROOT/build/c/codebase-memory-mcp.exe"
if [ -x "$CBM_BIN" ]; then
    echo "=== complexity ratchet (live graph vs. complexity.allow) ==="
    CBM_LINT_CACHE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cbm-lint-cache.XXXXXX")"
    trap 'rm -rf "$CBM_LINT_CACHE_DIR"' EXIT
    export CBM_CACHE_DIR="$CBM_LINT_CACHE_DIR"
    "$CBM_BIN" cli index_repository --repo-path "$ROOT" --mode full
    python3 "$ROOT/scripts/check-complexity.py" --binary "$CBM_BIN"
else
    echo "=== complexity ratchet: SKIPPED (no build/c/codebase-memory-mcp — run scripts/build.sh first) ==="
fi

if $CI_ONLY; then
    echo "=== CI mode: cppcheck + clang-format ==="
    make -j2 -f Makefile.cbm lint-ci "${MAKE_ARGS[@]+"${MAKE_ARGS[@]}"}"
    echo "=== CI linters passed ==="
else
    echo "=== Full lint: clang-tidy + cppcheck + clang-format ==="
    make -j3 -f Makefile.cbm lint "${MAKE_ARGS[@]+"${MAKE_ARGS[@]}"}"
fi

echo "=== All linters passed ==="
