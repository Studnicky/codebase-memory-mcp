#!/usr/bin/env bash
# Contract: a Nix package carries the hash-verified integration sidecar beside
# its binary, and an isolated install refuses any mutation of those bytes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

require() {
    [ "$1" = "$2" ] || fail "$3"
}

FLAKE="$ROOT/flake.nix"
python3 - "$FLAKE" <<'PY'
import pathlib
import re
import sys

flake = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
rule = re.compile(
    r"install\s+-Dm644\s+assets/cbm-integrations\.json\s+"
    r"\$out/bin/cbm-integrations\.json"
)
if not rule.search(flake):
    raise SystemExit("FAIL: flake.nix must install cbm-integrations.json beside the executable")
PY

RESULT="${CBM_NIX_RESULT:-}"
if [ -z "$RESULT" ] && command -v nix >/dev/null 2>&1; then
    RESULT="$WORK/result"
    nix build "$ROOT#" --out-link "$RESULT"
fi

if [ -n "$RESULT" ]; then
    BINARY="$RESULT/bin/codebase-memory-mcp"
    ASSET="$RESULT/bin/cbm-integrations.json"
    [ -x "$BINARY" ] || fail "Nix result lacks bin/codebase-memory-mcp"
    [ -s "$ASSET" ] || fail "Nix result lacks bin/cbm-integrations.json"
    echo "PASS: Nix closure contains executable and integration sidecar"
else
    BINARY="$ROOT/build/c/codebase-memory-mcp"
    ASSET="$ROOT/assets/cbm-integrations.json"
    [ -x "$BINARY" ] || fail "build/c/codebase-memory-mcp is required when nix is unavailable"
    [ -s "$ASSET" ] || fail "assets/cbm-integrations.json is missing"
    echo "SKIP: nix unavailable; validated the local binary with the same isolated sidecar contract"
fi

STAGE="$WORK/isolated/bin"
HOME_DIR="$WORK/home"
mkdir -p "$STAGE" "$HOME_DIR"
cp "$BINARY" "$STAGE/codebase-memory-mcp"
cp "$ASSET" "$STAGE/cbm-integrations.json"
chmod 755 "$STAGE/codebase-memory-mcp"

run_command() {
    local home="$1"
    shift
    HOME="$home" PATH="$PATH" env -u CBM_ASSETS_DIR \
        "$STAGE/codebase-memory-mcp" "$@"
}

run_command "$HOME_DIR" install --skip-config --yes >"$WORK/install.out" 2>"$WORK/install.err" ||
    fail "isolated install could not resolve the verified sibling sidecar"
[ -x "$HOME_DIR/.local/bin/codebase-memory-mcp" ] ||
    fail "isolated install did not publish its binary"
[ -s "$HOME_DIR/.cbm/assets/dev/cbm-integrations.json" ] ||
    fail "isolated install did not persist the verified integration sidecar"
run_command "$HOME_DIR" uninstall --yes >"$WORK/uninstall.out" 2>"$WORK/uninstall.err" ||
    fail "isolated uninstall could not resolve the verified sibling sidecar"
[ ! -e "$HOME_DIR/.local/bin/codebase-memory-mcp" ] ||
    fail "isolated uninstall did not remove the installed binary"
echo "PASS: isolated install and uninstall resolve the sibling sidecar"

printf '\n' >>"$STAGE/cbm-integrations.json"
TAMPER_HOME="$WORK/tamper-home"
mkdir -p "$TAMPER_HOME"
if run_command "$TAMPER_HOME" install --dry-run --skip-config --yes >"$WORK/tampered.out" \
    2>"$WORK/tampered.err"; then
    fail "isolated install accepted a tampered sibling sidecar"
fi
grep -q 'integration asset' "$WORK/tampered.err" ||
    fail "tampered sidecar failure did not identify the integration asset"
echo "PASS: isolated install refuses a tampered sibling sidecar"
