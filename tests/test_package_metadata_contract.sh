#!/usr/bin/env bash
# Contract: server.json is the checked-in version source; package and public
# metadata cannot drift from it or from the grammar-backed language count.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$ROOT/scripts/check-package-metadata.py"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
VERSION="$(python3 - "$ROOT/server.json" <<'PY'
import json
import pathlib
import sys

print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["version"])
PY
)"

fail() { echo "FAIL: $1" >&2; exit 1; }

copy_fixture() {
    mkdir -p "$STAGE"/{internal/cbm,pkg/npm,pkg/pypi/src/codebase_memory_mcp,pkg/go/cmd/codebase-memory-mcp,pkg/chocolatey/tools,pkg/homebrew/Formula,pkg/aur,pkg/scoop,pkg/winget/manifests/d/DeusData/CodebaseMemoryMcp/"$VERSION"}
    cp "$ROOT/server.json" "$ROOT/LICENSE" "$ROOT/flake.nix" "$ROOT/README.md" "$STAGE/"
    cp "$ROOT"/internal/cbm/grammar_*.c "$STAGE/internal/cbm/"
    cp "$ROOT/pkg/npm/package.json" "$ROOT/pkg/npm/README.md" "$STAGE/pkg/npm/"
    cp "$ROOT/pkg/pypi/pyproject.toml" "$STAGE/pkg/pypi/"
    cp "$ROOT/pkg/pypi/src/codebase_memory_mcp/_cli.py" "$STAGE/pkg/pypi/src/codebase_memory_mcp/"
    cp "$ROOT/pkg/go/cmd/codebase-memory-mcp/main.go" "$STAGE/pkg/go/cmd/codebase-memory-mcp/"
    cp "$ROOT/pkg/chocolatey/codebase-memory-mcp.nuspec" "$STAGE/pkg/chocolatey/"
    cp "$ROOT/pkg/chocolatey/tools/chocolateyInstall.ps1" "$STAGE/pkg/chocolatey/tools/"
    cp "$ROOT/pkg/homebrew/Formula/codebase-memory-mcp.rb" "$STAGE/pkg/homebrew/Formula/"
    cp "$ROOT/pkg/aur/PKGBUILD" "$STAGE/pkg/aur/"
    cp "$ROOT/pkg/scoop/codebase-memory-mcp.json" "$STAGE/pkg/scoop/"
    cp "$ROOT/pkg/winget/manifests/d/DeusData/CodebaseMemoryMcp/$VERSION/"*.yaml "$STAGE/pkg/winget/manifests/d/DeusData/CodebaseMemoryMcp/$VERSION/"
}

python3 "$CHECKER" "$ROOT"
echo "PASS: checked-in package metadata is coherent"

copy_fixture
python3 "$CHECKER" "$STAGE"

python3 - "$STAGE/flake.nix" "$VERSION" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
version = sys.argv[2]
path.write_text(path.read_text(encoding="utf-8").replace(f'version = "{version}";', 'version = "9.9.9";'), encoding="utf-8")
PY
if python3 "$CHECKER" "$STAGE"; then
    fail "checker accepted a package version drift"
fi
echo "PASS: checker rejects package version drift"

cp "$ROOT/flake.nix" "$STAGE/flake.nix"
python3 - "$STAGE/README.md" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text(encoding="utf-8").replace('159 languages', '158 languages'), encoding="utf-8")
PY
if python3 "$CHECKER" "$STAGE"; then
    fail "checker accepted a user-facing language-count drift"
fi
echo "PASS: checker rejects language-count drift"
