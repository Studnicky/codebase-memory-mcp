#!/usr/bin/env bash
# Contract: a ScanCode false-positive exception matches one path and one full
# detected expression. It cannot hide a copyleft detection in that script or a
# JSON detection anywhere else.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECKER="$ROOT/scripts/license-gate-check.py"
POLICY="$ROOT/scripts/license-policy.json"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

scan() {
    local name="$1"
    local path="$2"
    local expression="$3"
    python3 - "$STAGE/$name.json" "$path" "$expression" <<'PY'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as out:
    json.dump({"files": [{
        "path": sys.argv[2],
        "type": "file",
        "detected_license_expression_spdx": sys.argv[3],
    }]}, out)
PY
}

require_pass() {
    local fixture="$1"
    if ! python3 "$CHECKER" "$fixture" "$POLICY"; then
        echo "FAIL: expected allow-listed finding to pass: $fixture" >&2
        exit 1
    fi
}

require_block() {
    local fixture="$1"
    if python3 "$CHECKER" "$fixture" "$POLICY"; then
        echo "FAIL: expected finding to be blocked: $fixture" >&2
        exit 1
    fi
}

scan known-package tree/scripts/package-release.sh JSON
scan known-smoke tree/scripts/smoke-local.sh JSON
scan gpl-in-package tree/scripts/package-release.sh GPL-3.0-only
scan agpl-in-package tree/scripts/package-release.sh AGPL-3.0-only
scan unrelated-json tree/scripts/not-an-archive-script.sh JSON

require_pass "$STAGE/known-package.json"
require_pass "$STAGE/known-smoke.json"
require_block "$STAGE/gpl-in-package.json"
require_block "$STAGE/agpl-in-package.json"
require_block "$STAGE/unrelated-json.json"

echo "PASS: license finding exceptions match exact path and expression pairs"
