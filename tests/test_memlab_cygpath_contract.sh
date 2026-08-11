#!/usr/bin/env bash
# Contract: native-Windows cache conversion must fail closed. An empty or
# failed cygpath result must never reach mkdir or the memory-profile driver.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MEMLAB="$ROOT/scripts/memlab.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

FAKE_BIN="$WORK/bin"
INPUT="$WORK/cygpath-input"
DRIVER="$WORK/driver-ran"
RESULT="$WORK/native-cache"
BINARY="$WORK/codebase-memory-mcp"
mkdir -p "$FAKE_BIN"

cat >"$BINARY" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$BINARY"

cat >"$FAKE_BIN/cygpath" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${2:?expected cygpath path}" >"${MEMLAB_CYGPATH_INPUT:?}"
case "${MEMLAB_CYGPATH_MODE:?}" in
    fail) exit 29 ;;
    empty) exit 0 ;;
    success) printf '%s\n' "${MEMLAB_CYGPATH_RESULT:?}" ;;
    *) exit 64 ;;
esac
EOF
chmod +x "$FAKE_BIN/cygpath"

cat >"$FAKE_BIN/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${CBM_CACHE_DIR:?}" >"${MEMLAB_DRIVER_MARKER:?}"
EOF
chmod +x "$FAKE_BIN/python3"

run_memlab() {
    local mode="$1"
    local run_dir="$WORK/$mode"
    mkdir -p "$run_dir"
    (
        cd "$run_dir"
        PATH="$FAKE_BIN:/usr/bin:/bin" \
            MEMLAB_CYGPATH_INPUT="$INPUT" \
            MEMLAB_CYGPATH_MODE="$mode" \
            MEMLAB_CYGPATH_RESULT="$RESULT" \
            MEMLAB_DRIVER_MARKER="$DRIVER" \
            bash "$MEMLAB" "$BINARY" 1 "$mode"
    ) >"$run_dir/output" 2>&1
}

assert_conversion_failure() {
    local mode="$1"
    rm -f "$INPUT" "$DRIVER"
    if run_memlab "$mode"; then
        fail "memlab accepted a $mode cygpath conversion"
    fi
    if [ ! -f "$INPUT" ]; then
        cat "$WORK/$mode/output" >&2
        fail "memlab did not request a cache conversion for $mode"
    fi
    [ ! -d "$(cat "$INPUT")" ] || fail "memlab created the cache after a $mode conversion"
    [ ! -e "$DRIVER" ] || fail "memlab launched the driver after a $mode conversion"
    echo "PASS: $mode cygpath conversion stops before cache creation and driver launch"
}

assert_conversion_failure fail
assert_conversion_failure empty

rm -f "$INPUT" "$DRIVER"
run_memlab success || fail "memlab rejected a valid cygpath conversion"
[ "$(cat "$DRIVER")" = "$RESULT" ] || fail "memlab did not export the converted cache path"
[ -d "$RESULT" ] || fail "memlab did not create the converted cache path"
echo "PASS: successful cygpath conversion exports the native cache path"
