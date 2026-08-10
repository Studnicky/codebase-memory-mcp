#!/usr/bin/env bash
# Keep the LSP unity-build warning inventory explicit while its first-party
# sources are brought to zero. Each source keeps its own expected count so a
# warning cannot move between included files unnoticed.
set -euo pipefail
IFS=$'\n\t'

root=$(cd "$(dirname "$0")/.." && pwd)
expected="$root/scripts/lsp-warning-census.expected"
diagnostics=$(mktemp "${TMPDIR:-/tmp}/cbm-lsp-warning-census.XXXXXX")
actual=$(mktemp "${TMPDIR:-/tmp}/cbm-lsp-warning-census.XXXXXX")
trap 'rm -f "$diagnostics" "$actual"' EXIT

if ! "$root/scripts/warncheck.sh" internal/cbm/lsp_all.c > /dev/null 2> "$diagnostics"; then
  cat "$diagnostics" >&2
  exit 1
fi

awk '
  /^internal\/cbm\/lsp\/.*: warning:/ {
    split($1, location, ":");
    counts[location[1]]++;
    total++;
  }
  END {
    for (path in counts) printf "%s %d\n", path, counts[path];
    printf "total %d\n", total;
  }
' "$diagnostics" | LC_ALL=C sort > "$actual"

if ! diff -u "$expected" "$actual"; then
  printf 'LSP unity warning census drifted; fix the warnings and update the expected per-file counts.\n' >&2
  exit 1
fi

cat "$actual"
