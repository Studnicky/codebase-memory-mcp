#!/usr/bin/env bash
# Per-file warning check with the production strict flag set, without touching
# build/. Lets one file be driven to zero warnings while other work is in
# flight — `make` serializes on shared build output, this does not.
# Usage: scripts/warncheck.sh <file.c> [more.c ...]
set -uo pipefail
cd "$(dirname "$0")/.."
exec clang -fsyntax-only \
  -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE \
  -Wall -Wextra -Wno-unused-parameter -Wdate-time \
  -Wconversion -Wsign-conversion -Wshadow -Wcast-qual -Wcast-align \
  -Wstrict-prototypes -Wmissing-prototypes -Wdouble-promotion \
  -Wpointer-arith -Wredundant-decls -Wundef \
  -Isrc -Ivendored -Ivendored/sqlite3 -Ivendored/mimalloc/include \
  -Iinternal/cbm -Iinternal/cbm/vendored/ts_runtime/include \
  -isystem internal/cbm/vendored/verstable \
  -O2 "$@"
