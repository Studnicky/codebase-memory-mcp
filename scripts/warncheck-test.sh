#!/usr/bin/env bash
# Per-file warning check with the TEST flag set, without touching build/.
#
# Mirrors CFLAGS_TEST exactly: the production strict warnings plus every
# test-seam define, ASan/UBSan, and real codegen. Both of those last two matter
# — code behind CBM_ENABLE_TEST_SEAMS is invisible to scripts/warncheck.sh,
# and several -Wsign-conversion sites only appear once the sanitizers
# instrument them, so -fsyntax-only reports a file clean that the real test
# build rejects.
#
# Usage: scripts/warncheck-test.sh <file.c> [more.c ...]
set -uo pipefail
cd "$(dirname "$0")/.."
exec cc -c -o /dev/null \
  -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE \
  -Wall -Wextra -Wno-unused-parameter -Wdate-time \
  -Wconversion -Wsign-conversion -Wshadow -Wcast-qual -Wcast-align \
  -Wstrict-prototypes -Wmissing-prototypes -Wdouble-promotion \
  -Wpointer-arith -Wredundant-decls -Wundef \
  -Isrc -Ivendored -Ivendored/sqlite3 -Ivendored/mimalloc/include \
  -Iinternal/cbm -Iinternal/cbm/vendored/ts_runtime/include \
  -isystem internal/cbm/vendored/verstable \
  -DCBM_JSON_LIKE_ENABLE_TEST_API=1 -DCBM_TOML_EDIT_ENABLE_TEST_API=1 \
  -DCBM_YAML_ENABLE_TEST_API=1 -DCBM_TEXT_EDIT_ENABLE_TEST_API=1 \
  -DCBM_CLI_ENABLE_TEST_API=1 -DCBM_DIAGNOSTICS_ENABLE_TEST_API=1 \
  -DCBM_ENABLE_TEST_SEAMS=1 -DCBM_SANITIZED_BUILD=1 \
  -DCBM_KOTLIN_DEDUP_TEST_API=1 -DCBM_CALL_REFERENCE_LOOKUP_TEST_API=1 \
  -DCBM_INCREMENTAL_TEST_API=1 \
  -Itests -Itests/repro -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer "$@"
