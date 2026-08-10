# Goal: Post-merge stabilization and production readiness

> **Status:** Ready for execution. Start with H1. Complete and verify one phase before opening the next.
>
> **Purpose:** Give an implementation agent enough verified context to execute without relying on chat history. Facts, hypotheses, prohibitions, edit boundaries, tests, and completion criteria are explicit below.
>
> **Related audit:** [Full architecture review](../reviews/review-arch-2026-08-08-1411-main.md)
>
> **Additive architecture program:** [Per-user broker with checkout-scoped project actors](per-user-broker-project-actors.md). Its B0 phase opens only after this goal reaches A20; it does not replace or reorder the stabilization work map.

## 1. Objective

Bring the merged package to a release-ready state by:

1. removing the known daemon test flake through evidence-based fixes;
2. exposing and eliminating the LSP unity build's hidden warnings;
3. classifying nullable decoded fields without destroying real optionality;
4. adding missing regression coverage for partial parsing and node identity;
5. resolving the retained architecture-review findings; and
6. completing the full release validation with zero unexplained failures.

## 2. Current evidence baseline

- Main contains the hardening, gate, and upstream-merge commits `b5c5e397`, `fe6759a0`, and `a494ec97`.
- Four top-level binaries build with zero visible warnings.
- Layering reports 61 module edges and 29 external edges with no violations.
- Complexity reports 30/30 within policy. The PR workflow contains a live post-build check.
- NULL callable-slot violations are zero. The decoded-null inventory classifies 282 observed sites and ratchets unreviewed growth.
- Capacity sweep violations are zero.
- The latest full parallel validation records 7,439 passing tests, zero failures, and four skips.
- `internal/cbm/lsp_all.c` compiles under LSP-specific strict test, TSan, and production flags. The checked-in unity census is zero.

## 3. Execution contract

Every implementation agent follows this sequence:

1. Read this document and only the active task card plus its direct dependencies.
2. Use codebase-memory graph tools before code search or source reads.
3. Read every file before editing it.
4. Make only the bounded change named by the active task.
5. Add a behavioral or failure-path regression before declaring the task complete.
6. Run the focused checks in the task card and report exact pass/fail/skip counts.
7. Update the task's status and evidence in this document using current-state wording.
8. Stop if an acceptance criterion is not met. Do not open the next phase.

Global prohibitions:

- Do not commit or push without explicit user authorization.
- Do not use `-w`, new `-Wno-*` flags, diagnostic pragmas, casts used only to silence warnings, test retries, disabled assertions, or weakened gates.
- Do not increase activation or IPC timeouts without a failing run that identifies a timeout as the cause.
- Do not convert allocation failure into empty data.
- Do not sweep nullable strings or replace sentinels globally.
- Do not change `heap_strdup(NULL)` without the complete identity migration described in H7.
- Preserve unrelated and unfamiliar work; investigate before changing it.

## 4. Ordered work map

| ID | Work | Status | Depends on |
|---|---|---|---|
| H1 | Child-ready liveness bound | Complete | — |
| H2 | Activation failure evidence and causal fix | Complete | H1 |
| H3 | Daemon IPC failure evidence and causal fix | Complete | H2 evidence model |
| P1 | Python LSP scaling-guard venue | Complete | — |
| H4 | LSP warning census and remediation | Complete | H3 |
| H5 | Decoded-null classification | Complete | H4 |
| H6 | `parse_partial` root-ERROR regression | Complete | H5 |
| H7 | Missing-name identity migration design and implementation | Complete | H6 |
| A1–A3 | Memory ownership substrate | Pending | H6 and H7 |
| A4–A8 | Data and API truthfulness | Pending | A1–A3 |
| A9–A13 | Verification gates | Pending | A4–A8 |
| A14–A19 | Distribution and UI quality | Pending | A9–A13 |
| A20 | Release validation | Pending | Every prior card |

H6 and H7 run sequentially: the root-ERROR regression establishes parsing evidence before the graph identity migration.

---

## 5. Handoff track

### H1 — Raise the child-ready liveness bound

**Status:** Complete

**Scope**

- `tests/test_daemon_runtime.c`
- `CHILD_READY_BOUND_MS` near line 3525
- `runtime_test_wait_pid_marker()` near lines 572–595

**Verified evidence**

- The test copies the ASan test runner, executes it as `git`, and polls for a PID marker every 1 ms.
- Marker publication proves startup/liveness, not latency performance.
- The current bound is 5,000 ms.
- Comparable hang guards use 30,000 ms in `tests/test_daemon_frontend.c` and 20,000 ms for the same copied blocking-git mechanism in `tests/test_watcher.c`.
- The failure occurs before child identity, cancellation, and cleanup assertions.

**Required change**

Change exactly:

```c
CHILD_READY_BOUND_MS = 5000,
```

to:

```c
CHILD_READY_BOUND_MS = 30000,
```

Do not change cancellation, cleanup, request, activation, or catastrophic bounds. Do not add retries or sleeps.

**Verification**

```sh
scripts/test.sh --suites daemon_runtime
build/c/test-runner daemon_runtime
```

**Done when**

- The source diff contains the one constant change.
- `daemon_runtime` passes under the default ASan/UBSan configuration.
- A child that never publishes a marker still fails the test.

**Current verification**

- `scripts/test.sh --suites daemon_runtime` passes 44 tests under ASan/UBSan.
- `build/c/test-runner daemon_runtime` passes the same 44 tests under ASan/UBSan.

### H2 — Capture and fix the activation-child failure

**Scope and call chain**

- `tests/test_daemon_runtime.c`: `runtime_test_run_activation_image()` near 743–811
- `tests/test_daemon_runtime.c`: `daemon_runtime_activation_accepts_authenticated_different_build` near 2096–2175
- `tests/test_main.c`: `tf_maybe_run_runtime_activation_client()` near 464–487
- `src/daemon/runtime.c`: `cbm_daemon_runtime_request_activation_shutdown()` near 2463–2495
- `tests/test_daemon_runtime_contract.h`: 60-second exchange timeout and 125-second watchdog

```text
activation test
  → runtime_test_run_activation_image
  → posix_spawn copied image in __cbm_runtime_activation_client mode
  → tf_maybe_run_runtime_activation_client
  → cbm_daemon_runtime_request_activation_shutdown
  → activation-shutdown request/response exchange
```

**Verified evidence**

- A passing instrumented run records `copied=1 changed=1 runnable=1 fingerprinted=1 differs=1`.
- The hypothesis that the copied image fingerprint does not differ is disproven.
- `foreign_exit` starts at `-1` and is assigned only when the child exits normally.
- A normal activation failure exits 29 and makes `foreign_ran=true`; assertion failure at `foreign_ran` therefore indicates process creation, wait, or abnormal termination rather than a normal rejected exchange.
- An elevated ASan/UBSan run reproduces the failure with all copied-image preconditions true,
  an accepted owner connection, `foreign_ran=0`, and `foreign_exit=-1`.
- `waitpid` returns the copied child with raw status `14`: `WIFSIGNALED=1` and
  `WTERMSIG=14` (`SIGALRM`). The 125-second watchdog terminates the exchange. This rules out
  normal activation rejection, fork failure, and parent wait failure.
- The server does not emit `daemon.activation_shutdown` before the watchdog; the copied child
  remains in the activation exchange until the watchdog sends `SIGALRM`.

**Implementation**

- POSIX starts the copied activation client with `posix_spawn` and a bounded mutable argument
  vector, avoiding fork's duplicate sanitizer address space.
- POSIX and Windows keep failure-only process diagnostics for launch, wait, exit, and termination
  state.
- The 60-second exchange timeout and 125-second watchdog remain unchanged.

**Current verification**

- Two focused `daemon_runtime` ASan/UBSan runs pass 44 tests each.
- The full ASan/UBSan venue passes 7,439 tests with 0 failures and 4 platform skips.
- The activation test emits `daemon.activation_shutdown` and passes with a separately signed,
  fingerprint-distinct child image.

### H3 — Capture and fix the daemon IPC child-report failure

**Status:** Complete

**Scope**

- `tests/test_daemon_ipc.c`: `ipc_test_fd_write_all()` near 2693–2707
- `tests/test_daemon_ipc.c`: `ipc_test_fd_read_all()` near 2709–2723
- `tests/test_daemon_ipc.c`: `daemon_ipc_posix_lifetime_reservation_rejects_fork_inheritance` near 2949–3025
- `src/daemon/ipc.c`: `cbm_daemon_ipc_listen_reserved()`

**Verified evidence**

- `child_result` initializes to zero.
- The child writes one result byte and exits.
- The parent reads one byte; a failed read overwrites `child_result` with zero.
- The read helper retries `EINTR` and has no timeout. A timeout increase cannot fix this path.
- The zero fallback hides whether zero is a real result or missing report data.
- Isolation passes do not identify the full-venue failure cause.

**Causal evidence and implementation**

- The forked child copied a reservation whose release calls `process_lock_unclaim()`, which locks
  the process-wide `process_locks_mutex`; it also reached runtime validation and logging before
  reporting. These operations are unsafe in a child after fork and can prevent its pipe report.
- `cbm_daemon_ipc_listen_reserved()` rejects an owner-PID mismatch before runtime validation or
  logging. An inherited reservation therefore has no side effects in the child.
- The test child writes its result, closes its pipe descriptor, and exits without releasing or
  closing copied library state; process teardown releases the copied descriptors.
- Failure-only parent and terminal-read diagnostics remain installed, including EOF/error and
  child-status classification.

**Current run evidence**

- The focused script and direct runner each pass `daemon_ipc` (46 tests) with no child-report
  diagnostic.
- Ten post-fix isolated `daemon_ipc` ASan/UBSan runs pass all 46 tests.
- The full ASan/UBSan scheduler passes `daemon_ipc` and 7,439 tests overall with 0 failures and
  4 platform skips.

Interpret evidence as follows:

| Received | Child state | Meaning |
|---|---|---|
| true, byte 0 | exit 1 | Reservation invariant failed and was reported |
| false | exit 1 | Child failed to deliver the report |
| false | signaled | Child termination caused EOF |
| false | exit 0 | Pipe/read accounting contradicts the child contract |
| true, byte 1 | exit 0 | Success |

**Verification**

```sh
scripts/test.sh --suites daemon_ipc
build/c/test-runner daemon_ipc
scripts/test.sh
```

Do not add a timeout, ignore read/status results, change fallback to success, or modify production reservation behavior before the failure category is known.

**Completion evidence**

- The owner-PID rejection prevents the inherited-state path from performing non-fork-safe work.
- Repeated isolated runs and the full venue pass with the missing-report assertion enabled.

### P1 — Run the Python LSP scaling guard in the quiet test tail

**Status:** Complete

**Scope**

- `scripts/run-tests-parallel.sh`: `SERIAL_SUITES`
- `tests/test_py_lsp_scale.c`: `pylsp_scale_linear_growth`

**Verified evidence**

- The guard measures a 100-class and a 2,000-class extraction using wall-clock time and retains
  its 100x ratio limit.
- The 16-job parallel wave records 66.8 ms and 8,330.4 ms respectively, a failing 124.6x ratio.
- Four isolated ASan/UBSan runs pass with ratios of 72.3x, 68.1x, 66.0x, and 70.5x.
- `extraction` already uses the quiet serial tail for the same ratio-under-contention failure mode.
- The Python LSP scale guard was introduced with a bounded dedup implementation in `ecfbbf48`;
  no active stabilization card previously covered its execution venue.

**Implementation**

- Add `py_lsp_scale` to `SERIAL_SUITES` without widening its threshold or changing the fixture.

**Verification**

```sh
build/c/test-runner py_lsp_scale
scripts/test.sh
```

**Done when**

- The guard runs in the quiet serial tail.
- Isolated and full ASan/UBSan venues pass without changing the 100x product-scaling bound.

**Completion evidence**

- `py_lsp_scale` runs in the 19-suite serial tail and passes its 100x bound.
- The full ASan/UBSan scheduler passes 7,439 tests with 0 failures and 4 platform skips.

### H4 — Remove the LSP unity warning blind spot

**Scope**

- `Makefile.cbm`: `LSP_SRCS`, `LSP_UNITY_DEPS`, `GRAMMAR_CFLAGS*`, and test/TSan/production `lsp_all.o` recipes
- `internal/cbm/lsp_all.c`
- First-party `internal/cbm/lsp/*.c` and related headers; generated files only when the diagnostic originates there

**Current state**

- The unity TU includes 27 `.c` files. Eighteen are first-party top-level LSP files.
- `scripts/check-lsp-warning-census.sh` records an empty per-source inventory with `total 0` and runs in lint CI.
- Test, TSan, and production LSP objects use `CFLAGS_LSP_TEST`, `CFLAGS_LSP_TSAN`, and `CFLAGS_LSP_PROD`, derived from their respective strict normal flags. Grammar and Tree-sitter runtime compilation remains separately scoped under grammar flags.

**Completion evidence**

- `make -f Makefile.cbm lsp-warning-census` reports `total 0`.
- `make -f Makefile.cbm -B build/c/lsp_all.o build/c/tsan_lsp_all.o build/c/prod_lsp_all.o` passes with `-Werror` and no `-w` in the LSP recipes.
- Focused C/C++, Rust, Kotlin, Go, Python, C#, Java, PHP, TypeScript, Perl, Rustdoc, and type-representation suites pass after their source-level warning fixes.
- The unity TU remains intact.

**Reproduction**

```sh
cc -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter \
  -Wdate-time -Wconversion -Wsign-conversion -Wshadow -Wcast-qual -Wcast-align \
  -Wstrict-prototypes -Wmissing-prototypes -Wdouble-promotion -Wpointer-arith \
  -Wredundant-decls -Wundef -Isrc -Ivendored -Ivendored/sqlite3 \
  -Ivendored/mimalloc/include -Iinternal/cbm \
  -Iinternal/cbm/vendored/ts_runtime/include -Ibuild/c/generated \
  -isystem internal/cbm/vendored/verstable -fsyntax-only internal/cbm/lsp_all.c
make -f Makefile.cbm -B -n build/c/lsp_all.o
```

Run matching LSP suites after every batch, then `test-par`, production build, and TSan build. Completion requires zero census warnings, strict LSP object recipes, no suppressions, and green focused/full checks.

### H5 — Classify and ratchet decoded NULLs

**Scope**

- `scripts/check-null-discipline.py`
- The 282 sites from `python3 scripts/check-null-discipline.py --report`

**Verified contracts to preserve**

- `cbm_fqn_module_source_lang()` can return NULL on arena allocation failure; operational module-QN guards are load-bearing unless the API becomes status-plus-out-value.
- `gb_prop_string_dup()` returns NULL when a typed string property is absent. Dump-side `local_names` is zero-initialized and populated only for IMPORTS edges; this is genuine optionality.
- Current `CBMImport` initializers populate `.local_name`. The nullable storage described above is the dump-side array, not an omitted import initializer.
- `?`, `(null)`, `unknown`, `ANY`, and `{}` have display/property semantics in specific fields and are not interchangeable with decoded domain values.

**Required sequence**

1. Save the report grouped by producer/accessor.
2. Classify every family as allocation failure, lookup-not-found, semantically absent, display/log boundary, or wrongly nullable decoded string.
3. For wrongly nullable values, establish a non-NULL producer contract and tests before removing downstream guards.
4. Preserve explicit presence predicates when absence carries meaning.
5. Re-run the report after each family. Count reductions must map to reviewed contract changes, not regex evasion.

**Verification**

```sh
python3 scripts/check-null-discipline.py --self-test
python3 scripts/check-null-discipline.py --report
python3 scripts/check-null-discipline.py
```

Callable-slot remains zero. Every removed guard has a tested producer contract. Optional properties, OOM, and display values remain distinguishable.

**Completion evidence**

- `scripts/null-discipline-decoded.inventory.tsv` classifies all 282 current decoded-null boundaries by a stable identity, semantic category, and producer/accessor family.
- The current categories are 36 allocation failures, 41 lookup-not-found cases, 124 semantically absent values, 81 display/log boundaries, and zero wrongly nullable decoded strings.
- `scripts/check-null-discipline.py` hashes the complete conditional expression, reports every record by category and family, rejects unclassified additions, permits reviewed removals, and retains zero tolerance for callable slots.
- Its self-test proves positional callback detection, exact inventory matching, fallback-change detection, unclassified-record reporting, and reviewed-record removal.

### H6 — Add a root-ERROR `parse_partial` regression

**Status: Complete**

**Scope**

- `internal/cbm/cbm.c`: `parse_partial` root handling near 1511–1538
- `tests/test_index_resilience.c`: existing partial-parse tests near 292–467
- `tests/test_parse_coverage.c` and extraction tests where shape assertions fit

**Verified evidence**

- The protected branch requires a tree whose root type is `ERROR`, at least one recovered definition, and at least one remaining failed region after recovered-region and benign-macro subtraction.
- Ordinary small syntax errors usually create an ERROR descendant or a fully recovered definition; they do not exercise this branch.
- Candidate fixtures that stay green with both the target fix and fallback removed are non-falsifying and must not be kept.

**Required test**

1. Minimize a small fixture with root type `ERROR` and at least one recovered definition.
2. Assert the parser shape so grammar drift cannot turn it into a descendant-error test.
3. Assert recovered symbol presence, `has_error == false`, `parse_incomplete == true`, positive/narrow error ranges, and persistence through indexing.
4. Mutation-check the exact root-ERROR handling: reverting it must fail the regression.

```sh
make -f Makefile.cbm test-focused TEST_SUITES='index_resilience parse_coverage extraction'
```

Do not copy the 11k-line CLI file into fixtures, weaken region subtraction, or assert only `parse_incomplete`.

**Completion evidence**

- A 27-line C fixture with two preprocessor-split loop functions has a tree root of `ERROR` and retains the trailing `recovered` definition.
- Parse coverage asserts the root shape, recovered symbol, `has_error == false`, `parse_incomplete == true`, and an inner error range that is positive and narrower than the fixture.
- The index-resilience regression verifies the persisted `parse_partial` row, `index_status`, logs, and snippet coverage note for `root_error.c`.
- Removing the existing root-ERROR handling makes `c_root_error_keeps_recovered_def_and_narrow_range` fail; the restored implementation passes the focused suites (290 passed, 0 failed).

### H7 — Design and implement missing-name identity migration

**Status: Complete**

**Scope**

- `src/graph_buffer/graph_buffer.c`: `heap_strdup`, `gb_intern`, node creation/update, winner selection, merge, and name index
- `tests/test_graph_buffer.c`, `tests/test_pipeline.c`, `tests/test_incremental.c`
- Store/dump/load equality and persisted identity if representation changes

**Verified evidence**

- A missing node name is `NULL`; a literal `"{}"` is an ordinary name, and absent property JSON is `"{}"`.
- Sequential upsert and parallel merge use the same total NULL-safe name ordering for canonical-winner selection.
- Unnamed nodes have no `nodes_by_name` entry; literal `"{}"` remains addressable through that index.
- The NOT NULL stored name column writes absence as empty text and decodes empty text as `NULL`; property JSON remains an empty JSON object.

**Required sequence**

1. Automate the divergence first: compare fresh full, sequential incremental repair, and parallel/second incremental repair. Include a genuine node named `"{}"`.
2. Inventory helper calls by field semantics. Keep property JSON normalization as `"{}"`.
3. Define a canonical missing-name representation that cannot alias a valid source name.
4. Apply it consistently to sequential upsert, parallel merge, node copy/create, `nodes_by_name`, dump/load, and store equality/upsert keys.
5. Define migration/compatibility for persisted rows if storage representation changes.
6. Assert identical node, edge, reference, winner, remap, and name-index results across full and incremental paths.

```sh
make -f Makefile.cbm test-focused TEST_SUITES='graph_buffer pipeline incremental'
```

**Completion evidence**

- Direct graph-buffer, parallel merge, and store flush/load tests preserve both an unnamed node and a literal `"{}"` node, while retaining `{}` property JSON.
- The focused graph-buffer suite passes 56 checks; graph-buffer, pipeline, and incremental suites pass 305 checks in the local environment. The network-backed incremental fixture does not run while GitHub DNS is unavailable.
- Existing databases remain readable. Rows produced by the former `"{}"` missing-name encoding are indistinguishable from genuine literal names, so reindexing is the safe migration path that writes the empty persisted representation.

---

## 6. Retained architecture-review track

### A1 — Make SQLite allocator binding one-shot and transactional

- **Files:** `src/store/sql.c:229–243`; fresh-process store tests.
- **Evidence:** active `g_alloc` changes before SQLite accepts the callback table; repeated/late bind can redirect live frees.
- **Change:** serialize bind, prepare local methods, call `sqlite3_config`, then publish allocator and bound state only on `SQLITE_OK`. Reject or idempotently report subsequent binds. Never call `sqlite3_shutdown` around live stores.
- **Tests:** first bind succeeds; late/repeated bind fails without changing callbacks; concurrent callers yield one winner; open/use/close survives rejected bind under ASan.
- **Verify:** `scripts/test.sh --suites store`, then full sanitizer venue.

### A2 — Make semantic paired-array growth transactional

- **Files:** `src/semantic/semantic.c:553–570,707–726`; `tests/test_semantic.c`.
- **Evidence:** independent reallocations can leave a dangling retained member after one-sided success.
- **Change:** one unexported helper allocates two fresh arrays, copies the live prefix, and publishes both pointers/capacity only after both succeed.
- **Tests:** deterministic failure of allocation 1 and 2 in both add paths; state remains usable and freeable; boundary growth succeeds.
- **Verify:** `scripts/test.sh --suites semantic` under ASan/UBSan.

### A3 — Preflight and unwind graph-buffer OOM paths

- **Files:** `src/graph_buffer/graph_buffer.c:1840–2289`; graph-buffer tests.
- **Evidence:** dump arrays and remaps are written unchecked, including after transaction/index/store mutation begins.
- **Change:** explicit-status builders with initialized out-params; preflight allocation before destructive work; rollback/abort/unlink on later failure; preserve reusable/freeable graph buffer.
- **Tests:** fail every allocation and partial parallel-array step; no output publication, store mutation, index loss, leak, or NULL write.
- **Verify:** `scripts/test.sh --suites graph_buffer` under sanitizers.

### A4 — Make `ingest_traces` truthful

- **Files:** `src/mcp/mcp.c:10882–10912`; MCP/incremental tests.
- **Evidence:** handler returns `accepted` and a count while persisting nothing.
- **Smallest correct change:** return stable MCP `unsupported` error and align schema/profile exposure. Persistence is acceptable only with a durable store mutation proven by a subsequent graph query.
- **Acceptance:** success always means persisted/queryable traces; no test asserts false acceptance.
- **Verify:** `scripts/test.sh --suites 'mcp incremental'`.

### A5 — Refuse immutable reads with a nonempty WAL

- **Files:** `src/store/store.c:793–913`; checkpoint/read-only MCP tests.
- **Evidence:** `immutable=1` ignores committed WAL frames; existing fallback coverage checkpoints first.
- **Change:** detect `<db>-wal`; if nonempty, fail closed or open a safe merged writable snapshot. Preserve immutable fallback only for absent/empty WAL.
- **Test:** committed sentinel exists only in WAL; read-only query must error rather than return an older graph; checkpointed case succeeds.

### A6 — Make mutation generation atomic

- **Files:** `src/store/store.c:1491–1530`; store pragma tests.
- **Evidence:** generation SQL result is discarded and project upsert can return success with stale cursors.
- **Change:** checked SQL with recorded error and savepoint compatible with caller transactions; rollback project and generation together.
- **Test:** injected authorization failure leaves project and generation unchanged; nominal upsert increments once.

### A7 — Give trace URL results caller-owned storage

- **Files:** `src/traces/traces.c:77–120`, `traces.h:54–58`; trace tests.
- **Evidence:** `url.full` uses one global static buffer and contradicts the lifetime contract.
- **Change:** store normalized URL path in the output object or caller buffer; update the contract.
- **Tests:** two sequential outputs remain distinct; concurrent extraction retains per-call paths; TSan clean.

### A8 — Reject malformed MinHash encodings

- **Files:** `src/simhash/minhash.c:297–314`; simhash tests.
- **Change:** require exactly 512 hex digits, parse into a temporary, and publish only on complete success.
- **Tests:** invalid first/middle/final characters, signs, spaces, mixed-case valid input, and unchanged output on failure.

### A9 — Close the remaining complexity-gate bypass

- **Files:** `.github/workflows/pr.yml:43–66,130–145`; `scripts/test.sh`; complexity contract.
- **Current state:** PR contains the correct post-build live comparison.
- **Remaining change:** classify `complexity.allow`, checker, and contract changes as product changes; gate mode treats missing binary/index as failure rather than green skip. Keep the existing post-build live step.
- **Tests:** each control file triggers product work; missing prerequisite fails; clean/new/stale/malformed/index cases remain covered.

### A10 — Gate Graph UI Vitest in embedded builds

- **Files:** `Makefile.cbm:1109–1113`; Graph UI package/tests; CI contract.
- **Change:** run one dependency install, then Vitest, then build through a shared frontend prerequisite.
- **Acceptance:** `cbm-with-ui` fails when a Graph UI test fails.
- **Verify:** `make -f Makefile.cbm frontend`.

### A11 — Run allocator-abort coverage in canonical CI

- **Files:** `tests/test_platform.c:286–328`; foundation target; `scripts/test.sh`.
- **Evidence:** the real abort assertion exists only in the isolated single-purpose foundation runner.
- **Change:** invoke that isolated runner from the canonical default venue; do not enable the abort/fork path inside the multi-suite runner.
- **Acceptance:** injected realloc failure terminates with SIGABRT in the merge lane.

### A12 — Narrow license exceptions

- **Files:** `scripts/license-policy.json`; license checker/tests.
- **Evidence:** whole release-script exclusions hide every future finding to suppress one ScanCode JSON false positive.
- **Change:** suppress only the exact path plus detected JSON license pair, or change the false-positive token shape. Do not globally allow JSON.
- **Tests:** the known pair passes; GPL/AGPL in the same file fails; unrelated JSON finding fails.

### A13 — Ratchet decoded-NULL growth

- **Depends on:** H5 classification.
- **Files:** `scripts/check-null-discipline.py` and self-tests.
- **Change:** check in a stable baseline/inventory and fail on growth while preserving the detailed report. Prefer stable path/expression identity; count ratchet is the minimum.
- **Tests:** equal/below baseline pass, one new synthetic site fails and is named, callable-slot zero behavior stays unchanged.

### A14 — Install the integration sidecar in Nix

- **Files:** `flake.nix`; `assets/cbm-integrations.json`; package tests.
- **Change:** install the hash-matched JSON beside the executable. Preserve direct Nix make invocation if compiler-wrapper constraints require it.
- **Tests:** closure contains both files; isolated integration install/uninstall resolves the sidecar; tampering fails hash verification.
- **Verify:** `nix build .#` plus isolated result-binary smoke.

### A15 — Prevent stale Graph UI responses

- **Files:** `graph-ui/src/hooks/useGraphData.ts`; hook tests.
- **Change:** AbortSignal plus controller and monotonically increasing request generation; gate progress/data/error/finally writes; abort on replacement/unmount; ignore AbortError.
- **Tests:** resolve newer request before older and prove only newer state survives; prior signal is aborted.

### A16 — Emit bounded, valid UI JSON

- **Files:** `src/ui/http_server.c:587–745`; UI/HTTP tests.
- **Change:** construct process and browse results with yyjson dynamic docs/arrays. Return a JSON 500 on allocation/serialization failure. Do not return truncated 200 bodies.
- **Tests:** quotes, backslashes, controls, wide listings; every 200 body parses and round-trips values.

### A17 — Complete keyboard and assistive semantics

- **Files:** `ResizeHandle.tsx`, `FilterPanel.tsx`, `Sidebar.tsx`; UI tests.
- **Change:** separator role/focus/orientation/keyboard resizing; pressed or checkbox state on toggles; accessible search label; visible focus.
- **Tests:** role/name queries, ArrowLeft/ArrowRight behavior, pressed-state changes, and labeled search.

### A18 — Make package metadata coherent

- **Files:** `server.json`, `flake.nix`, README/site/package metadata.
- **Change:** choose one canonical version source and derive/validate all consumers; derive language count from registry/grammar source.
- **Acceptance:** one version and language count across package and user-facing metadata; checker identifies file/key drift.

### A19 — Fail memlab when `cygpath` fails

- **Files:** `scripts/memlab.sh:88–100`; shell contract.
- **Change:** assign conversion to a task-specific variable, require successful nonempty output, then export.
- **Test:** fake failing/empty `cygpath` stops before mkdir/binary launch; successful conversion exports expected path.

### A20 — Release validation

Run only after every prior card is complete:

1. focused suites recorded in each task;
2. strict LSP warning census at zero;
3. `make -f Makefile.cbm frontend` with UI tests/typecheck/build;
4. Nix build and sidecar smoke;
5. `scripts/lint.sh`;
6. default `scripts/test.sh` under ASan/UBSan;
7. `scripts/test.sh --tsan`;
8. Windows temp/concurrency and packaging contracts;
9. release/package smoke from an extracted artifact.

**Final definition of done**

- Zero test failures and zero unexplained skips.
- Zero LSP warnings and no `-w` on LSP objects.
- No new suppressions or weakened gates.
- Live complexity comparison executes against the current binary/index.
- Decoded-null inventory is at or below its reviewed baseline and callable-slot remains zero.
- Integration sidecar, metadata, UI tests, JSON, accessibility, and platform package contracts pass.
- H2 and H3 contain captured evidence and causal fixes; flakes are not accepted as release exceptions.

## 7. Task completion record template

Update the active card in place and add this block beneath it:

```markdown
**Completion evidence**

- Status: Complete
- Files changed: ...
- Behavioral regression: ...
- Commands: ...
- Results: N passed, N failed, N skipped
- Remaining risk: None / exact bounded risk
```

Do not add a chronological diary. Keep the document as the current executable state of the goal.
