# Wrapper notes — efs/efs-recovery-h0 (Harbor single-turn task)

Authoring project (read-only source): `/home/jfernandes33/efs-eval-h0`
at the 77-entry source manifest revision pinned in `VERSION_PINS.txt`.
Wrapper root (non-Eden, btrfs): `/home/jfernandes33/efs-harbor-wrap/`.
Wrapper vendor tree: `tests/vendor/` at the 71-entry vendor manifest
(`tests/vendor/packaging/source_manifest.json`), with documented
wrapper-owned patches (see "Vendor patches" below).

## What the wrapper is

A Harbor `tbench` single-turn task around the EFS H0 repair gate. The
model receives the vetted calibration candidate-view (docs, fixed ABI,
faulty starter, public tests, profiles, redacted world.h, dev-keys
lib) in the agent image and may edit ONLY `candidate/src/efs_impl.{h,cpp}`.
The verifier image carries the full grading closure (vendored under
`tests/vendor/`), receives exactly the two submitted files via
`artifacts`, and grades H0 through the sealed process split driven by
the wrapper-owned harness. Canonical reward: `1` iff the sealed H0
matrix reports `STRICT_SUCCESS` with full adversarial containment,
else `0`.

## Source/reward artifact contract

- Agent -> verifier: `/app/candidate/src/efs_impl.h`,
  `/app/candidate/src/efs_impl.cpp` (file artifacts, same absolute
  paths; immediate parent `/app/candidate/src` pre-created in
  tests/Dockerfile). Nothing else crosses. In particular the agent's
  build dir, CMakeLists, and any extra files never reach the grader.
- Grader reads: the two artifacts + everything baked in the verifier
  image (`/tests/vendor/*`). It never reads agent state otherwise.
- Reward: `/logs/verifier/reward.txt` (`1`/`0`) via the template's
  fail-closed prologue + CTRF scoring over `tests/test_outputs.py`
  (`test_h0_strict_success`, `test_h0_case_accounting`,
  `test_no_infrastructure_error`).
  `reward.json` handling is the template's byte-identical logic.
- Verdict file (internal): `$GRADER_TMP/efs-verdict.env`
  (`EFS_VERDICT=PASS|FAIL|INFRA`, `EFS_DETAIL=...`,
  `EFS_CHECKS=<finite int>`, `EFS_FAILED=<finite int>`), written ONLY
  by the harness binary (0600 root). test.sh can write only FAIL/INFRA.

## Grade pipeline (tests/test.sh, after GRADER_TMP exists)

0. Submitted sources present, else INFRA/missing-submission.
1. Static anti-cheat scan (12 SuiteAntiCheat patterns + 8
   runtime-extraction patterns: `dlsym dlopen /proc/ ptrace system(
   popen( execv socket(`) — reference and starter contain zero of
   them. Any hit -> FAIL/anticheat (scores 0, not infra).
2. Frozen vendor gate (71-entry manifest, impl files exempt as the
   designated untrusted input). Drift -> INFRA/vendor-drift.
3. Harness (`/tests/harness-build/efs_harness`, built at image time):
   copies submission into the staging input, stages/builds/spawns the
   sandboxed candidate image, serves RPCs, runs the matrix (291 checks)
   + adversarial set (92 checks: substitution/snoop/reuse/xtenant/rpc)
   verifier-side, writes the verdict file. Harness exit codes:
   0=PASS, 1=FAIL, 2=INFRA (sandbox refused, build/spawn failure,
   unparseable evidence).
4. Verdict authentication (strict enums, detail charset, finite
   1-9-digit counts) + pass-exit-contradiction check. Unauthenticated
   or missing file -> INFRA (never a pass).

## Isolation argument (true process isolation + designated stdio)

- Child stdio discipline: EVERY spawned child (helper, image, all
  adversarial doubles -- single SpawnChild path) receives stdin=/dev/null
  and stdout+stderr=one parent-owned bounded pipe, designated pre-exec
  before any initializer runs. The parent continuously drains the pipe
  on a detached thread (blocking reads; 64 KiB retained per child to
  harness stderr, never parsed -- see sealed/rpc.cpp DrainChildOutput
  and tests/patches/runtime-boundary.md). Drained bytes can therefore
  land in efs-harness.log; they never decide the reward, which comes
  ONLY from the authenticated harness-written verdict file. No
  candidate-inheritable verifier-log/reward stream exists; the strict
  fd-target gate (no absolute target on ANY fd) passes unweakened even
  when the operator redirects the grade's own output.
- Container boundary: fresh verifier container per trial (separate
  mode); agent filesystem never inherits.
- Address space: the harness links verifier-owned objects ONLY (build
  gate asserts zero `efs::candidate` symbols). Submitted code is never
  linked into the grading process -- not even via static initializers.
- Execution: candidate code runs ONLY inside the fixed chroot as UID/GID
  60001 (empty groups, zero capabilities, no_new_privs, task-owned seccomp
  allowlist, resource bounds; compiled under UID/GID 60002), with
  parent-side pre-exec attestation. No namespaces or mounts are requested;
  the runtime's existing controls are unchanged (see
  tests/patches/runtime-boundary.md). No candidate-linked code executes as
  root at any point (public_tests is not in the grade path).
- Filesystem: oracle material is outside the staging chroot; the verdict
  and evidence files live outside it too (0600 root). Only fresh work/tmp
  are writable by the candidate. The old efsgrade/chmod dance is deleted.
- Fail-closed downgrade policy: a refused boundary yields INFRA via the
  harness. In-process grading is NOT an accepted fallback.
- Reward channel: template fail-closed baseline + CTRF collection
  pinning; the verdict file is harness-written, sandbox-unreachable.

## Vendor patches (wrapper-owned, re-pinned in vendor manifest)

1. `grader/sealed_run.cpp`: snoop probe lists use manifest-pinned
   `trusted/allocator.cpp` + `trusted/world.cpp` instead of non-vendored
   `reports/evidence_*.json` (Phase-A efficacy gate needs paths that
   exist in the probed tree). The fd-target gate is STRICT
   (pipe/socket/null/dev-null/snoop.result only, any fd): a brief fd1/2
   redirect allowance was found unsound (inherited streams bypass path
   perms) and reverted -- see FINDINGS_EVIDENCE.md T16.
2. `sealed/adv_snoop.cpp`: REL/ABS probe lists aligned with (1).
3. `sealed/rpc.cpp` (SpawnChild): designated stdio pre-exec -- stdin
   /dev/null, stdout+stderr to one parent-owned pipe, continuously
   drained by the parent (64 KiB retained per child to harness stderr
   via DrainChildOutput; never parsed, never graded); never an
   inherited verifier stream. Single spawn path covers helper, image,
   all doubles. (Prior notes said 1 MiB to /dev/null nonblocking --
   corrected 2026-10-30 to match the code; the /dev/null-sink
   alternative is flagged for human review. Drain behavior unchanged.)
4. `packaging/source_manifest.json`: 71 entries (dropped README.md,
   reports/authoring_report.md, 4 calibration files -- none ship in
   the verifier image); re-pinned the patched files above.
5. `grader/profile.cpp` (F-C, 2026-10-30, comment-only): stale
   "writers/readers exercised" comment reworded to declared limits,
   NOT consumed / NOT a tested coverage dimension; no code change,
   no grading-behavior change. Re-pinned in the vendor manifest
   (`1c40c648...`) + `vendor-pins.json`; delta appended to
   `vendor-local.patch`.

## Profile writers/readers (F-C: declared limits, not a tested dimension)

`profiles/H*.json` `writers`/`readers` are parsed into
`grader::Profile` (`grader/profile.cpp` `Profile::Load`) but never
read by any suite (`tests/vendor/grader/*.cpp` + `tests/harness/*`
reference only `.async_in_flight` in `suites.cpp`, `.epochs` in
`suites2.cpp`, feature flags, and `.name`). They are declared
limits, NOT consumed and NOT a tested coverage dimension. Suites
exercise concurrency via deterministic sequential calls +
async-overlap (`SuiteAsync` fills `min(p.async_in_flight, 6)`; no OS
threads in suites). The stale `profile.cpp` comment claiming
writers/readers are "exercised via deterministic sequential +
async-overlap" was corrected 2026-10-30 (comment-only reword to
declared limits, NOT consumed / NOT a tested coverage dimension;
re-pinned in the vendor manifest -- see "Vendor patches" item 5).
`docs/contract.md` frozen per owner hold; `H*.json` fields and
`grader.h` struct fields intentionally unchanged (no new
concurrency, no grading-behavior change).

## Qualification gaps (honest, not gates claimed)

1. **instruction.md drafted, needs Josh's review and ownership.**
   Transcribed from human-authored candidate/README.md + submission
   mechanics; no new problem content invented.
2. **task.toml: classification + metadata author FILLED; only
   [task] authors=[] blank (schema-unverified, left for Josh).**
   `track_assignment="cyber-security"`, `workstream="cyber_bench"`,
   `format="terminal_bench_single_turn"`, plus `[metadata]
   author_name="Josh Fernandes"` and
   `author_email="jfernandes33@meta.com"`, are all set in task.toml.
   Only `[task] authors=[]` is still blank: no canonical task-toml
   schema or verified author-entry format was available in this
   session (task-init help shows no format; bench validation not
   run per owner scope), so it was NOT filled -- needs Josh's
   schema-verified entry. Taxonomy IS set from canonical labels
   (logic_errors/security_and_privacy/encryption).
3. **test_outputs.py + test.sh EFS block + harness + solve.sh need
   Josh's human review and ownership** (grading-content rule).
   Mechanical transcription + new harness logic; review recorded
   before any submission/registration.
4. **Container proof: parent-verified Harbor Docker evidence on the
   fixed revision (per owner direction 2026-10-30; NOT re-run in
   this round).** Oracle: 3/3, reward 1.0, STRICT_SUCCESS 293/293
   checks 0 failed; same task checksum
   `c5a7598b799406e70f153d495ee2a360e2ee50952059a37ba7cca195f3505420`
   across trials; public repro prints `published commit honored:
   OK`. Starter control: reward 0, FAIL:security, 250 checks
   11 failed, first failure `dangling block b_0_1_2_0_0`.
   (Supersedes the prior PLATFORM BLOCKED note: `docker run` was
   refused in the earlier session, but the parent has since proven
   the Harbor path in-container. A refused sandbox still fails
   INFRA, never a downgraded pass.)
5. **H0-only + 3600s are PROPOSED DEFAULTS (confirm).** Profiles H1-H5
   ship for context; reward grades H0.
6. **Toolchain patches float** (Ubuntu 24.04 archives; host is
   g++ 11.5.0/cmake 3.31.8/OpenSSL 3.5.8). Empirical gates: harness
   link + bundle link/run at image build; vendor frozen gate at grade
   time. Image compile runs as container root with fixed argv +
   allowlisted inputs (trusted toolchain, host-identical).

## Stop-before list (unchanged)

No model attempts/calibration, no remote task creation/registration
(`task init` was local scaffolding only; nothing pushed), no GitHub
pushes, no publications/review submissions, no contacting others, no
`task submit` (not even --dry-run), no `bench run`, no `bench validate`
against Nest.
