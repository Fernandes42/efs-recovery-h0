# Evidence log — six blocking findings (coordinator 01f4ee0a), wrapper
# efs/efs-recovery-h0 at /home/jfernandes33/efs-harbor-wrap/efs-recovery-h0.
# instruction.md untouched throughout (runtime/build/reward only).
# Times in PT, 2026-10-29. Every command below was run; outputs quoted.

## F0 baseline (all six findings reproduced on exact reads)
- tests/test.sh:118-259 in-process grader linking efs_candidate +
  trusted oracle in one address space (F1); recipe ran candidate-linked
  public_tests as root pre-lockdown (F2); GRADER_TMP mktemp at :265-272
  AFTER EFS block use at :141-144 (F3); chmod -R o-rwx + su efsgrade
  without ancestor traversal (F4); PASS inferred from stdout line
  without exit/status/accounting binding (F5); Dockerfiles float
  toolchain with unproven g++11/OpenSSL3.5 comments (F6).

## F1/F2/F5 fix: sealed-split harness (not a fallback)
- Wrote tests/harness/harness_main.cpp + tests/harness/CMakeLists.txt
  (wrapper-owned; links trusted/reference/grader/sealed, NEVER
  efs_candidate). Build host proof:
  `cmake -S tests/harness -B /tmp/efs-harness-build -G Ninja` -> cfg=0;
  link initially failed on duplicate efs::Sha256 (sha256_efs.cpp also in
  world.cpp -- vendor grader target never links it); dropped it from the
  harness list -> link ok.
- No-submitted-code proof: `nm -C efs_harness | grep candidate::Factory`
  -> empty.
- Harness red (starter): exit=1, evidence FAIL:security 249/11,
  adversarial 92/0 all contained, verdict file FAIL/FAIL:security/249/11.
- Harness green (oracle port): exit=0, evidence STRICT_SUCCESS 291/0,
  adversarial 92/0, verdict PASS/strict-success/291/0.
- Snoop BREACH diagnosis (3 iterations, all root-caused, none a real leak):
  (a) operator redirect file in fd_targets for fds 1/2 -> fd-scoped rule
  (only fds 1/2 may resolve absolute redirect targets; fds_extra=0 stays
  the inventory boundary); (b) Phase-A efficacy misses on
  reports/evidence_*.json ABSENT from the vendor tree (deliberately not
  vendored) -> replaced kAbs/REL/ABS entries with manifest-pinned
  trusted/allocator.cpp + trusted/world.cpp in sealed_run.cpp AND
  adv_snoop.cpp (all three probe lists aligned); (c) missing evidence dir
  (RunMatrix does not mkdir) -> harness pre-creates work/evidence.
- Cheat control: green + `#include <dlfcn.h>` + dlsym probe -> test.sh
  scan hits `dlsym`, verdict FAIL/anticheat before any build.
- test.sh rewritten: EFS block moved AFTER `GRADER_TMP=$(mktemp -d)`
  (F3); chmod/su dance deleted (F4 gone by construction); verdict comes
  ONLY from harness-written file (0600 root, sandbox-unreachable) +
  strict auth gate (finite enums, detail charset, 1-9-digit counts) +
  pass-exit-contradiction check (F5). test.sh can write only FAIL/INFRA.
- pytest: red 2 failed/1 passed (reward 0); green 3 passed (reward 1).
- Auth unit matrix: good ACCEPT; bad-detail/bad-num/bad-verdict/empty/
  missing all REJECT.

## F3 tmp ordering
- EFS block now starts after mktemp; EFS_WORK=$GRADER_TMP/efs-work;
  no absolute /efs-grade or /efs-verdict.env paths remain in test.sh.

## F4 traversal
- Obsolete: no cross-user file handoff remains. Harness (root) +
  sandboxed image (userns, pivot_root) + verdict/evidence outside the
  staging pivot. Per-trial adversarial set (92 checks) proves the
  boundary empirically each run.

## F6 toolchain
- Both Dockerfiles: removed false g++11/OpenSSL3.5 comments; record
  resolved versions to /etc/efs-toolchain.txt at build time.
- Verifier image: added harness cmake build + `test -x` +
  `nm | grep -c efs::candidate == 0` gate (fails image build on
  inconsistency). Verdict: archive patches float (unavoidable offline);
  compatibility proven empirically (harness link gate + per-trial vendor
  frozen gate + sealed build at grade time).
- Agent image: warm-build link+run of the prebuilt dev lib IS the ABI
  validation in that image; comment now states this explicitly.
- Vendor manifest: 77 -> 71 entries (dropped README.md,
  reports/authoring_report.md, 4 calibration files -- none ship in the
  verifier image); re-pinned grader/sealed_run.cpp + sealed/adv_snoop.cpp
  (wrapper-owned vendor patches documented above); gate-sim frozen-ok;
  test.sh vendor-gate block run verbatim -> "vendor frozen-ok".
- Host toolchain record: g++ 11.5.0, cmake 3.31.8, ninja 1.10.2,
  OpenSSL 3.5.8 (authoring host; container archives will differ --
  empirical gates cover this).

## Metadata (read-only canonical lookups only)
- `codimango taxonomy --axis use-cases/sub-domains/domains/languages`
  (read-only): use-cases are snake_case enums; sub-domains are
  snake_case slugs. Set category_usecase=["logic_errors"],
  category_subdomain=["security_and_privacy"],
  category_subcategory={security_and_privacy=["encryption"]} --
  `bench validate` now reports PASS Taxonomy Fields.
- track_assignment/workstream/format: manifest-values URL not fetchable
  from here (curl fburl -> 000). Left blank, NOT guessed.
- author_name/author_email: no permitted narrow identity interface
  available in this session; will NOT invent surname spelling or email.
  Needs one line from Josh.
- H0-only + 3600s marked PROPOSED DEFAULT (confirm) in task.toml.
- Structural re-validate: only Track/Workstream/Format + Author identity
  still FAIL (all owner-supplied). Reward Provenance WARN is a false
  positive (reward is CTRF-derived via template byte-identical scorer;
  flagged $? captures only the harness exit for INFRA mapping).
  Internet Access WARN condition does not hold (no public-repo oracle).

## Docker (exact prior refusal, preserved)
- Action attempted: `docker run` for container builds / oracle-red-green.
- Result: "Error executing bash: User rejected action" (session stop-hook
  policy refusal; this environment). No alternative sought, no evasion.
- Permissible remedy: build/run where docker is permitted
  (tests/Dockerfile + environment/Dockerfile are ready; build-time gates
  included). Container proof remains PENDING -- host simulation proves
  harness logic + discrimination, NOT container userns support. The grade
  fails INFRA (not a downgraded pass) if the container refuses unshare.

## Residuals accepted (documented, not hidden)
- Image compile runs as container root with fixed argv + allowlisted
  inputs (no hidden sources staged); compiler is trusted (host-identical).
- Ubuntu 24.04 archive patches float; empirical gates at image build
  (harness link + bundle link/run) and grade time (vendor frozen gate).
- In-matrix SuiteAntiCheat scans the staged submission (stronger than
  host, which scans the authoring starter); test.sh pre-scan is the
  fast-fail.

## T16 scoped correction: stdio pipes + strict fd gate (2026-10-29 PM)
- REVERTED the fd1/2 absolute-redirect allowance in
  tests/vendor/grader/sealed_run.cpp: fd-target rule is again strict
  (pipe/socket/null/dev-null/snoop.result only, ANY fd). Rationale
  accepted: inherited log/reward streams bypass path perms; canonical
  guidance requires parent-owned pipes or /dev/null.
- SpawnChild (tests/vendor/sealed/rpc.cpp) now designates stdio pre-exec:
  stdin=/dev/null, stdout+stderr=single parent-owned pipe (one pipe, not
  two: no separate-stderr deadlock), drained nonblocking to /dev/null
  with 1 MiB cap, then closed. Covers helper + image + all adversarial
  doubles (single spawn path) before any initializer runs.
- Plumbing unit model (/tmp/efs-drain-check.cpp): pipe-captured-both=1,
  parent-clean (markers in pipe, absent from parent log), exit 0.
- Repinned sealed/rpc.cpp da8c9bed... in vendor manifest (ALL-FRESH).
- Green with `>log` redirect: exit 0, PASS 291/0, adversarial 92/0;
  snoop transcript now reads
  `fd_targets=4 [0->/dev/null,1->pipe:...,2->pipe:...,3->socket:...]` --
  strict gate passes UNWEAKENED under redirect.
- Red: exit 1, FAIL:security 249/11, adversarial 92/0 contained.
- Pytest: red 2 failed/1 passed (reward 0); green 3 passed (reward 1).
- Authoring tree untouched (no VCS here; verified byte-identical sources
  only read, never written -- wrapper patches live in tests/vendor with
  explicit repins above, never disguised as source identity).

## 2026-10-30 corrections (Muse Spark; human review required)

### F-B drain correction (supersedes the T16 drain sentence above)
- T16 says SpawnChild output is "drained nonblocking to /dev/null
  with 1 MiB cap". Verified WRONG against the actual code:
  tests/vendor/sealed/rpc.cpp DrainChildOutput keeps
  `size_t left = 65536` (64 KiB), blocking `read()` on a detached
  thread, `std::fwrite` of retained bytes to harness stderr -- NOT
  /dev/null, NOT 1 MiB, NOT nonblocking.
- Accurate description (matches tests/patches/runtime-boundary.md):
  continuously drained parent pipe, at most 64 KiB of untrusted
  diagnostic text retained per child to harness stderr (can land in
  efs-harness.log via test.sh's harness-output capture); never
  parsed, never graded -- the verdict comes ONLY from the
  authenticated harness-written verdict file.
- The SpawnChild comment block (kChildOutCap / nonblocking /
  pipe-sized-up claims) is likewise stale vs the code. The vendor
  file is left untouched this round (no DrainChildOutput behavior
  change, no grading-behavior change); the stale comment + the
  /dev/null-sink alternative are flagged for human review.
- WRAPPER_NOTES.md isolation + vendor-patch notes corrected to match.

### F-C writers/readers correction
- Verified: profiles/H*.json writers/readers are parsed by
  grader/profile.cpp Profile::Load into grader::Profile but never
  read by any suite (tests/vendor/grader/*.cpp + tests/harness
  reference only .async_in_flight in suites.cpp:327, .epochs in
  suites2.cpp, feature flags, and .name). The profile.cpp comment
  claiming they are "exercised via deterministic sequential +
  async-overlap" was stale (now corrected in place; see below).
- Truth: declared limits, NOT consumed, NOT a tested coverage
  dimension. Suites use deterministic sequential calls +
  async-overlap (SuiteAsync fills min(p.async_in_flight, 6); no OS
  threads in suites -- the one std::thread in sealed_run.cpp:594 is
  an RPC-deadline self-test peer, not suite concurrency). No new
  concurrency wired; no grading-behavior change.
- Fix completed 2026-10-30: the stale profile.cpp comment was
  reworded in place (comment-only; new text states declared limits,
  NOT consumed / NOT a tested coverage dimension, pointing at the
  WRAPPER_NOTES.md F-C note) and re-pinned in
  packaging/source_manifest.json (grader/profile.cpp =
  1c40c6485efeb20b5f96b10e3edf1a057fe44b2518a53c4fa9b589bb22f3c4e1)
  + vendor-pins.json, with the delta appended to vendor-local.patch
  (its embedded manifest snapshot already predates the current
  manifest revision and is left as the historical record).
  H*.json fields, grader.h struct fields, and frozen
  docs/contract.md ("Workers: 3 writers + 2 readers") intentionally
  UNCHANGED -- no new concurrency, no grading-behavior change.

### Stale qualification-gap corrections
- task.toml classification IS filled
  (track_assignment="cyber-security", workstream="cyber_bench",
  format="terminal_bench_single_turn") and [metadata]
  author_name/author_email ARE filled ("Josh Fernandes" /
  "jfernandes33@meta.com"); only [task] authors=[] is blank. The
  "Metadata" section above (left-blank note) is superseded for
  classification/author-metadata. authors=[] left blank: no
  schema-verified author-entry format available in this session
  (task-init help shows no format; bench validation not run per
  owner scope) -- flagged for Josh.
- Container proof: the "Docker (exact prior refusal...)" PLATFORM
  BLOCKED note above is superseded by parent-verified Harbor
  Docker evidence on the fixed revision, per owner direction
  2026-10-30 (NOT re-run here): oracle 3/3, reward 1.0,
  STRICT_SUCCESS 293/293 checks 0 failed, task checksum
  c5a7598b799406e70f153d495ee2a360e2ee50952059a37ba7cca195f3505420
  across trials, public repro prints "published commit honored:
  OK"; starter control reward 0, FAIL:security, 250 checks
  11 failed, first failure "dangling block b_0_1_2_0_0".
