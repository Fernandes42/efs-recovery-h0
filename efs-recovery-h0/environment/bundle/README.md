# EFS Recovery Evaluation — Implementation (H0-C++)

Synthetic C++ crash-consistency benchmark for an encrypted filesystem.
Planning document: Google Doc `1C94owlG21fAEvoyCbvz0HNKo3yNxYwdTqqd3hzl_9U4`
(Implementation Plan, Rev 1, 2026-10-28). Companion difficulty catalogue:
`https://artifacts.internalmeta.com/a/1096209916384034` (unchanged).

Status: H0–H5 functional, sealed, and sanitizer checks pass as reported
(in-process + sealed reference STRICT_SUCCESS on all profiles;
sealed-ASan/UBSan/TSan reference green; candidates FAIL:security on
the same planted violation; adversarial 4/4 contained every run).
Isolation review closed (see authoring_report §4b). Calibration packaging
ready (see packaging/calibration/CALIBRATION_RUNBOOK.md) — no model runs
claimed. No Codimango publication, review submission, or outreach is claimed.

## Layout

- `docs/` — frozen public semantics, wire encoding, failure model.
- `include/efs/` — fixed ABI (errors, types, service + driver interfaces).
- `trusted/` — storage simulator, anchor, crypto/key broker, managed allocator.
- `reference/` — correct implementation (authoring/verifier only).
- `candidate/src/` — faulty starter (the only code the evaluated agent edits).
- `grader/` — independent oracle, format parser, fault schedules, metrics.
- `public-tests/` — smoke tests + visible reproduction (no hidden material).
- `profiles/` — versioned H0–H5 scenario manifests + frozen budgets.
- `packaging/` — image/source manifests.
- `reports/` — authoring evidence (no invented pass results).

## Build

Requires C++20, CMake ≥ 3.20, Ninja, OpenSSL 3.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/public_tests
./build/grader --profile profiles/H0.json
```

Sanitizer builds are separate (release metrics are authoritative):

```sh
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DSANITIZE=asan-ubsan
cmake --build build-asan && ./build-asan/grader --profile profiles/H0.json
cmake -S . -B build-tsan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DSANITIZE=tsan
cmake --build build-tsan && ./build-tsan/grader --profile profiles/H0.json
```

## Roles

The candidate build sees only `include/efs/` + `candidate/src/`.
The verifier build links `trusted/` + `reference/` (oracle) + `grader/`
and rebuilds the candidate from source with the fixed recipe in
`packaging/`. Nothing in `reference/`, `trusted/` internals, hidden
schedules, or expected results is visible to the evaluated agent.
