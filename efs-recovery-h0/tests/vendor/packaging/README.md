# packaging/ — sealed evaluation boundary (H0 v1)

## Fixed verifier-side rebuild (normative for evaluated runs)

The verifier rebuilds the submitted candidate from source with fixed
flags and headers. Candidate build scripts are never executed with
grader permissions.

```sh
# Allowlisted inputs: include/efs/** + candidate/src/** only.
# Everything else (reference/, trusted/ internals, grader/,
# profiles/, reports/, packaging/) comes from the frozen verifier image.
cmake -S <candidate_root> -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_STANDARD=20
cmake --build build --target efs_candidate public_tests
```

The candidate image contains exactly:

- `include/efs/errors.h`, `types.h`, `services.h`, `driver.h`, `faults.h`
- `candidate/src/*`, `candidate/README.md`
- `docs/*`, `public-tests/*`, `profiles/H0.json`, `profiles/budgets.json`
- A compiler toolchain per `toolchain.pins`

It MUST NOT contain `reference/`, `trusted/*.cpp`, `trusted/impl.h`,
`trusted/admin.h`, `grader/`, hidden fixtures, or mutation tooling.
`grader/suites3.cpp::SuiteAntiCheat` enforces this by scanning the
submitted `candidate/src/efs_impl.cpp` for `trusted/`, `reference/`,
`admin_*`, `SetDurableImage`, `RevokeEpoch`, `NonceUseCount`,
`SetFailurePlan`, and `grader/` references.

## Process separation

Functional prototype runs may execute in-process, but model evaluation
runs the candidate in its own process (or container) connected to the
protected verifier through a capability-limited channel. The candidate
process cannot mount verifier/reference/ledger paths, replace trusted
service binaries, forge verdicts, request another tenant's capability,
or bypass instrumentation by replacing headers/libraries: the verifier
image is read-only and the channel exposes only the narrow driver ABI
(no admin interfaces). Adversarial controls in the matrix (allocator /
counter bypass, untracked crypto, forged acknowledgements,
cross-tenant requests, hidden-file access, verifier tampering) are run
against this boundary; an unauditable metric is reported as a
harness-integrity failure, never as a pass.

## In-scope/out-of-scope for model runs

- In scope: `candidate/src/**` edits; any internal algorithm that meets
  the frozen contract, encoding, and budgets.
- Out of scope (reject at packaging): wire-format changes, public ABI
  changes, verifier-file edits, new dependencies (no fetching during
  evaluation), plaintext fallback stores.

## Files

- `toolchain.pins` — pinned compiler/dependency versions.
- `source_manifest.json` — SHA-256 of every source file in the
  implementation package (regenerate on revision).
- `valgrind.supp` — suppressions for OpenSSL-internal GCM noise.
- `build_recipe.sh` — the fixed rebuild script.
- `calibration/` — calibration operator kit (no model runs claimed):
  `CALIBRATION_RUNBOOK.md` (entry gates, bundle recipe, red/green
  controls, run order, stop criteria), `world.redacted.h` (vetted
  exact-layout redaction for the candidate view),
  `CMakeLists.candidate-view.txt` (import-target build for the
  prebuilt-lib bundle), `port_ref.py` (green-control port script).
