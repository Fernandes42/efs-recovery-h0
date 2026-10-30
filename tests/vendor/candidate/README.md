# H0-C++ repair task (evaluated agent instructions)

You receive a faulty C++ starter for a synthetic encrypted filesystem
plus its public contract. Repair it. The reference solution, hidden
schedules, expected results, and trusted components are not in your
workspace.

## What you may use

- `candidate/src/` — the only code you may edit.
- `include/efs/` — fixed ABI (errors, types, service + driver interfaces).
- `docs/contract.md`, `docs/format.md`, `docs/threat-model.md` — frozen
  public semantics, wire encoding, and failure model. Do not change wire
  semantics or verifier interpretation.
- `public-tests/` — smoke tests + the visible failure reproduction.
- `profiles/H0.json`, `profiles/budgets.json` — scenario manifest and
  frozen resource budgets (see below).

`reference/`, `trusted/` internals, `grader/`, hidden fixtures, and
mutation tooling are outside your workspace. Do not look for them.

## Invariant requirements (all three are in force)

1. A file mutation is durably committed only when every newly
   referenced encrypted data object is flushed **before** the manifest
   root that references it is published. Publishing early exposes
   dangling committed state after a crash.
2. Encryption nonces come from durable, non-rollbackable per-key
   reservation. Deriving the next nonce from rollbackable
   transaction/manifest state reuses nonces across a crash-and-retry
   under the same epoch; the broker audit detects reuse and verification
   fails.
3. Async input is captured (owned) before `put_async` returns. A
   non-owning span into caller/pool storage that is released or reused
   before deferred encryption consumes it commits wrong data.

## Resource budgets (frozen, measured from the correct reference)

- Managed allocation count ≤ 288 (2× reference).
- Bytes copied through the managed buffer API ≤ 908576 (2× reference).
- Peak managed bytes ≤ 73728 (2× reference peak + 64 KiB).
- Zero orphaned managed buffers after quiescence; zero erasure
  violations on success/error/cancel paths.
- Storage amplification is diagnostic-only. No throughput threshold;
  a watchdog separates hung candidates from failures.

## Build and check

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/public_tests
```

`public_tests` must print `smoke passed` and the reproduction section
must show `OK` lines (no `BUG REPRODUCED`). Do not modify `docs/`,
`profiles/`, or the public tests to make them pass. A simple repair
that satisfies every contract is valid, whatever algorithm it uses.
