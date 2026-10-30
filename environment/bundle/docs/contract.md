# docs/contract.md — Frozen public operation contract (H0)

Version: H0 v1. All requests carry a fixture-issued tenant capability
(`tenant` + `secret`) and a unique operation ID (`op_id`). Model-visible
inputs are synthetic; expected results are generated independently by the
controller.

## Limits (H0)

- C++20, CMake/Ninja, Linux x86-64, OpenSSL 3 EVP AES-256-GCM. No fetch
  during evaluation.
- Tenants: 2 isolated (`0`, `1`). Workers: 3 writers + 2 readers.
  At most 6 async write requests in flight. One active FS handle per
  tenant; snapshot handles are explicitly leased.
- 4 KiB blocks; ≤ 16 live files per tenant; ≤ 256 KiB per file;
  ≤ 4 MiB live plaintext across tenants.
- 3 key epochs per tenant; 1 retained snapshot per tenant. Rotation
  migrates one complete file at a time; mixed epochs are legal while
  interrupted. Volume-wide atomic rotation is not required.
- Flat encrypted manifest (no Merkle tree in H0).

## Names and IDs

- Names are UTF-8 path-free identifiers of 1–64 bytes. Reject `/`, NUL,
  `.`, `..` with `INVALID_ARGUMENT`.
- File IDs (`uint64`) are stable across rename and never reused after
  deletion. `op_id` (`uint64`) is unique per request.
- Reject out-of-range lengths before allocation (`INVALID_ARGUMENT`).

## Operations

| Operation | Semantics |
|---|---|
| `read(name, offset, length)` | Slice of one committed version. Clamp at EOF; offset beyond EOF → empty. Linearisation point within invocation/completion. No mixed-version response. Auth/key failure → error, never unauthenticated bytes. |
| `put(name, bytes)` | Create/replace whole file atomically. Success = durably committed (published root), not merely queued. Empty files valid. |
| `write_range(name, offset, bytes)` | Atomic update of existing file. Offset beyond EOF rejected (`INVALID_ARGUMENT`), including for zero-length writes; offset == EOF is a valid commit point (including offset 0 on an empty file). In-range offset may extend up to the file-size limit. Untouched ranges preserved. Zero-length write on an existing file is a literal per-file commit: it seals + publishes a new manifest root and advances the generation with unchanged content bytes, returning `Ok`. Missing file → `NOT_FOUND` with no commit. |
| `truncate(name, new_length)` | Shrink only (incl. to zero). Extension rejected. Success = durable per-file commit. |
| `rename(from, to)` | Atomic namespace mutation, preserves file ID + contents. Existing destination rejected. Same-name = no-op. No overwrite in H0. |
| `remove(name)` | Atomically remove live entry; retained snapshots stay readable. Recreating the name mints a new file ID. |
| `put_async(name, input)` + `await(op_id)` | Candidate captures the input value before returning pending handle. Ownership/leasing valid only if later caller mutation/destruction cannot change it; a shared mutable span is insufficient. Initiating handle may be destroyed while admitted work completes. Success completion = durable. Cancel wins only before publication, else `ALREADY_COMMITTED`. Crash after publication but before response = committed op with no ack. |
| `snapshot()` / `read_snapshot(h,…)` / `release_snapshot(h)` | Pin one immutable committed root. Tenant-scoped, survives restart. Released/cross-tenant handles rejected. Snapshot reads may return the pinned historical version (not live-root rollback). |
| `begin_rotation()` / `migrate_file(name)` / `finish_rotation()` | Begin picks a new epoch; later encryptions use it. Migrate commits one complete file at a time; interrupted rotation may leave mixed epochs. Finish declares migration complete but must not retire keys needed by live roots, retained snapshots, or in-flight leases. |
| `recover()` / `collect()` | Recovery reconciles the committed root; ignores/discards incomplete unpublished transactions without losing committed data; restartable. Collection removes unreachable objects only after considering live roots, snapshots, in-flight leases. |

## Errors (named, machine-readable)

`NOT_FOUND`, `INVALID_ARGUMENT`, `AUTHENTICATION_FAILED`,
`PERMISSION_DENIED`, `STALE_ROOT`, `KEY_UNAVAILABLE`, `OUT_OF_MEMORY`,
`CANCELLED`, `ALREADY_COMMITTED`, `CORRUPT_COMMITTED_STATE`.
Expected errors are returned, never process aborts.

## Ordering and durability

- Anchor publication is the irrevocable linearisation point. Cancel and
  publication are mutually ordered; cancel cannot succeed after.
  A lost response or later allocation/broker error cannot undo a
  published mutation; the history oracle honours trusted anchor
  transitions even without an acknowledgement.
- Acknowledged durability is required under ordinary simulator crashes.
  Adversarial replay/corruption/revocation instead produce the specified
  fail-closed errors; those probes do not require reconstructing
  irretrievable data. An unpublished interrupted op resolves to old or
  new state only where its observed publication history permits it.
- Per-tenant mutators are serialisable; reads observe a committed
  version within their window. The controller records invocation,
  completion, cancellation, crash boundaries; the oracle accepts any
  legal ordering. In H0 the controller may assign explicit commit turns
  while overlapping preparation/encryption/readers.

## Rotation / snapshot / GC lifecycle

- `begin_rotation` advances the epoch for new encryptions at the
  crypto-service admission boundary: seals admitted before it may finish
  on the old epoch; later admissions use the new epoch.
- Snapshot pins are durable before creation returns. Release blocks new
  admissions but not already-admitted reads. Process leases are
  incarnation-scoped; reclaimable only after that incarnation stopped.
- Root selection + protection registration are atomic w.r.t.
  object/key reclamation. Staged objects + admitted crypto ops stay
  protected until their last user finishes.
