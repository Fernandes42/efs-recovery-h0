# docs/threat-model.md — Failure model + measured leakage boundary (H0 v1)

## Crash model

- Deterministic storage simulator is the only durable store.
  Candidate-local files are not durable. `stage(id, bytes)` is
  volatile; `flush(id)` makes one immutable object durable. A process
  crash discards all unflushed contents; flushed objects survive.
  (Not a claim about fsync, torn sectors, or power loss.)
- External anchor (per tenant: generation, manifest ID, SHA-256)
  survives crash and storage replay. Publication is CAS against the
  expected generation; it verifies the manifest object exists durably
  and matches the digest. It does not verify referenced data blocks
  (candidate responsibility).
- After a crash the durable anchor is authoritative. Unpublished
  objects may be GC'd; a published root must be recovered or rejected
  as corrupt, never silently rolled back. Storage replay replaces only
  the backing-store image, not the anchor: if a newer committed object
  is missing, fail closed (`STALE_ROOT` / `CORRUPT_COMMITTED_STATE` /
  `AUTHENTICATION_FAILED`); reconstruction is not required.
- Normal crash recovery preserves authentic committed files.
  Corruption probes test fail-closed behaviour on the affected op; no
  replacement block is magically required. Unaffected tenants stay
  usable. Revocation changes future service behaviour at a documented
  boundary; it does not erase already-returned plaintext.

## Publication protocol (correct)

Prepare under a lease → encrypt + persist data objects → encrypt +
persist manifest → CAS-publish root → ack. Publishing early, reusing
mutable object IDs, or acking before publication is incorrect. CAS
conflict → contract-valid retry. An abandoned transaction must not
delete objects reachable from another transaction/snapshot.

## Adversary probes (H0)

- Authenticated block/metadata substitution (flip/truncate ciphertext;
  swap valid blocks across offsets/files/tenants; alter
  metadata/length/version/epoch): accept only authentic correctly-bound
  data; precise fail-closed error is valid.
- Full-storage replay (old durable image + newer anchor): live reads
  must not accept it. A pinned valid snapshot stays readable while its
  objects exist.
- Allocator/counter bypass, untracked crypto calls, mutable verifier
  build inputs, raw local backing-store use, forged acks/evidence,
  cross-tenant capability misuse, hidden-file access: must not yield
  strict success (anti-cheat controls).

## Memory / secrecy boundary (precisely bounded)

- Erasure is graded only for designated managed plaintext buffers
  (incl. capacity + pool slots), immediately before release or
  reassignment, on success/error/cancel paths. Graded via the release
  observer + protected allocator; candidate counters/logs alone prove
  nothing. Use `OPENSSL_cleanse` (not plain `memset`).
- Out of scope (not claimed): compiler temporaries, stack/register
  copies, OpenSSL internal copies, swap/core dumps, timing/cache leaks.
  Caller input/output buffers are outside the erasure claim. Raw keys
  stay in the broker (opaque handles only).
- Candidate backing files + stdout/stderr must not contain file
  payload plaintext or key material outside explicitly authorised
  outputs (grader scans within declared scope).
- Sanitizer-clean (ASan+UBSan; TSan separately) is a separate signal
  from secret erasure. Deterministic schedules + ownership controls
  are used; clean runs alone prove no interleaving.

## Efficiency boundary

- Fixed workloads 16 KiB–4 MiB + bounded op sequences. Metrics over the
  declared managed scope only: allocation count, bytes copied through
  the fixed buffer API, peak managed bytes, post-quiescence live
  allocations. Storage amplification is diagnostic-only in H0.
- Budgets frozen from the reference before any evaluated run:
  ≤ 2× ref allocs, ≤ 2× ref copied bytes, peak ≤ 2× ref peak + 64 KiB,
  zero orphaned managed buffers (enumerated cache/snapshot allowances
  excepted; zero-ref metrics use a stated block-size allowance).
  An unobservable mandatory event = harness-integrity failure.
- No throughput threshold in H0; finite watchdog separates infra
  timeouts from task failures.
