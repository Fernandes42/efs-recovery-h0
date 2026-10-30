# docs/format.md — Exact wire encoding (H0 v1, frozen)

All integers little-endian. All bounds enforced by the independent
verifier parser, which rejects truncation, duplicates, trailing bytes,
overflow, and invalid references. Public wire semantics and verifier
interpretation are frozen; candidate internals may change.

## Primitives

- `u32`, `u64`: LE. `bytes(n)`: `u32 len` + exactly `len` bytes.
  Parsers must reject lengths that overrun the buffer, arithmetic
  overflow in size computations, and any trailing bytes.
- Names: 1–64 bytes, no `0x00`, no `/`, not `.` or `..`.

## Data object (outer, stored)

```
ver      u32 = 1
tenant   u32 (0..1)
file_id  u64
content_version u64
block_idx u32
pt_len   u32 (0..4096)
epoch    u32 (0..2)
nonce    12 bytes = namespace[4] || counter[8] (counter BE)
ct_len   u32 (= pt_len)
ciphertext ct_len bytes
tag      16 bytes
```

- AAD (fixed-size LE concatenation, never ambiguous string concat):
  `tenant(4) || file_id(8) || content_version(8) || block_idx(4) ||
  epoch(4) || pt_len(4)`.
- `ciphertext` = AES-256-GCM encrypt of the `pt_len` plaintext bytes.
- Object ID: `b_<tenant>_<file_id>_<content_version>_<block_idx>_<epoch>`;
  immutable; never reused.

## Manifest plaintext (decrypts from manifest object)

```
magic    4 bytes "EFS1"
ver      u32 = 1
generation u64
op_id    u64
tenant   u32
manifest_epoch u32
file_count u32 (0..16)
repeat file_count:
  name        bytes (1..64, validated)
  file_id     u64
  file_len    u64 (0..262144)
  content_version u64
  block_count u32 (= ceil(file_len/4096), 0 if empty; <= 64)
  repeat block_count:
    block_idx u32
    content_version u64 (retained version that produced the block)
    object_id bytes (1..128)
    epoch     u32
    pt_len    u32
```

Constraints: file IDs unique; names unique; block indexes dense
`0..block_count-1` in order; `sum(pt_len)` consistent with `file_len`;
each referenced object must exist durably (ordinary path) and its
decrypted header must match `(file_id, content_version, block_idx,
epoch, pt_len)`.

## Manifest object (outer, stored)

```
ver      u32 = 1
tenant   u32
generation u64
epoch    u32 (encryption epoch)
nonce    12 bytes
ct_len   u32
ciphertext
tag      16 bytes
```

- AAD: `"EFSM"(4) || tenant(4) || generation(8)`.
- Plaintext is the manifest encoding above; its embedded
  `tenant`/`generation` must equal the outer header (binding check).
- Object ID: `m_<tenant>_<generation>`; immutable per generation.
- Anchor stores `(generation, manifest_id, sha256(manifest_object))`;
  publication CAS verifies the named object exists durably and the
  digest matches.

## Nonce discipline

- 96-bit nonce per (key = tenant+epoch). Reference uses durable
  per-key counter: `namespace = tenant_id`, `counter` strictly
  increasing, persisted in the broker (non-rollbackable). Exhaustion
  (`counter = 2^64-1`) fails before encryption.
- The broker audits requested nonces and every sealing attempt under
  the actual key identity, including attempts aborted before
  publication. It never silently replaces a nonce or repairs reuse.
- Duplicate `(key, nonce)` use fails verification even if the second
  object never reached storage (broker replays the audit on `open`).

## Endianness/bounds summary

LE everywhere except the 8-byte nonce counter (BE by convention).
Max manifest plaintext ≈ 16 files × (64 + 64×~150B) < 256 KiB.
Implementations must pre-validate lengths before allocation.
