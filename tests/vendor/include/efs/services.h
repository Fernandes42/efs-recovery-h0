#pragma once
// Fixed trusted-service interfaces. The candidate may call only these.
// It must not touch service internals, local files, or hidden state.
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "efs/errors.h"
#include "efs/types.h"

namespace efs {

// ---- Object store: volatile staged vs durable persisted ----
class IObjectStore {
 public:
  virtual ~IObjectStore() = default;
  // Stage a new immutable object. Re-staging an existing id is an error.
  virtual Err Stage(const std::string& id, std::vector<uint8_t> bytes) = 0;
  // Atomically persist one staged object.
  virtual Err Flush(const std::string& id) = 0;
  virtual bool DurableExists(const std::string& id) const = 0;
  virtual std::optional<std::vector<uint8_t>> ReadDurable(
      const std::string& id) const = 0;
  // Read-only whole-image enumeration (GC reachability). Ciphertext only.
  virtual std::map<std::string, std::vector<uint8_t>> DurableImage() const = 0;
  // Unconditional durable delete (GC path validates reachability first).
  virtual void DeleteDurable(const std::string& id) = 0;
};

// ---- Anchor: per-tenant generation + manifest binding ----
struct AnchorState {
  uint64_t generation = 0;
  std::string manifest_id;
  std::vector<uint8_t> digest;  // SHA-256 over the manifest object bytes
};

class IAnchor {
 public:
  virtual ~IAnchor() = default;
  virtual AnchorState Get(uint32_t tenant) const = 0;
  // CAS: atomically move generation expected->expected+1 after verifying
  // the named manifest object exists durably and matches digest.
  // Returns OK, STALE_ROOT (generation mismatch), INVALID_ARGUMENT
  // (missing object / digest mismatch).
  virtual Err Publish(uint32_t tenant, uint64_t expected_gen,
                      const std::string& manifest_id,
                      const std::vector<uint8_t>& digest) = 0;
  // Snapshot pins (durable before return).
  virtual Err Pin(uint32_t tenant, uint64_t generation,
                  const std::string& manifest_id,
                  const std::vector<uint8_t>& digest, uint64_t lease) = 0;
  virtual Err Unpin(uint32_t tenant, uint64_t lease) = 0;
  virtual bool Pinned(uint32_t tenant, uint64_t lease,
                      AnchorState* out) const = 0;
  // Read-only enumeration of durable pins (for snapshot-aware GC).
  virtual std::map<uint64_t, AnchorState> PinsFor(uint32_t tenant) const = 0;
};

// ---- Crypto/key broker: opaque handles, durable nonce reservation ----
class ICryptoBroker {
 public:
  virtual ~ICryptoBroker() = default;
  // Durable, non-rollbackable nonce reservation per (tenant, epoch).
  // Fails with KEY_UNAVAILABLE when revoked/unavailable, OUT_OF_MEMORY
  // on exhaustion (never wraps).
  virtual Result<std::vector<uint8_t>> ReserveNonce(uint32_t tenant,
                                                    uint32_t epoch) = 0;
  // Seal with a caller-supplied nonce (audited, never silently replaced).
  virtual Result<std::vector<uint8_t>> Seal(
      uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
      const std::vector<uint8_t>& aad,
      const std::vector<uint8_t>& plaintext) = 0;
  // Open; fails closed on auth failure, nonce reuse, or key outage.
  virtual Result<std::vector<uint8_t>> Open(
      uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
      const std::vector<uint8_t>& aad,
      const std::vector<uint8_t>& ciphertext_and_tag) = 0;
};

// ---- Managed allocator with erasure observer ----
class IManagedAllocator {
 public:
  virtual ~IManagedAllocator() = default;
  // Allocate n bytes (capacity n). May fail deterministically under a
  // failure plan with OUT_OF_MEMORY.
  virtual Result<std::vector<uint8_t>*> Allocate(size_t n) = 0;
  // Mandatory: cleanse the full capacity before release/reassignment.
  virtual void SecureErase(std::vector<uint8_t>* buf) = 0;
  virtual void Release(std::vector<uint8_t>* buf) = 0;
  // Bytes copied through the managed path (candidate must route all
  // graded plaintext transfers through Copy).
  virtual void Copy(std::vector<uint8_t>* dst, const uint8_t* src, size_t n,
                    size_t dst_off = 0) = 0;
  struct Metrics {
    uint64_t alloc_count = 0;
    uint64_t copied_bytes = 0;
    uint64_t peak_managed = 0;
    uint64_t live_managed = 0;
    uint64_t live_buffers = 0;
    uint64_t erasure_violations = 0;
  };
};

}  // namespace efs
