#pragma once
// Fixed candidate driver interface. The evaluated agent edits only the
// implementation behind this interface (candidate/src/). The signatures,
// error names, and observable semantics are frozen by docs/contract.md.
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "efs/errors.h"
#include "efs/services.h"
#include "efs/types.h"

namespace efs {

// Abort/lease protection: the world registers staged objects + admitted
// crypto ops until their last user finishes. Implementations obtain a
// lease implicitly by holding operation state; the world exposes the
// primitive below for the reference/starter to mark in-flight objects.
class ILeaseTracker {
 public:
  virtual ~ILeaseTracker() = default;
  virtual uint64_t Admit(const std::vector<std::string>& object_ids) = 0;
  virtual void ReleaseLease(uint64_t lease) = 0;
  // Read-only enumeration of in-flight protected objects (for GC).
  virtual std::set<std::string> Protected() const = 0;
};

// One filesystem handle per tenant. All methods are synchronous except
// put_async/await/cancel. op_id must be unique per mutating call.
class IDriver {
 public:
  virtual ~IDriver() = default;
  virtual Result<ReadOut> Read(const TenantCap& cap, const std::string& name,
                               uint64_t offset, size_t length) = 0;
  virtual Result<void> Put(const TenantCap& cap, uint64_t op_id,
                           const std::string& name,
                           const std::vector<uint8_t>& bytes) = 0;
  virtual Result<void> WriteRange(const TenantCap& cap, uint64_t op_id,
                                  const std::string& name, uint64_t offset,
                                  const std::vector<uint8_t>& bytes) = 0;
  virtual Result<void> Truncate(const TenantCap& cap, uint64_t op_id,
                                const std::string& name,
                                uint64_t new_length) = 0;
  virtual Result<void> Rename(const TenantCap& cap, uint64_t op_id,
                              const std::string& from,
                              const std::string& to) = 0;
  virtual Result<void> Remove(const TenantCap& cap, uint64_t op_id,
                              const std::string& name) = 0;
  // Async: captures the input value before returning. Returns the op_id
  // as the pending handle (echoed). Caller may destroy/mutate its buffer
  // immediately after return.
  virtual Err PutAsync(const TenantCap& cap, uint64_t op_id,
                       const std::string& name,
                       const std::vector<uint8_t>& input) = 0;
  virtual Result<void> Await(uint64_t op_id) = 0;
  virtual Result<void> Cancel(uint64_t op_id) = 0;

  virtual Result<SnapshotHandle> Snapshot(const TenantCap& cap,
                                          uint64_t op_id) = 0;
  virtual Result<ReadOut> ReadSnapshot(const TenantCap& cap,
                                       SnapshotHandle snap,
                                       const std::string& name,
                                       uint64_t offset, size_t length) = 0;
  virtual Result<void> ReleaseSnapshot(const TenantCap& cap,
                                       SnapshotHandle snap) = 0;

  virtual Result<void> BeginRotation(const TenantCap& cap, uint64_t op_id) = 0;
  virtual Result<void> MigrateFile(const TenantCap& cap, uint64_t op_id,
                                   const std::string& name) = 0;
  virtual Result<void> FinishRotation(const TenantCap& cap,
                                      uint64_t op_id) = 0;

  // Restartable recovery of the committed root. Never rolls back past
  // the durable anchor; missing/corrupt committed state fails closed.
  virtual Result<void> Recover() = 0;
  // Reclaim unreachable objects after considering live roots, snapshot
  // pins, and in-flight leases.
  virtual Result<void> Collect() = 0;
};

// Factory implemented by reference/ and candidate/src/ respectively.
// Services are verifier-owned; the driver must not retain raw key
// material or bypass them.
class IDriverFactory {
 public:
  virtual ~IDriverFactory() = default;
  virtual IDriver* OpenHandle(uint32_t tenant, IObjectStore* store,
                              IAnchor* anchor, ICryptoBroker* broker,
                              IManagedAllocator* alloc,
                              ILeaseTracker* leases) = 0;
};

}  // namespace efs
