#pragma once
// Verifier-owned administration interfaces. The candidate build never
// receives these pointers through the driver ABI (drivers are handed the
// narrow base interfaces only), and the sealed packaging excludes this
// header plus trusted/ from the candidate image. Any candidate attempt
// to reach them (downcasts, hidden includes) is outside the allowlisted
// build inputs and fails the boundary gate.
#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include "efs/services.h"

namespace efs {

class IAdminStore : public IObjectStore {
 public:
  virtual void Crash() = 0;  // discard all unflushed staged contents
  virtual void SetDurableImage(
      std::map<std::string, std::vector<uint8_t>> img) = 0;
};

class IAdminAnchor : public IAnchor {
 public:
  virtual void Crash() = 0;
};

class IAdminBroker : public ICryptoBroker {
 public:
  virtual size_t NonceUseCount(
      uint32_t tenant, uint32_t epoch,
      const std::vector<uint8_t>& nonce) const = 0;
  virtual void Crash() = 0;
  virtual void SetEpochAvailable(uint32_t tenant, uint32_t epoch,
                                 bool available) = 0;
  virtual void RevokeEpoch(uint32_t tenant, uint32_t epoch) = 0;
  virtual bool EpochAvailable(uint32_t tenant, uint32_t epoch) const = 0;
};

class IAdminAlloc : public IManagedAllocator {
 public:
  virtual Metrics GetMetrics() const = 0;
  virtual void Crash() = 0;
  virtual void Quiesce() = 0;
  // Fail the allocation(s) at the given global sequence numbers.
  virtual void SetFailurePlan(std::vector<uint64_t> seqs) = 0;
};

}  // namespace efs
