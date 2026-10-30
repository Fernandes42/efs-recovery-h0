#pragma once
// Private trusted-implementation declarations (verifier-owned).
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "efs/driver.h"
#include "efs/faults.h"
#include "efs/services.h"
#include "trusted/admin.h"

namespace efs {

class ObjectStoreImpl : public IAdminStore {
 public:
  explicit ObjectStoreImpl(FaultPlan* plan = nullptr);
  Err Stage(const std::string& id, std::vector<uint8_t> bytes) override;
  Err Flush(const std::string& id) override;
  bool DurableExists(const std::string& id) const override;
  std::optional<std::vector<uint8_t>> ReadDurable(
      const std::string& id) const override;
  void Crash() override;
  std::map<std::string, std::vector<uint8_t>> DurableImage() const override;
  void SetDurableImage(
      std::map<std::string, std::vector<uint8_t>> img) override;
  void DeleteDurable(const std::string& id) override;

 private:
  FaultPlan* plan_;
  std::map<std::string, std::vector<uint8_t>> staged_;
  std::map<std::string, std::vector<uint8_t>> durable_;
};

class AnchorImpl : public IAdminAnchor {
 public:
  explicit AnchorImpl(IObjectStore* store, FaultPlan* plan = nullptr);
  AnchorState Get(uint32_t tenant) const override;
  Err Publish(uint32_t tenant, uint64_t expected_gen,
              const std::string& manifest_id,
              const std::vector<uint8_t>& digest) override;
  Err Pin(uint32_t tenant, uint64_t generation,
          const std::string& manifest_id, const std::vector<uint8_t>& digest,
          uint64_t lease) override;
  Err Unpin(uint32_t tenant, uint64_t lease) override;
  bool Pinned(uint32_t tenant, uint64_t lease,
              AnchorState* out) const override;
  void Crash() override;
  std::map<uint64_t, AnchorState> PinsFor(uint32_t tenant) const override;

 private:
  IObjectStore* store_;
  FaultPlan* plan_;
  std::map<uint32_t, AnchorState> committed_;
  std::map<uint32_t, std::map<uint64_t, AnchorState>> pins_;
};

class CryptoBrokerImpl : public IAdminBroker {
 public:
  CryptoBrokerImpl();
  Result<std::vector<uint8_t>> ReserveNonce(uint32_t tenant,
                                            uint32_t epoch) override;
  Result<std::vector<uint8_t>> Seal(
      uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
      const std::vector<uint8_t>& aad,
      const std::vector<uint8_t>& plaintext) override;
  Result<std::vector<uint8_t>> Open(
      uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
      const std::vector<uint8_t>& aad,
      const std::vector<uint8_t>& ciphertext_and_tag) override;
  size_t NonceUseCount(uint32_t tenant, uint32_t epoch,
                       const std::vector<uint8_t>& nonce) const override;
  void Crash() override;
  void SetEpochAvailable(uint32_t tenant, uint32_t epoch,
                         bool available) override;
  void RevokeEpoch(uint32_t tenant, uint32_t epoch) override;
  bool EpochAvailable(uint32_t tenant, uint32_t epoch) const override;

 private:
  std::vector<uint8_t> key_for(uint32_t tenant, uint32_t epoch) const;
  uint8_t keys_[kNumTenants][kNumEpochs][32];
  uint64_t counters_[kNumTenants][kNumEpochs];
  bool available_[kNumTenants][kNumEpochs];
  bool revoked_[kNumTenants][kNumEpochs];
  std::map<std::string, size_t> use_count_;
};

class ManagedAllocatorImpl : public IAdminAlloc {
 public:
  ManagedAllocatorImpl();
  ~ManagedAllocatorImpl() override;
  Result<std::vector<uint8_t>*> Allocate(size_t n) override;
  void SecureErase(std::vector<uint8_t>* buf) override;
  void Release(std::vector<uint8_t>* buf) override;
  void Copy(std::vector<uint8_t>* dst, const uint8_t* src, size_t n,
            size_t dst_off = 0) override;
  Metrics GetMetrics() const override;
  void Crash() override;
  void Quiesce() override;
  void SetFailurePlan(std::vector<uint64_t> seqs) override;

 private:
  struct Slot {
    std::vector<uint8_t>* buf = nullptr;
    bool erased = true;
  };
  std::map<std::vector<uint8_t>*, bool> live_;  // buf -> erased flag
  std::vector<Slot> free_list_;
  Metrics metrics_;
  uint64_t alloc_seq_ = 0;
  std::set<uint64_t> fail_seqs_;
};

class LeaseTrackerImpl : public ILeaseTracker {
 public:
  uint64_t Admit(const std::vector<std::string>& object_ids) override;
  void ReleaseLease(uint64_t lease) override;
  void Crash();  // incarnation stopped: all leases reclaimable
  std::set<std::string> Protected() const override;

 private:
  uint64_t next_ = 1;
  std::map<uint64_t, std::vector<std::string>> leases_;
};

}  // namespace efs
