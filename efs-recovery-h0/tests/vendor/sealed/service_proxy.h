#pragma once
// Candidate-side service proxies: implement the narrow trusted-service
// interfaces by forwarding over the sealed channel. Ships in the
// candidate image (efs/* + sealed/rpc.h only).
#include <cstdint>
#include <map>
#include <vector>

#include "efs/driver.h"
#include "efs/faults.h"
#include "efs/services.h"
#include "sealed/rpc.h"

namespace sealed {

// Caller handle id (assigned by the verifier at D.open).
using HC = uint64_t;

void SetChannel(Channel* ch);
Channel* Chan();

struct ProxyStore : efs::IObjectStore {
  explicit ProxyStore(HC h) : h_(h) {}
  efs::Err Stage(const std::string& id, std::vector<uint8_t> bytes) override;
  efs::Err Flush(const std::string& id) override;
  bool DurableExists(const std::string& id) const override;
  std::optional<std::vector<uint8_t>> ReadDurable(
      const std::string& id) const override;
  std::map<std::string, std::vector<uint8_t>> DurableImage() const override;
  void DeleteDurable(const std::string& id) override;
  HC h_;
};

struct ProxyAnchor : efs::IAnchor {
  explicit ProxyAnchor(HC h) : h_(h) {}
  efs::AnchorState Get(uint32_t tenant) const override;
  efs::Err Publish(uint32_t tenant, uint64_t expected_gen,
                   const std::string& manifest_id,
                   const std::vector<uint8_t>& digest) override;
  efs::Err Pin(uint32_t tenant, uint64_t generation,
               const std::string& manifest_id,
               const std::vector<uint8_t>& digest, uint64_t lease) override;
  efs::Err Unpin(uint32_t tenant, uint64_t lease) override;
  bool Pinned(uint32_t tenant, uint64_t lease,
              efs::AnchorState* out) const override;
  std::map<uint64_t, efs::AnchorState> PinsFor(uint32_t tenant) const override;
  HC h_;
};

struct ProxyBroker : efs::ICryptoBroker {
  explicit ProxyBroker(HC h) : h_(h) {}
  efs::Result<std::vector<uint8_t>> ReserveNonce(uint32_t tenant,
                                                 uint32_t epoch) override;
  efs::Result<std::vector<uint8_t>> Seal(
      uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
      const std::vector<uint8_t>& aad,
      const std::vector<uint8_t>& plaintext) override;
  efs::Result<std::vector<uint8_t>> Open(
      uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
      const std::vector<uint8_t>& aad,
      const std::vector<uint8_t>& ciphertext_and_tag) override;
  HC h_;
};

struct ProxyAlloc : efs::IManagedAllocator {
  explicit ProxyAlloc(HC h) : h_(h) {}
  ~ProxyAlloc() override;
  efs::Result<std::vector<uint8_t>*> Allocate(size_t n) override;
  void SecureErase(std::vector<uint8_t>* buf) override;
  void Release(std::vector<uint8_t>* buf) override;
  void Copy(std::vector<uint8_t>* dst, const uint8_t* src, size_t n,
            size_t dst_off = 0) override;
  // Fetch current remote bytes (for Seal input / await capture).
  std::vector<uint8_t> Read(std::vector<uint8_t>* buf);
  HC h_;
  // Local shadows so driver code keeps using vector<uint8_t>*.
  std::map<std::vector<uint8_t>*, uint64_t> ids_;
  std::map<uint64_t, std::vector<uint8_t>*> ptrs_;
};

struct ProxyLeases : efs::ILeaseTracker {
  explicit ProxyLeases(HC h) : h_(h) {}
  uint64_t Admit(const std::vector<std::string>& object_ids) override;
  void ReleaseLease(uint64_t lease) override;
  std::set<std::string> Protected() const override;
  HC h_;
};

}  // namespace sealed
