#include "trusted/world.h"

#include <memory>

#include <openssl/sha.h>

#include "trusted/impl.h"

namespace efs {

std::vector<uint8_t> Sha256(const uint8_t* data, size_t n) {
  std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
  SHA256(data, n, out.data());
  return out;
}

std::vector<uint8_t> Sha256(const std::vector<uint8_t>& bytes) {
  return Sha256(bytes.data(), bytes.size());
}

World::World() {
  auto store = std::make_unique<ObjectStoreImpl>(&plan_);
  IObjectStore* sptr = store.get();
  store_ = std::move(store);
  anchor_ = std::make_unique<AnchorImpl>(sptr, &plan_);
  broker_ = std::make_unique<CryptoBrokerImpl>();
  alloc_ = std::make_unique<ManagedAllocatorImpl>();
  leases_ = std::make_unique<LeaseTrackerImpl>();
}

IDriver* World::Open(uint32_t tenant, IDriverFactory* factory) {
  auto it = handles_.find(tenant);
  if (it != handles_.end()) return it->second.get();
  IDriver* d = factory->OpenHandle(tenant, store_.get(), anchor_.get(),
                                   broker_.get(), alloc_.get(), leases_.get());
  handles_[tenant].reset(d);
  return d;
}

void World::Crash() {
  admin_store()->Crash();
  admin_anchor()->Crash();
  admin_broker()->Crash();
  admin_alloc()->Crash();
  static_cast<LeaseTrackerImpl*>(leases_.get())->Crash();
  handles_.clear();  // volatile handle state discarded
  incarnation_++;
}

std::map<std::string, std::vector<uint8_t>> World::Image() const {
  return store_->DurableImage();
}

void World::SetImage(std::map<std::string, std::vector<uint8_t>> img) {
  admin_store()->SetDurableImage(std::move(img));
}

}  // namespace efs
