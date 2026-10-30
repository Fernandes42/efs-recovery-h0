#include "trusted/impl.h"

#include "trusted/world.h"

namespace efs {

AnchorImpl::AnchorImpl(IObjectStore* store, FaultPlan* plan)
    : store_(store), plan_(plan) {}

AnchorState AnchorImpl::Get(uint32_t tenant) const {
  auto it = committed_.find(tenant);
  if (it == committed_.end()) return AnchorState{};
  return it->second;
}

Err AnchorImpl::Publish(uint32_t tenant, uint64_t expected_gen,
                        const std::string& manifest_id,
                        const std::vector<uint8_t>& digest) {
  if (tenant >= kNumTenants) return Err::INVALID_ARGUMENT;
  auto cur = committed_.find(tenant);
  uint64_t have = (cur == committed_.end()) ? 0 : cur->second.generation;
  if (have != expected_gen) return Err::STALE_ROOT;
  auto obj = store_->ReadDurable(manifest_id);
  if (!obj.has_value()) return Err::INVALID_ARGUMENT;
  auto actual = Sha256(obj.value());
  if (actual != digest) return Err::INVALID_ARGUMENT;
  AnchorState next;
  next.generation = expected_gen + 1;
  next.manifest_id = manifest_id;
  next.digest = digest;
  committed_[tenant] = std::move(next);
  if (plan_ != nullptr && plan_->crash_after_publish) {
    plan_->crash_after_publish = false;
    throw SimulatedCrash{};  // crash after publication, before response
  }
  return Err::OK;
}

Err AnchorImpl::Pin(uint32_t tenant, uint64_t generation,
                    const std::string& manifest_id,
                    const std::vector<uint8_t>& digest, uint64_t lease) {
  if (tenant >= kNumTenants || lease == 0) return Err::INVALID_ARGUMENT;
  auto obj = store_->ReadDurable(manifest_id);
  if (!obj.has_value()) return Err::INVALID_ARGUMENT;
  if (Sha256(obj.value()) != digest) return Err::INVALID_ARGUMENT;
  AnchorState st;
  st.generation = generation;
  st.manifest_id = manifest_id;
  st.digest = digest;
  pins_[tenant][lease] = std::move(st);
  return Err::OK;
}

Err AnchorImpl::Unpin(uint32_t tenant, uint64_t lease) {
  auto t = pins_.find(tenant);
  if (t == pins_.end()) return Err::NOT_FOUND;
  auto it = t->second.find(lease);
  if (it == t->second.end()) return Err::NOT_FOUND;
  t->second.erase(it);
  return Err::OK;
}

bool AnchorImpl::Pinned(uint32_t tenant, uint64_t lease,
                        AnchorState* out) const {
  auto t = pins_.find(tenant);
  if (t == pins_.end()) return false;
  auto it = t->second.find(lease);
  if (it == t->second.end()) return false;
  if (out) *out = it->second;
  return true;
}

void AnchorImpl::Crash() {
  // Durable by design: committed roots + pins survive. Nothing volatile.
}

std::map<uint64_t, AnchorState> AnchorImpl::PinsFor(uint32_t tenant) const {
  auto it = pins_.find(tenant);
  if (it == pins_.end()) return {};
  return it->second;
}

}  // namespace efs
