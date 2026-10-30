#include "trusted/impl.h"

namespace efs {

ObjectStoreImpl::ObjectStoreImpl(FaultPlan* plan) : plan_(plan) {}

Err ObjectStoreImpl::Stage(const std::string& id,
                           std::vector<uint8_t> bytes) {
  if (id.empty() || id.size() > 256) return Err::INVALID_ARGUMENT;
  if (staged_.count(id) || durable_.count(id)) return Err::INVALID_ARGUMENT;
  staged_[id] = std::move(bytes);
  return Err::OK;
}

Err ObjectStoreImpl::Flush(const std::string& id) {
  auto it = staged_.find(id);
  if (it == staged_.end()) return Err::INVALID_ARGUMENT;
  durable_[id] = std::move(it->second);
  staged_.erase(it);
  if (plan_ != nullptr) {
    bool is_manifest = !id.empty() && id[0] == 'm';
    if (is_manifest && plan_->crash_after_manifest_flush) {
      plan_->crash_after_manifest_flush = false;
      throw SimulatedCrash{};
    }
    if (!is_manifest &&
        plan_->crash_after_nth_data_flush == plan_->data_flush_count) {
      plan_->crash_after_nth_data_flush = -1;
      throw SimulatedCrash{};
    }
    if (!is_manifest) plan_->data_flush_count++;
  }
  return Err::OK;
}

bool ObjectStoreImpl::DurableExists(const std::string& id) const {
  return durable_.count(id) > 0;
}

std::optional<std::vector<uint8_t>> ObjectStoreImpl::ReadDurable(
    const std::string& id) const {
  auto it = durable_.find(id);
  if (it == durable_.end()) return std::nullopt;
  return it->second;
}

void ObjectStoreImpl::Crash() { staged_.clear(); }

std::map<std::string, std::vector<uint8_t>> ObjectStoreImpl::DurableImage()
    const {
  return durable_;
}

void ObjectStoreImpl::SetDurableImage(
    std::map<std::string, std::vector<uint8_t>> img) {
  durable_ = std::move(img);
}

void ObjectStoreImpl::DeleteDurable(const std::string& id) {
  durable_.erase(id);
  staged_.erase(id);
}

}  // namespace efs
