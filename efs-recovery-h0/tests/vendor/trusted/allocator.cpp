#include "trusted/impl.h"

#include <cstring>

#include <openssl/crypto.h>

namespace efs {

ManagedAllocatorImpl::ManagedAllocatorImpl() = default;

ManagedAllocatorImpl::~ManagedAllocatorImpl() {
  for (auto& [buf, _] : live_) delete buf;
  for (auto& s : free_list_) delete s.buf;
}

Result<std::vector<uint8_t>*> ManagedAllocatorImpl::Allocate(size_t n) {
  ++alloc_seq_;
  if (fail_seqs_.count(alloc_seq_))
    return Result<std::vector<uint8_t>*>::Fail(Err::OUT_OF_MEMORY);
  // Reject absurd sizes before allocation (candidate-controlled via RPC).
  // Largest single live object is 256 KiB (file/manifest); 4 MiB is the
  // contract live-total limit. Human review: bound choice (4 MiB).
  if (n > 4 * 1024 * 1024)
    return Result<std::vector<uint8_t>*>::Fail(Err::INVALID_ARGUMENT);
  // Pool-slot reuse: first free slot with capacity >= n (threat model:
  // erasure covers capacity + pool slots; size alone undercounts).
  for (auto it = free_list_.begin(); it != free_list_.end(); ++it) {
    if (it->buf->capacity() >= n) {
      std::vector<uint8_t>* b = it->buf;
      if (!it->erased) metrics_.erasure_violations++;
      free_list_.erase(it);
      b->resize(n);
      live_[b] = false;
      metrics_.alloc_count++;
      metrics_.live_managed += n;
      metrics_.live_buffers++;
      if (metrics_.live_managed > metrics_.peak_managed)
        metrics_.peak_managed = metrics_.live_managed;
      return Result<std::vector<uint8_t>*>::Ok(b);
    }
  }
  auto* b = new std::vector<uint8_t>(n);
  live_[b] = false;
  metrics_.alloc_count++;
  metrics_.live_managed += n;
  metrics_.live_buffers++;
  if (metrics_.live_managed > metrics_.peak_managed)
    metrics_.peak_managed = metrics_.live_managed;
  return Result<std::vector<uint8_t>*>::Ok(b);
}

void ManagedAllocatorImpl::SecureErase(std::vector<uint8_t>* buf) {
  auto it = live_.find(buf);
  if (it == live_.end()) return;
  if (buf->capacity() > 0) OPENSSL_cleanse(buf->data(), buf->capacity());
  it->second = true;
}

void ManagedAllocatorImpl::Release(std::vector<uint8_t>* buf) {
  auto it = live_.find(buf);
  if (it == live_.end()) return;  // double-release ignored (grader flags)
  if (!it->second) metrics_.erasure_violations++;
  metrics_.live_managed -= buf->size();
  metrics_.live_buffers--;
  live_.erase(it);
  free_list_.push_back(Slot{buf, true});
  // Keep the slot cleansed regardless (defense in depth; the violation
  // is still recorded above). Capacity, not just size (threat model).
  if (buf->capacity() > 0) OPENSSL_cleanse(buf->data(), buf->capacity());
}

void ManagedAllocatorImpl::Copy(std::vector<uint8_t>* dst, const uint8_t* src,
                                size_t n, size_t dst_off) {
  if (dst == nullptr) return;
  auto it = live_.find(dst);
  if (it == live_.end()) return;  // unknown buffer; fail closed, no touch
  // Overflow-safe bounds (candidate-controlled off/n via RPC): dst_off + n
  // may wrap, so compare without addition.
  if (n > dst->size() || dst_off > dst->size() - n) return;
  if (n > 0) {
    if (src == nullptr) return;
    std::memcpy(dst->data() + dst_off, src, n);
  }
  it->second = false;  // dirtied; requires re-erase before release/reuse
  metrics_.copied_bytes += n;
}

IManagedAllocator::Metrics ManagedAllocatorImpl::GetMetrics() const {
  return metrics_;
}

void ManagedAllocatorImpl::Crash() {
  // Live set survives: a crash does not hide leaks.
}

void ManagedAllocatorImpl::Quiesce() {}

void ManagedAllocatorImpl::SetFailurePlan(std::vector<uint64_t> seqs) {
  fail_seqs_.clear();
  for (auto s : seqs) fail_seqs_.insert(s);
}

uint64_t LeaseTrackerImpl::Admit(const std::vector<std::string>& object_ids) {
  uint64_t l = next_++;
  leases_[l] = object_ids;
  return l;
}

void LeaseTrackerImpl::ReleaseLease(uint64_t lease) { leases_.erase(lease); }

void LeaseTrackerImpl::Crash() { leases_.clear(); }

std::set<std::string> LeaseTrackerImpl::Protected() const {
  std::set<std::string> out;
  for (auto& [_, ids] : leases_)
    for (auto& id : ids) out.insert(id);
  return out;
}

}  // namespace efs
