#pragma once
// Verifier-side driver stubs: present IDriver to the harness while the
// implementation runs in the candidate process. Built into the grader
// binary (verifier-owned).
#include "efs/driver.h"
#include "sealed/rpc.h"

namespace sealed {

class RemoteFactory;

class RemoteDriver : public efs::IDriver {
 public:
  RemoteDriver(Channel* ch, uint64_t h, RemoteFactory* factory)
      : ch_(ch), h_(h), factory_(factory) {}
  ~RemoteDriver() override;
  efs::Result<efs::ReadOut> Read(const efs::TenantCap& cap,
                                 const std::string& name, uint64_t offset,
                                 size_t length) override;
  efs::Result<void> Put(const efs::TenantCap& cap, uint64_t op_id,
                        const std::string& name,
                        const std::vector<uint8_t>& bytes) override;
  efs::Result<void> WriteRange(const efs::TenantCap& cap, uint64_t op_id,
                               const std::string& name, uint64_t offset,
                               const std::vector<uint8_t>& bytes) override;
  efs::Result<void> Truncate(const efs::TenantCap& cap, uint64_t op_id,
                             const std::string& name,
                             uint64_t new_length) override;
  efs::Result<void> Rename(const efs::TenantCap& cap, uint64_t op_id,
                           const std::string& from,
                           const std::string& to) override;
  efs::Result<void> Remove(const efs::TenantCap& cap, uint64_t op_id,
                           const std::string& name) override;
  efs::Err PutAsync(const efs::TenantCap& cap, uint64_t op_id,
                    const std::string& name,
                    const std::vector<uint8_t>& input) override;
  efs::Result<void> Await(uint64_t op_id) override;
  efs::Result<void> Cancel(uint64_t op_id) override;
  efs::Result<efs::SnapshotHandle> Snapshot(const efs::TenantCap& cap,
                                            uint64_t op_id) override;
  efs::Result<efs::ReadOut> ReadSnapshot(const efs::TenantCap& cap,
                                         efs::SnapshotHandle snap,
                                         const std::string& name,
                                         uint64_t offset,
                                         size_t length) override;
  efs::Result<void> ReleaseSnapshot(const efs::TenantCap& cap,
                                    efs::SnapshotHandle snap) override;
  efs::Result<void> BeginRotation(const efs::TenantCap& cap,
                                  uint64_t op_id) override;
  efs::Result<void> MigrateFile(const efs::TenantCap& cap, uint64_t op_id,
                                const std::string& name) override;
  efs::Result<void> FinishRotation(const efs::TenantCap& cap,
                                   uint64_t op_id) override;
  efs::Result<void> Recover() override;
  efs::Result<void> Collect() override;

 private:
  Channel* ch_;
  uint64_t h_;
  RemoteFactory* factory_;
};

struct SvcSet {
  efs::IObjectStore* store = nullptr;
  efs::IAnchor* anchor = nullptr;
  efs::ICryptoBroker* broker = nullptr;
  efs::IManagedAllocator* alloc = nullptr;
  efs::ILeaseTracker* leases = nullptr;
};

class RemoteFactory : public efs::IDriverFactory {
 public:
  explicit RemoteFactory(Channel* ch) : ch_(ch) {}
  efs::IDriver* OpenHandle(uint32_t tenant, efs::IObjectStore* store,
                           efs::IAnchor* anchor, efs::ICryptoBroker* broker,
                           efs::IManagedAllocator* alloc,
                           efs::ILeaseTracker* leases) override;
  // Pre-register a handle for adversarial drivers (bypasses D.open).
  void RegisterHandle(uint64_t h, uint32_t tenant, const SvcSet& svcs);
  // Revoke parent-side authorization for a handle and all its allocator
  // cookies. Called when the RemoteDriver is destroyed (World::Crash clears
  // handles for a new incarnation; World destruction clears all). Prevents
  // stale/dangling use across incarnations and use-after-free after the
  // owning TestWorld is destroyed. Never throws.
  void CloseHandle(uint64_t h) noexcept;
  // Serve candidate-issued service calls with tenant-scoped dispatch.
  // Must be called once per channel before running.
  void ServeServices();
  // For adversarial assertions: cookies currently live.
  size_t LiveHandles() const { return tenants_.size(); }

 private:
  Channel* ch_;
  std::map<uint64_t, uint32_t> tenants_;
  std::map<uint64_t, SvcSet> svcs_;
  std::map<uint64_t, std::vector<uint8_t>*> bufs_;
  std::map<uint64_t, uint64_t> buf_handle_;  // cookie -> owning handle
  std::map<std::vector<uint8_t>*, uint64_t> buf_ids_;
  uint64_t next_cookie_ = 1;
  uint64_t Cookie();
  uint32_t Ten(uint64_t h);
  SvcSet& Svcs(uint64_t h);
};

}  // namespace sealed
