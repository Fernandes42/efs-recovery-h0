#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "efs/driver.h"
#include "efs/faults.h"
#include "efs/hash.h"
#include "efs/services.h"
#include "trusted/admin.h"

namespace efs {

// Deterministic world: owns all trusted services + lease tracker.
// The harness drives crashes, replay, revocation through this object.
// Drivers receive only the narrow base interfaces; the harness uses the
// admin accessors below (never handed to candidate code).
class World {
 public:
  World();
  IObjectStore* store() { return store_.get(); }
  IAnchor* anchor() { return anchor_.get(); }
  ICryptoBroker* broker() { return broker_.get(); }
  IManagedAllocator* alloc() { return alloc_.get(); }
  ILeaseTracker* leases() { return leases_.get(); }

  IAdminStore* admin_store() {
    return static_cast<IAdminStore*>(store_.get());
  }
  IAdminAnchor* admin_anchor() {
    return static_cast<IAdminAnchor*>(anchor_.get());
  }
  IAdminBroker* admin_broker() {
    return static_cast<IAdminBroker*>(broker_.get());
  }
  IAdminAlloc* admin_alloc() {
    return static_cast<IAdminAlloc*>(alloc_.get());
  }

  // Open one handle per tenant via the given factory.
  IDriver* Open(uint32_t tenant, IDriverFactory* factory);
  // Simulate a process crash: discard staged objects + volatile handle
  // state; durable services survive; incarnation leases are stopped.
  void Crash();
  // Whole-image replay probe support (verifier-owned).
  std::map<std::string, std::vector<uint8_t>> Image() const;
  void SetImage(std::map<std::string, std::vector<uint8_t>> img);

  // Crash-point arming (verifier-owned fault schedule). The data
  // counter resets at arm time, so nth counts flushes of the next op.
  void ArmCrashAfterDataFlush(int nth) {
    plan_.crash_after_nth_data_flush = nth;
    plan_.data_flush_count = 0;
  }
  void ArmCrashAfterManifestFlush() {
    plan_.crash_after_manifest_flush = true;
  }
  void ArmCrashAfterPublish() { plan_.crash_after_publish = true; }
  void DisarmCrashPoints() { plan_.Reset(); }

  uint64_t incarnation() const { return incarnation_; }

 private:
  FaultPlan plan_;
  std::unique_ptr<IObjectStore> store_;
  std::unique_ptr<IAnchor> anchor_;
  std::unique_ptr<ICryptoBroker> broker_;
  std::unique_ptr<IManagedAllocator> alloc_;
  std::unique_ptr<ILeaseTracker> leases_;
  std::map<uint32_t, std::unique_ptr<IDriver>> handles_;
  uint64_t incarnation_ = 1;
};

}  // namespace efs

