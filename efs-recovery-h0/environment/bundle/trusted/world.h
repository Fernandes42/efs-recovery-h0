#pragma once
// Redacted world header for the calibration candidate view.
// Same class layout as the verifier's trusted/world.h (no virtuals;
// FaultPlan is already candidate-visible in efs/faults.h), but the
// verifier-owned surface is absent: no admin accessors, no durable
// image replay, no lease internals. Public tests use only
// construction, Open, Crash, crash-point arming, and incarnation.
// Any agent code reaching beyond this fails to compile — the boundary
// working as designed. Implemented by the prebuilt trusted library;
// no trusted sources ship in this bundle.
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "efs/driver.h"
#include "efs/faults.h"
#include "efs/services.h"

namespace efs {

class World {
 public:
  World();
  IDriver* Open(uint32_t tenant, IDriverFactory* factory);
  void Crash();

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
