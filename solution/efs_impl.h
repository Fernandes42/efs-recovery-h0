#pragma once
// Correct reference implementation (authoring/verifier only).
// Never exposed to the evaluated agent.
#include "efs/driver.h"

namespace efs::candidate {

class Factory : public IDriverFactory {
 public:
  IDriver* OpenHandle(uint32_t tenant, IObjectStore* store, IAnchor* anchor,
                      ICryptoBroker* broker, IManagedAllocator* alloc,
                      ILeaseTracker* leases) override;
};

}  // namespace efs::candidate
