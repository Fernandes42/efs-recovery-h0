#pragma once
// Faulty starter factory. Evaluated agent edits candidate/src/ only.
#include "efs/driver.h"

namespace efs::candidate {

class Factory : public IDriverFactory {
 public:
  IDriver* OpenHandle(uint32_t tenant, IObjectStore* store, IAnchor* anchor,
                      ICryptoBroker* broker, IManagedAllocator* alloc,
                      ILeaseTracker* leases) override;
};

}  // namespace efs::candidate
