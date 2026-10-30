#pragma once
// Deterministic crash-point injection, armed by the verifier-owned fault
// schedule and fired inside trusted-service calls by throwing
// SimulatedCrash. The candidate build sees this header (it must compile
// against the same World type in the in-process prototype), but any
// candidate use of the arming calls outside the harness protocol is
// tampering: an armed-but-unfired crash point is recorded by the harness
// as a harness-integrity failure attributed to the candidate. In the
// sealed packaging the candidate runs in a separate process whose image
// excludes the plan entirely.
#include <cstddef>

namespace efs {

struct SimulatedCrash {};

struct FaultPlan {
  int crash_after_nth_data_flush = -1;  // 0-based count of b_* Flush calls
  int data_flush_count = 0;
  bool crash_after_manifest_flush = false;
  bool crash_after_publish = false;
  void Reset() {
    crash_after_nth_data_flush = -1;
    data_flush_count = 0;
    crash_after_manifest_flush = false;
    crash_after_publish = false;
  }
};

}  // namespace efs
