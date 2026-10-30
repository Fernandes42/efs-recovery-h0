#pragma once
// Independent verifier: format parser, oracle, suites (grader-owned).
// The grader links the candidate only through IDriverFactory; verdicts
// come from verifier-owned observations (anchor transitions, broker
// audit, allocator metrics, durable image), never candidate assertions.
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "efs/driver.h"
#include "efs/errors.h"
#include "trusted/world.h"

namespace grader {

struct Counts {
  int checks = 0;
  int failed = 0;
  std::string first_failure;
  void Check(bool cond, const std::string& what) {
    ++checks;
    if (!cond) {
      ++failed;
      if (first_failure.empty()) first_failure = what;
    }
  }
};

// ---- minimal JSON (profiles + budgets + evidence; author-controlled) ----
struct Json {
  enum class T { NUL, NUM, STR, ARR, OBJ } t = T::NUL;
  double num = 0;
  std::string str;
  std::vector<Json> arr;
  std::map<std::string, Json> obj;
  static Json Parse(const std::string& s);
  std::string Dump() const;
};

struct Profile {
  std::string name;
  int writers = 1;
  int readers = 1;
  int async_in_flight = 2;
  int epochs = 1;
  bool snapshots = true;
  bool gc = true;
  bool range_ops = true;
  bool rotation = true;
  bool multi_crash = true;
  bool replay = true;
  bool revocation = true;
  bool outage = true;
  std::vector<size_t> workload_bytes;
  std::vector<uint64_t> seeds;
  static Profile Load(const std::string& path);
  static Profile H0();
};

// Frozen budget manifest (section 6 rule applied to reference measures).
struct Budgets {
  uint64_t max_alloc_count = 0;
  uint64_t max_copied_bytes = 0;
  uint64_t max_peak_managed = 0;
  uint64_t max_live_after_quiescence = 0;
  static Budgets Load(const std::string& path);
  void Save(const std::string& path) const;
};

std::vector<uint8_t> Pattern(size_t n, uint64_t seed = 0xA5);
inline efs::TenantCap Cap(uint32_t t) {
  return efs::TenantCap{t, efs::CapSecretFor(t)};
}

// A test world bundles a World with per-tenant handles from one factory.
struct TestWorld {
  efs::World world;
  efs::IDriverFactory* factory = nullptr;
  uint64_t next_op = 1;
  efs::IDriver* Open(uint32_t tenant) {
    return world.Open(tenant, factory);
  }
  uint64_t Op() { return next_op++; }
};

int RunAll(efs::IDriverFactory& factory, const Profile& profile,
           const Budgets* budgets, const std::string& evidence_path,
           bool derive_budgets, const std::string& budgets_out);

}  // namespace grader
