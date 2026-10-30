// Shared matrix runner (see runner.h).
#include "grader/runner.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "grader/fmt.h"
#include "grader/oracle.h"
#include "grader/suites.h"

namespace grader {
namespace {

struct SuiteRec {
  std::string name;
  std::string category;
  Counts counts;
  std::string error;
};

void RunSuite(SuiteRec& rec, efs::IDriverFactory& factory,
              const Profile& profile, const Budgets* budgets,
              void (*fn)(efs::IDriverFactory&, const Profile&, Counts&)) {
  try {
    fn(factory, profile, rec.counts);
  } catch (const efs::SimulatedCrash&) {
    rec.error = "harness-integrity: armed crash point escaped the harness";
    rec.counts.Check(false, rec.error);
  } catch (const std::exception& e) {
    rec.error = std::string("infrastructure: ") + e.what();
    rec.counts.Check(false, rec.error);
  } catch (...) {
    rec.error = "infrastructure: unknown exception";
    rec.counts.Check(false, rec.error);
  }
}

void RunLeakage(SuiteRec& rec, efs::IDriverFactory& factory,
                const Profile& profile, const Budgets* budgets) {
  try {
    efs::IManagedAllocator::Metrics m;
    suites::SuiteLeakage(factory, profile, budgets, rec.counts, &m);
    char b[256];
    std::snprintf(b, sizeof b,
                  "metrics allocs=%llu copied=%llu peak=%llu live=%llu "
                  "violations=%llu",
                  (unsigned long long)m.alloc_count,
                  (unsigned long long)m.copied_bytes,
                  (unsigned long long)m.peak_managed,
                  (unsigned long long)m.live_managed,
                  (unsigned long long)m.erasure_violations);
    rec.error = b;
  } catch (const std::exception& e) {
    rec.error = std::string("infrastructure: ") + e.what();
    rec.counts.Check(false, rec.error);
  }
}

}  // namespace

int RunMatrix(efs::IDriverFactory& factory, const Profile& profile,
              const Budgets* budgets, const std::string& factory_name,
              const std::string& evidence_dir) {
  std::vector<SuiteRec> recs = {
      {"format-parser", "harness-integrity"},
      {"oracle", "harness-integrity"},
      {"oracle-rejection", "security"},
      {"ordinary", "functional"},
      {"crash-sweep", "functional"},
      {"repeated-recovery", "functional"},
      {"async-memory", "functional"},
      {"nonce-lifecycle", "security"},
      {"rotation-snapshot-gc", "functional"},
      {"binding-corruption", "security"},
      {"replay-freshness", "security"},
      {"failure-handling", "functional"},
      {"leakage-resources", "performance-bound"},
      {"anti-cheat", "security"},
  };

  {
    Counts c;
    fmt::SelfTest(c);
    recs[0].counts = c;
    if (c.failed) recs[0].counts.first_failure = c.first_failure;
  }
  {
    Counts c;
    oracle::SelfTest(c);
    recs[1].counts = c;
  }
  RunSuite(recs[2], factory, profile, budgets, suites::SuiteOracleRejection);
  RunSuite(recs[3], factory, profile, budgets, suites::SuiteOrdinary);
  RunSuite(recs[4], factory, profile, budgets, suites::SuiteCrash);
  RunSuite(recs[5], factory, profile, budgets, suites::SuiteRepeatedRecovery);
  RunSuite(recs[6], factory, profile, budgets, suites::SuiteAsync);
  RunSuite(recs[7], factory, profile, budgets, suites::SuiteNonce);
  RunSuite(recs[8], factory, profile, budgets, suites::SuiteRotation);
  RunSuite(recs[9], factory, profile, budgets, suites::SuiteBinding);
  RunSuite(recs[10], factory, profile, budgets, suites::SuiteReplay);
  RunSuite(recs[11], factory, profile, budgets, suites::SuiteFailures);
  RunLeakage(recs[12], factory, profile, budgets);
  RunSuite(recs[13], factory, profile, budgets, suites::SuiteAntiCheat);

  int total_failed = 0, total_checks = 0;
  std::string first_suite, first_reason, first_category;
  for (auto& r : recs) {
    total_failed += r.counts.failed;
    total_checks += r.counts.checks;
    std::printf("%-22s checks=%-4d failed=%-4d %s%s\n", r.name.c_str(),
                r.counts.checks, r.counts.failed,
                r.counts.first_failure.c_str(),
                r.name == "leakage-resources" && !r.error.empty()
                    ? (" [" + r.error + "]").c_str()
                    : (r.error.empty() ? "" : (" [" + r.error + "]").c_str()));
    if (r.counts.failed > 0 && first_suite.empty()) {
      first_suite = r.name;
      first_reason = r.counts.first_failure.empty() ? r.error
                                                   : r.counts.first_failure;
      first_category = r.category;
    }
  }

  std::string verdict =
      total_failed == 0 ? "STRICT_SUCCESS" : "FAIL:" + first_category;
  std::printf("profile=%s factory=%s verdict=%s checks=%d failed=%d\n",
              profile.name.c_str(), factory_name.c_str(), verdict.c_str(),
              total_checks, total_failed);
  if (!first_suite.empty())
    std::printf("first violation: [%s] %s\n", first_suite.c_str(),
                first_reason.c_str());

  if (!evidence_dir.empty()) {
    Json root;
    root.t = Json::T::OBJ;
    auto str = [](const std::string& s) {
      Json j;
      j.t = Json::T::STR;
      j.str = s;
      return j;
    };
    auto num = [](double v) {
      Json j;
      j.t = Json::T::NUM;
      j.num = v;
      return j;
    };
    root.obj["profile"] = str(profile.name);
    root.obj["factory"] = str(factory_name);
    root.obj["verdict"] = str(verdict);
    root.obj["checks"] = num(total_checks);
    root.obj["failed"] = num(total_failed);
    Json suites;
    suites.t = Json::T::ARR;
    for (auto& r : recs) {
      Json e;
      e.t = Json::T::OBJ;
      e.obj["name"] = str(r.name);
      e.obj["category"] = str(r.category);
      e.obj["checks"] = num(r.counts.checks);
      e.obj["failed"] = num(r.counts.failed);
      e.obj["first_failure"] = str(r.counts.first_failure);
      suites.arr.push_back(e);
    }
    root.obj["suites"] = suites;
    std::string path = evidence_dir + "/evidence_" + profile.name + "_" +
                       factory_name + ".json";
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f << root.Dump() << "\n";
    std::printf("evidence: %s\n", path.c_str());
  }

  return total_failed == 0 ? 0 : 1;
}

}  // namespace grader
