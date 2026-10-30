#pragma once
// Grader suite declarations (all suites share Counts/Profile).
#include "grader/grader.h"
#include "grader/oracle.h"

namespace grader {
namespace suites {

bool FailClosed(efs::Err e);
void CheckTenant(Counts& c, TestWorld& tw, uint32_t tenant,
                 oracle::LogicalModel& model, const std::string& where);

void SuiteOrdinary(efs::IDriverFactory& factory, const Profile& p,
                   Counts& c);
void SuiteCrash(efs::IDriverFactory& factory, const Profile& p, Counts& c);
void SuiteRepeatedRecovery(efs::IDriverFactory& factory, const Profile& p,
                           Counts& c);
void SuiteAsync(efs::IDriverFactory& factory, const Profile& p, Counts& c);
void SuiteNonce(efs::IDriverFactory& factory, const Profile& p, Counts& c);
void SuiteRotation(efs::IDriverFactory& factory, const Profile& p,
                   Counts& c);
void SuiteBinding(efs::IDriverFactory& factory, const Profile& p,
                  Counts& c);
void SuiteReplay(efs::IDriverFactory& factory, const Profile& p, Counts& c);
void SuiteFailures(efs::IDriverFactory& factory, const Profile& p,
                   Counts& c);
void SuiteAntiCheat(efs::IDriverFactory& factory, const Profile& p,
                    Counts& c);
void SuiteOracleRejection(efs::IDriverFactory& factory, const Profile& p,
                          Counts& c);

// Degenerate mock drivers (defined in suites3.cpp).
efs::IDriver* MakeRejectAll();
efs::IDriver* MakeFakeAck();
class MockFactory : public efs::IDriverFactory {
 public:
  using Maker = efs::IDriver* (*)();
  explicit MockFactory(Maker m) : m_(m) {}
  efs::IDriver* OpenHandle(uint32_t, efs::IObjectStore*, efs::IAnchor*,
                           efs::ICryptoBroker*, efs::IManagedAllocator*,
                           efs::ILeaseTracker*) override {
    return m_();  // heap object; World takes ownership
  }

 private:
  Maker m_;
};

void SuiteLeakage(efs::IDriverFactory& factory, const Profile& p,
                  const Budgets* budgets, Counts& c,
                  efs::IManagedAllocator::Metrics* observed);
Budgets DeriveBudgets(const efs::IManagedAllocator::Metrics& ref);
// Runs the fixed budget workload. Returns true only if every valid
// operation succeeded and Collect succeeded; a valid op failing is a
// workload failure, not a silent early stop (metrics from a truncated
// workload must not pass budgets trivially).
bool RunBudgetWorkload(efs::IDriverFactory& factory, const Profile& p,
                       efs::IManagedAllocator::Metrics& out);

}  // namespace suites
}  // namespace grader
