// Grader entry point: flags, then in-process matrix, sealed mode, or
// budget derivation.
#include <cstdio>
#include <string>

#include "candidate/src/efs_impl.h"
#include "grader/grader.h"
#include "grader/runner.h"
#include "grader/sealed_run.h"
#include "grader/suites.h"
#include "reference/efs_impl.h"

int main(int argc, char** argv) {
  std::string profile_path, budgets_path, factory_name = "candidate";
  std::string evidence_dir, derive_path;
  bool sealed = false;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    std::string key;
    std::string value;
    auto eq = a.find('=');
    if (a.rfind("--", 0) == 0 && eq != std::string::npos) {
      key = a.substr(2, eq - 2);
      value = a.substr(eq + 1);
    } else if (a.rfind("--", 0) == 0 && a.substr(2) == "sealed") {
      sealed = true;
      continue;
    } else if (a.rfind("--", 0) == 0 && i + 1 < argc) {
      key = a.substr(2);
      value = argv[++i];
    } else {
      continue;
    }
    if (key == "profile") profile_path = value;
    if (key == "budgets") budgets_path = value;
    if (key == "factory") factory_name = value;
    if (key == "evidence-dir") evidence_dir = value;
    if (key == "derive-budgets") derive_path = value;
  }

  grader::Profile profile = grader::Profile::H0();
  if (!profile_path.empty()) {
    try {
      profile = grader::Profile::Load(profile_path);
    } catch (const std::exception& e) {
      std::printf("grader: cannot load profile: %s\n", e.what());
      return 2;
    }
  }

  if (sealed) {
    return grader::sealed_run::RunSealed(profile, factory_name,
                                         budgets_path, evidence_dir);
  }

  efs::reference::Factory ref_factory;
  efs::candidate::Factory cand_factory;
  efs::IDriverFactory* factory =
      (factory_name == "reference") ? (efs::IDriverFactory*)&ref_factory
                                    : (efs::IDriverFactory*)&cand_factory;

  if (!derive_path.empty()) {
    efs::IManagedAllocator::Metrics m;
    bool completed =
        grader::suites::RunBudgetWorkload(ref_factory, profile, m);
    grader::Budgets b = grader::suites::DeriveBudgets(m);
    b.Save(derive_path);
    std::printf(
        "budgets derived to %s: allocs=%llu copied=%llu peak=%llu "
        "(ref allocs=%llu copied=%llu peak=%llu live=%llu violations=%llu "
        "completed=%d)\n",
        derive_path.c_str(), (unsigned long long)b.max_alloc_count,
        (unsigned long long)b.max_copied_bytes,
        (unsigned long long)b.max_peak_managed,
        (unsigned long long)m.alloc_count,
        (unsigned long long)m.copied_bytes,
        (unsigned long long)m.peak_managed,
        (unsigned long long)m.live_managed,
        (unsigned long long)m.erasure_violations, completed ? 1 : 0);
    return (completed && m.erasure_violations == 0 && m.live_buffers == 0)
               ? 0
               : 1;
  }

  grader::Budgets budgets;
  const grader::Budgets* budgets_ptr = nullptr;
  if (!budgets_path.empty()) {
    try {
      budgets = grader::Budgets::Load(budgets_path);
      budgets_ptr = &budgets;
    } catch (const std::exception& e) {
      std::printf("grader: cannot load budgets: %s\n", e.what());
      return 2;
    }
  }

  return grader::RunMatrix(*factory, profile, budgets_ptr, factory_name,
                           evidence_dir);
}
