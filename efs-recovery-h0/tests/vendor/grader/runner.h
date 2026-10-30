#pragma once
// Shared matrix runner (in-process and sealed modes).
#include <string>

#include "efs/driver.h"
#include "grader/grader.h"

namespace grader {

// Runs the full suite matrix against factory; writes evidence when
// evidence_dir is non-empty (tag used in the file name). Returns 0 on
// strict success, 1 otherwise.
int RunMatrix(efs::IDriverFactory& factory, const Profile& profile,
              const Budgets* budgets, const std::string& factory_name,
              const std::string& evidence_dir);

}  // namespace grader
