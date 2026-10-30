#pragma once
// Sealed evaluation runner (release gate 2): stages the allowlisted
// candidate image, rebuilds it with the fixed recipe, runs the full
// matrix across the process split, then executes the adversarial set.
// Verifier-owned; never ships in the candidate image.
#include <string>

#include "grader/grader.h"

namespace grader {
namespace sealed_run {

// Runs sealed matrix + adversarial set. Returns 0 only if everything
// passes (matrix strict success AND all adversarial contained).
int RunSealed(const Profile& profile, const std::string& factory_name,
              const std::string& budgets_path,
              const std::string& evidence_dir);

}  // namespace sealed_run
}  // namespace grader
