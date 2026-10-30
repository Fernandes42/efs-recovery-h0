// efs_harness (wrapper-owned, NOT part of the pinned authoring tree).
//
// Grade entry for the Harbor separate-verifier container. Links ONLY
// verifier-owned objects (trusted oracle, reference, grader suites,
// sealed transport/dispatch). Submitted candidate code is NEVER linked
// here: it enters solely as two source files copied into the staging
// input, compiled into a sandboxed child image by the vetted
// StageAndBuild path, and driven over RPC. The H0 matrix runs
// verifier-side; the verdict below comes from verifier-owned counters
// and the grader-written evidence JSON -- never from candidate stdout.
//
// argv: <vendor_root> <submitted_h> <submitted_cpp> <profile>
//       <budgets> <work_root> <verdict_file>
// Exits 0 on PASS, 1 on FAIL (graded, not strict), 2 on INFRA.
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "grader/grader.h"
#include "grader/sealed_run.h"

namespace {

int WriteVerdict(const std::string& path, const std::string& verdict,
                 const std::string& detail, long checks, long failed) {
  // Owner root, group/other none: the sandboxed candidate image runs
  // unprivileged and must not rewrite its own grade.
  std::string tmp = path + ".tmp";
  {
    std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
    if (!o) return 2;
    o << "EFS_VERDICT=" << verdict << "\nEFS_DETAIL=" << detail
      << "\nEFS_CHECKS=" << checks << "\nEFS_FAILED=" << failed << "\n";
    if (!o) return 2;
  }
  if (chmod(tmp.c_str(), 0600) != 0) return 2;
  if (rename(tmp.c_str(), path.c_str()) != 0) return 2;
  return 0;
}

bool CopyFile(const std::string& src, const std::string& dst) {
  std::ifstream in(src, std::ios::binary);
  if (!in) return false;
  std::ofstream o(dst, std::ios::binary | std::ios::trunc);
  if (!o) return false;
  o << in.rdbuf();
  return (bool)o;
}

// Strict evidence parse: exact verdict string, finite integer case
// accounting, per-suite failure scan. Anything unparseable is INFRA,
// never an inferred PASS.
bool ParseEvidence(const std::string& path, std::string& verdict, long& checks,
                   long& failed) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  std::ostringstream o;
  o << f.rdbuf();
  grader::Json root;
  try {
    root = grader::Json::Parse(o.str());
  } catch (...) {
    return false;
  }
  auto want_str = [&](const char* k, std::string& out) {
    auto it = root.obj.find(k);
    if (it == root.obj.end() || it->second.t != grader::Json::T::STR)
      return false;
    out = it->second.str;
    return true;
  };
  auto want_int = [&](const char* k, long& out) {
    auto it = root.obj.find(k);
    if (it == root.obj.end() || it->second.t != grader::Json::T::NUM)
      return false;
    double v = it->second.num;
    if (!(v >= 0 && v <= 1000000000.0 && v == (double)(long)v)) return false;
    out = (long)v;
    return true;
  };
  std::string v;
  if (!want_str("verdict", v)) return false;
  if (!want_int("checks", checks)) return false;
  if (!want_int("failed", failed)) return false;
  verdict = v;
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 8) {
    std::fprintf(stderr, "usage: efs_harness <vendor> <sub_h> <sub_cpp> "
                         "<profile> <budgets> <work> <verdict>\n");
    return 2;
  }
  std::string vendor = argv[1], sub_h = argv[2], sub_cpp = argv[3];
  std::string profile_path = argv[4], budgets_path = argv[5];
  std::string work = argv[6], verdict_file = argv[7];
  auto infra = [&](const std::string& detail) {
    WriteVerdict(verdict_file, "INFRA", detail, 0, 0);
    std::fprintf(stderr, "efs_harness INFRA: %s\n", detail.c_str());
    return 2;
  };
  // All relative paths below (manifest, sealed staging ".", adv doubles)
  // resolve against the vendor root, exactly like the host grader.
  if (chdir(vendor.c_str()) != 0) return infra("chdir-vendor");
  // The two submitted files overwrite the vendored starter: impl files
  // are the designated untrusted input (exempt from every frozen gate
  // by design); everything else stays manifest-pinned.
  if (!CopyFile(sub_h, "candidate/src/efs_impl.h")) return infra("copy-sub-h");
  if (!CopyFile(sub_cpp, "candidate/src/efs_impl.cpp"))
    return infra("copy-sub-cpp");
  grader::Profile profile;
  try {
    profile = grader::Profile::Load(profile_path);
  } catch (const std::exception& e) {
    return infra("profile-load");
  }
  // RunMatrix opens evidence_dir/evidence_*.json without creating the
  // directory: pre-create it (root-owned; the sandboxed image never
  // sees this path -- it is outside the staging pivot).
  {
    std::string evdir = work + "/evidence";
    if (evdir.find('\'') != std::string::npos) return infra("bad-workdir");
    std::string mk = "mkdir -p '" + evdir + "'";
    int mrc = system(mk.c_str());
    if (mrc != 0) return infra("mkdir-evidence");
  }
  int rc = grader::sealed_run::RunSealed(profile, "candidate", budgets_path,
                                         work + "/evidence");
  if (rc == 2) {
    // RunSealed reports its own infrastructure failure (sandbox refused,
    // build failure, spawn failure): honest INFRA, never a PASS.
    WriteVerdict(verdict_file, "INFRA", "sealed-infra", 0, 0);
    return 2;
  }
  std::string verdict;
  long checks = 0, failed = 0;
  std::string ev = work + "/evidence/evidence_" + profile.name +
                   "_sealed-candidate.json";
  if (!ParseEvidence(ev, verdict, checks, failed))
    return infra("evidence-unparseable");
  if (rc == 0 && verdict == "STRICT_SUCCESS" && failed == 0 &&
      checks >= 250) {
    WriteVerdict(verdict_file, "PASS", "strict-success", checks, failed);
    std::printf("efs_harness PASS checks=%ld\n", checks);
    return 0;
  }
  WriteVerdict(verdict_file, "FAIL", verdict, checks, failed);
  std::printf("efs_harness FAIL verdict=%s checks=%ld failed=%ld\n",
              verdict.c_str(), checks, failed);
  return 1;
}
