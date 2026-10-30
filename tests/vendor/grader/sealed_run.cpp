// Sealed evaluation runner (see sealed_run.h).
#include "grader/sealed_run.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

#include "candidate/src/efs_impl.h"
#include "grader/fmt.h"
#include "grader/oracle.h"
#include "grader/runner.h"
#include "grader/suites.h"
#include "reference/efs_impl.h"
#include "sealed/driver_stub.h"
#include "sealed/rpc.h"
#include "sealed/sandbox.h"
#include "trusted/admin.h"
#include "trusted/world.h"

namespace grader {
namespace sealed_run {
namespace {

std::string ShellQuote(const std::string& s) {
  std::string o = "'";
  for (char ch : s) {
    if (ch == '\'') o += "'\\''";
    else o += ch;
  }
  return o + "'";
}

int RunCmd(const std::string& cmd, std::string* out = nullptr) {
  std::string full = cmd + " 2>&1";
  FILE* p = popen(full.c_str(), "r");
  if (!p) return 127;
  char buf[4096];
  std::string acc;
  while (fgets(buf, sizeof buf, p)) acc += buf;
  int rc = pclose(p);
  if (out) *out = acc;
  return WIFEXITED(rc) ? WEXITSTATUS(rc) : 128;
}

void CopyFile(const std::string& src, const std::string& dst) {
  std::ifstream in(src, std::ios::binary);
  if (!in) throw std::runtime_error("stage missing " + src);
  std::string dir = dst.substr(0, dst.find_last_of('/'));
  RunCmd("mkdir -p " + ShellQuote(dir));
  std::ofstream o(dst, std::ios::binary | std::ios::trunc);
  o << in.rdbuf();
  if (!o) throw std::runtime_error("stage write failed " + dst);
}

// Manifest-pinned hash check for staged build inputs. Parses
// packaging/source_manifest.json with the grader's own Json parser and
// compares SHA-256 (OpenSSL) of every staged verifier file. The two
// submission impl files are exempt (untrusted input by design).
void VerifyStaged(const std::string& staging, const std::string& factory) {
  (void)factory;
  std::string mpath = "packaging/source_manifest.json";
  std::ifstream mf(mpath, std::ios::binary);
  if (!mf) throw std::runtime_error("stage: cannot read " + mpath);
  std::ostringstream mo;
  mo << mf.rdbuf();
  Json manifest = Json::Parse(mo.str());
  auto fit = manifest.obj.find("files");
  if (fit == manifest.obj.end() || fit->second.t != Json::T::ARR)
    throw std::runtime_error("stage: bad manifest");
  for (auto& e : fit->second.arr) {
    auto pit = e.obj.find("path");
    auto hit = e.obj.find("sha256");
    if (pit == e.obj.end() || hit == e.obj.end()) continue;
    const std::string& p = pit->second.str;
    if (p == "candidate/src/efs_impl.h" || p == "candidate/src/efs_impl.cpp")
      continue;  // untrusted submission input
    std::string sp = staging + "/" + p;
    std::ifstream f(sp, std::ios::binary);
    if (!f) continue;  // not staged (grader-only/report file); skip
    std::ostringstream o;
    o << f.rdbuf();
    std::string bytes = o.str();
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(),
           digest);
    char hex[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
      std::snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    if (hit->second.str != hex)
      throw std::runtime_error("stage: frozen-input mismatch: " + p);
  }
}

std::vector<std::string> Allowlist(const std::string& factory) {  std::vector<std::string> files = {
      "include/efs/errors.h", "include/efs/types.h",
      "include/efs/services.h", "include/efs/driver.h",
      "include/efs/faults.h", "include/efs/hash.h",
      "sealed/rpc.h", "sealed/rpc.cpp",
      "sealed/service_proxy.h", "sealed/service_proxy.cpp",
      "sealed/sha256.h", "sealed/sha256.cpp", "sealed/sha256_efs.cpp",
      "sealed/candidate_main.cpp",
  };
  if (factory == "reference") {
    files.push_back("reference/efs_impl.h");
    files.push_back("reference/efs_impl.cpp");
  } else {
    files.push_back("candidate/src/efs_impl.h");
    files.push_back("candidate/src/efs_impl.cpp");
  }
  return files;
}

// Stage allowlisted sources from src_root, verify them against the
// pinned manifest, and rebuild with the fixed recipe. Returns the
// staging dir (binary at <staging>/image). Only the submission impl
// files are exempt from the hash check (they are the untrusted input;
// everything else must be bit-identical to the frozen verifier tree).
std::string StageAndBuild(const std::string& src_root,
                          const std::string& factory,
                          const std::string& workdir) {
  std::string staging = workdir + "/stage-" + factory;
  RunCmd("rm -rf " + ShellQuote(staging));
  RunCmd("mkdir -p " + ShellQuote(staging));
  auto files = Allowlist(factory);
  for (auto& f : files) CopyFile(src_root + "/" + f, staging + "/" + f);
  VerifyStaged(staging, factory);
  std::string impl = (factory == "reference") ? "reference/efs_impl.cpp"
                                              : "candidate/src/efs_impl.cpp";
  // Diagnostic builds (e.g. sanitizers) can instrument the image via
  // EFS_SEALED_CXXFLAGS. The recipe stays fixed otherwise: same sources,
  // same defines, no operator-controlled include paths or libraries.
  std::string extra;
  if (const char* e = getenv("EFS_SEALED_CXXFLAGS")) extra = " " + std::string(e);
  // Parse/compile submitted text under a separate, bounded identity. Hidden
  // /tests and the root-private grading scratch are inaccessible to it.
  const std::string compile = staging + "/compile";
  if (RunCmd("mkdir -p " + ShellQuote(compile) +
      " && chown 60002:60002 " + ShellQuote(compile) +
      " && chmod 0700 " + ShellQuote(compile)) != 0)
    throw std::runtime_error("sealed compiler workspace setup failed");
  std::string cmd = "cd " + ShellQuote(staging) +
      " && /usr/bin/timeout 60 /usr/bin/prlimit --cpu=45 --as=2147483648 "
      "--fsize=67108864 --nproc=64 --core=0 -- /usr/bin/env -i "
      "PATH=/usr/bin:/bin HOME=" + ShellQuote(compile) +
      " TMPDIR=" + ShellQuote(compile) +
      " /usr/bin/setpriv --reuid=60002 --regid=60002 --clear-groups "
      "--no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all "
      "/usr/bin/g++ -std=c++20 -O2" + extra + " -I " +
                    ShellQuote(staging + "/include") + " -I " +
                    ShellQuote(staging) + " " +
                    ShellQuote(staging + "/sealed/rpc.cpp") + " " +
                    ShellQuote(staging + "/sealed/sha256.cpp") + " " +
                    ShellQuote(staging + "/sealed/sha256_efs.cpp") + " " +
                    ShellQuote(staging + "/sealed/service_proxy.cpp") + " " +
                    ShellQuote(staging + "/sealed/candidate_main.cpp") + " " +
                    ShellQuote(staging + "/" + impl) + " -o " +
                    ShellQuote(compile + "/image") +
                    (factory == "reference" ? " -DUSE_REFERENCE" : "") +
                    extra;
  std::string log;
  if (RunCmd(cmd, &log) != 0)
    throw std::runtime_error("sealed build failed:\n" + log);
  if (RunCmd("mv " + ShellQuote(compile + "/image") + " " +
      ShellQuote(staging + "/image") + " && chown 0:0 " +
      ShellQuote(staging + "/image") + " && chmod 0555 " +
      ShellQuote(staging + "/image") + " && rm -rf " + ShellQuote(compile)) != 0)
    throw std::runtime_error("sealed executable protection failed");
  return staging;
}

void WaitChild(int pid, int secs, const std::string& what) {
  for (int i = 0; i < secs * 10; ++i) {
    int st = 0;
    int r = waitpid(pid, &st, WNOHANG);
    if (r == pid) {
      if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
        throw std::runtime_error(what + " exited " +
                                 std::to_string(WEXITSTATUS(st)));
      if (!WIFEXITED(st)) throw std::runtime_error(what + " killed");
      return;
    }
    usleep(100000);
  }
  // Timeout: SIGTERM first — the sandbox launcher forwards it to the
  // confined grandchild (which plain SIGKILL of the launcher alone
  // would orphan inside its PID namespace). Grace, then SIGKILL.
  kill(pid, SIGTERM);
  for (int i = 0; i < 20; ++i) {
    int st = 0;
    if (waitpid(pid, &st, WNOHANG) == pid) {
      throw std::runtime_error(what + " timeout (watchdog, termed)");
    }
    usleep(100000);
  }
  kill(pid, SIGKILL);
  waitpid(pid, nullptr, 0);
  throw std::runtime_error(what + " timeout (watchdog)");
}

std::string ReadFile(const std::string& p) {
  std::ifstream f(p, std::ios::binary);
  if (!f) throw std::runtime_error("cannot read " + p);
  std::ostringstream o;
  o << f.rdbuf();
  return o.str();
}

bool Contains(const std::string& hay, const std::string& needle) {
  return hay.find(needle) != std::string::npos;
}

// ---- adversarial 0: build-input substitution ----
bool AdvSubstitution(Counts& c, const std::string& workdir) {
  // Fake submission: legit sources plus decoys outside the allowlist
  // plus a backdoored-but-irrelevant extra header.
  std::string sub = workdir + "/evil-submission";
  RunCmd("rm -rf " + ShellQuote(sub));
  for (auto& f : Allowlist("candidate")) {
    if (f == "candidate/src/efs_impl.h" || f == "candidate/src/efs_impl.cpp")
      continue;  // keep real impl from repo below
    CopyFile(f, sub + "/" + f);
  }
  CopyFile("candidate/src/efs_impl.h", sub + "/candidate/src/efs_impl.h");
  CopyFile("candidate/src/efs_impl.cpp", sub + "/candidate/src/efs_impl.cpp");
  // Decoy: extra implementation file, fake trusted/, fake reference/.
  RunCmd("mkdir -p " + ShellQuote(sub + "/trusted") + " " +
         ShellQuote(sub + "/reference"));
  {
    std::ofstream o(sub + "/candidate/src/evil.cpp");
    o << "const char* kEvilMarker = \"EVIL_MARKER_9ZQ\";\n";
  }
  {
    std::ofstream o(sub + "/trusted/admin.h");
    o << "// decoy admin\n";
  }
  {
    std::ofstream o(sub + "/reference/efs_impl.cpp");
    o << "// decoy reference\n";
  }
  std::string staging;
  try {
    staging = StageAndBuild(sub, "candidate", workdir + "/evil");
  } catch (const std::exception& e) {
    c.Check(false, std::string("subst stage: ") + e.what());
    return false;
  }
  bool ok = true;
  auto check = [&](bool cond, const std::string& n) {
    c.Check(cond, "subst " + n);
    if (!cond && getenv("EFS_ADV_DEBUG"))
      std::printf("[adv-subst] FAIL %s\n", n.c_str());
    ok = ok && cond;
  };
  // Staged set must equal the allowlist exactly (both sorted: find
  // emits sorted paths, the allowlist is grouped by area).
  std::string listed;
  RunCmd("cd " + ShellQuote(staging) + " && find . -type f | LC_ALL=C sort",
           &listed);
  std::vector<std::string> want = {"./image"};
  for (auto& f : Allowlist("candidate")) want.push_back("./" + f);
  std::sort(want.begin(), want.end());
  std::string expect;
  for (auto& w : want) expect += w + "\n";
  check(listed == expect, "staged set == allowlist");
  if (listed != expect && getenv("EFS_ADV_DEBUG"))
    std::printf("[adv-subst] listed:\n%s[end]\nexpect:\n%s[end]\n",
                listed.c_str(), expect.c_str());
  // Evil marker must not reach the binary.
  std::string strings_out;
  RunCmd("strings " + ShellQuote(staging + "/image"), &strings_out);
  check(!Contains(strings_out, "EVIL_MARKER_9ZQ"), "evil absent from binary");
  // Re-staging wipes planted decoys.
  RunCmd("touch " + ShellQuote(staging + "/planted_decoy"));
  StageAndBuild(sub, "candidate", workdir + "/evil");
  std::string listed2;
  RunCmd("cd " + ShellQuote(staging) + " && find . -type f | LC_ALL=C sort",
           &listed2);
  check(listed2 == expect, "restage wipes decoys");
  (void)listed;
  return ok;
}

// ---- adversarial 1: read-boundary snooper ----
// Phase A (baseline, unsandboxed, repo cwd) demonstrates the threat:
// same-user absolute-path reads of reference/verifier/evidence
// material succeed, so the probes are efficacious. Phase B runs the
// identical double sandboxed (pivot_root into the candidate staging)
// and requires every such read to be denied.
bool AdvSnoop(Counts& c, const std::string& staging,
              const std::string& workdir, const std::string& repo) {
  const std::vector<std::string> kAbs = {
      "reference/efs_impl.h", "reference/efs_impl.cpp",
      "trusted/admin.h", "trusted/world.h", "trusted/impl.h",
      "trusted/crypto_broker.cpp", "grader/sealed_run.cpp",
      "grader/suites.h", "grader/suites_oracle.cpp",
      // NOTE (wrapper vendor tree): reports/evidence_*.json are
      // authoring evidence, deliberately NOT vendored (the verifier
      // image must not ship past verdicts an agent could read back
      // through a boundary failure). The snooper's Phase-A efficacy
      // gate needs paths that EXIST in the tree it probes, so the
      // evidence entries from the host list are replaced here by two
      // manifest-pinned oracle sources that must equally be denied.
      "trusted/allocator.cpp", "trusted/world.cpp", "profiles/H0.json",
      "profiles/budgets.json", "packaging/source_manifest.json",
      "candidate/src/efs_impl.cpp"};
  std::string bin = workdir + "/adv_snoop";
  std::string log;
  std::string cmd = "g++ -std=c++20 -O2 sealed/adv_snoop.cpp -o " +
                    ShellQuote(bin);
  if (RunCmd(cmd, &log) != 0) {
    c.Check(false, "snoop build: " + log);
    return false;
  }
  bool ok = true;
  auto check = [&](bool cond, const std::string& n) {
    c.Check(cond, "snoop " + n);
    ok = ok && cond;
  };
  // Phase A: baseline threat demonstration (unsandboxed).
  std::string base = workdir + "/snoop.base";
  RunCmd("rm -f " + ShellQuote(base));
  try {
    sealed::Spawned sp = sealed::SpawnChild(
        bin.c_str(), {staging, base, repo, "--baseline"}, nullptr);
    close(sp.fd);  // no channel traffic expected
    WaitChild(sp.pid, 20, "snoop-base");
  } catch (const std::exception& e) {
    c.Check(false, std::string("snoop base wait: ") + e.what());
    return false;
  }
  std::string bbody = ReadFile(base);
  for (auto& p : kAbs)
    check(Contains(bbody, "OPENED ABS " + repo + "/" + p),
          "base reads " + p);
  check(Contains(bbody, "OPENED CTL /etc/passwd"), "base ctl passwd");
  check(Contains(bbody, "OPENED CTL /etc/shadow"), "trusted-root base ctl shadow");
  check(Contains(bbody, "OPENED REL sealed/rpc.h"), "base ctl rel");
  // Phase B: sandboxed — the same reads must all fail.
  // High-fd marker: dup /dev/null onto fd 2000 before spawning. The old
  // fixed 1024-cap scrub would have leaked this into the sandbox; the
  // unbounded /proc/self/fd enumeration must close it. The snooper's
  // fds_extra=0 check below is the assertion.
  int marker = open("/dev/null", O_RDONLY);
  int highfd = -1;
  if (marker >= 0) {
    highfd = fcntl(marker, F_DUPFD, 2000);
    close(marker);
  }
  std::string result = staging + "/work/snoop.result";
  RunCmd("rm -f " + ShellQuote(result));
  try {
    sealed::Spawned sp = sealed::SpawnSandboxed(bin.c_str(), staging,
                                                {staging, result, repo});
    close(sp.fd);
    WaitChild(sp.pid, 20, "snoop");
  } catch (const std::exception& e) {
    if (highfd >= 0) close(highfd);
    c.Check(false, std::string("snoop wait: ") + e.what());
    return false;
  }
  if (highfd >= 0) close(highfd);
  std::string body = ReadFile(result);
  for (auto& p : kAbs)
    check(Contains(body, "denied ABS " + repo + "/" + p), "denied " + p);
  for (auto& p :
       {"reference/efs_impl.h", "reference/efs_impl.cpp",
        "trusted/admin.h", "trusted/world.h", "trusted/impl.h",
        "trusted/allocator.cpp", "trusted/world.cpp",
        "grader/sealed_run.cpp", "grader/suites.h",
        "profiles/H0.json", "profiles/budgets.json",
        "../reference", "../trusted",
        "../grader"})
    check(Contains(body, std::string("denied REL ") + p),
          std::string("denied view ") + p);
  // This candidate root exposes no procfs. The read/process/network
  // isolation outcome is enforced without requesting denied namespaces.
  for (auto& p : {"/proc/self/environ", "/proc/self/cmdline",
                  "/proc/self/maps", "/proc/self/fd", "/proc/net/tcp"})
    check(Contains(body, std::string("denied PROC ") + p),
          std::string("proc absent ") + p);
  check(!Contains(body, "OPENED PROC "), "no process visibility through proc");
  for (auto& probe : {"write_reward=denied", "read_tests=denied",
                      "fork=denied", "setsid=denied", "socket=denied"})
    check(Contains(body, probe), std::string("negative boundary ") + probe);
  check(Contains(body, "denied CTL /etc/passwd"), "denied ctl passwd");
  check(Contains(body, "denied CTL /etc/shadow"), "denied ctl shadow");
  // Positive control: staging-local reads still work, so denials mean
  // containment rather than a broken double.
  check(Contains(body, "OPENED REL sealed/rpc.h"), "control opens");
  check(Contains(body, "fds_extra=0"), "no inherited fds");
  // No procfs means no descriptor-target or network-table disclosure.
  // High descriptors are probed via fcntl, including the planted fd 2000.
  check(Contains(body, "net_tcp_lines=-1"), "no network-table visibility");
  check(Contains(body, "opened_total=1"), "only staging control opens");
  return ok;
}

// ---- adversarial 2: nonce reuse across the split ----
bool AdvReuse(Counts& c, const std::string& staging,
              const std::string& workdir) {
  std::string bin = workdir + "/adv_reuse";
  std::string log;
  std::string cmd =
      "g++ -std=c++20 -O2 -I . -I include sealed/adv_reuse.cpp "
      "sealed/rpc.cpp sealed/service_proxy.cpp -o " +
      ShellQuote(bin);
  if (RunCmd(cmd, &log) != 0) {
    c.Check(false, "reuse build: " + log);
    return false;
  }
  efs::World world;
  // Spawn first, then serve over the real channel.
  sealed::Spawned sp = sealed::SpawnSandboxed(
      bin.c_str(), staging, {staging, "77411", staging + "/work/reuse.result"});
  sealed::Channel chan(sp.fd);
  sealed::RemoteFactory rf(&chan);
  rf.ServeServices();
  sealed::SvcSet svcs{world.store(), world.anchor(), world.broker(),
                      world.alloc(), world.leases()};
  rf.RegisterHandle(77411, 0, svcs);
  bool ok = true;
  try {
    chan.Serve();  // pump until child exits
    WaitChild(sp.pid, 30, "reuse");
  } catch (const std::exception& e) {
    c.Check(false, std::string("reuse run: ") + e.what());
    return false;
  }
  std::string body = ReadFile(staging + "/work/reuse.result");
  bool s1 = Contains(body, "seal1=OK");
  bool s2 = Contains(body, "seal2=OK");
  bool open_fail = Contains(body, "open_reused=AUTHENTICATION_FAILED");
  c.Check(s1 && s2, "reuse seals recorded");
  c.Check(open_fail, "reuse fails verification across split");
  return s1 && s2 && open_fail;
}

// ---- adversarial 3: cross-tenant access ----
bool AdvXtenant(Counts& c, const std::string& staging,
                const std::string& workdir) {
  std::string bin = workdir + "/adv_xtenant";
  std::string log;
  std::string cmd =
      "g++ -std=c++20 -O2 -I . -I include sealed/adv_xtenant.cpp "
      "sealed/rpc.cpp sealed/service_proxy.cpp -o " +
      ShellQuote(bin);
  if (RunCmd(cmd, &log) != 0) {
    c.Check(false, "xtenant build: " + log);
    return false;
  }
  efs::World world;
  efs::reference::Factory rf_direct;
  efs::IDriver* d1 = world.Open(1, &rf_direct);
  efs::TenantCap c1{1, efs::CapSecretFor(1)};
  std::vector<uint8_t> victim_bytes(9000, 0x51);
  if (!d1->Put(c1, 9001, "victim", victim_bytes).ok()) {
    c.Check(false, "xtenant setup");
    return false;
  }
  uint64_t gen_before = world.anchor()->Get(1).generation;
  std::string victim;
  for (auto& [id, _] : world.Image())
    if (id.rfind("b_1_", 0) == 0) {
      victim = id;
      break;
    }
  if (victim.empty()) {
    c.Check(false, "xtenant victim id");
    return false;
  }
  std::string result = staging + "/work/xtenant.result";
  RunCmd("rm -f " + ShellQuote(result));
  sealed::Spawned sp = sealed::SpawnSandboxed(
      bin.c_str(), staging, {staging, "77522", victim, result});
  sealed::Channel chan(sp.fd);
  sealed::RemoteFactory rf(&chan);
  rf.ServeServices();
  sealed::SvcSet svcs{world.store(), world.anchor(), world.broker(),
                      world.alloc(), world.leases()};
  rf.RegisterHandle(77522, 0, svcs);
  bool ok = true;
  try {
    chan.Serve();
    WaitChild(sp.pid, 30, "xtenant");
  } catch (const std::exception& e) {
    c.Check(false, std::string("xtenant run: ") + e.what());
    return false;
  }
  std::string body = ReadFile(result);
  for (auto& probe :
       {"stage_t1", "flush_t1", "read_t1", "delete_t1", "anchor_t1",
        "publish_t1", "broker_t1", "pin_t1"}) {
    bool denied = Contains(body, std::string("rejected ") + probe);
    c.Check(denied, std::string("xtenant ") + probe);
    ok = ok && denied;
  }
  bool none_allowed = Contains(body, "allowed_total=0");
  c.Check(none_allowed, "xtenant none allowed");
  ok = ok && none_allowed;
  // Victim tenant intact (oracle-decrypt, not driver claims).
  oracle::LogicalModel model;
  model.Put("victim", victim_bytes);
  oracle::CommittedState st;
  std::string why;
  bool dec = oracle::DecryptCommitted(
      world.admin_store(), world.admin_anchor(), world.admin_broker(), 1,
      st, why);
  c.Check(dec, "xtenant victim decrypt: " + why);
  ok = ok && dec;
  if (dec) {
    bool eq = oracle::ModelEquals(model, st, why);
    c.Check(eq, "xtenant victim intact: " + why);
    ok = ok && eq;
  }
  bool gen_same = world.anchor()->Get(1).generation == gen_before;
  c.Check(gen_same, "xtenant anchor stable");
  return ok && gen_same;
}

// ---- adversarial 4: RPC/sandbox hardening ----
// Malformed argument shapes must fail closed (RemoteError), never read
// out of bounds; the whole-call deadline must fire on a slow drip.
bool AdvRpcHardening(Counts& c) {
  bool ok = true;
  auto check = [&](bool cond, const std::string& n) {
    c.Check(cond, "rpc " + n);
    ok = ok && cond;
  };
  auto throws_remote = [](auto fn) {
    try {
      fn();
    } catch (const sealed::RemoteError&) {
      return true;
    } catch (...) {
      return false;
    }
    return false;
  };
  sealed::J arr0 = sealed::J::Arr();  // empty args
  sealed::J arr1 = sealed::J::Arr();
  arr1.arr.push_back(sealed::J::Num(7));
  sealed::J strobj = sealed::J::Obj();
  check(throws_remote([&] { sealed::ArgU64(arr0, 0); }), "u64 oob");
  check(throws_remote([&] { sealed::ArgU32(arr1, 5); }), "u32 oob");
  check(throws_remote([&] { sealed::ArgStr(arr1, 0); }), "str mistype");
  check(throws_remote([&] { sealed::ArgBytes(arr1, 0); }), "bytes mistype");
  check(throws_remote([&] { sealed::ArgSize(strobj, 0); }), "size non-arr");
  check(throws_remote([&] { sealed::ArgArr(arr1, 0); }), "arr mistype");
  check(throws_remote([&] { sealed::RequireArgs(arr1, 2); }), "arity");
  check(throws_remote([&] { sealed::UnU64(sealed::J::Str("12x")); }),
        "u64 trailing");
  check(throws_remote([&] {
    sealed::J b = sealed::J::Obj();
    b.obj["$hex"] = sealed::J::Num(1);
    sealed::Unbytes(b);
  }), "bytes mistype2");
  check(throws_remote([&] {
    sealed::J r = sealed::J::Obj();
    sealed::UnU64(r);
  }), "u64 nul");
  // Wrong-typed u32 values (negative, fractional, huge) rejected.
  check(throws_remote([&] {
    sealed::J a = sealed::J::Arr();
    a.arr.push_back(sealed::J::Num(-1));
    sealed::ArgU32(a, 0);
  }), "u32 negative");
  check(throws_remote([&] {
    sealed::J a = sealed::J::Arr();
    a.arr.push_back(sealed::J::Num(1.5));
    sealed::ArgU32(a, 0);
  }), "u32 fractional");
  // Whole-call deadline: the peer's handler sleeps far beyond the
  // per-read timeout's patience... precisely: per-read is 30 s, the
  // call deadline 0.4 s. Only the deadline can stop this call. Without
  // it, a silent-but-connected peer hangs the grader until the
  // per-read timer (or never, under a drip that resets it).
  {
    int sv[2];
    bool deadline_ok = false;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
      {
        sealed::Channel ch(sv[0], 30000, 400 /* 0.4 s deadline */);
        std::thread peer([fd = sv[1]] {
          sealed::Channel pch(fd, 30000, 60000);
          pch.On("N.slow", [](const sealed::J&) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            return sealed::J::Obj();
          });
          try {
            pch.Serve();
          } catch (...) {
          }
        });
        auto t0 = std::chrono::steady_clock::now();
        try {
          sealed::J args = sealed::J::Arr();
          ch.Call("N", "slow", args);
        } catch (const sealed::TimeoutWire&) {
          auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
          deadline_ok = ms < 5000;  // must beat the 30 s read timeout
        } catch (...) {
        }
        // EOF the peer pump, then join. ch's dtor closes sv[0].
        shutdown(sv[0], SHUT_RDWR);
        peer.join();
      }
      close(sv[1]);
    }
    check(deadline_ok, "call deadline fires on silent peer");
  }
  return ok;
}

}  // namespace

int RunSealed(const Profile& profile, const std::string& factory_name,
              const std::string& budgets_path,
              const std::string& evidence_dir) {
  Budgets budgets;
  const Budgets* budgets_ptr = nullptr;
  if (!budgets_path.empty()) {
    try {
      budgets = Budgets::Load(budgets_path);
      budgets_ptr = &budgets;
    } catch (const std::exception& e) {
      std::printf("grader: cannot load budgets: %s\n", e.what());
      return 2;
    }
  }
  std::string workdir = "/tmp/efs-sealed-" + factory_name + "-" + std::to_string(getpid());
  RunCmd("rm -rf " + ShellQuote(workdir));
  RunCmd("mkdir -p " + ShellQuote(workdir));
  int rc = 0;
  try {
    // 1. Sealed matrix through the spawned candidate process.
    // The child image runs in the fixed chroot (UID/GID 60001, seccomp,
    // no namespaces or mounts; see tests/patches/runtime-boundary.md):
    // absolute paths outside the staging view stop resolving before any
    // candidate code runs.
    std::string staging = StageAndBuild(".", factory_name, workdir);
    sealed::Spawned sp = sealed::SpawnSandboxed(
        (staging + "/image").c_str(), staging, {staging});
    {
      sealed::Channel chan(sp.fd);
      sealed::RemoteFactory rf(&chan);
      rf.ServeServices();
      std::printf("[sealed] matrix via %s (pid %d)\n", staging.c_str(),
                  sp.pid);
      rc = RunMatrix(rf, profile, budgets_ptr, "sealed-" + factory_name,
                     evidence_dir);
      // EOF the child by closing our end (Channel dtor), then reap.
    }
    // Channel closed above; child should exit on EOF.
    try {
      WaitChild(sp.pid, 15, "candidate proc");
    } catch (const std::exception& e) {
      std::printf("[sealed] child reap: %s\n", e.what());
      rc = 1;
    }

    // 2. Adversarial set.
    Counts adv;
    std::string staging2 = StageAndBuild(".", factory_name, workdir);
    bool a0 = AdvSubstitution(adv, workdir);
    // The filesystem snooper models the untrusted candidate image: its
    // staging must not contain reference/, trusted/, or grader sources.
    // (The reference self-check image legitimately stages reference/
    // sources, so probing it for them would be vacuous.)
    std::string staging_adv = (factory_name == "candidate")
                                  ? staging2
                                  : StageAndBuild(".", "candidate",
                                                 workdir + "/adv");
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
      throw std::runtime_error("snoop: cannot resolve repo root");
    bool a1 = AdvSnoop(adv, staging_adv, workdir, cwd);
    bool a2 = AdvReuse(adv, staging2, workdir);
    bool a3 = AdvXtenant(adv, staging2, workdir);
    bool a4 = AdvRpcHardening(adv);
    std::printf("[sealed] adversarial: substitution=%s snoop=%s reuse=%s "
                "xtenant=%s rpc=%s (checks=%d failed=%d)\n",
                a0 ? "contained" : "BREACH", a1 ? "contained" : "BREACH",
                a2 ? "contained" : "BREACH", a3 ? "contained" : "BREACH",
                a4 ? "contained" : "BREACH", adv.checks, adv.failed);
    if (!(a0 && a1 && a2 && a3 && a4)) rc = 1;
  } catch (const std::exception& e) {
    std::printf("[sealed] infrastructure: %s\n", e.what());
    RunCmd("rm -rf " + ShellQuote(workdir));
    return 2;
  }
  RunCmd("rm -rf " + ShellQuote(workdir));
  return rc;
}

}  // namespace sealed_run
}  // namespace grader
