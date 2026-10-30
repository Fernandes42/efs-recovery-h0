// Wrapper-local parent side of the fixed, task-contained candidate boundary.
#include "sealed/sandbox.h"
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace sealed {
namespace {
std::string Field(int pid, const char* name) {
  std::ifstream f("/proc/" + std::to_string(pid) + "/status");
  std::string line;
  while (std::getline(f, line))
    if (line.rfind(std::string(name) + ":", 0) == 0)
      return line.substr(line.find(':') + 1);
  throw RemoteError("boundary: missing parent-readable proc status");
}
std::vector<unsigned long long> Numbers(int pid, const char* key, int base=10) {
  std::istringstream s(Field(pid, key));
  if (base == 16) s >> std::hex;
  std::vector<unsigned long long> v;
  unsigned long long n;
  while (s >> n) v.push_back(n);
  return v;
}
void Attest(int pid, unsigned long long baseline_filters) {
  const std::vector<unsigned long long> identity(4, 60001);
  const std::vector<unsigned long long> zero{0}, one{1};
  if (Numbers(pid, "Uid") != identity || Numbers(pid, "Gid") != identity ||
      !Numbers(pid, "Groups").empty() ||
      Numbers(pid, "CapEff", 16) != zero ||
      Numbers(pid, "CapPrm", 16) != zero ||
      Numbers(pid, "CapInh", 16) != zero ||
      Numbers(pid, "CapAmb", 16) != zero ||
      Numbers(pid, "CapBnd", 16) != zero ||
      Numbers(pid, "NoNewPrivs") != one ||
      Numbers(pid, "Seccomp") != std::vector<unsigned long long>{2} ||
      Numbers(pid, "Seccomp_filters") !=
        std::vector<unsigned long long>{baseline_filters + 1})
    throw RemoteError("boundary: identity/capabilities/filter attestation failed");
}
} // namespace
Spawned SpawnSandboxed(const char* binary, const std::string& newroot,
                       const std::vector<std::string>& args) {
  auto baseline = Numbers(getpid(), "Seccomp_filters");
  if (baseline.size() != 1) throw RemoteError("boundary: no filter accounting");
  std::vector<std::string> hargs{newroot, binary, ""};
  hargs.insert(hargs.end(), args.begin(), args.end());
  Spawned sp = SpawnChild("/opt/efs-sandbox-helper", hargs, nullptr);
  try {
    bool stopped = false;
    for (int i=0; i<100; ++i) {
      int status=0;
      if (waitpid(sp.pid, &status, WNOHANG | WUNTRACED) == sp.pid) {
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
          throw RemoteError("boundary: trusted setup exited before attestation " +
            std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : 128));
        stopped = true; break;
      }
      usleep(50000);
    }
    if (!stopped) throw RemoteError("boundary: setup timeout");
    Attest(sp.pid, baseline[0]);
    std::printf("[boundary] pid=%d uid=60001 gid=60001 groups=empty "
                "caps=zero nnp=1 additional-filter=attested\n", sp.pid);
    if (kill(sp.pid, SIGCONT) != 0) throw RemoteError("boundary: continue failed");
    return sp;
  } catch (...) {
    kill(sp.pid, SIGKILL); waitpid(sp.pid, nullptr, 0); close(sp.fd); throw;
  }
}
} // namespace sealed
