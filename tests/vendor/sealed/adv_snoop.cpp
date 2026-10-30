// Adversarial double 1: filesystem/process snooper. Models untrusted
// candidate code running in the child: attempts to read verifier,
// reference, and evidence material through absolute paths, /proc, and
// inherited descriptors. Records only openability (never contents).
// Verifier-owned test double (never in the candidate image).
#include <dirent.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

FILE* g_out = nullptr;
int g_opened = 0;

void Probe(const char* kind, const std::string& target) {
  bool ok = false;
  if (FILE* in = fopen(target.c_str(), "r")) {
    ok = true;
    fclose(in);
  } else if (DIR* d = opendir(target.c_str())) {
    ok = true;
    closedir(d);
  }
  std::fprintf(g_out, "%s %s %s\n", ok ? "OPENED" : "denied", kind,
               target.c_str());
  if (ok) ++g_opened;
}

}  // namespace

int main(int argc, char** argv) {
  // argv[1] = staging root (sandbox rewrites it to "/"; baseline
  // ignores it and probes from the inherited cwd).
  // argv[2] = result path. argv[3] = repo root for absolute probes.
  bool baseline = argc > 4 && std::string(argv[4]) == "--baseline";
  if (!baseline && argc > 1 && chdir("/") != 0) return 3;
  const char* out = argc > 2 ? argv[2] : "snoop.result";
  std::string repo = argc > 3 ? argv[3] : ".";
  g_out = fopen(out, "w");
  if (!g_out) return 2;

  // Staging-relative view (positive control first: this one must open
  // in both modes, proving the probes can succeed). Mirrors the
  // verifier's denied-REL list in AdvSnoop (wrapper vendor tree: no
  // reports/evidence vendored; allocator/world.cpp replace them).
  Probe("REL", "sealed/rpc.h");
  for (auto& p : {"reference/efs_impl.h", "reference/efs_impl.cpp",
                  "trusted/admin.h", "trusted/world.h", "trusted/impl.h",
                  "trusted/allocator.cpp", "trusted/world.cpp",
                  "grader/sealed_run.cpp", "grader/suites.h",
                  "profiles/H0.json", "profiles/budgets.json",
                  "../reference", "../trusted", "../grader"})
    Probe("REL", p);

  // Absolute paths: the same-user read boundary under test. Mirrors
  // the verifier's kAbs list in AdvSnoop (wrapper vendor tree: no
  // reports/evidence vendored; allocator/world.cpp replace them).
  for (auto& p :
       {"reference/efs_impl.h", "reference/efs_impl.cpp",
        "trusted/admin.h", "trusted/world.h", "trusted/impl.h",
        "trusted/crypto_broker.cpp", "grader/sealed_run.cpp",
        "grader/suites.h", "grader/suites_oracle.cpp",
        "trusted/allocator.cpp", "trusted/world.cpp", "profiles/H0.json",
        "profiles/budgets.json", "packaging/source_manifest.json",
        "candidate/src/efs_impl.cpp"})
    Probe("ABS", repo + "/" + p);

  // /proc interfaces: environ/cmdline/maps/fd of self, parent snooping,
  // network state. Openability only; contents are never recorded.
  // The double also reports its parent pid: inside the sandbox it must
  // be the namespace init (pid 1), proving PID-namespace confinement.
  char ppid[64];
  std::snprintf(ppid, sizeof ppid, "/proc/%d/cmdline", (int)getppid());
  std::fprintf(g_out, "ppid=%d\n", (int)getppid());
  for (std::string p : {std::string("/proc/self/environ"),
                        std::string("/proc/self/cmdline"),
                        std::string("/proc/self/maps"),
                        std::string("/proc/self/fd"),
                        std::string("/proc/net/tcp"), std::string(ppid)})
    Probe("PROC", p);

  // World-readable vs permission-gated controls.
  Probe("CTL", "/etc/passwd");
  Probe("CTL", "/etc/shadow");

  // Inherited descriptors beyond 0,1,2 and the channel (3): presence
  // only — no IO is attempted on foreign fds. The double's own result
  // file (its designated output) is excluded.
  std::string extra;
  int n_extra = 0;
  int out_fd = fileno(g_out);
  for (int fd = 4; fd < 65536; ++fd) {
    if (fd == 3 || fd == out_fd) continue;
    if (fcntl(fd, F_GETFD) != -1) {
      if (n_extra) extra += ",";
      extra += std::to_string(fd);
      ++n_extra;
    }
  }
  std::fprintf(g_out, "fds_extra=%d [%s]\n", n_extra, extra.c_str());
  // Descriptor targets via /proc/self/fd (namespace-local /proc):
  // proves no inherited descriptor reaches host files. Own output
  // and the enumeration dir itself are excluded.
  {
    DIR* dd = opendir("/proc/self/fd");
    std::string tgts;
    int n = 0;
    if (dd) {
      int dfd = dirfd(dd);
      struct dirent* e;
      char link[64], buf[512];
      while ((e = readdir(dd))) {
        if (e->d_name[0] == '.') continue;
        int fd = atoi(e->d_name);
        if (fd == dfd || fd == out_fd) continue;
        std::snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
        ssize_t k = readlink(link, buf, sizeof buf - 1);
        if (k < 0) continue;
        buf[k] = 0;
        if (n) tgts += ",";
        tgts += std::to_string(fd) + "->" + buf;
        ++n;
      }
      closedir(dd);
    }
    std::fprintf(g_out, "fd_targets=%d [%s]\n", n, tgts.c_str());
  }
  // Empty-namespace network tables: header only, no peers.
  {
    int lines = -1;
    if (FILE* in = fopen("/proc/net/tcp", "r")) {
      lines = 0;
      char buf[1024];
      size_t total = 0;
      while (fgets(buf, sizeof buf, in) && total < 4096) {
        total += std::strlen(buf);
        ++lines;
      }
      fclose(in);
    }
    std::fprintf(g_out, "net_tcp_lines=%d\n", lines);
  }
  // Active negative probes. Only this trusted double may report their
  // results; candidate output is never used to decide a grading pass.
  if (!baseline) {
  int reward = open("/logs/verifier/reward.json", O_CREAT | O_WRONLY, 0600);
  std::fprintf(g_out, "write_reward=%s\n", reward < 0 ? "denied" : "BREACH");
  if (reward >= 0) close(reward);
  int tests = open("/tests/test.sh", O_RDONLY);
  std::fprintf(g_out, "read_tests=%s\n", tests < 0 ? "denied" : "BREACH");
  if (tests >= 0) close(tests);
    pid_t child = fork();
    if (child == 0) _exit(77);
    std::fprintf(g_out, "fork=%s\n", child < 0 ? "denied" : "BREACH");
    if (child > 0) waitpid(child, nullptr, 0);
    std::fprintf(g_out, "setsid=%s\n", setsid() < 0 ? "denied" : "BREACH");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    std::fprintf(g_out, "socket=%s\n", sock < 0 ? "denied" : "BREACH");
    if (sock >= 0) close(sock);
  }
  std::fprintf(g_out, "opened_total=%d\n", g_opened);
  fclose(g_out);
  return 0;
}
