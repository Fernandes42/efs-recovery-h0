// Wrapper-local Linux x86-64 candidate launcher. Uses only default container
// capabilities; never requests namespaces or mounts. Trusted setup copies a
// fixed runtime, chroots, drops identity/capabilities, adds seccomp, and stops
// for parent attestation before the candidate's first initializer can execute.
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace {
constexpr uid_t kUid = 60001;
constexpr gid_t kGid = 60001;
void Die(const char* what) { std::perror(what); _exit(25); }
void Limit(int kind, rlim_t value) {
  rlimit r{value, value};
  if (setrlimit(kind, &r) != 0) Die("efs limit");
}
void Filter() {
  std::vector<sock_filter> b;
  auto stmt = [&](unsigned short c, unsigned k) {
    b.push_back(sock_filter{c, 0, 0, k});
  };
  auto jump = [&](unsigned short c, unsigned k, unsigned char t,
                  unsigned char f) { b.push_back(sock_filter{c, t, f, k}); };
  stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch));
  jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr));
  // Only self-signalling is needed for the pre-exec stop and libc abort.
  for (int nr : {SYS_kill, SYS_tgkill}) {
    jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 4);
    stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0]));
    jump(BPF_JMP | BPF_JEQ | BPF_K, getpid(), 0, 1);
    stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
  }
  // Permit only CLONE_THREAD + shared-address-space thread creation. libc
  // falls back from clone3 when ENOSYS is returned; no process may be forked.
  jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);
  jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 5);
  stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0]));
  stmt(BPF_ALU | BPF_AND | BPF_K, CLONE_THREAD | CLONE_VM | CLONE_SIGHAND);
  jump(BPF_JMP | BPF_JEQ | BPF_K,
       CLONE_THREAD | CLONE_VM | CLONE_SIGHAND, 0, 1);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
  // The RPC driver requires no new processes or sockets.
  // fork/vfork/clone/clone3/setsid, socket/socketpair/connect, ptrace,
  // process_vm_*, io_uring, mount, namespace, and privilege calls are absent.
  for (int nr : {SYS_read, SYS_write, SYS_pread64, SYS_readv, SYS_writev, SYS_close,
       SYS_openat, SYS_newfstatat, SYS_fstat, SYS_stat, SYS_lstat,
       SYS_lseek, SYS_mmap, SYS_mprotect, SYS_munmap, SYS_brk, SYS_mremap,
       SYS_madvise, SYS_access, SYS_faccessat, SYS_faccessat2, SYS_readlink,
       SYS_readlinkat, SYS_getdents64, SYS_fcntl, SYS_ioctl, SYS_dup, SYS_dup2,
       SYS_dup3, SYS_poll, SYS_ppoll, SYS_select, SYS_pselect6,
       SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn,
       SYS_sigaltstack, SYS_arch_prctl, SYS_set_tid_address,
       SYS_set_robust_list, SYS_rseq, SYS_futex, SYS_getrandom,
       SYS_getpid, SYS_getppid, SYS_gettid, SYS_getuid, SYS_geteuid,
       SYS_getgid, SYS_getegid, SYS_getgroups, SYS_getcwd, SYS_chdir,
       SYS_clock_gettime, SYS_gettimeofday, SYS_time, SYS_nanosleep,
       SYS_clock_nanosleep, SYS_sched_yield, SYS_sched_getaffinity,
       SYS_prlimit64, SYS_getrlimit, SYS_getrusage, SYS_uname,
       SYS_recvfrom, SYS_sendto, SYS_recvmsg, SYS_sendmsg, SYS_shutdown,
       SYS_unlink, SYS_unlinkat, SYS_rename, SYS_renameat, SYS_renameat2,
       SYS_mkdir, SYS_mkdirat, SYS_ftruncate, SYS_fsync, SYS_fdatasync,
       SYS_execve, SYS_exit, SYS_exit_group}) {
    jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1);
    stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  }
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
  sock_fprog p{static_cast<unsigned short>(b.size()), b.data()};
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p) != 0)
    Die("efs install additional seccomp");
}
} // namespace

int main(int argc, char** argv) {
  if (argc < 4 || getuid() != 0) return 9;
  namespace fs = std::filesystem;
  const std::string root = argv[1], binary = argv[2], self = argv[3];
  const std::string name = fs::path(binary).filename();
  if (root.empty() || root[0] != '/' || name.empty()) return 9;
  try {
    // Only image-owned shared libraries and the trusted-selected executable.
    fs::copy("/opt/efs-runtime", root,
             fs::copy_options::recursive | fs::copy_options::overwrite_existing);
    if (binary != root + "/" + name)
      fs::copy_file(binary, root + "/" + name,
                    fs::copy_options::overwrite_existing);
    for (const auto& e : fs::recursive_directory_iterator(root)) {
      if (e.is_symlink()) return 26;
      if (chown(e.path().c_str(), 0, 0) != 0 ||
          chmod(e.path().c_str(), e.is_directory() ? 0755 : 0555) != 0)
        Die("efs stage protection");
    }
    for (const char* dir : {"work", "tmp"}) {
      const std::string p = root + "/" + dir;
      fs::remove_all(p);
      fs::create_directory(p);
      if (chown(p.c_str(), kUid, kGid) != 0 || chmod(p.c_str(), 0700) != 0)
        Die("efs work ownership");
    }
  } catch (const std::exception& e) {
    std::fprintf(stderr, "efs stage runtime: %s\n", e.what()); return 26;
  }
  // No inherited directory/file descriptor can escape the chroot.
  DIR* dd = opendir("/proc/self/fd");
  if (!dd) Die("efs fd enumeration");
  const int dfd = dirfd(dd);
  std::vector<int> close_fds;
  while (dirent* e = readdir(dd)) {
    if (e->d_name[0] == '.') continue;
    int fd = std::atoi(e->d_name);
    if (fd > 3 && fd != dfd) close_fds.push_back(fd);
  }
  closedir(dd);
  for (int fd : close_fds) close(fd);
  (void)self; // Fixed image-owned helper is never removed.
  if (chroot(root.c_str()) != 0 || chdir("/work") != 0)
    Die("efs chroot using existing capability");
  Limit(RLIMIT_CORE, 0); Limit(RLIMIT_CPU, 45);
  Limit(RLIMIT_AS, 1ULL << 30); Limit(RLIMIT_FSIZE, 32ULL << 20);
  Limit(RLIMIT_NPROC, 64); Limit(RLIMIT_NOFILE, 128);
  alarm(120);
  if (setgroups(0, nullptr) != 0) Die("efs clear groups");
  for (int cap = 0; cap <= CAP_LAST_CAP; ++cap)
    if (prctl(PR_CAPBSET_DROP, cap) != 0) Die("efs drop bounding cap");
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    Die("efs no_new_privs");
  if (setresgid(kGid, kGid, kGid) != 0 ||
      setresuid(kUid, kUid, kUid) != 0) Die("efs drop identity");
  __user_cap_header_struct h{_LINUX_CAPABILITY_VERSION_3, 0};
  __user_cap_data_struct caps[2]{};
  if (syscall(SYS_capset, &h, caps) != 0) Die("efs clear capabilities");
  clearenv();
  setenv("HOME", "/work", 1); setenv("TMPDIR", "/tmp", 1);
  for (const char* k : {"OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS",
                        "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"})
    setenv(k, "1", 1);
  std::vector<std::string> owned{"/" + name};
  const std::string prefix = root + "/";
  for (int i = 4; i < argc; ++i) {
    std::string a = argv[i];
    if (a == root) a = "/work";
    else if (a.compare(0, prefix.size(), prefix) == 0)
      a = "/" + a.substr(prefix.size());
    owned.push_back(a);
  }
  std::vector<char*> args;
  for (auto& s : owned) args.push_back(s.data());
  args.push_back(nullptr);
  Filter();
  // Only this trusted launcher reaches this stop, after successful filter
  // installation. The parent checks /proc status before releasing exec.
  if (kill(getpid(), SIGSTOP) != 0) Die("efs attestation stop");
  execv(owned[0].c_str(), args.data());
  Die("efs candidate exec");
}
