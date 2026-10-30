// Self-contained RPC transport (see rpc.h).
#include "sealed/rpc.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <algorithm>

namespace sealed {
namespace {

// A dead peer must surface as an EPIPE error, never as process death:
// both the grader and every spawned child link this file.
struct SigPipeIgnorer {
  SigPipeIgnorer() { signal(SIGPIPE, SIG_IGN); }
};
SigPipeIgnorer g_ignore_sigpipe;

// Move fd out of the way of the child's fixed channel fd (3), so the
// dup2/close spawn sequence cannot destroy the socket when socketpair
// hands out low numbers.
int MoveHigh(int fd) {
  if (fd == 3) {
    int n = fcntl(fd, F_DUPFD, 10);
    if (n < 0) throw RemoteError("dup high failed");
    close(fd);
    return n;
  }
  return fd;
}

// Drain child output through a bounded parent-owned pipe for its full
// lifetime. It is untrusted diagnostic text, never grading evidence. Keeping
// the reader alive avoids EPIPE for legitimate runtime diagnostics.
void DrainChildOutput(int fd) {
  std::thread([fd] {
    size_t left = 65536;
    char buf[4096];
    while (true) {
      ssize_t n = read(fd, buf, sizeof buf);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) break;
      const size_t keep = std::min(left, static_cast<size_t>(n));
      if (keep) {
        std::fwrite(buf, 1, keep, stderr);
        left -= keep;
      }
    }
    close(fd);
  }).detach();
}

struct P {
  const char* s;
  void ws() {
    while (*s && std::isspace((unsigned char)*s)) ++s;
  }
  J val() {
    ws();
    if (*s == '{') return obj();
    if (*s == '[') return arr();
    if (*s == '"') {
      J j = J::Str(str());
      return j;
    }
    if (*s == 't') {
      expect("true");
      return J::Num(1);
    }
    if (*s == 'f') {
      expect("false");
      return J::Num(0);
    }
    if (*s == 'n') {
      expect("null");
      return J();
    }
    J j = J::Num(0);
    char* e = nullptr;
    j.num = std::strtod(s, &e);
    if (e == s) throw RemoteError("bad json number");
    s = e;
    return j;
  }
  void expect(const char* w) {
    while (*w) {
      if (*s != *w) throw RemoteError("bad json literal");
      ++s;
      ++w;
    }
  }
  std::string str() {
    ++s;
    std::string o;
    while (*s && *s != '"') {
      if (*s == '\\') {
        ++s;
        if (*s == 'n') o += '\n';
        else if (*s == 't') o += '\t';
        else o += *s;
        if (*s) ++s;
      } else o += *s++;
    }
    if (*s != '"') throw RemoteError("unterminated string");
    ++s;
    return o;
  }
  J arr() {
    J j = J::Arr();
    ++s;
    ws();
    if (*s == ']') {
      ++s;
      return j;
    }
    while (true) {
      j.arr.push_back(val());
      ws();
      if (*s == ',') {
        ++s;
        continue;
      }
      if (*s == ']') {
        ++s;
        break;
      }
      throw RemoteError("bad json array");
    }
    return j;
  }
  J obj() {
    J j = J::Obj();
    ++s;
    ws();
    if (*s == '}') {
      ++s;
      return j;
    }
    while (true) {
      ws();
      if (*s != '"') throw RemoteError("bad json object key");
      std::string k = str();
      ws();
      if (*s != ':') throw RemoteError("bad json colon");
      ++s;
      j.obj[k] = val();
      ws();
      if (*s == ',') {
        ++s;
        continue;
      }
      if (*s == '}') {
        ++s;
        break;
      }
      throw RemoteError("bad json object");
    }
    return j;
  }
};

void DumpInto(const J& j, std::string& o) {
  switch (j.t) {
    case J::T::NUL: o += "null"; break;
    case J::T::NUM: {
      char b[32];
      std::snprintf(b, sizeof b, "%.0f", j.num);
      o += b;
      break;
    }
    case J::T::STR:
      o += '"';
      for (char ch : j.str) {
        if (ch == '"' || ch == '\\') o += '\\';
        o += ch;
      }
      o += '"';
      break;
    case J::T::ARR:
      o += '[';
      for (size_t i = 0; i < j.arr.size(); ++i) {
        if (i) o += ',';
        DumpInto(j.arr[i], o);
      }
      o += ']';
      break;
    case J::T::OBJ: {
      o += '{';
      bool first = true;
      for (auto& [k, v] : j.obj) {
        if (!first) o += ',';
        first = false;
        J kk = J::Str(k);
        DumpInto(kk, o);
        o += ':';
        DumpInto(v, o);
      }
      o += '}';
      break;
    }
  }
}

void WriteAll(int fd, const char* p, size_t n) {
  while (n > 0) {
    ssize_t w = write(fd, p, n);
    if (w < 0 && errno == EINTR) continue;
    if (w <= 0) throw RemoteError("channel write failed");
    p += w;
    n -= (size_t)w;
  }
}

}  // namespace

J J::Parse(const std::string& s) {
  P p{s.c_str()};
  J j = p.val();
  p.ws();
  if (*p.s) throw RemoteError("trailing json");
  return j;
}

std::string J::Dump() const {
  std::string o;
  DumpInto(*this, o);
  return o;
}

std::string ToHex(const std::vector<uint8_t>& b) {
  static const char* H = "0123456789abcdef";
  std::string o;
  o.reserve(b.size() * 2);
  for (uint8_t v : b) {
    o += H[v >> 4];
    o += H[v & 15];
  }
  return o;
}

std::vector<uint8_t> FromHex(const std::string& h) {
  if (h.size() % 2) throw RemoteError("odd hex");
  std::vector<uint8_t> o;
  o.reserve(h.size() / 2);
  auto nyb = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    throw RemoteError("bad hex");
  };
  for (size_t i = 0; i < h.size(); i += 2)
    o.push_back(uint8_t((nyb(h[i]) << 4) | nyb(h[i + 1])));
  return o;
}

J U64(uint64_t v) { return J::Str(std::to_string(v)); }

uint64_t UnU64(const J& j) {
  if (j.t == J::T::STR) {
    const char* s = j.str.c_str();
    char* e = nullptr;
    unsigned long long v = std::strtoull(s, &e, 10);
    if (e == s || *e) throw RemoteError("bad u64");
    return (uint64_t)v;
  }
  if (j.t == J::T::NUM) return (uint64_t)j.num;
  throw RemoteError("expected u64");
}

J Bytes(const std::vector<uint8_t>& b) {
  J j = J::Obj();
  j.obj["$hex"] = J::Str(ToHex(b));
  return j;
}

const J& Arg(const J& args, size_t i) {
  if (args.t != J::T::ARR || i >= args.arr.size())
    throw RemoteError("bad args");
  return args.arr[i];
}
void RequireArgs(const J& args, size_t n) {
  if (args.t != J::T::ARR || args.arr.size() != n)
    throw RemoteError("bad args");
}
uint64_t ArgU64(const J& args, size_t i) { return UnU64(Arg(args, i)); }
uint32_t ArgU32(const J& args, size_t i) {
  const J& j = Arg(args, i);
  if (j.t != J::T::NUM) throw RemoteError("bad args");
  double v = j.num;
  if (!(v >= 0 && v <= 4294967295.0 && v == (double)(uint32_t)v))
    throw RemoteError("bad args");
  return (uint32_t)v;
}
const std::string& ArgStr(const J& args, size_t i) {
  const J& j = Arg(args, i);
  if (j.t != J::T::STR) throw RemoteError("bad args");
  return j.str;
}
std::vector<uint8_t> ArgBytes(const J& args, size_t i) {
  return Unbytes(Arg(args, i));
}
size_t ArgSize(const J& args, size_t i) {
  const J& j = Arg(args, i);
  if (j.t != J::T::NUM) throw RemoteError("bad args");
  double v = j.num;
  // (double)SIZE_MAX rounds to 2^64; casting v >= 2^64 to size_t is UB.
  // Reject before the cast (candidate-controlled input to privileged grader).
  static const double k2pow64 = 18446744073709551616.0;
  if (!(v >= 0 && v < k2pow64)) throw RemoteError("bad args");
  size_t n = (size_t)v;
  if (v != (double)n) throw RemoteError("bad args");
  return n;
}
const std::vector<J>& ArgArr(const J& args, size_t i) {
  const J& j = Arg(args, i);
  if (j.t != J::T::ARR) throw RemoteError("bad args");
  return j.arr;
}

std::vector<uint8_t> Unbytes(const J& j) {
  auto it = j.obj.find("$hex");
  if (j.t != J::T::OBJ || it == j.obj.end() || it->second.t != J::T::STR)
    throw RemoteError("expected bytes");
  return FromHex(it->second.str);
}

Channel::Channel(int fd, int timeout_ms, int deadline_ms)
    : fd_(fd), timeout_ms_(timeout_ms), deadline_ms_(deadline_ms) {}
Channel::~Channel() {
  if (fd_ >= 0) close(fd_);
}

void Channel::On(const std::string& iface_method, Handler h) {
  handlers_[iface_method] = std::move(h);
}

void Channel::WriteMsg(const J& j) {
  std::string s = j.Dump();
  uint32_t n = (uint32_t)s.size();
  char h[4] = {char(n >> 24), char(n >> 16), char(n >> 8), char(n)};
  WriteAll(fd_, h, 4);
  WriteAll(fd_, s.data(), s.size());
}

J Channel::ReadMsg() {
  auto rd = [&](char* p, size_t n, int budget_ms) {
    while (n > 0) {
      struct pollfd pf{fd_, POLLIN, 0};
      int r = poll(&pf, 1, budget_ms);
      if (r < 0 && errno == EINTR) continue;
      if (r == 0) throw TimeoutWire("channel read timeout");
      if (r < 0) throw RemoteError("channel poll failed");
      ssize_t k = read(fd_, p, n);
      if (k < 0 && errno == EINTR) continue;
      if (k == 0) throw RemoteError("channel EOF");
      if (k < 0) throw RemoteError("channel read failed");
      p += k;
      n -= (size_t)k;
    }
  };
  char h[4];
  rd(h, 4, timeout_ms_);
  uint32_t n = (uint8_t(h[0]) << 24) | (uint8_t(h[1]) << 16) |
               (uint8_t(h[2]) << 8) | uint8_t(h[3]);
  if (n > (32 << 20)) throw RemoteError("message too large");
  std::string s(n, 0);
  if (n) rd(s.data(), n, timeout_ms_);
  return J::Parse(s);
}

// Deadline-bounded read: like ReadMsg but the whole wait counts against
// the call deadline (poll slices so a silent peer cannot out-wait it).
J Channel::ReadMsgBudget(int budget_ms) {
  if (budget_ms <= 0) throw TimeoutWire("call deadline");
  char h[4];
  size_t got = 0;
  auto rd = [&](char* p, size_t n) {
    while (n > 0) {
      if (budget_ms <= 0) throw TimeoutWire("call deadline");
      struct pollfd pf{fd_, POLLIN, 0};
      int slice = budget_ms < 200 ? budget_ms : 200;
      if (slice <= 0) throw TimeoutWire("call deadline");
      auto t0 = std::chrono::steady_clock::now();
      int r = poll(&pf, 1, slice);
      if (r < 0 && errno == EINTR) continue;
      auto spent = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0)
                       .count();
      budget_ms -= spent;
      if (r == 0) {
        if (budget_ms <= 0) throw TimeoutWire("call deadline");
        continue;  // slice elapsed but deadline remains: keep waiting
      }
      if (r < 0) throw RemoteError("channel poll failed");
      ssize_t k = read(fd_, p, n);
      if (k < 0 && errno == EINTR) continue;
      if (k == 0) throw RemoteError("channel EOF");
      if (k < 0) throw RemoteError("channel read failed");
      p += k;
      n -= (size_t)k;
      (void)got;
    }
  };
  rd(h, 4);
  uint32_t n = (uint8_t(h[0]) << 24) | (uint8_t(h[1]) << 16) |
               (uint8_t(h[2]) << 8) | uint8_t(h[3]);
  if (n > (32 << 20)) throw RemoteError("message too large");
  std::string s(n, 0);
  if (n) rd(s.data(), n);
  return J::Parse(s);
}

J Channel::Call(const std::string& iface, const std::string& method,
                const J& args) {
  uint64_t seq = next_seq_++;
  J req = J::Obj();
  req.obj["seq"] = J::Num((double)seq);
  req.obj["iface"] = J::Str(iface);
  req.obj["method"] = J::Str(method);
  req.obj["args"] = args;
  WriteMsg(req);
  auto start = std::chrono::steady_clock::now();
  auto elapsed_ms = [&] {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
        .count();
  };
  while (true) {
    int remain =
        deadline_ms_ - (int)elapsed_ms();
    J msg = ReadMsgBudget(remain);
    if (getenv("EFS_RPC_DEBUG")) {
      std::fprintf(stderr, "[call %s.%s] resp keys=", iface.c_str(),
                   method.c_str());
      for (auto& [k, v] : msg.obj)
        std::fprintf(stderr, "%s%s,", k.c_str(),
                     v.t == J::T::STR ? ("=" + v.str).c_str() : "");
      std::fprintf(stderr, "\n");
    }
    auto it = msg.obj.find("seq");
    if (it == msg.obj.end()) throw RemoteError("missing seq");
    // Incoming request while awaiting: dispatch (re-entrant pump).
    auto fi = msg.obj.find("iface");
    if (fi != msg.obj.end() && fi->second.t == J::T::STR) {
      auto fm = msg.obj.find("method");
      if (fm == msg.obj.end() || fm->second.t != J::T::STR)
        throw RemoteError("bad envelope");
      std::string key = fi->second.str + "." + fm->second.str;
      auto h = handlers_.find(key);
      auto fa = msg.obj.find("args");
      if (fa == msg.obj.end()) throw RemoteError("bad envelope");
      J resp = J::Obj();
      resp.obj["seq"] = it->second;
      if (h == handlers_.end()) {
        // Unknown method on a re-entrant pump: answer "no handler" so a
        // probing peer gets a clean error instead of a hung call. (The
        // top-level Serve loop keeps the throw for fail-closed parity.)
        resp.obj["ok"] = J::Num(0);
        resp.obj["error"] = J::Str("no handler " + key);
      } else {
        try {
          resp.obj["ok"] = J::Num(1);
          resp.obj["result"] = h->second(fa->second);
        } catch (const SimCrashWire&) {
          resp.obj["ok"] = J::Num(0);
          resp.obj["error"] = J::Str("SIMCRASH");
        } catch (const std::exception& e) {
          resp.obj["ok"] = J::Num(0);
          resp.obj["error"] = J::Str(std::string("INFRA:") + e.what());
        }
      }
      WriteMsg(resp);
      continue;
    }
    if (it->second.t != J::T::NUM || (uint64_t)it->second.num != seq)
      throw RemoteError("seq mismatch");
    auto fo = msg.obj.find("ok");
    if (fo == msg.obj.end() || fo->second.t != J::T::NUM)
      throw RemoteError("bad envelope");
    if (fo->second.num == 1) {
      auto fr = msg.obj.find("result");
      if (fr == msg.obj.end()) throw RemoteError("bad envelope");
      return fr->second;
    }
    auto fe = msg.obj.find("error");
    if (fe == msg.obj.end() || fe->second.t != J::T::STR)
      throw RemoteError("bad envelope");
    std::string err = fe->second.str;
    if (err == "SIMCRASH") throw SimCrashWire{};
    throw RemoteError(err);
  }
}

void Channel::Serve() {
  while (true) {
    J msg;
    try {
      msg = ReadMsg();
    } catch (const RemoteError& e) {
      if (std::string(e.what()) == "channel EOF") return;
      throw;
    }
    if (getenv("EFS_RPC_DEBUG")) {
      auto fi = msg.obj.find("iface");
      auto fm = msg.obj.find("method");
      std::fprintf(stderr, "[serve] iface=%s method=%s keys=",
                   fi != msg.obj.end() ? fi->second.str.c_str() : "?",
                   fm != msg.obj.end() ? fm->second.str.c_str() : "?");
      for (auto& [k, _] : msg.obj) std::fprintf(stderr, "%s,", k.c_str());
      std::fprintf(stderr, "\n");
    }
    auto fi = msg.obj.find("iface");
    if (fi == msg.obj.end() || fi->second.t != J::T::STR)
      throw RemoteError("expected request");
    auto fm = msg.obj.find("method");
    auto fs = msg.obj.find("seq");
    auto fa = msg.obj.find("args");
    if (fm == msg.obj.end() || fm->second.t != J::T::STR ||
        fs == msg.obj.end() || fa == msg.obj.end())
      throw RemoteError("bad envelope");
    std::string key = fi->second.str + "." + fm->second.str;
    auto h = handlers_.find(key);
    J resp = J::Obj();
    resp.obj["seq"] = fs->second;
    if (h == handlers_.end()) {
      resp.obj["ok"] = J::Num(0);
      resp.obj["error"] = J::Str("no handler " + key);
    } else {
      try {
        resp.obj["ok"] = J::Num(1);
        resp.obj["result"] = h->second(fa->second);
      } catch (const SimCrashWire&) {
        resp.obj["ok"] = J::Num(0);
        resp.obj["error"] = J::Str("SIMCRASH");
      } catch (const std::exception& e) {
        resp.obj["ok"] = J::Num(0);
        resp.obj["error"] = J::Str(std::string("INFRA:") + e.what());
      }
    }
    WriteMsg(resp);
  }
}

Spawned SpawnChild(const char* path, const std::vector<std::string>& args,
                   const char* /*workdir*/) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    throw RemoteError("socketpair failed");
  sv[0] = MoveHigh(sv[0]);
  sv[1] = MoveHigh(sv[1]);
  // Candidate/adversarial stdio discipline: the child NEVER inherits
  // the parent's stdout/stderr. It receives a parent-owned bounded
  // pipe (drained by the parent, never by the grade) or /dev/null --
  // never a verifier-log stream. Inherited descriptors bypass Unix
  // path permissions, so an inherited log/reward file would be
  // writable by untrusted code regardless of its mode bits. The file
  // actions below take effect in the child before any initializer
  // runs, covering statically-linked output as well.
  //
  // Designated capture, deadlock-free: child stdout+stderr BOTH go to
  // the same pipe (no separate stderr pipe to fill while the parent
  // drains stdout), the parent drains it to /dev/null with a bounded
  // total (kChildOutCap) using nonblocking reads alongside the channel
  // pump, and the pipe is sized up (64 KiB) so chatty-but-legitimate
  // children never block. Anything beyond the cap is discarded, never
  // parsed: child stdio is evidence of nothing.
  int out[2];
  if (pipe(out) != 0) {
    close(sv[0]);
    close(sv[1]);
    throw RemoteError("stdio pipe failed");
  }
  int out_rd = MoveHigh(out[0]);
  int out_wr = MoveHigh(out[1]);
  int devnull = open("/dev/null", O_RDONLY);
  if (devnull < 0) {
    close(sv[0]);
    close(sv[1]);
    close(out_rd);
    close(out_wr);
    throw RemoteError("open /dev/null failed");
  }
  devnull = MoveHigh(devnull);
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_adddup2(&fa, sv[1], 3);
  posix_spawn_file_actions_addclose(&fa, sv[0]);
  posix_spawn_file_actions_addclose(&fa, sv[1]);
  posix_spawn_file_actions_adddup2(&fa, devnull, 0);
  posix_spawn_file_actions_addclose(&fa, devnull);
  posix_spawn_file_actions_adddup2(&fa, out_wr, 1);
  posix_spawn_file_actions_adddup2(&fa, out_wr, 2);
  posix_spawn_file_actions_addclose(&fa, out_wr);
  posix_spawn_file_actions_addclose(&fa, out_rd);
  std::vector<char*> argv;
  argv.push_back(const_cast<char*>(path));
  for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
  argv.push_back(nullptr);
  int pid = -1;
  int r = posix_spawn(&pid, path, &fa, nullptr, argv.data(), ::environ);
  posix_spawn_file_actions_destroy(&fa);
  close(sv[1]);
  close(out_wr);
  close(devnull);
  if (r != 0) {
    close(sv[0]);
    close(out_rd);
    throw RemoteError("spawn failed");
  }
  DrainChildOutput(out_rd);
  return Spawned{pid, sv[0]};
}

}  // namespace sealed
