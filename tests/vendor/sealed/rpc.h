#pragma once
// Self-contained RPC transport for the sealed split. No includes beyond
// the C++ standard library and POSIX sockets: this header ships in the
// candidate image, so it must not pull in grader/ or trusted/ headers.
#include <cstdint>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace sealed {

// ---- minimal JSON value ----
struct J {
  enum class T { NUL, NUM, STR, ARR, OBJ } t = T::NUL;
  double num = 0;
  std::string str;
  std::vector<J> arr;
  std::map<std::string, J> obj;
  static J Parse(const std::string& s);
  std::string Dump() const;
  static J Num(double v) {
    J j;
    j.t = T::NUM;
    j.num = v;
    return j;
  }
  static J Str(const std::string& s) {
    J j;
    j.t = T::STR;
    j.str = s;
    return j;
  }
  static J Arr() {
    J j;
    j.t = T::ARR;
    return j;
  }
  static J Obj() {
    J j;
    j.t = T::OBJ;
    return j;
  }
};

// Bytes cross the channel as {"$hex":"..."}.
std::string ToHex(const std::vector<uint8_t>& b);
std::vector<uint8_t> FromHex(const std::string& h);
J Bytes(const std::vector<uint8_t>& b);
std::vector<uint8_t> Unbytes(const J& j);

// u64 values cross as decimal strings: JSON doubles cannot hold them.
J U64(uint64_t v);
uint64_t UnU64(const J& j);

// Checked argument access for RPC handlers. Every handler runs on
// attacker-influenced input (a compromised candidate image crafts
// requests); bare a.arr[i] indexing would read out of bounds. These
// throw RemoteError("bad args") on any shape mismatch — fail closed,
// never undefined behavior.
const J& Arg(const J& args, size_t i);
uint64_t ArgU64(const J& args, size_t i);
uint32_t ArgU32(const J& args, size_t i);
const std::string& ArgStr(const J& args, size_t i);
std::vector<uint8_t> ArgBytes(const J& args, size_t i);
size_t ArgSize(const J& args, size_t i);
const std::vector<J>& ArgArr(const J& args, size_t i);
void RequireArgs(const J& args, size_t n);

struct RemoteError : std::runtime_error {
  using std::runtime_error::runtime_error;
};
struct SimCrashWire {};  // SimulatedCrash crossing the channel
struct TimeoutWire : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// Re-entrant channel: while awaiting a response, incoming requests are
// dispatched (services never call back, so nesting is bounded, but the
// pump is general). dispatch maps "IFACE.method" -> handler.
class Channel {
 public:
  // timeout_ms bounds each read; deadline_ms bounds a whole Call
  // (a slow drip of responses must not reset the operation budget).
  explicit Channel(int fd, int timeout_ms = 30000, int deadline_ms = 120000);
  ~Channel();
  Channel(const Channel&) = delete;
  Channel& operator=(const Channel&) = delete;

  using Handler = std::function<J(const J& args)>;
  void On(const std::string& iface_method, Handler h);

  // Call the peer and wait for the matching response.
  J Call(const std::string& iface, const std::string& method,
         const J& args);

  // Serve peer requests until EOF (candidate main loop).
  void Serve();

 private:
  J ReadMsg();
  // Deadline-bounded variant used by the Call pump: the whole wait
  // counts against the call deadline (a silent peer cannot out-wait it
  // by staying quiet past the per-read timer).
  J ReadMsgBudget(int budget_ms);
  void WriteMsg(const J& j);
  int fd_;
  int timeout_ms_;
  int deadline_ms_;
  uint64_t next_seq_ = 1;
  std::map<std::string, Handler> handlers_;
};

// Spawn a child with a socketpair; returns {pid, channel-fd-ours}.
struct Spawned {
  int pid = -1;
  int fd = -1;
};
Spawned SpawnChild(const char* path, const std::vector<std::string>& args,
                   const char* workdir);

}  // namespace sealed
