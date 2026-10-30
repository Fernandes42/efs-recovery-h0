// Candidate-side service proxies (see service_proxy.h).
#include "sealed/service_proxy.h"

#include <cstdlib>
#include <cstring>

namespace sealed {
namespace {
// Verifier replies are trusted, but shape-check them anyway: uniform
// fail-closed taxonomy ("bad response") instead of std::out_of_range,
// and no vector operator[] anywhere on the parse path.
const J& RespGet(const J& r, const char* k) {
  auto it = r.obj.find(k);
  if (r.t != J::T::OBJ || it == r.obj.end())
    throw RemoteError("bad response");
  return it->second;
}
double RespNum(const J& r, const char* k) {
  const J& j = RespGet(r, k);
  if (j.t != J::T::NUM) throw RemoteError("bad response");
  return j.num;
}
const std::string& RespStr(const J& r, const char* k) {
  const J& j = RespGet(r, k);
  if (j.t != J::T::STR) throw RemoteError("bad response");
  return j.str;
}
}  // namespace
namespace {

Channel* g_ch = nullptr;

J Hargs(HC h) {
  J a = J::Arr();
  a.arr.push_back(U64(h));
  return a;
}

efs::Err CallErr(const std::string& iface, const std::string& method,
                 const J& args) {
  try {
    J r = g_ch->Call(iface, method, args);
    return (efs::Err)(int)RespNum(r, "err");
  } catch (const SimCrashWire&) { throw; }
}

}  // namespace

void SetChannel(Channel* ch) { g_ch = ch; }
Channel* Chan() { return g_ch; }

// ---- store ----
efs::Err ProxyStore::Stage(const std::string& id,
                           std::vector<uint8_t> bytes) {
  J a = Hargs(h_);
  a.arr.push_back(J::Str(id));
  a.arr.push_back(Bytes(bytes));
  return CallErr("S", "stage", a);
}
efs::Err ProxyStore::Flush(const std::string& id) {
  J a = Hargs(h_);
  a.arr.push_back(J::Str(id));
  return CallErr("S", "flush", a);
}
bool ProxyStore::DurableExists(const std::string& id) const {
  J a = Hargs(h_);
  a.arr.push_back(J::Str(id));
  try {
    return RespGet(g_ch->Call("S", "exists", a), "present").num != 0;
  } catch (const SimCrashWire&) { throw; }
}
std::optional<std::vector<uint8_t>> ProxyStore::ReadDurable(
    const std::string& id) const {
  J a = Hargs(h_);
  a.arr.push_back(J::Str(id));
  try {
    J r = g_ch->Call("S", "read", a);
    if (RespNum(r, "present") == 0) return std::nullopt;
    return Unbytes(RespGet(r, "bytes"));
  } catch (const SimCrashWire&) { throw; }
}
std::map<std::string, std::vector<uint8_t>> ProxyStore::DurableImage()
    const {
  J a = Hargs(h_);
  std::map<std::string, std::vector<uint8_t>> out;
  try {
    J r = g_ch->Call("S", "image", a);
    for (auto& [k, v] : RespGet(r, "map").obj) out[k] = Unbytes(v);
  } catch (const SimCrashWire&) { throw; }
  return out;
}
void ProxyStore::DeleteDurable(const std::string& id) {
  J a = Hargs(h_);
  a.arr.push_back(J::Str(id));
  CallErr("S", "del", a);
}

// ---- anchor ----
efs::AnchorState ProxyAnchor::Get(uint32_t tenant) const {
  J a = Hargs(h_);
  a.arr.push_back(J::Num(tenant));
  try {
    J r = g_ch->Call("A", "get", a);
    efs::AnchorState s;
    s.generation = UnU64(RespGet(r, "gen"));
    s.manifest_id = RespStr(r, "mid");
    s.digest = Unbytes(RespGet(r, "digest"));
    return s;
  } catch (const SimCrashWire&) { throw; }
}
efs::Err ProxyAnchor::Publish(uint32_t tenant, uint64_t expected_gen,
                              const std::string& manifest_id,
                              const std::vector<uint8_t>& digest) {
  J a = Hargs(h_);
  a.arr.push_back(J::Num(tenant));
  a.arr.push_back(U64(expected_gen));
  a.arr.push_back(J::Str(manifest_id));
  a.arr.push_back(Bytes(digest));
  return CallErr("A", "publish", a);
}
efs::Err ProxyAnchor::Pin(uint32_t tenant, uint64_t generation,
                          const std::string& manifest_id,
                          const std::vector<uint8_t>& digest, uint64_t lease) {
  J a = Hargs(h_);
  a.arr.push_back(J::Num(tenant));
  a.arr.push_back(U64(generation));
  a.arr.push_back(J::Str(manifest_id));
  a.arr.push_back(Bytes(digest));
  a.arr.push_back(U64(lease));
  return CallErr("A", "pin", a);
}
efs::Err ProxyAnchor::Unpin(uint32_t tenant, uint64_t lease) {
  J a = Hargs(h_);
  a.arr.push_back(J::Num(tenant));
  a.arr.push_back(U64(lease));
  return CallErr("A", "unpin", a);
}
bool ProxyAnchor::Pinned(uint32_t tenant, uint64_t lease,
                         efs::AnchorState* out) const {
  J a = Hargs(h_);
  a.arr.push_back(J::Num(tenant));
  a.arr.push_back(U64(lease));
  try {
    J r = g_ch->Call("A", "pinned", a);
    if (RespNum(r, "found") == 0) return false;
    if (out) {
      out->generation = UnU64(RespGet(r, "gen"));
      out->manifest_id = RespStr(r, "mid");
      out->digest = Unbytes(RespGet(r, "digest"));
    }
    return true;
  } catch (const SimCrashWire&) { throw; }
}
std::map<uint64_t, efs::AnchorState> ProxyAnchor::PinsFor(
    uint32_t tenant) const {
  J a = Hargs(h_);
  a.arr.push_back(J::Num(tenant));
  std::map<uint64_t, efs::AnchorState> out;
  try {
    J r = g_ch->Call("A", "pins_for", a);
    for (auto& [k, v] : RespGet(r, "pins").obj) {
      efs::AnchorState s;
      s.generation = UnU64(RespGet(v, "gen"));
      s.manifest_id = RespGet(v, "mid").str;
      s.digest = Unbytes(RespGet(v, "digest"));
      out[(uint64_t)std::strtoull(k.c_str(), nullptr, 10)] = s;
    }
  } catch (const SimCrashWire&) { throw; }
  return out;
}

// ---- broker ----
efs::Result<std::vector<uint8_t>> ProxyBroker::ReserveNonce(
    uint32_t tenant, uint32_t epoch) {
  J a = Hargs(h_);
  a.arr.push_back(J::Num(tenant));
  a.arr.push_back(J::Num(epoch));
  try {
    J r = g_ch->Call("B", "reserve", a);
    efs::Err e = (efs::Err)(int)RespNum(r, "err");
    if (e != efs::Err::OK)
      return efs::Result<std::vector<uint8_t>>::Fail(e);
    return efs::Result<std::vector<uint8_t>>::Ok(
        Unbytes(RespGet(r, "nonce")));
  } catch (const SimCrashWire&) { throw; }
}
efs::Result<std::vector<uint8_t>> ProxyBroker::Seal(
    uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& plaintext) {
  J a = Hargs(h_);
  a.arr.push_back(J::Num(tenant));
  a.arr.push_back(J::Num(epoch));
  a.arr.push_back(Bytes(nonce));
  a.arr.push_back(Bytes(aad));
  a.arr.push_back(Bytes(plaintext));
  try {
    J r = g_ch->Call("B", "seal", a);
    efs::Err e = (efs::Err)(int)RespNum(r, "err");
    if (e != efs::Err::OK)
      return efs::Result<std::vector<uint8_t>>::Fail(e);
    return efs::Result<std::vector<uint8_t>>::Ok(Unbytes(RespGet(r, "ct")));
  } catch (const SimCrashWire&) { throw; }
}
efs::Result<std::vector<uint8_t>> ProxyBroker::Open(
    uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& ciphertext_and_tag) {
  J a = Hargs(h_);
  a.arr.push_back(J::Num(tenant));
  a.arr.push_back(J::Num(epoch));
  a.arr.push_back(Bytes(nonce));
  a.arr.push_back(Bytes(aad));
  a.arr.push_back(Bytes(ciphertext_and_tag));
  try {
    J r = g_ch->Call("B", "open", a);
    efs::Err e = (efs::Err)(int)RespNum(r, "err");
    if (e != efs::Err::OK)
      return efs::Result<std::vector<uint8_t>>::Fail(e);
    return efs::Result<std::vector<uint8_t>>::Ok(Unbytes(RespGet(r, "pt")));
  } catch (const SimCrashWire&) { throw; }
}

// ---- allocator ----
efs::Result<std::vector<uint8_t>*> ProxyAlloc::Allocate(size_t n) {
  J a = Hargs(h_);
  a.arr.push_back(J::Num((double)n));
  try {
    J r = g_ch->Call("M", "alloc", a);
    efs::Err e = (efs::Err)(int)RespNum(r, "err");
    if (e != efs::Err::OK)
      return efs::Result<std::vector<uint8_t>*>::Fail(e);
    uint64_t id = UnU64(RespGet(r, "buf"));
    auto* v = new std::vector<uint8_t>(n);
    ids_[v] = id;
    ptrs_[id] = v;
    return efs::Result<std::vector<uint8_t>*>::Ok(v);
  } catch (const SimCrashWire&) { throw; }
}
ProxyAlloc::~ProxyAlloc() {
  for (auto& [p, _] : ids_) delete p;
}
void ProxyAlloc::SecureErase(std::vector<uint8_t>* buf) {
  auto it = ids_.find(buf);
  if (it == ids_.end()) return;
  J a = Hargs(h_);
  a.arr.push_back(U64(it->second));
  CallErr("M", "erase", a);
  if (!buf->empty())
    std::memset(buf->data(), 0, buf->size());  // shadow hygiene
}
void ProxyAlloc::Release(std::vector<uint8_t>* buf) {
  auto it = ids_.find(buf);
  if (it == ids_.end()) return;
  J a = Hargs(h_);
  a.arr.push_back(U64(it->second));
  CallErr("M", "release", a);
  ptrs_.erase(it->second);
  ids_.erase(it);
  delete buf;
}
void ProxyAlloc::Copy(std::vector<uint8_t>* dst, const uint8_t* src, size_t n,
                      size_t dst_off) {
  auto it = ids_.find(dst);
  if (it == ids_.end()) return;
  if (n > 0 && src == nullptr) return;
  std::vector<uint8_t> chunk(src, src + n);
  if (n <= dst->size() && dst_off <= dst->size() - n) {
    if (n > 0) std::memcpy(dst->data() + dst_off, src, n);
  }
  J a = Hargs(h_);
  a.arr.push_back(U64(it->second));
  a.arr.push_back(Bytes(chunk));
  a.arr.push_back(J::Num((double)dst_off));
  CallErr("M", "copy", a);
}
std::vector<uint8_t> ProxyAlloc::Read(std::vector<uint8_t>* buf) {
  auto it = ids_.find(buf);
  if (it == ids_.end()) return {};
  J a = Hargs(h_);
  a.arr.push_back(U64(it->second));
  try {
    return Unbytes(RespGet(g_ch->Call("M", "read", a), "bytes"));
  } catch (const SimCrashWire&) { throw; }
}

// ---- leases ----
uint64_t ProxyLeases::Admit(const std::vector<std::string>& object_ids) {
  J a = Hargs(h_);
  J ids = J::Arr();
  for (auto& id : object_ids) ids.arr.push_back(J::Str(id));
  a.arr.push_back(ids);
  try {
    return UnU64(RespGet(g_ch->Call("L", "admit", a), "lease"));
  } catch (const SimCrashWire&) { throw; }
}
void ProxyLeases::ReleaseLease(uint64_t lease) {
  J a = Hargs(h_);
  a.arr.push_back(U64(lease));
  CallErr("L", "release", a);
}
std::set<std::string> ProxyLeases::Protected() const {
  J a = Hargs(h_);
  std::set<std::string> out;
  try {
    J r = g_ch->Call("L", "protected", a);
    for (auto& e : RespGet(r, "ids").arr) out.insert(e.str);
  } catch (const SimCrashWire&) { throw; }
  return out;
}

}  // namespace sealed
