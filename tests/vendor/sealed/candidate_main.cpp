// Candidate process entry: implements D.* over the sealed channel using
// the real driver factory, with all services proxied to the verifier.
// Ships in the candidate image. Build twice: default (candidate factory)
// and -DUSE_REFERENCE (reference factory, for verifier self-checks).
#include <unistd.h>

#include <cstdio>
#include <map>
#include <memory>
#include <random>
#include <string>

#include "sealed/rpc.h"
#include "sealed/service_proxy.h"
#ifdef USE_REFERENCE
#include "reference/efs_impl.h"
#else
#include "candidate/src/efs_impl.h"
#endif

namespace {

sealed::Channel* g_ch = nullptr;
std::mt19937_64 g_rng(0x5EA1EDu);

struct Bundle {
  std::unique_ptr<sealed::ProxyStore> store;
  std::unique_ptr<sealed::ProxyAnchor> anchor;
  std::unique_ptr<sealed::ProxyBroker> broker;
  std::unique_ptr<sealed::ProxyAlloc> alloc;
  std::unique_ptr<sealed::ProxyLeases> leases;
  // Owning: D.close must reclaim the driver, not just forget it.
  std::unique_ptr<efs::IDriver> driver;
};
std::map<uint64_t, std::unique_ptr<Bundle>> g_handles;

efs::TenantCap CapOf(const sealed::J& a, size_t i) {
  efs::TenantCap c;
  c.tenant = sealed::ArgU32(a, i);
  c.secret = sealed::ArgU64(a, i + 1);
  return c;
}

sealed::J ErrJ(efs::Err e) {
  sealed::J r = sealed::J::Obj();
  r.obj["err"] = sealed::J::Num((int)e);
  return r;
}

Bundle* H(const sealed::J& a) {
  uint64_t h = sealed::ArgU64(a, 0);
  auto it = g_handles.find(h);
  if (it == g_handles.end()) throw sealed::RemoteError("bad handle");
  return it->second.get();
}

#ifdef USE_REFERENCE
efs::reference::Factory g_factory;
#else
efs::candidate::Factory g_factory;
#endif

void Register() {
  using sealed::J;
  g_ch->On("D.open", [](const J& a) {
    uint32_t tenant = sealed::ArgU32(a, 0);
    uint64_t h = g_rng();
    while (h == 0 || g_handles.count(h)) h = g_rng();
    auto b = std::make_unique<Bundle>();
    b->store = std::make_unique<sealed::ProxyStore>(h);
    b->anchor = std::make_unique<sealed::ProxyAnchor>(h);
    b->broker = std::make_unique<sealed::ProxyBroker>(h);
    b->alloc = std::make_unique<sealed::ProxyAlloc>(h);
    b->leases = std::make_unique<sealed::ProxyLeases>(h);
    b->driver.reset(g_factory.OpenHandle(tenant, b->store.get(),
                                           b->anchor.get(), b->broker.get(),
                                           b->alloc.get(), b->leases.get()));
    g_handles[h] = std::move(b);
    J r = J::Obj();
    r.obj["h"] = sealed::U64(h);
    return r;
  });
  g_ch->On("D.close", [](const J& a) {
    g_handles.erase(sealed::ArgU64(a, 0));
    return J::Obj();
  });
  g_ch->On("D.read", [](const J& a) {
    auto r = H(a)->driver->Read(CapOf(a, 1), sealed::ArgStr(a, 3),
                                sealed::ArgU64(a, 4),
                                (size_t)sealed::ArgU64(a, 5));
    J o = ErrJ(r.err);
    if (r.ok()) o.obj["data"] = sealed::Bytes(r.value.data);
    return o;
  });
  g_ch->On("D.put", [](const J& a) {
    auto r = H(a)->driver->Put(CapOf(a, 1), sealed::ArgU64(a, 3),
                               sealed::ArgStr(a, 4), sealed::ArgBytes(a, 5));
    return ErrJ(r.err);
  });
  g_ch->On("D.write_range", [](const J& a) {
    auto r = H(a)->driver->WriteRange(CapOf(a, 1), sealed::ArgU64(a, 3),
                                      sealed::ArgStr(a, 4), sealed::ArgU64(a, 5),
                                      sealed::ArgBytes(a, 6));
    return ErrJ(r.err);
  });
  g_ch->On("D.truncate", [](const J& a) {
    auto r = H(a)->driver->Truncate(CapOf(a, 1), sealed::ArgU64(a, 3),
                                    sealed::ArgStr(a, 4), sealed::ArgU64(a, 5));
    return ErrJ(r.err);
  });
  g_ch->On("D.rename", [](const J& a) {
    auto r = H(a)->driver->Rename(CapOf(a, 1), sealed::ArgU64(a, 3),
                                  sealed::ArgStr(a, 4), sealed::ArgStr(a, 5));
    return ErrJ(r.err);
  });
  g_ch->On("D.remove", [](const J& a) {
    auto r = H(a)->driver->Remove(CapOf(a, 1), sealed::ArgU64(a, 3),
                                  sealed::ArgStr(a, 4));
    return ErrJ(r.err);
  });
  g_ch->On("D.put_async", [](const J& a) {
    efs::Err e = H(a)->driver->PutAsync(CapOf(a, 1), sealed::ArgU64(a, 3),
                                        sealed::ArgStr(a, 4),
                                        sealed::ArgBytes(a, 5));
    return ErrJ(e);
  });
  g_ch->On("D.await", [](const J& a) {
    return ErrJ(H(a)->driver->Await(sealed::ArgU64(a, 1)).err);
  });
  g_ch->On("D.cancel", [](const J& a) {
    return ErrJ(H(a)->driver->Cancel(sealed::ArgU64(a, 1)).err);
  });
  g_ch->On("D.snapshot", [](const J& a) {
    auto r = H(a)->driver->Snapshot(CapOf(a, 1), sealed::ArgU64(a, 3));
    J o = ErrJ(r.err);
    if (r.ok()) o.obj["snap"] = sealed::U64(r.value);
    return o;
  });
  g_ch->On("D.read_snapshot", [](const J& a) {
    auto r = H(a)->driver->ReadSnapshot(CapOf(a, 1), sealed::ArgU64(a, 3),
                                        sealed::ArgStr(a, 4), sealed::ArgU64(a, 5),
                                        (size_t)sealed::ArgU64(a, 6));
    J o = ErrJ(r.err);
    if (r.ok()) o.obj["data"] = sealed::Bytes(r.value.data);
    return o;
  });
  g_ch->On("D.release_snapshot", [](const J& a) {
    auto r = H(a)->driver->ReleaseSnapshot(CapOf(a, 1),
                                           sealed::ArgU64(a, 3));
    return ErrJ(r.err);
  });
  g_ch->On("D.begin_rotation", [](const J& a) {
    auto r = H(a)->driver->BeginRotation(CapOf(a, 1),
                                         sealed::ArgU64(a, 3));
    return ErrJ(r.err);
  });
  g_ch->On("D.migrate_file", [](const J& a) {
    auto r = H(a)->driver->MigrateFile(CapOf(a, 1), sealed::ArgU64(a, 3),
                                       sealed::ArgStr(a, 4));
    return ErrJ(r.err);
  });
  g_ch->On("D.finish_rotation", [](const J& a) {
    auto r = H(a)->driver->FinishRotation(CapOf(a, 1),
                                          sealed::ArgU64(a, 3));
    return ErrJ(r.err);
  });
  g_ch->On("D.recover", [](const J& a) { return ErrJ(H(a)->driver->Recover().err); });
  g_ch->On("D.collect", [](const J& a) { return ErrJ(H(a)->driver->Collect().err); });
}

}  // namespace

int main(int argc, char** argv) {
  // argv[1] = staging dir: confine filesystem access for snooper tests.
  if (argc > 1 && chdir(argv[1]) != 0) {
    std::perror("chdir staging");
    return 2;
  }
  sealed::Channel ch(3);
  g_ch = &ch;
  sealed::SetChannel(&ch);
  Register();
  ch.Serve();
  return 0;
}
