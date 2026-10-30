// Verification suites, part 3: leakage/resources (+budget derivation)
// and anti-cheat controls.
#include "grader/fmt.h"
#include "grader/oracle.h"
#include "grader/suites.h"
#include "trusted/admin.h"
#include "trusted/world.h"

#include <fstream>

namespace grader {
namespace suites {

using efs::TenantCap;

bool RunBudgetWorkload(efs::IDriverFactory& factory, const Profile& p,
                       efs::IManagedAllocator::Metrics& out);

// Section 6 rule: budgets are 2x the reference's allocation count and
// copied bytes, peak at most 2x reference peak plus 64 KiB, zero
// orphaned managed buffers after quiescence.
Budgets DeriveBudgets(const efs::IManagedAllocator::Metrics& ref) {
  Budgets b;
  b.max_alloc_count = 2 * ref.alloc_count;
  b.max_copied_bytes = 2 * ref.copied_bytes;
  b.max_peak_managed = 2 * ref.peak_managed + 65536;
  b.max_live_after_quiescence = 0;
  if (b.max_alloc_count == 0) b.max_alloc_count = 10000;
  if (b.max_copied_bytes == 0) b.max_copied_bytes = 1 << 20;
  if (b.max_peak_managed < 65536) b.max_peak_managed = 65536;
  return b;
}

bool ImageContains(const std::map<std::string, std::vector<uint8_t>>& img,
                   const std::vector<uint8_t>& needle) {
  if (needle.empty()) return false;
  for (auto& [_, hay] : img) {
    if (hay.size() < needle.size()) continue;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
      bool eq = true;
      for (size_t j = 0; j < needle.size(); ++j)
        if (hay[i + j] != needle[j]) {
          eq = false;
          break;
        }
      if (eq) return true;
    }
  }
  return false;
}

void SuiteLeakage(efs::IDriverFactory& factory, const Profile& p,
                  const Budgets* budgets, Counts& c,
                  efs::IManagedAllocator::Metrics* observed) {
  // Erasure takes effect on the measured buffer: allocate, fill through
  // the managed path, erase, then read back zeros. tw.world.alloc() is
  // the authoritative allocator in both paths (in-process directly;
  // sealed via verifier-side dispatch), so this verifies the bytes the
  // grader measures — not just the violation counter.
  {
    TestWorld tw;
    tw.factory = &factory;
    efs::IDriver* d = tw.Open(0);
    (void)d;
    auto ar = tw.world.alloc()->Allocate(4096);
    c.Check(ar.ok(), "erase-rb alloc");
    if (ar.ok()) {
      auto* buf = ar.value;
      std::vector<uint8_t> secret = Pattern(4096, 77);
      tw.world.alloc()->Copy(buf, secret.data(), secret.size(), 0);
      bool staged = buf->size() == 4096 && (*buf)[0] == secret[0];
      c.Check(staged, "erase-rb staged");
      tw.world.alloc()->SecureErase(buf);
      bool allzero = true;
      for (uint8_t b : *buf)
        if (b != 0) {
          allzero = false;
          break;
        }
      c.Check(allzero, "erase read-back zeroed");
      tw.world.alloc()->Release(buf);
    }
  }
  // Erasure + quiescence on a dedicated world exercising success,
// error, and cancel paths.
  {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0);
    efs::IDriver* d = tw.Open(0);
    auto secret = Pattern(5000, 201);
    std::vector<uint8_t> marker(secret.begin(), secret.begin() + 64);
    c.Check(d->Put(c0, tw.Op(), "s", secret).ok(), "leak setup");
    // Error path: failing op must still erase.
    tw.world.admin_alloc()->SetFailurePlan({1});
    auto r = d->Put(c0, tw.Op(), "fail", Pattern(5000, 202));
    tw.world.admin_alloc()->SetFailurePlan({});
    c.Check(r.err == efs::Err::OUT_OF_MEMORY || r.ok(), "leak fail named");
    // Cancel path.
    std::vector<uint8_t> in = Pattern(3000, 203);
    uint64_t op = tw.Op();
    if (d->PutAsync(c0, op, "cx", in) == efs::Err::OK)
      c.Check(d->Cancel(op).err == efs::Err::CANCELLED, "leak cancel");
    // Async success path.
    uint64_t op2 = tw.Op();
    if (d->PutAsync(c0, op2, "ok", in) == efs::Err::OK)
      c.Check(d->Await(op2).ok(), "leak await");
    auto m = tw.world.admin_alloc()->GetMetrics();
    c.Check(m.erasure_violations == 0, "leak no erasure violations");
    // Backing-store scan within declared scope: no plaintext payloads.
    c.Check(!ImageContains(tw.world.Image(), marker),
            "leak no plaintext in durable image");
    if (observed) *observed = m;
  }
  // Budget workload + enforcement.
  {
    efs::IManagedAllocator::Metrics m;
    bool completed = RunBudgetWorkload(factory, p, m);
    c.Check(completed, "budget workload completed (no valid-op failure)");
    c.Check(m.erasure_violations == 0, "budget erasure clean");
    c.Check(m.live_buffers == 0 && m.live_managed == 0,
            "budget zero orphaned buffers");
    if (budgets) {
      c.Check(m.alloc_count <= budgets->max_alloc_count,
              "budget alloc count");
      c.Check(m.copied_bytes <= budgets->max_copied_bytes,
              "budget copied bytes");
      c.Check(m.peak_managed <= budgets->max_peak_managed, "budget peak");
    }
    if (observed) *observed = m;
  }
}

// ---- degenerate mock candidates: must never earn strict success ----
class RejectAll : public efs::IDriver {
 public:
  efs::Result<efs::ReadOut> Read(const efs::TenantCap&, const std::string&,
                                 uint64_t, size_t) override {
    return efs::Result<efs::ReadOut>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> Put(const efs::TenantCap&, uint64_t, const std::string&,
                        const std::vector<uint8_t>&) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> WriteRange(const efs::TenantCap&, uint64_t,
                               const std::string&, uint64_t,
                               const std::vector<uint8_t>&) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> Truncate(const efs::TenantCap&, uint64_t,
                             const std::string&, uint64_t) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> Rename(const efs::TenantCap&, uint64_t, const std::string&,
                           const std::string&) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> Remove(const efs::TenantCap&, uint64_t,
                           const std::string&) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Err PutAsync(const efs::TenantCap&, uint64_t, const std::string&,
                    const std::vector<uint8_t>&) override {
    return efs::Err::PERMISSION_DENIED;
  }
  efs::Result<void> Await(uint64_t) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> Cancel(uint64_t) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<efs::SnapshotHandle> Snapshot(const efs::TenantCap&,
                                            uint64_t) override {
    return efs::Result<efs::SnapshotHandle>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<efs::ReadOut> ReadSnapshot(const efs::TenantCap&,
                                         efs::SnapshotHandle,
                                         const std::string&, uint64_t,
                                         size_t) override {
    return efs::Result<efs::ReadOut>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> ReleaseSnapshot(const efs::TenantCap&,
                                    efs::SnapshotHandle) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> BeginRotation(const efs::TenantCap&, uint64_t) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> MigrateFile(const efs::TenantCap&, uint64_t,
                                const std::string&) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> FinishRotation(const efs::TenantCap&, uint64_t) override {
    return efs::Result<void>::Fail(efs::Err::PERMISSION_DENIED);
  }
  efs::Result<void> Recover() override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> Collect() override {
    return efs::Result<void>::Ok();
  }
};

class FakeAck : public efs::IDriver {
 public:
  std::map<std::string, std::vector<uint8_t>> mem;
  efs::Result<efs::ReadOut> Read(const efs::TenantCap&, const std::string& n,
                                 uint64_t off, size_t len) override {
    auto it = mem.find(n);
    if (it == mem.end())
      return efs::Result<efs::ReadOut>::Fail(efs::Err::NOT_FOUND);
    efs::ReadOut o;
    if (off < it->second.size())
      o.data.insert(o.data.end(), it->second.begin() + off,
                    it->second.begin() +
                        std::min(it->second.size(), (size_t)off + len));
    return efs::Result<efs::ReadOut>::Ok(std::move(o));
  }
  // Forged acknowledgement: reports success without publishing anything.
  efs::Result<void> Put(const efs::TenantCap&, uint64_t, const std::string&,
                        const std::vector<uint8_t>&) override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> WriteRange(const efs::TenantCap&, uint64_t,
                               const std::string&, uint64_t,
                               const std::vector<uint8_t>&) override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> Truncate(const efs::TenantCap&, uint64_t,
                             const std::string&, uint64_t) override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> Rename(const efs::TenantCap&, uint64_t, const std::string&,
                           const std::string&) override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> Remove(const efs::TenantCap&, uint64_t,
                           const std::string&) override {
    return efs::Result<void>::Ok();
  }
  efs::Err PutAsync(const efs::TenantCap&, uint64_t, const std::string&,
                    const std::vector<uint8_t>&) override {
    return efs::Err::OK;
  }
  efs::Result<void> Await(uint64_t) override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> Cancel(uint64_t) override {
    return efs::Result<void>::Fail(efs::Err::CANCELLED);
  }
  efs::Result<efs::SnapshotHandle> Snapshot(const efs::TenantCap&,
                                            uint64_t) override {
    return efs::Result<efs::SnapshotHandle>::Ok(1);
  }
  efs::Result<efs::ReadOut> ReadSnapshot(const efs::TenantCap&,
                                         efs::SnapshotHandle,
                                         const std::string&, uint64_t,
                                         size_t) override {
    return efs::Result<efs::ReadOut>::Fail(efs::Err::NOT_FOUND);
  }
  efs::Result<void> ReleaseSnapshot(const efs::TenantCap&,
                                    efs::SnapshotHandle) override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> BeginRotation(const efs::TenantCap&, uint64_t) override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> MigrateFile(const efs::TenantCap&, uint64_t,
                                const std::string&) override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> FinishRotation(const efs::TenantCap&, uint64_t) override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> Recover() override {
    return efs::Result<void>::Ok();
  }
  efs::Result<void> Collect() override {
    return efs::Result<void>::Ok();
  }
};

efs::IDriver* MakeRejectAll() { return new RejectAll(); }
efs::IDriver* MakeFakeAck() { return new FakeAck(); }
// NOTE: MockFactory lives in suites.h (needed by the oracle-rejection
// suite); keep this file free of duplicate definitions.

void SuiteAntiCheat(efs::IDriverFactory& factory, const Profile& p, Counts& c) {
  // 1. Candidate sources must not reach for trusted internals, the
  // reference, hidden schedules, or admin interfaces.
  {
    std::ifstream f("candidate/src/efs_impl.cpp", std::ios::binary);
    std::string src((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    c.Check(!src.empty(), "anticheat source readable");
    bool clean = true;
    for (const char* pat :
         {"trusted/impl.h", "trusted/admin.h", "reference/",
          "admin_broker", "admin_store", "admin_alloc", "admin_anchor",
          "SetDurableImage", "RevokeEpoch", "NonceUseCount",
          "SetFailurePlan", "grader/"})
      if (src.find(pat) != std::string::npos) {
        clean = false;
        c.Check(false, std::string("anticheat forbids ") + pat);
      }
    if (clean) c.Check(true, "anticheat source allowlist");
  }
  // 2. Degenerate strategies are denied strict success.
  {
    MockFactory mf(MakeRejectAll);
    Counts inner;
    SuiteOrdinary(mf, p, inner);
    c.Check(inner.failed > 0, "reject-all denied strict success");
  }
  {
    MockFactory mf(MakeFakeAck);
    Counts inner;
    SuiteOrdinary(mf, p, inner);
    c.Check(inner.failed > 0, "fake-ack ordinary denied strict success");
  }
  {
    MockFactory mf(MakeFakeAck);
    Counts inner;
    SuiteCrash(mf, p, inner);
    c.Check(inner.failed > 0, "fake-ack crash denied strict success");
  }
  // 3. Allocation observability is load-bearing, not decorative.
  // A bypass that moves no bytes through the managed path must be
  // denied; the evaluated factory must register managed traffic on
  // the fixed workload (the contract requires routing all graded
  // plaintext transfers through Copy).
  {
    MockFactory mf(MakeFakeAck);
    efs::IManagedAllocator::Metrics bypass;
    RunBudgetWorkload(mf, p, bypass);
    c.Check(bypass.alloc_count == 0, "bypass workload allocates nothing");
    Counts inner;
    SuiteOrdinary(mf, p, inner);
    c.Check(inner.failed > 0 && bypass.alloc_count == 0,
            "zero-alloc bypass denied strict success");
  }
  {
    efs::IManagedAllocator::Metrics m;
    bool completed = RunBudgetWorkload(factory, p, m);
    c.Check(completed && m.alloc_count > 0 && m.copied_bytes > 0,
            "managed path load-bearing");
  }
}

}  // namespace suites
}  // namespace grader
