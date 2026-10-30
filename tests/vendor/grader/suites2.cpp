// Verification suites, part 2: rotation/snapshot/GC, binding,
// replay, failure handling, leakage/resources, anti-cheat.
#include "grader/fmt.h"
#include "grader/oracle.h"
#include "grader/suites.h"
#include "trusted/admin.h"
#include "trusted/world.h"

#include <fstream>

namespace grader {
namespace suites {

using efs::TenantCap;

void SuiteRotation(efs::IDriverFactory& factory, const Profile& p,
                   Counts& c) {
  if (!p.rotation || p.epochs < 2) return;
  TestWorld tw;
  tw.factory = &factory;
  auto c0 = Cap(0);
  efs::IDriver* d = tw.Open(0);
  oracle::LogicalModel m;
  auto v1 = Pattern(5000, 71);
  auto v2 = Pattern(9000, 72);
  m.Put("a", v1);
  m.Put("b", v2);
  c.Check(d->Put(c0, tw.Op(), "a", v1).ok(), "rot setup a");
  c.Check(d->Put(c0, tw.Op(), "b", v2).ok(), "rot setup b");
  if (p.snapshots) {
    auto s = d->Snapshot(c0, tw.Op());
    c.Check(s.ok(), "rot snapshot");
    efs::SnapshotHandle snap = s.ok() ? s.value : 0;
    // Begin rotation; new writes use the new epoch.
    c.Check(d->BeginRotation(c0, tw.Op()).ok(), "rot begin");
    auto v3 = Pattern(100, 73);
    m.Put("c", v3);
    c.Check(d->Put(c0, tw.Op(), "c", v3).ok(), "rot write new epoch");
    // Migrate one file, crash, recover: mixed epochs are legal.
    c.Check(d->MigrateFile(c0, tw.Op(), "a").ok(), "rot migrate a");
    tw.world.Crash();
    d = tw.Open(0);
    c.Check(d->Recover().ok(), "rot recover mid-rotation");
    {
      oracle::CommittedState st;
      std::string why;
      c.Check(oracle::DecryptCommitted(tw.world.admin_store(),
                                       tw.world.admin_anchor(),
                                       tw.world.admin_broker(), 0, st, why),
              "rot mid decrypt: " + why);
      c.Check(oracle::ModelEquals(m, st, why), "rot mid model: " + why);
    }
    // Old snapshot still reads while its objects exist.
    auto sr = d->ReadSnapshot(c0, snap, "a", 0, v1.size());
    c.Check(sr.ok() && sr.value.data == v1, "rot old snapshot read");
    // Finish remaining migration, then finish rotation.
    c.Check(d->MigrateFile(c0, tw.Op(), "b").ok(), "rot migrate b");
    c.Check(d->MigrateFile(c0, tw.Op(), "c").ok(), "rot migrate c");
    c.Check(d->FinishRotation(c0, tw.Op()).ok(), "rot finish");
    // All live blocks at the new epoch (independent decrypt + parse).
    {
      oracle::CommittedState st;
      std::string why;
      c.Check(oracle::DecryptCommitted(tw.world.admin_store(),
                                       tw.world.admin_anchor(),
                                       tw.world.admin_broker(), 0, st, why),
              "rot final decrypt: " + why);
      auto man = tw.world.admin_anchor()->Get(0);
      auto mobj = tw.world.store()->ReadDurable(man.manifest_id);
      fmt::ManifestOuter mo;
      std::string w;
      c.Check(mobj.has_value() && fmt::ParseManifestOuter(mobj.value(), mo, w),
              "rot manifest outer: " + w);
      auto mpt = tw.world.admin_broker()->Open(
          0, mo.epoch, mo.nonce,
          oracle::ManifestAad(0, mo.gen), mo.ct);
      c.Check(mpt.ok(), "rot manifest open");
      fmt::Manifest mm;
      c.Check(fmt::ParseManifestPlain(mpt.value, 0, mo.gen, mm, w),
              "rot manifest plain: " + w);
      for (auto& [name, f] : mm.files)
        for (auto& b : f.blocks)
          c.Check(b.epoch == mm.epoch, "rot block at target epoch");
    }
    // Release then reclaim; live contents stay valid.
    c.Check(d->ReleaseSnapshot(c0, snap).ok(), "rot release");
    if (p.gc) {
      size_t before = tw.world.Image().size();
      c.Check(d->Collect().ok(), "rot collect");
      size_t after = tw.world.Image().size();
      c.Check(after <= before, "rot reclamation converges");
      c.Check(d->Collect().ok(), "rot collect again");
      c.Check(tw.world.Image().size() == after, "rot collect stable");
    }
    auto r = d->Read(c0, "a", 0, v1.size());
    c.Check(r.ok() && r.value.data == v1, "rot live after gc");
    // Released handle rejected; cross-tenant handle rejected.
    c.Check(d->ReadSnapshot(c0, snap, "a", 0, 1).err ==
                efs::Err::INVALID_ARGUMENT,
            "rot released rejected");
    efs::IDriver* d1 = tw.Open(1);
    c.Check(d1->ReadSnapshot(Cap(1), snap, "a", 0, 1).err ==
                efs::Err::INVALID_ARGUMENT,
            "rot cross-tenant rejected");
  }
  // Epoch exhaustion: only epochs-1 rotations possible.
  if ((int)p.epochs <= 3) {
    // Already at epoch 1 after the cycle above; rotating past the last
    // epoch must be rejected (H0 has exactly 3 epochs: 0,1,2).
    efs::Err e = d->BeginRotation(c0, tw.Op()).err;
    // May succeed once more (epoch 2) or be rejected; either way the
    // read path stays valid.
    auto r = d->Read(c0, "a", 0, v1.size());
    c.Check(r.ok() && r.value.data == v1, "rot live after extra begin");
    (void)e;
  }
}

void CorruptImage(Counts& c, TestWorld& tw, const std::string& target,
                  int mode) {
  auto img = tw.world.Image();
  auto it = img.find(target);
  if (it == img.end()) {
    c.Check(false, "corrupt target missing " + target);
    return;
  }
  if (mode == 0 && it->second.size() > 60) it->second[60] ^= 0xFF;  // flip
  if (mode == 1 && it->second.size() > 16) it->second.resize(it->second.size() - 16);  // truncate
  tw.world.SetImage(std::move(img));
}

void SuiteBinding(efs::IDriverFactory& factory, const Profile& p,
                  Counts& c) {
  TestWorld tw;
  tw.factory = &factory;
  auto c0 = Cap(0), c1 = Cap(1);
  efs::IDriver* d0 = tw.Open(0);
  efs::IDriver* d1 = tw.Open(1);
  auto va = Pattern(9000, 81);
  auto vb = Pattern(9000, 82);
  auto vc = Pattern(100, 83);
  c.Check(d0->Put(c0, tw.Op(), "a", va).ok(), "bind setup a");
  c.Check(d0->Put(c0, tw.Op(), "b", vb).ok(), "bind setup b");
  c.Check(d1->Put(c1, tw.Op(), "a", vc).ok(), "bind setup t1");
  auto pristine = tw.world.Image();

  // Find two block ids of file a.
  std::string blk0, blk1;
  for (auto& [id, _] : pristine)
    if (id.rfind("b_0_", 0) == 0) {
      if (blk0.empty())
        blk0 = id;
      else if (blk1.empty())
        blk1 = id;
    }
  c.Check(!blk0.empty() && !blk1.empty(), "bind found blocks");

  // Flip ciphertext byte.
  CorruptImage(c, tw, blk0, 0);
  c.Check(FailClosed(d0->Read(c0, "a", 0, va.size()).err), "bind flip closed");
  tw.world.SetImage(pristine);
  // Truncate object.
  CorruptImage(c, tw, blk0, 1);
  c.Check(FailClosed(d0->Read(c0, "a", 0, va.size()).err),
          "bind truncate closed");
  tw.world.SetImage(pristine);
  // Swap two valid blocks across offsets (same file): index binding.
  {
    auto img = tw.world.Image();
    std::swap(img[blk0], img[blk1]);
    tw.world.SetImage(std::move(img));
    c.Check(FailClosed(d0->Read(c0, "a", 0, va.size()).err),
            "bind swap offsets closed");
    tw.world.SetImage(pristine);
  }
  // Swap across files (file binding: different file_id, not just a
  // different block of the same file).
  {
    auto file_id_of = [](const std::string& oid) -> std::string {
      // b_<tenant>_<file_id>_<cver>_<idx>_<epoch>
      size_t p1 = oid.find('_', 2);
      if (p1 == std::string::npos) return "";
      size_t p2 = oid.find('_', p1 + 1);
      if (p2 == std::string::npos) return "";
      return oid.substr(p1 + 1, p2 - p1 - 1);
    };
    std::string fid0 = file_id_of(blk0);
    std::string other;
    for (auto& [id, _] : pristine)
      if (id.rfind("b_0_", 0) == 0 && !fid0.empty() &&
          file_id_of(id) != fid0) {
        other = id;
        break;
      }
    c.Check(!other.empty(), "bind found cross-file block");
    if (!other.empty()) {
      auto img = tw.world.Image();
      std::swap(img[blk0], img[other]);
      tw.world.SetImage(std::move(img));
      auto r = d0->Read(c0, "a", 0, va.size());
      c.Check(FailClosed(r.err), "bind swap files closed");
      tw.world.SetImage(pristine);
    }
  }
  // Swap across tenants.
  {
    std::string t1blk;
    for (auto& [id, _] : pristine)
      if (id.rfind("b_1_", 0) == 0) {
        t1blk = id;
        break;
      }
    if (!t1blk.empty()) {
      auto img = tw.world.Image();
      std::swap(img[blk0], img[t1blk]);
      tw.world.SetImage(std::move(img));
      c.Check(FailClosed(d0->Read(c0, "a", 0, va.size()).err),
              "bind swap tenants closed");
      tw.world.SetImage(pristine);
    }
  }
  // Alter manifest metadata (flip a ciphertext byte of the manifest).
  {
    std::string mid = tw.world.anchor()->Get(0).manifest_id;
    CorruptImage(c, tw, mid, 0);
    c.Check(FailClosed(d0->Read(c0, "a", 0, va.size()).err),
            "bind manifest flip closed");
    tw.world.SetImage(pristine);
  }
  // Control: pristine image reads fine.
  {
    auto r = d0->Read(c0, "a", 0, va.size());
    c.Check(r.ok() && r.value.data == va, "bind control read");
  }
  // Admin-driven negative controls (sensitivity of the suite itself):
  // revoking a referenced epoch must break reads fail-closed (this is
  // why retirement timing matters).
  if (p.revocation) {
    tw.world.admin_broker()->RevokeEpoch(0, 0);
    c.Check(FailClosed(d0->Read(c0, "a", 0, va.size()).err),
            "bind revoked epoch closed");
    // NOTE: RevokeEpoch is sticky by design. The world is discarded
    // after this suite, so no restore is needed.
  }
}

void SuiteReplay(efs::IDriverFactory& factory, const Profile& p, Counts& c) {
  if (!p.replay) return;
  TestWorld tw;
  tw.factory = &factory;
  auto c0 = Cap(0);
  efs::IDriver* d = tw.Open(0);
  auto v1 = Pattern(5000, 91);
  auto v2 = Pattern(5000, 92);
  c.Check(d->Put(c0, tw.Op(), "f", v1).ok(), "replay setup");
  efs::SnapshotHandle snap = 0;
  if (p.snapshots) {
    auto s = d->Snapshot(c0, tw.Op());
    c.Check(s.ok(), "replay snapshot");
    snap = s.ok() ? s.value : 0;
  }
  auto old_image = tw.world.Image();
  c.Check(d->Put(c0, tw.Op(), "f", v2).ok(), "replay advance");
  c.Check(d->Put(c0, tw.Op(), "g", v1).ok(), "replay advance2");
  // Restore the whole old storage image; anchor stays newer.
  tw.world.SetImage(old_image);
  auto r = d->Read(c0, "f", 0, v2.size());
  // Live reads must fail closed (newer committed objects are missing from
  // the replayed image); any OK -- stale, cached, or fabricated -- is an
  // unauthenticated success and must not pass.
  c.Check(!r.ok() && FailClosed(r.err), "replay live fail-closed");
  if (p.snapshots && snap != 0) {
    // The pinned snapshot's objects exist in the old image: readable.
    auto sr = d->ReadSnapshot(c0, snap, "f", 0, v1.size());
    c.Check(sr.ok() && sr.value.data == v1, "replay snapshot readable");
  }
}

void SuiteFailures(efs::IDriverFactory& factory, const Profile& p, Counts& c) {
  // Deterministic allocation failure at supported sites.
  for (uint64_t seq : {1, 2, 3, 5, 8}) {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0);
    efs::IDriver* d = tw.Open(0);
    auto base = Pattern(3000, 101);
    c.Check(d->Put(c0, tw.Op(), "base", base).ok(), "fail setup");
    uint64_t gen_before = tw.world.anchor()->Get(0).generation;
    tw.world.admin_alloc()->SetFailurePlan({seq});
    auto big = Pattern(9000, 102);
    auto r = d->Put(c0, tw.Op(), "big", big);
    tw.world.admin_alloc()->SetFailurePlan({});
    if (r.err == efs::Err::OUT_OF_MEMORY) {
      c.Check(true, "fail alloc named error");
      // Earlier commits preserved; partial resources released.
      d = tw.Open(0);
      c.Check(d->Recover().ok(), "fail recover");
      auto rr = d->Read(c0, "base", 0, base.size());
      c.Check(rr.ok() && rr.value.data == base, "fail prior intact");
      c.Check(tw.world.anchor()->Get(0).generation == gen_before,
              "fail no phantom commit");
      auto m = tw.world.admin_alloc()->GetMetrics();
      c.Check(m.erasure_violations == 0, "fail erasure clean");
    } else if (r.ok()) {
      // Failure plan missed every graded site for this shape; the op
      // succeeding is legal, state must still verify.
      oracle::LogicalModel mm;
      mm.Put("base", base);
      mm.Put("big", big);
      CheckTenant(c, tw, 0, mm, "fail seq missed");
    } else {
      c.Check(false, "fail unexpected error " +
                         std::string(efs::ToString(r.err)));
    }
  }
  // Temporary broker failure.
  if (p.outage) {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0);
    efs::IDriver* d = tw.Open(0);
    tw.world.admin_broker()->SetEpochAvailable(0, 0, false);
    auto r = d->Put(c0, tw.Op(), "x", {1, 2, 3});
    c.Check(r.err == efs::Err::KEY_UNAVAILABLE, "outage named error");
    c.Check(tw.world.anchor()->Get(0).generation == 0, "outage no commit");
    tw.world.admin_broker()->SetEpochAvailable(0, 0, true);
    c.Check(d->Put(c0, tw.Op(), "x", {1, 2, 3}).ok(), "outage recover");
    auto rr = d->Read(c0, "x", 0, 3);
    c.Check(rr.ok() && rr.value.data == std::vector<uint8_t>({1, 2, 3}),
            "outage bytes");
  }
}

// Budget workload: single-file sizes from the profile (H0 narrowed to
// 16 KiB .. 256 KiB; larger entries exceed the 256 KiB per-file limit and
// cannot be single-file Puts, so they are skipped here) plus bounded
// operation mixes. Every valid op must succeed; any failure truncates
// nothing silently (returns false). Seeds from the profile drive fixture
// bytes (content varies, sizes/metrics do not).
bool RunBudgetWorkload(efs::IDriverFactory& factory, const Profile& p,
                       efs::IManagedAllocator::Metrics& out) {
  TestWorld tw;
  tw.factory = &factory;
  auto c0 = Cap(0);
  efs::IDriver* d = tw.Open(0);
  uint64_t op = 100000;
  uint64_t seed0 = p.seeds.empty() ? 11 : p.seeds[0];
  bool ok = true;
  for (size_t n : p.workload_bytes) {
    if (n == 0 || n > 262144) continue;  // not a valid single-file size
    auto v = Pattern(n, seed0 + n);
    if (!d->Put(c0, op++, "w", v).ok()) {
      ok = false;
      break;
    }
    auto r = d->Read(c0, "w", 0, n);
    if (!r.ok() || r.value.data != v) {
      ok = false;
      break;
    }
    auto patch = Pattern(4096, seed0 + n + 1);
    if (!d->WriteRange(c0, op++, "w", 100, patch).ok()) {
      ok = false;
      break;
    }
    if (!d->Truncate(c0, op++, "w", n / 2).ok()) {
      ok = false;
      break;
    }
  }
  // 15 small files + "w" = 16 live (the per-tenant limit); 20 would
  // exceed it and fail valid-op completion.
  for (int i = 0; ok && i < 15; ++i) {
    auto v = Pattern(1000 + (size_t)i * 100, seed0 + 500 + (uint64_t)i);
    if (!d->Put(c0, op++, "m" + std::to_string(i), v).ok()) ok = false;
  }
  for (int i = 0; ok && i < 15; ++i)
    if (!d->Remove(c0, op++, "m" + std::to_string(i)).ok()) ok = false;
  if (ok && !d->Collect().ok()) ok = false;
  out = tw.world.admin_alloc()->GetMetrics();
  return ok;
}

}  // namespace suites
}  // namespace grader
