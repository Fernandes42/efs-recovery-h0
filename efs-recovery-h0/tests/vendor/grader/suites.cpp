// Verification suites, part 1: ordinary semantics, crash sweep,
// repeated recovery, async memory, nonce lifecycle.
#include "grader/fmt.h"
#include "grader/oracle.h"
#include "grader/suites.h"
#include "trusted/admin.h"
#include "trusted/world.h"

namespace grader {
namespace suites {

using efs::TenantCap;

bool FailClosed(efs::Err e) {
  return e == efs::Err::AUTHENTICATION_FAILED ||
         e == efs::Err::CORRUPT_COMMITTED_STATE ||
         e == efs::Err::STALE_ROOT ||
         e == efs::Err::KEY_UNAVAILABLE;
}

// Compare driver-committed state for one tenant against the model.
void CheckTenant(Counts& c, TestWorld& tw, uint32_t tenant,
                 oracle::LogicalModel& model, const std::string& where) {
  oracle::CommittedState st;
  std::string why;
  bool ok = oracle::DecryptCommitted(tw.world.admin_store(),
                                     tw.world.admin_anchor(),
                                     tw.world.admin_broker(), tenant, st, why);
  c.Check(ok, where + " decrypt: " + why);
  if (!ok) return;
  c.Check(oracle::ModelEquals(model, st, why), where + " model: " + why);
}

void CheckRead(Counts& c, efs::IDriver* d, const TenantCap& cap,
               const std::string& name,
               const std::vector<uint8_t>& expect, const std::string& where) {
  auto r = d->Read(cap, name, 0, expect.size() + 64);
  c.Check(r.ok(), where + " read ok: " + std::string(efs::ToString(r.err)));
  if (r.ok()) c.Check(r.value.data == expect, where + " read bytes");
}

void SuiteOrdinary(efs::IDriverFactory& factory, const Profile& p,
                   Counts& c) {
  TestWorld tw;
  tw.factory = &factory;
  oracle::LogicalModel m0, m1;
  efs::IDriver* d0 = tw.Open(0);
  efs::IDriver* d1 = tw.Open(1);
  auto c0 = Cap(0), c1 = Cap(1);

  // Empty, short-final-block, multi-block fixtures.
  std::vector<std::pair<std::string, std::vector<uint8_t>>> fixtures = {
      {"empty", {}},
      {"one", {0x41}},
      {"block", Pattern(4096, 1)},
      {"blockplus", Pattern(4097, 2)},
      {"multi", Pattern(10000, 3)},
  };
  for (auto& [name, bytes] : fixtures) {
    auto e = m0.Put(name, bytes);
    auto r = d0->Put(c0, tw.Op(), name, bytes);
    c.Check(r.err == e, "put " + name);
    CheckRead(c, d0, c0, name, bytes, "put " + name);
  }
  CheckTenant(c, tw, 0, m0, "ordinary fixtures");

  // Overwrite + partial-block range overwrites (whole-file only
  // where the profile removes range ops).
  if (p.range_ops) {
    auto patch = Pattern(100, 9);
    c.Check(m0.WriteRange("multi", 100, patch) == efs::Err::OK, "model range");
    auto r = d0->WriteRange(c0, tw.Op(), "multi", 100, patch);
    c.Check(r.ok(), "write_range");
    CheckRead(c, d0, c0, "multi", m0.files["multi"].bytes, "range kept");
    // Range extending the file.
    auto tail = Pattern(5000, 10);
    c.Check(m0.WriteRange("block", 4000, tail) == efs::Err::OK, "model ext");
    c.Check(d0->WriteRange(c0, tw.Op(), "block", 4000, tail).ok(), "ext range");
    CheckRead(c, d0, c0, "block", m0.files["block"].bytes, "ext bytes");
    // F-A option (a): zero-length is a LITERAL per-file commit. It seals
    // + publishes a new manifest root (anchor generation advances) with
    // unchanged content bytes. Publication durability is verified by the
    // CheckTenant below ("ordinary ranges") against the trusted anchor.
    {
      uint64_t gen_before = tw.world.anchor()->Get(0).generation;
      auto expect_before = m0.files["block"].bytes;
      c.Check(m0.WriteRange("block", 10, {}) == efs::Err::OK,
              "model zero range");
      c.Check(d0->WriteRange(c0, tw.Op(), "block", 10, {}).ok(),
              "zero range");
      c.Check(tw.world.anchor()->Get(0).generation == gen_before + 1,
              "zero range commits new generation");
      CheckRead(c, d0, c0, "block", expect_before, "zero range kept");
    }
    // Offset == EOF is a valid zero-length commit point (including
    // offset 0 on an empty file); offset beyond EOF is rejected with
    // no commit.
    {
      uint64_t eof = (uint64_t)m0.files["block"].bytes.size();
      uint64_t gen_before = tw.world.anchor()->Get(0).generation;
      c.Check(d0->WriteRange(c0, tw.Op(), "block", eof, {}).ok(),
              "zero range at EOF");
      c.Check(tw.world.anchor()->Get(0).generation == gen_before + 1,
              "zero range at EOF commits");
      gen_before = tw.world.anchor()->Get(0).generation;
      c.Check(m0.WriteRange("block", eof + 1, {}) ==
                  efs::Err::INVALID_ARGUMENT,
              "model zero range beyond EOF");
      c.Check(d0->WriteRange(c0, tw.Op(), "block", eof + 1, {}).err ==
                  efs::Err::INVALID_ARGUMENT,
              "zero range beyond EOF");
      c.Check(tw.world.anchor()->Get(0).generation == gen_before,
              "zero range beyond EOF no commit");
    }
    {
      uint64_t gen_before = tw.world.anchor()->Get(0).generation;
      c.Check(d0->WriteRange(c0, tw.Op(), "empty", 0, {}).ok(),
              "zero range empty file");
      c.Check(tw.world.anchor()->Get(0).generation == gen_before + 1,
              "zero range empty file commits");
    }
    // Zero-length on a missing file: NOT_FOUND with no commit.
    {
      uint64_t gen_before = tw.world.anchor()->Get(0).generation;
      c.Check(m0.WriteRange("nosuch", 0, {}) == efs::Err::NOT_FOUND,
              "model zero range missing");
      c.Check(d0->WriteRange(c0, tw.Op(), "nosuch", 0, {}).err ==
                  efs::Err::NOT_FOUND,
              "zero range missing");
      c.Check(tw.world.anchor()->Get(0).generation == gen_before,
              "zero range missing no commit");
    }
    // Beyond EOF rejected.
    c.Check(d0->WriteRange(c0, tw.Op(), "block", 999999, {1}).err ==
                efs::Err::INVALID_ARGUMENT,
            "range beyond EOF");
    c.Check(d0->WriteRange(c0, tw.Op(), "nosuch", 0, {1}).err ==
                efs::Err::NOT_FOUND,
            "range missing");
  }
  CheckTenant(c, tw, 0, m0, "ordinary ranges");

  // Shrink-only truncate.
  if (p.range_ops) {
    c.Check(m0.Truncate("multi", 5000) == efs::Err::OK, "model trunc");
    c.Check(d0->Truncate(c0, tw.Op(), "multi", 5000).ok(), "truncate");
    CheckRead(c, d0, c0, "multi", m0.files["multi"].bytes, "trunc bytes");
    c.Check(d0->Truncate(c0, tw.Op(), "multi", 5001).err ==
                efs::Err::INVALID_ARGUMENT,
            "truncate ext rejected");
    c.Check(d0->Truncate(c0, tw.Op(), "multi", 0).ok(), "truncate to zero");
    m0.Truncate("multi", 0);
    CheckRead(c, d0, c0, "multi", {}, "trunc zero bytes");
  }

  // Rename / remove / recreate with stable, never-reused IDs.
  {
    uint64_t id_before = m0.files["block"].id;
    c.Check(m0.Rename("block", "renamed") == efs::Err::OK, "model rename");
    c.Check(d0->Rename(c0, tw.Op(), "block", "renamed").ok(), "rename");
    c.Check(m0.files["renamed"].id == id_before, "model id stable");
    oracle::CommittedState st;
    std::string why;
    c.Check(oracle::DecryptCommitted(tw.world.admin_store(),
                                     tw.world.admin_anchor(),
                                     tw.world.admin_broker(), 0, st, why),
            "decrypt for id: " + why);
    c.Check(st.ids["renamed"] == id_before, "id stable across rename");
    c.Check(d0->Rename(c0, tw.Op(), "renamed", "renamed").ok(), "same rename");
    c.Check(d0->Rename(c0, tw.Op(), "renamed", "empty").err ==
                efs::Err::INVALID_ARGUMENT,
            "rename overwrite rejected");
    c.Check(m0.Remove("renamed") == efs::Err::OK, "model remove");
    c.Check(d0->Remove(c0, tw.Op(), "renamed").ok(), "remove");
    c.Check(m0.Put("renamed", {9, 9}) == efs::Err::OK, "model recreate");
    c.Check(d0->Put(c0, tw.Op(), "renamed", {9, 9}).ok(), "recreate");
    c.Check(m0.files["renamed"].id != id_before, "model new id");
    c.Check(oracle::DecryptCommitted(tw.world.admin_store(),
                                     tw.world.admin_anchor(),
                                     tw.world.admin_broker(), 0, st, why),
            "decrypt for id2: " + why);
    c.Check(st.ids["renamed"] != id_before, "new id after recreate");
  }
  CheckTenant(c, tw, 0, m0, "ordinary rename");

  // Second tenant isolation + error cases.
  {
    auto b = Pattern(3000, 21);
    m1.Put("t1", b);
    c.Check(d1->Put(c1, tw.Op(), "t1", b).ok(), "tenant1 put");
    CheckRead(c, d1, c1, "t1", b, "tenant1 read");
    c.Check(d1->Read(c1, "empty", 0, 1).err == efs::Err::NOT_FOUND,
            "tenant isolation");
    c.Check(d0->Read({0, 123}, "empty", 0, 1).err ==
                efs::Err::PERMISSION_DENIED,
            "bad cap");
    c.Check(d0->Read({1, efs::CapSecretFor(1)}, "empty", 0, 1).err ==
                efs::Err::PERMISSION_DENIED,
            "cross cap");
    c.Check(d0->Read(c0, "missing", 0, 1).err == efs::Err::NOT_FOUND,
            "missing");
    for (const char* bad : {"", "x/y", ".", ".."})
      c.Check(d0->Put(c0, tw.Op(), bad, {1}).err ==
                  efs::Err::INVALID_ARGUMENT,
              std::string("bad name ") + bad);
    c.Check(d0->Put(c0, tw.Op(), "toolarge",
                    std::vector<uint8_t>(262145, 1))
                    .err == efs::Err::INVALID_ARGUMENT,
            "oversize rejected before allocation");
  }
  CheckTenant(c, tw, 0, m0, "ordinary final t0");
  CheckTenant(c, tw, 1, m1, "ordinary final t1");
}

// One crash-sweep case: setup v1, armed fault during overwriting put,
// crash, reopen, recover, then verify legal-history outcome.
void CrashCase(Counts& c, efs::IDriverFactory& factory,
               const std::string& point, bool expect_new) {
  TestWorld tw;
  tw.factory = &factory;
  auto c0 = Cap(0);
  auto v1 = Pattern(9000, 31);
  auto v2 = Pattern(9000, 32);
  {
    efs::IDriver* d = tw.Open(0);
    if (!d->Put(c0, tw.Op(), "f", v1).ok()) {
      c.Check(false, point + ": setup");
      return;
    }
  }
  uint64_t gen_before = tw.world.anchor()->Get(0).generation;
  bool fired = false;
  {
    efs::IDriver* d = tw.Open(0);
    if (point == "data0") tw.world.ArmCrashAfterDataFlush(0);
    if (point == "data-last") tw.world.ArmCrashAfterDataFlush(2);
    if (point == "manifest") tw.world.ArmCrashAfterManifestFlush();
    if (point == "publish") tw.world.ArmCrashAfterPublish();
    try {
      auto r = d->Put(c0, tw.Op(), "f", v2);
      if (point != "ack") {
        c.Check(false, point + ": armed crash did not fire (tamper?)");
        return;
      }
      if (!r.ok()) {
        c.Check(false, point + ": post-ack put failed");
        return;
      }
    } catch (const efs::SimulatedCrash&) {
      fired = true;
    }
    tw.world.Crash();
  }
  if (point != "ack") c.Check(fired, point + ": crash fired");
  {
    efs::IDriver* d = tw.Open(0);
    auto rc = d->Recover();
    uint64_t gen_after = tw.world.anchor()->Get(0).generation;
    if (expect_new) {
      c.Check(rc.ok(), point + ": recover ok: " +
                                std::string(efs::ToString(rc.err)));
      c.Check(gen_after == gen_before + 1, point + ": gen advanced");
      auto r = d->Read(c0, "f", 0, v2.size());
      c.Check(r.ok() && r.value.data == v2, point + ": new data survives");
    } else {
      // Unpublished op: old state intact, op absent. Fail-closed only
      // if the manifest itself dangles (defect); correct code recovers
      // cleanly with old data.
      if (!rc.ok()) {
        c.Check(false, point + ": clean recovery expected, got " +
                                  std::string(efs::ToString(rc.err)));
        return;
      }
      c.Check(gen_after == gen_before, point + ": gen unchanged");
      auto r = d->Read(c0, "f", 0, v1.size());
      c.Check(r.ok() && r.value.data == v1, point + ": old data intact");
    }
  }
}

void SuiteCrash(efs::IDriverFactory& factory, const Profile& p, Counts& c) {
  CrashCase(c, factory, "data0", false);
  if (p.multi_crash) {
    CrashCase(c, factory, "data-last", false);
    CrashCase(c, factory, "manifest", false);
  }
  CrashCase(c, factory, "publish", true);
  CrashCase(c, factory, "ack", true);
}

void SuiteRepeatedRecovery(efs::IDriverFactory& factory, const Profile&,
                           Counts& c) {
  TestWorld tw;
  tw.factory = &factory;
  auto c0 = Cap(0);
  auto v = Pattern(5000, 41);
  efs::IDriver* d = tw.Open(0);
  c.Check(d->Put(c0, tw.Op(), "f", v).ok(), "rr setup");
  uint64_t gen0 = tw.world.anchor()->Get(0).generation;
  tw.world.Crash();
  d = tw.Open(0);
  c.Check(d->Recover().ok(), "rr recover1");
  // Second crash during/after recovery, before any new commit.
  tw.world.Crash();
  d = tw.Open(0);
  c.Check(d->Recover().ok(), "rr recover2");
  c.Check(tw.world.anchor()->Get(0).generation == gen0, "rr gen stable");
  auto r = d->Read(c0, "f", 0, v.size());
  c.Check(r.ok() && r.value.data == v, "rr data intact");
  // Repeated recover on a healthy root.
  c.Check(d->Recover().ok(), "rr healthy");
  c.Check(d->Recover().ok(), "rr healthy twice");
}

void SuiteAsync(efs::IDriverFactory& factory, const Profile& p, Counts& c) {
  TestWorld tw;
  tw.factory = &factory;
  auto c0 = Cap(0);
  efs::IDriver* d = tw.Open(0);

  // Caller mutation after enqueue must not change the captured value.
  {
    std::vector<uint8_t> in = Pattern(6000, 51);
    std::vector<uint8_t> want = in;
    uint64_t op = tw.Op();
    c.Check(d->PutAsync(c0, op, "a", in) == efs::Err::OK, "async enqueue");
    in.assign(in.size(), 0x5A);
    // Overlapping reader observes the old committed version (absent).
    c.Check(d->Read(c0, "a", 0, 1).err == efs::Err::NOT_FOUND,
            "async pending invisible");
    c.Check(d->Await(op).ok(), "async await");
    auto r = d->Read(c0, "a", 0, want.size());
    c.Check(r.ok() && r.value.data == want, "async captured value");
  }
  // Initiating buffer destroyed while admitted work completes.
  {
    uint64_t op = tw.Op();
    {
      std::vector<uint8_t> tmp = Pattern(7000, 52);
      c.Check(d->PutAsync(c0, op, "b", tmp) == efs::Err::OK, "async tmp");
    }
    c.Check(d->Await(op).ok(), "async await after destroy");
    auto r = d->Read(c0, "b", 0, 7000);
    c.Check(r.ok() && r.value.data == Pattern(7000, 52), "async tmp bytes");
  }
  // Pool-slot reuse: same caller storage reused for a second enqueue.
  {
    std::vector<uint8_t> slot = Pattern(4096, 53);
    uint64_t op1 = tw.Op(), op2 = tw.Op();
    c.Check(d->PutAsync(c0, op1, "c1", slot) == efs::Err::OK, "async slot1");
    slot = Pattern(4096, 54);
    c.Check(d->PutAsync(c0, op2, "c2", slot) == efs::Err::OK, "async slot2");
    c.Check(d->Await(op1).ok(), "async await1");
    c.Check(d->Await(op2).ok(), "async await2");
    auto r1 = d->Read(c0, "c1", 0, 4096);
    auto r2 = d->Read(c0, "c2", 0, 4096);
    c.Check(r1.ok() && r1.value.data == Pattern(4096, 53), "async slot1 kept");
    c.Check(r2.ok() && r2.value.data == Pattern(4096, 54), "async slot2 kept");
  }
  // Cancellation before publication wins; afterwards ALREADY_COMMITTED.
  {
    uint64_t op = tw.Op();
    std::vector<uint8_t> in = {1, 2, 3};
    c.Check(d->PutAsync(c0, op, "cancelme", in) == efs::Err::OK, "async pend");
    c.Check(d->Cancel(op).err == efs::Err::CANCELLED, "cancel wins");
    c.Check(d->Read(c0, "cancelme", 0, 1).err == efs::Err::NOT_FOUND,
            "cancelled absent");
    uint64_t op2 = tw.Op();
    c.Check(d->PutAsync(c0, op2, "keep", in) == efs::Err::OK, "async pend2");
    c.Check(d->Await(op2).ok(), "async await2");
    c.Check(d->Cancel(op2).err == efs::Err::ALREADY_COMMITTED,
            "cancel after publish");
    c.Check(d->Cancel(999999).err == efs::Err::NOT_FOUND, "cancel unknown");
  }
  // In-flight overlap at the profile's scale; the fixed contract cap
  // (6) is enforced only when the profile actually fills it.
  {
    int fill = std::min(p.async_in_flight, 6);
    std::vector<uint64_t> ops;
    for (int i = 0; i < fill; ++i) {
      uint64_t op = tw.Op();
      ops.push_back(op);
      std::vector<uint8_t> in = {uint8_t(i)};
      c.Check(d->PutAsync(c0, op, "cap" + std::to_string(i), in) ==
                  efs::Err::OK,
              "async cap fill");
    }
    if (fill >= 6) {
      std::vector<uint8_t> in = {0xFF};
      c.Check(d->PutAsync(c0, tw.Op(), "capover", in) ==
                  efs::Err::INVALID_ARGUMENT,
              "async cap enforced");
    }
    for (size_t i = 0; i < ops.size(); ++i) {
      c.Check(d->Await(ops[i]).ok(), "async cap drain");
    }
  }
}

// Crash an encryption before publication, retry under the same epoch,
// then audit every stored nonce: reuse must be absent (reference) and
// is the starter's planted defect (caught here).
void SuiteNonce(efs::IDriverFactory& factory, const Profile& p, Counts& c) {
  TestWorld tw;
  tw.factory = &factory;
  auto c0 = Cap(0);
  efs::IDriver* d = tw.Open(0);
  auto v = Pattern(9000, 61);
  c.Check(d->Put(c0, tw.Op(), "base", v).ok(), "nonce setup");
  // Crash mid-encryption (before publication), then retry as a new op.
  d = tw.Open(0);
  tw.world.ArmCrashAfterDataFlush(0);
  bool fired = false;
  try {
    d->Put(c0, tw.Op(), "n", v);
  } catch (const efs::SimulatedCrash&) {
    fired = true;
  }
  c.Check(fired, "nonce crash fired");
  tw.world.Crash();
  d = tw.Open(0);
  c.Check(d->Recover().ok(), "nonce recover");
  c.Check(d->Put(c0, tw.Op(), "n", v).ok(), "nonce retry");
  auto r = d->Read(c0, "n", 0, v.size());
  c.Check(r.ok() && r.value.data == v, "nonce retry bytes");
  // Audit: parse every stored data object, check broker use counts.
  size_t reused = 0, total = 0;
  for (auto& [id, bytes] : tw.world.Image()) {
    if (id.empty() || id[0] != 'b') continue;
    fmt::DataOuter h;
    std::string why;
    if (!fmt::ParseDataOuter(bytes, h, why)) continue;
    if (h.tenant != 0) continue;
    ++total;
    size_t uses =
        tw.world.admin_broker()->NonceUseCount(h.tenant, h.epoch, h.nonce);
    if (uses > 1) ++reused;
  }
  c.Check(total > 0, "nonce audit saw objects");
  c.Check(reused == 0, "no nonce reuse across abandoned encryption");
  (void)p;

  // Isolate nonce state from publication ordering: crash after the
  // manifest flush but before publication, so the anchor is unchanged
  // and a retry runs under the same epoch. Only durable reservation
  // survives this; rollbackable derivation reuses nonces.
  {
    TestWorld tw2;
    tw2.factory = &factory;
    efs::IDriver* d2 = tw2.Open(0);
    auto w = Pattern(9000, 62);
    c.Check(d2->Put(c0, tw2.Op(), "base", w).ok(), "nonce2 setup");
    d2 = tw2.Open(0);
    tw2.world.ArmCrashAfterManifestFlush();
    bool f2 = false;
    try {
      d2->Put(c0, tw2.Op(), "m", w);
    } catch (const efs::SimulatedCrash&) {
      f2 = true;
    }
    c.Check(f2, "nonce2 crash fired");
    tw2.world.Crash();
    d2 = tw2.Open(0);
    c.Check(d2->Recover().ok(), "nonce2 recover");
    c.Check(d2->Put(c0, tw2.Op(), "m", w).ok(), "nonce2 retry");
    auto rr = d2->Read(c0, "m", 0, w.size());
    c.Check(rr.ok() && rr.value.data == w, "nonce2 retry bytes");
    size_t re2 = 0, tot2 = 0;
    for (auto& [id, bytes] : tw2.world.Image()) {
      if (id.empty() || id[0] != 'b') continue;
      fmt::DataOuter h;
      std::string why;
      if (!fmt::ParseDataOuter(bytes, h, why)) continue;
      if (h.tenant != 0) continue;
      ++tot2;
      if (tw2.world.admin_broker()->NonceUseCount(h.tenant, h.epoch,
                                                  h.nonce) > 1)
        ++re2;
    }
    c.Check(tot2 > 0, "nonce2 audit saw objects");
    c.Check(re2 == 0, "nonce2 no reuse under same epoch");
  }
}

}  // namespace suites
}  // namespace grader
