// Oracle-rejection suite (release gate 1): the verifier oracle must
// reject malformed formats, wrong bindings, stale roots, missing
// committed objects, forged evidence, and inconsistent
// acknowledgements — observed as explicit rejection verdicts, including
// end-to-end cases where an invalid candidate receives failure.
// A lost response after durable publication is a valid committed
// outcome, not a rejection: rejection targets inconsistent state or
// forged acknowledgements, never a missing response on its own.
#include "grader/fmt.h"
#include "grader/oracle.h"
#include "grader/suites.h"
#include "trusted/admin.h"
#include "trusted/world.h"

#include <cstdint>
#include <stdexcept>

namespace grader {
namespace suites {

using efs::TenantCap;

namespace {

// Decrypt the committed manifest plaintext via verifier-owned observations.
bool LiveManifestPlain(TestWorld& tw, uint32_t tenant,
                       std::vector<uint8_t>& pt, uint64_t& gen) {
  efs::AnchorState a = tw.world.anchor()->Get(tenant);
  if (a.generation == 0) return false;
  auto obj = tw.world.store()->ReadDurable(a.manifest_id);
  if (!obj.has_value()) return false;
  fmt::ManifestOuter mo;
  std::string why;
  if (!fmt::ParseManifestOuter(obj.value(), mo, why)) return false;
  auto dec = tw.world.admin_broker()->Open(
      tenant, mo.epoch, mo.nonce, oracle::ManifestAad(tenant, mo.gen),
      mo.ct);
  if (!dec.ok()) return false;
  pt = dec.value;
  gen = mo.gen;
  return true;
}

void PutU32At(std::vector<uint8_t>& b, size_t off, uint32_t v) {
  // Candidate-influenced plaintext (decrypted committed manifest): bounds
  // before write, never OOB in the privileged grader.
  if (off + 4 < off || off + 4 > b.size())
    throw std::runtime_error("PutU32At out of range");
  for (int i = 0; i < 4; ++i) b[off + i] = uint8_t((v >> (8 * i)) & 0xFF);
}
uint32_t GetU32At(const std::vector<uint8_t>& b, size_t off) {
  if (off + 4 < off || off + 4 > b.size())
    throw std::runtime_error("GetU32At out of range");
  return uint32_t(b[off]) | (uint32_t(b[off + 1]) << 8) |
         (uint32_t(b[off + 2]) << 16) | (uint32_t(b[off + 3]) << 24);
}

// Split manifest plaintext into header(36) + entry byte ranges.
bool SplitEntries(const std::vector<uint8_t>& pt,
                  std::vector<std::vector<uint8_t>>& entries) {
  if (pt.size() < 36) return false;
  size_t off = 36;
  uint32_t fc = GetU32At(pt, 32);
  if (fc > 16) return false;  // format bound; untrusted count, no 4G loop
  for (uint32_t i = 0; i < fc; ++i) {
    size_t start = off;
    if (off + 4 < off || off + 4 > pt.size()) return false;
    uint32_t nl = GetU32At(pt, off);
    if (nl > 64) return false;
    if (off > SIZE_MAX - 4 - nl) return false;
    off += 4 + nl;
    if (off + 28 < off || off + 28 > pt.size()) return false;
    off += 24;  // fid + len + cver
    uint32_t bc = GetU32At(pt, off);
    if (bc > 64) return false;
    off += 4;
    for (uint32_t j = 0; j < bc; ++j) {
      if (off + 16 < off || off + 16 > pt.size()) return false;
      off += 4 + 8;  // idx + cver
      uint32_t ol = GetU32At(pt, off);
      if (ol == 0 || ol > 128) return false;
      if (off > SIZE_MAX - 4 - ol - 8) return false;
      off += 4 + ol + 8;  // oid + epoch + pt_len
      if (off > pt.size()) return false;
    }
    if (off < start || off > pt.size()) return false;
    entries.emplace_back(pt.begin() + start, pt.begin() + off);
  }
  return off == pt.size();
}

}  // namespace

void SuiteOracleRejection(efs::IDriverFactory& factory, const Profile&,
                          Counts& c) {
  // ---- A. malformed manifest plaintext variants ----
  {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0);
    efs::IDriver* d = tw.Open(0);
    std::vector<uint8_t> v = Pattern(100, 301);
    if (!d->Put(c0, tw.Op(), "d1", v).ok() ||
        !d->Put(c0, tw.Op(), "d2", v).ok()) {
      c.Check(false, "reject setup");
      return;
    }
    std::vector<uint8_t> pt;
    uint64_t gen = 0;
    c.Check(LiveManifestPlain(tw, 0, pt, gen), "reject live plaintext");
    if (pt.empty()) return;
    // Mutations below write at offsets 4, 8, 32, 36: require a plausible
    // two-file manifest size before touching candidate-influenced bytes.
    if (pt.size() < 40) {
      c.Check(false, "reject plaintext too small for mutations");
      return;
    }
    fmt::Manifest m;
    std::string why;
    c.Check(fmt::ParseManifestPlain(pt, 0, gen, m, why), "reject sane: " + why);

    auto expect_reject = [&](std::vector<uint8_t> bad, const std::string& n) {
      fmt::Manifest mm;
      std::string w;
      c.Check(!fmt::ParseManifestPlain(bad, 0, gen, mm, w), "reject " + n);
    };
    {  // bad version
      auto b = pt;
      b[4] = 2;
      expect_reject(b, "version");
    }
    {  // generation mismatch
      auto b = pt;
      b[8] ^= 0xFF;
      expect_reject(b, "generation");
    }
    {  // absurd file count (overflow-safe)
      auto b = pt;
      PutU32At(b, 32, 0xFFFFFFFFu);
      expect_reject(b, "file count");
    }
    {  // name length overflow
      auto b = pt;
      PutU32At(b, 36, 0xFFFFFFFFu);
      expect_reject(b, "name length");
    }
    {  // truncation
      auto b = pt;
      b.pop_back();
      expect_reject(b, "truncation");
    }
    {  // trailing bytes
      auto b = pt;
      b.push_back(0);
      expect_reject(b, "trailing");
    }
    {  // duplicate name + duplicate file id
      std::vector<std::vector<uint8_t>> entries;
      bool split_ok = SplitEntries(pt, entries);
      c.Check(split_ok, "reject split");
      if (split_ok && entries.size() == 2) {
        auto b = std::vector<uint8_t>(pt.begin(), pt.begin() + 36);
        PutU32At(b, 32, 2);
        b.insert(b.end(), entries[0].begin(), entries[0].end());
        b.insert(b.end(), entries[0].begin(), entries[0].end());
        expect_reject(b, "duplicate");
      }
    }
    {  // wrong tenant binding
      fmt::Manifest mm;
      std::string w;
      c.Check(!fmt::ParseManifestPlain(pt, 1, gen, mm, w), "reject tenant");
    }
    {  // wrong generation binding
      fmt::Manifest mm;
      std::string w;
      c.Check(!fmt::ParseManifestPlain(pt, 0, gen + 1, mm, w),
              "reject stale gen");
    }
  }

  // ---- B. stale root: anchor newer than the storage image ----
  {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0);
    efs::IDriver* d = tw.Open(0);
    auto v1 = Pattern(5000, 302);
    auto v2 = Pattern(5000, 303);
    d->Put(c0, tw.Op(), "f", v1);
    auto old_image = tw.world.Image();
    d->Put(c0, tw.Op(), "f", v2);
    d->Put(c0, tw.Op(), "g", v1);
    tw.world.SetImage(old_image);  // replay old image under newer anchor
    oracle::CommittedState st;
    std::string why;
    c.Check(!oracle::DecryptCommitted(tw.world.admin_store(),
                                      tw.world.admin_anchor(),
                                      tw.world.admin_broker(), 0, st, why),
            "reject stale root");
    c.Check(!why.empty(), "reject stale reason");
  }

  // ---- C. missing committed object ----
  {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0);
    efs::IDriver* d = tw.Open(0);
    auto v = Pattern(9000, 304);
    if (!d->Put(c0, tw.Op(), "f", v).ok()) {
      c.Check(false, "reject missing setup");
      return;
    }
    std::vector<uint8_t> pt;
    uint64_t gen = 0;
    bool live2 = LiveManifestPlain(tw, 0, pt, gen);
    c.Check(live2, "reject live pt2");
    if (!live2) return;
    fmt::Manifest m;
    std::string why;
    bool parse2 = fmt::ParseManifestPlain(pt, 0, gen, m, why);
    c.Check(parse2, "reject parse2");
    if (!parse2) return;
    if (m.files["f"].blocks.empty()) {
      c.Check(false, "reject has blocks");
      return;
    }
    tw.world.admin_store()->DeleteDurable(m.files["f"].blocks[0].oid);
    oracle::CommittedState st;
    c.Check(!oracle::DecryptCommitted(tw.world.admin_store(),
                                      tw.world.admin_anchor(),
                                      tw.world.admin_broker(), 0, st, why),
            "reject dangling block");
  }

  // ---- D. wrong bindings ----
  {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0), c1 = Cap(1);
    efs::IDriver* d0 = tw.Open(0);
    efs::IDriver* d1 = tw.Open(1);
    auto va = Pattern(9000, 305);
    auto vb = Pattern(9000, 306);
    auto vc = Pattern(9000, 307);
    if (!d0->Put(c0, tw.Op(), "a", va).ok() ||
        !d0->Put(c0, tw.Op(), "b", vb).ok() ||
        !d1->Put(c1, tw.Op(), "a", vc).ok()) {
      c.Check(false, "reject binding setup");
      return;
    }
    auto pristine = tw.world.Image();
    std::vector<std::string> t0;
    std::string t1blk;
    for (auto& [id, _] : pristine) {
      if (id.rfind("b_0_", 0) == 0) t0.push_back(id);
      if (t1blk.empty() && id.rfind("b_1_", 0) == 0) t1blk = id;
    }
    bool have_blocks = t0.size() >= 2;
    c.Check(have_blocks, "reject blocks");
    if (!have_blocks) return;
    oracle::CommittedState st;
    std::string why;
    {  // offset binding: swap two blocks of one file
      auto img = pristine;
      std::swap(img[t0[0]], img[t0[1]]);
      tw.world.SetImage(std::move(img));
      c.Check(!oracle::DecryptCommitted(tw.world.admin_store(),
                                        tw.world.admin_anchor(),
                                        tw.world.admin_broker(), 0, st, why),
              "reject offset swap");
      tw.world.SetImage(pristine);
    }
    {  // file binding: swap across files (find a block of file b)
      std::vector<uint8_t> pt;
      uint64_t gen = 0;
      LiveManifestPlain(tw, 0, pt, gen);
      fmt::Manifest m;
      std::string w;
      fmt::ParseManifestPlain(pt, 0, gen, m, w);
      std::string other = m.files["b"].blocks.empty()
                              ? ""
                              : m.files["b"].blocks[0].oid;
      bool have_other = !other.empty() && other != t0[0];
      c.Check(have_other, "reject other block");
      if (have_other) {
        auto img = pristine;
        std::swap(img[t0[0]], img[other]);
        tw.world.SetImage(std::move(img));
        c.Check(!oracle::DecryptCommitted(tw.world.admin_store(),
                                          tw.world.admin_anchor(),
                                          tw.world.admin_broker(), 0, st, why),
                "reject file swap");
        tw.world.SetImage(pristine);
      }
    }
    if (!t1blk.empty()) {  // tenant binding
      auto img = pristine;
      std::swap(img[t0[0]], img[t1blk]);
      tw.world.SetImage(std::move(img));
      c.Check(!oracle::DecryptCommitted(tw.world.admin_store(),
                                        tw.world.admin_anchor(),
                                        tw.world.admin_broker(), 0, st, why),
              "reject tenant swap");
      tw.world.SetImage(pristine);
    }
  }

  // ---- E. model/state mismatches ----
  {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0);
    efs::IDriver* d = tw.Open(0);
    auto v = Pattern(3000, 308);
    if (!d->Put(c0, tw.Op(), "f", v).ok() ||
        !d->Put(c0, tw.Op(), "g", v).ok()) {
      c.Check(false, "reject model setup");
      return;
    }
    oracle::LogicalModel good;
    good.Put("f", v);
    good.Put("g", v);
    oracle::CommittedState st;
    std::string why;
    bool dec_ok = oracle::DecryptCommitted(tw.world.admin_store(),
                                           tw.world.admin_anchor(),
                                           tw.world.admin_broker(), 0, st,
                                           why);
    c.Check(dec_ok, "reject decrypt ok: " + why);
    if (!dec_ok) return;
    c.Check(oracle::ModelEquals(good, st, why), "reject equal: " + why);
    {  // content divergence
      auto bad = good;
      bad.files["f"].bytes[0] ^= 0xFF;
      c.Check(!oracle::ModelEquals(bad, st, why), "reject content");
    }
    {  // missing file
      auto bad = good;
      bad.files.erase("g");
      c.Check(!oracle::ModelEquals(bad, st, why), "reject count");
    }
    {  // extra file
      auto bad = good;
      bad.Put("extra", {1});
      c.Check(!oracle::ModelEquals(bad, st, why), "reject extra");
    }
    {  // wrong stable id
      auto bad = good;
      bad.files["f"].id += 1000;
      c.Check(!oracle::ModelEquals(bad, st, why), "reject file id");
    }
    {  // reused retired id
      auto bad = good;
      bad.Remove("g");
      bad.Put("g", v);
      bad.files["g"].id = st.ids["g"];  // forge: reuse live id as retired
      bad.retired_ids.insert(st.ids["g"]);
      c.Check(!oracle::ModelEquals(bad, st, why), "reject retired reuse");
    }
  }

  // ---- F. forged evidence end-to-end: invalid candidate gets failure --
  {
    TestWorld tw;
    MockFactory mf(MakeFakeAck);
    tw.factory = &mf;
    efs::IDriver* d = tw.Open(0);
    auto c0 = Cap(0);
    auto v = Pattern(3000, 309);
    auto pr = d->Put(c0, tw.Op(), "f", v);  // mock claims success
    c.Check(pr.ok(), "reject forged claim made");
    oracle::LogicalModel model;
    model.Put("f", v);
    oracle::CommittedState st;
    std::string why;
    c.Check(oracle::DecryptCommitted(tw.world.admin_store(),
                                     tw.world.admin_anchor(),
                                     tw.world.admin_broker(), 0, st, why),
            "reject forged decrypt");
    // Verdict comes from the oracle, not the driver's claimed acks.
    c.Check(!oracle::ModelEquals(model, st, why), "reject forged evidence");
  }

  // ---- G. lost acknowledgement end-to-end ----
  // Crash after publication loses the ack; the oracle must honour the
  // trusted anchor transition (post-image), never a mix — the missing
  // response is a valid committed outcome, and only inconsistency
  // between claimed and committed state would be rejected.
  {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0);
    efs::IDriver* d = tw.Open(0);
    auto v1 = Pattern(5000, 310);
    auto v2 = Pattern(5000, 311);
    if (!d->Put(c0, tw.Op(), "f", v1).ok()) {
      c.Check(false, "reject ack setup");
      return;
    }
    oracle::LogicalModel pre, post;
    pre.Put("f", v1);
    post.Put("f", v2);
    d = tw.Open(0);
    tw.world.ArmCrashAfterPublish();
    bool fired = false;
    try {
      d->Put(c0, tw.Op(), "f", v2);  // ack lost
    } catch (const efs::SimulatedCrash&) {
      fired = true;
    }
    c.Check(fired, "reject ack crash fired");
    if (!fired) return;
    tw.world.Crash();
    d = tw.Open(0);
    d->Recover();
    oracle::CommittedState st;
    std::string why;
    bool ack_dec = oracle::DecryptCommitted(tw.world.admin_store(),
                                            tw.world.admin_anchor(),
                                            tw.world.admin_broker(), 0, st,
                                            why);
    c.Check(ack_dec, "reject ack decrypt: " + why);
    if (!ack_dec) return;
    c.Check(oracle::ModelEquals(post, st, why), "reject ack honors post");
    c.Check(!oracle::ModelEquals(pre, st, why), "reject ack not pre");
  }

  // ---- G2. lost response without crash ----
  // The driver's success reply is discarded on the wire; the oracle
  // still honours the durably published state rather than rejecting
  // the outcome for the missing response.
  {
    TestWorld tw;
    tw.factory = &factory;
    auto c0 = Cap(0);
    efs::IDriver* d = tw.Open(0);
    auto v = Pattern(5000, 312);
    auto pr = d->Put(c0, tw.Op(), "g", v);
    if (!pr.ok()) {
      c.Check(false, "reject wire-loss setup");
      return;
    }
    (void)pr;  // reply dropped: commit stands on durable state alone
    oracle::LogicalModel post;
    post.Put("g", v);
    oracle::CommittedState st;
    std::string why;
    bool dec = oracle::DecryptCommitted(tw.world.admin_store(),
                                        tw.world.admin_anchor(),
                                        tw.world.admin_broker(), 0, st,
                                        why);
    c.Check(dec, "reject wire-loss decrypt: " + why);
    if (!dec) return;
    c.Check(oracle::ModelEquals(post, st, why), "reject wire-loss honors");
  }
}

}  // namespace suites
}  // namespace grader
