// Independent logical + history oracle. The logical model reimplements
// the contract from docs/contract.md; DecryptCommitted re-derives the
// committed file state from verifier-owned observations (anchor +
// durable image + broker admin decrypt), never from candidate claims.
#include "grader/fmt.h"
#include "grader/oracle.h"
#include "trusted/admin.h"
#include "trusted/world.h"

namespace grader {
namespace oracle {

efs::Err LogicalModel::Put(const std::string& name,
                                const std::vector<uint8_t>& b) {
  if (b.size() > 262144) return efs::Err::INVALID_ARGUMENT;
  auto it = files.find(name);
  uint64_t id = (it == files.end()) ? next_id++ : it->second.id;
  files[name] = {id, b};
  return efs::Err::OK;
}
efs::Err LogicalModel::WriteRange(const std::string& name, uint64_t off,
                                  const std::vector<uint8_t>& b) {
  auto it = files.find(name);
  if (it == files.end()) return efs::Err::NOT_FOUND;
  // F-A option (a), owner decision 2026-10-30: zero-length write_range on
  // an existing file is a LITERAL per-file commit. The offset rule has no
  // zero-length exception (contract: "Offset beyond EOF rejected"), so
  // offset > EOF is INVALID_ARGUMENT and offset == EOF is a valid commit
  // point (including offset 0 on an empty file). The driver must seal +
  // publish a new manifest root / advance the generation with unchanged
  // content bytes. This logical model carries no generation counter:
  // bytes are unchanged here, and the suite asserts the generation
  // advance + durability against the trusted anchor (human review kept).
  if (off > it->second.bytes.size()) return efs::Err::INVALID_ARGUMENT;
  if (b.empty()) return efs::Err::OK;
  if (b.size() > 262144 || off > 262144 - b.size())
    return efs::Err::INVALID_ARGUMENT;
  auto& v = it->second.bytes;
  if (v.size() < off + b.size()) v.resize(off + b.size());
  std::copy(b.begin(), b.end(), v.begin() + off);
  return efs::Err::OK;
}
efs::Err LogicalModel::Truncate(const std::string& name, uint64_t n) {
  auto it = files.find(name);
  if (it == files.end()) return efs::Err::NOT_FOUND;
  if (n > it->second.bytes.size()) return efs::Err::INVALID_ARGUMENT;
  it->second.bytes.resize((size_t)n);
  return efs::Err::OK;
}
efs::Err LogicalModel::Rename(const std::string& from, const std::string& to) {
  if (from == to) {
    return files.count(from) ? efs::Err::OK : efs::Err::NOT_FOUND;
  }
  auto it = files.find(from);
  if (it == files.end()) return efs::Err::NOT_FOUND;
  if (files.count(to)) return efs::Err::INVALID_ARGUMENT;
  files[to] = it->second;
  files.erase(it);
  return efs::Err::OK;
}
efs::Err LogicalModel::Remove(const std::string& name) {
  auto it = files.find(name);
  if (it == files.end()) return efs::Err::NOT_FOUND;
  retired_ids.insert(it->second.id);
  files.erase(it);
  return efs::Err::OK;
}

std::vector<uint8_t> ManifestAad(uint32_t tenant, uint64_t gen) {
  std::vector<uint8_t> a = {'E', 'F', 'S', 'M'};
  a.push_back(tenant & 0xFF);
  a.push_back((tenant >> 8) & 0xFF);
  a.push_back((tenant >> 16) & 0xFF);
  a.push_back((tenant >> 24) & 0xFF);
  for (int i = 0; i < 8; ++i) a.push_back(uint8_t((gen >> (8 * i)) & 0xFF));
  return a;
}
std::vector<uint8_t> DataAad(uint32_t tenant, uint64_t file, uint64_t cver,
                             uint32_t idx, uint32_t epoch, uint32_t pt_len) {
  std::vector<uint8_t> a;
  auto u32 = [&](uint32_t v) {
    for (int i = 0; i < 4; ++i) a.push_back(uint8_t((v >> (8 * i)) & 0xFF));
  };
  auto u64 = [&](uint64_t v) {
    for (int i = 0; i < 8; ++i) a.push_back(uint8_t((v >> (8 * i)) & 0xFF));
  };
  u32(tenant);
  u64(file);
  u64(cver);
  u32(idx);
  u32(epoch);
  u32(pt_len);
  return a;
}

// Re-derive committed state from trusted observations. Fail-closed:
// any structural/auth problem is reported, never papered over.
bool DecryptCommitted(efs::IAdminStore* store, efs::IAdminAnchor* anchor,
                      efs::IAdminBroker* broker, uint32_t tenant,
                      CommittedState& out, std::string& why) {
  efs::AnchorState a = anchor->Get(tenant);
  out.gen = a.generation;
  if (a.generation == 0) return true;
  auto mobj = store->ReadDurable(a.manifest_id);
  if (!mobj.has_value()) {
    why = "anchor manifest missing (stale/replay)";
    return false;
  }
  if (efs::Sha256(mobj.value()) != a.digest) {
    why = "anchor digest mismatch";
    return false;
  }
  fmt::ManifestOuter mo;
  if (!fmt::ParseManifestOuter(mobj.value(), mo, why)) {
    why = "manifest outer: " + why;
    return false;
  }
  if (mo.tenant != tenant || mo.gen != a.generation) {
    why = "manifest outer binding";
    return false;
  }
  auto mpt = broker->Open(tenant, mo.epoch, mo.nonce,
                          ManifestAad(tenant, mo.gen), mo.ct);
  if (!mpt.ok()) {
    why = "manifest open: " + std::string(efs::ToString(mpt.err));
    return false;
  }
  fmt::Manifest m;
  if (!fmt::ParseManifestPlain(mpt.value, tenant, a.generation, m, why)) {
    why = "manifest plain: " + why;
    return false;
  }
  for (auto& [name, f] : m.files) {
    std::vector<uint8_t> content;
    for (auto& b : f.blocks) {
      auto robj = store->ReadDurable(b.oid);
      if (!robj.has_value()) {
        why = "dangling block " + b.oid;
        return false;
      }
      fmt::DataOuter h;
      std::string w;
      if (!fmt::ParseDataOuter(robj.value(), h, w)) {
        why = "block outer " + b.oid + ": " + w;
        return false;
      }
      // Binding against the manifest reference (recorded values).
      if (h.tenant != tenant || h.file != f.id || h.cver != b.cver ||
          h.idx != b.idx || h.pt_len != b.pt_len || h.epoch != b.epoch) {
        why = "block binding " + b.oid;
        return false;
      }
      auto dpt = broker->Open(tenant, h.epoch, h.nonce,
                              DataAad(tenant, h.file, h.cver, h.idx,
                                      h.epoch, h.pt_len),
                              h.ct);
      if (!dpt.ok()) {
        why = "block open " + b.oid + ": " +
              std::string(efs::ToString(dpt.err));
        return false;
      }
      content.insert(content.end(), dpt.value.begin(), dpt.value.end());
    }
    if (content.size() != (size_t)f.len) {
      why = "file length mismatch " + name;
      return false;
    }
    out.files[name] = std::move(content);
    out.ids[name] = f.id;
  }
  return true;
}

bool ModelEquals(const LogicalModel& model, const CommittedState& state,
                 std::string& why) {
  if (model.files.size() != state.files.size()) {
    why = "file count";
    return false;
  }
  for (auto& [name, mf] : model.files) {
    auto it = state.files.find(name);
    if (it == state.files.end()) {
      why = "missing file " + name;
      return false;
    }
    if (it->second != mf.bytes) {
      why = "content mismatch " + name;
      return false;
    }
    auto ii = state.ids.find(name);
    if (ii == state.ids.end() || ii->second != mf.id) {
      why = "file id mismatch " + name;
      return false;
    }
    if (model.retired_ids.count(mf.id)) {
      why = "reused file id " + name;
      return false;
    }
  }
  return true;
}

void SelfTest(Counts& c) {
  LogicalModel m;
  c.Check(m.Put("a", {1, 2, 3}) == efs::Err::OK, "model put");
  c.Check(m.WriteRange("a", 1, {9}) == efs::Err::OK, "model range");
  c.Check(m.files["a"].bytes == std::vector<uint8_t>({1, 9, 3}),
          "model range content");
  c.Check(m.Truncate("a", 2) == efs::Err::OK, "model trunc");
  c.Check(m.Truncate("a", 5) == efs::Err::INVALID_ARGUMENT,
          "model trunc ext");
  c.Check(m.Rename("a", "b") == efs::Err::OK, "model rename");
  uint64_t id = m.files["b"].id;
  c.Check(m.Remove("b") == efs::Err::OK, "model remove");
  c.Check(m.Put("b", {7}) == efs::Err::OK, "model recreate");
  c.Check(m.files["b"].id != id, "model new id");
  c.Check(m.retired_ids.count(id), "model retired");
}

}  // namespace oracle
}  // namespace grader
