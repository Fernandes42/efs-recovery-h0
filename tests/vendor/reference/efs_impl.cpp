// Correct reference implementation (H0 v1). Authoring/verifier only.
#include "reference/efs_impl.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <string>

#include "efs/hash.h"

namespace efs::reference {
namespace {

void PutU32(std::vector<uint8_t>& o, uint32_t v) {
  o.push_back(uint8_t(v & 0xFF));
  o.push_back(uint8_t((v >> 8) & 0xFF));
  o.push_back(uint8_t((v >> 16) & 0xFF));
  o.push_back(uint8_t((v >> 24) & 0xFF));
}
void PutU64(std::vector<uint8_t>& o, uint64_t v) {
  for (int i = 0; i < 8; ++i) o.push_back(uint8_t((v >> (8 * i)) & 0xFF));
}
void PutBytes(std::vector<uint8_t>& o, const uint8_t* p, size_t n) {
  PutU32(o, uint32_t(n));
  o.insert(o.end(), p, p + n);
}
void PutStr(std::vector<uint8_t>& o, const std::string& s) {
  PutBytes(o, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

struct Cursor {
  const uint8_t* p;
  size_t n;
  bool ok = true;
};
uint32_t GetU32(Cursor& c) {
  if (c.n < 4) {
    c.ok = false;
    return 0;
  }
  uint32_t v = uint32_t(c.p[0]) | (uint32_t(c.p[1]) << 8) |
               (uint32_t(c.p[2]) << 16) | (uint32_t(c.p[3]) << 24);
  c.p += 4;
  c.n -= 4;
  return v;
}
uint64_t GetU64(Cursor& c) {
  if (c.n < 8) {
    c.ok = false;
    return 0;
  }
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= uint64_t(c.p[i]) << (8 * i);
  c.p += 8;
  c.n -= 8;
  return v;
}
std::vector<uint8_t> GetBytes(Cursor& c, size_t bound) {
  uint32_t len = GetU32(c);
  if (!c.ok || len > bound || c.n < len) {
    c.ok = false;
    return {};
  }
  std::vector<uint8_t> o(c.p, c.p + len);
  c.p += len;
  c.n -= len;
  return o;
}

std::vector<uint8_t> DataAad(uint32_t tenant, uint64_t file_id,
                             uint64_t cver, uint32_t idx, uint32_t epoch,
                             uint32_t pt_len) {
  std::vector<uint8_t> a;
  PutU32(a, tenant);
  PutU64(a, file_id);
  PutU64(a, cver);
  PutU32(a, idx);
  PutU32(a, epoch);
  PutU32(a, pt_len);
  return a;
}
std::vector<uint8_t> ManifestAad(uint32_t tenant, uint64_t generation) {
  std::vector<uint8_t> a = {'E', 'F', 'S', 'M'};
  PutU32(a, tenant);
  PutU64(a, generation);
  return a;
}

struct BlockRef {
  uint32_t index = 0;
  uint64_t content_ver = 0;
  std::string object_id;
  uint32_t epoch = 0;
  uint32_t pt_len = 0;
};
struct FileEntry {
  uint64_t file_id = 0;
  uint64_t length = 0;
  uint64_t content_ver = 0;
  std::vector<BlockRef> blocks;  // dense, index-ordered
};

struct PendingOp {
  uint64_t op_id = 0;
  std::string name;
  std::vector<uint8_t>* captured = nullptr;  // managed, owned
  size_t true_len = 0;
};

class Driver : public IDriver {
 public:
  Driver(uint32_t tenant, IObjectStore* store, IAnchor* anchor,
         ICryptoBroker* broker, IManagedAllocator* alloc,
         ILeaseTracker* leases)
      : tenant_(tenant),
        store_(store),
        anchor_(anchor),
        broker_(broker),
        alloc_(alloc),
        leases_(leases) {}

  ~Driver() override {
    for (auto& [_, p] : pending_) {
      if (p.captured) {
        alloc_->SecureErase(p.captured);
        alloc_->Release(p.captured);
      }
    }
  }

  // ---- helpers ----
  Err CheckCap(const TenantCap& cap) const {
    if (cap.tenant != tenant_ || cap.tenant >= kNumTenants)
      return Err::PERMISSION_DENIED;
    if (cap.secret != CapSecretFor(cap.tenant))
      return Err::PERMISSION_DENIED;
    return Err::OK;
  }

  // Encode the manifest plaintext for (files, gen, op_id, epoch).
  std::vector<uint8_t> EncodeManifest(
      const std::map<std::string, FileEntry>& files, uint64_t gen,
      uint64_t op_id, uint32_t epoch) {
    std::vector<uint8_t> o;
    o.insert(o.end(), {'E', 'F', 'S', '1'});
    PutU32(o, 1);
    PutU64(o, gen);
    PutU64(o, op_id);
    PutU32(o, tenant_);
    PutU32(o, epoch);
    PutU32(o, uint32_t(files.size()));
    for (auto& [name, f] : files) {
      PutStr(o, name);
      PutU64(o, f.file_id);
      PutU64(o, f.length);
      PutU64(o, f.content_ver);
      PutU32(o, uint32_t(f.blocks.size()));
      for (auto& b : f.blocks) {
        PutU32(o, b.index);
        PutU64(o, b.content_ver);
        PutStr(o, b.object_id);
        PutU32(o, b.epoch);
        PutU32(o, b.pt_len);
      }
    }
    return o;
  }

  // Strict decode; duplicates/trailing/overflow/invalid refs rejected.
  bool DecodeManifest(const std::vector<uint8_t>& pt, uint64_t expect_gen,
                      std::map<std::string, FileEntry>& out) {
    Cursor c{pt.data(), pt.size()};
    if (c.n < 4 || std::memcmp(c.p, "EFS1", 4) != 0) return false;
    c.p += 4;
    c.n -= 4;
    if (GetU32(c) != 1) return false;
    if (GetU64(c) != expect_gen) return false;
    GetU64(c);  // op_id (evidence only)
    if (!c.ok) return false;
    if (GetU32(c) != tenant_) return false;
    GetU32(c);  // manifest epoch
    if (!c.ok) return false;
    uint32_t fc = GetU32(c);
    if (!c.ok || fc > kMaxFilesPerTenant) return false;
    std::set<std::string> names;
    std::set<uint64_t> ids;
    for (uint32_t i = 0; i < fc; ++i) {
      auto nb = GetBytes(c, kMaxNameLen);
      if (!c.ok || nb.empty()) return false;
      std::string name(nb.begin(), nb.end());
      if (!ValidName(name) || !names.insert(name).second) return false;
      FileEntry f;
      f.file_id = GetU64(c);
      f.length = GetU64(c);
      f.content_ver = GetU64(c);
      uint32_t bc = GetU32(c);
      if (!c.ok || f.length > kMaxFileSize) return false;
      uint32_t expect_bc = f.length == 0
                               ? 0
                               : uint32_t((f.length + kBlockSize - 1) /
                                          kBlockSize);
      if (bc != expect_bc || bc > 64) return false;
      if (!ids.insert(f.file_id).second || f.file_id == 0) return false;
      uint64_t covered = 0;
      for (uint32_t j = 0; j < bc; ++j) {
        BlockRef b;
        b.index = GetU32(c);
        b.content_ver = GetU64(c);
        auto ob = GetBytes(c, 128);
        if (!c.ok || ob.empty()) return false;
        b.object_id = std::string(ob.begin(), ob.end());
        b.epoch = GetU32(c);
        b.pt_len = GetU32(c);
        if (!c.ok || b.index != j || b.epoch >= kNumEpochs ||
            b.pt_len == 0 || b.pt_len > kBlockSize)
          return false;
        covered += b.pt_len;
        f.blocks.push_back(std::move(b));
      }
      // Last block may be short; others must be full.
      for (uint32_t j = 0; j + 1 < f.blocks.size(); ++j)
        if (f.blocks[j].pt_len != kBlockSize) return false;
      if (!f.blocks.empty() && covered != f.length) return false;
      out[std::move(name)] = std::move(f);
    }
    if (!c.ok || c.n != 0) return false;  // trailing bytes rejected
    return true;
  }

  // Load + verify the committed root from the anchor. Fail closed.
  Result<void> LoadCommitted() {
    AnchorState a = anchor_->Get(tenant_);
    if (a.generation == 0) {
      files_.clear();
      committed_gen_ = 0;
      manifest_epoch_ = 0;
      return Result<void>::Ok();
    }
    auto obj = store_->ReadDurable(a.manifest_id);
    if (!obj.has_value()) return Result<void>::Fail(Err::STALE_ROOT);
    if (Sha256(obj.value()) != a.digest)
      return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    const auto& raw = obj.value();
    Cursor c{raw.data(), raw.size()};
    if (GetU32(c) != 1) return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    if (GetU32(c) != tenant_)
      return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    uint64_t gen = GetU64(c);
    uint32_t epoch = GetU32(c);
    if (!c.ok || gen != a.generation)
      return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    if (c.n < kNonceLen + 4 + kTagLen)
      return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    std::vector<uint8_t> nonce(c.p, c.p + kNonceLen);
    c.p += kNonceLen;
    c.n -= kNonceLen;
    uint32_t ct_len = GetU32(c);
    if (!c.ok || c.n != (size_t)ct_len + kTagLen)
      return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    std::vector<uint8_t> ct(c.p, c.p + c.n);
    auto pt = broker_->Open(tenant_, epoch, nonce, ManifestAad(tenant_, gen),
                            ct);
    if (!pt.ok())
      return Result<void>::Fail(pt.err == Err::KEY_UNAVAILABLE
                                    ? Err::KEY_UNAVAILABLE
                                    : Err::AUTHENTICATION_FAILED);
    std::map<std::string, FileEntry> files;
    if (!DecodeManifest(pt.value, gen, files))
      return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    files_ = std::move(files);
    committed_gen_ = gen;
    manifest_epoch_ = epoch;
    uint64_t mx = 0;
    for (auto& [_, f] : files_) mx = std::max(mx, f.file_id);
    next_file_id_ = std::max(next_file_id_, mx + 1);
    return Result<void>::Ok();
  }

  void BumpFileId() {
    uint64_t mx = next_file_id_;
    for (auto& [_, f] : files_) mx = std::max(mx, f.file_id + 1);
    next_file_id_ = mx;
  }

  // True if id is referenced by the live root, any snapshot pin, or an
  // in-flight lease. Conservative: anything unverifiable counts as
  // referenced (never delete what might be live).
  bool IsReachable(const std::string& id) {
    AnchorState cur = anchor_->Get(tenant_);
    if (cur.generation > 0 && cur.manifest_id == id) return true;
    for (auto& [_, f] : files_)
      for (auto& b : f.blocks)
        if (b.object_id == id) return true;
    for (auto& [lease, st] : anchor_->PinsFor(tenant_)) {
      if (st.manifest_id == id) return true;
      auto obj = store_->ReadDurable(st.manifest_id);
      if (!obj.has_value()) return true;
      if (Sha256(obj.value()) != st.digest) return true;
      const auto& raw = obj.value();
      Cursor c{raw.data(), raw.size()};
      GetU32(c);
      GetU32(c);
      uint64_t g = GetU64(c);
      uint32_t epoch = GetU32(c);
      if (!c.ok || g != st.generation || c.n < kNonceLen + 4 + kTagLen)
        return true;
      std::vector<uint8_t> nonce(c.p, c.p + kNonceLen);
      c.p += kNonceLen;
      c.n -= kNonceLen;
      GetU32(c);
      std::vector<uint8_t> ct(c.p, c.p + c.n);
      auto pt = broker_->Open(tenant_, epoch, nonce,
                              ManifestAad(tenant_, g), ct);
      if (!pt.ok()) return true;
      std::map<std::string, FileEntry> files;
      if (!DecodeManifest(pt.value, g, files)) return true;
      for (auto& [_, f] : files) {
        for (auto& b : f.blocks)
          if (b.object_id == id) return true;
      }
    }
    if (leases_->Protected().count(id)) return true;
    return false;
  }

  // Stage, replacing a durable orphan left by an interrupted attempt.
  // Referenced IDs are never replaced (an abandoned transaction cannot
  // delete objects reachable from another transaction or snapshot).
  Err StageChecked(const std::string& id,
                   const std::vector<uint8_t>& bytes) {
    if (store_->Stage(id, bytes) == Err::OK) return Err::OK;
    if (IsReachable(id)) return Err::CORRUPT_COMMITTED_STATE;
    store_->DeleteDurable(id);
    return store_->Stage(id, bytes);
  }

  // Encrypt one block through the managed path; stage (not flush).
  struct Staged {
    std::string id;
  };
  Result<BlockRef> SealBlock(uint64_t file_id, uint64_t cver, uint32_t idx,
                             const uint8_t* pt, size_t pt_len, uint32_t epoch,
                             std::vector<std::string>& staged_ids) {
    auto nn = broker_->ReserveNonce(tenant_, epoch);
    if (!nn.ok()) return Result<BlockRef>::Fail(nn.err);
    auto ab = alloc_->Allocate(pt_len == 0 ? 1 : pt_len);
    if (!ab.ok()) return Result<BlockRef>::Fail(ab.err);
    std::vector<uint8_t>* m = ab.value;
    if (pt_len > 0) alloc_->Copy(m, pt, pt_len);
    std::vector<uint8_t> plain(m->begin(), m->end());
    if (pt_len == 0) plain.clear();
    alloc_->SecureErase(m);
    alloc_->Release(m);
    auto aad = DataAad(tenant_, file_id, cver, idx, epoch,
                       uint32_t(pt_len));
    auto ct = broker_->Seal(tenant_, epoch, nn.value, aad, plain);
    if (!ct.ok()) {
      alloc_->SecureErase(m);
      alloc_->Release(m);
      return Result<BlockRef>::Fail(ct.err);
    }
    // Outer encoding.
    std::vector<uint8_t> o;
    PutU32(o, 1);
    PutU32(o, tenant_);
    PutU64(o, file_id);
    PutU64(o, cver);
    PutU32(o, idx);
    PutU32(o, uint32_t(pt_len));
    PutU32(o, epoch);
    o.insert(o.end(), nn.value.begin(), nn.value.end());
    PutU32(o, uint32_t(ct.value.size() - kTagLen));  // plaintext length
    o.insert(o.end(), ct.value.begin(), ct.value.end());
    std::string id =
        DataObjectId(tenant_, file_id, cver, idx, epoch);
    if (StageChecked(id, o) != Err::OK)
      return Result<BlockRef>::Fail(Err::CORRUPT_COMMITTED_STATE);
    staged_ids.push_back(id);
    BlockRef b;
    b.index = idx;
    b.content_ver = cver;
    b.object_id = id;
    b.epoch = epoch;
    b.pt_len = uint32_t(pt_len);
    return Result<BlockRef>::Ok(std::move(b));
  }

  // Publish the manifest for `files` (all data objects already flushed).
  // Single CAS attempt; caller retries at the op level on STALE_ROOT.
  Result<void> Publish(uint64_t op_id,
                       const std::map<std::string, FileEntry>& files,
                       uint32_t epoch, std::vector<std::string> data_ids) {
    uint64_t gen = committed_gen_ + 1;
    std::string mid = ManifestObjectId(tenant_, gen);
    auto pt = EncodeManifest(files, gen, op_id, epoch);
    // Manifest plaintext through the managed path.
    auto ab = alloc_->Allocate(pt.size() == 0 ? 1 : pt.size());
    if (!ab.ok()) return Result<void>::Fail(ab.err);
    std::vector<uint8_t>* m = ab.value;
    if (!pt.empty()) alloc_->Copy(m, pt.data(), pt.size());
    std::vector<uint8_t> mplain(m->begin(), m->end());
    alloc_->SecureErase(m);
    alloc_->Release(m);
    auto nn = broker_->ReserveNonce(tenant_, epoch);
    if (!nn.ok()) return Result<void>::Fail(nn.err);
    auto ct = broker_->Seal(tenant_, epoch, nn.value,
                            ManifestAad(tenant_, gen), mplain);
    if (!ct.ok()) return Result<void>::Fail(ct.err);
    std::vector<uint8_t> o;
    PutU32(o, 1);
    PutU32(o, tenant_);
    PutU64(o, gen);
    PutU32(o, epoch);
    o.insert(o.end(), nn.value.begin(), nn.value.end());
    PutU32(o, uint32_t(ct.value.size() - kTagLen));  // plaintext length
    o.insert(o.end(), ct.value.begin(), ct.value.end());
    if (StageChecked(mid, o) != Err::OK)
      return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    if (store_->Flush(mid) != Err::OK)
      return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    data_ids.push_back(mid);
    uint64_t lease = leases_->Admit(data_ids);
    auto digest = Sha256(o);
    Err p = anchor_->Publish(tenant_, committed_gen_, mid, digest);
    leases_->ReleaseLease(lease);
    if (p != Err::OK) return Result<void>::Fail(p);
    committed_gen_ = gen;
    files_ = files;
    manifest_epoch_ = epoch;
    return Result<void>::Ok();
  }

  // Flush staged data objects (correct ordering: data before manifest).
  Err FlushAll(const std::vector<std::string>& ids) {
    for (auto& id : ids)
      if (store_->Flush(id) != Err::OK) return Err::CORRUPT_COMMITTED_STATE;
    return Err::OK;
  }

  uint64_t NextCver(uint64_t file_id, uint64_t base) {
    uint64_t v = std::max(base, cver_hint_[file_id]);
    cver_hint_[file_id] = v + 1;
    return v;
  }

  struct DataHdr {
    uint32_t tenant = 0;
    uint64_t file_id = 0;
    uint64_t cver = 0;
    uint32_t idx = 0;
    uint32_t pt_len = 0;
    uint32_t epoch = 0;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> ct;
  };
  static bool ParseDataOuter(const std::vector<uint8_t>& raw, DataHdr& h) {
    Cursor c{raw.data(), raw.size()};
    if (GetU32(c) != 1) return false;
    h.tenant = GetU32(c);
    h.file_id = GetU64(c);
    h.cver = GetU64(c);
    h.idx = GetU32(c);
    h.pt_len = GetU32(c);
    h.epoch = GetU32(c);
    if (!c.ok || c.n < kNonceLen + 4 + kTagLen) return false;
    h.nonce = std::vector<uint8_t>(c.p, c.p + kNonceLen);
    c.p += kNonceLen;
    c.n -= kNonceLen;
    uint32_t ctl = GetU32(c);
    if (!c.ok || c.n != (size_t)ctl + kTagLen || ctl != h.pt_len)
      return false;
    h.ct = std::vector<uint8_t>(c.p, c.p + c.n);
    return c.ok;
  }

  // Fetch + authenticate a whole file from a given files map.
  Result<std::vector<uint8_t>> FetchFile(
      const std::map<std::string, FileEntry>& files, const std::string& name) {
    auto it = files.find(name);
    if (it == files.end()) return Result<std::vector<uint8_t>>::Fail(Err::NOT_FOUND);
    const FileEntry& f = it->second;
    std::vector<uint8_t> out;
    out.reserve((size_t)f.length);
    for (auto& b : f.blocks) {
      auto raw = store_->ReadDurable(b.object_id);
      if (!raw.has_value())
        return Result<std::vector<uint8_t>>::Fail(Err::CORRUPT_COMMITTED_STATE);
      DataHdr h;
      if (!ParseDataOuter(raw.value(), h))
        return Result<std::vector<uint8_t>>::Fail(Err::CORRUPT_COMMITTED_STATE);
      // Binding check against the manifest reference (recorded values).
      if (h.tenant != tenant_ || h.file_id != f.file_id ||
          h.cver != b.content_ver || h.idx != b.index ||
          h.pt_len != b.pt_len || h.epoch != b.epoch ||
          h.nonce.size() != kNonceLen)
        return Result<std::vector<uint8_t>>::Fail(
            Err::AUTHENTICATION_FAILED);
      auto pt = broker_->Open(tenant_, h.epoch, h.nonce,
                              DataAad(tenant_, h.file_id, h.cver, h.idx,
                                      h.epoch, h.pt_len),
                              h.ct);
      if (!pt.ok())
        return Result<std::vector<uint8_t>>::Fail(
            pt.err == Err::KEY_UNAVAILABLE ? Err::KEY_UNAVAILABLE
                                           : Err::AUTHENTICATION_FAILED);
      if (pt.value.size() != b.pt_len)
        return Result<std::vector<uint8_t>>::Fail(
            Err::AUTHENTICATION_FAILED);
      out.insert(out.end(), pt.value.begin(), pt.value.end());
    }
    if (out.size() != (size_t)f.length)
      return Result<std::vector<uint8_t>>::Fail(Err::CORRUPT_COMMITTED_STATE);
    return Result<std::vector<uint8_t>>::Ok(std::move(out));
  }

  // Seal full content; changed(i)==true means seal block i, else reuse old.
  Result<std::vector<BlockRef>> SealContent(
      uint64_t file_id, uint64_t cver, const std::vector<uint8_t>& content,
      uint32_t epoch, const std::vector<BlockRef>& old,
      const std::vector<char>& changed, std::vector<std::string>& staged) {
    std::vector<BlockRef> refs;
    size_t nb = content.empty()
                    ? 0
                    : (content.size() + kBlockSize - 1) / kBlockSize;
    for (size_t i = 0; i < nb; ++i) {
      if (i < changed.size() && !changed[i] && i < old.size()) {
        refs.push_back(old[i]);
        continue;
      }
      size_t off = i * kBlockSize;
      size_t len = std::min(kBlockSize, content.size() - off);
      auto r = SealBlock(file_id, cver, uint32_t(i), content.data() + off,
                         len, epoch, staged);
      if (!r.ok()) return Result<std::vector<BlockRef>>::Fail(r.err);
      refs.push_back(std::move(r.value));
    }
    return Result<std::vector<BlockRef>>::Ok(std::move(refs));
  }

  struct Prepared {
    std::map<std::string, FileEntry> files;
    uint32_t epoch = 0;
    std::vector<std::string> staged;
  };
  // Load, prepare (seal+stage), flush data, publish manifest.
  // One contract-valid retry on CAS conflict with bumped content
  // versions so retried objects never reuse IDs.
  template <typename Prep>
  Result<void> RunOp(uint64_t op_id, Prep&& prep) {
    for (int attempt = 0; attempt < 2; ++attempt) {
      auto l = LoadCommitted();
      if (!l.ok()) return l;
      auto pr = prep();
      if (!pr.ok()) return Result<void>::Fail(pr.err);
      Prepared p = std::move(pr.value);
      Err f = FlushAll(p.staged);
      if (f != Err::OK) return Result<void>::Fail(f);
      auto r = Publish(op_id, p.files, p.epoch, p.staged);
      if (r.ok()) return r;
      if (r.err != Err::STALE_ROOT || attempt == 1) return r;
      for (auto& [_, fl] : p.files)
        cver_hint_[fl.file_id] =
            std::max(cver_hint_[fl.file_id], fl.content_ver + 1);
    }
    return Result<void>::Fail(Err::STALE_ROOT);
  }

  Result<ReadOut> ServeRead(
      const std::map<std::string, FileEntry>& files, const std::string& name,
      uint64_t offset, size_t length) {
    auto full = FetchFile(files, name);
    if (!full.ok()) return Result<ReadOut>::Fail(full.err);
    ReadOut ro;
    if (offset < full.value.size()) {
      size_t n = std::min(length, full.value.size() - (size_t)offset);
      ro.data.insert(ro.data.end(), full.value.begin() + offset,
                     full.value.begin() + offset + n);
    }
    return Result<ReadOut>::Ok(std::move(ro));
  }

  // ---- IDriver ----
  Result<ReadOut> Read(const TenantCap& cap, const std::string& name,
                       uint64_t offset, size_t length) override {
    if (CheckCap(cap) != Err::OK)
      return Result<ReadOut>::Fail(Err::PERMISSION_DENIED);
    if (!ValidName(name)) return Result<ReadOut>::Fail(Err::INVALID_ARGUMENT);
    auto l = LoadCommitted();
    if (!l.ok()) return Result<ReadOut>::Fail(l.err);
    if (files_.find(name) == files_.end())
      return Result<ReadOut>::Fail(Err::NOT_FOUND);
    return ServeRead(files_, name, offset, length);
  }

  Result<void> Put(const TenantCap& cap, uint64_t op_id,
                   const std::string& name,
                   const std::vector<uint8_t>& bytes) override {
    if (CheckCap(cap) != Err::OK)
      return Result<void>::Fail(Err::PERMISSION_DENIED);
    if (!ValidName(name))
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    if (bytes.size() > kMaxFileSize)
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    return RunOp(op_id, [&]() -> Result<Prepared> {
      auto it = files_.find(name);
      bool is_new = (it == files_.end());
      if (is_new && files_.size() >= kMaxFilesPerTenant)
        return Result<Prepared>::Fail(Err::INVALID_ARGUMENT);
      BumpFileId();
      uint64_t fid = is_new ? next_file_id_++ : it->second.file_id;
      uint64_t base = is_new ? 1 : it->second.content_ver + 1;
      uint64_t cver = NextCver(fid, base);
      Prepared p;
      p.epoch = manifest_epoch_;
      std::vector<char> changed(
          bytes.empty() ? 0
                        : (bytes.size() + kBlockSize - 1) / kBlockSize,
          1);
      auto refs = SealContent(fid, cver, bytes, p.epoch, {}, changed,
                              p.staged);
      if (!refs.ok()) return Result<Prepared>::Fail(refs.err);
      p.files = files_;
      FileEntry f;
      f.file_id = fid;
      f.length = bytes.size();
      f.content_ver = cver;
      f.blocks = std::move(refs.value);
      p.files[name] = std::move(f);
      return Result<Prepared>::Ok(std::move(p));
    });
  }

  Result<void> WriteRange(const TenantCap& cap, uint64_t op_id,
                          const std::string& name, uint64_t offset,
                          const std::vector<uint8_t>& bytes) override {
    if (CheckCap(cap) != Err::OK)
      return Result<void>::Fail(Err::PERMISSION_DENIED);
    if (!ValidName(name))
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    auto l0 = LoadCommitted();
    if (!l0.ok()) return l0;
    auto fit = files_.find(name);
    if (fit == files_.end()) return Result<void>::Fail(Err::NOT_FOUND);
    if (offset > fit->second.length)
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    if (bytes.empty()) {
      // F-A option (a): zero-length is a LITERAL per-file commit. Seal +
      // publish a new manifest root / advance the generation with
      // unchanged content bytes. No data blocks are resealed (block refs
      // are reused, only the file content_ver is bumped); the standard
      // RunOp path seals + publishes the new manifest, so
      // flush-before-publish holds trivially (no new data objects).
      return RunOp(op_id, [&]() -> Result<Prepared> {
        auto it = files_.find(name);
        if (it == files_.end())
          return Result<Prepared>::Fail(Err::NOT_FOUND);
        if (offset > it->second.length)
          return Result<Prepared>::Fail(Err::INVALID_ARGUMENT);
        const FileEntry& fe = it->second;
        uint64_t cver = NextCver(fe.file_id, fe.content_ver + 1);
        Prepared p;
        p.epoch = manifest_epoch_;
        p.files = files_;
        FileEntry f = fe;
        f.content_ver = cver;
        p.files[name] = std::move(f);
        return Result<Prepared>::Ok(std::move(p));
      });
    }
    uint64_t new_end = offset + bytes.size();
    if (new_end > kMaxFileSize)
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    return RunOp(op_id, [&]() -> Result<Prepared> {
      auto old = FetchFile(files_, name);
      if (!old.ok()) return Result<Prepared>::Fail(old.err);
      const FileEntry& fe = files_.at(name);
      std::vector<uint8_t> content = std::move(old.value);
      if (content.size() < (size_t)new_end) content.resize((size_t)new_end);
      std::copy(bytes.begin(), bytes.end(), content.begin() + offset);
      uint64_t cver = NextCver(fe.file_id, fe.content_ver + 1);
      Prepared p;
      p.epoch = manifest_epoch_;
      size_t nb = (content.size() + kBlockSize - 1) / kBlockSize;
      size_t first = offset / kBlockSize;
      size_t last = (offset + bytes.size() - 1) / kBlockSize;
      std::vector<char> changed(nb, 0);
      for (size_t i = first; i <= last && i < nb; ++i) changed[i] = 1;
      auto refs = SealContent(fe.file_id, cver, content, p.epoch, fe.blocks,
                              changed, p.staged);
      if (!refs.ok()) return Result<Prepared>::Fail(refs.err);
      p.files = files_;
      FileEntry f;
      f.file_id = fe.file_id;
      f.length = content.size();
      f.content_ver = cver;
      f.blocks = std::move(refs.value);
      p.files[name] = std::move(f);
      return Result<Prepared>::Ok(std::move(p));
    });
  }

  Result<void> Truncate(const TenantCap& cap, uint64_t op_id,
                        const std::string& name,
                        uint64_t new_length) override {
    if (CheckCap(cap) != Err::OK)
      return Result<void>::Fail(Err::PERMISSION_DENIED);
    if (!ValidName(name))
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    auto l0 = LoadCommitted();
    if (!l0.ok()) return l0;
    auto fit = files_.find(name);
    if (fit == files_.end()) return Result<void>::Fail(Err::NOT_FOUND);
    if (new_length > fit->second.length)
      return Result<void>::Fail(Err::INVALID_ARGUMENT);  // no extension
    if (new_length == fit->second.length) return Result<void>::Ok();
    return RunOp(op_id, [&]() -> Result<Prepared> {
      auto old = FetchFile(files_, name);
      if (!old.ok()) return Result<Prepared>::Fail(old.err);
      const FileEntry& fe = files_.at(name);
      std::vector<uint8_t> content(old.value.begin(),
                                   old.value.begin() + (size_t)new_length);
      uint64_t cver = NextCver(fe.file_id, fe.content_ver + 1);
      Prepared p;
      p.epoch = manifest_epoch_;
      // Blocks fully retained are reused; the new tail block (if
      // shortened mid-block) and dropped suffix are resealed/dropped.
      size_t nb = content.empty()
                      ? 0
                      : (content.size() + kBlockSize - 1) / kBlockSize;
      std::vector<char> changed(nb, 0);
      if (nb > 0) {
        size_t tail = nb - 1;
        size_t tail_len = content.size() - tail * kBlockSize;
        bool same = tail < fe.blocks.size() &&
                    fe.blocks[tail].pt_len == tail_len;
        if (!same) changed[tail] = 1;
      }
      auto refs = SealContent(fe.file_id, cver, content, p.epoch, fe.blocks,
                              changed, p.staged);
      if (!refs.ok()) return Result<Prepared>::Fail(refs.err);
      p.files = files_;
      FileEntry f;
      f.file_id = fe.file_id;
      f.length = content.size();
      f.content_ver = cver;
      f.blocks = std::move(refs.value);
      p.files[name] = std::move(f);
      return Result<Prepared>::Ok(std::move(p));
    });
  }

  Result<void> Rename(const TenantCap& cap, uint64_t op_id,
                      const std::string& from,
                      const std::string& to) override {
    if (CheckCap(cap) != Err::OK)
      return Result<void>::Fail(Err::PERMISSION_DENIED);
    if (!ValidName(from) || !ValidName(to))
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    if (from == to) {
      auto l = LoadCommitted();
      if (!l.ok()) return l;
      if (files_.find(from) == files_.end())
        return Result<void>::Fail(Err::NOT_FOUND);
      return Result<void>::Ok();  // no-op
    }
    return RunOp(op_id, [&]() -> Result<Prepared> {
      auto it = files_.find(from);
      if (it == files_.end())
        return Result<Prepared>::Fail(Err::NOT_FOUND);
      if (files_.find(to) != files_.end())
        return Result<Prepared>::Fail(Err::INVALID_ARGUMENT);
      Prepared p;
      p.epoch = manifest_epoch_;
      p.files = files_;
      p.files[to] = it->second;  // stable file identity + contents
      p.files.erase(from);
      return Result<Prepared>::Ok(std::move(p));
    });
  }

  Result<void> Remove(const TenantCap& cap, uint64_t op_id,
                      const std::string& name) override {
    if (CheckCap(cap) != Err::OK)
      return Result<void>::Fail(Err::PERMISSION_DENIED);
    if (!ValidName(name))
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    return RunOp(op_id, [&]() -> Result<Prepared> {
      if (files_.find(name) == files_.end())
        return Result<Prepared>::Fail(Err::NOT_FOUND);
      Prepared p;
      p.epoch = manifest_epoch_;
      p.files = files_;
      p.files.erase(name);  // snapshots keep the old manifest readable
      return Result<Prepared>::Ok(std::move(p));
    });
  }

  // Commit helper for Await (captured bytes already owned).
  Result<void> CommitPut(const TenantCap& cap, uint64_t op_id,
                         const std::string& name,
                         const std::vector<uint8_t>& bytes) {
    if (bytes.size() > kMaxFileSize)
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    return RunOp(op_id, [&]() -> Result<Prepared> {
      auto it = files_.find(name);
      bool is_new = (it == files_.end());
      if (is_new && files_.size() >= kMaxFilesPerTenant)
        return Result<Prepared>::Fail(Err::INVALID_ARGUMENT);
      BumpFileId();
      uint64_t fid = is_new ? next_file_id_++ : it->second.file_id;
      uint64_t cver = NextCver(fid, is_new ? 1 : it->second.content_ver + 1);
      Prepared p;
      p.epoch = manifest_epoch_;
      std::vector<char> changed(
          bytes.empty() ? 0 : (bytes.size() + kBlockSize - 1) / kBlockSize,
          1);
      auto refs =
          SealContent(fid, cver, bytes, p.epoch, {}, changed, p.staged);
      if (!refs.ok()) return Result<Prepared>::Fail(refs.err);
      p.files = files_;
      FileEntry f;
      f.file_id = fid;
      f.length = bytes.size();
      f.content_ver = cver;
      f.blocks = std::move(refs.value);
      p.files[name] = std::move(f);
      return Result<Prepared>::Ok(std::move(p));
    });
  }

  Err PutAsync(const TenantCap& cap, uint64_t op_id, const std::string& name,
               const std::vector<uint8_t>& input) override {
    if (CheckCap(cap) != Err::OK) return Err::PERMISSION_DENIED;
    if (!ValidName(name)) return Err::INVALID_ARGUMENT;
    if (input.size() > kMaxFileSize) return Err::INVALID_ARGUMENT;
    if (pending_.count(op_id) || completed_.count(op_id))
      return Err::INVALID_ARGUMENT;
    if (pending_.size() >= kMaxAsyncInFlight) return Err::INVALID_ARGUMENT;
    // Capture the input value before returning: later caller
    // mutation/destruction cannot change it. A shared mutable span
    // would be insufficient; we own a managed copy.
    auto ab = alloc_->Allocate(input.size() == 0 ? 1 : input.size());
    if (!ab.ok()) return ab.err;
    std::vector<uint8_t>* m = ab.value;
    if (!input.empty()) alloc_->Copy(m, input.data(), input.size());
    PendingOp p;
    p.op_id = op_id;
    p.name = name;
    p.captured = m;
    p.true_len = input.size();
    last_cap_[op_id] = cap;
    pending_[op_id] = std::move(p);
    return Err::OK;
  }

  Result<void> Await(uint64_t op_id) override {
    auto it = pending_.find(op_id);
    if (it == pending_.end()) {
      if (completed_.count(op_id))
        return Result<void>::Ok();  // idempotent re-await
      return Result<void>::Fail(Err::NOT_FOUND);
    }
    PendingOp p = std::move(it->second);
    pending_.erase(it);
    TenantCap cap = last_cap_[op_id];
    std::vector<uint8_t> bytes(p.captured->begin(), p.captured->end());
    bytes.resize(p.true_len);  // empty input uses a 1-byte managed slot
    alloc_->SecureErase(p.captured);
    alloc_->Release(p.captured);
    last_cap_.erase(op_id);
    empty_async_.erase(op_id);
    auto r = CommitPut(cap, op_id, p.name, bytes);
    if (r.ok()) completed_.insert(op_id);
    return r;
  }

  Result<void> Cancel(uint64_t op_id) override {
    auto it = pending_.find(op_id);
    if (it == pending_.end()) {
      if (completed_.count(op_id))
        return Result<void>::Fail(Err::ALREADY_COMMITTED);
      return Result<void>::Fail(Err::NOT_FOUND);
    }
    // Wins only before publication (the op was never awaited).
    alloc_->SecureErase(it->second.captured);
    alloc_->Release(it->second.captured);
    pending_.erase(it);
    last_cap_.erase(op_id);
    empty_async_.erase(op_id);
    return Result<void>::Fail(Err::CANCELLED);
  }

  Result<SnapshotHandle> Snapshot(const TenantCap& cap,
                                  uint64_t op_id) override {
    if (CheckCap(cap) != Err::OK)
      return Result<SnapshotHandle>::Fail(Err::PERMISSION_DENIED);
    auto l = LoadCommitted();
    if (!l.ok()) return Result<SnapshotHandle>::Fail(l.err);
    AnchorState a = anchor_->Get(tenant_);
    if (a.generation == 0)
      return Result<SnapshotHandle>::Fail(Err::INVALID_ARGUMENT);
    // Lease unique across incarnations (generation + op id).
    SnapshotHandle h =
        (a.generation << 32) ^ (op_id * 0x9E3779B97F4A7C15ull);
    if (h == 0) h = 1;
    Err e = anchor_->Pin(tenant_, a.generation, a.manifest_id, a.digest, h);
    if (e != Err::OK) return Result<SnapshotHandle>::Fail(e);
    return Result<SnapshotHandle>::Ok(h);
  }

  Result<ReadOut> ReadSnapshot(const TenantCap& cap, SnapshotHandle snap,
                               const std::string& name, uint64_t offset,
                               size_t length) override {
    if (CheckCap(cap) != Err::OK)
      return Result<ReadOut>::Fail(Err::PERMISSION_DENIED);
    if (snap == 0) return Result<ReadOut>::Fail(Err::INVALID_ARGUMENT);
    if (!ValidName(name)) return Result<ReadOut>::Fail(Err::INVALID_ARGUMENT);
    AnchorState a;
    if (!anchor_->Pinned(tenant_, snap, &a))
      return Result<ReadOut>::Fail(Err::INVALID_ARGUMENT);
    auto obj = store_->ReadDurable(a.manifest_id);
    if (!obj.has_value()) return Result<ReadOut>::Fail(Err::STALE_ROOT);
    if (Sha256(obj.value()) != a.digest)
      return Result<ReadOut>::Fail(Err::CORRUPT_COMMITTED_STATE);
    const auto& raw = obj.value();
    Cursor c{raw.data(), raw.size()};
    GetU32(c);
    GetU32(c);
    uint64_t gen = GetU64(c);
    uint32_t epoch = GetU32(c);
    if (!c.ok || gen != a.generation)
      return Result<ReadOut>::Fail(Err::CORRUPT_COMMITTED_STATE);
    std::vector<uint8_t> nonce(c.p, c.p + kNonceLen);
    c.p += kNonceLen;
    c.n -= kNonceLen;
    GetU32(c);
    std::vector<uint8_t> ct(c.p, c.p + c.n);
    auto pt = broker_->Open(tenant_, epoch, nonce, ManifestAad(tenant_, gen),
                            ct);
    if (!pt.ok())
      return Result<ReadOut>::Fail(pt.err == Err::KEY_UNAVAILABLE
                                       ? Err::KEY_UNAVAILABLE
                                       : Err::AUTHENTICATION_FAILED);
    std::map<std::string, FileEntry> files;
    if (!DecodeManifest(pt.value, gen, files))
      return Result<ReadOut>::Fail(Err::CORRUPT_COMMITTED_STATE);
    if (files.find(name) == files.end())
      return Result<ReadOut>::Fail(Err::NOT_FOUND);
    return ServeRead(files, name, offset, length);
  }

  Result<void> ReleaseSnapshot(const TenantCap& cap,
                               SnapshotHandle snap) override {
    if (CheckCap(cap) != Err::OK)
      return Result<void>::Fail(Err::PERMISSION_DENIED);
    Err e = anchor_->Unpin(tenant_, snap);
    if (e != Err::OK) return Result<void>::Fail(e);
    return Result<void>::Ok();
  }

  Result<void> BeginRotation(const TenantCap& cap, uint64_t op_id) override {
    if (CheckCap(cap) != Err::OK)
      return Result<void>::Fail(Err::PERMISSION_DENIED);
    auto l = LoadCommitted();
    if (!l.ok()) return l;
    if (manifest_epoch_ + 1 >= kNumEpochs)
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    return RunOp(op_id, [&]() -> Result<Prepared> {
      Prepared p;
      p.files = files_;
      p.epoch = manifest_epoch_ + 1;  // new encryptions use the new epoch
      return Result<Prepared>::Ok(std::move(p));
    });
  }

  Result<void> MigrateFile(const TenantCap& cap, uint64_t op_id,
                           const std::string& name) override {
    if (CheckCap(cap) != Err::OK)
      return Result<void>::Fail(Err::PERMISSION_DENIED);
    if (!ValidName(name))
      return Result<void>::Fail(Err::INVALID_ARGUMENT);
    auto l0 = LoadCommitted();
    if (!l0.ok()) return l0;
    if (files_.find(name) == files_.end())
      return Result<void>::Fail(Err::NOT_FOUND);
    return RunOp(op_id, [&]() -> Result<Prepared> {
      auto full = FetchFile(files_, name);
      if (!full.ok()) return Result<Prepared>::Fail(full.err);
      const FileEntry& fe = files_.at(name);
      uint64_t cver = NextCver(fe.file_id, fe.content_ver + 1);
      Prepared p;
      p.epoch = manifest_epoch_;  // current target epoch
      std::vector<char> changed(
          full.value.empty()
              ? 0
              : (full.value.size() + kBlockSize - 1) / kBlockSize,
          1);
      auto refs = SealContent(fe.file_id, cver, full.value, p.epoch,
                              {}, changed, p.staged);
      if (!refs.ok()) return Result<Prepared>::Fail(refs.err);
      p.files = files_;
      FileEntry f;
      f.file_id = fe.file_id;
      f.length = full.value.size();
      f.content_ver = cver;
      f.blocks = std::move(refs.value);
      p.files[name] = std::move(f);
      return Result<Prepared>::Ok(std::move(p));
    });
  }

  Result<void> FinishRotation(const TenantCap& cap,
                              uint64_t op_id) override {
    if (CheckCap(cap) != Err::OK)
      return Result<void>::Fail(Err::PERMISSION_DENIED);
    auto l = LoadCommitted();
    if (!l.ok()) return l;
    if (!pending_.empty()) return Result<void>::Fail(Err::INVALID_ARGUMENT);
    for (auto& [_, f] : files_)
      for (auto& b : f.blocks)
        if (b.epoch != manifest_epoch_)
          return Result<void>::Fail(Err::INVALID_ARGUMENT);
    // Declaration commit: identical content, new generation. Keys needed
    // by live roots/snapshots/leases are never retired here.
    return RunOp(op_id, [&]() -> Result<Prepared> {
      Prepared p;
      p.files = files_;
      p.epoch = manifest_epoch_;
      return Result<Prepared>::Ok(std::move(p));
    });
  }

  Result<void> Recover() override {
    auto l = LoadCommitted();
    if (!l.ok()) return l;
    // Fail closed on dangling committed references; never roll back.
    for (auto& [_, f] : files_)
      for (auto& b : f.blocks)
        if (!store_->DurableExists(b.object_id))
          return Result<void>::Fail(Err::CORRUPT_COMMITTED_STATE);
    return Result<void>::Ok();
  }

  Result<void> Collect() override {
    auto l = LoadCommitted();
    if (!l.ok()) return l;
    // Reachable manifests: live root + all snapshot pins, each with
    // its own expected digest.
    struct ManInfo {
      uint64_t gen;
      std::vector<uint8_t> digest;
    };
    std::map<std::string, ManInfo> manifests;  // id -> info
    AnchorState cur = anchor_->Get(tenant_);
    if (cur.generation > 0)
      manifests[cur.manifest_id] = {cur.generation, cur.digest};
    for (auto& [lease, st] : anchor_->PinsFor(tenant_))
      manifests[st.manifest_id] = {st.generation, st.digest};
    std::set<std::string> reachable;
    std::set<uint32_t> used_epochs;
    for (auto& [mid, info] : manifests) {
      auto obj = store_->ReadDurable(mid);
      if (!obj.has_value()) continue;  // replayed-away image: stay safe
      if (Sha256(obj.value()) != info.digest) continue;  // corrupt: keep
      const auto& raw = obj.value();
      Cursor c{raw.data(), raw.size()};
      GetU32(c);
      GetU32(c);
      uint64_t g = GetU64(c);
      uint32_t epoch = GetU32(c);
      if (!c.ok || g != info.gen || c.n < kNonceLen + 4 + kTagLen) continue;
      std::vector<uint8_t> nonce(c.p, c.p + kNonceLen);
      c.p += kNonceLen;
      c.n -= kNonceLen;
      GetU32(c);
      std::vector<uint8_t> ct(c.p, c.p + c.n);
      auto pt =
          broker_->Open(tenant_, epoch, nonce, ManifestAad(tenant_, g), ct);
      if (!pt.ok()) continue;  // revoked/unreadable: keep everything
      std::map<std::string, FileEntry> files;
      if (!DecodeManifest(pt.value, g, files)) continue;
      reachable.insert(mid);
      used_epochs.insert(epoch);
      for (auto& [_, f] : files)
        for (auto& b : f.blocks) {
          reachable.insert(b.object_id);
          used_epochs.insert(b.epoch);
        }
    }
    if (reachable.empty() && cur.generation > 0)
      return Result<void>::Ok();  // cannot prove anything: delete nothing
    std::set<std::string> prot = leases_->Protected();
    std::string bpre = "b_" + std::to_string(tenant_) + "_";
    std::string mpre = "m_" + std::to_string(tenant_) + "_";
    for (auto& [id, _] : store_->DurableImage()) {
      bool mine = (id.rfind(bpre, 0) == 0) || (id.rfind(mpre, 0) == 0);
      if (!mine) continue;
      if (reachable.count(id) || prot.count(id)) continue;
      store_->DeleteDurable(id);
    }
    // Key retirement is verifier-administered (see threat model): this
    // path deletes unreachable objects, which is what stops accumulation.
    // Epochs with no reachable reference are simply unused afterwards;
    // revocation itself is exercised by the harness through the admin
    // broker interface, never by candidate code.
    (void)used_epochs;
    (void)prot;
    return Result<void>::Ok();
  }

  uint32_t tenant_;
  IObjectStore* store_;
  IAnchor* anchor_;
  ICryptoBroker* broker_;
  IManagedAllocator* alloc_;
  ILeaseTracker* leases_;
  std::map<std::string, FileEntry> files_;
  uint64_t committed_gen_ = 0;
  uint32_t manifest_epoch_ = 0;
  uint64_t next_file_id_ = 1;
  std::map<uint64_t, uint64_t> cver_hint_;
  std::map<uint64_t, PendingOp> pending_;
  std::map<uint64_t, TenantCap> last_cap_;
  std::set<uint64_t> empty_async_;
  std::set<uint64_t> completed_;
};

}  // namespace

IDriver* Factory::OpenHandle(uint32_t tenant, IObjectStore* store,
                             IAnchor* anchor, ICryptoBroker* broker,
                             IManagedAllocator* alloc,
                             ILeaseTracker* leases) {
  return new Driver(tenant, store, anchor, broker, alloc, leases);
}

}  // namespace efs::reference




