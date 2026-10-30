// Independent format parser, derived from docs/format.md (not from the
// implementation source). Strict: rejects truncation, duplicates,
// trailing bytes, overflow, and invalid references.
#include "grader/grader.h"

#include <cstring>

namespace grader {
namespace fmt {

struct Cursor {
  const uint8_t* p;
  size_t n;
  bool ok = true;
};
uint32_t U32(Cursor& c) {
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
uint64_t U64(Cursor& c) {
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
// Length-delimited byte string with an explicit bound; overflow-safe.
bool LPBytes(Cursor& c, std::vector<uint8_t>& out, size_t bound) {
  uint32_t len = U32(c);
  if (!c.ok) return false;
  if (len > bound) {
    c.ok = false;
    return false;
  }
  if (c.n < len) {
    c.ok = false;
    return false;
  }
  out.assign(c.p, c.p + len);
  c.p += len;
  c.n -= len;
  return true;
}

bool ValidName(const std::vector<uint8_t>& n) {
  if (n.empty() || n.size() > 64) return false;
  std::string s(n.begin(), n.end());
  if (s == "." || s == "..") return false;
  for (unsigned char ch : s)
    if (ch == 0 || ch == '/') return false;
  return true;
}

struct Block {
  uint32_t idx = 0;
  uint64_t cver = 0;
  std::string oid;
  uint32_t epoch = 0;
  uint32_t pt_len = 0;
};
struct File {
  uint64_t id = 0;
  uint64_t len = 0;
  uint64_t cver = 0;
  std::vector<Block> blocks;
};
struct Manifest {
  uint64_t gen = 0;
  uint64_t op = 0;
  uint32_t tenant = 0;
  uint32_t epoch = 0;
  std::map<std::string, File> files;
};

// Parses manifest PLAINTEXT (post-decryption). Returns false with a
// reason on any violation.
bool ParseManifestPlain(const std::vector<uint8_t>& pt, uint32_t tenant,
                        uint64_t expect_gen, Manifest& m, std::string& why) {
  Cursor c{pt.data(), pt.size()};
  if (c.n < 4 || std::memcmp(c.p, "EFS1", 4) != 0) {
    why = "bad magic";
    return false;
  }
  c.p += 4;
  c.n -= 4;
  if (U32(c) != 1) {
    why = "bad version";
    return false;
  }
  m.gen = U64(c);
  m.op = U64(c);
  m.tenant = U32(c);
  m.epoch = U32(c);
  if (!c.ok) {
    why = "truncated header";
    return false;
  }
  if (m.gen != expect_gen) {
    why = "generation mismatch";
    return false;
  }
  if (m.tenant != tenant) {
    why = "tenant mismatch";
    return false;
  }
  if (m.epoch > 2) {
    why = "bad epoch";
    return false;
  }
  uint32_t fc = U32(c);
  if (!c.ok || fc > 16) {
    why = "bad file count";
    return false;
  }
  std::set<std::string> names, ids_seen;
  std::set<uint64_t> ids;
  for (uint32_t i = 0; i < fc; ++i) {
    std::vector<uint8_t> nb;
    if (!LPBytes(c, nb, 64) || !ValidName(nb)) {
      why = "bad name";
      return false;
    }
    std::string name(nb.begin(), nb.end());
    if (!names.insert(name).second) {
      why = "duplicate name";
      return false;
    }
    File f;
    f.id = U64(c);
    f.len = U64(c);
    f.cver = U64(c);
    uint32_t bc = U32(c);
    if (!c.ok) {
      why = "truncated file header";
      return false;
    }
    if (f.id == 0 || !ids.insert(f.id).second) {
      why = "duplicate/zero file id";
      return false;
    }
    if (f.len > 262144) {
      why = "file too large";
      return false;
    }
    // Overflow-safe block count expectation.
    uint64_t ebc = (f.len == 0) ? 0 : (f.len + 4095) / 4096;
    if (bc != ebc || bc > 64) {
      why = "bad block count";
      return false;
    }
    uint64_t covered = 0;
    for (uint32_t j = 0; j < bc; ++j) {
      Block b;
      b.idx = U32(c);
      b.cver = U64(c);
      std::vector<uint8_t> ob;
      if (!LPBytes(c, ob, 128) || ob.empty()) {
        why = "bad object id";
        return false;
      }
      b.oid = std::string(ob.begin(), ob.end());
      b.epoch = U32(c);
      b.pt_len = U32(c);
      if (!c.ok) {
        why = "truncated block";
        return false;
      }
      if (b.idx != j) {
        why = "sparse block index";
        return false;
      }
      if (b.epoch > 2 || b.pt_len == 0 || b.pt_len > 4096) {
        why = "bad block ref";
        return false;
      }
      // Overflow-safe accumulation.
      if (covered > 262144 - b.pt_len) {
        why = "length overflow";
        return false;
      }
      covered += b.pt_len;
      f.blocks.push_back(std::move(b));
    }
    for (size_t j = 0; j + 1 < f.blocks.size(); ++j)
      if (f.blocks[j].pt_len != 4096) {
        why = "non-tail short block";
        return false;
      }
    if (!f.blocks.empty() && covered != f.len) {
      why = "length/blocks mismatch";
      return false;
    }
    m.files[name] = std::move(f);
    ids_seen.insert(name);
  }
  if (!c.ok) {
    why = "truncated";
    return false;
  }
  if (c.n != 0) {
    why = "trailing bytes";
    return false;
  }
  return true;
}

struct DataOuter {
  uint32_t tenant = 0;
  uint64_t file = 0;
  uint64_t cver = 0;
  uint32_t idx = 0;
  uint32_t pt_len = 0;
  uint32_t epoch = 0;
  std::vector<uint8_t> nonce;
  std::vector<uint8_t> ct;
};

bool ParseDataOuter(const std::vector<uint8_t>& raw, DataOuter& h,
                    std::string& why) {
  Cursor c{raw.data(), raw.size()};
  if (U32(c) != 1) {
    why = "bad version";
    return false;
  }
  h.tenant = U32(c);
  h.file = U64(c);
  h.cver = U64(c);
  h.idx = U32(c);
  h.pt_len = U32(c);
  h.epoch = U32(c);
  if (!c.ok) {
    why = "truncated header";
    return false;
  }
  if (h.tenant > 1 || h.epoch > 2 || h.pt_len == 0 || h.pt_len > 4096) {
    why = "bad header values";
    return false;
  }
  if (c.n < 12 + 4 + 16) {
    why = "truncated body";
    return false;
  }
  h.nonce.assign(c.p, c.p + 12);
  c.p += 12;
  c.n -= 12;
  uint32_t ctl = U32(c);
  if (!c.ok || ctl != h.pt_len) {
    why = "ct/pt length mismatch";
    return false;
  }
  if (c.n != (size_t)ctl + 16) {
    why = "trailing bytes";
    return false;
  }
  h.ct.assign(c.p, c.p + c.n);
  return true;
}

struct ManifestOuter {
  uint32_t tenant = 0;
  uint64_t gen = 0;
  uint32_t epoch = 0;
  std::vector<uint8_t> nonce;
  std::vector<uint8_t> ct;
};

bool ParseManifestOuter(const std::vector<uint8_t>& raw, ManifestOuter& h,
                        std::string& why) {
  Cursor c{raw.data(), raw.size()};
  if (U32(c) != 1) {
    why = "bad version";
    return false;
  }
  h.tenant = U32(c);
  h.gen = U64(c);
  h.epoch = U32(c);
  if (!c.ok) {
    why = "truncated header";
    return false;
  }
  if (h.tenant > 1 || h.epoch > 2) {
    why = "bad header values";
    return false;
  }
  if (c.n < 12 + 4 + 16) {
    why = "truncated body";
    return false;
  }
  h.nonce.assign(c.p, c.p + 12);
  c.p += 12;
  c.n -= 12;
  uint32_t ctl = U32(c);
  if (!c.ok || ctl > (256 << 10)) {
    why = "absurd ct length";
    return false;
  }
  if (c.n != (size_t)ctl + 16) {
    why = "trailing bytes";
    return false;
  }
  h.ct.assign(c.p, c.p + c.n);
  return true;
}

void SelfTest(Counts& c) {
  // Hand-built minimal manifest plaintext: gen 7, one empty file.
  std::vector<uint8_t> good;
  auto u32 = [&](uint32_t v) {
    good.push_back(v & 0xFF);
    good.push_back((v >> 8) & 0xFF);
    good.push_back((v >> 16) & 0xFF);
    good.push_back((v >> 24) & 0xFF);
  };
  auto u64 = [&](uint64_t v) {
    for (int i = 0; i < 8; ++i) good.push_back((v >> (8 * i)) & 0xFF);
  };
  good.insert(good.end(), {'E', 'F', 'S', '1'});
  u32(1);
  u64(7);
  u64(99);
  u32(0);
  u32(0);
  u32(1);
  u32(1);
  good.push_back('f');
  u64(5);
  u64(0);
  u64(3);
  u32(0);
  Manifest m;
  std::string why;
  c.Check(ParseManifestPlain(good, 0, 7, m, why), "parser accepts good: " + why);
  c.Check(m.files.count("f") && m.files["f"].id == 5, "parser file fields");
  for (size_t cut = 0; cut < good.size(); ++cut) {
    std::vector<uint8_t> t(good.begin(), good.begin() + cut);
    Manifest mm;
    std::string w;
    if (ParseManifestPlain(t, 0, 7, mm, w)) {
      // Only the full buffer may parse (empty prefix fails earlier).
      c.Check(false, "parser accepted truncation at " + std::to_string(cut));
      break;
    }
  }
  c.Check(true, "parser rejects all truncations");
  {
    auto dup = good;
    // Append a second identical file entry but keep count 1 -> trailing.
    dup.insert(dup.end(), good.begin() + 36, good.end());
    Manifest mm;
    std::string w;
    c.Check(!ParseManifestPlain(dup, 0, 7, mm, w), "parser rejects trailing");
  }
  {
    auto bad = good;
    bad[4] = 2;  // version
    Manifest mm;
    std::string w;
    c.Check(!ParseManifestPlain(bad, 0, 7, mm, w), "parser rejects version");
  }
  {
    std::vector<uint8_t> raw(10, 0);
    DataOuter h;
    std::string w;
    c.Check(!ParseDataOuter(raw, h, w), "parser rejects short outer");
  }
}

}  // namespace fmt
}  // namespace grader
