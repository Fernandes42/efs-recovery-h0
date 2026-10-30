#pragma once
// Independent format parser (docs/format.md). Shared by oracle + suites.
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "grader/grader.h"

namespace grader {
namespace fmt {

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
struct ManifestOuter {
  uint32_t tenant = 0;
  uint64_t gen = 0;
  uint32_t epoch = 0;
  std::vector<uint8_t> nonce;
  std::vector<uint8_t> ct;
};

bool ParseManifestPlain(const std::vector<uint8_t>& pt, uint32_t tenant,
                        uint64_t expect_gen, Manifest& m, std::string& why);
bool ParseDataOuter(const std::vector<uint8_t>& raw, DataOuter& h,
                    std::string& why);
bool ParseManifestOuter(const std::vector<uint8_t>& raw, ManifestOuter& h,
                        std::string& why);
void SelfTest(Counts& c);

}  // namespace fmt
}  // namespace grader
