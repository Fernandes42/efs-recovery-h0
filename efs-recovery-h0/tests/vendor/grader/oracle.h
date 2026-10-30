#pragma once
// Independent oracle declarations.
#include <string>
#include <vector>

#include "grader/grader.h"
#include "trusted/admin.h"

namespace grader {
namespace oracle {

struct ModelFile {
  uint64_t id = 0;
  std::vector<uint8_t> bytes;
};
struct LogicalModel {
  std::map<std::string, ModelFile> files;
  std::set<uint64_t> retired_ids;
  uint64_t next_id = 1;
  efs::Err Put(const std::string& name, const std::vector<uint8_t>& b);
  efs::Err WriteRange(const std::string& name, uint64_t off,
                      const std::vector<uint8_t>& b);
  efs::Err Truncate(const std::string& name, uint64_t n);
  efs::Err Rename(const std::string& from, const std::string& to);
  efs::Err Remove(const std::string& name);
};
struct CommittedState {
  uint64_t gen = 0;
  std::map<std::string, std::vector<uint8_t>> files;
  std::map<std::string, uint64_t> ids;
};
bool DecryptCommitted(efs::IAdminStore* store, efs::IAdminAnchor* anchor,
                      efs::IAdminBroker* broker, uint32_t tenant,
                      CommittedState& out, std::string& why);
std::vector<uint8_t> ManifestAad(uint32_t tenant, uint64_t gen);
std::vector<uint8_t> DataAad(uint32_t tenant, uint64_t file, uint64_t cver,
                             uint32_t idx, uint32_t epoch, uint32_t pt_len);
bool ModelEquals(const LogicalModel& model, const CommittedState& state,
                 std::string& why);
void SelfTest(Counts& c);

}  // namespace oracle
}  // namespace grader
