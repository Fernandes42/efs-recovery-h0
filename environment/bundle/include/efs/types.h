#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace efs {

inline constexpr uint32_t kNumTenants = 2;
inline constexpr uint32_t kNumEpochs = 3;
inline constexpr size_t kBlockSize = 4096;
inline constexpr size_t kMaxFilesPerTenant = 16;
inline constexpr size_t kMaxFileSize = 256 * 1024;
inline constexpr size_t kMaxLivePlaintext = 4 * 1024 * 1024;
inline constexpr size_t kMaxNameLen = 64;
inline constexpr size_t kMaxAsyncInFlight = 6;
inline constexpr size_t kNonceLen = 12;
inline constexpr size_t kTagLen = 16;

struct TenantCap {
  uint32_t tenant = 0;
  uint64_t secret = 0;
};

struct ReadOut {
  std::vector<uint8_t> data;
};

using SnapshotHandle = uint64_t;  // 0 = invalid

inline std::string DataObjectId(uint32_t tenant, uint64_t file_id,
                                uint64_t content_ver, uint32_t block_idx,
                                uint32_t epoch) {
  return "b_" + std::to_string(tenant) + "_" + std::to_string(file_id) +
         "_" + std::to_string(content_ver) + "_" +
         std::to_string(block_idx) + "_" + std::to_string(epoch);
}

inline std::string ManifestObjectId(uint32_t tenant, uint64_t generation) {
  return "m_" + std::to_string(tenant) + "_" + std::to_string(generation);
}

inline uint64_t CapSecretFor(uint32_t tenant) {
  return 0x5EEDC0DEull + uint64_t(tenant) * 0x9E3779B97F4A7C15ull;
}

inline bool ValidName(const std::string& n) {
  if (n.empty() || n.size() > kMaxNameLen) return false;
  if (n == "." || n == "..") return false;
  for (unsigned char c : n) {
    if (c == 0 || c == '/') return false;
  }
  return true;
}

}  // namespace efs
