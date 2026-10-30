#pragma once
// Public test helpers (candidate-visible only: smoke + visible repro).
#include <cstdint>
#include <string>
#include <vector>

#include "efs/driver.h"
#include "trusted/world.h"

namespace pub {

inline efs::TenantCap Cap(uint32_t t) {
  return efs::TenantCap{t, efs::CapSecretFor(t)};
}

inline std::vector<uint8_t> Bytes(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

inline std::string Str(const std::vector<uint8_t>& b) {
  return std::string(b.begin(), b.end());
}

// Deterministic pseudo-bytes for fixtures.
inline std::vector<uint8_t> Pattern(size_t n, uint8_t seed = 0xA5) {
  std::vector<uint8_t> o(n);
  uint64_t x = 0x12345678u + seed;
  for (size_t i = 0; i < n; ++i) {
    x = x * 6364136223846793005ull + 1442695040888963407ull;
    o[i] = uint8_t((x >> 33) & 0xFF);
  }
  return o;
}

int RunSmoke();
int RunRepro();

}  // namespace pub
