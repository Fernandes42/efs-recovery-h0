#pragma once
// Self-contained SHA-256 (candidate image must not link trusted/world.cpp).
// Standard FIPS 180-4, verified against the "abc" vector plus OpenSSL
// cross-checks in the sealed matrix (anchor digests must match).
#include <cstdint>
#include <vector>

namespace sealed_sha256 {

std::vector<uint8_t> Hash(const uint8_t* data, size_t n);
inline std::vector<uint8_t> Hash(const std::vector<uint8_t>& b) {
  return Hash(b.data(), b.size());
}

}  // namespace sealed_sha256
