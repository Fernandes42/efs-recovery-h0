// Binds efs::Sha256 (efs/hash.h) to the self-contained implementation
// for sealed-image builds. In-process builds use trusted/world.cpp.
#include "efs/hash.h"
#include "sealed/sha256.h"

namespace efs {

std::vector<uint8_t> Sha256(const std::vector<uint8_t>& bytes) {
  return sealed_sha256::Hash(bytes);
}

std::vector<uint8_t> Sha256(const uint8_t* data, size_t n) {
  return sealed_sha256::Hash(data, n);
}

}  // namespace efs
