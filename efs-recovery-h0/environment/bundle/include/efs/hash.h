#pragma once
// SHA-256 over bytes (OpenSSL-backed, trusted implementation in
// trusted/world.cpp). Part of the narrow candidate-visible surface:
// drivers need it to verify anchor digests.
#include <cstddef>
#include <cstdint>
#include <vector>

namespace efs {

std::vector<uint8_t> Sha256(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> Sha256(const uint8_t* data, size_t n);

}  // namespace efs
