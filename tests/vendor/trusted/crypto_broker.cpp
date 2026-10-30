#include "trusted/impl.h"

#include <cstdint>
#include <cstring>
#include <random>

#include <openssl/evp.h>

namespace efs {
namespace {

std::string AuditKey(uint32_t t, uint32_t e, const std::vector<uint8_t>& n) {
  std::string k;
  k.reserve(8 + n.size());
  k.push_back(static_cast<char>(t));
  k.push_back(static_cast<char>(e));
  k.append(reinterpret_cast<const char*>(n.data()), n.size());
  return k;
}

}  // namespace

CryptoBrokerImpl::CryptoBrokerImpl() {
  // Deterministic keys (fixed seed) so evidence is reproducible.
  // Model-facing dev builds define EFS_DEV_KEYS to draw per-process
  // keys from OS entropy instead: identical behavior, and the grading
  // keys never appear in model-shipped artifacts. The verifier always
  // builds without EFS_DEV_KEYS.
#ifdef EFS_DEV_KEYS
  std::random_device rd;
  std::mt19937_64 rng((uint64_t(rd()) << 32) | rd());
#else
  std::mt19937_64 rng(0xE75F0CA1u);
#endif
  for (uint32_t t = 0; t < kNumTenants; ++t)
    for (uint32_t e = 0; e < kNumEpochs; ++e) {
      for (int i = 0; i < 32; ++i) keys_[t][e][i] = uint8_t(rng() & 0xFF);
      counters_[t][e] = 0;
      available_[t][e] = true;
      revoked_[t][e] = false;
    }
}

std::vector<uint8_t> CryptoBrokerImpl::key_for(uint32_t tenant,
                                               uint32_t epoch) const {
  return std::vector<uint8_t>(keys_[tenant][epoch],
                              keys_[tenant][epoch] + 32);
}

Result<std::vector<uint8_t>> CryptoBrokerImpl::ReserveNonce(uint32_t tenant,
                                                            uint32_t epoch) {
  if (tenant >= kNumTenants || epoch >= kNumEpochs)
    return Result<std::vector<uint8_t>>::Fail(Err::INVALID_ARGUMENT);
  if (!available_[tenant][epoch] || revoked_[tenant][epoch])
    return Result<std::vector<uint8_t>>::Fail(Err::KEY_UNAVAILABLE);
  if (counters_[tenant][epoch] == UINT64_MAX)
    return Result<std::vector<uint8_t>>::Fail(Err::OUT_OF_MEMORY);
  uint64_t c = ++counters_[tenant][epoch];
  std::vector<uint8_t> n(kNonceLen);
  n[0] = uint8_t(tenant & 0xFF);
  n[1] = uint8_t((tenant >> 8) & 0xFF);
  n[2] = uint8_t((tenant >> 16) & 0xFF);
  n[3] = uint8_t((tenant >> 24) & 0xFF);
  for (int i = 0; i < 8; ++i) n[4 + i] = uint8_t((c >> (56 - 8 * i)) & 0xFF);
  return Result<std::vector<uint8_t>>::Ok(std::move(n));
}

Result<std::vector<uint8_t>> CryptoBrokerImpl::Seal(
    uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& plaintext) {
  if (tenant >= kNumTenants || epoch >= kNumEpochs)
    return Result<std::vector<uint8_t>>::Fail(Err::INVALID_ARGUMENT);
  if (nonce.size() != kNonceLen)
    return Result<std::vector<uint8_t>>::Fail(Err::INVALID_ARGUMENT);
  if (!available_[tenant][epoch] || revoked_[tenant][epoch])
    return Result<std::vector<uint8_t>>::Fail(Err::KEY_UNAVAILABLE);
  // Audit every attempt under the actual key identity, including attempts
  // the caller later abandons. Never silently replace the nonce.
  use_count_[AuditKey(tenant, epoch, nonce)]++;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return Result<std::vector<uint8_t>>::Fail(Err::KEY_UNAVAILABLE);
  std::vector<uint8_t> out(plaintext.size() + kTagLen);
  int len = 0;
  bool ok = false;
  auto key = key_for(tenant, epoch);
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ==
      1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) ==
          1 &&
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) ==
          1) {
    int alen = 0;
    if (!aad.empty())
      ok = EVP_EncryptUpdate(ctx, nullptr, &alen, aad.data(),
                             (int)aad.size()) == 1;
    else
      ok = true;
    if (ok) {
      int clen = 0;
      ok = EVP_EncryptUpdate(ctx, out.data(), &clen, plaintext.data(),
                             (int)plaintext.size()) == 1;
      len = clen;
      int flen = 0;
      ok = ok && EVP_EncryptFinal_ex(ctx, out.data() + len, &flen) == 1;
      len += flen;
      ok = ok &&
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen,
                               out.data() + plaintext.size()) == 1;
      len = (int)plaintext.size() + (int)kTagLen;
    }
  }
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) return Result<std::vector<uint8_t>>::Fail(Err::KEY_UNAVAILABLE);
  out.resize(len);
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> CryptoBrokerImpl::Open(
    uint32_t tenant, uint32_t epoch, const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& ciphertext_and_tag) {
  if (tenant >= kNumTenants || epoch >= kNumEpochs)
    return Result<std::vector<uint8_t>>::Fail(Err::INVALID_ARGUMENT);
  if (nonce.size() != kNonceLen ||
      ciphertext_and_tag.size() < kTagLen)
    return Result<std::vector<uint8_t>>::Fail(
        Err::AUTHENTICATION_FAILED);
  if (!available_[tenant][epoch] || revoked_[tenant][epoch])
    return Result<std::vector<uint8_t>>::Fail(Err::KEY_UNAVAILABLE);
  // Duplicate (key, nonce) use fails verification even if the second
  // object never reached storage.
  auto it = use_count_.find(AuditKey(tenant, epoch, nonce));
  size_t uses = (it == use_count_.end()) ? 0 : it->second;
  if (uses > 1)
    return Result<std::vector<uint8_t>>::Fail(
        Err::AUTHENTICATION_FAILED);

  size_t ct_len = ciphertext_and_tag.size() - kTagLen;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return Result<std::vector<uint8_t>>::Fail(Err::KEY_UNAVAILABLE);
  std::vector<uint8_t> out(ct_len);
  bool ok = false;
  auto key = key_for(tenant, epoch);
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ==
      1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) ==
          1 &&
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) ==
          1) {
    int alen = 0;
    ok = true;
    if (!aad.empty())
      ok = EVP_DecryptUpdate(ctx, nullptr, &alen, aad.data(),
                             (int)aad.size()) == 1;
    if (ok) {
      int plen = 0;
      ok = EVP_DecryptUpdate(ctx, out.data(), &plen,
                             ciphertext_and_tag.data(), (int)ct_len) == 1;
      if (ok &&
          EVP_CIPHER_CTX_ctrl(
              ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
              (void*)(ciphertext_and_tag.data() + ct_len)) == 1) {
        int flen = 0;
        ok = EVP_DecryptFinal_ex(ctx, out.data() + plen, &flen) == 1;
      } else {
        ok = false;
      }
    }
  }
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    return Result<std::vector<uint8_t>>::Fail(Err::AUTHENTICATION_FAILED);
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

size_t CryptoBrokerImpl::NonceUseCount(
    uint32_t tenant, uint32_t epoch,
    const std::vector<uint8_t>& nonce) const {
  auto it = use_count_.find(AuditKey(tenant, epoch, nonce));
  return it == use_count_.end() ? 0 : it->second;
}

void CryptoBrokerImpl::Crash() {
  // Durable counters/keys/audit survive; nothing volatile to clear.
}

void CryptoBrokerImpl::SetEpochAvailable(uint32_t tenant, uint32_t epoch,
                                         bool available) {
  if (tenant < kNumTenants && epoch < kNumEpochs)
    available_[tenant][epoch] = available;
}

void CryptoBrokerImpl::RevokeEpoch(uint32_t tenant, uint32_t epoch) {
  if (tenant < kNumTenants && epoch < kNumEpochs) {
    revoked_[tenant][epoch] = true;
    available_[tenant][epoch] = false;
  }
}

bool CryptoBrokerImpl::EpochAvailable(uint32_t tenant,
                                      uint32_t epoch) const {
  if (tenant >= kNumTenants || epoch >= kNumEpochs) return false;
  return available_[tenant][epoch] && !revoked_[tenant][epoch];
}

}  // namespace efs
