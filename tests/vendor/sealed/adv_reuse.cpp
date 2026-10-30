// Adversarial double 2: nonce reuse across the split. Seals twice under
// the same (tenant, epoch, nonce) through the channel and demands that
// verification of the second object fails. Proves broker auditing
// survived the process split. Verifier-owned (never in candidate image).
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "efs/errors.h"
#include "sealed/rpc.h"
#include "sealed/service_proxy.h"

int main(int argc, char** argv) {
  const char* out = argc > 3 ? argv[3] : "reuse.result";
  uint64_t h = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0;
  FILE* f = fopen(out, "w");
  if (!f) return 2;
  sealed::Channel ch(3);
  sealed::SetChannel(&ch);
  sealed::ProxyBroker broker(h);
  std::vector<uint8_t> aad = {'A', 'D'};
  auto nn = broker.ReserveNonce(0, 0);
  if (!nn.ok()) {
    fprintf(f, "reserve=%s\n", efs::ToString(nn.err));
    fclose(f);
    return 0;
  }
  std::vector<uint8_t> p1 = {1, 2, 3}, p2 = {4, 5, 6};
  auto s1 = broker.Seal(0, 0, nn.value, aad, p1);
  auto s2 = broker.Seal(0, 0, nn.value, aad, p2);  // reuse!
  fprintf(f, "seal1=%s seal2=%s\n", efs::ToString(s1.err),
          efs::ToString(s2.err));
  if (s2.ok()) {
    auto o = broker.Open(0, 0, nn.value, aad, s2.value);
    fprintf(f, "open_reused=%s\n", efs::ToString(o.err));
  }
  fclose(f);
  return 0;
}
