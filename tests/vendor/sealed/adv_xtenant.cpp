// Adversarial double 3: cross-tenant access from a tenant-0 handle.
// Every attempt must be rejected by verifier-side dispatch, and the
// victim tenant's state must remain intact. Verifier-owned.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "sealed/rpc.h"
#include "sealed/service_proxy.h"

#define TRY(label, expr)                                   \
  do {                                                     \
    bool rejected = false;                                 \
    std::string why;                                       \
    try {                                                  \
      expr;                                                \
    } catch (const std::exception& e) {                    \
      rejected = true;                                     \
      why = e.what();                                      \
    }                                                      \
    fprintf(f, "%s %s %s\n", rejected ? "rejected" : "ALLOWED", label, \
            why.c_str());                                  \
    if (!rejected) ++allowed;                              \
  } while (0)

int main(int argc, char** argv) {
  const char* victim = argc > 3 ? argv[3] : "";
  const char* out = argc > 4 ? argv[4] : "xtenant.result";
  uint64_t h = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0;
  FILE* f = fopen(out, "w");
  if (!f) return 2;
  sealed::Channel ch(3);
  sealed::SetChannel(&ch);
  sealed::ProxyStore store(h);
  sealed::ProxyAnchor anchor(h);
  sealed::ProxyBroker broker(h);
  int allowed = 0;
  std::vector<uint8_t> v = {9, 9, 9};
  TRY("stage_t1", store.Stage("b_1_777_1_0_0", v));
  TRY("flush_t1", store.Flush("b_1_777_1_0_0"));
  {  // reads deny data (empty), not exceptions
    bool got = false;
    try {
      got = store.ReadDurable(victim).has_value();
    } catch (const std::exception&) {
      got = false;
    }
    fprintf(f, "%s read_t1\n", got ? "ALLOWED" : "rejected");
    if (got) ++allowed;
  }
  TRY("delete_t1", store.DeleteDurable(victim));
  TRY("anchor_t1", anchor.Get(1));
  TRY("publish_t1", anchor.Publish(1, 0, "m_1_99", v));
  TRY("broker_t1", broker.Seal(1, 0, std::vector<uint8_t>(12, 1), v, v));
  TRY("pin_t1", anchor.Pin(1, 1, "m_1_99", v, 4242));
  fprintf(f, "allowed_total=%d\n", allowed);
  fclose(f);
  return 0;
}
