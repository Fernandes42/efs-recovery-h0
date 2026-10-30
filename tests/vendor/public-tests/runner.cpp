#include <cstdio>

#include "public-tests/pub.h"

int main() {
  int fails = pub::RunSmoke();
  pub::RunRepro();
  if (fails == 0)
    std::printf("PUBLIC TESTS: smoke passed (see repro lines above)\n");
  else
    std::printf("PUBLIC TESTS: smoke FAILS=%d\n", fails);
  return fails == 0 ? 0 : 1;
}
