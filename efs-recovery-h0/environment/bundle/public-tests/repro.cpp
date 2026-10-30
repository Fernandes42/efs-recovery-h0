// Visible failure reproduction (no diagnosis, no reference patch).
// Exercises the publication incident plus an overlapping async operation.
// Against the faulty starter it prints BUG lines; against the fixed code
// it prints OK lines. Exit code is always 0; the text is the signal.
#include "public-tests/pub.h"

#include <cstdio>

#include "candidate/src/efs_impl.h"

namespace pub {
namespace {

void ReproOnFactory(efs::IDriverFactory& f, const char* label) {
  efs::World w;
  efs::IDriverFactory* fp = &f;
  uint64_t op = 1000;
  auto c0 = Cap(0);

  auto big = Pattern(10000, 11);
  auto bigger = Pattern(12000, 13);  // published update; must survive
  {
    efs::IDriver* d = w.Open(0, fp);
    if (!d->Put(c0, op++, "victim", big).ok())
      std::printf("[%s] setup put failed\n", label);
  }

  // Overlapping async operation admitted before the incident.
  std::vector<uint8_t> async_in = Bytes("overlap-async-original-value");
  {
    efs::IDriver* d = w.Open(0, fp);
    if (d->PutAsync(c0, op, "overlap", async_in) != efs::Err::OK)
      std::printf("[%s] setup put_async failed\n", label);
    // Caller reuses its buffer before deferred encryption consumes it.
    async_in.assign(async_in.size(), 'Z');
    // Crash after publication (contract: publication is the irrevocable
    // linearisation point; the history oracle honours the post-image even
    // without an ack). Correct code flushed data+manifest before
    // publishing, so the new root is intact. Faulty publish-early code
    // published before flushing, so the new root dangles (unflushed
    // objects are discarded on crash).
    w.ArmCrashAfterPublish();
    bool crashed = false;
    try {
      d->Put(c0, op + 1, "victim", bigger);
    } catch (const efs::SimulatedCrash&) {
      crashed = true;
    }
    std::printf("[%s] publication incident crash injected: %s\n", label,
                crashed ? "yes" : "NO");
    w.Crash();
    op += 2;
  }

  // Recovery must honour the published mutation (post-image), never roll
  // back to the pre-image; dangling committed state must fail closed.
  {
    efs::IDriver* d = w.Open(0, fp);
    auto rc = d->Recover();
    std::printf("[%s] recover after incident: %s\n", label,
                efs::ToString(rc.err));
    auto r = d->Read(c0, "victim", 0, bigger.size());
    if (r.ok() && r.value.data == bigger)
      std::printf("[%s] published commit honored: OK\n", label);
    else if (r.ok())
      std::printf("[%s] BUG: published mutation lost/rolled back/mixed\n",
                  label);
    else
      std::printf("[%s] read after incident: %s\n", label,
                  efs::ToString(r.err));
    if (rc.err == efs::Err::CORRUPT_COMMITTED_STATE)
      std::printf(
          "[%s] BUG REPRODUCED: committed root dangles "
          "(manifest references unflushed objects)\n",
          label);
  }

  // Async ownership: the value at enqueue time must win.
  {
    efs::World w2;
    efs::IDriver* d = w2.Open(0, fp);
    uint64_t op2 = 5000;
    std::vector<uint8_t> in = Bytes("async-value-at-enqueue");
    d->PutAsync(c0, op2, "afile", in);
    in.assign(in.size(), 'Q');
    d->Await(op2);
    auto r = d->Read(c0, "afile", 0, 100);
    if (r.ok() && Str(r.value.data) == "async-value-at-enqueue")
      std::printf("[%s] async capture: OK\n", label);
    else if (r.ok())
      std::printf(
          "[%s] BUG REPRODUCED: async commit used caller-mutated "
          "bytes '%s'\n",
          label, Str(r.value.data).c_str());
    else
      std::printf("[%s] async read: %s\n", label,
                  efs::ToString(r.err));
  }
}

}  // namespace

int RunRepro() {
  efs::candidate::Factory f;
  ReproOnFactory(f, "candidate");
  return 0;
}

}  // namespace pub
