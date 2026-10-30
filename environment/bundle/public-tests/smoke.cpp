// Ordinary sequential/no-crash smoke tests. The starter must pass these.
#include "public-tests/pub.h"

#include <cstdio>

#include "candidate/src/efs_impl.h"

namespace pub {
namespace {

int fails = 0;
#define CHECK(cond, msg)                                        \
  do {                                                          \
    if (!(cond)) {                                              \
      std::printf("SMOKE FAIL %s:%d: %s\n", __FILE__, __LINE__, \
                  msg);                                         \
      ++fails;                                                  \
    }                                                           \
  } while (0)

int SmokeOnFactory(efs::IDriverFactory& f, const char* label) {
  efs::World w;
  efs::IDriver* d0 = w.Open(0, &f);
  efs::IDriver* d1 = w.Open(1, &f);
  uint64_t op = 1;
  auto c0 = Cap(0), c1 = Cap(1);

  // Empty file + boundary sizes.
  CHECK(d0->Put(c0, op++, "empty", {}).ok(), "put empty");
  auto r = d0->Read(c0, "empty", 0, 100);
  CHECK(r.ok() && r.value.data.empty(), "read empty");

  auto big = Pattern(10000, 1);
  CHECK(d0->Put(c0, op++, "big", big).ok(), "put big");
  r = d0->Read(c0, "big", 0, big.size());
  CHECK(r.ok() && r.value.data == big, "read big");
  r = d0->Read(c0, "big", 999990, 100);
  CHECK(r.ok() && r.value.data.empty(), "read beyond EOF");
  r = d0->Read(c0, "big", 4090, 20);  // cross-block slice
  CHECK(r.ok() &&
            r.value.data ==
                std::vector<uint8_t>(big.begin() + 4090,
                                     big.begin() + 4110),
        "cross-block slice");

  // Partial-block range overwrite preserves untouched ranges.
  auto patch = Pattern(100, 7);
  CHECK(d0->WriteRange(c0, op++, "big", 100, patch).ok(), "write_range");
  r = d0->Read(c0, "big", 0, big.size());
  bool kept = r.ok() && r.value.data.size() == big.size();
  for (size_t i = 0; kept && i < big.size(); ++i) {
    uint8_t want =
        (i >= 100 && i < 200) ? patch[i - 100] : big[i];
    if (r.value.data[i] != want) kept = false;
  }
  CHECK(kept, "range overwrite preserves rest");

  // Shrink-only truncate.
  CHECK(d0->Truncate(c0, op++, "big", 5000).ok(), "truncate shrink");
  r = d0->Read(c0, "big", 0, 6000);
  CHECK(r.ok() && r.value.data.size() == 5000, "truncated length");
  CHECK(d0->Truncate(c0, op++, "big", 6000).err ==
            efs::Err::INVALID_ARGUMENT,
        "truncate extension rejected");

  // Rename preserves identity; no overwrite.
  CHECK(d0->Put(c0, op++, "other", Bytes("x")).ok(), "put other");
  CHECK(d0->Rename(c0, op++, "big", "other").err ==
            efs::Err::INVALID_ARGUMENT,
        "rename onto existing rejected");
  CHECK(d0->Rename(c0, op++, "big", "big2").ok(), "rename");
  r = d0->Read(c0, "big2", 0, 5000);
  CHECK(r.ok() && r.value.data.size() == 5000, "renamed contents");
  CHECK(d0->Read(c0, "big", 0, 1).err == efs::Err::NOT_FOUND,
        "old name gone");

  // Remove + recreate mints progress (readable under new content).
  CHECK(d0->Remove(c0, op++, "big2").ok(), "remove");
  CHECK(d0->Read(c0, "big2", 0, 1).err == efs::Err::NOT_FOUND,
        "removed gone");
  CHECK(d0->Put(c0, op++, "big2", Bytes("fresh")).ok(), "recreate");
  r = d0->Read(c0, "big2", 0, 5);
  CHECK(r.ok() && Str(r.value.data) == "fresh", "recreated contents");

  // Tenant isolation.
  CHECK(d1->Read(c1, "big2", 0, 1).err == efs::Err::NOT_FOUND,
        "tenant isolation");
  efs::TenantCap wrong{0, 999};
  CHECK(d0->Read(wrong, "big2", 0, 1).err == efs::Err::PERMISSION_DENIED,
        "bad capability rejected");

  // Name validation.
  for (const char* bad : {"", "a/b", ".", ".."}) {
    CHECK(d0->Put(c0, op++, bad, Bytes("z")).err ==
              efs::Err::INVALID_ARGUMENT,
          "bad name rejected");
  }

  // Async capture: mutate caller buffer after enqueue; data must hold.
  {
    std::vector<uint8_t> in = Bytes("async-payload-data");
    CHECK(d0->PutAsync(c0, op++, "asyncf", in) == efs::Err::OK,
          "put_async");
    in.assign(in.size(), 'M');  // caller reuse before encryption
    auto a = d0->Await(op - 1);
    CHECK(a.ok(), "await ok");
    auto rr = d0->Read(c0, "asyncf", 0, 100);
    (void)rr;
    // NOTE: starter defect 3 makes this read back mutated data; the
    // public smoke only requires await success, not the value. The
    // visible repro pins the value for the reference/correct path.
  }

  // Snapshot round-trip on live data.
  {
    auto s = d0->Snapshot(c0, op++);
    CHECK(s.ok(), "snapshot");
    CHECK(d0->Put(c0, op++, "big2", Bytes("v2")).ok(), "overwrite live");
    auto sr = d0->ReadSnapshot(c0, s.value, "big2", 0, 100);
    CHECK(sr.ok() && Str(sr.value.data) == "fresh", "snapshot pinned");
    auto live = d0->Read(c0, "big2", 0, 100);
    CHECK(live.ok() && Str(live.value.data) == "v2", "live advanced");
    CHECK(d0->ReleaseSnapshot(c0, s.value).ok(), "release snapshot");
  }

  // Rotation happy path: begin, migrate all, finish.
  {
    CHECK(d0->BeginRotation(c0, op++).ok(), "begin rotation");
    CHECK(d0->MigrateFile(c0, op++, "big2").ok(), "migrate big2");
    CHECK(d0->MigrateFile(c0, op++, "empty").ok(), "migrate empty");
    CHECK(d0->MigrateFile(c0, op++, "other").ok(), "migrate other");
    CHECK(d0->MigrateFile(c0, op++, "asyncf").ok(), "migrate asyncf");
    auto fr = d0->FinishRotation(c0, op++);
    CHECK(fr.ok(), "finish rotation");
    auto rr = d0->Read(c0, "big2", 0, 100);
    CHECK(rr.ok() && Str(rr.value.data) == "v2", "post-rotation read");
  }

  // Recover on healthy root + collect converge.
  CHECK(d0->Recover().ok(), "recover healthy");
  CHECK(d0->Recover().ok(), "recover twice");
  CHECK(d0->Collect().ok(), "collect");
  CHECK(d0->Collect().ok(), "collect twice");

  std::printf("[%s] smoke done, fails=%d\n", label, fails);
  return fails;
}

}  // namespace

int RunSmoke() {
  efs::candidate::Factory f;
  return SmokeOnFactory(f, "candidate");
}

}  // namespace pub
