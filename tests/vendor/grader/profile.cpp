// Profile + budget manifest loading/saving.
#include "grader/grader.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace grader {

namespace {
std::string ReadFile(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open " + path);
  std::ostringstream o;
  o << f.rdbuf();
  return o.str();
}
bool GetBool(const Json& j, const std::string& k, bool dflt) {
  auto it = j.obj.find(k);
  if (it == j.obj.end() || it->second.t != Json::T::NUM) return dflt;
  return it->second.num != 0;
}
double GetNum(const Json& j, const std::string& k, double dflt) {
  auto it = j.obj.find(k);
  if (it == j.obj.end() || it->second.t != Json::T::NUM) return dflt;
  return it->second.num;
}
}  // namespace

Profile Profile::Load(const std::string& path) {
  Json j = Json::Parse(ReadFile(path));
  Profile p;
  auto it = j.obj.find("name");
  if (it != j.obj.end() && it->second.t == Json::T::STR) p.name = it->second.str;
  p.writers = (int)GetNum(j, "writers", 1);
  p.readers = (int)GetNum(j, "readers", 1);
  p.async_in_flight = (int)GetNum(j, "async_in_flight", 2);
  p.epochs = (int)GetNum(j, "epochs", 1);
  p.snapshots = GetBool(j, "snapshots", true);
  p.gc = GetBool(j, "gc", true);
  p.range_ops = GetBool(j, "range_ops", true);
  p.rotation = GetBool(j, "rotation", true);
  p.multi_crash = GetBool(j, "multi_crash", true);
  p.replay = GetBool(j, "replay", true);
  p.revocation = GetBool(j, "revocation", true);
  p.outage = GetBool(j, "outage", true);
  auto wit = j.obj.find("workload_bytes");
  if (wit != j.obj.end() && wit->second.t == Json::T::ARR)
    for (auto& e : wit->second.arr) p.workload_bytes.push_back((size_t)e.num);
  auto sit = j.obj.find("seeds");
  if (sit != j.obj.end() && sit->second.t == Json::T::ARR)
    for (auto& e : sit->second.arr) p.seeds.push_back((uint64_t)e.num);
  if (p.workload_bytes.empty()) p.workload_bytes = {16384};
  if (p.seeds.empty()) p.seeds = {11};
  return p;
}

Profile Profile::H0() {
  Profile p;
  p.name = "H0";
  p.writers = 3;
  p.readers = 2;
  p.async_in_flight = 6;
  p.epochs = 3;
  p.snapshots = p.gc = p.range_ops = p.rotation = true;
  p.multi_crash = p.replay = p.revocation = p.outage = true;
  // Narrowed to exercised single-file sizes (1M/4M exceed the 256 KiB
  // per-file limit and are not single-file workloads) and the primary
  // seed (suites use fixed internal seeds; budget workload uses seed0).
  // Writers/readers are declared limits, NOT consumed: no suite reads
  // them (see the F-C note in WRAPPER_NOTES.md). Suites use deterministic
  // sequential calls + async-overlap (async_in_flight, 6 in-flight),
  // not OS threads; writers/readers are not a tested coverage dimension.
  // Human review: whether to add multi-file 4M live-total workload
  // (requires budget re-derive) or update docs scale claims.
  p.workload_bytes = {16384, 65536, 262144};
  p.seeds = {11};
  return p;
}

Budgets Budgets::Load(const std::string& path) {
  Json j = Json::Parse(ReadFile(path));
  Budgets b;
  b.max_alloc_count = (uint64_t)GetNum(j, "max_alloc_count", 0);
  b.max_copied_bytes = (uint64_t)GetNum(j, "max_copied_bytes", 0);
  b.max_peak_managed = (uint64_t)GetNum(j, "max_peak_managed", 0);
  b.max_live_after_quiescence =
      (uint64_t)GetNum(j, "max_live_after_quiescence", 0);
  return b;
}

void Budgets::Save(const std::string& path) const {
  Json j;
  j.t = Json::T::OBJ;
  auto num = [](uint64_t v) {
    Json e;
    e.t = Json::T::NUM;
    e.num = (double)v;
    return e;
  };
  j.obj["max_alloc_count"] = num(max_alloc_count);
  j.obj["max_copied_bytes"] = num(max_copied_bytes);
  j.obj["max_peak_managed"] = num(max_peak_managed);
  j.obj["max_live_after_quiescence"] = num(max_live_after_quiescence);
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f << j.Dump() << "\n";
}

}  // namespace grader
