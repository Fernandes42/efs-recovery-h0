// Verifier-side driver stubs (see driver_stub.h).
#include "sealed/driver_stub.h"

#include "efs/faults.h"

namespace sealed {
namespace {

J CapArgs(uint64_t h, const efs::TenantCap& cap) {
  J a = J::Arr();
  a.arr.push_back(U64(h));
  a.arr.push_back(J::Num(cap.tenant));
  a.arr.push_back(U64(cap.secret));
  return a;
}

J CallRes(Channel* ch, const std::string& method, const J& args) {
  try {
    return ch->Call("D", method, args);
  } catch (const SimCrashWire&) {
    throw efs::SimulatedCrash{};
  } catch (const TimeoutWire&) {
    throw std::runtime_error("candidate timeout (watchdog)");
  }
}

const J& RespGet(const J& r, const char* k) {
  auto it = r.obj.find(k);
  if (r.t != J::T::OBJ || it == r.obj.end())
    throw RemoteError("bad response");
  return it->second;
}

efs::Err ErrOf(const J& r) {
  auto it = r.obj.find("err");
  if (r.t != J::T::OBJ || it == r.obj.end() || it->second.t != J::T::NUM)
    throw RemoteError("bad response");
  return (efs::Err)(int)it->second.num;
}

efs::Result<void> VoidRes(Channel* ch, const std::string& method,
                          const J& args) {
  efs::Err e = ErrOf(CallRes(ch, method, args));
  return e == efs::Err::OK ? efs::Result<void>::Ok()
                           : efs::Result<void>::Fail(e);
}

}  // namespace

RemoteDriver::~RemoteDriver() {
  // Revoke parent-side authorization first (noexcept, always runs), then
  // ask the candidate to drop its side. Order matters: even if the RPC
  // fails (dead peer), the handle must not stay authorized.
  if (factory_) {
    try {
      factory_->CloseHandle(h_);
    } catch (...) {
    }
  }
  try {
    J a = J::Arr();
    a.arr.push_back(U64(h_));
    ch_->Call("D", "close", a);
  } catch (...) {
  }
}

efs::IDriver* RemoteFactory::OpenHandle(uint32_t tenant, efs::IObjectStore* store,
                                        efs::IAnchor* anchor, efs::ICryptoBroker* broker,
                                        efs::IManagedAllocator* alloc,
                                        efs::ILeaseTracker* leases) {
  J a = J::Arr();
  a.arr.push_back(J::Num(tenant));
  J r = CallRes(ch_, "open", a);
  uint64_t h = UnU64(RespGet(r, "h"));
  if (h == 0) throw RemoteError("bad handle cookie");
  if (tenants_.count(h)) throw RemoteError("duplicate handle cookie");
  tenants_[h] = tenant;
  svcs_[h] = SvcSet{store, anchor, broker, alloc, leases};
  return new RemoteDriver(ch_, h, this);
}

void RemoteFactory::RegisterHandle(uint64_t h, uint32_t tenant,
                                   const SvcSet& svcs) {
  if (h == 0 || tenants_.count(h)) throw RemoteError("bad handle register");
  tenants_[h] = tenant;
  svcs_[h] = svcs;
}

void RemoteFactory::CloseHandle(uint64_t h) noexcept {
  try {
    tenants_.erase(h);
    svcs_.erase(h);
    // Revoke allocator cookies owned by this handle. The underlying
    // allocator buffers stay live (leak detection via GetMetrics); only
    // the factory's authorization entries are removed, so stale cookies
    // cannot dereference freed TestWorld memory after teardown.
    for (auto it = buf_handle_.begin(); it != buf_handle_.end();) {
      if (it->second != h) {
        ++it;
        continue;
      }
      uint64_t c = it->first;
      auto b = bufs_.find(c);
      if (b != bufs_.end()) {
        buf_ids_.erase(b->second);
        bufs_.erase(b);
      }
      it = buf_handle_.erase(it);
    }
  } catch (...) {
  }
}

uint64_t RemoteFactory::Cookie() {
  uint64_t c = next_cookie_++;
  if (c == 0) c = next_cookie_++;
  return c;
}

namespace {

bool Mine(uint32_t t, const std::string& id) {
  std::string b = "b_" + std::to_string(t) + "_";
  std::string m = "m_" + std::to_string(t) + "_";
  return id.rfind(b, 0) == 0 || id.rfind(m, 0) == 0;
}

}  // namespace

uint32_t RemoteFactory::Ten(uint64_t h) {
  auto it = tenants_.find(h);
  if (it == tenants_.end()) throw RemoteError("unknown handle");
  return it->second;
}

SvcSet& RemoteFactory::Svcs(uint64_t h) {
  auto it = svcs_.find(h);
  if (it == svcs_.end()) throw RemoteError("unknown handle");
  return it->second;
}

void RemoteFactory::ServeServices() {
  // All handlers translate trusted SimulatedCrash to the wire so crash
  // injection keeps working across the split.
  auto sim = [](std::function<J()> fn) -> J {
    try {
      return fn();
    } catch (const efs::SimulatedCrash&) {
      throw SimCrashWire{};
    }
  };
  ch_->On("S.stage", [this, sim](const J& a) {
    return sim([&] {
      uint64_t h = ArgU64(a, 0);
      std::string id = ArgStr(a, 1);
      if (!Mine(Ten(h), id))
        throw RemoteError("cross-tenant stage rejected");
      J r = J::Obj();
      r.obj["err"] = J::Num((int)Svcs(h).store->Stage(id, ArgBytes(a, 2)));
      return r;
    });
  });
  ch_->On("S.flush", [this, sim](const J& a) {
    return sim([&] {
      uint64_t h = ArgU64(a, 0);
      std::string id = ArgStr(a, 1);
      if (!Mine(Ten(h), id))
        throw RemoteError("cross-tenant flush rejected");
      J r = J::Obj();
      r.obj["err"] = J::Num((int)Svcs(h).store->Flush(id));
      return r;
    });
  });
  ch_->On("S.exists", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    std::string id = ArgStr(a, 1);
    J r = J::Obj();
    bool ok = Mine(Ten(h), id) && Svcs(h).store->DurableExists(id);
    r.obj["present"] = J::Num(ok ? 1 : 0);
    return r;
  });
  ch_->On("S.read", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    std::string id = ArgStr(a, 1);
    J r = J::Obj();
    if (!Mine(Ten(h), id)) {
      r.obj["present"] = J::Num(0);
      return r;
    }
    auto v = Svcs(h).store->ReadDurable(id);
    r.obj["present"] = J::Num(v.has_value() ? 1 : 0);
    if (v.has_value()) r.obj["bytes"] = Bytes(v.value());
    return r;
  });
  ch_->On("S.image", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = Ten(h);
    J r = J::Obj();
    J m = J::Obj();
    for (auto& [id, bytes] : Svcs(h).store->DurableImage())
      if (Mine(t, id)) m.obj[id] = Bytes(bytes);
    r.obj["map"] = m;
    return r;
  });
  ch_->On("S.del", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    std::string id = ArgStr(a, 1);
    if (!Mine(Ten(h), id))
      throw RemoteError("cross-tenant delete rejected");
    Svcs(h).store->DeleteDurable(id);
    J r = J::Obj();
    r.obj["err"] = J::Num(0);
    return r;
  });
  ch_->On("A.get", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = ArgU32(a, 1);
    if (t != Ten(h)) throw RemoteError("cross-tenant anchor");
    efs::AnchorState s = Svcs(h).anchor->Get(t);
    J r = J::Obj();
    r.obj["gen"] = U64(s.generation);
    r.obj["mid"] = J::Str(s.manifest_id);
    r.obj["digest"] = Bytes(s.digest);
    return r;
  });
  ch_->On("A.publish", [this, sim](const J& a) {
    return sim([&] {
      uint64_t h = ArgU64(a, 0);
      uint32_t t = ArgU32(a, 1);
      if (t != Ten(h)) throw RemoteError("cross-tenant anchor");
      J r = J::Obj();
      r.obj["err"] = J::Num((int)Svcs(h).anchor->Publish(
          t, ArgU64(a, 2), ArgStr(a, 3), ArgBytes(a, 4)));
      return r;
    });
  });
  ch_->On("A.pin", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = ArgU32(a, 1);
    if (t != Ten(h)) throw RemoteError("cross-tenant anchor");
    J r = J::Obj();
    r.obj["err"] = J::Num((int)Svcs(h).anchor->Pin(
        t, ArgU64(a, 2), ArgStr(a, 3), ArgBytes(a, 4),
        ArgU64(a, 5)));
    return r;
  });
  ch_->On("A.unpin", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = ArgU32(a, 1);
    if (t != Ten(h)) throw RemoteError("cross-tenant anchor");
    J r = J::Obj();
    r.obj["err"] =
        J::Num((int)Svcs(h).anchor->Unpin(t, ArgU64(a, 2)));
    return r;
  });
  ch_->On("A.pinned", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = ArgU32(a, 1);
    if (t != Ten(h)) throw RemoteError("cross-tenant anchor");
    efs::AnchorState s;
    J r = J::Obj();
    bool found = Svcs(h).anchor->Pinned(t, ArgU64(a, 2), &s);
    r.obj["found"] = J::Num(found ? 1 : 0);
    if (found) {
      r.obj["gen"] = U64(s.generation);
      r.obj["mid"] = J::Str(s.manifest_id);
      r.obj["digest"] = Bytes(s.digest);
    }
    return r;
  });
  ch_->On("A.pins_for", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = ArgU32(a, 1);
    if (t != Ten(h)) throw RemoteError("cross-tenant anchor");
    J r = J::Obj();
    J pins = J::Obj();
    for (auto& [lease, s] : Svcs(h).anchor->PinsFor(t)) {
      J e = J::Obj();
      e.obj["gen"] = U64(s.generation);
      e.obj["mid"] = J::Str(s.manifest_id);
      e.obj["digest"] = Bytes(s.digest);
      pins.obj[std::to_string(lease)] = e;
    }
    r.obj["pins"] = pins;
    return r;
  });
  ch_->On("B.reserve", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = ArgU32(a, 1);
    if (t != Ten(h)) throw RemoteError("cross-tenant broker");
    auto r0 = Svcs(h).broker->ReserveNonce(t, ArgU32(a, 2));
    J r = J::Obj();
    r.obj["err"] = J::Num((int)r0.err);
    if (r0.ok()) r.obj["nonce"] = Bytes(r0.value);
    return r;
  });
  ch_->On("B.seal", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = ArgU32(a, 1);
    if (t != Ten(h)) throw RemoteError("cross-tenant broker");
    auto r0 = Svcs(h).broker->Seal(t, ArgU32(a, 2),
                                   ArgBytes(a, 3), ArgBytes(a, 4),
                                   ArgBytes(a, 5));
    J r = J::Obj();
    r.obj["err"] = J::Num((int)r0.err);
    if (r0.ok()) r.obj["ct"] = Bytes(r0.value);
    return r;
  });
  ch_->On("B.open", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = ArgU32(a, 1);
    if (t != Ten(h)) throw RemoteError("cross-tenant broker");
    auto r0 = Svcs(h).broker->Open(t, ArgU32(a, 2),
                                   ArgBytes(a, 3), ArgBytes(a, 4),
                                   ArgBytes(a, 5));
    J r = J::Obj();
    r.obj["err"] = J::Num((int)r0.err);
    if (r0.ok()) r.obj["pt"] = Bytes(r0.value);
    return r;
  });
  ch_->On("M.alloc", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    size_t n = ArgSize(a, 1);
    auto r0 = Svcs(h).alloc->Allocate(n);
    J r = J::Obj();
    r.obj["err"] = J::Num((int)r0.err);
    if (r0.ok()) {
      uint64_t c = Cookie();
      bufs_[c] = r0.value;
      buf_handle_[c] = h;
      buf_ids_[r0.value] = c;
      r.obj["buf"] = U64(c);
    }
    return r;
  });
  auto bufptr = [this](uint64_t h, const J& a) -> std::vector<uint8_t>* {
    uint64_t c = ArgU64(a, 1);
    auto it = bufs_.find(c);
    auto jt = buf_handle_.find(c);
    // Same-handle binding (not just same-tenant): a new incarnation with
    // the same tenant must not reuse the old handle's cookies. No
    // operator[] insertion on the lookup path (fail closed, no mutation).
    if (it == bufs_.end() || jt == buf_handle_.end() || jt->second != h)
      throw RemoteError("bad buffer cookie");
    // Handle must still be authorized (revoked on CloseHandle).
    (void)Ten(h);
    return it->second;
  };
  auto ok0 = [] {
    J r = J::Obj();
    r.obj["err"] = J::Num(0);
    return r;
  };
  ch_->On("M.erase", [this, bufptr, ok0](const J& a) {
    uint64_t h = ArgU64(a, 0);
    Svcs(h).alloc->SecureErase(bufptr(h, a));
    return ok0();
  });
  ch_->On("M.release", [this, bufptr, ok0](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint64_t c = ArgU64(a, 1);
    std::vector<uint8_t>* p = bufptr(h, a);
    Svcs(h).alloc->Release(p);
    buf_ids_.erase(p);
    bufs_.erase(c);
    buf_handle_.erase(c);
    return ok0();
  });
  ch_->On("M.copy", [this, bufptr, ok0](const J& a) {
    uint64_t h = ArgU64(a, 0);
    std::vector<uint8_t> chunk = ArgBytes(a, 2);
    size_t off = ArgSize(a, 3);
    Svcs(h).alloc->Copy(bufptr(h, a), chunk.data(), chunk.size(), off);
    return ok0();
  });
  ch_->On("M.read", [this, bufptr](const J& a) {
    uint64_t h = ArgU64(a, 0);
    (void)h;
    std::vector<uint8_t>* p = bufptr(h, a);
    J r = J::Obj();
    r.obj["bytes"] = Bytes(*p);
    return r;
  });
  ch_->On("L.admit", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = Ten(h);
    std::vector<std::string> ids;
    for (auto& e : ArgArr(a, 1)) {
      if (!Mine(t, e.str)) throw RemoteError("cross-tenant lease");
      ids.push_back(e.str);
    }
    J r = J::Obj();
    r.obj["lease"] = U64(Svcs(h).leases->Admit(ids));
    return r;
  });
  ch_->On("L.release", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    Svcs(h).leases->ReleaseLease(ArgU64(a, 1));
    J r = J::Obj();
    r.obj["err"] = J::Num(0);
    return r;
  });
  ch_->On("L.protected", [this](const J& a) {
    uint64_t h = ArgU64(a, 0);
    uint32_t t = Ten(h);
    J r = J::Obj();
    J ids = J::Arr();
    for (auto& id : Svcs(h).leases->Protected())
      if (Mine(t, id)) ids.arr.push_back(J::Str(id));
    r.obj["ids"] = ids;
    return r;
  });
}

efs::Result<efs::ReadOut> RemoteDriver::Read(
    const efs::TenantCap& cap, const std::string& name, uint64_t offset,
    size_t length) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(J::Str(name));
  a.arr.push_back(U64(offset));
  a.arr.push_back(U64(length));
  J r = CallRes(ch_, "read", a);
  efs::Err e = ErrOf(r);
  if (e != efs::Err::OK) return efs::Result<efs::ReadOut>::Fail(e);
  efs::ReadOut o;
  o.data = Unbytes(RespGet(r, "data"));
  return efs::Result<efs::ReadOut>::Ok(std::move(o));
}

efs::Result<void> RemoteDriver::Put(const efs::TenantCap& cap, uint64_t op_id,
                                    const std::string& name,
                                    const std::vector<uint8_t>& bytes) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  a.arr.push_back(J::Str(name));
  a.arr.push_back(Bytes(bytes));
  return VoidRes(ch_, "put", a);
}

efs::Result<void> RemoteDriver::WriteRange(
    const efs::TenantCap& cap, uint64_t op_id, const std::string& name,
    uint64_t offset, const std::vector<uint8_t>& bytes) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  a.arr.push_back(J::Str(name));
  a.arr.push_back(U64(offset));
  a.arr.push_back(Bytes(bytes));
  return VoidRes(ch_, "write_range", a);
}

efs::Result<void> RemoteDriver::Truncate(const efs::TenantCap& cap,
                                         uint64_t op_id,
                                         const std::string& name,
                                         uint64_t new_length) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  a.arr.push_back(J::Str(name));
  a.arr.push_back(U64(new_length));
  return VoidRes(ch_, "truncate", a);
}

efs::Result<void> RemoteDriver::Rename(const efs::TenantCap& cap,
                                       uint64_t op_id, const std::string& from,
                                       const std::string& to) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  a.arr.push_back(J::Str(from));
  a.arr.push_back(J::Str(to));
  return VoidRes(ch_, "rename", a);
}

efs::Result<void> RemoteDriver::Remove(const efs::TenantCap& cap,
                                       uint64_t op_id,
                                       const std::string& name) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  a.arr.push_back(J::Str(name));
  return VoidRes(ch_, "remove", a);
}

efs::Err RemoteDriver::PutAsync(const efs::TenantCap& cap, uint64_t op_id,
                                const std::string& name,
                                const std::vector<uint8_t>& input) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  a.arr.push_back(J::Str(name));
  a.arr.push_back(Bytes(input));
  return ErrOf(CallRes(ch_, "put_async", a));
}

efs::Result<void> RemoteDriver::Await(uint64_t op_id) {
  J a = J::Arr();
  a.arr.push_back(U64(h_));
  a.arr.push_back(U64(op_id));
  return VoidRes(ch_, "await", a);
}

efs::Result<void> RemoteDriver::Cancel(uint64_t op_id) {
  J a = J::Arr();
  a.arr.push_back(U64(h_));
  a.arr.push_back(U64(op_id));
  return VoidRes(ch_, "cancel", a);
}

efs::Result<efs::SnapshotHandle> RemoteDriver::Snapshot(
    const efs::TenantCap& cap, uint64_t op_id) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  J r = CallRes(ch_, "snapshot", a);
  efs::Err e = ErrOf(r);
  if (e != efs::Err::OK)
    return efs::Result<efs::SnapshotHandle>::Fail(e);
  return efs::Result<efs::SnapshotHandle>::Ok(
      (efs::SnapshotHandle)UnU64(RespGet(r, "snap")));
}

efs::Result<efs::ReadOut> RemoteDriver::ReadSnapshot(
    const efs::TenantCap& cap, efs::SnapshotHandle snap,
    const std::string& name, uint64_t offset, size_t length) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(snap));
  a.arr.push_back(J::Str(name));
  a.arr.push_back(U64(offset));
  a.arr.push_back(U64(length));
  J r = CallRes(ch_, "read_snapshot", a);
  efs::Err e = ErrOf(r);
  if (e != efs::Err::OK) return efs::Result<efs::ReadOut>::Fail(e);
  efs::ReadOut o;
  o.data = Unbytes(RespGet(r, "data"));
  return efs::Result<efs::ReadOut>::Ok(std::move(o));
}

efs::Result<void> RemoteDriver::ReleaseSnapshot(
    const efs::TenantCap& cap, efs::SnapshotHandle snap) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(snap));
  return VoidRes(ch_, "release_snapshot", a);
}

efs::Result<void> RemoteDriver::BeginRotation(const efs::TenantCap& cap,
                                              uint64_t op_id) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  return VoidRes(ch_, "begin_rotation", a);
}

efs::Result<void> RemoteDriver::MigrateFile(const efs::TenantCap& cap,
                                            uint64_t op_id,
                                            const std::string& name) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  a.arr.push_back(J::Str(name));
  return VoidRes(ch_, "migrate_file", a);
}

efs::Result<void> RemoteDriver::FinishRotation(const efs::TenantCap& cap,
                                               uint64_t op_id) {
  J a = CapArgs(h_, cap);
  a.arr.push_back(U64(op_id));
  return VoidRes(ch_, "finish_rotation", a);
}

efs::Result<void> RemoteDriver::Recover() {
  J a = J::Arr();
  a.arr.push_back(U64(h_));
  return VoidRes(ch_, "recover", a);
}

efs::Result<void> RemoteDriver::Collect() {
  J a = J::Arr();
  a.arr.push_back(U64(h_));
  return VoidRes(ch_, "collect", a);
}

}  // namespace sealed
