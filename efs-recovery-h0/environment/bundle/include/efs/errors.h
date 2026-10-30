#pragma once
#include <cstdint>
#include <string>

namespace efs {

enum class Err : int {
  OK = 0,
  NOT_FOUND = 1,
  INVALID_ARGUMENT = 2,
  AUTHENTICATION_FAILED = 3,
  PERMISSION_DENIED = 4,
  STALE_ROOT = 5,
  KEY_UNAVAILABLE = 6,
  OUT_OF_MEMORY = 7,
  CANCELLED = 8,
  ALREADY_COMMITTED = 9,
  CORRUPT_COMMITTED_STATE = 10,
};

inline const char* ToString(Err e) {
  switch (e) {
    case Err::OK: return "OK";
    case Err::NOT_FOUND: return "NOT_FOUND";
    case Err::INVALID_ARGUMENT: return "INVALID_ARGUMENT";
    case Err::AUTHENTICATION_FAILED: return "AUTHENTICATION_FAILED";
    case Err::PERMISSION_DENIED: return "PERMISSION_DENIED";
    case Err::STALE_ROOT: return "STALE_ROOT";
    case Err::KEY_UNAVAILABLE: return "KEY_UNAVAILABLE";
    case Err::OUT_OF_MEMORY: return "OUT_OF_MEMORY";
    case Err::CANCELLED: return "CANCELLED";
    case Err::ALREADY_COMMITTED: return "ALREADY_COMMITTED";
    case Err::CORRUPT_COMMITTED_STATE: return "CORRUPT_COMMITTED_STATE";
  }
  return "UNKNOWN";
}

template <typename T>
struct Result {
  Err err = Err::OK;
  T value{};
  static Result Ok(T v) { return {Err::OK, std::move(v)}; }
  static Result Fail(Err e) { return {e, T{}}; }
  bool ok() const { return err == Err::OK; }
};

template <>
struct Result<void> {
  Err err = Err::OK;
  static Result Ok() { return {Err::OK}; }
  static Result Fail(Err e) { return {e}; }
  bool ok() const { return err == Err::OK; }
};

}  // namespace efs
