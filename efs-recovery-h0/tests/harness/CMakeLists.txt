cmake_minimum_required(VERSION 3.20)
# Wrapper-owned harness build. Compiles the vendored (frozen) verifier
# sources plus the wrapper-owned harness_main.cpp. Links efs_reference
# (verifier-owned oracle, harmless) and NEVER efs_candidate: submitted
# code must not enter the grading process's address space, not even via
# static initializers.
project(efs_harness CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL 3 REQUIRED)

set(EFS_VENDOR "${CMAKE_CURRENT_SOURCE_DIR}/../vendor")

add_executable(efs_harness
  harness_main.cpp
  ${EFS_VENDOR}/trusted/storage.cpp
  ${EFS_VENDOR}/trusted/anchor.cpp
  ${EFS_VENDOR}/trusted/crypto_broker.cpp
  ${EFS_VENDOR}/trusted/allocator.cpp
  ${EFS_VENDOR}/trusted/world.cpp
  ${EFS_VENDOR}/reference/efs_impl.cpp
  ${EFS_VENDOR}/grader/format_parser.cpp
  ${EFS_VENDOR}/grader/oracle.cpp
  ${EFS_VENDOR}/grader/suites.cpp
  ${EFS_VENDOR}/grader/suites2.cpp
  ${EFS_VENDOR}/grader/suites3.cpp
  ${EFS_VENDOR}/grader/suites_oracle.cpp
  ${EFS_VENDOR}/grader/sealed_run.cpp
  ${EFS_VENDOR}/grader/runner.cpp
  ${EFS_VENDOR}/grader/json.cpp
  ${EFS_VENDOR}/grader/profile.cpp
  ${EFS_VENDOR}/sealed/rpc.cpp
  ${EFS_VENDOR}/sealed/driver_stub.cpp
  ${EFS_VENDOR}/sealed/sandbox.cpp
  ${EFS_VENDOR}/sealed/service_proxy.cpp
  ${EFS_VENDOR}/sealed/sha256.cpp)
target_include_directories(efs_harness PRIVATE
  ${EFS_VENDOR}/include ${EFS_VENDOR})
target_link_libraries(efs_harness PRIVATE OpenSSL::Crypto)
