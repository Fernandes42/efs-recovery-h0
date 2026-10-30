cmake_minimum_required(VERSION 3.20)
# Calibration candidate view: the evaluated agent builds and iterates here.
# Trusted services ship ONLY as a prebuilt static library built WITH
# EFS_DEV_KEYS (per-process keys from OS entropy): the grading keys
# never appear in model-shipped artifacts. No trusted sources ship.
# The verifier rebuilds any submitted candidate/src against the frozen
# verifier image with the fixed recipe in the authoring package
# (packaging/build_recipe.sh) — never with this file.
#
# Dev-lib build (verifier-side, once per revision):
#   g++ -std=c++20 -O2 -DEFS_DEV_KEYS -I <pkg>/include -I <pkg> \
#       -c <pkg>/trusted/<each>.cpp ... && ar rcs libefs_trusted_dev.a ...
# Then verify: strings libefs_trusted_dev.a | grep -c E75F0CA1 == 0
# (the fixed grading seed must be absent) before shipping.
project(efs_calibration CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL 3 REQUIRED)

add_library(efs_trusted STATIC IMPORTED)
set_target_properties(efs_trusted PROPERTIES
  IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/lib/libefs_trusted_dev.a
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/include;${CMAKE_SOURCE_DIR}"
  INTERFACE_LINK_LIBRARIES OpenSSL::Crypto)

add_library(efs_candidate candidate/src/efs_impl.cpp)
target_include_directories(efs_candidate PUBLIC include ${CMAKE_SOURCE_DIR})
target_link_libraries(efs_candidate PUBLIC efs_trusted)

add_executable(public_tests
  public-tests/smoke.cpp
  public-tests/repro.cpp
  public-tests/runner.cpp)
target_include_directories(public_tests PRIVATE include ${CMAKE_SOURCE_DIR})
target_link_libraries(public_tests PRIVATE efs_trusted efs_candidate)

enable_testing()
add_test(NAME public_tests COMMAND public_tests
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
