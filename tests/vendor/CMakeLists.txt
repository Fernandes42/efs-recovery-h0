cmake_minimum_required(VERSION 3.20)
project(efs_eval CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(SANITIZE STREQUAL "asan-ubsan")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
elseif(SANITIZE STREQUAL "ubsan")
  add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=undefined)
elseif(SANITIZE STREQUAL "tsan")
  add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
  add_link_options(-fsanitize=thread)
endif()

find_package(OpenSSL 3 REQUIRED)

add_library(efs_trusted
  trusted/storage.cpp
  trusted/anchor.cpp
  trusted/crypto_broker.cpp
  trusted/allocator.cpp
  trusted/world.cpp)
target_include_directories(efs_trusted PUBLIC include ${CMAKE_SOURCE_DIR})
target_link_libraries(efs_trusted PUBLIC OpenSSL::Crypto)

add_library(efs_reference reference/efs_impl.cpp)
target_include_directories(efs_reference PUBLIC include ${CMAKE_SOURCE_DIR})
target_link_libraries(efs_reference PUBLIC efs_trusted)

add_library(efs_candidate candidate/src/efs_impl.cpp)
target_include_directories(efs_candidate PUBLIC include ${CMAKE_SOURCE_DIR})
target_link_libraries(efs_candidate PUBLIC efs_trusted)

add_executable(grader
  grader/main.cpp
  grader/format_parser.cpp
  grader/oracle.cpp
  grader/suites.cpp
  grader/suites2.cpp
  grader/suites3.cpp
  grader/suites_oracle.cpp
  grader/sealed_run.cpp
  grader/runner.cpp
  sealed/rpc.cpp
  sealed/driver_stub.cpp
  sealed/sandbox.cpp
  grader/json.cpp
  grader/profile.cpp)
target_include_directories(grader PRIVATE include ${CMAKE_SOURCE_DIR})
target_link_libraries(grader PRIVATE efs_trusted efs_reference efs_candidate)

add_executable(public_tests
  public-tests/smoke.cpp
  public-tests/repro.cpp
  public-tests/runner.cpp)
target_include_directories(public_tests PRIVATE include ${CMAKE_SOURCE_DIR})
target_link_libraries(public_tests PRIVATE efs_trusted efs_candidate)

enable_testing()
add_test(NAME public_tests COMMAND public_tests
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME grader_h0_reference COMMAND grader --profile profiles/H0.json
  --budgets profiles/budgets.json --factory reference
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
