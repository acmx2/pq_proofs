# MIT License
# Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

cmake_minimum_required(VERSION 3.16)
project(BatchQuintetCommitmentSuite VERSION 1.0.0 LANGUAGES CXX)

# Enforce strict modern C++20 language layout invariants parameters
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Configure hardened production compiler flags and warning constraints
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Werror
        -O3
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_compile_options(
        /W4
        /WX
        /O2
    )
endif()

# FIXED: Removed all OpenSSL discovery directives to preserve zero-dependency isolation

# Declare corporate workspace global directory paths definitions
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# Declare internal source files suite modules tracking list
set(SUITE_SOURCES
    ${SRC_DIR}/common_procedures.cpp
    ${SRC_DIR}/super_array.cpp
    ${SRC_DIR}/challenge_builder.cpp
    ${SRC_DIR}/io_helper.cpp
    ${SRC_DIR}/merkle_tree.cpp
    ${SRC_DIR}/prover.cpp
    ${SRC_DIR}/verifier.cpp
)

# Define the primary test flight sequence executable build target
add_executable(batch_test_suite
    ${SUITE_SOURCES}
    ${TESTS_DIR}/metrics_aggregator.cpp
    ${TESTS_DIR}/test_main.cpp
)

# Configure include directories targets mappings
target_include_directories(batch_test_suite PRIVATE ${INCLUDE_DIR} ${TESTS_DIR})


