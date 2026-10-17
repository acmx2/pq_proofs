# MIT License
# Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

cmake_minimum_required(VERSION 3.20)
project(OneTimeSignature CXX)

# Enforce standard C++20 compliance for modern array layout property support
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ----------------=========================================================
# CROSS-DIRECTORY DEPENDENCY RESOLUTION
# ----------------------------------------------------------------=========
# Check if the Batch Deniable Commitment Suite (BDCS) target is already initialized.
# If missing, locate the relative subdirectory path and build it out-of-source seamlessly.
if(NOT TARGET batchdeniablecommitment)
    add_subdirectory(
        ${CMAKE_CURRENT_SOURCE_DIR}/../batch_deniable_commitment 
        ${CMAKE_CURRENT_BINARY_DIR}/bdc_build
    )
endif()

# -------------------------------------------------------------------------
# OTS MASTER TARGET DEFINITION
# -------------------------------------------------------------------------
# Consolidated all test tracks, randomized tracks, and benchmarking suites 
# down into a single master executable binary runner target to prevent linking conflicts.
add_executable(ots_test_runner
    src/pfmt.cpp
    src/ots_procedures.cpp
    src/signature_data.cpp
    src/signer.cpp
    src/ots_verifier.cpp
    tests/main_test.cpp
)

# Bind internal project headers and the tests folder namespace context
target_include_directories(ots_test_runner PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
)

# Link against the compiled archive of our neighboring BDCS library ('libbatchdeniablecommitment.a')
target_link_libraries(ots_test_runner PRIVATE batchdeniablecommitment)

