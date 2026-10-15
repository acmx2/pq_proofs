# MIT License
# Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

cmake_minimum_required(VERSION 3.20)
project(OneTimeSignature CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ----------------=========================================================
# CROSS-DIRECTORY DEPENDENCY RESOLUTION
# ----------------------------------------------------------------=========
# Cross-directory property propagation consuming the autonomous 'batch_deniable_commitment' library
if(NOT TARGET batchdeniablecommitment)
    add_subdirectory(
        ${CMAKE_CURRENT_SOURCE_DIR}/../batch_deniable_commitment 
        ${CMAKE_CURRENT_BINARY_DIR}/bdc_build
    )
endif()

# -------------------------------------------------------------------------
# OTS TARGET DEFINITION
# -------------------------------------------------------------------------
add_executable(ots_test_runner
    src/pfmt.cpp
    src/ots_procedures.cpp
    tests/main_test.cpp
)

target_include_directories(ots_test_runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Links 'libbatchdeniablecommitment.a' and inherits public headers seamlessly
target_link_libraries(ots_test_runner PRIVATE batchdeniablecommitment)

