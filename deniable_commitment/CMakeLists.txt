# MIT License
# Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

cmake_minimum_required(VERSION 3.12)
project(DeniableCommitmentScheme LANGUAGES CXX)

# Force strict standard enforcement criteria
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Inject rigorous diagnostic warning flags and optimization rules
if(MSVC)
    add_compile_options(/W4 /WX /O2 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Werror -O3)
endif()

# Map include directory boundaries cleanly
include_directories(include tests)

# Core Cryptographic Protocol Library Source Components
set(PROTO_SOURCES
    src/merkle_tree.cpp
    src/challenge_builder.cpp
    src/common_procedures.cpp
    src/prover.cpp
    src/verifier.cpp
)

# Decoupled Diagnostic Testing Sub-Suite Source Components
set(TEST_SOURCES
    tests/metrics_aggregator.cpp
    tests/test_pipeline.cpp
    tests/test_measurements.cpp
    tests/test_fraud.cpp
    tests/test_main.cpp
)

# Instantiate the final target executable environment loop linked cleanly
add_executable(test_single_commitment ${PROTO_SOURCES} ${TEST_SOURCES})

