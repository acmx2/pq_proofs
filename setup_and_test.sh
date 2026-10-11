#!/usr/bin/env bash
# MIT License - Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

set -e # Terminate script immediately if any compilation step encounters an error state

echo "==============================================================================="
echo "   Launching Automated Compilation and Validation for 'pq_proofs' Repository   "
echo "==============================================================================="

# Track 1: Baseline Deniable Commitment Compilation
echo -e "\n[Track 1/2] Processing Baseline 1-out-of-2 Deniable Commitment Codebase..."
cd deniable_commitment
mkdir -p build && cd build
cmake ..
cmake --build .
if [ -f ./test_single_commitment ]; then
    ./test_single_commitment
fi

# Track 2: Advanced Batch Engine Suite Compilation
echo -e "\n[Track 2/2] Processing Advanced Batch Quintet Commitment Suite..."
cd ../../batch_deniable_commitment
mkdir -p build && cd build
cmake ..
cmake --build .
./batch_test_suite

echo -e "\n==============================================================================="
echo "   Both cryptographic engines compiled; tests completed. "
echo "==============================================================================="

