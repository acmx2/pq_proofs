#!/usr/bin/env bash
# MIT License - Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

set -e # Terminate script immediately if any compilation step encounters an error state

echo "==============================================================================="
echo "   Launching Automated Compilation and Validation for 'pq_proofs' Repository   "
echo "==============================================================================="

# -------------------------------------------------------------------------
# TRACK 1: BASELINE DENIABLE COMMITMENT SUITE
# -------------------------------------------------------------------------
echo -e "\n[Track 1/3] Processing Baseline 1-out-of-2 Deniable Commitment Codebase..."
cd deniable_commitment
mkdir -p build && cd build
rm -rf * # Clear cached build states to enforce a clean target compilation pass
cmake ..
cmake --build .
if [ -f ./test_single_commitment ]; then
    ./test_single_commitment
fi

# -------------------------------------------------------------------------
# TRACK 2: ADVANCED BATCH DENIABLE COMMITMENT SUITE
# -------------------------------------------------------------------------
echo -e "\n[Track 2/3] Processing Batch Deniable Commitment Suite..."
cd ../../batch_deniable_commitment
mkdir -p build && cd build
rm -rf * # Clear cached build states to enforce a clean target compilation pass
cmake ..
cmake --build .
./batch_test_suite

# -------------------------------------------------------------------------
# TRACK 3: POST-QUANTUM SOUND ONE-TIME RING SIGNATURE SUITE
# -------------------------------------------------------------------------
echo -e "\n[Track 3/3] Processing Post-Quantum One-Time Ring Signature Suite..."
cd ../../one_time_signature
mkdir -p build && cd build
rm -rf * # Clear cached build states to enforce a clean target compilation pass
cmake ..
cmake --build .
./ots_test_runner

# -------------------------------------------------------------------------
# AUTOMATED REPOSITORY COMPLIANCE CLOSURE
# -------------------------------------------------------------------------
echo -e "\n==============================================================================="
echo "   All 3 Cryptographic Modules Compiled Successfully; Tests Completed. "
echo "==============================================================================="

