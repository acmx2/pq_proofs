/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "challenge_builder.hpp"
#include <iostream>

namespace DeniableCommitment {

// Purpose: Identifies matching index alignment cells across two unpacked bit vectors.
// Arguments: bitsA/bitsB - twin input processing buffers to intercept.
std::vector<Index> ChallengeBuilder::buildCandidatePool(const UnpackedBitstream& bitsA,
                                                       const UnpackedBitstream& bitsB) {
    std::vector<Index> pool;
    
    // Step 1: Scan all 1,024 alignment coordinates to record intersection points where the bits match.
    for (Index i = 0; i < BitstreamLength; ++i) {
        if (bitsA[i] == bitsB[i]) {
            pool.push_back(i);
        }
    }
    
    // Step 2: Return the computed coincidence pool array vector.
    return pool;
}

// Purpose: Resolves the 128 deterministic check coordinates sequence out of matching profiles.
// Arguments: bitsA/bitsB - expanded stream profiles; candidatePoolLengthOut - optional diagnostics trace capture pointer.
ChallengeIndices ChallengeBuilder::deriveChallengeIndices(const UnpackedBitstream& bitsA,
                                                           const UnpackedBitstream& bitsB,
                                                           std::size_t* candidatePoolLengthOut) {
    // Step 1: Compute the continuous intersection pool of matching bit coordinates.
    std::vector<Index> pool = buildCandidatePool(bitsA, bitsB);
    if (candidatePoolLengthOut != nullptr) {
        *candidatePoolLengthOut = pool.size();
    }

    // Step 2: Enforce the minimum capacity bounds constraint required by the protocol.
    if (pool.size() < ChallengeLength) {
        std::cerr << "CRITICAL ERROR: Coincidence pool size underflows challenge bound constraints.\n";
        std::exit(1);
    }

    // Step 3: Sequentially isolate the first 128 matching indices to serve as coordinates.
    ChallengeIndices selection;
    for (std::size_t i = 0; i < ChallengeLength; ++i) {
        selection[i] = pool[i];
    }
    
    // Step 4: Return the deterministic selection array to the caller environment.
    return selection;
}

} // namespace DeniableCommitment

