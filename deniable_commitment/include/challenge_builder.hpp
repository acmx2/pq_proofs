// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef CHALLENGE_BUILDER_HPP
#define CHALLENGE_BUILDER_HPP

#include "common_structures.hpp"
#include <vector>

namespace DeniableCommitment {

// Array of 128 deterministic check coordinate locations isolated from the coincidence pool
using ChallengeIndices = std::array<Index, ChallengeLength>;

class ChallengeBuilder {
public:
    // Section 2.3: Deterministically isolates 128 challenge indices from two expanded bitstreams
    static ChallengeIndices deriveChallengeIndices(const UnpackedBitstream& bitsA,
                                                   const UnpackedBitstream& bitsB,
                                                   std::size_t* candidatePoolLengthOut = nullptr);

private:
    // Section 2.2: Computes flat coincidence intersection pool from the noise profiles
    static std::vector<Index> buildCandidatePool(const UnpackedBitstream& bitsA,
                                                 const UnpackedBitstream& bitsB);
};

} // namespace DeniableCommitment

#endif // CHALLENGE_BUILDER_HPP

