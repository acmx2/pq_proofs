// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef PROOF_DATA_HPP
#define PROOF_DATA_HPP

#include "common_structures.hpp"
#include <vector>

namespace BatchDeniableCommitment {

// Sparse network transmission packet framing structure containing loose multi-proof payload arrays.
struct ProofPayload {
    std::vector<Scalar> revealedGgmKeys;    // Compressed top-down sub-root GGM key token fragments list.
    std::vector<Hash> prunedMerkleHashes;  // Pruned bottom-up sibling path companion tree stubs list.
    std::vector<Hash> floorHashStubs;      // Intermediate cascade partial-match floor penalty stubs list.
};

using ProofPayloadFrame = ProofPayload;

} // namespace BatchDeniableCommitment

#endif // PROOF_DATA_HPP

