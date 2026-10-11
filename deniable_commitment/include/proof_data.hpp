// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef PROOF_DATA_HPP
#define PROOF_DATA_HPP

#include "common_structures.hpp"
#include "merkle_tree.hpp"
#include <vector>

namespace DeniableCommitment {

// The public protocol commitment, represented by the Merkle root hash.
using PublicCommitment = Hash;

// Unoptimized baseline payload path size constraint: 128 check indices * 10 tree levels = 1280 sibling hashes
constexpr std::size_t NaiveCompanionHashesCount = ChallengeLength * LeafExponent;

// Auxiliary data structures for proof layouts
using NaivePathHashes  = std::array<Hash, NaiveCompanionHashesCount>; // Continuous array block holding 1,280 companion hashes
using SiblingPath      = std::vector<Hash>; // Variable-size sequence tracing dynamic pruned unique sibling sub-branches

// Immutable core parameter package required to re-evaluate the commitment state.
// Contains only the low-weight raw materials, acting as a lightweight opening witness payload.
struct PrivateCommitmentOpeningData {
    Scalar secretScalar;       // The original 256-bit secret input variable committed during Phase 1 (S_committed).
    std::uint32_t secureSeed;  // The numeric entropy seed driving the pseudorandom generation of leaf masking salts.
};

// Heavy, pre-computed cache snapshot containing the fully expanded state of a commitment.
// Inherits basic opening witness parameters and appends volatile intermediate pre-computation blocks.
struct PrivateCommitmentFullData : public PrivateCommitmentOpeningData {
    UnpackedBitstream privateBits;                    // Expanded pseudorandom bitstream array generated via Engine E(S).
    std::array<Scalar, BitstreamLength> privateMasks; // The full sequence of 1,024 secret random 256-bit masking salts (M_i).
    MerkleTree privateTree;                           // The complete calculated binary authentication tree topology.
};

// SECURITY SPECIFICATION: The challenge index set is derived locally by both parties. 
// This deterministic selection prevents provers from executing ad-hoc manipulation attacks.

// The sequence of 128 secret masking salts opened in the proofs.
using OpenMasksBlock   = std::array<Scalar, ChallengeLength>; 

// Network payload frame used in the unoptimized independent path tracing approach.
// Transmits complete proof branches redundantly, resulting in an invariant, predictable wire footprint.
struct NaiveProof {
    OpenBitsBlock packedBits;          // 128 opened bit values packed into a uniform 16-byte buffer footprint.
    OpenMasksBlock masks;              // The 128 individual 256-bit masking salts revealing the target checked leaves.
    NaivePathHashes companionHashes;   // The 1,280 independent, unpruned path sibling hashes needed to fold up to the root.
};

// Optimized network wire payload implementing the Octopus multi-proof tree-pruning engine.
// Homogenizes and eliminates redundant sibling hashes layer-by-layer, minimizing data footprint for overlapping branches.
struct OctopusProof {
    OpenBitsBlock packedBits;          // 128 opened bit values packed into a uniform 16-byte buffer footprint.
    OpenMasksBlock masks;              // The 128 individual 256-bit masking salts revealing the target checked leaves.
    SiblingPath prunedHashes;          // Dynamically sized vector containing only unique, uncomputed layer sibling hashes.
};

} // namespace DeniableCommitment

#endif // PROOF_DATA_HPP

