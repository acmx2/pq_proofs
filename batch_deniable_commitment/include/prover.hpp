// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef PROVER_HPP
#define PROVER_HPP

#include "common_structures.hpp"
#include "super_array.hpp"
#include "proof_data.hpp"
#include "merkle_tree.hpp"
#include <utility>
#include <vector>

namespace BatchDeniableCommitment {

// Private commitment cache data structural frame holding secret parameters on the Prover side.
struct PrivateCommitmentFullData {
    BatchScalars secretScalars;        // Original private scalar bit streams inputs.
    Scalar ggmRootKey;                 // Master GGM private seed key.
    std::vector<Scalar> derivedMasks;  // Full calculated dynamic sequence of 2^D leaf masking salts.
    SuperArray superArrayB;            // Mixed, un-padded global super-array matrix B.
    MerkleTree commitmentTree;         // Fully generated reference Merkle tree structure.
};

class Prover {
public:
    // Core initialization method mapping parallel tracks and outputting the public root commitment signature.
    // Argument 'secretScalars' passes the private lane input vectors context.
    // Argument 'ggmRootKey' provides the master key seed to anchor private masking loops.
    // Returns a symmetrical pair linking the public root digest to the private cache witness data block.
    static std::pair<PublicCommitment, PrivateCommitmentFullData> generateCommitment(
        const BatchScalars& secretScalars, 
        const Scalar& ggmRootKey
    );

    // Proof generation procedure loop compiling loose payload streams down to the wire.
    // Argument 'fullData' takes the private reference commitment cache data structure block.
    // Argument 'presentationRings' passes the coordinate public scalar pairs requested for verification.
    // Returns a complete sparse ProofPayload frame.
    static ProofPayload genProof(
        const PrivateCommitmentFullData& fullData, 
        const BatchRings& presentationRings
    );

private:
    // Expands a master key seed top-down into 2^D localized leaf masking salts.
    static void deriveGgmMasks(const Scalar& rootKey, std::vector<Scalar>& masksOut);
    
    // Evaluates dynamic prefix leaf cascades to output Floor 5 hashes.
    static Hash evaluateCascadeLeaf(const SuperArray& superArray, std::size_t chunkIdx, const Scalar& mask);
};

} // namespace BatchDeniableCommitment

#endif // PROVER_HPP

