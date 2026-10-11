// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef PROVER_HPP
#define PROVER_HPP

#include "common_structures.hpp"
#include "merkle_tree.hpp"
#include "proof_data.hpp"
#include "challenge_builder.hpp"
#include <utility>

namespace DeniableCommitment {

class Prover {
public:
    // Commitment lifecycle routines
    static std::pair<PublicCommitment, PrivateCommitmentFullData> generateCommitment(const Scalar& secretScalar, std::uint32_t secureSeed);
    static PrivateCommitmentFullData restoreFullData(const PrivateCommitmentOpeningData& openingData);

    // High-level proof generation interfaces
    static NaiveProof genProofNaive(const PrivateCommitmentFullData& fullData, const Scalar& arbitraryScalar);
    static OctopusProof genProofOctopus(const PrivateCommitmentFullData& fullData, const Scalar& arbitraryScalar);
    static NaiveProof genProofNaive(const PrivateCommitmentOpeningData& openingData, const Scalar& arbitraryScalar);
    static OctopusProof genProofOctopus(const PrivateCommitmentOpeningData& openingData, const Scalar& arbitraryScalar);

private:
    // Low-level proof serialization loops
    static NaiveProof executeGenProofNaive(const MerkleTree& tree, 
                                           const UnpackedBitstream& bits,
                                           const std::array<Scalar, BitstreamLength>& masks,
                                           const ChallengeIndices& challengeIndices);

    static OctopusProof executeGenProofOctopus(const MerkleTree& tree, 
                                               const UnpackedBitstream& bits,
                                               const std::array<Scalar, BitstreamLength>& masks,
                                               const ChallengeIndices& challengeIndices);
};

} // namespace DeniableCommitment

#endif // PROVER_HPP

