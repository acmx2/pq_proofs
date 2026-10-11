// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef VERIFIER_HPP
#define VERIFIER_HPP

#include "common_structures.hpp"
#include "proof_data.hpp"
#include "challenge_builder.hpp"
#include <utility>

namespace DeniableCommitment {

class Verifier {
public:
    // Symmetric high-level verification entries
    static bool verifyProofNaive(const PublicCommitment& root,
                                 const Ring& ring,
                                 const NaiveProof& proof);

    static bool verifyProofOctopus(const PublicCommitment& root,
                                   const Ring& ring,
                                   const OctopusProof& proof);

private:
    // Independent path tracking loops
    static bool executeVerifyProofNaive(const Hash& root, 
                                        const ChallengeIndices& derivedIndices,
                                        const UnpackedBitstream& expectedBits, 
                                        const NaiveProof& proof);
    
    static bool executeVerifyProofOctopus(const Hash& root, 
                                          const ChallengeIndices& derivedIndices,
                                          const UnpackedBitstream& expectedBits, 
                                          const OctopusProof& proof);
};

} // namespace DeniableCommitment

#endif // VERIFIER_HPP

