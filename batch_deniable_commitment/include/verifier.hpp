// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef VERIFIER_HPP
#define VERIFIER_HPP

#include "common_structures.hpp"
#include "super_array.hpp"
#include "proof_data.hpp"
#include <vector>

namespace BatchDeniableCommitment {

class Verifier {
public:
    // Non-distinguishing blind proof validation path verification routine.
    // Argument 'root' provides the public commitment tree root signature to evaluate against.
    // Argument 'presentationRings' passes the submitted ring track scalar coordinates.
    // Argument 'proof' passes the sparse payload vectors packet received from the wire.
    // Returns true if the computed root intersects the public commitment perfectly; false otherwise.
    static bool verifyProof(
        const PublicCommitment& root, 
        const BatchRings& presentationRings, 
        const ProofPayload& proof
    );

private:
    // Recomputes contextual cascade leaf hash tokens using payload elements or stubs.
    static Hash reconstructCascadeLeaf(
        const SuperArray& superArray, 
        const Index chunkIdx, 
        const Hash& contextBlock, 
        const Rank rank
    );
};

} // namespace BatchDeniableCommitment

#endif // VERIFIER_HPP

