/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "test_pipeline.hpp"
#include "prover.hpp"
#include "verifier.hpp"
#include "proof_data.hpp"
#include <iostream>
#include <stdexcept>

namespace DeniableCommitment {
namespace TestSubSuite {

// Purpose: Validates the core protocol lifecycle using only compact opening data tokens.
void runSimplePipelineTest() {
    std::cout << ">>> RUNNING SIMPLE PIPELINE TEST <<<\n";

    // Step 1: Initialize the committed private secret scalar with a uniform byte pattern.
    Scalar secretScalar;
    secretScalar.fill(0x42); 
    std::uint32_t secureSeed = 9999;
    
    // Step 2: Evaluate the public Merkle tree root hash and generate full pre-computation maps.
    auto commitmentPair = Prover::generateCommitment(secretScalar, secureSeed);
    PublicCommitment publicRoot = commitmentPair.first;

    // Step 3: Extract the low-weight OpeningData slice and drop the heavy internal caches entirely.
    PrivateCommitmentOpeningData openingWitness = commitmentPair.second;

    // Step 4: Instantiates an independent arbitrary random scalar to drive the challenge layer.
    Scalar arbitraryRandomScalar;
    arbitraryRandomScalar.fill(0x77);
    
    // Step 5: Bundle the secret scalar and the arbitrary material symmetrically into a verification Ring.
    Ring ring = std::make_pair(secretScalar, arbitraryRandomScalar);

    // Step 6: Generate both unoptimized and optimized Merkle proofs on-the-fly from the lightweight opening witness.
    OctopusProof octopusProof = Prover::genProofOctopus(openingWitness, arbitraryRandomScalar);
    NaiveProof naiveProof = Prover::genProofNaive(openingWitness, arbitraryRandomScalar);

    // Step 7: Verifier evaluates both proof structures independently using only public parameters.
    bool octVerified = Verifier::verifyProofOctopus(publicRoot, ring, octopusProof);
    bool naiveVerified = Verifier::verifyProofNaive(publicRoot, ring, naiveProof);

    // Step 8: Throw runtime exceptions if the verifier rejects.
    if (!octVerified) {
        throw std::runtime_error("Pipeline verification failure: Octopus proof structure rejected.");
    }
    if (!naiveVerified) {
        throw std::runtime_error("Pipeline verification failure: Naive proof structure rejected.");
    }

    std::cout << "  [SUCCESS] Symmetrical simple opening witness pipeline verified flawlessly.\n\n";
}

} // namespace TestSubSuite
} // namespace DeniableCommitment

