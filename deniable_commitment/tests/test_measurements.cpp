/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "test_measurements.hpp"
#include "common_procedures.hpp"
#include "prover.hpp"
#include "verifier.hpp"
#include <chrono>
#include <random>
#include <iostream>

namespace DeniableCommitment {
namespace TestSubSuite {

namespace {
    namespace hr = std::chrono;
    
    // Purpose: Evaluates the bitwise cross-correlation density between two expanded streams.
    // Arguments: bitsA/bitsB - Twin bitstreams to evaluate for matching indices.
    void printIntersectionDensityReport(const UnpackedBitstream& bitsA, const UnpackedBitstream& bitsB) {
        std::size_t naturalCollisions = 0;
        
        // Step 1: Scan all 1,024 positions to count matching bit fields.
        for (std::size_t i = 0; i < BitstreamLength; ++i) {
            if (bitsA[i] == bitsB[i]) { naturalCollisions++; }
        }
        
        // Step 2: Calculate the natural matching percentage and output results to the console.
        double percent = (static_cast<double>(naturalCollisions) / BitstreamLength) * 100.0;
        std::cout << "  [NATURAL INTERSECTION DENSITY] Overlapping bits across full 1024 stream: " 
                  << naturalCollisions << " / " << BitstreamLength << " (" << percent << "%)\n";
    }

    // Purpose: Executes a single benchmark cycle to measure timing profile statistics and proof footprints.
    // Arguments: seeds - input entropy seeds; naiveOut/octopusOut - metrics destinations; scalarCommittedOut - output container for the secret scalar.
    void executeBenchmarkRound(const SeedConfiguration& seeds, Diagnostics::ExecutionMetrics& naiveOut, Diagnostics::ExecutionMetrics& octopusOut, Scalar& scalarCommittedOut) {
        // Step 1: Initialize the committed secret scalar array using the specified seed.
        std::cout << ">>> RUNNING MATRIX PROFILE: " << seeds.environmentProfile << " <<<\n";
        std::mt19937 rngCommitted(seeds.committedScalarSeed);
        for (std::size_t i = 0; i < 32; ++i) { scalarCommittedOut[i] = rngCommitted() % 256; }

        // Step 2: Initialize the independent arbitrary random scalar array using its respective seed.
        std::mt19937 rngArbitrary(seeds.arbitraryScalarSeed);
        Scalar scalarArbitrary;
        for (std::size_t i = 0; i < 32; ++i) { scalarArbitrary[i] = rngArbitrary() % 256; }

        // Step 3: Compute expanded bitstreams, masking salts, and evaluate the public Merkle root commitment.
        auto commitment = Prover::generateCommitment(scalarCommittedOut, seeds.proverMasksSeed);
        PublicCommitment publicRoot = commitment.first;
        PrivateCommitmentFullData originalFullData = commitment.second;

        // Step 4: Expand the scalars into their 1,024-bit representations.
        Bitstream streamA = CryptoEngine::expandScalar(scalarCommittedOut);
        Bitstream streamB = CryptoEngine::expandScalar(scalarArbitrary);
        UnpackedBitstream bitsA = CryptoEngine::unpackBitstream(streamA);
        UnpackedBitstream bitsB = CryptoEngine::unpackBitstream(streamB);

        // Step 5: Isolate the coincidence candidate pool size and log the natural intersection uniformity.
        std::size_t poolLength = 0;
        ChallengeBuilder::deriveChallengeIndices(bitsA, bitsB, &poolLength);
        printIntersectionDensityReport(bitsA, bitsB);

        // Step 6: Construct and measure execution runtime for the independent path proof generator.
        auto start = hr::high_resolution_clock::now();
        NaiveProof proofNaive = Prover::genProofNaive(originalFullData, scalarArbitrary);
        auto end = hr::high_resolution_clock::now();
        double tGenNaive = hr::duration<double, std::micro>(end - start).count();

        // Step 7: Initialize the symmetric verification ring container.
        Ring honestRing = std::make_pair(scalarCommittedOut, scalarArbitrary);

        // Step 8: Measure execution runtime for independent path verification.
        start = hr::high_resolution_clock::now();
        bool verifyNaive = Verifier::verifyProofNaive(publicRoot, honestRing, proofNaive);
        end = hr::high_resolution_clock::now();
        double tVerNaive = hr::duration<double, std::micro>(end - start).count();

        // Step 9: Populate the naive evaluation metrics record structure.
        naiveOut.candidatePoolLength = poolLength;
        naiveOut.selectionLength = ChallengeLength;
        naiveOut.commitmentGenTimeUs = 0.0;
        naiveOut.proofGenTimeUs = tGenNaive;
        naiveOut.verificationTimeUs = tVerNaive;
        naiveOut.proofSizeBytes = proofNaive.packedBits.size() + sizeof(proofNaive.masks) + (proofNaive.companionHashes.size() * 32);
        naiveOut.isAccepted = verifyNaive;

        // Step 10: Construct and measure execution runtime for the optimized tree-pruned multi-proof generator.
        start = hr::high_resolution_clock::now();
        OctopusProof proofOctopus = Prover::genProofOctopus(originalFullData, scalarArbitrary);
        end = hr::high_resolution_clock::now();
        double tGenOct = hr::duration<double, std::micro>(end - start).count();

        // Step 11: Measure execution runtime for tree-pruned multi-proof verification.
        start = hr::high_resolution_clock::now();
        bool verifyOct = Verifier::verifyProofOctopus(publicRoot, honestRing, proofOctopus);
        end = hr::high_resolution_clock::now();
        double tVerOct = hr::duration<double, std::micro>(end - start).count();

        // Step 12: Populate the octopus evaluation metrics record structure.
        octopusOut.candidatePoolLength = poolLength;
        octopusOut.selectionLength = ChallengeLength;
        octopusOut.commitmentGenTimeUs = 0.0;
        octopusOut.proofGenTimeUs = tGenOct;
        octopusOut.verificationTimeUs = tVerOct;
        octopusOut.proofSizeBytes = proofOctopus.packedBits.size() + sizeof(proofOctopus.masks) + (proofOctopus.prunedHashes.size() * 32);
        octopusOut.isAccepted = verifyOct;

        Diagnostics::MetricsAggregator::printSeedReport(seeds.proverMasksSeed, naiveOut, octopusOut);
    }
}

// Purpose: Loops through all 32 hardcoded configurations to capture sequential benchmark metrics.
// Arguments: naiveOut/octopusOut - metric destination vectors; generatedScalarsOut - history tracker for generated scalars.
void runMeasurementsBenchmark(std::vector<Diagnostics::ExecutionMetrics>& naiveOut, std::vector<Diagnostics::ExecutionMetrics>& octopusOut, std::vector<Scalar>& generatedScalarsOut) {
    // Step 1: Declare the 32 hardcoded operational seed presets.
    std::vector<SeedConfiguration> testRuns = {
        {101, 202, 303, "P1"}, {555, 555, 999, "P2"}, {777, 888, 777, "P3"}, {888, 666, 666, "P4"},
        {123, 123, 123, "P5"}, {0,   0,   0,   "P6"}, {4294967295U, 4294967295U, 4294967295U, "P7"},
        {999, 111, 222, "P8"}, {1101, 2102, 3103, "P9"}, {1104, 2104, 3104, "P10"},
        {1105, 2105, 3105, "P11"}, {1106, 2106, 3106, "P12"}, {1107, 2107, 3107, "P13"},
        {1108, 2108, 3108, "P14"}, {1109, 2109, 3109, "P15"}, {1110, 2110, 3110, "P16"},
        {1411, 1511, 1611, "P17"}, {1412, 1512, 1612, "P18"}, {1413, 1513, 1613, "P19"},
        {1414, 1514, 1614, "P20"}, {1811, 1822, 1833, "P21"}, {1814, 1825, 1836, "P22"},
        {1901, 1902, 1903, "P23"}, {1904, 1905, 1906, "P24"}, {1701, 1702, 1703, "P25"},
        {1704, 1705, 1706, "P26"}, {1131, 1141, 1151, "P27"}, {1132, 1142, 1152, "P28"},
        {1161, 1171, 1181, "P29"}, {1162, 1172, 1182, "P30"}, {3100, 3200, 3300, "P31"},
        {3400, 3500, 3600, "P32"}
    };

    // Step 2: Reset vectors to force precise dynamic tracking allocations.
    naiveOut.clear();
    octopusOut.clear();
    generatedScalarsOut.clear();

    // Step 3: Optimize vector allocation layouts using expected context bounds.
    naiveOut.reserve(testRuns.size());
    octopusOut.reserve(testRuns.size());
    generatedScalarsOut.reserve(testRuns.size());

    // Step 4: Iteratively run individual tests, tracking results dynamically.
    for (std::size_t i = 0; i < testRuns.size(); ++i) {
        Diagnostics::ExecutionMetrics outNaive;
        Diagnostics::ExecutionMetrics outOctopus;
        Scalar activeScalar;

        executeBenchmarkRound(testRuns[i], outNaive, outOctopus, activeScalar);

        naiveOut.push_back(outNaive);
        octopusOut.push_back(outOctopus);
        generatedScalarsOut.push_back(activeScalar);
    }
}

} // namespace TestSubSuite
} // namespace DeniableCommitment

