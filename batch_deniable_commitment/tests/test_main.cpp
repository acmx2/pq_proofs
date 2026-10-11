/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "common_structures.hpp"
#include "common_procedures.hpp"
#include "super_array.hpp"
#include "prover.hpp"
#include "verifier.hpp"
#include "metrics_aggregator.hpp"
#include "challenge_builder.hpp"
#include "io_helper.hpp"
#include <iostream>
#include <random>
#include <chrono>
#include <vector>
#include <map>

using namespace BatchDeniableCommitment;
using namespace BatchDeniableCommitment::CryptoEngine;
using namespace BatchDeniableCommitment::Diagnostics;

namespace hr = std::chrono;

int main() {
    // Step 1: Print initialization flight banner configuration details.
    std::cout << "Initializing batch test flight sequence...\n";

    // Step 2: Initialize pseudorandom seeds and private authentic secret vectors.
    std::mt19937 workspaceRng(2026);
    BatchScalars authenticSecrets;
    Scalar secureGgmRootSeed;
    
    for (std::size_t b = 0; b < 32; ++b) { secureGgmRootSeed[b] = workspaceRng() % 256; }
    for (std::size_t i = 0; i < V; ++i) {
        for (std::size_t b = 0; b < 32; ++b) { authenticSecrets[i][b] = workspaceRng() % 256; }
    }

    // Step 3: Profile the core commitment phase generation timelines.
    auto startClock = hr::high_resolution_clock::now();
    auto commitmentResult = Prover::generateCommitment(authenticSecrets, secureGgmRootSeed);
    auto endClock = hr::high_resolution_clock::now();
    
    const double trackingCommitmentTime = hr::duration<double, std::micro>(endClock - startClock).count();
    const PublicCommitment publicRootCommitment = commitmentResult.first;
    PrivateCommitmentFullData privateWitnessCache = std::move(commitmentResult.second);

    // Step 4: Construct the dual verification ring spaces arbitrarily.
    BatchRings presentationRings;
    for (std::size_t i = 0; i < V; ++i) {
        Scalar arbitraryScalar;
        for (std::size_t b = 0; b < 32; ++b) { arbitraryScalar[b] = workspaceRng() % 256; }
        if (workspaceRng() % 2 == 0) {
            presentationRings[i] = std::make_pair(authenticSecrets[i], arbitraryScalar);
        } else {
            presentationRings[i] = std::make_pair(arbitraryScalar, authenticSecrets[i]);
        }
    }

    // Step 5: Profile the two-phase structural compaction proof generation phase.
    startClock = hr::high_resolution_clock::now();
    ProofPayload generatedProof = Prover::genProof(privateWitnessCache, presentationRings);
    endClock = hr::high_resolution_clock::now();
    const double provingOptimizationTime = hr::duration<double, std::micro>(endClock - startClock).count();

    // Step 6: Profile the verifier's path validation reconstruction loops.
    startClock = hr::high_resolution_clock::now();
    const bool verificationSuccess = Verifier::verifyProof(publicRootCommitment, presentationRings, generatedProof);
    endClock = hr::high_resolution_clock::now();
    const double validationReconstructionTime = hr::duration<double, std::micro>(endClock - startClock).count();

    // Step 7: Parse layout results to aggregate dashboard telemetry metrics.
    std::map<Rank, std::size_t> distributionMap;
    std::map<std::size_t, std::size_t> companionHashesPerLevelMap;
    std::map<std::size_t, std::size_t> ggmKeysPerLevelMap;

    std::vector<TrackBits> testB0(V), testB1(V);
    for (std::size_t i = 0; i < V; ++i) {
        testB0[i] = CryptoEngine::expandScalar(presentationRings[i].first);
        testB1[i] = CryptoEngine::expandScalar(presentationRings[i].second);
    }

    SuperArray b0Super = SuperArray::mixTracks(testB0);
    SuperArray b1Super = SuperArray::mixTracks(testB1);
    SuperArray xorSuper = b0Super.computeXor(b1Super);
    
    std::vector<Index> candidatePool = ChallengeBuilder::buildCandidatePool(xorSuper);
    std::vector<Index> actualOpenIndices = ChallengeBuilder::runSelectionEngine(candidatePool, xorSuper);
    
    std::vector<ChunkMarkup> topologicalRoadmap = IoHelper::generateTopologicalMarkup(actualOpenIndices, xorSuper);

    std::size_t openedLeavesCount = 0;
    std::size_t companionHashesAtLeafLevel = 0;
    std::size_t totalAccumulatedEntropyBits = 0; 
    std::vector<std::size_t> bitsPerTrackCounter(V, 0);

    for (std::size_t chunkIdx = 0; chunkIdx < topologicalRoadmap.size(); ++chunkIdx) {
        const auto& chunk = topologicalRoadmap[chunkIdx];

        if (chunk.isSelected) {
            distributionMap[chunk.rank]++;
            openedLeavesCount++;
            totalAccumulatedEntropyBits += chunk.rank; 

            std::size_t bitStartOffset = chunkIdx * C;
            for (std::size_t b = 0; b < chunk.rank; ++b) {
                std::size_t targetTrackIndex = xorSuper.getTrackIndexForBit(bitStartOffset + b);
                bitsPerTrackCounter[targetTrackIndex]++;
            }
        }
        
        if (!chunk.isSelected && chunk.isMerkleStubRevealed) {
            companionHashesPerLevelMap[chunk.merkleSubRootLocation.level]++;
            if (chunk.merkleSubRootLocation.level == D) { companionHashesAtLeafLevel++; }
        }
        if (chunk.isSelected && chunk.rank == C && chunk.isGgmSubRootRevealed) {
            ggmKeysPerLevelMap[chunk.ggmSubRootLocation.level]++;
        }
    }

    std::size_t fullyPopulatedLevelsCount = 0;
    for (std::size_t lvl = 0; lvl <= D; ++lvl) {
        if (companionHashesPerLevelMap.count(lvl) == 0 || companionHashesPerLevelMap[lvl] == 0) {
            fullyPopulatedLevelsCount++;
        }
    }

    std::size_t absoluteBytesWeight = (generatedProof.revealedGgmKeys.size() * 32) +
                                      (generatedProof.prunedMerkleHashes.size() * 32) +
                                      (generatedProof.floorHashStubs.size() * 32);
    
    double bytesSpentPerBit = totalAccumulatedEntropyBits > 0 ? 
                              static_cast<double>(absoluteBytesWeight) / static_cast<double>(totalAccumulatedEntropyBits) : 0.0;

    // Step 8: Build and render the definitive diagnostics dashboard report.
    TrackedMetrics flightReport;
    flightReport.commitmentGenerationTimeUs = trackingCommitmentTime;
    flightReport.provingTimeUs = provingOptimizationTime;
    flightReport.verificationTimeUs = validationReconstructionTime;
    flightReport.rankDistribution = distributionMap;
    flightReport.fullyPopulatedMerkleLevelsCount = fullyPopulatedLevelsCount;
    flightReport.openedLeavesAtLeafLevelCount = openedLeavesCount;
    flightReport.companionHashesAtLeafLevelCount = companionHashesAtLeafLevel;
    flightReport.merkleCompanionHashesPerLevel = companionHashesPerLevelMap;
    flightReport.ggmKeysPerLevel = ggmKeysPerLevelMap;
    flightReport.averageSpendBytesPerBit = bytesSpentPerBit;
    flightReport.openedBitsPerTrack = std::move(bitsPerTrackCounter);
    flightReport.proofSizeGgmBytes = generatedProof.revealedGgmKeys.size() * 32;
    flightReport.proofSizeMerkleBytes = generatedProof.prunedMerkleHashes.size() * 32;
    flightReport.proofSizeStubBytes = generatedProof.floorHashStubs.size() * 32;
    flightReport.passStatus = verificationSuccess;

    MetricsAggregator::printMetricsDashboard(flightReport);

    // Step 9: Validate exit state correctness.
    if (!verificationSuccess) {
        std::cerr << "Test process aborted: Verification loop rejected valid protocol proof.\n";
        return 1;
    }

    std::cout << "Test flight completed successfully.\n";
    return 0;
}

