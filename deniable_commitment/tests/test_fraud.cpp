/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "test_fraud.hpp"
#include "test_measurements.hpp"
#include "common_procedures.hpp"
#include "challenge_builder.hpp"
#include "prover.hpp"
#include "verifier.hpp"
#include "metrics_aggregator.hpp"
#include <random>
#include <iostream>

namespace DeniableCommitment {
namespace TestSubSuite {

namespace {
    // Purpose: Simulates adversarial forgery attempts to verify that the protocol forces full fraud rejection.
    // Arguments: realScalar - valid secret value; masksSeed - baseline leaf mask PRNG seed; bitFlips - targeted bit inversion count; doubleFakeAttack - proxy attack vector flag.
    Diagnostics::AdversarialMetrics simulateFraudAudit(const Scalar& realScalar, std::uint32_t masksSeed, std::size_t bitFlips, bool doubleFakeAttack = false) {
        Scalar fakeScalarA, fakeScalarB;
        
        // Step 1: Generate static adversarial inputs using a fixed seed to keep parameters fully reproducible.
        std::mt19937 adversaryRng(13579); 
        for (std::size_t i = 0; i < 32; ++i) {
            fakeScalarA[i] = adversaryRng() % 256;
            fakeScalarB[i] = adversaryRng() % 256;
        }

        // Step 2: Inject targeted modifications into presentation vectors to replicate forgery strategies.
        Scalar targetScalarA = realScalar;
        if (doubleFakeAttack) {
            targetScalarA = fakeScalarA; 
        } else {
            for (std::size_t i = 0; i < bitFlips && i < 32; ++i) { targetScalarA[i] ^= 0x01; }
        }
        Scalar targetScalarB = fakeScalarB;

        // Step 3: Create an honest public root reference commitment from the original valid key data.
        auto commitment = Prover::generateCommitment(realScalar, masksSeed);
        Bitstream streamFakeA = CryptoEngine::expandScalar(targetScalarA);
        UnpackedBitstream bitsFakeA = CryptoEngine::unpackBitstream(streamFakeA);

        // Step 4: Reconstruct verifier-side check indices independently from the fake presentation ring inputs.
        std::size_t poolLength = 0;
        ChallengeBuilder::deriveChallengeIndices(bitsFakeA, CryptoEngine::unpackBitstream(CryptoEngine::expandScalar(targetScalarB)), &poolLength);

        // Step 5: Prover builds proof sets from their honest private tree logs over faked challenge states.
        NaiveProof proofNaive = Prover::genProofNaive(commitment.second, targetScalarB);
        OctopusProof proofOctopus = Prover::genProofOctopus(commitment.second, targetScalarB);

        // Step 6: Count natural bit overlaps matching inside the local derived verification bounds.
        std::size_t rawBitMatches = 0;
        Bitstream streamFakeB = CryptoEngine::expandScalar(targetScalarB);
        UnpackedBitstream bitsFakeB = CryptoEngine::unpackBitstream(streamFakeB);
        ChallengeIndices selection = ChallengeBuilder::deriveChallengeIndices(bitsFakeA, bitsFakeB);
        for (std::size_t i = 0; i < ChallengeLength; ++i) {
            Index targetIdx = selection[i];
            if (commitment.second.privateBits[targetIdx] == bitsFakeA[targetIdx]) { rawBitMatches++; }
        }

        // Step 7: Symmetrically verify faked parameters using non-distinguishing Ring coordinate packages.
        Ring ring = std::make_pair(targetScalarA, targetScalarB);
        bool naiveVerified = Verifier::verifyProofNaive(commitment.first, ring, proofNaive);
        bool octVerified = Verifier::verifyProofOctopus(commitment.first, ring, proofOctopus);

        // Step 8: Collect and return adversarial metrics fields.
        Diagnostics::AdversarialMetrics advMetrics;
        advMetrics.bitFlipCount = doubleFakeAttack ? 0 : bitFlips;
        advMetrics.passedChecksNaive = rawBitMatches;
        advMetrics.naiveAccepted = naiveVerified;
        advMetrics.octopusAccepted = octVerified;

        // Step 9: Forward individual verification results onto the diagnostic dashboard engine.
        Diagnostics::MetricsAggregator::printAdversarialReport(advMetrics);
        return advMetrics;
    }
}

// Purpose: Subjects verification layers to bit-flip distortions and proxy assignment attack vectors.
// Arguments: generatedScalars - populated scalar presets; naiveMetrics/octopusMetrics - historical benchmark metrics; pipelinePassed - simple pipeline status tracker flag.
void runAdversarialFraudSuite(const std::vector<Scalar>& generatedScalars, const std::vector<Diagnostics::ExecutionMetrics>& naiveMetrics, const std::vector<Diagnostics::ExecutionMetrics>& octopusMetrics, bool pipelinePassed) {
    std::cout << "------------------------------------------------------------------------\n";
    std::cout << "   Multi-bit adversarial fraud audits run\n";
    std::cout << "------------------------------------------------------------------------\n\n";

    // Step 1: Map target masking seeds straight to P1 execution definitions context.
    std::uint32_t activeAuditMasksSeed = 202; 
    std::vector<Diagnostics::AdversarialMetrics> fraudRecords;

    // Step 2: Enforce defensive vector content boundaries checks to safeguard index lookup passes.
    if (generatedScalars.empty()) {
        std::cerr << "Simulation error: Scalar context repository is unpopulated.\n";
        std::exit(1);
    }

    // Step 3: Extract the concrete base entry element using explicit array indexing notation and execute incremental forgery iterations.
    fraudRecords.push_back(simulateFraudAudit(generatedScalars[0], activeAuditMasksSeed, 1));  
    fraudRecords.push_back(simulateFraudAudit(generatedScalars[0], activeAuditMasksSeed, 2));  
    fraudRecords.push_back(simulateFraudAudit(generatedScalars[0], activeAuditMasksSeed, 4));  
    fraudRecords.push_back(simulateFraudAudit(generatedScalars[0], activeAuditMasksSeed, 8));  
    fraudRecords.push_back(simulateFraudAudit(generatedScalars[0], activeAuditMasksSeed, 16));  
    fraudRecords.push_back(simulateFraudAudit(generatedScalars[0], activeAuditMasksSeed, 32));  
    fraudRecords.push_back(simulateFraudAudit(generatedScalars[0], activeAuditMasksSeed, 0, true));

    // Step 4: Consolidate tracking timelines directly down onto global validation dashboards output loops.
    Diagnostics::MetricsAggregator::printGlobalConsensusSummary(naiveMetrics, octopusMetrics, fraudRecords, pipelinePassed);
}

} // namespace TestSubSuite
} // namespace DeniableCommitment

