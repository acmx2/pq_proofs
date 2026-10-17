// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef BENCHMARK_TEST_HPP
#define BENCHMARK_TEST_HPP

#include "ots_common.hpp"
#include "signature_data.hpp"
#include "signer.hpp"
#include "ots_verifier.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>

namespace OtSignature::TestTrack {

// Test Scenario 5: High-Precision Performance Tracking & Logging Matrix.
// This suite generates keys and caches full data beforehand, measures keygen time, 
// and runs signing and verification routines in focused loops using cached metrics 
// to calculate and display mean operation times in a clean console table.
inline bool runPerformanceBenchmarkSuite() {
    std::cout << "\n[Test 5] Initializing High-Resolution Performance Benchmarks..." << std::endl;
    
    // Establish iteration counts (5 loop iterations over depth V=16 trees balances stability and memory).
    constexpr std::size_t iterations = 5; 
    constexpr std::size_t ringSize = (1ULL << OtSignature::V) - 1;

    // Allocate batch arrays to separate precomputation phases from hot tracking runs.
    std::vector<OtSignature::PrivateKeyFullData> cachedWitnessArray;
    std::vector<OtSignature::PublicRing> structuredRingsArray;
    std::vector<OtSignature::Signature> signaturePayloadsArray;
    
    OtSignature::Scalar512 benchmarkMessage{};
    benchmarkMessage.fill(0x9A); // Establish an arbitrary fixed context message block

    cachedWitnessArray.reserve(iterations);
    structuredRingsArray.reserve(iterations);
    signaturePayloadsArray.reserve(iterations);

    // -------------------------------------------------------------------------
    // PHASE 5.1: KEY GENERATION BENCHMARK LOOP
    // -------------------------------------------------------------------------
    // Generate public keys and full data arrays beforehand, measuring total execution drift.
    auto keygenStart = std::chrono::high_resolution_clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        OtSignature::PrivateKey sk{};
        sk.skp.fill(static_cast<OtSignature::Byte>(i + 1));
        sk.trs.fill(static_cast<OtSignature::Byte>(i + 2));
        sk.ggmri.fill(static_cast<OtSignature::Byte>(i + 3));

        // Generate keypair and cache full data witness properties
        auto keypair = OtSignature::Signer::generatePublicKey(sk, OtSignature::V);
        cachedWitnessArray.push_back(keypair.second);

        // Pre-build public rings matching the exact target built-in coordinates
        OtSignature::PublicRing ring(ringSize);
        std::size_t slot = keypair.second.getSigningIndex();
        ring[slot] = keypair.first;
        structuredRingsArray.push_back(ring);
    }
    auto keygenEnd = std::chrono::high_resolution_clock::now();
    double meanKeygenMs = std::chrono::duration<double, std::milli>(keygenEnd - keygenStart).count() / iterations;

    // -------------------------------------------------------------------------
    // PHASE 5.2: SIGNING LOOP BENCHMARK PASS (USING CACHED DATA)
    // -------------------------------------------------------------------------
    // Run the signing loop pass sequentially using the cached data arrays we prepared above.
    auto signStart = std::chrono::high_resolution_clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        signaturePayloadsArray.push_back(
            OtSignature::Signer::sign(cachedWitnessArray[i], structuredRingsArray[i], benchmarkMessage, OtSignature::V)
        );
    }
    auto signEnd = std::chrono::high_resolution_clock::now();
    double meanSignMs = std::chrono::duration<double, std::milli>(signEnd - signStart).count() / iterations;

    // -------------------------------------------------------------------------
    // PHASE 5.3: PUBLIC PIPELINE VERIFICATION BENCHMARK LOOP
    // -------------------------------------------------------------------------
    // Run the verification checks in a loop pass to calculate the system's processing limits.
    bool allValid = true;
    auto verifyStart = std::chrono::high_resolution_clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        allValid &= OtSignature::Verifier::verify(structuredRingsArray[i], benchmarkMessage, signaturePayloadsArray[i], OtSignature::V);
    }
    auto verifyEnd = std::chrono::high_resolution_clock::now();
    double meanVerifyMs = std::chrono::duration<double, std::milli>(verifyEnd - verifyStart).count() / iterations;

    // -------------------------------------------------------------------------
    // PHASE 5.4: DISPLAY CONSOLE PERFORMANCE MATRIX TABLE
    // -------------------------------------------------------------------------
    std::cout << "\n+" << std::string(35, '-') << "+" << std::string(22, '-') << "+";
    std::cout << "\n| Cryptographic Operation Track     | Mean Execution Time  |";
    std::cout << "\n+" << std::string(35, '-') << "+" << std::string(22, '-') << "+";
    std::cout << "\n| Public Key Generation (PK Gen)    | " << std::setw(14) << std::fixed << std::setprecision(3) << meanKeygenMs << " ms     |";
    std::cout << "\n| Ring Signing Pass (Sign)          | " << std::setw(14) << std::fixed << std::setprecision(3) << meanSignMs << " ms     |";
    std::cout << "\n| Pipeline Verification (Verify)    | " << std::setw(14) << std::fixed << std::setprecision(3) << meanVerifyMs << " ms     |";
    std::cout << "\n+" << std::string(35, '-') << "+" << std::string(22, '-') << "+" << std::endl;

    return allValid;
}

} // namespace OtSignature::TestTrack

#endif // BENCHMARK_TEST_HPP

