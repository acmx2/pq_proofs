// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef RANDOM_TEST_HPP
#define RANDOM_TEST_HPP

#include "ots_common.hpp"
#include "signature_data.hpp"
#include "signer.hpp"
#include "ots_verifier.hpp"
#include <iostream>
#include <vector>
#include <random>

namespace OtSignature::TestTrack {

// Test Scenario 3: Real Hardware Non-Deterministic Randomness Pass.
// This tracking loop tests the signature engine against fully unpredictable credentials.
// It seeds private parameters using true system entropy streams via std::random_device.
inline bool runHardwareEntropyScenario() {
    std::cout << "\n[Test 3] Sampling non-deterministic hardware entropy blocks..." << std::endl;
    constexpr std::size_t ringSize = (1ULL << OtSignature::V) - 1;

    // Initialize the hardware entropy source to seed our random numbers generator.
    std::random_device rd;
    OtSignature::PrivateKey hardwarePrivateKey{};
    
    // Fill the private key fields byte-by-byte using raw non-deterministic hardware entropy.
    for (auto& byte : hardwarePrivateKey.skp)   byte = static_cast<OtSignature::Byte>(rd() & 0xFF);
    for (auto& byte : hardwarePrivateKey.trs)   byte = static_cast<OtSignature::Byte>(rd() & 0xFF);
    for (auto& byte : hardwarePrivateKey.ggmri) byte = static_cast<OtSignature::Byte>(rd() & 0xFF);

    // Generate the public/private keypair mapping on-the-fly using the randomized private seeds.
    auto keypair = OtSignature::Signer::generatePublicKey(hardwarePrivateKey, OtSignature::V);
    OtSignature::PrivateKeyFullData cachedInternals = keypair.second;

    // Instantiate the public verification ring vector array.
    OtSignature::PublicRing randomRing(ringSize);
    
    // Read the precise signer slot index coordinate k embedded within the cache parameters.
    std::size_t targetSlot = cachedInternals.getSigningIndex();
    
    // Assemble the ring vector by hiding our real public key at its designated index slot,
    // while filling all remaining lanes with completely randomized mock public key values.
    for (std::size_t k = 0; k < ringSize; ++k) {
        if (k == targetSlot) {
            randomRing[k] = keypair.first;
        } else {
            for (auto& byte : randomRing[k].pk) {
                byte = static_cast<OtSignature::Byte>(rd() & 0xFF);
            }
        }
    }

    // Generate a completely randomized 512-bit message context payload.
    OtSignature::Scalar512 dynamicMessage{};
    for (auto& byte : dynamicMessage) byte = static_cast<OtSignature::Byte>(rd() & 0xFF);

    // Execute the signing loop pass to compile the post-quantum ring signature payload.
    auto sig = OtSignature::Signer::sign(cachedInternals, randomRing, dynamicMessage, OtSignature::V);
    
    // Forward the compiled token straight into the public verifier and return the truth evaluation.
    return OtSignature::Verifier::verify(randomRing, dynamicMessage, sig, OtSignature::V);
}

} // namespace OtSignature::TestTrack

#endif // RANDOM_TEST_HPP

