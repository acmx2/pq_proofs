// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "ots_common.hpp"
#include "signature_data.hpp"
#include "signer.hpp"
#include "ots_verifier.hpp"
#include <iostream>
#include <vector>
#include <cassert>

int main() {
    std::cout << "=== Running OTS Complete Specification Sign/Verify Suite ===" << std::endl;

    constexpr std::size_t ringSize = (1ULL << OtSignature::V) - 1;

    std::cout << "[1/5] Configuring cryptographic private credentials..." << std::endl;
    OtSignature::PrivateKey privateKey{};
    privateKey.skp.fill(0x1A);  
    privateKey.trs.fill(0x2B);  
    privateKey.ggmri.fill(0x3C); 

    std::cout << "[2/5] Compiling unlinked Public Key via Phase-Split strategy..." << std::endl;
    auto keypair = OtSignature::Signer::generatePublicKey(privateKey, OtSignature::V);
    OtSignature::PublicKey myPublicKey = keypair.first;
    OtSignature::PrivateKeyFullData myCachedInternals = keypair.second;

    std::cout << "[3/5] Decoding imprinted bitpath tracking matrix indices..." << std::endl;
    // SPECIFICATION ALIGNMENT: Dynamically reconstruct the precise index coordinate k 
    // imprinted within the public key footprint via the TBP routing trajectory
    std::size_t targetSignerIndexSlot = 0;
    for (std::size_t b = 0; b < myCachedInternals.bitpathTBP.size(); ++b) {
        targetSignerIndexSlot |= (static_cast<std::size_t>(myCachedInternals.bitpathTBP[b]) << b);
    }
    std::cout << ">> Target signer placement mapped to imprinted index: " << targetSignerIndexSlot << std::endl;

    std::cout << "[4/5] Assembling ad-hoc public key verification ring vector (size: " << ringSize << ")..." << std::endl;
    OtSignature::PublicRing adHocVerificationRing(ringSize);
    
    for (std::size_t k = 0; k < ringSize; ++k) {
        if (k == targetSignerIndexSlot) {
            adHocVerificationRing[k] = myPublicKey;
        } else {
            adHocVerificationRing[k].pk.fill(static_cast<OtSignature::Byte>(k & 0xFF));
        }
    }

    std::cout << "[5/5] Executing Signer::sign loop over arbitrary transaction message..." << std::endl;
    OtSignature::Scalar512 transactionMessageContext{};
    transactionMessageContext.fill(0x7E); 

    OtSignature::Signature computedWireSignature = OtSignature::Signer::sign(
        myCachedInternals, 
        adHocVerificationRing, 
        transactionMessageContext, 
        OtSignature::V
    );

    std::cout << "[6/5] Passing payload straight into Verifier pipeline engine..." << std::endl;
    bool isSignatureValid = OtSignature::Verifier::verify(
        adHocVerificationRing, 
        transactionMessageContext, 
        computedWireSignature, 
        OtSignature::V
    );

    if (isSignatureValid) {
        std::cout << "\n>>> [SUCCESS]: Post-Quantum Ring Signature Verification Passed Flawlessly!" << std::endl;
    } else {
        std::cout << "\n>>> [FAILURE]: Signature Validation Pipeline Rejected Transmission Packet." << std::endl;
        return 1;
    }

    std::cout << "=== All Specification Verification Milestones Succeeded ===" << std::endl;
    return 0;
}

