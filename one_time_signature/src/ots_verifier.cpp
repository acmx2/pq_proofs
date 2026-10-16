// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "ots_verifier.hpp"
#include "ots_procedures.hpp"
#include "common_procedures.hpp"
#include <verifier.hpp>
#include <iostream>
#include <stdexcept>

namespace OtSignature {

bool Verifier::verify(const PublicRing& ringIn, const Scalar512& message, const Signature& sig, std::size_t parameterV) {
    if (parameterV != V || sig.slr.size() != V) {
        return false;
    }

    std::size_t originalRingSize = ringIn.size();
    std::size_t balancedRingSize = static_cast<std::size_t>(1) << V;

    if (originalRingSize != balancedRingSize - 1) {
        return false;
    }

    // =========================================================================
    // PHASE 1: BDC BINDING VALIDATION (SECTION 5.1)
    // =========================================================================
    BdcBatchRings bdcPresentationRings{};
    for (std::size_t i = 0; i < V; ++i) {
        std::vector<Byte> leftBuf(sig.slr[i].first.begin(), sig.slr[i].first.end());
        std::vector<Byte> rightBuf(sig.slr[i].second.begin(), sig.slr[i].second.end());

        BatchDeniableCommitment::Hash leftHash = BatchDeniableCommitment::CryptoEngine::sha256(leftBuf);
        BatchDeniableCommitment::Hash rightHash = BatchDeniableCommitment::CryptoEngine::sha256(rightBuf);

        std::copy(leftHash.begin(), leftHash.end(), bdcPresentationRings[i].first.begin());
        std::copy(rightHash.begin(), rightHash.end(), bdcPresentationRings[i].second.begin());
    }

    bool bdcCheck = BatchDeniableCommitment::Verifier::verifyProof(sig.mtr, bdcPresentationRings, sig.bdcp);
    if (!bdcCheck) {
        std::cout << "[Diagnostics Verifier]: CRITICAL REJECTION: Phase 1 BDC Binding check failed!" << std::endl;
        return false; 
    }

    // =========================================================================
    // PHASE 2: PFMT BOUNDARY ALIGNMENT VALIDATION (SECTION 5.2)
    // =========================================================================
    Hash512 linkingTagI = sig.getLinkingTag();
    std::vector<Byte> msgBuffer;
    msgBuffer.reserve(64 + 64);
    msgBuffer.insert(msgBuffer.end(), message.begin(), message.end());
    msgBuffer.insert(msgBuffer.end(), linkingTagI.begin(), linkingTagI.end());
    Hash512 hashedAnchor = CryptoEngine::sha512(msgBuffer);
    Scalar512 messageAnchorM = CryptoEngine::computeXor512(hashedAnchor, linkingTagI);

    std::vector<Scalar512> validationNodes(balancedRingSize);
    for (std::size_t k = 0; k < balancedRingSize - 1; ++k) {
        validationNodes[k] = ringIn[k].pk;
    }
    validationNodes[balancedRingSize - 1] = messageAnchorM;

    for (std::size_t k = 0; k < balancedRingSize; ++k) {
        validationNodes[k] = CryptoEngine::computeXor512(validationNodes[k], linkingTagI);
    }

    std::vector<Hash512> currentLayerNodes = validationNodes;
    for (std::size_t i = 0; i < V; ++i) {
        std::size_t nextLayerSize = currentLayerNodes.size() / 2;
        std::vector<Hash512> nextLayerNodes(nextLayerSize);

        for (std::size_t j = 0; j < nextLayerSize; ++j) {
            std::vector<Byte> concatBuffer;
            concatBuffer.reserve(128);

            Scalar512 leftMaskedNode = CryptoEngine::computeXor512(currentLayerNodes[2 * j], sig.slr[i].first);
            Scalar512 rightMaskedNode = CryptoEngine::computeXor512(currentLayerNodes[2 * j + 1], sig.slr[i].second);

            concatBuffer.insert(concatBuffer.end(), leftMaskedNode.begin(), leftMaskedNode.end());
            concatBuffer.insert(concatBuffer.end(), rightMaskedNode.begin(), rightMaskedNode.end());

            nextLayerNodes[j] = CryptoEngine::sha512(concatBuffer);
        }
        currentLayerNodes = std::move(nextLayerNodes);
    }

    if (currentLayerNodes.size() != 1) {
        return false;
    }

    std::cout << "[Diagnostics Verifier]: Reconstructed up-tree root hash context state byte: " 
              << static_cast<int>(currentLayerNodes[0][0]) << std::endl;
    std::cout << "[Diagnostics Verifier]: Transmitted reference root token Sig.rt byte:        " 
              << static_cast<int>(sig.rt[0]) << std::endl;

    return (currentLayerNodes[0] == sig.rt);
}

} // namespace OtSignature

