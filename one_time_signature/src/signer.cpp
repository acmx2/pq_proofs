// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "signer.hpp"
#include "pfmt.hpp"
#include "ots_procedures.hpp"
#include "prover.hpp"
#include <iostream>
#include <stdexcept>

namespace OtSignature {

std::pair<PublicKey, PrivateKeyFullData> Signer::generatePublicKey(const PrivateKey& sk, std::size_t parameterV) {
    if (parameterV != V) {
        throw std::runtime_error("Signer Error: Height parameter V must match global topological constant V.");
    }

    PartiallyFixedMerkleTree pfmtEngine;
    pfmtEngine.initialize(sk.trs, V);
    Hash512 fixedIdentityRootRt = pfmtEngine.getRoot();

    pfmtEngine.incorporateSecret(sk.skp, 0);

    std::vector<Byte> pathVectorTBP = pfmtEngine.getBitPath();
    std::vector<std::optional<Scalar512>> sparseSL = pfmtEngine.getSecretLeft();
    std::vector<std::optional<Scalar512>> sparseSR = pfmtEngine.getSecretRight();

    std::vector<BdcScalar> pathHashesHCPS(V);
    std::vector<std::pair<Scalar512, Scalar512>> cachedSparseSLR(V);

    for (std::size_t i = 0; i < V; ++i) {
        Scalar512 activeDelta{};
        if (sparseSL[i].has_value()) {
            activeDelta = sparseSL[i].value();
            cachedSparseSLR[i].first = activeDelta;
            cachedSparseSLR[i].second.fill(0);
        } else if (sparseSR[i].has_value()) {
            activeDelta = sparseSR[i].value();
            cachedSparseSLR[i].second = activeDelta;
            cachedSparseSLR[i].first.fill(0);
        } else {
            throw std::runtime_error("Signer Error: Found unallocated tracking lane during Phase-Split extraction.");
        }

        std::vector<Byte> hashBuffer(activeDelta.begin(), activeDelta.end());
        BatchDeniableCommitment::Hash bdcHash = BatchDeniableCommitment::CryptoEngine::sha256(hashBuffer);
        std::copy(bdcHash.begin(), bdcHash.end(), pathHashesHCPS[i].begin());
    }

    BdcBatchScalars bdcInputScalars{};
    for (std::size_t i = 0; i < V; ++i) {
        bdcInputScalars[i] = pathHashesHCPS[i];
    }

    auto bdcCommitmentPair = BatchDeniableCommitment::Prover::generateCommitment(bdcInputScalars, sk.ggmri);
    BdcPublicCommitment commitmentMatrixRootMTR = bdcCommitmentPair.first;

    std::vector<Byte> cmtBuffer;
    cmtBuffer.reserve(64 + 32);
    cmtBuffer.insert(cmtBuffer.end(), fixedIdentityRootRt.begin(), fixedIdentityRootRt.end());
    cmtBuffer.insert(cmtBuffer.end(), commitmentMatrixRootMTR.begin(), commitmentMatrixRootMTR.end());
    Hash512 publicCommitmentTokenCMT = CryptoEngine::sha512(cmtBuffer);

    PublicKey pubKey{};
    pubKey.pk = CryptoEngine::computeXor512(sk.skp, publicCommitmentTokenCMT);

    PrivateKeyFullData fullData{};
    fullData.baseKey = sk;
    fullData.pfmtRootRt = fixedIdentityRootRt;
    fullData.bitpathTBP = pathVectorTBP;
    fullData.slr = cachedSparseSLR;
    fullData.bdcFullData = bdcCommitmentPair.second;
    fullData.cachedBdcMtr = commitmentMatrixRootMTR;

    return {pubKey, fullData};
}

Signature Signer::sign(const PrivateKeyFullData& fullData, const PublicRing& ringIn, const Scalar512& message, std::size_t parameterV) {
    if (parameterV != V) {
        throw std::runtime_error("Signer Error: Height parameter V must match global topological constant V.");
    }

    std::size_t originalRingSize = ringIn.size();
    std::size_t balancedRingSize = static_cast<std::size_t>(1) << V;

    if (originalRingSize != balancedRingSize - 1) {
        throw std::runtime_error("Signer Error: Ad-hoc ring size must equal exactly 2^V - 1 public key targets.");
    }

    std::vector<Byte> cmtBuffer;
    cmtBuffer.reserve(64 + 32);
    cmtBuffer.insert(cmtBuffer.end(), fullData.pfmtRootRt.begin(), fullData.pfmtRootRt.end());
    
    BdcPublicCommitment commitmentMatrixRootMTR = fullData.cachedBdcMtr;
    cmtBuffer.insert(cmtBuffer.end(), commitmentMatrixRootMTR.begin(), commitmentMatrixRootMTR.end());
    Hash512 linkingTagI = CryptoEngine::sha512(cmtBuffer);

    std::vector<Byte> msgBuffer;
    msgBuffer.reserve(64 + 64);
    msgBuffer.insert(msgBuffer.end(), message.begin(), message.end());
    msgBuffer.insert(msgBuffer.end(), linkingTagI.begin(), linkingTagI.end());
    Hash512 hashedAnchor = CryptoEngine::sha512(msgBuffer);
    Scalar512 messageAnchorM = CryptoEngine::computeXor512(hashedAnchor, linkingTagI);

    std::size_t signerIndexInsideRing = 0xFFFFFFFF;
    PublicKey myComputedPubKey{};
    std::vector<Byte> dynamicCmtBuffer;
    dynamicCmtBuffer.reserve(64 + 32);
    dynamicCmtBuffer.insert(dynamicCmtBuffer.end(), fullData.pfmtRootRt.begin(), fullData.pfmtRootRt.end());
    dynamicCmtBuffer.insert(dynamicCmtBuffer.end(), fullData.cachedBdcMtr.begin(), fullData.cachedBdcMtr.end());
    Hash512 myCmt = CryptoEngine::sha512(dynamicCmtBuffer);
    myComputedPubKey.pk = CryptoEngine::computeXor512(fullData.baseKey.skp, myCmt);

    for (std::size_t k = 0; k < originalRingSize; ++k) {
        if (ringIn[k].pk == myComputedPubKey.pk) {
            signerIndexInsideRing = k;
            break;
        }
    }

    if (signerIndexInsideRing == 0xFFFFFFFF) {
        throw std::runtime_error("Signer Error: Signer public key footprint missing from input ring.");
    }

    std::vector<Scalar512> expandedRingNodes(balancedRingSize);
    for (std::size_t k = 0; k < balancedRingSize - 1; ++k) {
        expandedRingNodes[k] = ringIn[k].pk;
    }
    expandedRingNodes[balancedRingSize - 1] = messageAnchorM;

    std::vector<Scalar512> leafSpectrum(balancedRingSize);
    for (std::size_t k = 0; k < balancedRingSize; ++k) {
        leafSpectrum[k] = CryptoEngine::computeXor512(expandedRingNodes[k], linkingTagI);
    }

    std::vector<std::pair<Scalar512, Scalar512>> expansionPairs(V);
    for (std::size_t i = 0; i < V; ++i) {
        std::vector<Byte> leftBuffer;
        leftBuffer.reserve(64 + 1 + sizeof(i));
        leftBuffer.insert(leftBuffer.end(), fullData.baseKey.trs.begin(), fullData.baseKey.trs.end());
        leftBuffer.push_back('L');
        const Byte* iBytes = reinterpret_cast<const Byte*>(&i);
        leftBuffer.insert(leftBuffer.end(), iBytes, iBytes + sizeof(i));
        expansionPairs[i].first = CryptoEngine::sha512(leftBuffer);

        std::vector<Byte> rightBuffer;
        rightBuffer.reserve(64 + 1 + sizeof(i));
        rightBuffer.insert(rightBuffer.end(), fullData.baseKey.trs.begin(), fullData.baseKey.trs.end());
        rightBuffer.push_back('R');
        rightBuffer.insert(rightBuffer.end(), iBytes, iBytes + sizeof(i));
        expansionPairs[i].second = CryptoEngine::sha512(rightBuffer);
    }

    std::vector<std::pair<Scalar512, Scalar512>> completelyPopulatedSLR = fullData.slr;
    std::vector<Hash512> currentLayerNodes = leafSpectrum;
    std::size_t activeTrackIndex = signerIndexInsideRing;

    for (std::size_t i = 0; i < V; ++i) {
        std::size_t basePairIdx = activeTrackIndex & ~1ULL;
        std::size_t siblingIndex = activeTrackIndex ^ 1;
        Hash512 companionNode = currentLayerNodes[siblingIndex];

        Byte pathBit = (activeTrackIndex & 1);

        if (pathBit == 0) {
            completelyPopulatedSLR[i].first = fullData.slr[i].first;
            Scalar512 rightMaskedTarget = expansionPairs[i].second;
            completelyPopulatedSLR[i].second = CryptoEngine::computeXor512(companionNode, rightMaskedTarget);
        } else {
            completelyPopulatedSLR[i].second = fullData.slr[i].second;
            Scalar512 leftMaskedTarget = expansionPairs[i].first;
            completelyPopulatedSLR[i].first = CryptoEngine::computeXor512(companionNode, leftMaskedTarget);
        }

        activeTrackIndex >>= 1;

        std::size_t nextLayerSize = currentLayerNodes.size() / 2;
        std::vector<Hash512> nextLayerNodes(nextLayerSize);

        for (std::size_t j = 0; j < nextLayerSize; ++j) {
            std::vector<Byte> concatBuffer;
            concatBuffer.reserve(128);

            Scalar512 leftMaskedNode = CryptoEngine::computeXor512(currentLayerNodes[2 * j], completelyPopulatedSLR[i].first);
            Scalar512 rightMaskedNode = CryptoEngine::computeXor512(currentLayerNodes[2 * j + 1], completelyPopulatedSLR[i].second);

            concatBuffer.insert(concatBuffer.end(), leftMaskedNode.begin(), leftMaskedNode.end());
            concatBuffer.insert(concatBuffer.end(), rightMaskedNode.begin(), rightMaskedNode.end());
            nextLayerNodes[j] = CryptoEngine::sha512(concatBuffer);
        }
        currentLayerNodes = std::move(nextLayerNodes);
    }

    std::cout << "[Diagnostics Signer]: Final calculated specification root hash context state byte: " 
              << static_cast<int>(currentLayerNodes[0][0]) << std::endl;

    BdcBatchRings bdcPresentationRings{};
    for (std::size_t i = 0; i < V; ++i) {
        std::vector<Byte> leftBuf(completelyPopulatedSLR[i].first.begin(), completelyPopulatedSLR[i].first.end());
        std::vector<Byte> rightBuf(completelyPopulatedSLR[i].second.begin(), completelyPopulatedSLR[i].second.end());
        
        BatchDeniableCommitment::Hash leftHash = BatchDeniableCommitment::CryptoEngine::sha256(leftBuf);
        BatchDeniableCommitment::Hash rightHash = BatchDeniableCommitment::CryptoEngine::sha256(rightBuf);
        
        std::copy(leftHash.begin(), leftHash.end(), bdcPresentationRings[i].first.begin());
        std::copy(rightHash.begin(), rightHash.end(), bdcPresentationRings[i].second.begin());
    }

    BdcProofPayload derivedBdcMultiProof = BatchDeniableCommitment::Prover::genProof(fullData.bdcFullData, bdcPresentationRings);

    Signature wireSignature{};
    wireSignature.rt = fullData.pfmtRootRt;
    wireSignature.mtr = commitmentMatrixRootMTR;
    wireSignature.slr = completelyPopulatedSLR;
    wireSignature.bdcp = derivedBdcMultiProof;

    return wireSignature;
}

} // namespace OtSignature

