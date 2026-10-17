// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "signer.hpp"
#include "pfmt.hpp"
#include "ots_procedures.hpp"
#include "prover.hpp"
#include <iostream>
#include <stdexcept>

namespace OtSignature {

namespace {

    // =========================================================================
    // SUB-ROUTINE: ENTRANCE PAIR REALIGNMENT LOOPS (Section 2.2)
    // =========================================================================
    // Reconstructs level-wise entrance target parameters directly from the private TRS seed.
    // This allows the signing routine to re-evaluate the exact entrance constants computed during KeyGen.
    // Buffer Serialization Strategy: Private Seed TRS (64 bytes) || Side ('L' or 'R') || Layer Index i
    std::pair<Scalar512, Scalar512> evaluateEntrancePair(const Scalar512& trs, std::size_t layerIndex) {
        std::pair<Scalar512, Scalar512> pairs;
        const Byte* idxBytes = reinterpret_cast<const Byte*>(&layerIndex);

        // Precompute Left Entrance Token Block (EL_i) using domain separation tag 'L'
        std::vector<Byte> leftBuffer(trs.begin(), trs.end());
        leftBuffer.push_back('L');
        leftBuffer.insert(leftBuffer.end(), idxBytes, idxBytes + sizeof(layerIndex));
        pairs.first = CryptoEngine::sha512(leftBuffer);

        // Precompute Right Entrance Token Block (ER_i) using domain separation tag 'R'
        std::vector<Byte> rightBuffer(trs.begin(), trs.end());
        rightBuffer.push_back('R');
        rightBuffer.insert(rightBuffer.end(), idxBytes, idxBytes + sizeof(layerIndex));
        pairs.second = CryptoEngine::sha512(rightBuffer);

        return pairs;
    }

    // =========================================================================
    // SUB-ROUTINE: KEYGEN PATH DELTAS PACKING
    // =========================================================================
    // Converts the sparse, optional tracking data structures from the PFMT engine
    // into a standardized flat collection of Left/Right delta scalar pairs, and prepares the 
    // 256-bit hashed presentation entries needed for the Batch Deniable Commitment Suite.
    BdcBatchScalars processKeygenPathDeltas(
        const std::vector<std::optional<Scalar512>>& sparseSL,
        const std::vector<std::optional<Scalar512>>& sparseSR,
        std::vector<std::pair<Scalar512, Scalar512>>& outCachedSparseSLR) 
    {
        BdcBatchScalars bdcInputScalars{};

        // Loop over each layer index to pack sparse entries into dense arrays.
        for (std::size_t i = 0; i < V; ++i) {
            Scalar512 activeDelta{};
            
            // Isolate the assigned lane from key generation and fill the vacant side with zero padding.
            if (sparseSL[i].has_value()) {
                activeDelta = sparseSL[i].value();
                outCachedSparseSLR[i].first = activeDelta;
                outCachedSparseSLR[i].second.fill(0); 
            } else if (sparseSR[i].has_value()) {
                activeDelta = sparseSR[i].value();
                outCachedSparseSLR[i].second = activeDelta;
                outCachedSparseSLR[i].first.fill(0); 
            } else {
                throw std::runtime_error("Signer Error: Unallocated path lane during keygen split.");
            }

            // Compress the 512-bit delta into a standard 256-bit BDCS commitment leaf hash using SHA-256.
            std::vector<Byte> hashBuffer(activeDelta.begin(), activeDelta.end());
            BdcHash bdcHash = BatchDeniableCommitment::CryptoEngine::sha256(hashBuffer);
            std::copy(bdcHash.begin(), bdcHash.end(), bdcInputScalars[i].begin());
        }

        return bdcInputScalars;
    }

} // namespace

namespace {

    // =========================================================================
    // SUB-ROUTINE: DYNAMIC SIBLING EXTRACTION STEP
    // =========================================================================
    // Processes a single tree layer step to calculate companion deltas on-the-fly.
    // It maps the unknown sibling path node directly to the pristine entrance target constants.
    void processSigningLayerStep(
        std::size_t layerIndex,
        std::size_t activeTrackIndex,
        const Scalar512& trs,
        const std::vector<Hash512>& currentLayerNodes,
        const std::vector<std::pair<Scalar512, Scalar512>>& keygenSlr,
        std::vector<std::pair<Scalar512, Scalar512>>& outCompletelyPopulatedSLR)
    {
        // Identify the exact index location of the sibling branch sitting opposite our current track.
        std::size_t siblingIndex = activeTrackIndex ^ 1;
        Hash512 companionNode = currentLayerNodes[siblingIndex];
        
        // Isolate the parity routing bit for the current layer.
        Byte pathBit = (activeTrackIndex & 1);

        // Fetch pristine entrance targets from the private tracking root seed (TRS).
        auto entranceConstants = evaluateEntrancePair(trs, layerIndex);

        // Compute the missing delta scalar component using bitwise XOR subtraction against the sibling.
        if (pathBit == 0) {
            outCompletelyPopulatedSLR[layerIndex].first = keygenSlr[layerIndex].first;
            outCompletelyPopulatedSLR[layerIndex].second = CryptoEngine::computeXor512(companionNode, entranceConstants.second);
        } else {
            outCompletelyPopulatedSLR[layerIndex].second = keygenSlr[layerIndex].second;
            outCompletelyPopulatedSLR[layerIndex].first = CryptoEngine::computeXor512(companionNode, entranceConstants.first);
        }
    }

    // =========================================================================
    // SUB-ROUTINE: UP-TREE MERKLE STEP FOLDING
    // =========================================================================
    // Pairwise compresses an active node layer by computing the intermediate parent nodes.
    std::vector<Hash512> computeNextSigningLayer(
        const std::vector<Hash512>& currentLayerNodes,
        const std::pair<Scalar512, Scalar512>& layerDeltas)
    {
        std::size_t nextLayerSize = currentLayerNodes.size() / 2;
        std::vector<Hash512> nextLayerNodes(nextLayerSize);

        // Progress horizontally across the current layer, compressing adjacent nodes pairwise.
        for (std::size_t j = 0; j < nextLayerSize; ++j) {
            std::vector<Byte> concatBuffer;
            concatBuffer.reserve(128);

            // Apply signature delta masks to the left and right children before hashing.
            Scalar512 leftMaskedNode = CryptoEngine::computeXor512(currentLayerNodes[2 * j], layerDeltas.first);
            Scalar512 rightMaskedNode = CryptoEngine::computeXor512(currentLayerNodes[2 * j + 1], layerDeltas.second);

            // Concatenate the masked states together to construct the SHA-512 input buffer.
            concatBuffer.insert(concatBuffer.end(), leftMaskedNode.begin(), leftMaskedNode.end());
            concatBuffer.insert(concatBuffer.end(), rightMaskedNode.begin(), rightMaskedNode.end());
            nextLayerNodes[j] = CryptoEngine::sha512(concatBuffer);
        }

        return nextLayerNodes;
    }

    // =========================================================================
    // SUB-ROUTINE: BDC PRESENTATION MATRIX FORMATTING
    // =========================================================================
    // Compresses the final populated 512-bit signature SLR pairs array down to 256 bits
    // to match the exact mathematical structural format expected by the BDC zero-knowledge Prover.
    BdcBatchRings generateBdcPresentationRings(const std::vector<std::pair<Scalar512, Scalar512>>& completelyPopulatedSLR) {
        BdcBatchRings bdcPresentationRings{};
        for (std::size_t i = 0; i < V; ++i) {
            std::vector<Byte> leftBuf(completelyPopulatedSLR[i].first.begin(), completelyPopulatedSLR[i].first.end());
            std::vector<Byte> rightBuf(completelyPopulatedSLR[i].second.begin(), completelyPopulatedSLR[i].second.end());
            
            BdcHash leftHash = BatchDeniableCommitment::CryptoEngine::sha256(leftBuf);
            BdcHash rightHash = BatchDeniableCommitment::CryptoEngine::sha256(rightBuf);
            
            std::copy(leftHash.begin(), leftHash.end(), bdcPresentationRings[i].first.begin());
            std::copy(rightHash.begin(), rightHash.end(), bdcPresentationRings[i].second.begin());
        }
        return bdcPresentationRings;
    }

} // namespace

// =============================================================================
// METHOD: Signer::generatePublicKey (Section 3.2 - Key Generation)
// =============================================================================
std::pair<PublicKey, PrivateKeyFullData> Signer::generatePublicKey(const PrivateKey& sk, std::size_t parameterV) {
    // STEP 1: Enforce parameter height system constant bounds verification pass.
    if (parameterV != V) {
        throw std::runtime_error("Signer Error: Parameter height bounds validation failure.");
    }

    // STEP 2: Initialize the Partially Fixed Merkle Tree engine using the tracking root seed (TRS).
    PartiallyFixedMerkleTree pfmt;
    pfmt.initialize(sk.trs, V);
    Hash512 fixedIdentityRootRt = pfmt.getRoot();

    // STEP 3: Incorporate secret key identity parameter (SKP) into the structure at base level index 0.
    pfmt.incorporateSecret(sk.skp, 0);

    // STEP 4: Extract the sparse path parameters and trajectory maps from the tree state.
    std::vector<Byte> pathVectorTBP = pfmt.getBitPath();
    std::vector<std::optional<Scalar512>> sparseSL = pfmt.getSecretLeft();
    std::vector<std::optional<Scalar512>> sparseSR = pfmt.getSecretRight();

    // STEP 5: Call our helper function to flatten the sparse path tracking arrays and build the BDCS leaf commitments.
    std::vector<std::pair<Scalar512, Scalar512>> cachedSparseSLR(V);
    BdcBatchScalars bdcInputScalars = processKeygenPathDeltas(sparseSL, sparseSR, cachedSparseSLR);

    // STEP 6: Invoke the Batch Deniable Commitment Suite (BDCS) Prover to generate the commitment tree root (BDC.MTR).
    auto bdcCommitmentPair = BatchDeniableCommitment::Prover::generateCommitment(bdcInputScalars, sk.ggmri);
    BdcPublicCommitment commitmentMatrixRootMTR = bdcCommitmentPair.first;

    // STEP 7: Synthesize both roots to compile the public linkable commitment token value CMT.
    std::vector<Byte> cmtBuffer;
    cmtBuffer.reserve(64 + 32);
    cmtBuffer.insert(cmtBuffer.end(), fixedIdentityRootRt.begin(), fixedIdentityRootRt.end());
    cmtBuffer.insert(cmtBuffer.end(), commitmentMatrixRootMTR.begin(), commitmentMatrixRootMTR.end());
    Hash512 publicCommitmentTokenCMT = CryptoEngine::sha512(cmtBuffer);

    // STEP 8: Construct the public key payload (PK) by masking the secret scalar behind the public commitment.
    PublicKey pubKey{};
    pubKey.pk = CryptoEngine::computeXor512(sk.skp, publicCommitmentTokenCMT);

    // STEP 9: Package all components and commitments into the full data caching structure.
    PrivateKeyFullData fullData{};
    fullData.baseKey = sk;
    fullData.pfmtRootRt = fixedIdentityRootRt;
    fullData.bitpathTBP = pathVectorTBP;
    fullData.slr = cachedSparseSLR;
    fullData.bdcFullData = bdcCommitmentPair.second;
    fullData.cachedBdcMtr = commitmentMatrixRootMTR;

    return {pubKey, fullData};
}

// =============================================================================
// METHOD: Signer::sign (Section 4 - Ring Signature Generation)
// =============================================================================
Signature Signer::sign(const PrivateKeyFullData& fullData, const PublicRing& ringIn, const Scalar512& message, std::size_t parameterV) {
    // STEP 1: Enforce parameter height system constant bounds verification pass.
    if (parameterV != V) {
        throw std::runtime_error("Signer Error: Parameter height bounds validation failure.");
    }

    std::size_t originalRingSize = ringIn.size();
    std::size_t balancedRingSize = static_cast<std::size_t>(1) << V;

    // STEP 2: Verify the input ring topology. The ring must contain exactly 2^V - 1 entries.
    if (originalRingSize != balancedRingSize - 1) {
        throw std::runtime_error("Signer Error: Ring size dimension invariant failure.");
    }

    // STEP 3: DRY REALIGNMENT REFAC: Instantiate a temporary Signature skeleton frame mapping.
    // This allows us to invoke the object-oriented helper method `getLinkingTag()` natively,
    // completely eliminating duplicate low-level buffer calculation code loops.
    Signature skeletonSig{};
    skeletonSig.rt = fullData.pfmtRootRt;
    skeletonSig.mtr = fullData.cachedBdcMtr;
    Hash512 linkingTagI = skeletonSig.getLinkingTag();

    // STEP 4: Compute the cryptographic message anchor position value M = sha512(Message || I) XOR I.
    std::vector<Byte> msgBuffer;
    msgBuffer.reserve(64 + 64);
    msgBuffer.insert(msgBuffer.end(), message.begin(), message.end());
    msgBuffer.insert(msgBuffer.end(), linkingTagI.begin(), linkingTagI.end());
    Hash512 hashedAnchor = CryptoEngine::sha512(msgBuffer);
    Scalar512 messageAnchorM = CryptoEngine::computeXor512(hashedAnchor, linkingTagI);

    // STEP 5: Read our unique horizontal indexing slot k in O(1) via the cached private bitpath trajectory helper.
    std::size_t signerIndexInsideRing = fullData.getSigningIndex();

    // STEP 6: Expand the ring nodes list to size 2^V by seating M at the absolute last slot.
    std::vector<Scalar512> expandedRingNodes(balancedRingSize);
    for (std::size_t k = 0; k < balancedRingSize - 1; ++k) {
        expandedRingNodes[k] = ringIn[k].pk;
    }
    expandedRingNodes[balancedRingSize - 1] = messageAnchorM;

    // STEP 7: Execute element-wise bitwise XOR subtraction pass using linking tag I across the leaf group.
    std::vector<Scalar512> leafSpectrum(balancedRingSize);
    for (std::size_t k = 0; k < balancedRingSize; ++k) {
        leafSpectrum[k] = CryptoEngine::computeXor512(expandedRingNodes[k], linkingTagI);
    }

    // STEP 8: Loop bottom-up across all V tree layers to calculate companion deltas on-the-fly and fold the tree.
    std::vector<std::pair<Scalar512, Scalar512>> completelyPopulatedSLR = fullData.slr;
    std::vector<Hash512> currentLayerNodes = leafSpectrum;
    std::size_t activeTrackIndex = signerIndexInsideRing;

    for (std::size_t i = 0; i < V; ++i) {
        // Step 8a: Compute companion delta elements using our decoupled layer helper function
        processSigningLayerStep(i, activeTrackIndex, fullData.baseKey.trs, currentLayerNodes, fullData.slr, completelyPopulatedSLR);

        // Step 8b: Shift our tracking index right to stay synchronized as the tree contracts
        activeTrackIndex >>= 1;

        // Step 8c: Fold the current layer to calculate the parent nodes for the next level
        currentLayerNodes = computeNextSigningLayer(currentLayerNodes, completelyPopulatedSLR[i]);
    }

    // STEP 9: Extract the diagnostic trace byte safely from the root element vector array
    std::cout << "[Diagnostics Signer]: Final calculated specification root hash context state byte: " 
              << static_cast<int>(currentLayerNodes[0][0]) << std::endl;

    // STEP 10: Format the completed SLR pairs into 256-bit hashes for Phase 1 verification.
    BdcBatchRings bdcPresentationRings = generateBdcPresentationRings(completelyPopulatedSLR);

    // STEP 11: Generate the zero-knowledge proof payload block against our pre-cached witness state data.
    BdcProofPayload derivedBdcMultiProof = BatchDeniableCommitment::Prover::genProof(fullData.bdcFullData, bdcPresentationRings);

    // STEP 12: Output the final compiled signature package.
    Signature wireSignature{};
    wireSignature.rt = fullData.pfmtRootRt;
    wireSignature.mtr = fullData.cachedBdcMtr;
    wireSignature.slr = completelyPopulatedSLR;
    wireSignature.bdcp = derivedBdcMultiProof;

    return wireSignature;
}

} // namespace OtSignature

