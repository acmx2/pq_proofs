// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "ots_verifier.hpp"
#include "ots_procedures.hpp"
#include "common_procedures.hpp"
#include <verifier.hpp>
#include <iostream>
#include <stdexcept>

namespace OtSignature {

namespace {
    
    // =========================================================================
    // SUB-ROUTINE: PHASE 1 RAW TRAJECTORY PARSING
    // =========================================================================
    // This helper compresses the transmitted 512-bit signature SLR pairs down to 
    // standard 256-bit hashes using SHA-256. 
    // This step formats the tracks to match the exact mathematical structural layout 
    // expected by the multi-proof input layer of the BDC Verifier component.
    BdcBatchRings parseSignatureSlrToBdcRings(const std::vector<std::pair<Scalar512, Scalar512>>& slr) {
        BdcBatchRings bdcRings{};
        
        // Loop over each layer index to compress the 512-bit vectors to 256-bit blocks.
        for (std::size_t i = 0; i < V; ++i) {
            std::vector<Byte> leftBuf(slr[i].first.begin(), slr[i].first.end());
            std::vector<Byte> rightBuf(slr[i].second.begin(), slr[i].second.end());

            // Compute independent SHA-256 hashes for both left and right component channels.
            BdcHash leftHash = BatchDeniableCommitment::CryptoEngine::sha256(leftBuf);
            BdcHash rightHash = BatchDeniableCommitment::CryptoEngine::sha256(rightBuf);

            // Copy the resulting digest words directly into the structured BDCS input container slot fields.
            std::copy(leftHash.begin(), leftHash.end(), bdcRings[i].first.begin());
            std::copy(rightHash.begin(), rightHash.end(), bdcRings[i].second.begin());
        }
        return bdcRings;
    }

    // =========================================================================
    // SUB-ROUTINE: MESSAGE ANCHOR RECONSTRUCTION
    // =========================================================================
    // Reconstructs the contextual message anchor block value M from the message and linking tag I.
    // This enforces absolute binding between the dynamic signature data and the transmitted message text.
    // Formula Invariant: M = sha512(Message || I) XOR I
    Scalar512 computeVerifierMessageAnchor(const Scalar512& message, const Hash512& linkingTagI) {
        std::vector<Byte> msgBuffer;
        msgBuffer.reserve(64 + 64);
        
        // Concatenate the raw message byte array together with the 512-bit linking tag I string.
        msgBuffer.insert(msgBuffer.end(), message.begin(), message.end());
        msgBuffer.insert(msgBuffer.end(), linkingTagI.begin(), linkingTagI.end());
        
        // Hash the combined context buffer using the SHA-512 engine.
        Hash512 hashedAnchor = CryptoEngine::sha512(msgBuffer);
        
        // Perform a pointwise bitwise XOR subtraction step against the linking tag I to isolate M.
        return CryptoEngine::computeXor512(hashedAnchor, linkingTagI);
    }

    // =========================================================================
    // SUB-ROUTINE: SPECTRUM ALLOCATION INITIALIZATION
    // =========================================================================
    // Assembles the leaf spectrum layer array from the public key ring and message anchor M.
    // Applies a bitwise XOR transformation pass using the linking tag context token I across the spectrum.
    std::vector<Scalar512> buildInitialSpectrumLayer(const PublicRing& ringIn, const Scalar512& message, const Signature& sig, std::size_t balancedSize) {
        // DRY REALIGNMENT REFAC: Reuses the object-oriented method call sig.getLinkingTag() natively 
        // to retrieve the 512-bit linkable identity token context string I.
        Hash512 linkingTagI = sig.getLinkingTag();
        
        // Reconstruct the contextual message anchor M using our isolated helper function.
        Scalar512 messageAnchorM = computeVerifierMessageAnchor(message, linkingTagI);

        // Populate the base leaf spectrum array up to size 2^V elements.
        // Copy the original public verification ring elements into slots 0 through 2^V-2.
        std::vector<Scalar512> spectrum(balancedSize);
        for (std::size_t k = 0; k < balancedSize - 1; ++k) {
            spectrum[k] = ringIn[k].pk;
        }
        
        // Seat the newly reconstructed message anchor M at the absolute last slot position (index 2^V - 1).
        spectrum[balancedSize - 1] = messageAnchorM;

        // Perform a linear XOR masking pass element-wise across all spectrum entries using linking tag I.
        // This strips away the masking outer shell layer to expose the raw verifiable internal nodes.
        for (std::size_t k = 0; k < balancedSize; ++k) {
            spectrum[k] = CryptoEngine::computeXor512(spectrum[k], linkingTagI);
        }
        return spectrum;
    }
} // namespace

namespace {

    // =========================================================================
    // SUB-ROUTINE: MERKLE TREE FOLDING LOOP STEP
    // =========================================================================
    // Processes a single up-tree tree layer compression pass over adjacent node tracks.
    // Pairwise compresses adjacent elements using the corresponding layer's signature delta masks.
    std::vector<Hash512> foldSingleVerifierLayer(const std::vector<Hash512>& currentLayer, const std::pair<Scalar512, Scalar512>& layerDeltas) {
        std::size_t nextLayerSize = currentLayer.size() / 2;
        std::vector<Hash512> nextLayer(nextLayerSize);

        // Progress horizontally across the current layer, processing nodes in adjacent pairs.
        for (std::size_t j = 0; j < nextLayerSize; ++j) {
            std::vector<Byte> concatBuffer;
            concatBuffer.reserve(128);

            // Apply the signature delta masks to the left and right children before compression.
            Scalar512 leftMaskedNode = CryptoEngine::computeXor512(currentLayer[2 * j], layerDeltas.first);
            Scalar512 rightMaskedNode = CryptoEngine::computeXor512(currentLayer[2 * j + 1], layerDeltas.second);

            // Concatenate the masked sibling values together to build the 128-byte SHA-512 input block.
            concatBuffer.insert(concatBuffer.end(), leftMaskedNode.begin(), leftMaskedNode.end());
            concatBuffer.insert(concatBuffer.end(), rightMaskedNode.begin(), rightMaskedNode.end());

            // Compute the parent hash block for the next layer up.
            nextLayer[j] = CryptoEngine::sha512(concatBuffer);
        }
        return nextLayer;
    }

    // =========================================================================
    // SUB-ROUTINE: COLLAPSE SPECTRUM TRAVERSAL
    // =========================================================================
    // Loops bottom-up across all V layers to collapse the leaf spectrum nodes completely down to a single root.
    std::vector<Hash512> collapseSpectrumToRoot(const std::vector<Scalar512>& baseSpectrum, const std::vector<std::pair<Scalar512, Scalar512>>& slr) {
        std::vector<Hash512> currentLayer = baseSpectrum;
        
        // Execute the folding step up the entire height of the tree.
        for (std::size_t i = 0; i < V; ++i) {
            currentLayer = foldSingleVerifierLayer(currentLayer, slr[i]);
        }
        return currentLayer;
    }

} // namespace

// =============================================================================
// METHOD: Verifier::verify (Section 5 - Verification Protocol)
// =============================================================================
bool Verifier::verify(const PublicRing& ringIn, const Scalar512& message, const Signature& sig, std::size_t parameterV) {
    // STEP 1: Verify structural data layout dimension boundaries.
    if (parameterV != V || sig.slr.size() != V) {
        return false;
    }

    std::size_t originalRingSize = ringIn.size();
    std::size_t balancedRingSize = static_cast<std::size_t>(1) << V;

    // Validate that the verification ring matches the topological specification rule exactly (2^V - 1 elements).
    if (originalRingSize != balancedRingSize - 1) {
        return false;
    }

    // =========================================================================
    // PHASE 1: BDC BINDING VALIDATION (SECTION 5.1)
    // =========================================================================
    // Compress transmitted 512-bit SLR elements down to 256-bit hashes using our isolated routine.
    BdcBatchRings bdcPresentationRings = parseSignatureSlrToBdcRings(sig.slr);
    
    // Invoke the Batch Deniable Commitment Suite (BDCS) Verifier to validate the zero-knowledge multi-proof.
    // This confirms that the values presented in the signature match the initial cryptographic public keys commitments.
    if (!BatchDeniableCommitment::Verifier::verifyProof(sig.mtr, bdcPresentationRings, sig.bdcp)) {
        std::cout << "[Diagnostics Verifier]: CRITICAL REJECTION: Phase 1 BDC Binding check failed!" << std::endl;
        return false; 
    }

    // =========================================================================
    // PHASE 2: PFMT BOUNDARY ALIGNMENT VALIDATION (SECTION 5.2)
    // =========================================================================
    // Step 2a: Reconstruct the base leaf spectrum layer by parsing the public keys and message anchor.
    auto baseSpectrum = buildInitialSpectrumLayer(ringIn, message, sig, balancedRingSize);
    
    // Step 2b: Collapse the spectrum layers recursively up-tree to compute the definitive single root hash.
    auto finalRootLayer = collapseSpectrumToRoot(baseSpectrum, sig.slr);

    // Enforce that the up-tree contraction condensed the structure down into a single element.
    if (finalRootLayer.size() != 1) {
        return false;
    }

    // Extract diagnostic trace values for terminal tracking inspection loops.
    // Double indexes the vector array element to print out the first primitive raw data byte.
    std::cout << "[Diagnostics Verifier]: Reconstructed up-tree root hash context state byte: " 
              << static_cast<int>(finalRootLayer[0][0]) << std::endl;
    std::cout << "[Diagnostics Verifier]: Transmitted reference root token Sig.rt byte:        " 
              << static_cast<int>(sig.rt[0]) << std::endl;

    // Step 2c: Assert that the reconstructed tree root matches the transmitted signature commitment anchor (Sig.RT).
    return (finalRootLayer[0] == sig.rt);
}

} // namespace OtSignature

