/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "verifier.hpp"
#include "common_procedures.hpp"
#include "challenge_builder.hpp"
#include <map>

namespace DeniableCommitment {

using std::array;
using std::map;

// Purpose: Symmetrically expands validation bitstreams and evaluates naive validation.
// Arguments: root - commitment reference; ring - input vector bundle; proof - wire frame context data.
bool Verifier::verifyProofNaive(const PublicCommitment& root,
                                const Ring& ring,
                                const NaiveProof& proof) {
    // Step 1: Expand Ring component items symmetrically to extract their bitstreams.
    Bitstream streamA = CryptoEngine::expandScalar(ring.first);
    UnpackedBitstream bitsA = CryptoEngine::unpackBitstream(streamA);

    Bitstream streamB = CryptoEngine::expandScalar(ring.second);
    UnpackedBitstream bitsB = CryptoEngine::unpackBitstream(streamB);

    // Step 2: Locally derive the challenge indices array to prevent parameter manipulation.
    ChallengeIndices selection = ChallengeBuilder::deriveChallengeIndices(bitsA, bitsB);

    // Step 3: Forward variables onto the flat verification path validator loop.
    return executeVerifyProofNaive(root, selection, bitsA, proof);
}

// Purpose: Symmetrically expands validation bitstreams and evaluates compressed octopus validation.
// Arguments: root - commitment reference; ring - input vector bundle; proof - wire frame context data.
bool Verifier::verifyProofOctopus(const PublicCommitment& root,
                                  const Ring& ring,
                                  const OctopusProof& proof) {
    // Step 1: Expand Ring component items symmetrically to extract their bitstreams.
    Bitstream streamA = CryptoEngine::expandScalar(ring.first);
    UnpackedBitstream bitsA = CryptoEngine::unpackBitstream(streamA);

    Bitstream streamB = CryptoEngine::expandScalar(ring.second);
    UnpackedBitstream bitsB = CryptoEngine::unpackBitstream(streamB);

    // Step 2: Locally derive the challenge indices array to prevent parameter manipulation.
    ChallengeIndices selection = ChallengeBuilder::deriveChallengeIndices(bitsA, bitsB);

    // Step 3: Forward variables onto the tree-pruned row consolidation validator loop.
    return executeVerifyProofOctopus(root, selection, bitsA, proof);
}

// Purpose: Iterates through discrete independent hashes paths to match the target commitment root.
// Arguments: root - root digest hash block; derivedIndices - verifier computed checkpoints; expectedBits - expanded baseline reference bit matrix floor; proof - naive wire payload reference.
bool Verifier::executeVerifyProofNaive(const Hash& root, 
                                      const ChallengeIndices& derivedIndices,
                                      const UnpackedBitstream& expectedBits, 
                                      const NaiveProof& proof) {
    // Step 1: Extract loose challenge bits out of packed wire payload components.
    UnpackedOpenBitsBlock bits = CryptoEngine::unpackChallengeBits(proof.packedBits); 
    std::size_t proofIdx = 0;
    
    // Step 2: Symmetrically validate proof paths across all 128 individual challenge slots.
    for (std::size_t i = 0; i < ChallengeLength; ++i) {
        Index targetIdx = derivedIndices[i];

        if (bits[i] != expectedBits[targetIdx]) {
            return false;
        }

        // Step 3: Reconstruct leaf hash from received bits and masks data arrays.
        Hash current = CryptoEngine::sha256Leaf(bits[i], proof.masks[i]);
        MtIndex currentToken = MtIndex::fromLeafIndex(targetIdx);
        
        // Step 4: Fold hashes upstream level-by-level to match against the root.
        for (std::size_t lvl = LeafExponent; lvl > 0; --lvl) {
            if (proofIdx >= proof.companionHashes.size()) return false;
            Hash sibling = proof.companionHashes[proofIdx++];
            
            if (currentToken.indexAtLevel % 2 == 0) {
                current = CryptoEngine::sha256Nodes(current, sibling);
            } else {
                current = CryptoEngine::sha256Nodes(sibling, current);
            }
            currentToken = currentToken.getParent();
        }
        if (current != root) return false;
    }
    
    // Step 5: Path matches confirmed completely across all slots bounds.
    return true;
}

// Purpose: Collapses compressed level maps concurrently to reconstruct and validate the multi-proof root.
// Arguments: root - root digest hash block; derivedIndices - verifier computed checkpoints; expectedBits - expanded baseline reference bit matrix floor; proof - octopus wire payload reference.
bool Verifier::executeVerifyProofOctopus(const Hash& root, 
                                        const ChallengeIndices& derivedIndices,
                                        const UnpackedBitstream& expectedBits, 
                                        const OctopusProof& proof) {
    // Step 1: Extract loose challenge bits out of packed wire payload components.
    UnpackedOpenBitsBlock bits = CryptoEngine::unpackChallengeBits(proof.packedBits); 
    
    // Step 2: Populate the active layer row registry map with evaluated base leaf hashes.
    map<std::size_t, Hash> currentLevelMap;
    for (std::size_t i = 0; i < ChallengeLength; ++i) {
        Index targetIdx = derivedIndices[i];
        if (bits[i] != expectedBits[targetIdx]) {
            return false;
        }
        currentLevelMap[targetIdx] = CryptoEngine::sha256Leaf(bits[i], proof.masks[i]);
    }

    std::size_t proofIdx = 0;
    
    // Step 3: Compute row layers concurrently up the tree layers to compress shared paths.
    for (std::size_t lvl = LeafExponent; lvl > 0; --lvl) {
        map<std::size_t, Hash> nextLevelMap;
        for (auto const& [currentHorizIdx, hashVal] : currentLevelMap) {
            MtIndex currentToken{ lvl, currentHorizIdx };
            MtIndex parentToken = currentToken.getParent();
            
            if (nextLevelMap.find(parentToken.indexAtLevel) != nextLevelMap.end()) continue;

            MtIndex siblingToken = currentToken.getSibling();
            Hash siblingHash;
            auto sibIt = currentLevelMap.find(siblingToken.indexAtLevel);

            if (sibIt != currentLevelMap.end()) {
                // Sibling is present in active map; pull it straight from local computations.
                siblingHash = sibIt->second;
            } else {
                // Sibling is absent; pull its hash value directly out of the wire vector payload.
                if (proofIdx >= proof.prunedHashes.size()) return false;
                siblingHash = proof.prunedHashes[proofIdx++];
            }

            // Step 4: Merge sibling pairs and register the calculated parent hash.
            if (currentHorizIdx % 2 == 0) {
                nextLevelMap[parentToken.indexAtLevel] = CryptoEngine::sha256Nodes(hashVal, siblingHash);
            } else {
                nextLevelMap[parentToken.indexAtLevel] = CryptoEngine::sha256Nodes(siblingHash, hashVal);
            }
        }
        currentLevelMap = nextLevelMap;
    }
    
    // Step 5: Check that the finalized topmost computed parent node is equivalent to the root.
    if (currentLevelMap.empty()) return false;
    return currentLevelMap.begin()->second == root;
}

} // namespace DeniableCommitment

