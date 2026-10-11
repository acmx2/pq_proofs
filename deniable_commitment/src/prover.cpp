/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "prover.hpp"
#include "common_procedures.hpp"
#include "challenge_builder.hpp"
#include <algorithm>
#include <random>

namespace DeniableCommitment {

using std::array;
using std::vector;
using std::make_pair;
using std::pair;

// Purpose: Initializes expanded bitstreams, secret mask maps, and builds a public Merkle root.
// Arguments: secretScalar - committed input value; secureSeed - loop entropy generator seed parameter.
pair<PublicCommitment, PrivateCommitmentFullData> Prover::generateCommitment(const Scalar& secretScalar, std::uint32_t secureSeed) {
    // Step 1: Pre-allocate the heavy private cache data block.
    PrivateCommitmentFullData fullData;
    fullData.secretScalar = secretScalar;
    fullData.secureSeed = secureSeed;
    
    // Step 2: Expand the secret scalar value out to its full 1,024 pseudorandom bits.
    Bitstream stream = CryptoEngine::expandScalar(secretScalar);
    fullData.privateBits = CryptoEngine::unpackBitstream(stream);
    
    // Step 3: Instantiate a PRNG to evaluate the full sequence of 1,024 unique 32-byte leaf masks.
    std::mt19937 secureRng(secureSeed);
    for (std::size_t i = 0; i < BitstreamLength; ++i) {
        for (std::size_t j = 0; j < 32; ++j) {
            fullData.privateMasks[i][j] = secureRng() % 256;
        }
    }
    
    // Step 4: Iteratively compute all base leaf hashes before constructing the topology.
    std::array<Hash, BitstreamLength> localLeafHashes;
    for (std::size_t i = 0; i < BitstreamLength; ++i) {
        localLeafHashes[i] = CryptoEngine::sha256Leaf(fullData.privateBits[i], fullData.privateMasks[i]);
    }
    
    // Step 5: Construct the tree structure and isolate the public root hash parameter.
    fullData.privateTree = MerkleTree::build(localLeafHashes);
    PublicCommitment publicRoot = fullData.privateTree.getRoot();
    
    return make_pair(publicRoot, fullData);
}

// Purpose: Transparently restores the deep tree context from an opening snapshot.
// Arguments: openingData - minimal witness container struct.
PrivateCommitmentFullData Prover::restoreFullData(const PrivateCommitmentOpeningData& openingData) {
    // Step 1: Re-execute full deterministic pipeline setup using original low-weight parameters.
    auto result = generateCommitment(openingData.secretScalar, openingData.secureSeed);
    return result.second;
}

// Purpose: Prepares unoptimized proof execution by resolving challenge indices dynamically.
// Arguments: fullData - private tree cache reference; arbitraryScalar - presentation context variable.
NaiveProof Prover::genProofNaive(const PrivateCommitmentFullData& fullData, const Scalar& arbitraryScalar) {
    // Step 1: Expand the arbitrary input scalar into its corresponding bit representation.
    Bitstream streamB = CryptoEngine::expandScalar(arbitraryScalar);
    UnpackedBitstream bitsB = CryptoEngine::unpackBitstream(streamB);

    // Step 2: Locally derive challenge indices from the intersection pool.
    ChallengeIndices selection = ChallengeBuilder::deriveChallengeIndices(fullData.privateBits, bitsB);

    // Step 3: Forward parameters onto the unoptimized baseline branch assembly loop.
    return executeGenProofNaive(fullData.privateTree, fullData.privateBits, fullData.privateMasks, selection);
}

// Purpose: Prepares optimized proof execution by resolving challenge indices dynamically.
// Arguments: fullData - private tree cache reference; arbitraryScalar - presentation context variable.
OctopusProof Prover::genProofOctopus(const PrivateCommitmentFullData& fullData, const Scalar& arbitraryScalar) {
    // Step 1: Expand the arbitrary input scalar into its corresponding bit representation.
    Bitstream streamB = CryptoEngine::expandScalar(arbitraryScalar);
    UnpackedBitstream bitsB = CryptoEngine::unpackBitstream(streamB);

    // Step 2: Locally derive challenge indices from the intersection pool.
    ChallengeIndices selection = ChallengeBuilder::deriveChallengeIndices(fullData.privateBits, bitsB);

    // Step 3: Forward parameters onto the optimized multi-proof tree consolidation loop.
    return executeGenProofOctopus(fullData.privateTree, fullData.privateBits, fullData.privateMasks, selection);
}

// Purpose: Transparently overloads naive generation to restore tree data on the fly.
// Arguments: openingData - minimal opening payload witness; arbitraryScalar - presentation variable.
NaiveProof Prover::genProofNaive(const PrivateCommitmentOpeningData& openingData, const Scalar& arbitraryScalar) {
    // Step 1: Transparently restore the deep tree context from the opening snapshot.
    PrivateCommitmentFullData restoredData = restoreFullData(openingData);
    return genProofNaive(restoredData, arbitraryScalar);
}

// Purpose: Transparently overloads octopus generation to restore tree data on the fly.
// Arguments: openingData - minimal opening payload witness; arbitraryScalar - presentation variable.
OctopusProof Prover::genProofOctopus(const PrivateCommitmentOpeningData& openingData, const Scalar& arbitraryScalar) {
    // Step 1: Transparently restore the deep tree context from the opening snapshot.
    PrivateCommitmentFullData restoredData = restoreFullData(openingData);
    return genProofOctopus(restoredData, arbitraryScalar);
}

// Purpose: Compiles flat redundant sibling authentication rows path vectors.
// Arguments: tree - Merkle authentication mapping; bits - local expanded byte bit stream; masks - private salts vector block; challengeIndices - roadmap indices token.
NaiveProof Prover::executeGenProofNaive(const MerkleTree& tree, 
                                        const UnpackedBitstream& bits,
                                        const array<Scalar, BitstreamLength>& masks,
                                        const ChallengeIndices& challengeIndices) {
    NaiveProof proof;
    UnpackedOpenBitsBlock unencodedBits; 
    std::size_t hashIdx = 0;

    // Step 1: Build independent branch segments for each of the 128 challenge coordinates.
    for (std::size_t i = 0; i < ChallengeLength; ++i) {
        Index idx = challengeIndices[i];
        unencodedBits[i] = bits[idx];
        proof.masks[i] = masks[idx];
        
        // Step 2: Record all companion sibling hashes layer-by-layer up to Level 1.
        MtIndex currentToken = MtIndex::fromLeafIndex(idx);
        for (std::size_t lvl = LeafExponent; lvl > 0; --lvl) {
            proof.companionHashes[hashIdx++] = tree.getNode(currentToken.getSibling());
            currentToken = currentToken.getParent();
        }
    }
    
    // Step 3: Compress challenge bits and return the unoptimized baseline payload frame.
    proof.packedBits = CryptoEngine::packChallengeBits(unencodedBits);
    return proof;
}

// Purpose: Performs bottom-up tree-pruning consolidation to isolate unique sibling hashes.
// Arguments: tree - Merkle authentication mapping; bits - local expanded byte bit stream; masks - private salts vector block; challengeIndices - roadmap indices token.
OctopusProof Prover::executeGenProofOctopus(const MerkleTree& tree, 
                                            const UnpackedBitstream& bits,
                                            const array<Scalar, BitstreamLength>& masks,
                                            const ChallengeIndices& challengeIndices) {
    OctopusProof proof;
    UnpackedOpenBitsBlock unencodedBits; 
    
    // Step 1: Initialize the tracking loop vector array with base leaf index tokens.
    vector<MtIndex> activeTokens;
    activeTokens.reserve(ChallengeLength);
    for (std::size_t i = 0; i < ChallengeLength; ++i) {
        Index idx = challengeIndices[i];
        unencodedBits[i] = bits[idx];
        proof.masks[i] = masks[idx];
        activeTokens.push_back(MtIndex::fromLeafIndex(idx));
    }

    // Step 2: Iterate bottom-up to isolate and compress overlapping sibling path structures.
    for (std::size_t lvl = LeafExponent; lvl > 0; --lvl) {
        vector<MtIndex> nextLevelTokens;
        
        // Step 3: Sort tokens by active row indices to scan for adjacencies.
        std::sort(activeTokens.begin(), activeTokens.end(), [](const MtIndex& lhs, const MtIndex& rhs) {
            return lhs.indexAtLevel < rhs.indexAtLevel;
        });

        // Step 4: Prune siblings out if they are calculated dynamically by adjacent branches.
        for (std::size_t i = 0; i < activeTokens.size(); ++i) {
            MtIndex current = activeTokens[i];
            MtIndex sibling = current.getSibling();
            
            bool siblingFound = false;
            if (i + 1 < activeTokens.size() && activeTokens[i + 1].indexAtLevel == sibling.indexAtLevel) {
                siblingFound = true;
                ++i; 
            }
            
            if (!siblingFound) {
                proof.prunedHashes.push_back(tree.getNode(sibling));
            }
            nextLevelTokens.push_back(current.getParent());
        }
        activeTokens = nextLevelTokens;
    }
    
    // Step 5: Compress challenge bits and return the pruned optimized wire payload.
    proof.packedBits = CryptoEngine::packChallengeBits(unencodedBits);
    return proof;
}

} // namespace DeniableCommitment

