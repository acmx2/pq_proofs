/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "verifier.hpp"
#include "common_procedures.hpp"
#include "challenge_builder.hpp"
#include "io_helper.hpp"
#include "merkle_tree.hpp"
#include <algorithm>
#include <vector>

namespace BatchDeniableCommitment {

using std::vector;

Hash Verifier::reconstructCascadeLeaf(const SuperArray& superArray, const Index chunkIdx, const Hash& contextBlock, const Rank rank) {
    const std::size_t bitStartOffset = chunkIdx * C;
    Hash currentHash;

    // Step 1: Initialize hash state based on complete vs partial challenge criteria.
    if (rank == C) {
        vector<Byte> buffer(C + 32); 
        std::copy(superArray.getStorage().begin() + bitStartOffset, superArray.getStorage().begin() + bitStartOffset + C, buffer.begin());
        std::copy(contextBlock.begin(), contextBlock.end(), buffer.begin() + C);
        currentHash = CryptoEngine::sha256(buffer);
    } else {
        currentHash = contextBlock; // Bypassed via floor penalty stub hash.
    }

    // Step 2: Symmetrically march down the prefix floors using an iterative loop.
    int startBits = (rank == C) ? static_cast<int>(C) - 1 : static_cast<int>(rank);
    for (int numBits = startBits; numBits >= 1; --numBits) {
        vector<Byte> buffer(static_cast<std::size_t>(numBits) + 32);
        std::copy_n(superArray.getStorage().begin() + bitStartOffset, static_cast<std::size_t>(numBits), buffer.begin());
        std::copy(currentHash.begin(), currentHash.end(), buffer.begin() + static_cast<std::size_t>(numBits));
        currentHash = CryptoEngine::sha256(buffer);
    }

    // Step 3: Return the fully reconstructed leaf node hash.
    return currentHash;
}

bool Verifier::verifyProof(const PublicCommitment& root, const BatchRings& presentationRings, const ProofPayload& proof) {
    // Step 1: Allocate parallel public tracks on the heap to avoid any stack storage traps.
    std::vector<TrackBits> tracksB0(V), tracksB1(V);
    for (std::size_t i = 0; i < V; ++i) {
        tracksB0[i] = CryptoEngine::expandScalar(presentationRings[i].first);
        tracksB1[i] = CryptoEngine::expandScalar(presentationRings[i].second);
    }

    const SuperArray b0Super = SuperArray::mixTracks(tracksB0);
    const SuperArray b1Super = SuperArray::mixTracks(tracksB1);
    SuperArray xorSuper = b0Super.computeXor(b1Super);
    
    // Step 2: Generate the candidate pool and execute the selection engine blind verification loops.
    std::vector<Index> candidatePool = ChallengeBuilder::buildCandidatePool(xorSuper);
    std::vector<Index> expectedOpenIndices = ChallengeBuilder::runSelectionEngine(candidatePool, xorSuper);

    std::sort(expectedOpenIndices.begin(), expectedOpenIndices.end());

    std::vector<ChunkMarkup> topologicalRoadmap = IoHelper::generateTopologicalMarkup(expectedOpenIndices, xorSuper);

    std::vector<Scalar> reconstructedGgmTree((2 * LeafCount) - 1);
    std::vector<bool> ggmNodePopulated((2 * LeafCount) - 1, false);
    std::size_t ggmKeyIdx = 0;

    std::vector<Hash> fullMerkleTreeArray((2 * LeafCount) - 1);
    std::vector<bool> merkleNodePopulated((2 * LeafCount) - 1, false);
    std::size_t merkleProofIdx = 0;

    std::size_t floorPenaltyIdx = 0;
    std::size_t leavesStartOffset = LeafCount - 1;

    // Step 3: Consume proof elements sequentially to fill tree baseline markers.
    for (std::size_t k = 0; k < LeafCount; ++k) {
        const auto& chunk = topologicalRoadmap[k];

        if (chunk.isSelected) {
            if (chunk.rank == C) {
                if (chunk.isGgmSubRootRevealed) {
                    if (ggmKeyIdx >= proof.revealedGgmKeys.size()) { return false; }
                    std::size_t flatGgmIdx = (1ULL << chunk.ggmSubRootLocation.level) - 1 + chunk.ggmSubRootLocation.nodeIndex;
                    reconstructedGgmTree[flatGgmIdx] = proof.revealedGgmKeys[ggmKeyIdx++];
                    ggmNodePopulated[flatGgmIdx] = true;
                }
            }
        } else {
            if (chunk.isMerkleStubRevealed) {
                if (merkleProofIdx >= proof.prunedMerkleHashes.size()) { return false; }
                std::size_t flatMerkleIdx = (1ULL << chunk.merkleSubRootLocation.level) - 1 + chunk.merkleSubRootLocation.nodeIndex;
                fullMerkleTreeArray[flatMerkleIdx] = proof.prunedMerkleHashes[merkleProofIdx++];
                merkleNodePopulated[flatMerkleIdx] = true;
            }
        }
    }

    // Step 4: Expand parent compressed GGM keys down-tree top-down.
    for (std::size_t lvl = 0; lvl < D; ++lvl) {
        std::size_t nodesInLvl = 1ULL << lvl;
        for (std::size_t i = 0; i < nodesInLvl; ++i) {
            std::size_t pIdx = (1ULL << lvl) - 1 + i;
            if (!ggmNodePopulated[pIdx]) continue;

            std::size_t leftChildFlatIdx = (1ULL << (lvl + 1)) - 1 + (i * 2);
            std::size_t rightChildFlatIdx = leftChildFlatIdx + 1;

            if (!ggmNodePopulated[leftChildFlatIdx]) {
                std::vector<Byte> leftBuffer(reconstructedGgmTree[pIdx].begin(), reconstructedGgmTree[pIdx].end());
                leftBuffer.push_back(0x00);
                reconstructedGgmTree[leftChildFlatIdx] = CryptoEngine::sha256(leftBuffer);
                ggmNodePopulated[leftChildFlatIdx] = true;
            }
            if (!ggmNodePopulated[rightChildFlatIdx]) {
                std::vector<Byte> rightBuffer(reconstructedGgmTree[pIdx].begin(), reconstructedGgmTree[pIdx].end());
                rightBuffer.push_back(0x01);
                reconstructedGgmTree[rightChildFlatIdx] = CryptoEngine::sha256(rightBuffer);
                ggmNodePopulated[rightChildFlatIdx] = true;
            }
        }
    }

    // Step 5: Evaluate base cascade leaf nodes and place them into the lowest layer tier.
    for (Index k : expectedOpenIndices) {
        const auto& chunk = topologicalRoadmap[k];
        Hash contextBlock = {};

        if (chunk.rank < C) {
            if (floorPenaltyIdx >= proof.floorHashStubs.size()) { return false; }
            contextBlock = proof.floorHashStubs[floorPenaltyIdx++];
        } else {
            std::size_t targetLeafFlatIdx = leavesStartOffset + k;
            contextBlock = reconstructedGgmTree[targetLeafFlatIdx];
        }

        std::size_t flatLeafIdx = leavesStartOffset + k;
        fullMerkleTreeArray[flatLeafIdx] = reconstructCascadeLeaf(b0Super, k, contextBlock, chunk.rank);
        merkleNodePopulated[flatLeafIdx] = true;
    }

    // Step 6: Fold tree layers bottom-up to complete the full Merkle validation path.
    for (int lvl = static_cast<int>(D) - 1; lvl >= 0; --lvl) {
        std::size_t nodesInLvl = 1ULL << lvl;
        for (std::size_t i = 0; i < nodesInLvl; ++i) {
            std::size_t pIdx = (1ULL << lvl) - 1 + i;
            std::size_t leftChildIdx = (1ULL << (lvl + 1)) - 1 + (i * 2);
            std::size_t rightChildIdx = leftChildIdx + 1;

            if (merkleNodePopulated[leftChildIdx] || merkleNodePopulated[rightChildIdx]) {
                fullMerkleTreeArray[pIdx] = CryptoEngine::sha256Nodes(fullMerkleTreeArray[leftChildIdx], fullMerkleTreeArray[rightChildIdx]);
                merkleNodePopulated[pIdx] = true;
            }
        }
    }

    // Step 7: Check index zero of the fully folded tree structure to validate the root.
    if (fullMerkleTreeArray[0] != root) { 
        return false; 
    }
    return true;
}

} // namespace BatchDeniableCommitment

