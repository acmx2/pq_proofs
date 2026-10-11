/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "prover.hpp"
#include "common_procedures.hpp"
#include "io_helper.hpp"
#include "challenge_builder.hpp"
#include <algorithm>
#include <set>
#include <vector>

namespace BatchDeniableCommitment {

void Prover::deriveGgmMasks(const Scalar& rootKey, std::vector<Scalar>& masksOut) {
    // Step 1: Allocate a complete binary tree vector buffer containing (2 * LeafCount) - 1 nodes.
    std::vector<Scalar> tempTree((2 * LeafCount) - 1);
    tempTree[0] = rootKey; 

    // Step 2: Traverse internal layers top-down, splitting parent nodes via domain-separated hashing.
    for (std::size_t lvl = 0; lvl < D; ++lvl) {
        std::size_t nodesInLvl = 1ULL << lvl;
        std::size_t currentLvlOffset = nodesInLvl - 1;
        std::size_t nextLvlOffset = (1ULL << (lvl + 1)) - 1;

        for (std::size_t i = 0; i < nodesInLvl; ++i) {
            std::size_t parentFlatIdx = currentLvlOffset + i;
            std::size_t leftChildFlatIdx = nextLvlOffset + (i * 2);
            std::size_t rightChildFlatIdx = leftChildFlatIdx + 1;

            std::vector<Byte> leftBuffer(tempTree[parentFlatIdx].begin(), tempTree[parentFlatIdx].end());
            leftBuffer.push_back(0x00);
            tempTree[leftChildFlatIdx] = CryptoEngine::sha256(leftBuffer);

            std::vector<Byte> rightBuffer(tempTree[parentFlatIdx].begin(), tempTree[parentFlatIdx].end());
            rightBuffer.push_back(0x01);
            tempTree[rightChildFlatIdx] = CryptoEngine::sha256(rightBuffer);
        }
    }

    // Step 3: Copy the computed bottom-tier layer nodes directly into the output leaf masks vector.
    std::size_t leavesStartOffset = LeafCount - 1;
    for (std::size_t i = 0; i < LeafCount; ++i) {
        masksOut[i] = tempTree[leavesStartOffset + i];
    }
}

Hash Prover::evaluateCascadeLeaf(const SuperArray& superArray, std::size_t chunkIdx, const Scalar& mask) {
    // Step 1: Fetch the isolated immutable view from the encapsulated container interface.
    ChunkView chunk = superArray.getChunk(chunkIdx);

    // Step 2: Initialize Floor 1 using the chunk view bits mapped safely.
    std::vector<Byte> buffer(C + 32); 
    std::copy(chunk.bits.begin(), chunk.bits.end(), buffer.begin());
    std::copy(mask.begin(), mask.end(), buffer.begin() + C);
    Hash currentHash = CryptoEngine::sha256(buffer);

    // Step 3: Run the downward cascade floors using signed boundary protection.
    for (int numBits = static_cast<int>(C) - 1; numBits >= 1; --numBits) {
        std::vector<Byte> innerBuffer(static_cast<std::size_t>(numBits) + 32);
        std::copy_n(chunk.bits.begin(), static_cast<std::size_t>(numBits), innerBuffer.begin());
        std::copy(currentHash.begin(), currentHash.end(), innerBuffer.begin() + static_cast<std::size_t>(numBits));
        currentHash = CryptoEngine::sha256(innerBuffer);
    }

    // Step 4: Return the finished Floor 5 base leaf hash token.
    return currentHash;
}

std::pair<PublicCommitment, PrivateCommitmentFullData> Prover::generateCommitment(const BatchScalars& secretScalars, const Scalar& ggmRootKey) {
    PrivateCommitmentFullData fullData;
    fullData.secretScalars = secretScalars;
    fullData.ggmRootKey = ggmRootKey;
    fullData.derivedMasks.resize(LeafCount);

    // Step 1: Expand each private secret scalar track independently into a flat bitstream on the heap.
    std::vector<TrackBits> individualTracks(V);
    for (std::size_t i = 0; i < V; ++i) {
        individualTracks[i] = CryptoEngine::expandScalar(secretScalars[i]);
    }

    // Step 2: Mix the parallel tracks obliviously to build the global super-array B.
    fullData.superArrayB = SuperArray::mixTracks(individualTracks);
    deriveGgmMasks(ggmRootKey, fullData.derivedMasks);

    // Step 3: Pass data segments through nested prefix cascade loops to bind leaf hashes.
    std::vector<Hash> leafHashes(LeafCount);
    for (std::size_t k = 0; k < LeafCount; ++k) {
        leafHashes[k] = evaluateCascadeLeaf(fullData.superArrayB, k, fullData.derivedMasks[k]);
    }

    // Step 4: Construct the balanced Merkle tree over the leaves and extract the root commitment.
    fullData.commitmentTree = MerkleTree::build(leafHashes);
    return std::make_pair(fullData.commitmentTree.getRoot(), fullData);
}

ProofPayload Prover::genProof(const PrivateCommitmentFullData& fullData, const BatchRings& presentationRings) {
    ProofPayload payload;

    // Step 1: Reconstruct the public mixed tracks out of the submitted ring scalars.
    std::vector<TrackBits> tracksB0(V), tracksB1(V);
    for (std::size_t i = 0; i < V; ++i) {
        tracksB0[i] = CryptoEngine::expandScalar(presentationRings[i].first);
        tracksB1[i] = CryptoEngine::expandScalar(presentationRings[i].second);
    }

    SuperArray b0Super = SuperArray::mixTracks(tracksB0);
    SuperArray b1Super = SuperArray::mixTracks(tracksB1);
    SuperArray xorSuper = b0Super.computeXor(b1Super);
    
    // Step 2: Generate the candidate pool and execute the selection engine.
    std::vector<Index> candidatePool = ChallengeBuilder::buildCandidatePool(xorSuper);
    std::vector<Index> openIndices = ChallengeBuilder::runSelectionEngine(candidatePool, xorSuper);

    std::sort(openIndices.begin(), openIndices.end());

    // Step 3: Pre-generate the definitive hierarchical layout roadmap using IoHelper.
    std::vector<ChunkMarkup> topologicalRoadmap = IoHelper::generateTopologicalMarkup(openIndices, xorSuper);

    // Step 4: Fully re-derive internal GGM tree coordinates on the heap to fetch compressed parent fragments.
    std::vector<Scalar> tempGgmTree((2 * LeafCount) - 1);
    tempGgmTree[0] = fullData.ggmRootKey;
    for (std::size_t lvl = 0; lvl < D; ++lvl) {
        std::size_t nodesInLvl = 1ULL << lvl;
        std::size_t currOffset = nodesInLvl - 1;
        std::size_t nextOffset = (1ULL << (lvl + 1)) - 1;
        for (std::size_t i = 0; i < nodesInLvl; ++i) {
            std::size_t pIdx = currOffset + i;
            std::vector<Byte> lBuf(tempGgmTree[pIdx].begin(), tempGgmTree[pIdx].end()); lBuf.push_back(0x00);
            tempGgmTree[nextOffset + (i * 2)] = CryptoEngine::sha256(lBuf);
            std::vector<Byte> rBuf(tempGgmTree[pIdx].begin(), tempGgmTree[pIdx].end()); rBuf.push_back(0x01);
            tempGgmTree[nextOffset + (i * 2) + 1] = CryptoEngine::sha256(rBuf);
        }
    }

    // Step 5: Run a single linear pass over all leaf markers to pack data into payload vectors.
    for (std::size_t k = 0; k < LeafCount; ++k) {
        const auto& chunk = topologicalRoadmap[k];

        if (chunk.isSelected) {
            // Case 5.1: Selected chunk underflows a complete block prefix (Rank < C). Push the floor penalty stub hash.
            if (chunk.rank < C) {
                ChunkView chunkData = fullData.superArrayB.getChunk(k);
                
                std::vector<Byte> buffer(C + 32);
                std::copy(chunkData.bits.begin(), chunkData.bits.end(), buffer.begin());
                std::copy(fullData.derivedMasks[k].begin(), fullData.derivedMasks[k].end(), buffer.begin() + C);
                Hash currentHash = CryptoEngine::sha256(buffer);

                const std::size_t loopLimit = (C - 1) - chunk.rank;
                for (std::size_t i = 0; i < loopLimit; ++i) {
                    const std::size_t numBits = (C - 1) - i;
                    std::vector<Byte> innerBuffer(numBits + 32);
                    std::copy_n(chunkData.bits.begin(), numBits, innerBuffer.begin());
                    std::copy(currentHash.begin(), currentHash.end(), innerBuffer.begin() + numBits);
                    currentHash = CryptoEngine::sha256(innerBuffer);
                }
                payload.floorHashStubs.push_back(currentHash);
            } else {
                // Case 5.2: Selected chunk matches completely (Rank == C). Send the compressed GGM root key fragment if flagged.
                if (chunk.isGgmSubRootRevealed) {
                    std::size_t flatGgmIdx = (1ULL << chunk.ggmSubRootLocation.level) - 1 + chunk.ggmSubRootLocation.nodeIndex;
                    payload.revealedGgmKeys.push_back(tempGgmTree[flatGgmIdx]);
                }
            }
        } else {
            // Case 5.3: Unselected chunk. Harvest and write the companion subtree sibling hash if flagged.
            if (chunk.isMerkleStubRevealed) {
                payload.prunedMerkleHashes.push_back(fullData.commitmentTree.getNode(TreeIndex{ chunk.merkleSubRootLocation.level, chunk.merkleSubRootLocation.nodeIndex }));
            }
        }
    }

    // Step 6: Return the completed, optimized proof transmission bundle.
    return payload;
}

} // namespace BatchDeniableCommitment

