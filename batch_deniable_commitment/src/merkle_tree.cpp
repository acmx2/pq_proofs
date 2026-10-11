/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "merkle_tree.hpp"
#include "common_procedures.hpp"
#include <cassert>

namespace BatchDeniableCommitment {

MerkleTree MerkleTree::build(const std::vector<Hash>& leavesList) {
    // Step 1: Assert that the leaves pool matches the strict compile-time parameter constraint LeafCount.
    assert(leavesList.size() == LeafCount && "MerkleTree Error: Leaves count mismatch.");
    MerkleTree tree;

    // Step 2: Allocate a complete flat binary array pool on the heap containing (2 * LeafCount) - 1 nodes.
    std::size_t totalNodesCount = (2 * LeafCount) - 1;
    tree.m_nodesBuffer.resize(totalNodesCount);

    // Step 3: Copy the computed leaf hashes into the bottom-tier index slots of the array buffer.
    std::size_t leavesStartOffset = LeafCount - 1;
    for (std::size_t i = 0; i < LeafCount; ++i) {
        tree.m_nodesBuffer[leavesStartOffset + i] = leavesList[i];
    }

    // Step 4: Fold tree layers bottom-up sequentially, hashing sibling node elements pairs together.
    for (int lvl = static_cast<int>(D) - 1; lvl >= 0; --lvl) {
        std::size_t nodesInLvl = 1ULL << lvl;
        std::size_t currentLvlOffset = nodesInLvl - 1;
        std::size_t nextLvlOffset = (1ULL << (lvl + 1)) - 1;

        for (std::size_t i = 0; i < nodesInLvl; ++i) {
            std::size_t parentFlatIdx = currentLvlOffset + i;
            std::size_t leftChildFlatIdx = nextLvlOffset + (i * 2);
            std::size_t rightChildFlatIdx = leftChildFlatIdx + 1;

            tree.m_nodesBuffer[parentFlatIdx] = CryptoEngine::sha256Nodes(
                tree.m_nodesBuffer[leftChildFlatIdx],
                tree.m_nodesBuffer[rightChildFlatIdx]
            );
        }
    }

    // Step 5: Return the fully constructed, complete static Merkle tree object container.
    return tree;
}

MerkleTree MerkleTree::build(const std::array<Hash, LeafCount>& leavesArray) {
    // Step 1: Convert the incoming raw static array reference into a standard vector instance.
    std::vector<Hash> leavesVector(leavesArray.begin(), leavesArray.end());

    // Step 2: Forward to the primary vector construction engine handler.
    return build(leavesVector);
}

Hash MerkleTree::getNode(const TreeIndex& token) const {
    // Step 1: Map the coordinate token (level, index) directly into its exact flat memory position.
    std::size_t flatOffset = (1ULL << token.level) - 1 + token.index;

    // Step 2: Verify that the mapped offset sits safely inside the allocation pool spectrum boundaries.
    assert(flatOffset < m_nodesBuffer.size() && "MerkleTree lookup out of bounds.");

    // Step 3: Return the specific node hash requested.
    return m_nodesBuffer[flatOffset];
}

Hash MerkleTree::getRoot() const {
    // Step 1: Return the master commitment signature digest located at index position zero.
    return m_nodesBuffer[0];
}

} // namespace BatchDeniableCommitment

