/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "merkle_tree.hpp"
#include "common_procedures.hpp"

namespace DeniableCommitment {

// Purpose: Generates a complete tree structure by processing leaf hash nodes bottom-up.
// Arguments: leafHashes - array containing exactly 1,024 pre-hashed cell values.
MerkleTree MerkleTree::build(const std::array<Hash, BitstreamLength>& leafHashes) {
    MerkleTree tree;

    // Step 1: Populate the bottom-most layer (Level 10) directly with the leaf hashes.
    for (std::size_t i = 0; i < BitstreamLength; ++i) {
        tree.setNode(MtIndex::fromLeafIndex(i), leafHashes[i]);
    }

    // Step 2: Compute internal parent levels bottom-up from Level 9 down to Level 0 (the Root).
    for (int lvl = static_cast<int>(LeafExponent) - 1; lvl >= 0; --lvl) {
        std::size_t layerCount = MerkleTree::getNodeCountAtLevel(static_cast<std::size_t>(lvl));
        
        // Step 3: Symmetrically combine adjacent left and right children pairs into their parents.
        for (std::size_t i = 0; i < layerCount; ++i) {
            MtIndex current{ static_cast<std::size_t>(lvl), i };
            tree.setNode(current, CryptoEngine::sha256Nodes(
                tree.getNode(current.getLeftChild()),
                tree.getNode(current.getRightChild())
            ));
        }
    }

    // Step 4: Return the structurally complete, fully calculated tree representation.
    return tree;
}

} // namespace DeniableCommitment

