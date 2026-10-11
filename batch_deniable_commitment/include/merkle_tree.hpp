// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef MERKLE_TREE_HPP
#define MERKLE_TREE_HPP

#include "common_structures.hpp"
#include <vector>
#include <array>

namespace BatchDeniableCommitment {

// Structural indexing coordinate token for clean, explicit tree lookups.
struct TreeIndex {
    std::size_t level;
    std::size_t index;
};

class MerkleTree {
public:
    MerkleTree() = default;

    // Factory compile utility to construct a balanced binary tree framework over a vector array list.
    // Argument 'leavesList' provides a vector containing exactly LeafCount computed base hashes.
    // Returns a completed static MerkleTree instance.
    static MerkleTree build(const std::vector<Hash>& leavesList);

    // Alternative array interface signature forwarding directly to the main construction engine.
    static MerkleTree build(const std::array<Hash, LeafCount>& leavesArray);

    // Extracts an internal node hash value via explicit coordinate lookup tokens.
    // Argument 'token' carries the level and horizontal offset index parameters.
    // Returns the requested 32-byte node hash digest.
    Hash getNode(const TreeIndex& token) const;

    // Returns the absolute root commitment signature digest holding the zero index position.
    Hash getRoot() const;

private:
    std::vector<Hash> m_nodesBuffer; // Flat complete linear tree buffer representation storage array.
};

} // namespace BatchDeniableCommitment

#endif // MERKLE_TREE_HPP

