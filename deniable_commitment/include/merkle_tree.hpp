// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef MERKLE_TREE_HPP
#define MERKLE_TREE_HPP

#include "common_structures.hpp"

namespace DeniableCommitment {

// 1-BASED BINARY HEAP TOPOLOGY LAYOUT SPECIFICATION:
// To achieve O(1) coordinate math, the tree uses a standard binary heap memory map.
//   - Element 0 is permanently left empty as a padding offset.
//   - Element 1 contains the root node (the global PublicCommitment).
//   - Elements 2 through 1023 contain intermediate layer parent branch hashes.
//   - Elements 1024 through 2047 store the 1,024 leaf hashes generated from the bitstream bits and masks.
// Total memory allocation space is bounded at exactly 2 * 1024 = 2048 elements.
constexpr std::size_t MerkleTreeNodesCount = 2 * BitstreamLength;

// Represents a typesafe level-relative coordinate token within the binary tree topology
struct MtIndex {
    std::size_t level;         // Vertical tree depth placement layer (0 = Root ... 10 = Leaves)
    std::size_t indexAtLevel;  // Horizontal stream array offset index position within the active layer row

    // O(1) coordinate math yielding a token pointing to the direct Parent node
    constexpr MtIndex getParent() const noexcept {
        return MtIndex{ level - 1, indexAtLevel / 2 };
    }

    // O(1) coordinate math yielding a token pointing to the Left Child node
    constexpr MtIndex getLeftChild() const noexcept {
        return MtIndex{ level + 1, indexAtLevel * 2 };
    }

    // O(1) coordinate math yielding a token pointing to the Right Child node
    constexpr MtIndex getRightChild() const noexcept {
        return MtIndex{ level + 1, (indexAtLevel * 2) + 1 };
    }

    // O(1) coordinate math yielding a token pointing to the Sibling node counterpart
    constexpr MtIndex getSibling() const noexcept {
        return MtIndex{ level, indexAtLevel ^ 1 };
    }

    // Generates a coordinate token mapping a local logical leaf offset to the active bottom level
    static constexpr MtIndex fromLeafIndex(std::size_t leafIndex) noexcept {
        return MtIndex{ LeafExponent, leafIndex };
    }
};

// Encapsulated Merkle Tree exposing level-relative continuous hash streams via coordinate tokens
class MerkleTree {
public:
    MerkleTree() {
        m_nodes.fill(Hash{});
    }

    // Static Factory Method: Construct a tree directly from BitstreamLength pre-computed leaf hashes
    static MerkleTree build(const std::array<Hash, BitstreamLength>& leafHashes);

    // Returns the total quantity of levels within the cryptographic structure
    static constexpr std::size_t getLevelCount() noexcept {
        return LeafExponent + 1; // 11 levels total: index 0 (Root) through index 10 (Leaves)
    }

    // Returns the total number of hash nodes contained across a specific level layer
    // Expresses nodes counts natively in terms of the global BitstreamLength definition
    static constexpr std::size_t getNodeCountAtLevel(std::size_t level) noexcept {
        if (level >= LeafExponent) {
            return BitstreamLength; // Bounded directly to N = 1024 cells for level 10
        }
        // Moves upwards from the leaf layer using our depth distance metric
        return BitstreamLength >> (LeafExponent - level);
    }

    // Accesses the unique Public Commitment root hash sitting at Level 0 (Index 1)
    const Hash& getRoot() const noexcept {
        return m_nodes[1]; // Reference to the dedicated root index position 1
    }

    // Safe read access to a continuous array position using a coordinate token
    const Hash& getNode(const MtIndex& coord) const noexcept {
        return m_nodes[(1ULL << coord.level) + coord.indexAtLevel];
    }

    // Safe write access used to assign node records inside localized coordinate token boundaries
    void setNode(const MtIndex& coord, const Hash& hashVal) noexcept {
        m_nodes[(1ULL << coord.level) + coord.indexAtLevel] = hashVal;
    }

private:
    std::array<Hash, MerkleTreeNodesCount> m_nodes; // The raw pointerless memory layout is completely hidden
};

} // namespace DeniableCommitment

#endif // MERKLE_TREE_HPP

