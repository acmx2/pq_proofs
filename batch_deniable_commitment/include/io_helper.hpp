// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef IO_HELPER_HPP
#define IO_HELPER_HPP

#include "common_structures.hpp"
#include "super_array.hpp"
#include "proof_data.hpp"
#include <vector>

namespace BatchDeniableCommitment {

// Structural location coordinates descriptor targeting internal nodes inside the tree.
struct NodeTreeLocation {
    std::size_t level = 0;
    std::size_t nodeIndex = 0;
};

// Definitive markup descriptor compiling the topological roadmap properties of a chunk position.
struct ChunkMarkup {
    bool isSelected = false;               // Flag indicating if this chunk index was opened by the builder.
    Rank rank = 0;                         // Copied leading zero prefix rank value.
    bool isGgmLeaf = false;                // Identifies complete matching chunks (Rank == C).
    bool isGgmSubRootRevealed = false;     // High-level anchor flag signaling a top-down GGM key fragment insertion point.
    NodeTreeLocation ggmSubRootLocation;   // Path level and offset tags referencing the compressed GGM sub-root.
    bool isMerkleStubRevealed = false;     // Companion stub flag signaling an unselected bottom-up path hash insertion point.
    NodeTreeLocation merkleSubRootLocation;// Level and offset tags referencing the pruned Merkle tree stub hash node.
};

class IoHelper {
public:
    // Simulates hierarchical layout trees top-down and bottom-up to build the definitive structural roadmap array.
    // Argument 'expectedOpenIndices' takes the sorted list of leaf coordinates chosen by the selector.
    // Argument 'xorSuper' provides the read-only public distance matrix container reference.
    // Returns a unified linear sequence vector mapping markup traits across all 2^D chunk positions.
    static std::vector<ChunkMarkup> generateTopologicalMarkup(
        const std::vector<Index>& expectedOpenIndices, 
        const SuperArray& xorSuper
    );
};

} // namespace BatchDeniableCommitment

#endif // IO_HELPER_HPP

