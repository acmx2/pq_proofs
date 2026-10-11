/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "io_helper.hpp"
#include <algorithm>

namespace BatchDeniableCommitment {

std::vector<ChunkMarkup> IoHelper::generateTopologicalMarkup(const std::vector<Index>& expectedOpenIndices, const SuperArray& xorSuper) {
    // Step 1: Allocate a complete, linear sequence array containing 2^D chunk markers on the heap.
    std::vector<ChunkMarkup> markupVector(LeafCount);

    // Step 2: Establish the basic selection configurations for all explicitly opened indices.
    for (Index k : expectedOpenIndices) {
        markupVector[k].isSelected = true;
        markupVector[k].rank = xorSuper.getChunk(k).rank;
        if (markupVector[k].rank == C) {
            markupVector[k].isGgmLeaf = true; // Perfect match requires full GGM key material.
        }
    }

    // Step 3: Run top-down tree simulation loops to compute GGM node key compression markers.
    std::vector<bool> ggmLayerMarks(LeafCount, false);
    for (std::size_t i = 0; i < LeafCount; ++i) { ggmLayerMarks[i] = markupVector[i].isGgmLeaf; }

    std::vector<std::vector<bool>> ggmRevealBitmaps(D + 1);
    for (std::size_t lvl = 0; lvl <= D; ++lvl) { ggmRevealBitmaps[lvl].resize(1ULL << lvl, false); }

    for (int lvl = static_cast<int>(D); lvl > 0; --lvl) {
        std::size_t nodesInLvl = 1ULL << lvl;
        std::vector<bool> nextGgmLayerMarks(nodesInLvl / 2, false);
        for (std::size_t i = 0; i < nodesInLvl; i += 2) {
            bool leftNeeded = ggmLayerMarks[i];
            bool rightNeeded = ggmLayerMarks[i + 1];
            if (leftNeeded && rightNeeded) {
                nextGgmLayerMarks[i / 2] = true; // Subtree completed: collapse upward.
            } else {
                if (leftNeeded)  { ggmRevealBitmaps[static_cast<std::size_t>(lvl)][i] = true; }
                if (rightNeeded) { ggmRevealBitmaps[static_cast<std::size_t>(lvl)][i + 1] = true; }
                nextGgmLayerMarks[i / 2] = false;
            }
        }
        ggmLayerMarks = nextGgmLayerMarks;
    }
    if (!ggmLayerMarks.empty() && ggmLayerMarks[0]) { ggmRevealBitmaps[0][0] = true; }

    // Step 4: Map GGM root coordinates back to unselected blocks for single-pass wire emissions.
    for (std::size_t i = 0; i < LeafCount; ++i) {
        if (!markupVector[i].isGgmLeaf) continue;
        std::size_t currIdx = i;
        for (int lvl = static_cast<int>(D); lvl >= 0; --lvl) {
            if (ggmRevealBitmaps[static_cast<std::size_t>(lvl)][currIdx]) {
                markupVector[i].ggmSubRootLocation = NodeTreeLocation{ static_cast<std::size_t>(lvl), currIdx };
                std::size_t leftmostLeafBound = currIdx * (1ULL << (D - static_cast<std::size_t>(lvl)));
                if (i == leftmostLeafBound) { markupVector[i].isGgmSubRootRevealed = true; }
                break;
            }
            currIdx /= 2;
            if (lvl == 0) break;
        }
    }

    // Step 5: Run bottom-up tree parsing loops to flag Merkle path companion stubs.
    std::vector<bool> merkleLayerMarks(LeafCount, false);
    for (Index k : expectedOpenIndices) { merkleLayerMarks[k] = true; }

    std::vector<std::vector<bool>> merkleRevealBitmaps(D + 1);
    for (std::size_t lvl = 0; lvl <= D; ++lvl) { merkleRevealBitmaps[lvl].resize(1ULL << lvl, false); }

    for (int lvl = static_cast<int>(D); lvl > 0; --lvl) {
        std::size_t nodesInLayer = 1ULL << lvl;
        std::vector<bool> nextLayerMarks(nodesInLayer / 2, false);
        for (std::size_t i = 0; i < nodesInLayer; i += 2) {
            bool leftOpen = merkleLayerMarks[i];
            bool rightOpen = merkleLayerMarks[i + 1];
            if (leftOpen && !rightOpen) {
                merkleRevealBitmaps[static_cast<std::size_t>(lvl)][i + 1] = true;
            } else if (!leftOpen && rightOpen) {
                merkleRevealBitmaps[static_cast<std::size_t>(lvl)][i] = true;
            }
            nextLayerMarks[i / 2] = (leftOpen || rightOpen);
        }
        merkleLayerMarks = nextLayerMarks;
    }

    // Step 6: Save marks back into unselected markup elements to finalize the wire framework.
    for (std::size_t i = 0; i < LeafCount; ++i) {
        if (markupVector[i].isSelected) continue;
        std::size_t currIdx = i;
        for (int lvl = static_cast<int>(D); lvl > 0; --lvl) {
            if (merkleRevealBitmaps[static_cast<std::size_t>(lvl)][currIdx]) {
                markupVector[i].merkleSubRootLocation = NodeTreeLocation{ static_cast<std::size_t>(lvl), currIdx };
                std::size_t leftmostLeafBound = currIdx * (1ULL << (D - static_cast<std::size_t>(lvl)));
                if (i == leftmostLeafBound) { markupVector[i].isMerkleStubRevealed = true; }
                break;
            }
            currIdx /= 2;
        }
    }

    // Step 7: Return the completed, linear topological structural roadmap layout.
    return markupVector;
}

} // namespace BatchDeniableCommitment
