/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "challenge_builder.hpp"
#include "super_array.hpp"
#include <algorithm>
#include <set>
#include <cmath>
#include <iostream>
#include <vector>
#include <iomanip>

namespace BatchDeniableCommitment {

std::vector<Index> ChallengeBuilder::buildCandidatePool(const SuperArray& xorSuper) {
    // Step 1: Pre-allocate memory capacity to handle the sequential tracking workspace array.
    std::vector<Index> pool;
    pool.reserve(LeafCount); 
    
    // Step 2: Iterate sequentially through every leaf chunk coordinate position inside the tree.
    std::size_t totalChunks = xorSuper.getChunkCount();
    for (Index k = 0; k < totalChunks; ++k) {
        // Step 2.1: Query the chunk views natively from the immutable encapsulation interface layer.
        if (xorSuper.getChunk(k).rank > 0) { 
            // Step 2.2: Extract and retain candidate coordinates if they offer non-zero entropy.
            pool.push_back(k); 
        }
    }

    // Step 3: Return the completed, coordinate-ordered candidate pool array.
    return pool;
}

std::vector<Index> ChallengeBuilder::runSelectionEngine(const std::vector<Index>& candidatePool, const SuperArray& xorSuper) {
    // Step 1: Initialize local trackers to compile selected index layouts.
    std::vector<Index> selectedIndicesList;
    std::set<Index> activeSelections;

    // Step 2: Compute the primary aggregate ceiling quota limits using our private header invariant.
    constexpr std::size_t TargetAggregateQuota = BaseEntropyQuotaPerTrack * V;
    constexpr std::size_t PhaseTransitionThreshold = TargetAggregateQuota / 2; 
    std::size_t accumulatedAggregateBits = 0;

    // Step 3: Allocate presence vectors to track active path fractures instantly.
    std::vector<bool> treeHasMerkleSelections((2 * LeafCount), false);
    std::vector<bool> treeHasGgmSelections((2 * LeafCount), false);

    // Step 4: Pre-map all available pool ranks internally to bypass repeated data view allocations.
    std::vector<Rank> poolRanks(LeafCount, 0);
    for (Index k : candidatePool) { poolRanks[k] = xorSuper.getChunk(k).rank; }

    // Step 5: Execute the main multi-phase greedy lookahead optimization loop.
    while (accumulatedAggregateBits < TargetAggregateQuota) {
        Index bestIdx = 0;
        Rank bestRank = 0;

        // Step 5.1: Execute a Phase 1a Symmetrical Twin arbitrage check.
        if (executePhase1aTwinArbitrage(candidatePool, activeSelections, poolRanks, bestIdx, bestRank)) {
            // Step 5.1.1: If a free twin is found, instantly commit it and update the topology paths.
            activeSelections.insert(bestIdx);
            selectedIndicesList.push_back(bestIdx);
            accumulatedAggregateBits += bestRank;

            std::size_t mCurr = (1ULL << D) - 1 + bestIdx;
            while (mCurr > 0) { treeHasMerkleSelections[mCurr] = true; mCurr = (mCurr - 1) / 2; }
            if (bestRank == C) {
                std::size_t gCurr = (1ULL << D) - 1 + bestIdx;
                while (gCurr > 0) { treeHasGgmSelections[gCurr] = true; gCurr = (gCurr - 1) / 2; }
            }
            continue; // Advance straight to the next selection cycle.
        }

        // Step 5.2: Fallback to evaluating mathematical scores if no free twins remain.
        double maxScore = -1e9;
        bool blockFound = false;
        bool isEmpiricalPhase = (accumulatedAggregateBits < PhaseTransitionThreshold);

        for (Index k : candidatePool) {
            if (activeSelections.count(k)) continue;

            // Step 5.2.1: Interchangably call the specialized subroutines depending on phase boundaries.
            double currentScore = 0.0;
            if (isEmpiricalPhase) {
                currentScore = evaluatePhase1Score(k, activeSelections, poolRanks);
            } else {
                currentScore = evaluatePhase2Score(k, treeHasMerkleSelections, treeHasGgmSelections, poolRanks);
            }

            // Step 5.2.2: Enforce strict coordinate-invariant tie-breaking via the greedy greater-than comparison.
            if (currentScore > maxScore) {
                maxScore = currentScore;
                bestIdx = k;
                bestRank = poolRanks[k];
                blockFound = true;
            }
        }

        // Step 5.3: Halt the engine safely if selection capabilities run entirely dry.
        if (!blockFound) { break; }

        // Step 5.4: Permanently commit the chosen optimal candidate and update ancestral markers.
        activeSelections.insert(bestIdx);
        selectedIndicesList.push_back(bestIdx);
        accumulatedAggregateBits += bestRank;

        std::size_t mCurr = (1ULL << D) - 1 + bestIdx;
        while (mCurr > 0) { treeHasMerkleSelections[mCurr] = true; mCurr = (mCurr - 1) / 2; }
        if (bestRank == C) {
            std::size_t gCurr = (1ULL << D) - 1 + bestIdx;
            while (gCurr > 0) { treeHasGgmSelections[gCurr] = true; gCurr = (gCurr - 1) / 2; }
        }
    }

    // Step 6: Invoke the Post-Processing Safeguard subroutine to guarantee absolute individual track correctness.
    std::vector<std::size_t> trackBitsCounter(V, 0);
    enforceTrackSafetySafeguard(candidatePool, poolRanks, xorSuper, activeSelections, selectedIndicesList, trackBitsCounter);

    // Step 7: Return the complete, optimized selection array list.
    return selectedIndicesList;
}


bool ChallengeBuilder::executePhase1aTwinArbitrage(const std::vector<Index>& candidatePool,
                                                   const std::set<Index>& activeSelections,
                                                   const std::vector<Rank>& poolRanks,
                                                   Index& bestIdx, Rank& bestRank) {
    // Step 1: Scan each candidate block inside the search workspace pool.
    for (Index k : candidatePool) {
        if (activeSelections.count(k)) continue;
        
        // Step 2: Use bitwise XOR to check the state of its immediate binary twin sister leaf.
        Index siblingIdx = k ^ 1;
        if (activeSelections.count(siblingIdx)) {
            // Step 3: If the sister path is active, this node is structurally free. Expose its parameters and return true.
            bestIdx = k;
            bestRank = poolRanks[k];
            return true; 
        }
    }
    
    // Step 4: Return false if no free sibling pairs can be immediately closed out.
    return false;
}

double ChallengeBuilder::evaluatePhase1Score(Index k,
                                             const std::set<Index>& activeSelections,
                                             const std::vector<Rank>& poolRanks) {
    // Step 1: Compute the boundary indices for our macro and micro structural tree windows.
    Index quadIdx = k / 4;
    Index window32Idx = k / 32;

    // Step 2: Compute the aggregate entropy density of the macro-vicinity (Diameter 32).
    std::size_t macroRankSum = 0;
    for (Index i = 0; i < 32; ++i) { macroRankSum += poolRanks[(window32Idx * 32) + i]; }

    // Step 3: Compute the exact rank sum and active count of our micro Quad-Cousin cluster (Diameter 4).
    std::size_t quadRankSum = 0;
    std::size_t openInQuad = 0;
    for (Index i = 0; i < 4; ++i) {
        Index leafIdx = (quadIdx * 4) + i;
        quadRankSum += poolRanks[leafIdx];
        if (activeSelections.count(leafIdx)) openInQuad++;
    }

    // Step 4: Apply the empirical cluster grouping formula.
    double alignmentReward = 1.0 + (static_cast<double>(openInQuad) * 0.65);
    double empiricalScore = (static_cast<double>(quadRankSum) * alignmentReward) + (static_cast<double>(macroRankSum) * 0.15);
    
    // Step 5: Incorporate the individual rank as an invariant tie-breaker multiplier and return the score.
    return empiricalScore + (static_cast<double>(poolRanks[k]) * 0.05);
}

double ChallengeBuilder::evaluatePhase2Score(Index k,
                                             const std::vector<bool>& treeHasMerkleSelections,
                                             const std::vector<bool>& treeHasGgmSelections,
                                             const std::vector<Rank>& poolRanks) {
    // Step 1: Compute flat tree indices for the leaf node position.
    std::size_t leafFlatOffset = (1ULL << D) - 1 + k;
    double deltaMerkleCost = 0.0;
    std::size_t currIdx = leafFlatOffset;
    std::size_t currLvl = D;

    // Step 2: Traverse up-tree path lines to track incremental Merkle companion stubs deltas.
    while (currIdx > 0) {
        std::size_t sibIdx = (currIdx % 2 == 1) ? currIdx + 1 : currIdx - 1;
        if (treeHasMerkleSelections[currIdx]) break; // Path is already split.

        // Apply the Layer-Weighted Fracture Modifier: higher-level fracturing increases penalty.
        double depthWeight = static_cast<double>(D - currLvl + 1);
        if (treeHasMerkleSelections[sibIdx]) {
            deltaMerkleCost -= (1.0 * depthWeight); // Collapsing pair reward.
        } else {
            deltaMerkleCost += (1.5 * depthWeight); // High-level split penalty.
        }
        currIdx = (currIdx - 1) / 2;
        currLvl--;
    }

    // Step 3: Traverse up-tree path lines to track incremental GGM parent keys deltas.
    int deltaGgmKeys = 0;
    if (poolRanks[k] == C) {
        currIdx = leafFlatOffset;
        while (currIdx > 0) {
            std::size_t sibIdx = (currIdx % 2 == 1) ? currIdx + 1 : currIdx - 1;
            if (treeHasGgmSelections[currIdx]) break;
            if (treeHasGgmSelections[sibIdx]) { deltaGgmKeys -= 1; } else { deltaGgmKeys += 1; }
            currIdx = (currIdx - 1) / 2;
        }
    }

    // Step 4: Consolidate cost metrics, accounting for cascade floor stub hash penalties.
    double finalStructuralDeltaCost = deltaMerkleCost + static_cast<double>(deltaGgmKeys);
    double marginalCostValue = (finalStructuralDeltaCost <= 0) ? 0.30 : finalStructuralDeltaCost;

    if (poolRanks[k] < C) {
        marginalCostValue += 1.0; 
    }

    // Step 5: Evaluate the Shannon Information Gain over marginal cost efficiency ratio and return.
    return static_cast<double>(poolRanks[k]) / marginalCostValue;
}


void ChallengeBuilder::enforceTrackSafetySafeguard(const std::vector<Index>& candidatePool,
                                                   const std::vector<Rank>& poolRanks,
                                                   const SuperArray& xorSuper,
                                                   std::set<Index>& activeSelections,
                                                   std::vector<Index>& selectedIndicesList,
                                                   std::vector<std::size_t>& trackBitsCounter) {
    // Step 1: Count the exact number of opened bits currently allocated per horizontal track lane.
    for (Index selIdx : selectedIndicesList) {
        std::size_t bitStartOffset = selIdx * C;
        Rank r = poolRanks[selIdx];
        for (std::size_t b = 0; b < r; ++b) {
            std::size_t targetTrack = xorSuper.getTrackIndexForBit(bitStartOffset + b);
            trackBitsCounter[targetTrack]++;
        }
    }

    // Step 2: Scan each track lane individually, enforcing the strict 128-bit safety ceiling.
    for (std::size_t t = 0; t < V; ++t) {
        while (trackBitsCounter[t] < 128) {
            Index targetRescueIdx = 0;
            Rank targetRescueRank = 0;
            bool rescueChunkFound = false;

            // Step 2.1: Traverse unselected candidates to find blocks that contribute bits to this track.
            for (Index k : candidatePool) {
                if (activeSelections.count(k)) continue;

                std::size_t bitStartOffset = k * C;
                std::size_t hitsForThisTrack = 0;
                Rank r = poolRanks[k];
                for (std::size_t b = 0; b < r; ++b) {
                    if (xorSuper.getTrackIndexForBit(bitStartOffset + b) == t) {
                        hitsForThisTrack++;
                    }
                }

                // Step 2.2: Prioritize the candidate providing maximum rescue bit yield for this specific track.
                if (hitsForThisTrack > 0 && hitsForThisTrack > targetRescueRank) {
                    targetRescueIdx = k;
                    targetRescueRank = r;
                    rescueChunkFound = true;
                }
            }

            // Step 2.3: Break safely if the candidate search space runs entirely dry of bits for this track.
            if (!rescueChunkFound) {
                std::cerr << "        [Critical Safeguard Warning] Candidate pool empty of usable bits for track T" << t << "!\n";
                break;
            }

            // Step 2.4: Commit the rescue chunk and dynamically update lane allocations.
            activeSelections.insert(targetRescueIdx);
            selectedIndicesList.push_back(targetRescueIdx);
            
            std::size_t bitStartOffset = targetRescueIdx * C;
            for (std::size_t b = 0; b < targetRescueRank; ++b) {
                std::size_t targetTrack = xorSuper.getTrackIndexForBit(bitStartOffset + b);
                trackBitsCounter[targetTrack]++;
            }
        }
    }
}

} // namespace BatchDeniableCommitment

