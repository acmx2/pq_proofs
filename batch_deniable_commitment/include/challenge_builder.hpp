// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef CHALLENGE_BUILDER_HPP
#define CHALLENGE_BUILDER_HPP

#include "common_structures.hpp"
#include "super_array.hpp"
#include "proof_data.hpp"
#include <vector>
#include <set>

namespace BatchDeniableCommitment {

// Purpose: Multi-Phase Selection Engine that extracts an optimal set of candidate leaf
// chunks from the zero-knowledge distance matrix. Balances local cluster density against
// global wire footprint stubs, while satisfying track-wise security floors.
class ChallengeBuilder {
public:
    // Scans all chunk slots sequentially, extracting non-zero candidate indices from the mixed map.
    static std::vector<Index> buildCandidatePool(const SuperArray& xorSuper);

    // Drives the multi-phase greedy optimization pipeline over the candidate index workspace.
    static std::vector<Index> runSelectionEngine(const std::vector<Index>& candidatePool, 
                                                 const SuperArray& xorSuper);

private:
    // The quota ceiling coefficient used to terminate Phase 1/Phase 2 primary optimizations early.
    static constexpr std::size_t BaseEntropyQuotaPerTrack = 124; 

    // Dedicated structural subroutines to maintain clean, modular compilation blocks.

    // Phase 1a Sweep: Sweeps and harvests free twins whose sibling paths are already paid for.
    static bool executePhase1aTwinArbitrage(const std::vector<Index>& candidatePool,
                                            const std::set<Index>& activeSelections,
                                            const std::vector<Rank>& poolRanks,
                                            Index& bestIdx, Rank& bestRank);

    // Phase 1 Scorer: Heuristically maps multi-scale macro and micro sub-tree cluster densities.
    static double evaluatePhase1Score(Index k,
                                      const std::set<Index>& activeSelections,
                                      const std::vector<Rank>& poolRanks);

    // Phase 2 Scorer: Evaluates the marginal information gain per byte of physical structural splitting.
    static double evaluatePhase2Score(Index k,
                                      const std::vector<bool>& treeHasMerkleSelections,
                                      const std::vector<bool>& treeHasGgmSelections,
                                      const std::vector<Rank>& poolRanks);

    // Post-Processing Safeguard: Enforces the strict 128-bit safety threshold across all parallel lanes.
    static void enforceTrackSafetySafeguard(const std::vector<Index>& candidatePool,
                                            const std::vector<Rank>& poolRanks,
                                            const SuperArray& xorSuper,
                                            std::set<Index>& activeSelections,
                                            std::vector<Index>& selectedIndicesList,
                                            std::vector<std::size_t>& trackBitsCounter);
};

} // namespace BatchDeniableCommitment

#endif // CHALLENGE_BUILDER_HPP

