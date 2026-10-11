// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef METRICS_AGGREGATOR_HPP
#define METRICS_AGGREGATOR_HPP

#include "common_structures.hpp"
#include "proof_data.hpp"
#include <map>
#include <vector>

namespace BatchDeniableCommitment {
namespace Diagnostics {

// Telemetry aggregation block collecting real-time operational constraints metrics.
struct TrackedMetrics {
    double commitmentGenerationTimeUs = 0.0;
    double provingTimeUs = 0.0;
    double verificationTimeUs = 0.0;
    
    std::map<Rank, std::size_t> rankDistribution;
    std::size_t fullyPopulatedMerkleLevelsCount = 0;
    std::size_t openedLeavesAtLeafLevelCount = 0;
    std::size_t companionHashesAtLeafLevelCount = 0;
    
    std::map<std::size_t, std::size_t> merkleCompanionHashesPerLevel;
    std::map<std::size_t, std::size_t> ggmKeysPerLevel;
    
    double averageSpendBytesPerBit = 0.0;
    std::vector<std::size_t> openedBitsPerTrack;
    
    std::size_t proofSizeGgmBytes = 0;
    std::size_t proofSizeMerkleBytes = 0;
    std::size_t proofSizeStubBytes = 0;
    
    bool passStatus = false;
};

class MetricsAggregator {
public:
    // Formats and prints real-time metrics logs side-by-side onto a text summary dashboard.
    // Argument 'metrics' takes the complete recorded TrackedMetrics frame instance.
    static void printMetricsDashboard(const TrackedMetrics& metrics);
};

} // namespace Diagnostics
} // namespace BatchDeniableCommitment

#endif // METRICS_AGGREGATOR_HPP

