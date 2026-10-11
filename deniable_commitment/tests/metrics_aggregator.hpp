// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef METRICS_AGGREGATOR_HPP
#define METRICS_AGGREGATOR_HPP

#include "common_structures.hpp"
#include "proof_data.hpp"
#include <vector>

namespace DeniableCommitment {
namespace Diagnostics {

// Metrics for honest protocol operations tracking candidate pool capacity and execution profiles.
struct ExecutionMetrics {
    std::size_t candidatePoolLength;
    std::size_t selectionLength;
    double commitmentGenTimeUs;
    double proofGenTimeUs;
    double verificationTimeUs;
    std::size_t proofSizeBytes;
    bool isAccepted;
};

// Metrics for adversarial simulation runs mapping bit-distortion weights and rejection pass rates.
struct AdversarialMetrics {
    std::size_t bitFlipCount;
    std::size_t passedChecksNaive;
    bool naiveAccepted;
    bool octopusAccepted;
};

class MetricsAggregator {
public:
    // Prints a single seed performance report for both baseline and tree-pruned variants.
    static void printSeedReport(std::uint32_t seed, const ExecutionMetrics& naive, const ExecutionMetrics& octopus);

    // Prints granular diagnostic metrics for individual simulated active forgery attempts.
    static void printAdversarialReport(const AdversarialMetrics& adv);

    // Computes and outputs final performance, timing, and compression averages for honest profiles.
    static void printFinalSummary(const std::vector<ExecutionMetrics>& naiveRuns, const std::vector<ExecutionMetrics>& octopusRuns);
    
    // Aggregates pipeline, benchmark, and security consensus data into a centralized verdict dashboard.
    static void printGlobalConsensusSummary(const std::vector<ExecutionMetrics>& naiveRuns,
                                            const std::vector<ExecutionMetrics>& octopusRuns,
                                            const std::vector<AdversarialMetrics>& fraudRecords,
                                            bool pipelinePassed = true);
};

} // namespace Diagnostics
} // namespace DeniableCommitment

#endif // METRICS_AGGREGATOR_HPP

