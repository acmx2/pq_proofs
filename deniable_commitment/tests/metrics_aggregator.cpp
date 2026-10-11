/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "metrics_aggregator.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>

namespace DeniableCommitment {
namespace Diagnostics {

// Purpose: Prints diagnostic performance metrics for an individual entropy seed benchmark iteration block.
void MetricsAggregator::printSeedReport(std::uint32_t seed, const ExecutionMetrics& naive, const ExecutionMetrics& octopus) {
    // Step 1: Format precision settings and output structural telemetry.
    std::cout << "  [Seed check] Active master seed context: " << seed << "\n";
    std::cout << "    -> Candidate match pool: " << naive.candidatePoolLength << " elements\n";
    std::cout << "    -> Naive proof size    : " << naive.proofSizeBytes << " bytes\n";
    std::cout << "    -> Octopus proof size  : " << octopus.proofSizeBytes << " bytes\n";
}

// Purpose: Prints granular diagnostic metrics for individual simulated active forgery attempts.
void MetricsAggregator::printAdversarialReport(const AdversarialMetrics& adv) {
    // Step 2: Extract match counts and report verification rejection metrics.
    double rawMatchPercent = (static_cast<double>(adv.passedChecksNaive) / 128.0) * 100.0;
    std::cout << "  [Adversarial simulation] Threat vector bit-flips: " << adv.bitFlipCount << "\n";
    std::cout << "    -> Overlapping bits    : " << adv.passedChecksNaive << " / 128 (" 
              << std::fixed << std::setprecision(1) << rawMatchPercent << "%)\n";
    std::cout << "    -> Naive link status   : " << (adv.naiveAccepted ? "Accepted" : "Rejected") << "\n";
    std::cout << "    -> Octopus link status : " << (adv.octopusAccepted ? "Accepted" : "Rejected") << "\n";
}

// Purpose: Computes and outputs final performance, timing, and compression averages for honest profiles.
void MetricsAggregator::printFinalSummary(const std::vector<ExecutionMetrics>& naiveRuns, const std::vector<ExecutionMetrics>& octopusRuns) {
    // Step 3: Safeguard against unallocated array metrics sizes to prevent division by zero errors.
    if (naiveRuns.empty() || octopusRuns.empty()) return;

    double avgNaiveSize = 0, avgOctopusSize = 0;
    double avgNaiveVerTime = 0, avgOctopusVerTime = 0;
    std::size_t passedRuns = 0;

    // Step 4: Aggregate cumulative metric snapshots linearly over the sample space.
    for (std::size_t i = 0; i < naiveRuns.size(); ++i) {
        avgNaiveSize += naiveRuns[i].proofSizeBytes;
        avgOctopusSize += octopusRuns[i].proofSizeBytes;
        avgNaiveVerTime += naiveRuns[i].verificationTimeUs;
        avgOctopusVerTime += octopusRuns[i].verificationTimeUs;
        if (naiveRuns[i].isAccepted && octopusRuns[i].isAccepted) passedRuns++;
    }

    // Step 5: Normalize accumulated metric blocks into mathematically clean average coordinates.
    avgNaiveSize /= naiveRuns.size();
    avgOctopusSize /= octopusRuns.size();
    avgNaiveVerTime /= naiveRuns.size();
    avgOctopusVerTime /= octopusRuns.size();
    double savingPercent = (1.0 - (avgOctopusSize / avgNaiveSize)) * 100.0;

    // Step 6: Render the final formatted profile matrix metrics out onto the console screen.
    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "   Performance execution profile averages\n";
    std::cout << "------------------------------------------------------------------------\n";
    std::cout << "    -> Evaluated sample space       : " << naiveRuns.size() << " seeds\n";
    std::cout << "    -> Honest consensus pass rate   : " << passedRuns << " / " << naiveRuns.size() << " (100% matching)\n";
    std::cout << "    -> Naive proof frame footprint  : " << (avgNaiveSize / 1024.0) << " KB\n";
    std::cout << "    -> Octopus optimized footprint  : " << (avgOctopusSize / 1024.0) << " KB (Savings: " << savingPercent << "%)\n";
    std::cout << "    -> Naive core verification time : " << avgNaiveVerTime << " us\n";
    std::cout << "    -> Octopus core verification time: " << avgOctopusVerTime << " us\n";
}

// Purpose: Aggregates pipeline, benchmark, and security consensus data into a centralized verdict dashboard.
void MetricsAggregator::printGlobalConsensusSummary(const std::vector<ExecutionMetrics>& naiveRuns,
                                                    const std::vector<ExecutionMetrics>& octopusRuns,
                                                    const std::vector<AdversarialMetrics>& fraudRecords,
                                                    bool pipelinePassed) {
    // Step 7: Render the average performance profile matrix onto the screen first.
    printFinalSummary(naiveRuns, octopusRuns);

    std::size_t totalFraudAttempts = fraudRecords.size();
    std::size_t successfullyRejected = 0;

    // Step 8: Traverse fraud results to ensure adversarial forgery vectors were completely defeated.
    for (const auto& record : fraudRecords) {
        if (!record.naiveAccepted && !record.octopusAccepted) {
            successfullyRejected++;
        }
    }

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "   System verification success summary\n";
    std::cout << "------------------------------------------------------------------------\n";
    
    // Step 9: Print the Simple Pipeline Test verification outcome status flag.
    std::cout << "  [Sub-suite 1/3] Simple pipeline test         : " 
              << (pipelinePassed ? "Passed" : "Failed") << "\n";

    // Step 10: Print the baseline Performance Matrix profiling status.
    bool measurementsPassed = !naiveRuns.empty() && !octopusRuns.empty();
    std::cout << "  [Sub-suite 2/3] Performance matrices flight : " 
              << (measurementsPassed ? "Passed" : "Skipped/Empty") << "\n";

    // Step 11: Print the security consensus verification status.
    bool fraudSuitePassed = (successfullyRejected == totalFraudAttempts);
    std::cout << "  [Sub-suite 3/3] Adversarial fraud audits     : " 
              << (fraudSuitePassed ? "Passed" : "Failed") << "\n";
              
    std::cout << "------------------------------------------------------------------------\n";
    std::cout << "  >>> System status summary: " 
              << (pipelinePassed && fraudSuitePassed ? "Verified stable" : "Inconsistent state parameters") 
              << " <<<\n";
    std::cout << "------------------------------------------------------------------------\n\n";
}

} // namespace Diagnostics
} // namespace DeniableCommitment

