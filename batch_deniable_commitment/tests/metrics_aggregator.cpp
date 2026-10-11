/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "metrics_aggregator.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>

namespace BatchDeniableCommitment {
namespace Diagnostics {

namespace {
    std::string formatLevelTag(std::size_t lvl) {
        std::string tag = std::to_string(lvl);
        if (lvl == 0) tag += "-Rt";
        else if (lvl == D) tag += "-Lf";
        return tag;
    }
}

void MetricsAggregator::printMetricsDashboard(const TrackedMetrics& metrics) {
    // Step 1: Compute absolute payload bytes weights.
    const std::size_t totalPayloadBytes = metrics.proofSizeGgmBytes + metrics.proofSizeMerkleBytes + metrics.proofSizeStubBytes;
    
    // Step 2: Calculate the theoretical average weight distributed per track lane.
    double bytesPerTrack = static_cast<double>(totalPayloadBytes) / static_cast<double>(V);
    double kbPerTrack = bytesPerTrack / 1024.0;

    // Step 3: Print the global scheme header specifications panel.
    std::cout << "\n------------------------------------------------------------------------------------------------------------------------\n";
    std::cout << "   Batch Deniable Commitment Scheme Execution Profile Summary [Constants: V=" << V << ", D=" << D << " (Leaves: " << LeafCount << "), N=" << N << ", W=" << W << ", C=" << C << "]\n";
    std::cout << "------------------------------------------------------------------------------------------------------------------------\n";
    
    // Step 4: Render consolidated execution timelines and profiles.
    std::cout << "    PROFILES:   Init: " << std::fixed << std::setprecision(1) << metrics.commitmentGenerationTimeUs << "us | Prove: " << metrics.provingTimeUs 
              << "us | Verify: " << metrics.verificationTimeUs << "us\n";
    std::cout << "    FOOTPRINTS: GGM: " << metrics.proofSizeGgmBytes << "B | Merkle: " << metrics.proofSizeMerkleBytes 
              << "B | Stubs: " << metrics.proofSizeStubBytes << "B\n";
              
    std::cout << "    EFFICIENCY: Total: " << totalPayloadBytes << "B (" << std::fixed << std::setprecision(1) << (static_cast<double>(totalPayloadBytes)/1024.0) 
              << "KB)  |  " << std::fixed << std::setprecision(1) << kbPerTrack << "KB per track  |  " 
              << std::fixed << std::setprecision(2) << metrics.averageSpendBytesPerBit << " bytes/bit spent per opened security bit\n";
    
    // Step 5: Render status summaries and leaf configurations.
    std::cout << "------------------------------------------------------------------------------------------------------------------------\n";
    std::cout << "    STATUS:     Total levels with 0 companion stubs: " << metrics.fullyPopulatedMerkleLevelsCount << "  |  Verification Confirmation: " 
              << (metrics.passStatus ? "PASSED (Consensus matches)" : "FAILED (Structural mismatch)") << "\n";
    std::cout << "    LEAF LAYER (" << formatLevelTag(D) << ") STATUS: Opened Leaves: " << metrics.openedLeavesAtLeafLevelCount 
              << " | Companion Leaf Hashes: " << metrics.companionHashesAtLeafLevelCount << "\n";
    std::cout << "------------------------------------------------------------------------------------------------------------------------\n";

    // Step 6: Compile side-by-side distribution data vectors text strings.
    std::vector<std::string> col1Lines;
    col1Lines.push_back("RANK DISTRIBUTION:");
    for (int r = static_cast<int>(C); r >= 0; --r) {
        Rank currentRank = static_cast<Rank>(r);
        std::size_t count = metrics.rankDistribution.count(currentRank) ? metrics.rankDistribution.at(currentRank) : 0;
        col1Lines.push_back("  rank" + std::to_string(r) + ": " + std::to_string(count));
    }

    std::vector<std::string> col2Lines;
    col2Lines.push_back("MERKLE STUBS DISTRIBUTION:");
    std::size_t totalWireCompanionHashes = 0;
    for (const auto& pair : metrics.merkleCompanionHashesPerLevel) { totalWireCompanionHashes += pair.second; }
    
    bool hasMerkle = false;
    for (std::size_t lvl = 0; lvl <= D; ++lvl) {
        std::size_t countAtLvl = metrics.merkleCompanionHashesPerLevel.count(lvl) ? metrics.merkleCompanionHashesPerLevel.at(lvl) : 0;
        if (countAtLvl > 0) {
            double percentage = totalWireCompanionHashes > 0 ? (static_cast<double>(countAtLvl) / static_cast<double>(totalWireCompanionHashes)) * 100.0 : 0.0;
            std::stringstream ss;
            ss << "  Lvl " << formatLevelTag(lvl) << ": " << countAtLvl << " (" << std::fixed << std::setprecision(1) << percentage << "%)";
            col2Lines.push_back(ss.str());
            hasMerkle = true;
        }
    }
    if (!hasMerkle) { col2Lines.push_back("  (None outside Leaf layer)"); }

    std::vector<std::string> col3Lines;
    col3Lines.push_back("GGM KEYS DISTRIBUTION:");
    bool hasGgm = false;
    for (std::size_t lvl = 0; lvl <= D; ++lvl) {
        std::size_t countGgmAtLvl = metrics.ggmKeysPerLevel.count(lvl) ? metrics.ggmKeysPerLevel.at(lvl) : 0;
        if (countGgmAtLvl > 0) {
            col3Lines.push_back("  Lvl " + formatLevelTag(lvl) + ": " + std::to_string(countGgmAtLvl));
            hasGgm = true;
        }
    }
    if (!hasGgm) { col3Lines.push_back("  (No compressed keys on wire)"); }

    // Step 7: Format and render text columns side-by-side.
    std::size_t maxRows = std::max({col1Lines.size(), col2Lines.size(), col3Lines.size()});
    for (std::size_t i = 0; i < maxRows; ++i) {
        std::string c1 = (i < col1Lines.size()) ? col1Lines[i] : "";
        std::string c2 = (i < col2Lines.size()) ? col2Lines[i] : "";
        std::string c3 = (i < col3Lines.size()) ? col3Lines[i] : "";

        std::cout << "    " << std::left << std::setw(30) << c1 
                  << " | " << std::setw(38) << c2 
                  << " | " << c3 << "\n";
    }

    // Step 8: Render the bottom-anchored, balanced track entropy bits count report.
    std::cout << "------------------------------------------------------------------------------------------------------------------------\n";
    std::cout << "    ACTUALLY OPENED TRACK BITS COUNTS:\n";
    
    std::size_t midPoint = metrics.openedBitsPerTrack.size() / 2;
    std::cout << "      -> ";
    for (std::size_t i = 0; i < midPoint; ++i) {
        std::cout << "T" << std::setw(2) << i << ":" << std::setw(3) << metrics.openedBitsPerTrack[i] << (i < midPoint - 1 ? "  |  " : "");
    }
    std::cout << "\n      -> ";
    for (std::size_t i = midPoint; i < metrics.openedBitsPerTrack.size(); ++i) {
        std::cout << "T" << std::setw(2) << i << ":" << std::setw(3) << metrics.openedBitsPerTrack[i] << (i < metrics.openedBitsPerTrack.size() - 1 ? "  |  " : "");
    }
    std::cout << "\n------------------------------------------------------------------------------------------------------------------------\n";
}

} // namespace Diagnostics
} // namespace BatchDeniableCommitment

