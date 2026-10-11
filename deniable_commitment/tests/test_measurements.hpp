// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef TEST_MEASUREMENTS_HPP
#define TEST_MEASUREMENTS_HPP

#include "common_structures.hpp"
#include "metrics_aggregator.hpp"
#include <vector>

namespace DeniableCommitment {
namespace TestSubSuite {

// Staging configuration preset defining individual PRNG iteration environments.
struct SeedConfiguration {
    std::uint32_t committedScalarSeed; 
    std::uint32_t proverMasksSeed;     
    std::uint32_t arbitraryScalarSeed; 
    const char* environmentProfile;
};

// Drives the sequential benchmark execution across all 32 hardcoded profile variations.
void runMeasurementsBenchmark(std::vector<Diagnostics::ExecutionMetrics>& naiveOut, 
                              std::vector<Diagnostics::ExecutionMetrics>& octopusOut, 
                              std::vector<Scalar>& generatedScalarsOut);

} // namespace TestSubSuite
} // namespace DeniableCommitment

#endif // TEST_MEASUREMENTS_HPP

