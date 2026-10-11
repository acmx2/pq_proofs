// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef TEST_FRAUD_HPP
#define TEST_FRAUD_HPP

#include "common_structures.hpp"
#include "metrics_aggregator.hpp"
#include <vector>

namespace DeniableCommitment {
namespace TestSubSuite {

// Runs adversarial manipulation simulations across defined threat vectors, 
// printing the global aggregated systems pass verdicts summary panel.
void runAdversarialFraudSuite(const std::vector<Scalar>& generatedScalars,
                              const std::vector<Diagnostics::ExecutionMetrics>& naiveMetrics,
                              const std::vector<Diagnostics::ExecutionMetrics>& octopusMetrics,
                              bool pipelinePassed);

} // namespace TestSubSuite
} // namespace DeniableCommitment

#endif // TEST_FRAUD_HPP

