// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "test_pipeline.hpp"
#include "test_measurements.hpp"
#include "test_fraud.hpp"
#include <vector>
#include <iostream>

using namespace DeniableCommitment;
using namespace DeniableCommitment::TestSubSuite;

// Purpose: Centralized orchestration execution node for sub-suite tests.
int main() {
    bool pipelinePassed = true;
    
    // Step 1: Execute Simple Pipeline Test catch block execution to guarantee safety bounds.
    try {
        runSimplePipelineTest();
    } catch (const std::exception& e) {
        std::cerr << "CRITICAL BREAK: Simple Pipeline Test failed with exception: " << e.what() << "\n";
        pipelinePassed = false;
    } catch (...) {
        std::cerr << "CRITICAL BREAK: Simple Pipeline Test failed with unhandled abort error code.\n";
        pipelinePassed = false;
    }

    // Storage containers allocating performance metric data pools.
    std::vector<Diagnostics::ExecutionMetrics> naiveMetrics;
    std::vector<Diagnostics::ExecutionMetrics> octopusMetrics;
    std::vector<Scalar> activeScalars;

    // Step 2: Run comprehensive performance profiling benchmarks across all hardcoded matrices.
    runMeasurementsBenchmark(naiveMetrics, octopusMetrics, activeScalars);

    // Step 3: Run the adversarial fraud suite to compute global system test summaries.
    runAdversarialFraudSuite(activeScalars, naiveMetrics, octopusMetrics, pipelinePassed);

    return 0;
}

