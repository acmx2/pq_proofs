// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef TEST_PIPELINE_HPP
#define TEST_PIPELINE_HPP

namespace DeniableCommitment {
namespace TestSubSuite {

// Runs a validation cycle of the core protocol, verifying that proofs 
// can be built dynamically using only PrivateCommitmentOpeningData witness packages.
void runSimplePipelineTest();

} // namespace TestSubSuite
} // namespace DeniableCommitment

#endif // TEST_PIPELINE_HPP

