// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef OTS_COMMON_HPP
#define OTS_COMMON_HPP

#include "common_structures.hpp"
#include "proof_data.hpp"
#include "prover.hpp"
#include <array>
#include <vector>

namespace OtSignature {

using Byte = std::uint8_t;
using Index = std::size_t;

using Scalar512 = std::array<Byte, 64>;
using Hash512   = std::array<Byte, 64>;

using BdcScalar               = BatchDeniableCommitment::Scalar;
using BdcHash                 = BatchDeniableCommitment::Hash;
using BdcPublicCommitment     = BatchDeniableCommitment::PublicCommitment;
using BdcProofPayload         = BatchDeniableCommitment::ProofPayload;
using BdcBatchScalars         = BatchDeniableCommitment::BatchScalars;
using BdcBatchRings           = BatchDeniableCommitment::BatchRings;
using BdcPrivateCommitmentData = BatchDeniableCommitment::PrivateCommitmentFullData;

constexpr std::size_t V = BatchDeniableCommitment::V;

} // namespace OtSignature

#endif // OTS_COMMON_HPP

