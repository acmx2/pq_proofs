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

// Core byte-level cryptographic type definitions.
// Every basic element in this scheme operates on 512-bit blocks (64 bytes),
// aligning with the output size of the SHA-512 hashing algorithm.
using Byte = std::uint8_t;
using Index = std::size_t;

using Scalar512 = std::array<Byte, 64>;
using Hash512   = std::array<Byte, 64>;

// Explicit alias mapping from the Batch Deniable Commitment Suite (BDCS) namespace, which is Scalar256-based.
// These types bridge the one-time signature layout with the multi-proof commitment tree.
using BdcScalar               = BatchDeniableCommitment::Scalar;
using BdcHash                 = BatchDeniableCommitment::Hash;
using BdcPublicCommitment     = BatchDeniableCommitment::PublicCommitment;
using BdcProofPayload         = BatchDeniableCommitment::ProofPayload;
using BdcBatchScalars         = BatchDeniableCommitment::BatchScalars;
using BdcBatchRings           = BatchDeniableCommitment::BatchRings;
using BdcPrivateCommitmentData = BatchDeniableCommitment::PrivateCommitmentFullData;

// Global architectural height invariant constant established by the BDC layer.
// V defines the global maximum number of commitment lanes or steps in the tree,
// as well as the amount of pubkeys in the rings, which is 2^V - 1.
constexpr std::size_t V = BatchDeniableCommitment::V;

} // namespace OtSignature

#endif // OTS_COMMON_HPP

