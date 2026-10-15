// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef OTS_COMMON_HPP
#define OTS_COMMON_HPP

#include "common_structures.hpp"
#include "proof_data.hpp"
#include <array>
#include <vector>
#include <utility>

namespace OtSignature {

using Byte = std::uint8_t;
using Index = std::size_t;

using Scalar512 = std::array<Byte, 64>;
using Hash512   = std::array<Byte, 64>;

// Ambigous context isolation through explicit Bdc prefixes
using BdcScalar           = BatchDeniableCommitment::Scalar;
using BdcHash             = BatchDeniableCommitment::Hash;
using BdcPublicCommitment = BatchDeniableCommitment::PublicCommitment;
using BdcProofPayload     = BatchDeniableCommitment::ProofPayload;
using BdcBatchScalars     = BatchDeniableCommitment::BatchScalars;
using BdcBatchRings       = BatchDeniableCommitment::BatchRings;

constexpr std::size_t V = BatchDeniableCommitment::V;

struct PrivateKey {
    Scalar512 skp;
    Scalar512 trs;
    BdcScalar ggmri;
};

struct PublicKey {
    Scalar512 pk;
};

struct Signature {
    Hash512 rt;
    BdcPublicCommitment mtr;
    std::vector<std::pair<Scalar512, Scalar512>> slr;
    BdcProofPayload bdcp;
};

} // namespace OtSignature

#endif // OTS_COMMON_HPP

