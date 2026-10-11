// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef COMMON_PROCEDURES_HPP
#define COMMON_PROCEDURES_HPP

#include "common_structures.hpp"
#include <vector>

namespace BatchDeniableCommitment {
namespace CryptoEngine {

    // Core Cryptographic Primitive Engine Wrapper Functions

    // Computes a standard 256-bit SHA-256 digest over a raw byte buffer.
    // Argument 'buffer' handles the heap-allocated contiguous input context.
    // Returns a completed 32-byte cryptographic hash token array.
    Hash sha256(const std::vector<Byte>& buffer);

    // High-performance concatenation hashing utility for internal tree nodes.
    // Accepts references to the left and right sibling 32-byte tree digests.
    // Returns the combined 32-byte joint parent digest output token.
    Hash sha256Nodes(const Hash& leftNode, const Hash& rightNode);

    // Expands a single 256-bit private scalar into a track-aligned stream.
    // Argument 'inputSecret' accepts the base private 32-byte scalar seed block.
    // Returns a stream vector filled with exactly W bits on the heap.
    TrackBits expandScalar(const Scalar& inputSecret);

} // namespace CryptoEngine
} // namespace BatchDeniableCommitment

#endif // COMMON_PROCEDURES_HPP

