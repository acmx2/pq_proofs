// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef COMMON_PROCEDURES_HPP
#define COMMON_PROCEDURES_HPP

#include "common_structures.hpp"
#include "merkle_tree.hpp"
#include <vector>

namespace DeniableCommitment {
namespace CryptoEngine {

// SHA256
Hash sha256(const std::vector<Byte>& byteData);
Hash sha256Leaf(UnpackedBit bit, const Scalar& mask);
Hash sha256Nodes(const Hash& left, const Hash& right);

// Expanding a scalar to Bitstream. This procedure is denoted as E(S) in the specification.
Bitstream expandScalar(const Scalar& scalar);

// Packing and unpacking bits
UnpackedBitstream unpackBitstream(const Bitstream& packedStream);
UnpackedOpenBitsBlock unpackChallengeBits(const OpenBitsBlock& packedBits);
OpenBitsBlock packChallengeBits(const UnpackedOpenBitsBlock& rawBits);

} // namespace CryptoEngine
} // namespace DeniableCommitment

#endif // COMMON_PROCEDURES_HPP

