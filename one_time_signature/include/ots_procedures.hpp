// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef OTS_PROCEDURES_HPP
#define OTS_PROCEDURES_HPP

#include "ots_common.hpp"
#include "common_procedures.hpp"
#include <vector>

namespace OtSignature {
namespace CryptoEngine {

    // Evaluates a standard NIST-compliant SHA-512 over an arbitrary byte array.
    Hash512 sha512(const std::vector<Byte>& buffer);

    // Computes bitwise pointwise XOR masking over 512-bit state structures.
    Scalar512 computeXor512(const Scalar512& a, const Scalar512& b);

} // namespace CryptoEngine
} // namespace OtSignature

#endif // OTS_PROCEDURES_HPP

