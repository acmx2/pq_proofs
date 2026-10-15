// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef OTS_PROCEDURES_HPP
#define OTS_PROCEDURES_HPP

#include "ots_common.hpp"
#include "common_procedures.hpp"
#include <vector>

namespace OtSignature {
namespace CryptoEngine {

    Hash512 sha512(const std::vector<Byte>& buffer);
    Scalar512 computeXor512(const Scalar512& a, const Scalar512& b);

} // namespace CryptoEngine
} // namespace OtSignature

#endif // OTS_PROCEDURES_HPP

