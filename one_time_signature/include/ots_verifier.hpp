// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef OTS_VERIFIER_HPP
#define OTS_VERIFIER_HPP

#include "ots_common.hpp"
#include "signature_data.hpp"
#include <vector>

namespace OtSignature {

class Verifier {
public:
    static bool verify(
        const PublicRing& ringIn, 
        const Scalar512& message, 
        const Signature& sig, 
        std::size_t parameterV = V
    );
};

} // namespace OtSignature

#endif // OTS_VERIFIER_HPP

