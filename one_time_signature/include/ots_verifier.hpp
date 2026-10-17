// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef OTS_VERIFIER_HPP
#define OTS_VERIFIER_HPP

#include "ots_common.hpp"
#include "signature_data.hpp"
#include <vector>

namespace OtSignature {

// The Verifier class exposes the public entry point for validating ring signatures.
// It coordinates the two-phase zero-knowledge verification routine, ensuring that
// the signature packet holds a valid multi-proof link to the public ring commitments
// and collapses to the correct pre-calculated tree root commitment anchor.
class Verifier {
public:
    // Technical Specification Section 5: Public Ring Signature Verification.
    // This routine takes the unlinked public keys ring, the dynamic 
    // message payload context, and the transmitted signature package.
    // It returns true if Verifier accepts (all zero-knowledge and structural equations 
    // pass perfectly), otherwise false.
    static bool verify(
        const PublicRing& ringIn, 
        const Scalar512& message, 
        const Signature& sig, 
        std::size_t parameterV = V
    );
};

} // namespace OtSignature

#endif // OTS_VERIFIER_HPP

