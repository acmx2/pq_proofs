// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef SIGNER_HPP
#define SIGNER_HPP

#include "ots_common.hpp"
#include "signature_data.hpp"
#include <vector>
#include <utility>

namespace OtSignature {

class Signer {
public:
    static std::pair<PublicKey, PrivateKeyFullData> generatePublicKey(const PrivateKey& sk, std::size_t parameterV = V);

    static Signature sign(
        const PrivateKeyFullData& fullData, 
        const PublicRing& ringIn, 
        const Scalar512& message, 
        std::size_t parameterV = V
    );
};

} // namespace OtSignature

#endif // SIGNER_HPP

