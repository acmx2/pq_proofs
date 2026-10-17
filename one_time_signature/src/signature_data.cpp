// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)


#include "signature_data.hpp"
#include "ots_procedures.hpp"


namespace OtSignature {

Hash512 Signature::getLinkingTag() const {
    std::vector<Byte> concatBuffer;
    concatBuffer.reserve(64 + 32);
    concatBuffer.insert(concatBuffer.end(), rt.begin(), rt.end());
    concatBuffer.insert(concatBuffer.end(), mtr.begin(), mtr.end());
    return CryptoEngine::sha512(concatBuffer);
}

std::size_t PrivateKeyFullData::getSigningIndex() const {
    std::size_t targetIndexSlot = 0;
        
    for (std::size_t b = 0; b < bitpathTBP.size(); ++b) {
        targetIndexSlot |= (static_cast<std::size_t>(bitpathTBP[b]) << b);
    }
    return targetIndexSlot;
}

} // namespace OtSignature
