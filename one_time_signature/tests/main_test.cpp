// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "ots_common.hpp"
#include "pfmt.hpp"
#include <iostream>
#include <vector>

int main() {
    std::cout << "=== Running OTS Fixed Pipeline Pass ===" << std::endl;
    OtSignature::Scalar512 privateSeed{};
    OtSignature::Scalar512 secretIdentity{};

    privateSeed.fill(0xAA);
    secretIdentity.fill(0xBB);

    constexpr std::size_t targetTreeHeight = OtSignature::V;
    OtSignature::PartiallyFixedMerkleTree pfmtEngine;
    pfmtEngine.initialize(privateSeed, targetTreeHeight);
    pfmtEngine.incorporateSecret(secretIdentity, 1);

    constexpr std::size_t computedLeafCount = (1ULL << targetTreeHeight);
    std::vector<OtSignature::Scalar512> leafRing(computedLeafCount);
    for (std::size_t i = 0; i < computedLeafCount; ++i) {
        leafRing[i].fill(static_cast<OtSignature::Byte>(i & 0xFF));
    }

    auto generatedSLR = pfmtEngine.populateAndFold(leafRing);
    std::cout << "Generated vector pairs count: " << generatedSLR.size() << std::endl;
    std::cout << "=== Build Pass Succeeded ===" << std::endl;
    return 0;
}
