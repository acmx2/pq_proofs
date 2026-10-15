// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef PFMT_HPP
#define PFMT_HPP

#include "ots_common.hpp"
#include <optional>
#include <vector>
#include <utility>

namespace OtSignature {

class PartiallyFixedMerkleTree {
public:
    PartiallyFixedMerkleTree() = default;
    ~PartiallyFixedMerkleTree() = default;

    void initialize(const Scalar512& trs, std::size_t parameterV);
    void incorporateSecret(const Scalar512& tsi, Byte coinFlipB0);
    std::vector<std::pair<Scalar512, Scalar512>> populateAndFold(const std::vector<Scalar512>& leafRing);

    Hash512 getRoot() const;
    std::vector<Byte> getBitPath() const;
    std::vector<std::optional<Scalar512>> getSecretLeft() const;
    std::vector<std::optional<Scalar512>> getSecretRight() const;

private:
    std::size_t m_V = 0;
    Hash512 m_rootRt = {};
    std::vector<Byte> m_bitpathTBP;
    std::vector<std::optional<Scalar512>> m_SL; 
    std::vector<std::optional<Scalar512>> m_SR; 
    std::vector<std::pair<Scalar512, Scalar512>> m_expansionPairs; 
};

} // namespace OtSignature

#endif // PFMT_HPP

