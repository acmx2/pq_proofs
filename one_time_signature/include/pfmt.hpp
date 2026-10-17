// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef PFMT_HPP
#define PFMT_HPP

#include "ots_common.hpp"
#include <optional>
#include <vector>
#include <utility>

namespace OtSignature {

// The PartiallyFixedMerkleTree manages the deterministic precomputation framework.
// It uses a private root seed (TRS) to expand level-wise entrance targets. These targets
// are then used to build tracking vectors (SL/SR) that allow recursive bottom-up folding.
class PartiallyFixedMerkleTree {
public:
    PartiallyFixedMerkleTree() = default;
    ~PartiallyFixedMerkleTree() = default;

    // Sets up internal storage buffers and precomputes level-wise entrance nodes.
    void initialize(const Scalar512& trs, std::size_t parameterV);

    // Ingests the private secret signing credential components to initialize the active path.
    void incorporateSecret(const Scalar512& tsi, Byte coinFlipB0);

    // Folds an expanded public leaf ring spectrum layer into a unified parent root.
    std::vector<std::pair<Scalar512, Scalar512>> populateAndFold(const std::vector<Scalar512>& leafRing);

    // Read-only property accessors to extract tree internal variables.
    Hash512 getRoot() const;  // RT
    std::vector<Byte> getBitPath() const;  // TBP
    std::vector<std::optional<Scalar512>> getSecretLeft() const;  // SL
    std::vector<std::optional<Scalar512>> getSecretRight() const; // SR

private:
    std::size_t m_V = 0;
    Hash512 m_rootRt = {}; // RT
    std::vector<Byte> m_bitpathTBP; // TBP
    std::vector<std::optional<Scalar512>> m_SL; // SL 
    std::vector<std::optional<Scalar512>> m_SR; // SR 
    std::vector<std::pair<Scalar512, Scalar512>> m_entrancePairs; // EL/ER 
};

} // namespace OtSignature

#endif // PFMT_HPP

