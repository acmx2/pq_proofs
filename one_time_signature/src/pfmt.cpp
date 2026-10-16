// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "pfmt.hpp"
#include "ots_procedures.hpp" 
#include <stdexcept>

namespace OtSignature {

void PartiallyFixedMerkleTree::initialize(const Scalar512& trs, std::size_t parameterV) {
    m_V = parameterV;
    m_rootRt = {};
    m_bitpathTBP.clear();
    m_SL.clear();
    m_SR.clear();
    m_expansionPairs.clear();

    m_SL.resize(m_V, std::nullopt);
    m_SR.resize(m_V, std::nullopt);
    m_expansionPairs.resize(m_V);

    for (std::size_t i = 0; i < m_V; ++i) {
        std::vector<Byte> leftBuffer;
        leftBuffer.reserve(64 + 1 + sizeof(i));
        leftBuffer.insert(leftBuffer.end(), trs.begin(), trs.end());
        leftBuffer.push_back('L');
        const Byte* iBytes = reinterpret_cast<const Byte*>(&i);
        leftBuffer.insert(leftBuffer.end(), iBytes, iBytes + sizeof(i));
        m_expansionPairs[i].first = CryptoEngine::sha512(leftBuffer);

        std::vector<Byte> rightBuffer;
        rightBuffer.reserve(64 + 1 + sizeof(i));
        rightBuffer.insert(rightBuffer.end(), trs.begin(), trs.end());
        rightBuffer.push_back('R');
        rightBuffer.insert(rightBuffer.end(), iBytes, iBytes + sizeof(i));
        m_expansionPairs[i].second = CryptoEngine::sha512(rightBuffer);
    }

    std::vector<Byte> rootBuffer;
    rootBuffer.reserve(128);
    rootBuffer.insert(rootBuffer.end(), m_expansionPairs[m_V - 1].first.begin(), m_expansionPairs[m_V - 1].first.end());
    rootBuffer.insert(rootBuffer.end(), m_expansionPairs[m_V - 1].second.begin(), m_expansionPairs[m_V - 1].second.end());
    m_rootRt = CryptoEngine::sha512(rootBuffer);

    m_bitpathTBP.resize(m_V - 1, 0);

    for (std::size_t i = 1; i < m_V; ++i) {
        std::vector<Byte> prevConcatBuffer;
        prevConcatBuffer.reserve(128);
        prevConcatBuffer.insert(prevConcatBuffer.end(), m_expansionPairs[i - 1].first.begin(), m_expansionPairs[i - 1].first.end());
        prevConcatBuffer.insert(prevConcatBuffer.end(), m_expansionPairs[i - 1].second.begin(), m_expansionPairs[i - 1].second.end());
        Hash512 prevLevelHash = CryptoEngine::sha512(prevConcatBuffer);

        Byte pathBit = m_bitpathTBP[i - 1];
        Scalar512 chosenE = (pathBit == 0) ? m_expansionPairs[i].first : m_expansionPairs[i].second;
        Scalar512 delta = CryptoEngine::computeXor512(chosenE, prevLevelHash);

        if (pathBit == 0) {
            m_SL[i] = delta;
        } else {
            m_SR[i] = delta;
        }
    }
}

void PartiallyFixedMerkleTree::incorporateSecret(const Scalar512& tsi, Byte coinFlipB0) {
    if (m_bitpathTBP.size() != m_V - 1) {
        throw std::runtime_error("PFMT Error: Module initialization missing.");
    }
    m_bitpathTBP.insert(m_bitpathTBP.begin(), coinFlipB0);

    Scalar512 chosenE0 = (coinFlipB0 == 0) ? m_expansionPairs[0].first : m_expansionPairs[0].second;
    Scalar512 delta0 = CryptoEngine::computeXor512(chosenE0, tsi);

    if (coinFlipB0 == 0) {
        m_SL[0] = delta0;
    } else {
        m_SR[0] = delta0;
    }
}

std::vector<std::pair<Scalar512, Scalar512>> PartiallyFixedMerkleTree::populateAndFold(const std::vector<Scalar512>& leafRing) {
    if (leafRing.size() != (static_cast<std::size_t>(1) << m_V)) {
        throw std::runtime_error("PFMT Error: Input vector dimension bounds mismatch.");
    }
    std::vector<Hash512> currentLayerNodes = leafRing;

    for (std::size_t i = 0; i < m_V; ++i) {
        std::size_t pathIndex = 0;
        for (std::size_t b = 0; b <= i; ++b) {
            pathIndex |= (static_cast<std::size_t>(m_bitpathTBP[b]) << b);
        }
        std::size_t siblingIndex = pathIndex ^ 1;
        Hash512 companionNode = currentLayerNodes[siblingIndex];

        Byte pathBit = m_bitpathTBP[i];
        Scalar512 companionE = (pathBit == 0) ? m_expansionPairs[i].second : m_expansionPairs[i].first;
        Scalar512 companionDelta = CryptoEngine::computeXor512(companionE, companionNode);

        if (pathBit == 0) {
            m_SR[i] = companionDelta;
        } else {
            m_SL[i] = companionDelta;
        }

        std::size_t nextLayerSize = currentLayerNodes.size() / 2;
        std::vector<Hash512> nextLayerNodes(nextLayerSize);
        for (std::size_t j = 0; j < nextLayerSize; ++j) {
            std::vector<Byte> concatBuffer;
            concatBuffer.reserve(128);

            Scalar512 leftMaskedNode = CryptoEngine::computeXor512(currentLayerNodes[2 * j], m_SL[i].value());
            Scalar512 rightMaskedNode = CryptoEngine::computeXor512(currentLayerNodes[2 * j + 1], m_SR[i].value());

            concatBuffer.insert(concatBuffer.end(), leftMaskedNode.begin(), leftMaskedNode.end());
            concatBuffer.insert(concatBuffer.end(), rightMaskedNode.begin(), rightMaskedNode.end());
            nextLayerNodes[j] = CryptoEngine::sha512(concatBuffer);
        }
        currentLayerNodes = std::move(nextLayerNodes);
    }

    std::vector<std::pair<Scalar512, Scalar512>> sigSLR(m_V);
    for (std::size_t i = 0; i < m_V; ++i) {
        sigSLR[i].first = m_SL[i].value();
        sigSLR[i].second = m_SR[i].value();
    }
    return sigSLR;
}

Hash512 PartiallyFixedMerkleTree::getRoot() const { return m_rootRt; }
std::vector<Byte> PartiallyFixedMerkleTree::getBitPath() const { return m_bitpathTBP; }
std::vector<std::optional<Scalar512>> PartiallyFixedMerkleTree::getSecretLeft() const { return m_SL; }
std::vector<std::optional<Scalar512>> PartiallyFixedMerkleTree::getSecretRight() const { return m_SR; }

} // namespace OtSignature

