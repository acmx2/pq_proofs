// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "pfmt.hpp"
#include "ots_procedures.hpp" 
#include <stdexcept>

namespace OtSignature {

namespace {
    // Technical Specification Section 2.2:
    // Formulates a domain-separated character flag buffer to derive deterministic stream paths.
    // Concatenates: Tracking Seed (64 bytes) || Side Flag ('L' or 'R') || Level Index (size_t bytes).
    std::vector<Byte> createEntranceLabelBuffer(const Scalar512& trs, char sideLabel, std::size_t layerIdx) {
        // Initialize output stream with tracking root seed contents.
        std::vector<Byte> buffer(trs.begin(), trs.end());
        
        // Push directional identifier byte element onto trailing edge slot.
        buffer.push_back(static_cast<Byte>(sideLabel));
        
        // Isolate memory structure address context parameters for index conversion tracking.
        const Byte* idxBytes = reinterpret_cast<const Byte*>(&layerIdx);
        
        // Append explicit layer index byte stream block array properties.
        buffer.insert(buffer.end(), idxBytes, idxBytes + sizeof(layerIdx));
        
        return buffer;
    }
} // namespace

void PartiallyFixedMerkleTree::initialize(const Scalar512& trs, std::size_t parameterV) {
    // -------------------------------------------------------------------------
    // STEP 1: CONTEXT INITIALIZATION & BUFFER ALLOCATION
    // -------------------------------------------------------------------------
    // Assign the tracking system height scale invariant parameter value.
    m_V = parameterV;
    m_rootRt = {};
    m_bitpathTBP.clear();
    
    // Clear state data slots and resize the sparse collection vectors out to length V.
    m_SL.assign(m_V, std::nullopt);
    m_SR.assign(m_V, std::nullopt);
    m_entrancePairs.resize(m_V);

    // -------------------------------------------------------------------------
    // STEP 2: IMMUTABLE ENTRANCE PAIRS GENERATION (Section 2.2)
    // -------------------------------------------------------------------------
    // Expand the pristine layer-wise entry constants (EL_i, ER_i) using SHA-512.
    // These constants form the immutable mathematical milestones of the scheme.
    for (std::size_t i = 0; i < m_V; ++i) {
        m_entrancePairs[i].first  = CryptoEngine::sha512(createEntranceLabelBuffer(trs, 'L', i));
        m_entrancePairs[i].second = CryptoEngine::sha512(createEntranceLabelBuffer(trs, 'R', i));
    }

    // -------------------------------------------------------------------------
    // STEP 3: TERMINAL IDENTITY ROOT SYNTHESIS (Section 2.3)
    // -------------------------------------------------------------------------
    // Pairwise compress the highest tier entrance constants to compile the root token.
    // This value represents the definitive top-level commitment anchor (Sig.RT).
    std::vector<Byte> rootBuffer;
    rootBuffer.reserve(128);
    rootBuffer.insert(rootBuffer.end(), m_entrancePairs[m_V - 1].first.begin(), m_entrancePairs[m_V - 1].first.end());
    rootBuffer.insert(rootBuffer.end(), m_entrancePairs[m_V - 1].second.begin(), m_entrancePairs[m_V - 1].second.end());
    m_rootRt = CryptoEngine::sha512(rootBuffer);

    // -------------------------------------------------------------------------
    // STEP 4: PRE-COMPUTATION BASELINE TRACKING PASS
    // -------------------------------------------------------------------------
    // Initialize the default tracking bitpath trajectory array mapping.
    m_bitpathTBP.assign(m_V - 1, 0);

    // Run the bottom-up pre-calculation loop to extract unassigned delta masks.
    // For every level from 1 to V-1, we look up the preceding level's compiled parent,
    // subtract it from the active entrance token using bitwise XOR, and cache the delta.
    for (std::size_t i = 1; i < m_V; ++i) {
        std::vector<Byte> prevLayerBuffer;
        prevLayerBuffer.reserve(128);
        prevLayerBuffer.insert(prevLayerBuffer.end(), m_entrancePairs[i - 1].first.begin(), m_entrancePairs[i - 1].first.end());
        prevLayerBuffer.insert(prevLayerBuffer.end(), m_entrancePairs[i - 1].second.begin(), m_entrancePairs[i - 1].second.end());
        Hash512 prevLevelHash = CryptoEngine::sha512(prevLayerBuffer);

        Byte pathBit = m_bitpathTBP[i - 1];
        Scalar512 chosenEntrance = (pathBit == 0) ? m_entrancePairs[i].first : m_entrancePairs[i].second;
        Scalar512 delta = CryptoEngine::computeXor512(chosenEntrance, prevLevelHash);

        if (pathBit == 0) m_SL[i] = delta;
        else              m_SR[i] = delta;
    }
}

void PartiallyFixedMerkleTree::incorporateSecret(const Scalar512& tsi, Byte coinFlipB0) {
    // -------------------------------------------------------------------------
    // STEP 1: INITIALIZATION BOUNDARY CHECKS
    // -------------------------------------------------------------------------
    if (m_bitpathTBP.size() != m_V - 1) {
        throw std::runtime_error("PFMT Error: Incomplete module setup context.");
    }
    
    // -------------------------------------------------------------------------
    // STEP 2: TRAJECTORY COIN-FLIP BIT INGESTION
    // -------------------------------------------------------------------------
    m_bitpathTBP.insert(m_bitpathTBP.begin(), coinFlipB0);

    // -------------------------------------------------------------------------
    // STEP 3: BASE LAYER DELTA COMPUTATION
    // -------------------------------------------------------------------------
    // Calculate the level-0 delta parameter by masking the secret scalar behind the entry constant.
    // Formula: Delta_0 = Entrance_0 XOR SecretScalar (TSI = SKP)
    Scalar512 chosenEntrance0 = (coinFlipB0 == 0) ? m_entrancePairs[0].first : m_entrancePairs[0].second;
    Scalar512 delta0 = CryptoEngine::computeXor512(chosenEntrance0, tsi);

    if (coinFlipB0 == 0) m_SL[0] = delta0;
    else                 m_SR[0] = delta0;
}

std::vector<std::pair<Scalar512, Scalar512>> PartiallyFixedMerkleTree::populateAndFold(const std::vector<Scalar512>& leafRing) {
    // -------------------------------------------------------------------------
    // STEP 1: DIMENSIONAL BOUNDARY VERIFICATION
    // -------------------------------------------------------------------------
    if (leafRing.size() != (static_cast<std::size_t>(1) << m_V)) {
        throw std::runtime_error("PFMT Error: Dimension invariant parameter failure.");
    }
    std::vector<Hash512> currentLayerNodes = leafRing;

    // -------------------------------------------------------------------------
    // STEP 2: RECURSIVE BOTTOM-UP TRAVERSAL & DELTA EXTRACTION
    // -------------------------------------------------------------------------
    for (std::size_t i = 0; i < m_V; ++i) {
        
        std::size_t pathIndex = 0;
        for (std::size_t b = 0; b <= i; ++b) {
            pathIndex |= (static_cast<std::size_t>(m_bitpathTBP[b]) << b);
        }
        
        std::size_t siblingIndex = pathIndex ^ 1;
        Hash512 companionNode = currentLayerNodes[siblingIndex];

        Byte pathBit = m_bitpathTBP[i];
        Scalar512 companionEntrance = (pathBit == 0) ? m_entrancePairs[i].second : m_entrancePairs[i].first;
        Scalar512 companionDelta = CryptoEngine::computeXor512(companionEntrance, companionNode);

        if (pathBit == 0) m_SR[i] = companionDelta;
        else              m_SL[i] = companionDelta;

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

    // -------------------------------------------------------------------------
    // STEP 3: DENSE EXPORT COMPILATION
    // -------------------------------------------------------------------------
    std::vector<std::pair<Scalar512, Scalar512>> sigSLR(m_V);
    for (std::size_t i = 0; i < m_V; ++i) {
        sigSLR[i].first  = m_SL[i].value();
        sigSLR[i].second = m_SR[i].value();
    }
    return sigSLR;
}

Hash512 PartiallyFixedMerkleTree::getRoot() const { return m_rootRt; }
std::vector<Byte> PartiallyFixedMerkleTree::getBitPath() const { return m_bitpathTBP; }
std::vector<std::optional<Scalar512>> PartiallyFixedMerkleTree::getSecretLeft() const { return m_SL; }
std::vector<std::optional<Scalar512>> PartiallyFixedMerkleTree::getSecretRight() const { return m_SR; }

} // namespace OtSignature

