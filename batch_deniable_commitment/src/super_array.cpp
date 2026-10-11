/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "super_array.hpp"
#include <cassert>
#include <utility>

namespace BatchDeniableCommitment {

// =========================================================================
// 1. CONSTRUCTOR
// =========================================================================
SuperArray::SuperArray() : m_bits(N, 0) {
    // Step 1: Allocate space and initialize the flat bit vector to the absolute global capacity N.
}

// =========================================================================
// 2. STATIC FACTORY CONSTRUCTOR (ORTHOGONAL BIT INTERLEAVING MIXING)
// =========================================================================
SuperArray SuperArray::mixTracks(const std::vector<TrackBits>& parallelTracks) {
    // Step 1: Assert that the incoming track collection size matches the compile-time parameter V.
    assert(parallelTracks.size() == V && "SuperArray Error: Track constraint multiplicity underflow.");
    SuperArray mixedArray;
    
    // Step 2: Traverse each horizontal bit column sequentially up to the track width W.
    std::size_t bitIdx = 0;
    while (bitIdx < W) {
        // Step 3: Interleave bits from each parallel track lane orthogonally into the global stream.
        std::size_t trackIdx = 0;
        while (trackIdx < V) {
            std::size_t destinationOffset = (bitIdx * V) + trackIdx;
            mixedArray.m_bits[destinationOffset] = parallelTracks[trackIdx][bitIdx];
            trackIdx++;
        }
        bitIdx++;
    }

    // Step 4: Return the completed, oblivious global mixed array layout container.
    return mixedArray;
}

// =========================================================================
// 3. METADATA & COORDINATE TRANSLATION ACCESSORS
// =========================================================================
std::size_t SuperArray::getTrackIndexForBit(Index globalBitIdx) const {
    // Step 1: Ensure the requested coordinate falls within the absolute global array spectrum.
    assert(globalBitIdx < N && "SuperArray Error: Global bit coordinate out of bounds.");

    // Step 2: Extract the exact track ownership lane using a direct modulus operation.
    return globalBitIdx % V;
}

std::size_t SuperArray::getLocalBitOffsetForBit(Index globalBitIdx) const {
    // Step 1: Ensure the requested coordinate falls within the absolute global array spectrum.
    assert(globalBitIdx < N && "SuperArray Error: Global bit coordinate out of bounds.");

    // Step 2: Compute the bit offset inside the single isolated track lane.
    return globalBitIdx / V;
}

// =========================================================================
// 4. ALGEBRAIC MATRIX TRANSFORMATIONS
// =========================================================================
SuperArray SuperArray::computeXor(const SuperArray& other) const {
    // Step 1: Verify the memory vectors are identical in width to allow cross-matrix combinations.
    assert(m_bits.size() == other.m_bits.size() && "SuperArray Error: Dimensional intersection mismatch.");
    SuperArray result;

    // Step 2: Execute point-wise XOR filtering across the storage buffers.
    for (std::size_t i = 0; i < m_bits.size(); ++i) {
        result.m_bits[i] = m_bits[i] ^ other.m_bits[i];
    }

    // Step 3: Return the calculated intersection map.
    return result;
}

// =========================================================================
// 5. INTERNAL HOOKS & RANK EVALUATION
// =========================================================================
Rank SuperArray::calculateChunkRank(std::size_t startBit) const {
    std::size_t zeroCount = 0;

    // Step 1: Measure consecutive leading zeroes sequentially up to the chunk capacity threshold C.
    for (std::size_t b = 0; b < C; ++b) {
        if (m_bits[startBit + b] == 0) {
            zeroCount++;
        } else {
            break; // Stop immediately upon hitting the first non-coincident marker bit.
        }
    }

    // Step 2: Return the evaluated prefix leading-zero rank weight value.
    return zeroCount;
}

// =========================================================================
// 6. OBJECT-ORIENTED PIECE-WISE SLICING
// =========================================================================
ChunkView SuperArray::getChunk(Index chunkIdx) const {
    // Step 1: Validate the target chunk offset coordinate sits within the total leaves boundary limit.
    assert(chunkIdx < LeafCount && "SuperArray Error: Chunk coordinate out of bounds.");
    
    // Step 2: Calculate the starting bit mapping offset and slice the raw bits from the storage vector.
    std::size_t startBit = chunkIdx * C;
    std::vector<Byte> slicedBits(C);
    for (std::size_t b = 0; b < C; ++b) {
        slicedBits[b] = m_bits[startBit + b];
    }

    // Step 3: Construct the standalone output view frame.
    ChunkView view;
    view.index = chunkIdx;
    view.rank = calculateChunkRank(startBit);
    
    // Step 4: Transfer ownership of the sliced data vector into the read-only chunk bits container.
    *const_cast<std::vector<Byte>*>(&view.bits) = std::move(slicedBits);

    // Step 5: Return the fully compiled chunk descriptor view block.
    return view;
}

std::size_t SuperArray::getChunkCount() const {
    // Step 1: Return the total available chunks count, matching the baseline leaf nodes multiplier.
    return LeafCount;
}

Byte SuperArray::operator[](Index globalBitIdx) const {
    // Step 1: Guard the lookup offset against raw memory underflow or overflow conditions.
    assert(globalBitIdx < N && "SuperArray Error: Lookup coordinate out of bounds.");

    // Step 2: Return the isolated bit state byte value.
    return m_bits[globalBitIdx];
}

std::size_t SuperArray::size() const {
    // Step 1: Return the total bit capacity managed by the current vector instance.
    return m_bits.size();
}

const std::vector<Byte>& SuperArray::getStorage() const {
    // Step 1: Expose the raw data buffer reference to optimize cryptographic hashing passes.
    return m_bits;
}

} // namespace BatchDeniableCommitment

