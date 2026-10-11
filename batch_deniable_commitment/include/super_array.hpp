// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef SUPER_ARRAY_HPP
#define SUPER_ARRAY_HPP

#include "common_structures.hpp"
#include <vector>

namespace BatchDeniableCommitment {

// A lightweight, clean read-only slice representing an isolated immutable chunk.
// Attached directly to leaf evaluation boundaries to secure total data immutability.
struct ChunkView {
    Index index = 0;               // Global coordinate index k of this chunk (0 to LeafCount - 1).
    Rank rank = 0;                 // Pre-calculated leading zero rank (0 to C) evaluated on retrieval.
    const std::vector<Byte> bits;  // Declared as const to enforce absolute data immutability.
};

class SuperArray {
public:
    // Default constructor initializing an empty buffer matching parameter length N.
    SuperArray();

    // Static factory constructor handling oblivious orthogonal interleave track mixing.
    // Accepts a vector holding exactly V parallel heap-allocated bit streams.
    // Returns the combined mixed global SuperArray container object.
    static SuperArray mixTracks(const std::vector<TrackBits>& parallelTracks);

    // Identifies which horizontal private track lane owns a specific global bit coordinate.
    // Argument 'globalBitIdx' specifies the target absolute bit offset inside the super-array.
    // Returns the track index (0 to V-1) mapping lane ownership rules.
    std::size_t getTrackIndexForBit(Index globalBitIdx) const;

    // Converts a global bit position into its local bit index offset inside its owning track.
    // Argument 'globalBitIdx' specifies the target absolute bit offset inside the super-array.
    // Returns the local track bit index coordinate (0 to W-1).
    std::size_t getLocalBitOffsetForBit(Index globalBitIdx) const;

    // Object-oriented point-wise XOR distance intersection mapping function.
    // Accepts a complementary public bit super-array to evaluate against.
    // Returns the completed distance matrix result container object.
    SuperArray computeXor(const SuperArray& other) const;

    // Slices out a standalone, read-only view of a specific chunk carrying its pre-evaluated rank.
    // Argument 'chunkIdx' identifies the target leaf chunk index offset k.
    // Returns a clean immutable ChunkView block object view.
    ChunkView getChunk(Index chunkIdx) const;

    // Returns the total count of C-bit chunks managed by the matrix layout.
    // Strictly returns the LeafCount value parameter (2^D).
    std::size_t getChunkCount() const;

    // Strictly preserved ONLY the const read-only accessor to protect encapsulation immutability.
    Byte operator[](Index globalBitIdx) const;

    // Returns the total aggregate bit capacity width of the storage pool.
    std::size_t size() const;

    // Provides direct reference access to the underlying vector for rapid hashing passes.
    const std::vector<Byte>& getStorage() const;

private:
    // Explicit private helper method to compute the leading-zero prefix rank of a chunk slice.
    // Argument 'startBit' specifies the starting bit position of the targeted block.
    // Returns the count of leading consecutive zeros up to the chunk threshold limit C.
    Rank calculateChunkRank(std::size_t startBit) const;

    std::vector<Byte> m_bits; // Main heap-allocated flat bit matrix storage pool.
};

} // namespace BatchDeniableCommitment

#endif // SUPER_ARRAY_HPP

