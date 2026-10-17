// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef COMMON_STRUCTURES_HPP
#define COMMON_STRUCTURES_HPP

#include <array>
#include <vector>
#include <cstdint>

namespace BatchDeniableCommitment {

// Global Compile-Time Topological Parameters & Strategy Macro Switch
#define SELECTIONENGINE(pool, xorMap) runSelectionEngine(pool, xorMap)

constexpr std::size_t V = 4;           // Number of parallel scalar pairs (V in [4 ... 20])
constexpr std::size_t D = 15;           // Target balanced binary tree depth (14 or 15)
constexpr std::size_t C = 9;            // Count of lower leaf-cascade floors

// Secondary computed global variables derived directly from configuration coefficients
constexpr std::size_t LeafCount = 1ULL << D; // Total number of leaf positions (2^D)
constexpr std::size_t N = LeafCount * C;     // Aggregate combined global bit footprint (2^D * C)
constexpr std::size_t W = N / V;             // Length of an individual horizontal bit track vector

// Core primitive scalar type definitions
using Byte = std::uint8_t;
using Index = std::size_t;
using Rank = std::size_t;

using Scalar = std::array<Byte, 32>;
using Hash = std::array<Byte, 32>;

using BatchScalars = std::array<Scalar, V>; 
using BatchRings = std::array<std::pair<Scalar, Scalar>, V>;

using TrackBits = std::vector<Byte>;
using PublicCommitment = Hash;

} // namespace BatchDeniableCommitment

#endif // COMMON_STRUCTURES_HPP

