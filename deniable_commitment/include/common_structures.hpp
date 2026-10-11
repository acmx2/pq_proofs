// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef COMMON_STRUCTURES_HPP
#define COMMON_STRUCTURES_HPP

#include <array>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <utility>

namespace DeniableCommitment {

// Protocol parameters derived directly from the technical specification
constexpr std::size_t LeafExponent = 10;                     // Exponent determining tree depth (10 levels, Section 1.3)
constexpr std::size_t BitstreamLength = 1ULL << LeafExponent; // Total bit count length N = 2^10 = 1024 bits (Section 1.1)
constexpr std::size_t ChallengeLength = 128;                 // Fixed quantity of spot-check indices opened (Section 2.3)

// Primitive domain-specific type mapping aliases
using Index = std::size_t;      // Represents structural buffer indexing positions or absolute coordinates
using Byte  = std::uint8_t;     // Raw single byte fundamental memory block unit
using UnpackedBit = Byte;       // A bit value expanded into a full byte (0x00 or 0x01) for fast local processing loops
using Hash  = std::array<Byte, 32>;  // Fixed 256-bit digest container matching standard SHA-256 outputs
using Scalar = std::array<Byte, 32>; // Fixed 256-bit primitive block representing secret inputs or masking salts

// Symmetric verification ring containing two unprioritized 256-bit scalar inputs
using Ring = std::pair<Scalar, Scalar>; 

// Uniform matching pairs for packed network transmission vs unpacked processing domains
using Bitstream         = std::array<Byte, BitstreamLength / 8>;         // 1024 bits packed tightly into 128 bytes
using UnpackedBitstream = std::array<UnpackedBit, BitstreamLength>;      // 1024 unpacked bytes for fast cell lookups

using OpenBitsBlock         = std::array<Byte, ChallengeLength / 8>;     // 128 open spot-check bits packed into 16 bytes
using UnpackedOpenBitsBlock = std::array<UnpackedBit, ChallengeLength>;  // 128 unpacked bytes matching challenge steps

} // namespace DeniableCommitment

#endif // COMMON_STRUCTURES_HPP

