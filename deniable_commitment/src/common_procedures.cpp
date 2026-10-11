/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "common_procedures.hpp"
#include <algorithm>
#include <iostream>

namespace DeniableCommitment {
namespace CryptoEngine {

using std::array;
using std::vector;
using std::copy;
using std::cerr;

namespace { 
    constexpr std::uint32_t rotateRight(std::uint32_t x, std::uint32_t n) noexcept {
        return (x >> n) | (x << (32 - n));
    }
    constexpr std::uint32_t choose(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
        return (x & y) ^ (~x & z);
    }
    constexpr std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    constexpr std::uint32_t bigSigma0(std::uint32_t x) noexcept {
        return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
    }
    constexpr std::uint32_t bigSigma1(std::uint32_t x) noexcept {
        return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
    }
    constexpr std::uint32_t smallSigma0(std::uint32_t x) noexcept {
        return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
    }
    constexpr std::uint32_t smallSigma1(std::uint32_t x) noexcept {
        return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
    }

    constexpr std::array<Byte, 9> ExtendingTag = { 'E', 'x', 't', 'e', 'n', 'd', 'i', 'n', 'g' };
}

// Purpose: Evaluates standard SHA-256 compression digests.
// Arguments: byteData - variable length buffer to hash.
Hash sha256(const vector<Byte>& byteData) {
    // Step 1: Initialize intermediate registers to the standard fractional parts of the first 8 primes.
    array<std::uint32_t, 8> h = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    static constexpr array<std::uint32_t, 64> k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Step 2: Copy input stream and determine the absolute bit length suffix metadata.
    vector<Byte> paddedData = byteData;
    std::uint64_t bitLength = paddedData.size() * 8;
    
    // Step 3: Inject the initial padding delimiter byte bit flag.
    paddedData.push_back(0x80);
    while ((paddedData.size() + 8) % 64 != 0) {
        paddedData.push_back(0x00);
    }
    
    // Step 4: Append the 64-bit length suffix integer values onto the tail of the block.
    for (int i = 7; i >= 0; --i) {
        paddedData.push_back((bitLength >> (i * 8)) & 0xFF);
    }

    // Step 5: Iteratively execute the 64 cryptographic round mixes over each 64-byte structural data block.
    for (std::size_t chunk = 0; chunk < paddedData.size(); chunk += 64) {
        array<std::uint32_t, 64> w;
        for (int i = 0; i < 16; ++i) {
            w[i] = (paddedData[chunk + i*4] << 24) | (paddedData[chunk + i*4 + 1] << 16) | 
                   (paddedData[chunk + i*4 + 2] << 8) | paddedData[chunk + i*4 + 3];
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = smallSigma1(w[i-2]) + w[i-7] + smallSigma0(w[i-15]) + w[i-16];
        }
        
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], iH = h[7];
        for (int i = 0; i < 64; ++i) {
            std::uint32_t t1 = iH + bigSigma1(e) + choose(e, f, g) + k[i] + w[i];
            std::uint32_t t2 = bigSigma0(a) + majority(a, b, c);
            iH = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += iH;
    }

    // Step 6: Parse state register configurations back into the final 32-byte continuous array.
    Hash output;
    for (int i = 0; i < 8; ++i) {
        output[i*4]   = (h[i] >> 24) & 0xFF; output[i*4+1] = (h[i] >> 16) & 0xFF;
        output[i*4+2] = (h[i] >> 8) & 0xFF;  output[i*4+3] = h[i] & 0xFF;
    }
    return output;
}

// Purpose: Serializes and hashes a single bit flag byte together with its companion salt mask.
// Arguments: bit - expanded cell value; mask - matching salt token reference.
Hash sha256Leaf(UnpackedBit bit, const Scalar& mask) {
    // Step 1: Pre-allocate a 33-byte serialization context buffer.
    vector<Byte> buffer(33);
    
    // Step 2: Assign the single bit flag byte into the front index cell.
    buffer[0] = bit;
    
    // Step 3: Copy the 32-byte salt mask array into the remaining trailing index positions.
    copy(mask.begin(), mask.end(), buffer.begin() + 1);
    
    // Step 4: Evaluate and return the raw compression hash outcome block.
    return sha256(buffer);
}

// Purpose: Concatenates and hashes a left and right node digest pair.
// Arguments: left/right - raw child node tokens.
Hash sha256Nodes(const Hash& left, const Hash& right) {
    // Step 1: Pre-allocate a continuous 64-byte structural staging buffer.
    vector<Byte> buffer(64);
    
    // Step 2: Copy the 32-byte left branch hash into the first index slot window.
    copy(left.begin(), left.end(), buffer.begin());
    
    // Step 3: Copy the 32-byte right branch hash into the secondary tail index slot window.
    copy(right.begin(), right.end(), buffer.begin() + 32);
    
    // Step 4: Evaluate and return the joint compression hash block.
    return sha256(buffer);
}

// Purpose: Stretches a 256-bit scalar input into a 1024-bit bitstream representation E(S).
// Arguments: scalar - 32-byte master seed material value.
Bitstream expandScalar(const Scalar& scalar) {
    // Step 1: Initialize the packed output target stream field to zero.
    Bitstream outputStream;
    outputStream.fill(0);
    std::size_t globalBitIdx = 0;

    // Step 2: Sequentially process 4 unique counter blocks to accumulate 1,024 total bits.
    for (std::uint32_t r = 0; r < 4; ++r) {
        // Step 3: Append the 9-byte context tag and the 1-byte counter loop index variable.
        vector<Byte> context(scalar.begin(), scalar.end());
        context.insert(context.end(), ExtendingTag.begin(), ExtendingTag.end());
        context.push_back(static_cast<Byte>(r));
        
        // Step 4: Evaluate the 32-byte pseudo-random hash digest block.
        Hash roundHash = sha256(context);
        
        // Step 5: Walk bit-by-bit from left to right (MSB to LSB) to serialize the output.
        for (Byte byte : roundHash) {
            for (int b = 7; b >= 0; --b) {
                Byte currentBit = (byte >> b) & 1;
                if (currentBit) {
                    std::size_t targetByteCell = globalBitIdx / 8;
                    std::size_t targetBitOffset = globalBitIdx % 8;
                    outputStream[targetByteCell] |= (1 << (7 - targetBitOffset));
                }
                globalBitIdx++;
            }
        }
    }
    
    // Step 6: Return the fully stretched 1024-bit packed bitstream data frame.
    return outputStream;
}

// Purpose: Slices a packed continuous bitstream layout into a loose byte cell lookup array.
// Arguments: packedStream - tight 128-byte array buffer input.
UnpackedBitstream unpackBitstream(const Bitstream& packedStream) {
    // Step 1: Linearly traverse all 1,024 bits packed within the 128-byte wire frame.
    UnpackedBitstream bits;
    for (std::size_t i = 0; i < BitstreamLength; ++i) {
        // Step 2: Decompress individual bit states into loose bytes for fast processing.
        bits[i] = (packedStream[i / 8] >> (7 - (i % 8))) & 1;
    }
    return bits;
}

// Purpose: Translates a packed byte field back into an array of loose challenge bit flags.
// Arguments: packedBits - tight 16-byte buffer input.
UnpackedOpenBitsBlock unpackChallengeBits(const OpenBitsBlock& packedBits) {
    // Step 1: Linearly traverse all 128 challenge indices packed inside the 16-byte buffer.
    UnpackedOpenBitsBlock bits;
    for (std::size_t i = 0; i < ChallengeLength; ++i) {
        // Step 2: Unpack individual bits back into a loose byte allocation layout.
        bits[i] = (packedBits[i / 8] >> (7 - (i % 8))) & 1;
    }
    return bits;
}

// Purpose: Packs an array of open challenge bit bytes tightly back into a continuous compressed wire field.
// Arguments: rawBits - loose 128-element byte array input.
OpenBitsBlock packChallengeBits(const UnpackedOpenBitsBlock& rawBits) {
    // Step 1: Pre-allocate a zero-filled compressed wire payload target frame.
    OpenBitsBlock output;
    output.fill(0);
    
    // Step 2: Compress loose boolean bytes back into tight bit segments sequentially.
    for (std::size_t i = 0; i < ChallengeLength; ++i) {
        if (rawBits[i]) {
            output[i / 8] |= (1 << (7 - (i % 8)));
        }
    }
    return output;
}

} // namespace CryptoEngine
} // namespace DeniableCommitment

