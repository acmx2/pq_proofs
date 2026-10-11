/*
 * MIT License
 * Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)
 */

#include "common_procedures.hpp"
#include <algorithm>
#include <cassert>

namespace BatchDeniableCommitment {
namespace CryptoEngine {

namespace {
    // Pure C++ Constant parameters array initialization for SHA-256 round keys
    constexpr std::uint32_t K256[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Inline bitwise rotational helper primitives macros
    inline std::uint32_t rotr(std::uint32_t x, std::uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
}

Hash sha256(const std::vector<Byte>& buffer) {
    // Step 1: Initialize the mandatory internal NIST state compression registers.
    std::uint32_t h0 = 0x6a09e667;
    std::uint32_t h1 = 0xbb67ae85;
    std::uint32_t h2 = 0x3c6ef372;
    std::uint32_t h3 = 0xa54ff53a;
    std::uint32_t h4 = 0x510e527f;
    std::uint32_t h5 = 0x9b05688c;
    std::uint32_t h6 = 0x1f83d9ab;
    std::uint32_t h7 = 0x5be0cd19;

    // Step 2: Construct the padded message payload copy on the heap.
    std::vector<Byte> paddedMsg = buffer;
    std::uint64_t bitLength = static_cast<std::uint64_t>(buffer.size()) * 8;

    // Step 2.1: Append the mandatory trailing separator bit '1' (0x80 byte block).
    paddedMsg.push_back(0x80);

    // Step 2.2: Pad trailing zeros until the data aligns perfectly with the 512-bit block border (minus 64 bits).
    while ((paddedMsg.size() + 8) % 64 != 0) {
        paddedMsg.push_back(0x00);
    }

    // Step 2.3: Append original message size as a big-endian 64-bit integer token.
    for (int i = 7; i >= 0; --i) {
        paddedMsg.push_back(static_cast<Byte>((bitLength >> (i * 8)) & 0xFF));
    }

    // Step 3: Process the message sequentially in 512-bit (64-byte) chunk steps.
    for (std::size_t chunkOffset = 0; chunkOffset < paddedMsg.size(); chunkOffset += 64) {
        std::uint32_t W_schedule[64] = {0};

        // Step 3.1: Load initial 16 words from the current 64-byte payload window.
        for (std::size_t t = 0; t < 16; ++t) {
            std::size_t idx = chunkOffset + (t * 4);
            W_schedule[t] = (static_cast<std::uint32_t>(paddedMsg[idx])     << 24) |
                            (static_cast<std::uint32_t>(paddedMsg[idx + 1]) << 16) |
                            (static_cast<std::uint32_t>(paddedMsg[idx + 2]) << 8)  |
                            (static_cast<std::uint32_t>(paddedMsg[idx + 3]));
        }

        // Step 3.2: Expand scheduling array words up to the 64 round limits using sigma transforms.
        for (std::size_t t = 16; t < 64; ++t) {
            std::uint32_t s0 = rotr(W_schedule[t - 15], 7) ^ rotr(W_schedule[t - 15], 18) ^ (W_schedule[t - 15] >> 3);
            std::uint32_t s1 = rotr(W_schedule[t - 2], 17) ^ rotr(W_schedule[t - 2], 19)  ^ (W_schedule[t - 2] >> 10);
            W_schedule[t] = W_schedule[t - 16] + s0 + W_schedule[t - 7] + s1;
        }

        // Step 3.3: Initialize local working variables to the current compression state metrics.
        std::uint32_t a = h0; std::uint32_t b = h1; std::uint32_t c = h2; std::uint32_t d = h3;
        std::uint32_t e = h4; std::uint32_t f = h5; std::uint32_t g = h6; std::uint32_t h = h7;

        // Step 3.4: Execute 64 cryptographic round mixing updates.
        for (std::size_t t = 0; t < 64; ++t) {
            std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            std::uint32_t ch = (e & f) ^ (~e & g);
            std::uint32_t temp1 = h + S1 + ch + K256[t] + W_schedule[t];
            
            std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t temp2 = S0 + maj;

            h = g; g = f; f = e;
            e = d + temp1;
            d = c; c = b; b = a;
            a = temp1 + temp2;
        }

        // Step 3.5: Accumulate the local working parameters back into core state registers.
        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += h;
    }

    // Step 4: Unpack the final register states into a clean 32-byte big-endian output array.
    Hash outputHash;
    std::uint32_t states[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    for (int i = 0; i < 8; ++i) {
        outputHash[(i * 4)]     = static_cast<Byte>((states[i] >> 24) & 0xFF);
        outputHash[(i * 4) + 1] = static_cast<Byte>((states[i] >> 16) & 0xFF);
        outputHash[(i * 4) + 2] = static_cast<Byte>((states[i] >> 8)  & 0xFF);
        outputHash[(i * 4) + 3] = static_cast<Byte>(states[i]        & 0xFF);
    }

    return outputHash;
}

Hash sha256Nodes(const Hash& leftNode, const Hash& rightNode) {
    // Step 1: Allocate a single contiguous 64-byte staging memory buffer segment.
    std::vector<Byte> pairedBuffer(64);

    // Step 2: Copy the left sibling node digest into the lower 32-byte memory slot.
    std::copy(leftNode.begin(), leftNode.end(), pairedBuffer.begin());

    // Step 3: Copy the right sibling node digest into the upper 32-byte memory slot.
    std::copy(rightNode.begin(), rightNode.end(), pairedBuffer.begin() + 32);

    // Step 4: Pass the consolidated 64-byte buffer into the custom native SHA-256 hash function engine.
    return sha256(pairedBuffer);
}

TrackBits expandScalar(const Scalar& inputSecret) {
    // Step 1: Compute the explicit target track bit width required on the heap.
    const std::size_t totalTargetBytes = (W + 7) / 8;
    TrackBits expandedStream;
    expandedStream.reserve(totalTargetBytes * 8);

    // Step 2: Initialize seed tracking variables using the initial private input scalar.
    std::vector<Byte> iterativeBuffer(inputSecret.begin(), inputSecret.end());
    std::size_t accumulatedBitsCount = 0;

    // Step 3: Run the expansion loop until the track capacity boundary requirement is met.
    while (accumulatedBitsCount < W) {
        // Step 3.1: Hash the current state buffer to generate a fresh 32-byte pseudorandom segment.
        Hash iterationHash = sha256(iterativeBuffer);

        // Step 3.2: Unpack the bits from each byte of the generated segment.
        for (std::size_t byteIdx = 0; byteIdx < 32 && accumulatedBitsCount < W; ++byteIdx) {
            Byte sourceByte = iterationHash[byteIdx];
            for (int bitPos = 7; bitPos >= 0 && accumulatedBitsCount < W; --bitPos) {
                Byte extractedBit = (sourceByte >> bitPos) & 0x01;
                expandedStream.push_back(extractedBit);
                accumulatedBitsCount++;
            }
        }

        // Step 3.3: Update the iterative state buffer with the new hash to preserve chain security forward.
        std::copy(iterationHash.begin(), iterationHash.end(), iterativeBuffer.begin());
    }

    return expandedStream;
}

} // namespace CryptoEngine
} // namespace BatchDeniableCommitment

