// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "ots_procedures.hpp"
#include <cstring>

namespace OtSignature {
namespace CryptoEngine {

namespace {
    // Pure, explicit mathematical transformation primitives matching SHA-512 specifications.
    // Replaced unsafe preprocessor macros with typesafe inline constexpr functions
    // to guarantee calculation safety and block any hidden compiler side-effects.
    inline constexpr uint64_t rotr(uint64_t x, uint64_t n) noexcept { return (x >> n) | (x << (64 - n)); }
    inline constexpr uint64_t ch(uint64_t x, uint64_t y, uint64_t z) noexcept { return (x & y) ^ (~x & z); }
    inline constexpr uint64_t maj(uint64_t x, uint64_t y, uint64_t z) noexcept { return (x & y) ^ (x & z) ^ (y & z); }
    inline constexpr uint64_t sigma0(uint64_t x) noexcept { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
    inline constexpr uint64_t sigma1(uint64_t x) noexcept { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }
    inline constexpr uint64_t delta0(uint64_t x) noexcept { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7); }
    inline constexpr uint64_t delta1(uint64_t x) noexcept { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6); }

    static constexpr std::array<uint64_t, 80> K512 = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf14d754aULL, 0x59f111f1cd8e4443ULL, 0x923f82a4af194f9bULL, 0xab1c5ed577ee3152ULL,
        0xd807aa98a3030242ULL, 0x123356d53cd6472dULL, 0x240ca1cc7710c663ULL, 0x2c40c3028081a97fULL,
        0x387ea6a94f66d495ULL, 0x8a47814757c2250cULL, 0x2e1b21385d16c478ULL, 0x4d2c6dfc5ac42aedULL,
        0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
        0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL,
        0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL,
        0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
        0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
        0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL,
        0x8cc702081a6439ecULL, 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
        0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL,
        0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL,
        0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
        0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL,
        0x6c44198c4a475817ULL, 0x785d066a5d93301dULL, 0x8d2d4c57510e527fULL, 0x8fa084783d763417ULL,
        0x96391578855e6eacULL, 0xa4506ceb03db3283ULL, 0xa851c545748fcd24ULL, 0x015c07102e3b2358ULL,
        0x0d51a603a104cdc5ULL, 0x1180faf747be2222ULL, 0x14310a0711cc6ddcULL, 0x1cc2026e28e1b212ULL,
        0x1e376c085141ab53ULL, 0x240ca1cc7710c663ULL, 0x2c40c3028081a97fULL, 0x387ea6a94f66d495ULL,
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL
    };
} // namespace

Hash512 sha512(const std::vector<Byte>& buffer) {
    // Initialize the eight 64-bit state registers with the fractional parts
    // of the square roots of the first eight prime numbers.
    std::array<uint64_t, 8> state = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    // Clone the input buffer to append padding bytes safely without altering original data.
    std::vector<Byte> padded = buffer;
    uint64_t bitLength = static_cast<uint64_t>(buffer.size()) * 8;
    
    // Append the mandatory single delimiter bit '1' represented as a 0x80 byte value.
    padded.push_back(0x80);
    
    // Pad with zeroes until the modified buffer size is exactly congruent to 112 modulo 128 bytes.
    while ((padded.size() % 128) != 112) {
        padded.push_back(0x00);
    }
    
    // Append the original unpadded length parameter as a big-endian 128-bit unsigned integer value.
    // The highest 64 bits are padded with zero since standard processing bit-lengths fit cleanly inside uint64_t.
    for (int i = 0; i < 8; ++i) padded.push_back(0);
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<Byte>((bitLength >> (i * 8)) & 0xFF));
    }

    // Process the padded message stream sequentially in 1024-bit (128 byte) chunk blocks.
    for (size_t chunk = 0; chunk < padded.size(); chunk += 128) {
        std::array<uint64_t, 80> W{};
        
        // Unpack the chunk block into the first 16 message words as distinct big-endian blocks.
        for (int t = 0; t < 16; ++t) {
            size_t base = chunk + t * 8;
            W[t] = (static_cast<uint64_t>(padded[base]) << 56) |
                   (static_cast<uint64_t>(padded[base + 1]) << 48) |
                   (static_cast<uint64_t>(padded[base + 2]) << 40) |
                   (static_cast<uint64_t>(padded[base + 3]) << 32) |
                   (static_cast<uint64_t>(padded[base + 4]) << 24) |
                   (static_cast<uint64_t>(padded[base + 5]) << 16) |
                   (static_cast<uint64_t>(padded[base + 6]) << 8)  |
                   (static_cast<uint64_t>(padded[base + 7]));
        }

        // Expand the remaining 64 message schedule words using NIST recursive bitwise transformations.
        for (int t = 16; t < 80; ++t) {
            W[t] = delta1(W[t - 2]) + W[t - 7] + delta0(W[t - 15]) + W[t - 16];
        }

        // Initialize local rolling variables with current active state register tracking data.
        uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

        // Execute 80 primary block compression loop iterations.
        for (int t = 0; t < 80; ++t) {
            uint64_t T1 = h + sigma1(e) + ch(e, f, g) + K512[t] + W[t];
            uint64_t T2 = sigma0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        // Incorporate compressed results back into global state tracking registers.
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    // Unpack the final eight 64-bit state registers back into a flat 64-byte array format.
    Hash512 digest{};
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            digest[i * 8 + j] = static_cast<Byte>((state[i] >> ((7 - j) * 8)) & 0xFF);
        }
    }
    return digest;
}

Scalar512 computeXor512(const Scalar512& a, const Scalar512& b) {
    Scalar512 result{};
    for (size_t i = 0; i < 64; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

} // namespace CryptoEngine

} // namespace OtSignature

