// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef SIGNER_HPP
#define SIGNER_HPP

#include "ots_common.hpp"
#include "signature_data.hpp"
#include <vector>
#include <utility>

namespace OtSignature {

class Signer {
public:
    // =========================================================================
    // PUBLIC KEY GENERATION INTERFACE
    // =========================================================================
    // Accepts the private key sk (containing cryptographic roots and private seeds) from the user.
    // Executes the Phase-Split Merkle structure extraction protocol.
    // Returns a Public Key paired with an un-truncated private metadata cache.
    // Note that the position of the generated PublicKey within any future ring it signs 
    // is fixed during this procedure and cached privately inside the returned PrivateKeyFullData.
    static std::pair<PublicKey, PrivateKeyFullData> generatePublicKey(const PrivateKey& sk, std::size_t parameterV = V);


    // =========================================================================
    // ANONYMOUS RING SIGNATURE INTERFACE
    // =========================================================================
    // Signs an arbitrary message while hiding actual signer inside an ad-hoc group ring.
    // The signer's exact operational position inside this ring is not arbitrary; it is 
    // deterministically fixed during the public key generation pass and retrieved directly 
    // from the input cache. As the cache is private, no information about the position is leaked to verifier.
    //
    // To construct the balanced 2^V leaf spectrum, the signature engine takes the input 
    // ring of 2^V - 1 public keys and explicitly appends a dynamic cryptographic anchor, derived 
    // directly from the message, at the absolute end of the leaf array. 
    // This allows the engine to evaluate sibling tracks on-the-fly and complete the bottom-up 
    // tree folding pass with clear O(1) indexing lookup complexity.
    //
    // Input Components:
    // - fullData: The private key generation cache holding the pre-calculated path bit trajectory,
    //             master private seeds, and baseline deniable witness parameters.
    // - ringIn:   The ad-hoc vector array containing exactly 2^V - 1 external public keys 
    //             which form the anonymity set hiding the signer's identity.
    // - message:  The raw 512-bit transactional context buffer that is securely signed by 
    //             binding it directly to the trailing leaf anchor slot.
    // - parameterV: The topological tree height scale invariant parameter that must match the
    //               global system constant V.
    //
    // Output Packet:
    // Returns a complete, wire-ready Signature structure containing the master root anchors, 
    // the dense left/right delta masks array, and the zero-knowledge commitment multi-proof.
    static Signature sign(
        const PrivateKeyFullData& fullData, 
        const PublicRing& ringIn, 
        const Scalar512& message, 
        std::size_t parameterV = V
    );

};

} // namespace OtSignature

#endif // SIGNER_HPP

