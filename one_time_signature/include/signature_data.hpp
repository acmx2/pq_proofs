// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef SIGNATURE_DATA_HPP
#define SIGNATURE_DATA_HPP

#include "ots_common.hpp"
#include <vector>
#include <utility>

namespace OtSignature {

// Private signing credentials containing master identity parameters.
// This structure holds all secret values needed to initialize the tree structures
// and generate corresponding signatures.
struct PrivateKey {
    Scalar512 skp;   // Secret signing key identity parameter (SKP).
    Scalar512 trs;   // Private tracking root seed for PFMT expansions.
    BdcScalar ggmri; // Master seed for GGM tree mask generation inside BDCS.
};

// Symmetrical public unlinked identifier token structure.
// Distributed to verifiers to validate signatures anonymously.
struct PublicKey {
    Scalar512 pk;    // Public Key payload: SKP XOR CMT.

    // Operator overload to allow clean ring-searching logic comparisons.
    bool operator==(const PublicKey& other) const { return pk == other.pk; }
};

// Private key generation cache structural frame holding internal parameters for signing.
// This stores all intermediate parameters derived during generatePublicKey() so that
// the signer can execute later operations with high clarity and known offsets.
struct PrivateKeyFullData {
    PrivateKey baseKey;                               // The original private baseline components.
    Hash512 pfmtRootRt;                               // The extracted fixed identity root hash.
    std::vector<Byte> bitpathTBP;                     // The derived private routing trajectory bitpath.
    std::vector<std::pair<Scalar512, Scalar512>> slr; // Sparse tracking loop layers populated at keygen.
    BdcPrivateCommitmentData bdcFullData;             // Cached BDC witness parameters.
    BdcPublicCommitment cachedBdcMtr;                 // Direct explicit BDC root cache member.

    // The position of the signing key inside any subsequent ad-hoc verification ring 
    // is deterministically fixed during the public key generation phase based on the 
    // private key's random seed trajectory (TRS). This trajectory path is uniquely 
    // evaluated and saved inside the tracking path cache (bitpathTBP) at keygen.
    // 
    // Consequently, this method extracts and returns that fixed, pre-calculated 
    // slot position directly from the generation cache. This allows the signing loop 
    // to map its active leaf index location in O(1) complexity without executing 
    // expensive runtime ring searches.
    std::size_t getSigningIndex() const;
};

// Complete compiled post-quantum anonymous ring signature packet.
// This is the collection of data blocks that gets transmitted across the wire.
struct Signature {
    Hash512 rt;                                       // Master PFMT root hash commitment anchor.
    BdcPublicCommitment mtr;                          // Batch Deniable Commitment Merkle Tree Root.
    std::vector<std::pair<Scalar512, Scalar512>> slr; // Symmetrical Left/Right layer delta pairs array.
    BdcProofPayload bdcp;                            // Compressed multi-proof payload data block.

    // Computes the linkable identifier tag context token string I.
    // Technical Specification Section 5.2, Step 1: I = sha512(Sig.RT || Sig.MTR)
    Hash512 getLinkingTag() const;
};

using PublicRing = std::vector<PublicKey>;

} // namespace OtSignature

#endif // SIGNATURE_DATA_HPP

