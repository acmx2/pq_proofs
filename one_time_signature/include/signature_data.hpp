// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#ifndef SIGNATURE_DATA_HPP
#define SIGNATURE_DATA_HPP

#include "ots_common.hpp"
#include <vector>
#include <utility>

namespace OtSignature {

struct PrivateKey {
    Scalar512 skp;   
    Scalar512 trs;   
    BdcScalar ggmri; 
};

struct PublicKey {
    Scalar512 pk;    
};

struct PrivateKeyFullData {
    PrivateKey baseKey;                               
    Hash512 pfmtRootRt;                               
    std::vector<Byte> bitpathTBP;                     
    std::vector<std::pair<Scalar512, Scalar512>> slr; 
    BdcPrivateCommitmentData bdcFullData;             
    BdcPublicCommitment cachedBdcMtr;                 
};

struct Signature {
    Hash512 rt;              
    BdcPublicCommitment mtr; 
    std::vector<std::pair<Scalar512, Scalar512>> slr; 
    BdcProofPayload bdcp;    

    Hash512 getLinkingTag() const;
};

using PublicRing = std::vector<PublicKey>;

} // namespace OtSignature

#endif // SIGNATURE_DATA_HPP

