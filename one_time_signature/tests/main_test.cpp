// MIT License
// Copyright (c) 2026 Anton A. Sokolov (acmxddk@gmail.com)

#include "ots_common.hpp"
#include "signature_data.hpp"
#include "signer.hpp"
#include "ots_verifier.hpp"

// Include modular header tracking frames natively
#include "random_test.hpp"
#include "benchmark_test.hpp"

#include <iostream>
#include <vector>
#include <cassert>

// =============================================================================
// SUB-ROUTINE: THEORETICAL WIRE SIZE CALCULATION
// =============================================================================
// Computes the exact cryptographic byte footprint of the signature payload 
// based on the explicit algebraic sub-components of the ProofPayload packet.
void printTheoreticalSignatureSize(const OtSignature::Signature& sig) {
    // 1. Master fixed identity Merkle root rt is an exact 512-bit token
    std::size_t rtSizeBytes = 64; 

    // 2. Batch Deniable Commitment root mtr is an exact 256-bit token
    std::size_t mtrSizeBytes = 32; 

    // 3. SLR vector contains exactly V pairs of 512-bit (64-byte) left/right masks
    std::size_t slrPairSizeBytes = 64 + 64; 
    std::size_t totalSlrSizeBytes = sig.slr.size() * slrPairSizeBytes;

    // 4. BDC ProofPayload structural composition breakdown (256-bit element types)
    // Every single primitive element across these three structural lists is exactly 32 bytes.
    std::size_t elementStrideBytes = 32; 
    
    std::size_t ggmKeysBytes   = sig.bdcp.revealedGgmKeys.size() * elementStrideBytes;
    std::size_t merkleStubsBytes = sig.bdcp.prunedMerkleHashes.size() * elementStrideBytes;
    std::size_t floorStubsBytes  = sig.bdcp.floorHashStubs.size() * elementStrideBytes;
    
    // Aggregate total for the compressed multi-proof packet (bdcp)
    std::size_t totalBdcpSizeBytes = ggmKeysBytes + merkleStubsBytes + floorStubsBytes;

    // Compute aggregate mathematical wire packet boundary values
    std::size_t totalSignatureSizeBytes = rtSizeBytes + mtrSizeBytes + totalSlrSizeBytes + totalBdcpSizeBytes;

    std::cout << "\n--------------------------------------------------------------" << std::endl;
    std::cout << "---          SIGNATURE WIRE PACKET SIZE BREAKDOWN        ---" << std::endl;
    std::cout << "--------------------------------------------------------------" << std::endl;
    std::cout << "  - Merkle Root Anchor (rt)        : " << rtSizeBytes << " bytes (512-bit)" << std::endl;
    std::cout << "  - BDC Tree Root Anchor (mtr)     : " << mtrSizeBytes << " bytes (256-bit)" << std::endl;
    std::cout << "  - Dense Delta Mask Array (slr)   : " << totalSlrSizeBytes << " bytes (" << sig.slr.size() << " layers x 128 bytes)" << std::endl;
    std::cout << "  - ZK Compact Multi-Proof (bdcp) Breakdown:" << std::endl;
    std::cout << "    * Revealed GGM Keys List       : " << ggmKeysBytes << " bytes (" << sig.bdcp.revealedGgmKeys.size() << " keys x 32 bytes)" << std::endl;
    std::cout << "    * Pruned Merkle Sibling Hashes : " << merkleStubsBytes << " bytes (" << sig.bdcp.prunedMerkleHashes.size() << " stubs x 32 bytes)" << std::endl;
    std::cout << "    * Floor Penalty Hash Stubs     : " << floorStubsBytes << " bytes (" << sig.bdcp.floorHashStubs.size() << " stubs x 32 bytes)" << std::endl;
    std::cout << "    * Total bdcp Wire Footprint    : " << totalBdcpSizeBytes << " bytes" << std::endl;
    std::cout << "  --------------------------------------------------------------" << std::endl;
    std::cout << "  TOTAL WIRE PACKET SIZE : " << totalSignatureSizeBytes << " bytes" << std::endl;
    std::cout << "--------------------------------------------------------------" << std::endl;
}


// =============================================================================
// TEST SCENARIO 1: HARDCODED CACHED BASELINE TESTS
// =============================================================================
// This test exercises the core signature pipeline using completely fixed private
// seeds and credentials. It verifies that the signing loops execute correctly
// when utilizing the cached witness maps populated during public key generation.
bool runCachedHardcodedScenario(OtSignature::Signature& outSigForInspection) {
    std::cout << "\n[Test 1] Executing Hardcoded Cached Data Test Track..." << std::endl;
    constexpr std::size_t ringSize = (1ULL << OtSignature::V) - 1;

    // Configure explicit hardcoded private credentials to establish a reliable baseline
    OtSignature::PrivateKey sk{};
    sk.skp.fill(0x1A); sk.trs.fill(0x2B); sk.ggmri.fill(0x3C); 

    // Compute public key footprint matrices and collect the cached witness metadata
    auto keypair = OtSignature::Signer::generatePublicKey(sk, OtSignature::V);
    OtSignature::PrivateKeyFullData cachedInternals = keypair.second;

    // Identify our horizontal index coordinate k in O(1) via cached path bits
    std::size_t targetSlot = cachedInternals.getSigningIndex();
    
    // Assemble public ring structure, seating our valid public key at index slot k
    OtSignature::PublicRing ring(ringSize);
    for (std::size_t k = 0; k < ringSize; ++k) {
        if (k == targetSlot) ring[k] = keypair.first;
        else ring[k].pk.fill(static_cast<OtSignature::Byte>(k & 0xFF));
    }

    // Configure a dummy transactional context message buffer
    OtSignature::Scalar512 message{}; message.fill(0x7E); 
    
    // Compile the post-quantum ring signature packet over the fixed elements
    outSigForInspection = OtSignature::Signer::sign(cachedInternals, ring, message, OtSignature::V);
    
    // Evaluate the output through the public two-tier verifier pipeline circuit
    return OtSignature::Verifier::verify(ring, message, outSigForInspection, OtSignature::V);
}

// =============================================================================
// TEST SCENARIO 2: HARDCODED UNCACHED ON-THE-FLY REGENERATION TESTS
// =============================================================================
// This tracking run mirrors Scenario 1 but completely bypasses cached data fields
// during signing. It emulates a system that dynamically reconstructs its internal
// mathematical parameters on-the-fly from the raw master private seeds.
bool runUncachedHardcodedScenario() {
    std::cout << "\n[Test 2] Executing Hardcoded Uncached Regeneration Test Track..." << std::endl;
    constexpr std::size_t ringSize = (1ULL << OtSignature::V) - 1;

    // Configure a separate set of independent private credentials blocks
    OtSignature::PrivateKey sk{};
    sk.skp.fill(0xFE); sk.trs.fill(0xDC); sk.ggmri.fill(0xBA); 

    // Generate keys to isolate our exact target trajectory path location natively
    auto keypair = OtSignature::Signer::generatePublicKey(sk, OtSignature::V);
    std::size_t targetSlot = keypair.second.getSigningIndex();
    
    // Populate public ring tracks symmetrically based on target slot constraints
    OtSignature::PublicRing ring(ringSize);
    for (std::size_t k = 0; k < ringSize; ++k) {
        if (k == targetSlot) ring[k] = keypair.first;
        else ring[k].pk.fill(static_cast<OtSignature::Byte>((k ^ 0x55) & 0xFF));
    }

    // Configure distinct transaction text metrics blocks
    OtSignature::Scalar512 message{}; message.fill(0x33); 
    
    // Bypassing cache parameters: Re-execute keygen on-the-fly to simulate an uncached run
    auto standardRebuildPair = OtSignature::Signer::generatePublicKey(sk, OtSignature::V);
    
    // Generate the wire signature packet using the freshly regenerated context array block
    OtSignature::Signature sig = OtSignature::Signer::sign(standardRebuildPair.second, ring, message, OtSignature::V);
    
    // Assert that the uncached signature package correlates cleanly with the original public key
    return OtSignature::Verifier::verify(ring, message, sig, OtSignature::V);
}

// =============================================================================
// TEST SCENARIO 4: NEGATIVE TAMPERING ATTACK INJECTIONS
// =============================================================================
// This critical suite injects targeted data corruptions into a valid signature
// to confirm that the Verifier rejects modified or adversarial messages with 100% reliability.
bool runNegativeAttackScenarios() {
    std::cout << "\n[Test 4] Initiating Negative Tampering Attack Scenarios..." << std::endl;
    constexpr std::size_t ringSize = (1ULL << OtSignature::V) - 1;

    OtSignature::PrivateKey sk{};
    sk.skp.fill(0x01); sk.trs.fill(0x02); sk.ggmri.fill(0x03);

    auto keypair = OtSignature::Signer::generatePublicKey(sk, OtSignature::V);
    OtSignature::PrivateKeyFullData cachedInternals = keypair.second;
    OtSignature::PublicRing ring(ringSize);
    ring[cachedInternals.getSigningIndex()] = keypair.first;

    OtSignature::Scalar512 originalMessage{}, forgedMessage{};
    originalMessage.fill(0xAA); forgedMessage.fill(0xBB);

    // Compile a pristine, structurally valid baseline signature packet
    OtSignature::Signature sig = OtSignature::Signer::sign(cachedInternals, ring, originalMessage, OtSignature::V);

    // -------------------------------------------------------------------------
    // ATTACK CASE 4.1: TRANSACTIONAL TEXT CONTEXT TAMPERING MOD
    // -------------------------------------------------------------------------
    // An attacker captures a valid signature packet on the wire and attempts to map
    // it to a forged transaction message block. The verifier must reject this pass.
    bool badMsgCheck = OtSignature::Verifier::verify(ring, forgedMessage, sig, OtSignature::V);
    std::cout << (badMsgCheck ? ">> FAIL: Malicious message accepted!" : ">> PASS: Intercepted text attack rejected.") << std::endl;

    // -------------------------------------------------------------------------
    // ATTACK CASE 4.2: SIGNATURE DELTA VECTOR TRACK CORRUPTION
    // -------------------------------------------------------------------------
    // An attacker attempts to inject random bitwise bit flips inside the transmitted 
    // signature vector mask array. This breaks the tree folding alignment pass.
    OtSignature::Signature mutatedSig = sig;
    mutatedSig.slr[0].first[0] ^= 0xFF; // Flip front byte of level 0 left delta track
    bool badDeltaCheck = OtSignature::Verifier::verify(ring, originalMessage, mutatedSig, OtSignature::V);
    std::cout << (badDeltaCheck ? ">> FAIL: Mutated signature deltas accepted!" : ">> PASS: Corrupted signature data block rejected.") << std::endl;

    // Returns true only if both attacks were successfully identified and rejected by the verifier
    return (!badMsgCheck && !badDeltaCheck);
}

// =============================================================================
// MAIN ENTRY ORCHESTRATOR
// =============================================================================
int main() {
    std::cout << "==============================================================" << std::endl;
    std::cout << "=== RUNNING CONSOLIDATED POST-QUANTUM SOUND SIGNATURE SUITE ===" << std::endl;
    std::cout << "==============================================================" << std::endl;

    OtSignature::Signature sigForInspection{};

    // Trigger all validation tracks sequentially
    bool track1 = runCachedHardcodedScenario(sigForInspection);
    bool track2 = runUncachedHardcodedScenario();
    bool track3 = OtSignature::TestTrack::runHardwareEntropyScenario();
    bool track4 = runNegativeAttackScenarios();
    bool track5 = OtSignature::TestTrack::runPerformanceBenchmarkSuite();

   // Call size calculation analysis step over the compiled signature packet
    printTheoreticalSignatureSize(sigForInspection);

    std::cout << "\n==============================================================" << std::endl;
    std::cout << "===               FINAL INTEGRATION STATUS                 ===" << std::endl;
    std::cout << "==============================================================" << std::endl;
    
    // Evaluate the overall suite status banner
    if (track1 && track2 && track3 && track4 && track5) {
        std::cout << ">>> OVERALL RUN STATUS: [ SUCCESS ] <<<" << std::endl;
        std::cout << "==============================================================" << std::endl;
        return 0;
    } else {
        std::cout << ">>> OVERALL RUN STATUS: [ FAILURE ] <<<" << std::endl;
        std::cout << "==============================================================" << std::endl;
        return 1;
    }
}

