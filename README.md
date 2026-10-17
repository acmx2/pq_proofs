# Post-Quantum Deniable Commitment & Ring Signature Engine Suites (pq_proofs)

⚠️ **PROOF OF CONCEPT ONLY:** This repository contains experimental cryptographic codebases designed for research, benchmarking, and theoretical validation. It has not been subjected to formal external security audits and should not be deployed in production environments.

A 100% self-contained, zero-dependency C++20 implementation of post-quantum sound, zero-knowledge deniable commitment protocols and a one-time linkable ring signature scheme. This repository tracks the complete development lifecycle of the protocol suite, scaling from a standalone single-instance deniable commitment prototype to a batching engine, and concluding with a one-time linkable anonymous signature pipeline.

---

## 📚 Technical Specifications & Documentation

Comprehensive technical specifications detailing the cryptographic security levels, topological equations, and selection heuristics are provided as compiled PDF documents within the repository tree:

* **Baseline Engine Spec:** [`deniable_commitment/docs/dc_poc_spec.pdf`](deniable_commitment/docs/dc_poc_spec.pdf)
* **Batch Suite Spec:** [`batch_deniable_commitment/docs/batch_dc_poc_spec.pdf`](batch_deniable_commitment/docs/batch_dc_poc_spec.pdf)
* **One-Time Signature Spec:** [`one_time_signature/docs/ots_poc_spec.pdf`](one_time_signature/docs/ots_poc_spec.pdf)

---

## 📐 Mathematical & Architectural Overview

The core objective of these protocol engines is to scale the concept of the 1-out-of-2 Deniable Plain Scalar Bit-Commitment Scheme into a complete post-quantum secure, zero-knowledge verification pipeline and apply it directly to high-dimensional linkable anonymity applications.

### Deniable Commitment
Given a public commitment `Cmt` and a subsequently presented pair of 256-bit scalars `(Pk, Pk')`, the Prover can convince the Verifier with 128-bit post-quantum security (NIST Level 1 Compliance) that one of these two scalars was originally bound to `Cmt`, while the other remains completely arbitrary. The verification routine preserves absolute zero-knowledge deniability; the Verifier learns nothing regarding which specific slot contained the authentic secret scalar.

*Note on Reusability:* This commitment verification process is strictly **one-time**. Running subsequent verification passes with a different arbitrary scalar in the pair will trivially reveal which of the two scalars was actually committed to.

### Batch Deniable Commitment Suite
For a fixed `V`, given a public commitment `Cmt` and subsequently presented `V` pairs of 256-bit scalars, the Prover convinces the Verifier with absolute zero-knowledge deniability and 128-bit post-quantum security that, for each pair, one of its two scalars was originally bound to `Cmt`, while the other remains completely arbitrary. 

### One-Time Linkable Ring Signature Suite
The one-time ring signature engine (OTS) leverages the properties of the Batch Deniable Commitment Suite (BDCS) paired with a Partially Fixed Merkle Tree (PFMT) structure to sign a message anonymously with 128-bit post-quantum security.

The public ring contains exactly \(2^V - 1\) public keys. To construct a balanced \(2^V\) leaf spectrum layer for the tree, a cryptographic anchor derived directly from the message and the public linkable identity tag is appended to the end of the public key ring vector. The signer's exact operational position inside this ring is deterministically derived from its private seeds during public key generation, allowing the signing logic to map sibling nodes on-the-fly and fold the tree bottom-up with clear O(1) indexing lookup complexity.

For $V \in [4 \dots 16]$ (corresponding to ring sizes from $15$ to $65,535$), the Proof-of-Concept OTS implementation exhibits a total signature size in the range of $[12\text{ KB} \dots 47\text{ KB}]$. Both signature generation (signing) and verification execute within a $[100\text{ ms} \dots 2000\text{ ms}]$ time frame.

---

### 🗂️ Included Codebases

1. **`deniable_commitment/`**: The initial standalone 1-out-of-2 plain scalar bit-commitment prototype. It demonstrates the core mechanics of symmetric stream collisions and "oblivious" bit tracking.
2. **`batch_deniable_commitment/`**: The definitive, high-throughput engine. It aggregates V parallel instances into a single global batch array `B`, optimizing bandwidth allocation through a multi-phase greedy optimization selection layer, GGM hierarchical key derivation, and a nested prefix cascade leaf structure.
3. **`one_time_signature/`**: The ring signature framework. It applies the batch commitment engine to an expanded verification ring space to build a linkable, post-quantum sound anonymous signature routine that folds leaf spectrum nodes into a unified parent root.

---

## ⚡ Key Optimization & Compaction Mechanics

The Batch Deniable Commitment Suite utilizes several topological techniques to compress the payload of multi-proofs:

* **Two-Phase Structural Compaction Selection Engine**: Shifts dynamically from local sub-tree density mining (Phase 1 Heuristics) to global marginal path-cost optimization (Phase 2 Layer-Weighted Shannon Entropy Consolidation) to fulfill a 128-bit security quota per track while preventing high-level branch fracturing.
* **Mandatory Symmetrical Sibling Sweep**: Automatically identifies free twin siblings whose tree path footprints have already been accounted for, recovering entropy at zero additional cryptographic bytes cost on the wire.

The core approach of the One-Time Linkable Ring Signature is:

* **Reduction of a $1\text{-out-of-}2^V$ selection to a $(1\text{-out-of-}2)^V$ batch instance**: Using a PFMT, the engine decomposes a single $1\text{-out-of-}2^V$ ring membership proof into a batch of V independent 1-out-of-2 statements, which is then efficiently resolved by the BDCS.

---

## 🚀 Local Compilation & Execution

All codebases feature standard CMake tracking files and require nothing but a modern C++20 compiler (`gcc >= 11` or `clang >= 13`). No third-party packages, system headers, or external cryptographic libraries are required.

To compile and execute the test validation pipelines for all three platforms sequentially in a single pass, trigger the automated shell script from the repository root:

```bash
chmod +x setup_and_test.sh
./setup_and_test.sh
```

---

## 🤖 Project Generation & Attribution

This repository is the product of an interactive AI co-development process:

* **Protocol Architecture & Direction:** Designed and structured by the author, including all core protocols, optimization heuristics, and cryptographic constraints.
* **Engineering & Documentation Execution:** Generated by **Gemini** (an AI developed by **Google**), which implemented the C++20 source code and authored the technical text strictly following the requested step-by-step logic.

---

## ⚖️ License

This repository is dual-licensed under a split legal framework:
* **Source Code:** All C++ source code files, build scripts, and test suites are licensed under the **MIT License**.
* **Documentation & Outputs:** All technical specifications, papers, compiled PDFs, and benchmark text reports are licensed under the **Creative Commons Attribution 4.0 International (CC BY 4.0)** license.

For full license texts, review the [`LICENSE.txt`](LICENSE.txt) file in the repository root.

