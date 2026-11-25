//! RISC Zero zkVM Guest Program for Al-Samawal Rollup HyperCompressor (`FORMAT_VERSION = 3`).
//!
//! Build with RISC Zero toolchain:
//!   `cd zkvm/risc0-guest && cargo risczero build`
//!
//! ## Mandatory On-Chain Verifier Policy (`C-2r`)
//! Any L1 verifier contract accepting receipts from this guest **MUST** enforce:
//! 1. **Dictionary Binding:** `journal.dict_sha256 == APPROVED_CHAIN_DICT_SHA256` (NEVER accept
//!    `[0u8; 32]` on a dictionary-enabled chain).
//! 2. **DA Blob Binding:** `journal.blob_sha256 == SHA-256(blob)` binds raw DA bytes:
//!    - On **Ethereum EIP-4844**, pair with a KZG point-evaluation / equivalence proof linking
//!      `blob_sha256` to the EIP-4844 blob `versioned_hash`.
//!    - On **Bitcoin (e.g. Citrea)**, pair with a Bitcoin light-client Taproot witness inclusion proof.
//! 3. **Prover-Fault Separation:** Prover-controlled dictionary witness faults (`MissingDictionary`,
//!    `DictionaryIdMismatch`) **abort proving** instead of committing `is_valid = false`, so a
//!    malicious prover can NEVER mark an honest batch invalid by withholding/swapping the dictionary.
//!    Intrinsic blob defects commit `(is_valid = false, error_code = err.code())` cleanly.
//! 4. **Consensus Limit Parity (`N-1` / `N-2`):** Uses `DecodeLimits::CONSENSUS`, identical to the
//!    encoder, sidecar, and L2 full nodes (`100k` slots, `8 MiB` pre-entropy, `8 MiB` Zstd window,
//!    `16 MiB` calibrated output, mandatory `Frame_Content_Size` + XXH64 checksum).

use hypercomp_decoder::{
    commit_state_deltas_sha256, decompress_state_deltas_with_prehashed_dict, sha256_bytes,
    DecodeLimits, PrehashedDict,
};
use risc0_zkvm::guest::env;

fn main() {
    // 1. Read compressed DA blob and pre-shared approved chain Zstd dictionary from RISC Zero host.
    let blob: Vec<u8> = env::read_frame();
    let dict: Vec<u8> = env::read_frame();

    // 2. Cryptographically bind raw blob and hash dictionary ONCE via `PrehashedDict` (`N-5`).
    let blob_sha256 = sha256_bytes(&blob);
    let prehashed_dict = if dict.is_empty() {
        None
    } else {
        Some(PrehashedDict::new(&dict))
    };
    let dict_sha256 = prehashed_dict.map_or([0u8; 32], |d| d.id());

    // 3. Deterministically decompress under unified consensus limits (`DecodeLimits::CONSENSUS`).
    match decompress_state_deltas_with_prehashed_dict(&blob, prehashed_dict, DecodeLimits::CONSENSUS)
    {
        Ok(contracts) => {
            let mut total_slots: u32 = 0;
            for c in &contracts {
                total_slots = total_slots.saturating_add(c.storage_deltas.len() as u32);
            }
            let deltas_sha256 = commit_state_deltas_sha256(&contracts);

            // 4. Commit complete cryptographic receipt journal (`error_code = 0` on valid batch).
            env::commit(&(
                blob_sha256,
                dict_sha256,
                true,
                0u8,
                contracts.len() as u32,
                total_slots,
                deltas_sha256,
            ));
        }
        Err(err) => {
            // Prover-supplied witness faults MUST abort proving (never emit `is_valid = false`).
            assert!(
                !err.is_prover_witness_error(),
                "prover supplied missing or mismatched Zstd dictionary witness"
            );
            env::commit(&(
                blob_sha256,
                dict_sha256,
                false,
                err.code(),
                0u32,
                0u32,
                [0u8; 32],
            ));
        }
    }
}
