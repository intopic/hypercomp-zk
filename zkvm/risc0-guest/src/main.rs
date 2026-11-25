//! RISC Zero zkVM Guest Program for Al-Samawal Rollup HyperCompressor.
//!
//! Build with RISC Zero toolchain:
//!   `cd zkvm/risc0-guest && cargo risczero build`
//!
//! Soundness guarantees:
//! - Commits `blob_sha256 = SHA-256(blob)` and `dict_sha256 = SHA-256(dict)` (or `[0u8; 32]`)
//!   so the verifier cryptographically binds the proof to the exact posted DA blob & dictionary.
//! - Uses `DecodeLimits::zkvm()` and NEVER panics on untrusted blobs (`is_valid = false` journal).
//! - Commits `deltas_sha256 = commit_state_deltas_sha256(&contracts)`, binding EVERY field
//!   (addresses, nonces, slots, `DeltaOp` tags, full 32B operand values, and `XorShifted` masks).

use hypercomp_decoder::{
    commit_state_deltas_sha256, decompress_state_deltas_with_limits, sha256_bytes, DecodeLimits,
};
use risc0_zkvm::guest::env;

fn main() {
    // 1. Read compressed DA blob and optional pre-shared chain Zstd dictionary from RISC Zero host.
    let blob: Vec<u8> = env::read_frame();
    let dict: Vec<u8> = env::read_frame();

    // 2. Cryptographically bind raw input blob and dictionary bytes before decoding.
    let blob_sha256 = sha256_bytes(&blob);
    let (dict_opt, dict_sha256) = if dict.is_empty() {
        (None, [0u8; 32])
    } else {
        (Some(dict.as_slice()), sha256_bytes(&dict))
    };

    // 3. Deterministically decompress under strict zkVM memory & item bounds (zero panics).
    match decompress_state_deltas_with_limits(&blob, dict_opt, DecodeLimits::zkvm()) {
        Ok(contracts) => {
            let mut total_slots: u32 = 0;
            for c in &contracts {
                total_slots = total_slots.saturating_add(c.storage_deltas.len() as u32);
            }
            let deltas_sha256 = commit_state_deltas_sha256(&contracts);

            // 4. Commit complete cryptographic receipt journal.
            env::commit(&(
                blob_sha256,
                dict_sha256,
                true,
                contracts.len() as u32,
                total_slots,
                deltas_sha256,
            ));
        }
        Err(_) => {
            env::commit(&(blob_sha256, dict_sha256, false, 0u32, 0u32, [0u8; 32]));
        }
    }
}
