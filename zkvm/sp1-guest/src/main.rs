//! Succinct SP1 zkVM Guest Program for Al-Samawal Rollup HyperCompressor.
//!
//! Build with Succinct SP1 toolchain:
//!   `cd zkvm/sp1-guest && cargo prove build`
//!
//! Soundness guarantees:
//! - Commits `blob_sha256 = SHA-256(blob)` so the on-chain verifier binds the proof
//!   directly to the posted DA blob bytes (EIP-4844 / Bitcoin witness commitment).
//! - Commits `dict_sha256 = SHA-256(dict)` (or `[0u8; 32]` when no dictionary is used)
//!   so the verifier binds the proof to the approved pre-shared chain dictionary.
//! - Uses `DecodeLimits::zkvm()` and NEVER panics (`.expect()`-free): malformed blobs
//!   commit `is_valid = false` cleanly so permissionless DA chains never halt.
//! - Commits `deltas_sha256 = commit_state_deltas_sha256(&contracts)`, binding EVERY
//!   decoded contract address, nonce, storage slot, `DeltaOp` discriminant, and full value.

#![no_main]
sp1_zkvm::entrypoint!(main);

use hypercomp_decoder::{
    commit_state_deltas_sha256, decompress_state_deltas_with_limits, sha256_bytes, DecodeLimits,
};

pub fn main() {
    // 1. Read compressed DA blob and optional pre-shared chain Zstd dictionary from SP1 stdin.
    let blob: Vec<u8> = sp1_zkvm::io::read_vec();
    let dict: Vec<u8> = sp1_zkvm::io::read_vec();

    // 2. Cryptographically bind the raw input blob and dictionary bytes before decoding.
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

            // 4. Commit complete cryptographic journal for on-chain DA + STF verification.
            sp1_zkvm::io::commit(&blob_sha256);
            sp1_zkvm::io::commit(&dict_sha256);
            sp1_zkvm::io::commit(&true);
            sp1_zkvm::io::commit(&(contracts.len() as u32));
            sp1_zkvm::io::commit(&total_slots);
            sp1_zkvm::io::commit(&deltas_sha256);
        }
        Err(_) => {
            // Invalid/malformed permissionless DA blob: commit explicit rejection without halting.
            sp1_zkvm::io::commit(&blob_sha256);
            sp1_zkvm::io::commit(&dict_sha256);
            sp1_zkvm::io::commit(&false);
            sp1_zkvm::io::commit(&0u32);
            sp1_zkvm::io::commit(&0u32);
            sp1_zkvm::io::commit(&[0u8; 32]);
        }
    }
}
