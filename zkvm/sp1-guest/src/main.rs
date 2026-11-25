//! Succinct SP1 v6 zkVM Guest Program for Al-Samawal Rollup HyperCompressor (`FORMAT_VERSION = 3`).
//!
//! Build with Succinct SP1 toolchain:
//!   `cd zkvm/sp1-guest && cargo prove build`
//! (Or automatically via `cd zkvm/sp1-host && cargo run --release -- --mode prove`)
//!
//! ## Fixed 107-Byte Canonical Public Journal Layout (Big-Endian, ABI-friendly)
//! - `[0..1]`    `mode: u8` (`0` = HC `StateDeltas`, `1` = HC `StateUpdates`, `2` = Raw Zstd `StateUpdates` baseline)
//! - `[1..33]`   `blob_sha256: [u8; 32]` (`SHA-256(blob)`)
//! - `[33..65]`  `dict_sha256: [u8; 32]` (`SHA-256(dict)`, or `[0u8; 32]` when `dict` is empty)
//! - `[65..66]`  `is_valid: u8` (`1` = valid, `0` = intrinsic blob rejection)
//! - `[66..67]`  `error_code: u8` (`0` = ok, `1..=19` = `HyperCompError::code()`)
//! - `[67..71]`  `num_contracts: u32` (BE)
//! - `[71..75]`  `total_slots: u32` (BE)
//! - `[75..107]` `payload_sha256: [u8; 32]` (`commit_state_deltas_sha256` or `commit_state_updates_sha256`)
//!
//! ## Mandatory On-Chain Verifier Policy (`C-2r`)
//! Any L1 verifier contract accepting proofs from this guest **MUST** enforce:
//! 1. **Mode Binding:** `journal.mode == EXPECTED_CHAIN_MODE` (`0` for Delta-DA or `1` for Updates-DA).
//! 2. **Dictionary Binding:** `journal.dict_sha256 == APPROVED_CHAIN_DICT_SHA256` (NEVER accept
//!    `[0u8; 32]` on a dictionary-enabled chain).
//! 3. **DA Blob Binding:** `journal.blob_sha256 == SHA-256(blob)` binds raw DA bytes:
//!    - On **Ethereum EIP-4844**, pair with a KZG point-evaluation / equivalence proof linking
//!      `blob_sha256` to the EIP-4844 blob `versioned_hash`.
//!    - On **Bitcoin (e.g. Citrea)**, pair with a Bitcoin light-client Taproot witness inclusion proof.
//! 4. **Prover-Fault Separation:** Prover-controlled dictionary witness faults (`MissingDictionary`,
//!    `DictionaryIdMismatch`) **abort proving** instead of committing `is_valid = 0`, so a
//!    malicious prover can NEVER suppress an honest batch by withholding/swapping the dictionary.
//!    Intrinsic blob defects commit `(is_valid = 0, error_code = err.code())` cleanly.
//! 5. **Consensus Limit Parity (`N-1` / `N-2`):** Enforces `DecodeLimits::CONSENSUS` identically to
//!    encoder, sidecar, and full nodes (`100k` slots, `8 MiB` pre-entropy, `8 MiB` Zstd window,
//!    `16 MiB` calibrated output, mandatory `Frame_Content_Size` + XXH64 checksum).

#![no_main]
sp1_zkvm::entrypoint!(main);

use hypercomp_decoder::{
    commit_state_deltas_sha256, commit_state_updates_sha256,
    decompress_state_deltas_with_prehashed_dict, decompress_state_updates_with_prehashed_dict,
    sha256_bytes, unwrap_frame_with_prehashed_dict, ContractDiff, DecodeLimits, HyperCompError,
    PayloadKind, PrehashedDict,
};

pub const MODE_HC_DELTAS: u8 = 0;
pub const MODE_HC_UPDATES: u8 = 1;
pub const MODE_RAW_ZSTD_UPDATES: u8 = 2;

fn pack_journal(
    mode: u8,
    blob_sha256: [u8; 32],
    dict_sha256: [u8; 32],
    is_valid: bool,
    error_code: u8,
    num_contracts: u32,
    total_slots: u32,
    payload_sha256: [u8; 32],
) -> [u8; 107] {
    let mut out = [0u8; 107];
    out[0] = mode;
    out[1..33].copy_from_slice(&blob_sha256);
    out[33..65].copy_from_slice(&dict_sha256);
    out[65] = u8::from(is_valid);
    out[66] = error_code;
    out[67..71].copy_from_slice(&num_contracts.to_be_bytes());
    out[71..75].copy_from_slice(&total_slots.to_be_bytes());
    out[75..107].copy_from_slice(&payload_sha256);
    out
}

pub fn main() {
    // 1. Read decode mode, raw DA blob bytes, and optional pre-shared chain dictionary from SP1 stdin.
    let mode: u8 = sp1_zkvm::io::read();
    let blob: Vec<u8> = sp1_zkvm::io::read_vec();
    let dict: Vec<u8> = sp1_zkvm::io::read_vec();

    // 2. Cryptographically bind raw blob and hash dictionary ONCE via `PrehashedDict` (`N-5`).
    let blob_sha256 = sha256_bytes(&blob);
    let prehashed_dict = if dict.is_empty() {
        None
    } else {
        Some(PrehashedDict::new(&dict))
    };
    let dict_sha256 = prehashed_dict.map_or([0u8; 32], |d| d.id());

    // 3. Deterministically decompress under unified consensus limits (`DecodeLimits::CONSENSUS`).
    let outcome: Result<(u32, u32, [u8; 32]), HyperCompError> = match mode {
        MODE_HC_DELTAS => decompress_state_deltas_with_prehashed_dict(
            &blob,
            prehashed_dict,
            DecodeLimits::CONSENSUS,
        )
        .map(|contracts| {
            let mut total_slots: u32 = 0;
            for c in &contracts {
                total_slots = total_slots.saturating_add(c.storage_deltas.len() as u32);
            }
            (
                contracts.len() as u32,
                total_slots,
                commit_state_deltas_sha256(&contracts),
            )
        }),
        MODE_HC_UPDATES => decompress_state_updates_with_prehashed_dict(
            &blob,
            prehashed_dict,
            DecodeLimits::CONSENSUS,
        )
        .map(|contracts| {
            let mut total_slots: u32 = 0;
            for c in &contracts {
                total_slots = total_slots.saturating_add(c.storage_updates.len() as u32);
            }
            (
                contracts.len() as u32,
                total_slots,
                commit_state_updates_sha256(&contracts),
            )
        }),
        MODE_RAW_ZSTD_UPDATES => unwrap_frame_with_prehashed_dict(
            &blob,
            PayloadKind::StateUpdates,
            prehashed_dict,
            DecodeLimits::CONSENSUS,
        )
        .and_then(|raw| ContractDiff::from_raw_bytes(&raw, DecodeLimits::CONSENSUS))
        .map(|contracts| {
            let mut total_slots: u32 = 0;
            for c in &contracts {
                total_slots = total_slots.saturating_add(c.storage_updates.len() as u32);
            }
            (
                contracts.len() as u32,
                total_slots,
                commit_state_updates_sha256(&contracts),
            )
        }),
        other => Err(HyperCompError::InvalidFlags(other)),
    };

    // 4. Commit canonical 107-byte journal (or abort proving on prover-supplied witness fault).
    match outcome {
        Ok((num_contracts, total_slots, payload_sha256)) => {
            let journal = pack_journal(
                mode,
                blob_sha256,
                dict_sha256,
                true,
                0,
                num_contracts,
                total_slots,
                payload_sha256,
            );
            sp1_zkvm::io::commit_slice(&journal);
        }
        Err(err) => {
            assert!(
                !err.is_prover_witness_error(),
                "prover supplied missing or mismatched Zstd dictionary witness"
            );
            let journal = pack_journal(
                mode,
                blob_sha256,
                dict_sha256,
                false,
                err.code(),
                0,
                0,
                [0u8; 32],
            );
            sp1_zkvm::io::commit_slice(&journal);
        }
    }
}
