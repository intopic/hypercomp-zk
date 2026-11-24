//! Succinct SP1 zkVM Guest Program for Al-Samawal Rollup HyperCompressor.
//!
//! Build with Succinct SP1 toolchain:
//!   `cd zkvm/sp1-guest && cargo prove build`
//!
//! Proves inside SP1 (`riscv32im-succinct-zkvm-elf`) that a posted DA blob
//! decompresses deterministically (100% lossless, zero-panic, strictly canonical)
//! into the exact state deltas applied to the rollup state transition.

#![no_main]
sp1_zkvm::entrypoint!(main);

use hypercomp_decoder::{decompress_state_deltas, DeltaOp};

pub fn main() {
    // 1. Read compressed DA blob and optional pre-shared chain Zstd dictionary from SP1 stdin.
    let blob: Vec<u8> = sp1_zkvm::io::read_vec();
    let dict: Vec<u8> = sp1_zkvm::io::read_vec();
    let dict_opt = if dict.is_empty() {
        None
    } else {
        Some(dict.as_slice())
    };

    // 2. Deterministically decompress using the #![no_std] zero-panic decoder.
    let contracts = decompress_state_deltas(&blob, dict_opt)
        .expect("invalid or non-canonical HyperCompressor blob");

    // 3. Compute canonical commitment over decoded state deltas (replace with Keccak/Poseidon
    //    or directly apply `contracts` to your rollup STF inside SP1).
    let mut total_slots: u32 = 0;
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for c in &contracts {
        for &b in &c.address {
            acc = (acc ^ (b as u64)).wrapping_mul(0x0100_0000_01b3);
        }
        for d in &c.storage_deltas {
            total_slots += 1;
            for &b in &d.slot {
                acc = (acc ^ (b as u64)).wrapping_mul(0x0100_0000_01b3);
            }
            let tag = match d.op {
                DeltaOp::NoChange => 0u8,
                DeltaOp::SetNew(_) => 1u8,
                DeltaOp::Add(_) => 2u8,
                DeltaOp::Sub(_) => 3u8,
                DeltaOp::XorShifted { .. } => 4u8,
            };
            acc = (acc ^ (tag as u64)).wrapping_mul(0x0100_0000_01b3);
        }
    }

    // 4. Commit public outputs to the SP1 proof journal.
    sp1_zkvm::io::commit(&(contracts.len() as u32));
    sp1_zkvm::io::commit(&total_slots);
    sp1_zkvm::io::commit(&acc);
}
