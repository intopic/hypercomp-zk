//! # Al-Samawal Rollup HyperCompressor — Open-Source `no_std` Decoder
//!
//! 100% deterministic, zero-panic, strictly canonical decoder for ZK-Rollup state diffs,
//! designed for off-chain L2 nodes and RISC-V zkVMs (`Succinct SP1`, `RISC Zero`).
//!
//! ## Safety & Soundness Guarantees
//! - **`#![no_std]` + `alloc` only** — zero C dependencies (`ruzstd` pure-Rust Zstd optional).
//! - **32-bit RISC-V (`riscv32im`) exact parity** — all counts & indices are `u32`-bounded.
//! - **Zero panics on untrusted input** — checked arithmetic, explicit decode & bomb limits.
//! - **Strict canonical bijection** — rejects overlong varints, trailing bytes, non-minimal U256,
//!   overflowing exponents, and non-optimal Rhind representations.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod dict;
pub mod error;
pub mod header;
pub mod poly;
pub mod rhind;
pub mod state_diff;
pub mod u256;
pub mod varint;

pub use error::HyperCompError;
pub use header::{
    compute_dict_id, EntropyCodec, PayloadKind, WireHeader, FORMAT_VERSION, MAGIC,
    MAX_DECOMPRESSED_BYTES, MAX_DECODE_ITEMS,
};
pub use poly::{alsamawal_poly_decode, alsamawal_poly_decode_exact};
pub use rhind::{delta_decode_column, rhind_decode_column, rhind_decode_u256, DeltaOp};
pub use state_diff::{
    decode_starknet_deltas_raw, decode_starknet_updates_raw, decode_state_deltas_raw,
    decode_state_transitions_raw, decode_state_updates_raw, decompress_starknet_deltas,
    decompress_starknet_updates, decompress_state_deltas, decompress_state_deltas_with_limits,
    decompress_state_transitions, decompress_state_transitions_with_limits,
    decompress_state_updates, decompress_state_updates_with_limits, unwrap_frame, ContractDelta,
    ContractDiff, DecodeLimits, StarknetContractDelta, StarknetContractDiff, StateDiff,
    StorageDelta, StorageUpdate,
};
pub use u256::{MAX_POW10_EXP, POW10, U256};
pub use varint::{
    decode_count, decode_varint_u128, decode_varint_u32, decode_varint_u64, zigzag_decode,
    zigzag_encode,
};
