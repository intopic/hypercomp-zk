# `hypercomp-decoder`

Open-source, 100% deterministic, zero-panic, `#![no_std]` (`#![forbid(unsafe_code)]`) Rust decoder for **Al-Samawal Rollup HyperCompressor** state-diff frames — purpose-built for **EVM ZK-Rollups** (Bitcoin ZK-Rollups & Ethereum L2 ZK-Rollups) running inside **Succinct SP1** and **RISC Zero** (`riscv32im`).

## Key Properties

- **`#![no_std]` + `alloc` only** — zero C dependencies (`ruzstd` pure-Rust Zstd optional via `zstd-nostd` feature).
- **`#![forbid(unsafe_code)]`** — zero `unsafe` blocks anywhere in the crate.
- **32-bit RV32IM ↔ 64-bit x86_64 bit-exact parity** — all counts & indices are `u32`-bounded; U256/Rhind arithmetic uses native 32-bit limbs (`POW10` compile-time table).
- **Zero panics & OOM-bomb protection** — canonical scalar primitives (LEB128 varints, Rhind U256, `DeltaOp`), strict ascending unique `(address, slot)` enforcement, trailing-byte rejection, remaining-byte RLE guards, mandatory Zstd `Frame_Content_Size` + XXH64 checksum, SHA-256 32-byte dictionary pinning (`PrehashedDict`), and unified `DecodeLimits::CONSENSUS` (`FORMAT_VERSION = 3`).

## Quick Usage (`#![no_std]` / zkVM Guest)

```toml
[dependencies]
hypercomp-decoder = { version = "0.2", default-features = false, features = ["zstd-nostd"] }
```

```rust,no_run
use hypercomp_decoder::{
    commit_state_deltas_sha256, decompress_state_deltas_with_prehashed_dict, sha256_bytes,
    DecodeLimits, PrehashedDict,
};

/// Returns `(blob_sha256, dict_sha256, is_valid, error_code, deltas_sha256)`.
/// L1 verifier contracts MUST check `dict_sha256 == APPROVED_CHAIN_DICT_SHA256` (never `[0u8; 32]`
/// on a dictionary-enabled chain) and bind `blob_sha256` to the DA layer commitment.
pub fn verify_blob(
    blob: &[u8],
    trained_dict: Option<&[u8]>,
) -> ([u8; 32], [u8; 32], bool, u8, [u8; 32]) {
    let blob_sha256 = sha256_bytes(blob);
    let prehashed = trained_dict.map(PrehashedDict::new);
    let dict_sha256 = prehashed.map_or([0u8; 32], |d| d.id());
    match decompress_state_deltas_with_prehashed_dict(blob, prehashed, DecodeLimits::CONSENSUS) {
        Ok(contracts) => (
            blob_sha256,
            dict_sha256,
            true,
            0,
            commit_state_deltas_sha256(&contracts),
        ),
        Err(err) => (blob_sha256, dict_sha256, false, err.code(), [0u8; 32]),
    }
}
```

## Features

| Feature | Default | Description |
|---|---|---|
| `zstd-nostd` | Yes | Enables pure-Rust `#![no_std]` Zstd & Zstd+Dictionary decompression via `ruzstd`. |
| `std` | No | Implements `std::error::Error` for `HyperCompError`. |

Disable default features (`default-features = false`) for zero external dependencies when decoding `EntropyCodec::None` pre-entropy streams.

## License

Dual-licensed under **MIT** or **Apache-2.0** at your option.
