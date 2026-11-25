# `hypercomp-decoder`

Open-source, 100% deterministic, zero-panic, `#![no_std]` (`#![forbid(unsafe_code)]`) Rust decoder for **Al-Samawal Rollup HyperCompressor** state-diff frames — purpose-built for **EVM ZK-Rollups** (Bitcoin ZK-Rollups & Ethereum L2 ZK-Rollups) running inside **Succinct SP1** and **RISC Zero** (`riscv32im`).

## Key Properties

- **`#![no_std]` + `alloc` only** — zero C dependencies (`ruzstd` pure-Rust Zstd optional via `zstd-nostd` feature).
- **`#![forbid(unsafe_code)]`** — zero `unsafe` blocks anywhere in the crate.
- **32-bit RV32IM ↔ 64-bit x86_64 bit-exact parity** — all counts & indices are `u32`-bounded; U256/Rhind arithmetic uses native 32-bit limbs (`POW10` compile-time table).
- **Zero panics & OOM-bomb protection** — canonical scalar primitives (LEB128 varints, Rhind U256, `DeltaOp`), strict ascending unique `(address, slot)` enforcement, trailing-byte rejection, remaining-byte RLE guards, mandatory Zstd XXH64 checksum, SHA-256 32-byte dictionary pinning, and `DecodeLimits::zkvm()`.

## Quick Usage (`#![no_std]` / zkVM Guest)

```toml
[dependencies]
hypercomp-decoder = { version = "0.2", default-features = false, features = ["zstd-nostd"] }
```

```rust,no_run
use hypercomp_decoder::{
    commit_state_deltas_sha256, decompress_state_deltas_with_limits, sha256_bytes, DecodeLimits,
};

pub fn verify_blob(blob: &[u8], trained_dict: Option<&[u8]>) -> ([u8; 32], bool, [u8; 32]) {
    let blob_hash = sha256_bytes(blob);
    match decompress_state_deltas_with_limits(blob, trained_dict, DecodeLimits::zkvm()) {
        Ok(contracts) => (blob_hash, true, commit_state_deltas_sha256(&contracts)),
        Err(_) => (blob_hash, false, [0u8; 32]),
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
