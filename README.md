# Al-Samawal Rollup HyperCompressor (`hypercomp-zk`)

Open-source, 100% lossless, `#![no_std]` RISC-V (`riscv32im`) decoder, cryptographically sound zkVM guest templates (**Succinct SP1** & **RISC Zero**), public gRPC contract, and transparent real-mainnet benchmarks for **EVM ZK-Rollup** Data Availability (DA) compression (Bitcoin ZK-Rollups & Ethereum L2 ZK-Rollups).

## Repository Contents (MIT OR Apache-2.0)

```text
hypercomp-zk/
├── crates/hypercomp-decoder/      # Open-Source #![no_std], #![forbid(unsafe_code)], zero-panic RV32IM decoder (crates.io)
├── zkvm/
│   ├── riscv-guest/               # Bare-metal riscv32im-unknown-none-elf ELF benchmark guest (198 KB)
│   ├── sp1-guest/                 # Succinct SP1 guest committing SHA-256(blob), SHA-256(dict), validity & full delta commitment
│   └── risc0-guest/               # RISC Zero guest committing SHA-256(blob), SHA-256(dict), validity & full delta commitment
├── proto/hypercomp.proto          # Public gRPC interface contract for the Pro Sidecar (32B SHA-256 dict IDs)
└── docs/
    ├── MULTI_ROLLUP_MAINNET_BENCHMARK.md # Multi-chain mainnet audit (Citrea, Gnosis, Eth L1, Base, Optimism, Polygon, Taiko)
    ├── WEEK2_MAINNET_BENCHMARK.md        # Real EVM & Starknet benchmarks (37,960 diffs, Brotli q=11, A2A Updates vs Deltas)
    └── WEEK3_ZKVM_CYCLES.md              # Bare-metal RV32IM instruction counts vs Raw Zstd+Dict & ROI sensitivity matrix
```

> **Open-Core Model:** The verifier/decoder (`hypercomp-decoder`), zkVM guest integrations, wire specification, and gRPC interface in this repository are permanently open-source under **MIT OR Apache-2.0** for full auditability and zero vendor lock-in. The commercial **Pro Encoder Engine & Docker gRPC Sidecar** (`hypercomp-pro`) is licensed separately for rollups & RaaS operators.

## Verified Mainnet & Bare-Metal RV32IM Highlights (Hardened v0.2 Format)

All results below use strict chronological train/test splits (**zero data leakage**), 32-byte SHA-256 `dict_id` pinning, mandatory Zstd XXH64 checksums, and end-to-end `#![no_std]` + `op.apply(old) == new` verification:

- **Gnosis EVM Mainnet (14 unseen 10-block batches, 7,005 net slots, vs. Brotli `q=11` & `Raw Zstd + Dict`):**
  - Strictly apples-to-apples stateless **`HC v2 Updates + Dict`** (`new_val` only): **`+17.7%` vs. Brotli `q=11`** (`+19.6%` at lvl 19) and **`+4.2%` incremental lift vs. `Raw Zstd + Dict`**.
  - Delta-DA **`HC v2 Deltas + Dict`** (`old_val -> new_val`): **`+19.8%` vs. Brotli `q=11`** (`+21.2%` at lvl 19), **`+24.2%` vs. Zstd**, and **`+6.6%` vs. `Raw Zstd + Dict`** ([`docs/WEEK2_MAINNET_BENCHMARK.md`](docs/WEEK2_MAINNET_BENCHMARK.md)).
- **Citrea Mainnet Sample (39 active unseen blocks, 157 net slots, 10.8 KB raw):** **`+23.0%` (`Updates`) / `+23.9%` (`Deltas`) vs. Brotli `q=11`** on uncompressed storage updates, and **`+6.0%` (`Updates`) / `+7.0%` (`Deltas`) vs. `Raw Zstd + Dict`** (rising to **`+10.9%`** on the collapsed 131-slot mega-batch; direct comparison against Citrea's internal Taproot witness format is planned for Milestone M3 — [`docs/MULTI_ROLLUP_MAINNET_BENCHMARK.md`](docs/MULTI_ROLLUP_MAINNET_BENCHMARK.md)).
- **High-Density DeFi EVM Live Snapshots:** On **Ethereum L1** (`+31.9%` vs. Zstd, `+24.9%` vs. `Raw Zstd + Dict`) and **Polygon PoS** (`+14.1%` vs. `Raw Zstd + Dict`), `HC v2` beats `Raw Zstd + Dict` **even without any dictionary** (`+14.1%` and `+9.8%`). On **Base Mainnet** (`+29.5%` vs. Zstd) and **Optimism** (`+24.2%` vs. Zstd), Delta-DA adds `+12.9%` and `+9.7%` over `Raw Zstd + Dict`.
- **Bare-Metal RV32IM Instructions (198 KB ELF, 10-block EVM batch):** On top of `Raw Zstd + Dict` (both paying the exact same dictionary SHA-256 + `decode_dict` cost), stateless **`HC Updates + Dict`** adds only **`+25,021` instructions (+0.3%)** and **`HC Deltas + Dict`** adds **`+331,508` instructions (+3.4%)** while using **less guest RAM** (`514–527 KB` vs. `558 KB`) — excluding zkVM paging/sharding, measured end-to-end on SP1/RISC Zero GPUs in Milestone M2 ([`docs/WEEK3_ZKVM_CYCLES.md`](docs/WEEK3_ZKVM_CYCLES.md)).

## Quick Start

### 1. Add the Open-Source `no_std` Decoder to Your zkVM Guest

```toml
[dependencies]
hypercomp-decoder = { version = "0.2", default-features = false, features = ["zstd-nostd"] }
```

### 2. Verify Locally (Adversarial & PoC Tests + Clippy + Bare-Metal RISC-V Build)

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
rustup target add riscv32im-unknown-none-elf
cargo check -p hypercomp-decoder --target riscv32im-unknown-none-elf --no-default-features
cargo check -p hypercomp-decoder --target riscv32im-unknown-none-elf --no-default-features --features zstd-nostd
(cd zkvm/riscv-guest && cargo build --release)
```

### 3. Benchmark Your Own EVM Rollup Live (Prebuilt CLI)

Download the prebuilt `hypercomp` binary for **Linux, macOS, or Windows** from **GitHub Releases** and audit your live RPC in one command:

```bash
hypercomp audit-rpc \
  --rpc https://rpc.mainnet.citrea.xyz \
  --blocks 40 --batch-size 10 \
  --da-asset BTC --da-cost-per-mb 0.0055 --usd-per-asset 95000
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
