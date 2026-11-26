# Al-Samawal Rollup HyperCompressor (`hypercomp-zk`)

Open-source, 100% lossless, `#![no_std]` RISC-V (`riscv32im`) decoder, cryptographically sound zkVM guest templates (**Succinct SP1** & **RISC Zero**), public gRPC contract, and transparent real-mainnet benchmarks for **EVM ZK-Rollup** Data Availability (DA) compression (Bitcoin ZK-Rollups & Ethereum L2 ZK-Rollups).

## Repository Contents (MIT OR Apache-2.0)

```text
hypercomp-zk/
├── crates/hypercomp-decoder/      # Open-Source #![no_std], #![forbid(unsafe_code)], zero-panic RV32IM decoder (crates.io)
├── zkvm/
│   ├── riscv-guest/               # Bare-metal riscv32im-unknown-none-elf ELF benchmark guest (200 KB)
│   ├── sp1-guest/                 # Succinct SP1 v6 guest (107B journal, PrehashedDict, SHA-256 precompile patch)
│   ├── sp1-host/                  # Reproducible SP1 v6 CUDA GPU benchmark & 7-test live security suite (+ v3 fixtures)
│   ├── risc0-guest/               # RISC Zero guest committing SHA-256(blob), SHA-256(dict), validity & full delta commitment
│   └── risc0-methods/             # Builds risc0-guest via risc0-build (`cargo build --release`), exposes ELF + image ID
├── proto/hypercomp.proto          # Public gRPC interface contract for the Pro Sidecar (32B SHA-256 dict IDs)
└── docs/
    ├── MULTI_ROLLUP_MAINNET_BENCHMARK.md # Multi-chain mainnet audit (Citrea, Gnosis, Eth L1, Base, Optimism, Polygon, Taiko)
    ├── WEEK2_MAINNET_BENCHMARK.md        # Real EVM & Starknet benchmarks (37,960 diffs, Brotli q=11, A2A Updates vs Deltas)
    └── WEEK3_ZKVM_CYCLES.md              # Bare-metal RV32IM instruction counts vs Raw Zstd+Dict & ROI sensitivity matrix
```

> **Open-Core Model:** The verifier/decoder (`hypercomp-decoder`), zkVM guest integrations, wire specification, and gRPC interface in this repository are permanently open-source under **MIT OR Apache-2.0** for full auditability and zero vendor lock-in. The commercial **Pro Encoder Engine & Docker gRPC Sidecar** (`hypercomp-pro`) is licensed separately for rollups & RaaS operators.

## Verified Mainnet & Bare-Metal RV32IM Highlights (Hardened `v3` Wire Format)

- **Hardened `v3` Fresh Benchmarks (strict chronological train/test splits, zero data leakage, 32-byte SHA-256 `dict_id`, mandatory Zstd XXH64 checksum + `Frame_Content_Size`, unified `DecodeLimits::CONSENSUS`, and end-to-end `#![no_std]` + `op.apply(old) == new` verification):**
  - **Gnosis EVM Mainnet (14 unseen 10-block batches, 7,005 net slots, vs. Brotli `q=11` & `Raw Zstd + Dict`):**
    - Strictly apples-to-apples stateless **`HC Updates + Dict`** (`new_val` only): **`+17.7%` vs. Brotli `q=11`** (`+19.6%` at lvl 19) and **`+4.2%` incremental lift vs. `Raw Zstd + Dict`**.
    - Delta-DA **`HC Deltas + Dict`** (`old_val -> new_val`): **`+19.8%` vs. Brotli `q=11`** (`+21.2%` at lvl 19), **`+24.2%` vs. Zstd**, and **`+6.6%` vs. `Raw Zstd + Dict`** ([`docs/WEEK2_MAINNET_BENCHMARK.md`](docs/WEEK2_MAINNET_BENCHMARK.md)).
  - **Citrea Mainnet Sample (39 active unseen blocks, 157 net slots, 10.8 KB raw):** **`+23.0%` (`Updates`) / `+23.9%` (`Deltas`) vs. Brotli `q=11`** on uncompressed storage updates, and **`+6.0%` (`Updates`) / `+7.0%` (`Deltas`) vs. `Raw Zstd + Dict`** (rising to **`+10.9%`** on the collapsed 131-slot mega-batch; direct comparison against Citrea's internal Taproot witness format is planned for Milestone M3 — [`docs/MULTI_ROLLUP_MAINNET_BENCHMARK.md`](docs/MULTI_ROLLUP_MAINNET_BENCHMARK.md)).
- **Pre-Hardening High-Density DeFi EVM Live RPC Snapshots (`H-6r` note):** On earlier live captures (prior to the `+28 B/batch` SHA-256 `dict_id` upgrade, a `< 0.1%` delta on multi-KB batches — see [`docs/MULTI_ROLLUP_MAINNET_BENCHMARK.md`](docs/MULTI_ROLLUP_MAINNET_BENCHMARK.md)), **Ethereum L1** (`+31.9%` vs. Zstd, `+24.9%` vs. `Raw Zstd + Dict`) and **Polygon PoS** (`+14.1%` vs. `Raw Zstd + Dict`) beat `Raw Zstd + Dict` **even without any dictionary** (`+14.1%` and `+9.8%`); **Base Mainnet** (`+29.5%` vs. Zstd) and **Optimism** (`+24.2%` vs. Zstd) added `+12.9%` and `+9.7%` over `Raw Zstd + Dict`.
- **Bare-Metal RV32IM Instructions & Worst-Case zkVM Envelope (`N-1` / `N-2` / `OPT-1` / `OPT-2`):** On top of `Raw Zstd + Dict` (10-block EVM batch), stateless **`HC Updates + Dict`** executes **`-21,426` FEWER instructions (-0.2%)** and **`HC Deltas + Dict`** adds only **`+271,465` instructions (+2.8%)** while using **less guest RAM** (`514–527 KB` vs. `558 KB`). Unified `DecodeLimits::CONSENSUS` (`100k` slots, `8 MiB` pre-entropy, `8 MiB` Zstd window, `16 MiB` calibrated output @ `144 B/slot`, mandatory `Frame_Content_Size` with single `Vec::with_capacity`) bounds worst-case *cumulative* bump-allocator RAM to **`~50–51 MiB`**, well inside the benchmark guest's **96 MiB** heap (zkVM guests should provision `>= 96 MiB`), and worst-case HC structural decode to **`~226M` RV32IM instructions** (end-to-end GPU proving on SP1/RISC Zero is scoped to Milestone M2 — [`docs/WEEK3_ZKVM_CYCLES.md`](docs/WEEK3_ZKVM_CYCLES.md)).
- **Mandatory zkVM Verifier Policy (`C-2r`):** Both `zkvm/sp1-guest` and `zkvm/risc0-guest` share the exact same **107-byte big-endian public journal**, hash the dictionary **once** (`PrehashedDict`), never abort on blob content (every decode error — including `MissingDictionary` / `DictionaryIdMismatch` — is committed as `is_valid = false` with its `error_code`, so blobs referencing unapproved dictionaries are provably invalid instead of unprovable), and require the L1 verifier contract to enforce `journal.dict_sha256 == APPROVED_CHAIN_DICT_SHA256` plus KZG (EIP-4844) or Bitcoin light-client DA blob inclusion.

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
