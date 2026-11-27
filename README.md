# Al-Samawal Rollup HyperCompressor (`hypercomp-zk`)

Open-source, 100% lossless, `#![no_std]` RISC-V (`riscv32im`) decoder, cryptographically sound zkVM guest templates (**Succinct SP1** & **RISC Zero**), public gRPC contract, and transparent real-mainnet benchmarks for **EVM ZK-Rollup** Data Availability (DA) compression (Bitcoin ZK-Rollups & Ethereum L2 ZK-Rollups).

## Repository Contents (MIT OR Apache-2.0)

```text
hypercomp-zk/
├── crates/hypercomp-decoder/      # Open-source #![no_std], #![forbid(unsafe_code)], zero-panic RV32IM decoder (crates.io)
├── zkvm/
│   ├── riscv-guest/               # Bare-metal riscv32im-unknown-none-elf benchmark guest
│   ├── sp1-guest/                 # Succinct SP1 v6 guest (107 B journal, PrehashedDict, SHA-256 precompile patch)
│   ├── sp1-host/                  # SP1 v6 execute/GPU-prove harness, 7 live security tests, mainnet fixtures
│   ├── risc0-guest/               # RISC Zero guest with the same 107 B journal
│   └── risc0-methods/             # Builds risc0-guest via risc0-build, exposes ELF + image ID
├── benchmarks/                    # Measured results (Nov 2026): data files, scripts, methodology
├── proto/hypercomp.proto          # Public gRPC interface contract for the Pro sidecar
└── docs/archive/                  # Superseded early benchmark write-ups (history only)
```

> **Open-Core Model:** The verifier/decoder (`hypercomp-decoder`), zkVM guest integrations, wire specification, and gRPC interface in this repository are permanently open-source under **MIT OR Apache-2.0** for full auditability and zero vendor lock-in. The commercial **Pro Encoder Engine & Docker gRPC Sidecar** (`hypercomp-pro`) is licensed separately for rollups & RaaS operators.

## Measured Results (November 2026)

All figures are measured on real mainnet data with chronological train/test splits and are reproducible from
[`benchmarks/`](benchmarks/README.md). Highlights:

- **EVM state diffs at each rollup's real batch size** (Base 161, OP Mainnet 63, Unichain 452 L2 blocks): HC beats the
  strongest do-it-yourself baseline, **Zstd + trained chain dictionary**, by **+3.9% to +8.2%** (`StateUpdates`) and
  **+7.7% to +12.8%** (`StateDeltas`); against plain Zstd / Brotli q=11 by **+8% to +22%**.
- **Citrea (Bitcoin):** Citrea's current DA payload uses hashed storage keys and 256 block hashes per proof; on it a
  trained Zstd dictionary alone gives **+6.9%** and HC adds nothing. Citrea's measured DA bill is **~$155/day** (~$242/MB).
- **Alpen (Bitcoin Signet):** Alpen posts plain `(address, slot, value)` diffs uncompressed; a trained Zstd
  dictionary alone shrinks them by **68.4%**, and at its current ~12 slots per batch HC adds nothing on top.
- **Ethereum blob DA:** Base, the largest blob user, paid a mean **$269/day** for blobs over 7 days (range $19–$840/day).
- **Every fixture is executed inside the real SP1 v6 zkVM in CI** with exact 107-byte journal parity; HC Updates needs
  5–31% fewer SP1 cycles than Zstd + Dict on 6 of 7 chains (+4.4% on Polygon). Real GPU proving has not yet been run.
- **Decoder safety envelope:** unified `DecodeLimits::CONSENSUS` (100k slots, 8 MiB pre-entropy, 8 MiB Zstd window,
  16 MiB output, mandatory `Frame_Content_Size` + XXH64) bounds worst-case cumulative bump-allocator RAM to ~50–51 MiB;
  zkVM guests should provision >= 96 MiB.
- **zkVM verifier policy (`C-2r`):** both guests commit every decode error as `is_valid = false` with its `error_code`
  (blobs referencing unapproved dictionaries are provably invalid, never unprovable); the L1 verifier must enforce
  `journal.dict_sha256 == APPROVED_CHAIN_DICT_SHA256` plus KZG (EIP-4844) or Bitcoin light-client DA inclusion.

See [`benchmarks/README.md`](benchmarks/README.md) for where HC does **not** help and what switching from transaction
data to state-diff DA implies for a rollup.

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
