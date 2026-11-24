# Al-Samawal Rollup HyperCompressor (`hypercomp-zk`)

Open-source, 100% lossless, `#![no_std]` RISC-V (`riscv32im`) decoder, zkVM guest templates (**Succinct SP1** & **RISC Zero**), public gRPC contract, and reproducible real-mainnet benchmarks for **EVM ZK-Rollup** Data Availability (DA) compression (Bitcoin ZK-Rollups such as **Citrea** & Ethereum L2 ZK-Rollups).

## Repository Contents (MIT OR Apache-2.0)

```text
hypercomp-zk/
├── crates/hypercomp-decoder/      # Open-Source #![no_std], #![forbid(unsafe_code)], zero-panic RV32IM decoder (crates.io)
├── zkvm/
│   ├── riscv-guest/               # Bare-metal riscv32im-unknown-none-elf ELF benchmark guest (176 KB)
│   ├── sp1-guest/                 # Succinct SP1 drop-in guest template
│   └── risc0-guest/               # RISC Zero drop-in guest template
├── proto/hypercomp.proto          # Public gRPC interface contract for the Pro Sidecar
└── docs/
    ├── WEEK2_MAINNET_BENCHMARK.md # Verified EVM & Starknet mainnet benchmarks (37,960 real state diffs)
    └── WEEK3_ZKVM_CYCLES.md       # Exact RV32IM cycle counts vs. Raw Zstd & Raw Zstd+Dict + Proving ROI
```

> **Open-Core Model:** The verifier/decoder (`hypercomp-decoder`), zkVM guest integrations, wire specification, and gRPC interface in this repository are permanently open-source under **MIT OR Apache-2.0** for full auditability and zero vendor lock-in. The commercial **Pro Encoder Engine & Docker gRPC Sidecar** (`hypercomp-pro`) is licensed separately for rollups & RaaS operators.

## Verified Real EVM Mainnet Highlights

- **L1 DA Reduction (14 unseen 10-block EVM mainnet batches):** **+24.4% vs. Zstd**, **+23.3% vs. Brotli**, and **+6.8% incremental reduction on top of `Raw Zstd + 112KB Trained Dict`** (full transparent attribution in [`docs/WEEK2_MAINNET_BENCHMARK.md`](docs/WEEK2_MAINNET_BENCHMARK.md)).
- **RV32IM zkVM Proving Cost (real bare-metal 176 KB ELF):** Only **+11.1% incremental cycles** (`+340,531` cyc) and **less guest RAM** (`527 KB` vs `558 KB`) compared to `Raw Zstd + Dict` → **344× – 860× incremental ROI** on Bitcoin DA and **34× – 86× incremental ROI** on Ethereum peak blobs ([`docs/WEEK3_ZKVM_CYCLES.md`](docs/WEEK3_ZKVM_CYCLES.md)).

## Quick Start

### 1. Add the Open-Source `no_std` Decoder to Your zkVM Guest

```toml
[dependencies]
hypercomp-decoder = { version = "0.2", default-features = false, features = ["zstd-nostd"] }
```

### 2. Verify Locally (Tests + Bare-Metal RISC-V Build)

```bash
cargo test --workspace
rustup target add riscv32im-unknown-none-elf
cargo check -p hypercomp-decoder --target riscv32im-unknown-none-elf --no-default-features --features zstd-nostd
cargo build --release --manifest-path zkvm/riscv-guest/Cargo.toml
```

### 3. Benchmark Your Own EVM Rollup Live (Prebuilt CLI)

Download the prebuilt `hypercomp` binary for **Linux, macOS, or Windows** from **GitHub Releases** and audit your live RPC in one command:

```bash
hypercomp audit-rpc \
  --rpc https://your-evm-rollup-rpc \
  --blocks 40 --batch-size 10 \
  --da-asset BTC --da-cost-per-mb 0.0055 --usd-per-asset 95000
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
