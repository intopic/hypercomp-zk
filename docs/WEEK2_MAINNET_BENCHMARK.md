# Al-Samawal Rollup HyperCompressor v0.2 — Week 2 Real-Mainnet Benchmark Report

**Date:** 2026-11-25 (Updated for v0.2 Hardened Wire Format — 32-byte SHA-256 `dict_id` + Mandatory XXH64 Checksum)  
**Primary Focus:** **EVM ZK-Rollups** (Bitcoin ZK-Rollups & Ethereum L2 ZK-Rollups)  
**Engine:** `hypercomp-encoder` v0.2.0 + Open-Source `#![no_std]` `hypercomp-decoder` v0.2.0 (`#![forbid(unsafe_code)]`, pure-Rust `ruzstd` verification)

> **100% Transparent Attribution (EVM Mainnet — 14 Unseen 10-Block Batches, Zstd Level 9 & 19 vs. Brotli `q=6` & `q=11`):**
> - **Strictly Apples-to-Apples Stateless Mode (`HC v2 Updates + Dict` vs. `Raw Zstd + Dict`, identical `new_val`-only inputs):** **`+4.2%`** incremental byte reduction at Zstd lvl 9 (**`+17.7%` vs. Brotli `q=11`**, `+21.1%` vs. Brotli `q=6`, `+22.2%` vs. plain Zstd lvl 9); at Zstd lvl 19: **`+3.9%` vs. `Raw Zstd + Dict`** (**`+19.6%` vs. Brotli `q=11`**).
> - **Delta-DA Mode (`HC v2 Deltas + Dict`, uses `old_val -> new_val` like ZKsync Era L1 pubdata delta compression):** **`+6.6%`** vs. `Raw Zstd + Dict` at lvl 9 (**`+19.8%` vs. Brotli `q=11`**, `+23.2%` vs. Brotli `q=6`, `+24.2%` vs. plain Zstd); at lvl 19: **`+21.2%` vs. Brotli `q=11`** and `+24.5%` vs. Brotli `q=6`.
> - **Dictionary vs. Structural Breakdown:** Adopting a 112 KB chain-specific trained Zstd dictionary alone (`Raw Zstd + Dict` vs. plain `Zstd`) accounts for `+18.8%` (lvl 9) / `+19.4%` (lvl 19). On top of that, HyperComp adds **`+4.2%`** (stateless `Updates`, strictly apples-to-apples) or **`+6.6%`** (Delta-DA `Deltas`), even after paying `+28 B/batch` for cryptographic 32-byte SHA-256 dictionary IDs.
> - **Secondary Non-EVM Reference (Starknet Mainnet):** Included below for completeness; on Starknet Cairo storage, the trained dictionary accounts for ~34% vs. plain Zstd/Brotli while stateless structural lift is `+0.8%` vs. `Raw Zstd + Dict` (`-1.3%` on the 146-block Delta-DA tail after 32-byte SHA-256 `dict_id` overhead), confirming **EVM ZK-Rollups** as our highest-leverage engineering and GTM target.

---

## 1. Datasets & Reproducibility Methodology (Zero Data Leakage)

All benchmarks were executed on **37,960 real, unmodified mainnet state diffs** fetched directly from public production RPC nodes (`prestateTracer` with `diffMode=true` on EVM; `starknet_getStateUpdate` + `starknet_getStorageAt` on Starknet):

| Dataset | Network & RPC | Block Range | Blocks | Total State Diffs | Unique Contracts | Unique Slots | Fixture SHA-256 |
|---|---|---|---:|---:|---:|---:|---|
| **Dataset 1 (EVM)** | Gnosis Chain Mainnet (EVM, Chain ID 100)<br>`https://rpc.gnosischain.com` | `49442959..=49443166` | 208 | **22,666** | 824 | 5,580 | `b37bd7ac222dfed1c382ae1d383ed4dac81d2e7ba513f49426b77c68741c6287` |
| **Dataset 2 (Cairo)** | Starknet Mainnet (Cairo ZK-Rollup)<br>`https://starknet-rpc.publicnode.com` | `18460603..=18461722` | 1,120 | **15,294**<br>*(3,337 w/ real `old_val`)* | 308 | 4,149 | `7eeb0618824e1cc62c34b8c874519ae441200b401a3b28da7156c24ebba5e1e2` |

### Strict Chronological Split & Fair Baselines
- **Zero train/test leakage:** Chain-specific 112 KB Zstd dictionaries are trained **strictly on earlier historical blocks** and evaluated **strictly on later unseen blocks**:
  - **EVM Mainnet:** Train = blocks `49442959..=49443027` (69 blocks, 10,419 transitions) → **Unseen Test = blocks `49443028..=49443166` (139 blocks, 12,247 transitions)**.
  - **Starknet Mainnet:** Train = blocks `18460603..=18461422` (820 blocks) → **Unseen Test = blocks `18461423..=18461722` (300 blocks)**.
- **Baselines included:** Plain `Zstd` (lvl 9 & lvl 19), `Brotli` (`q=6` AND max-quality `q=11`), and `Raw Zstd + 112 KB Trained Dictionary` trained on the exact same historical blocks over canonical uncompressed storage updates (`ContractDiff::to_raw_bytes`).
- **Scope note on prior art & production formats:** Existing ZK-Rollups such as **ZKsync Era** (state-diff pubdata compression), **Citrea** (stateful state-diff encoding + Brotli), and **Starknet** already apply rollup-specific state-diff encodings prior to entropy coding. The baselines below measure canonical uncompressed EVM storage updates (`20B addr + nonce + count + N * 64B (slot, val)`); direct benchmarks against partner rollups' internal DA wire formats are scoped for Milestone M3.
- **100% End-to-End Lossless Verification:** Every compressed blob is decoded via `#![no_std]` `hypercomp-decoder` (`ruzstd` + mandatory XXH64 checksum + 32-byte SHA-256 `dict_id`), asserted equal to the original structs, AND every decoded `DeltaOp` is verified end-to-end via `op.apply(first_old_val) == Ok(last_new_val)`.

---

## 2. Headline Results — Real EVM Mainnet (12,247 Unseen Transitions)

### 2A. Realistic L2 Rollup DA Batches (14 Unseen Batches of 10 Blocks — 7,005 Net Slot Updates / 462.78 KB Raw DA)

| Compressor | Input Model | Zstd Lvl 9 Size | vs. Zstd (lvl 9) | vs. Brotli `q=11` | vs. Zstd+Dict | Zstd Lvl 19 Size | vs. Brotli `q=11` (lvl 19) |
|---|---|---:|---:|---:|---:|---:|---:|
| Raw Uncompressed DA | `new_val` only | 473,887 B | — | — | — | 473,887 B | — |
| Standard Zstd | `new_val` only | 254,804 B | — | -5.9% | -23.2% | 249,631 B | -3.7% |
| Standard Brotli (`q=6`) | `new_val` only | 251,305 B | +1.4% | -4.4% | -21.5% | 251,305 B | -4.4% |
| **Standard Brotli (`q=11`, max)** | `new_val` only | **240,689 B** | +5.5% | — | -16.4% | **240,689 B** | — |
| Raw Zstd + Trained Dict (112 KB) | `new_val` only | 206,821 B | +18.8% | +14.1% | — | 201,311 B | +16.4% |
| HyperComp v2 `Updates` (no dict) | `new_val` only | 246,000 B | +3.5% | -2.2% | -18.9% | 243,074 B | -1.0% |
| **HyperComp v2 `Updates + Dict` (A2A)** | **`new_val` only** | **198,204 B** | **+22.2%** | **+17.7%** | **+4.2%** | **193,505 B** | **+19.6%** |
| HyperComp v2 `Deltas` (no dict) | `old -> new` | 237,521 B | +6.8% | +1.3% | -14.8% | 235,311 B | +2.2% |
| **HyperComp v2 Pro `Deltas + Dict`** | **`old -> new`** | **193,075 B** | **+24.2%** | **+19.8%** | **+6.6%** | **189,613 B** | **+21.2%** |

*(All `HC + Dict` numbers include full 36-byte headers with 32-byte SHA-256 `dict_id` and mandatory Zstd XXH64 checksums.)*

### 2B. Full Unseen Ordered EVM State-Transition Trace (12,247 Transitions / 1.35 MB Raw)

| Compressor | Size (lvl 9) | Ratio | Encode | `no_std` Decode | Savings vs. Baseline |
|---|---:|---:|---:|---:|---|
| Standard Zstd (lvl 9) | 298,276 B | 4.76× | — | — | — |
| Standard Brotli (`q=6`) | 289,455 B | 4.91× | — | — | — |
| Legacy Prototype v1 | 284,484 B | 4.99× | — | — | +4.6% vs. Zstd |
| **HyperComp v2 (Causal + Struct-Delta + Rhind)** | **249,606 B** | **5.69×** | **85.8 ms (16 MB/s)** | **15.2 ms (89 MB/s)** | **+16.3% vs. Zstd \| +13.8% vs. Brotli q=6 \| +12.3% vs. v1** |

*(At Zstd level 19: **244,380 B / 5.81×**, saving **+13.2% vs. Zstd lvl 19** and **+15.6% vs. Brotli q=6**, while `no_std` decode remains fast at **19.2 ms / 71 MB/s**.)*

---

## 3. Secondary Non-EVM Reference — Real Starknet Mainnet (300 Unseen Blocks)

### 3A. Unseen Starknet DA Batches (300 Blocks / 1,828 Net Slot Updates / 122.84 KB Raw DA)

| Compressor | Zstd Lvl 9 Size | vs. Zstd | vs. Brotli `q=6` | vs. Zstd+Dict | Zstd Lvl 19 Size | vs. Brotli `q=6` (lvl 19) |
|---|---:|---:|---:|---:|---:|---:|
| Standard Brotli (`q=6`) | 64,479 B | -0.05% | — | -51.9% | 64,479 B | — |
| Standard Zstd | 64,447 B | — | +0.05% | -51.8% | 63,719 B | +1.2% |
| Raw Zstd + Trained Dict (112 KB) | 42,460 B | +34.1% | +34.1% | — | 41,932 B | +35.0% |
| HyperComp v2 `SN Updates` (no dict) | 62,807 B | +2.5% | +2.6% | -47.9% | 62,198 B | +3.5% |
| **HyperComp v2 `SN Updates + Dict`** | **42,115 B** | **+34.7%** | **+34.7%** | **+0.8%** | **41,608 B** | **+35.5%** |

*(On the 146-block Starknet Delta-DA tail, `HC SN Deltas + Dict` is `22,632 B` vs. `22,350 B` for `Raw Zstd + Dict` (`-1.3%`) due to per-batch 32-byte SHA-256 `dict_id` headers across small Starknet batches, further confirming EVM ZK-Rollups as our primary target.)*

---

## 4. Forensic Findings on Real EVM Mainnet Storage (Why v0.2 Wins)

1. **Solidity Adjacent Struct/Array Slots (`SLOT_MODE_STRUCT_DELTA`):** **27.4%** of unique 32-byte EVM slots satisfy `slot[i] = slot[i-1] + k` (`1 <= k <= 16`) due to Solidity structs/arrays (`keccak(p) + k`), collapsing 32-byte hashes down to 1 byte.
2. **Delta/XOR Cuts Wide 17–32B Words Nearly in Half:** Switching from raw `new_val` to `DeltaOp` (`Add` 34.2%, `Sub` 11.7%, `XorShifted` 10.2%, `SetNew` 43.9%) cuts 17–32B wide words from **60.8% → 35.1%**, boosts Rhind decimal hits **5× (0.8% → 4.0%)**, and captures **10.4%** `U256::MAX` + **14.9%** small literals (`1..=16`) in 1 byte each.
3. **Left-Aligned Solidity `string`/`bytes` (`TAG_LEFT_BASE`):** **15.8%** of wide mainnet values have ≥ 4 trailing zero bytes; stripping right-padded zeros while keeping intact ASCII preserves Zstd's symbol modeling.
4. **Chain-Specific Trained Zstd Dictionary (112 KB):** Captures recurring DeFi contracts and hot storage slots across unseen future blocks while remaining bound cryptographically via 32-byte SHA-256 `dict_id`.

---

## 5. Self-Contained Reproduction (In This Public Repository)

```bash
# 1. Verify all 9 adversarial, PoC-regression, and 10,000-input fuzz tests + zero-warning Clippy
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 2. Verify pure #![no_std] RV32IM compilation (with and without ruzstd) + bare-metal ELF
cargo check -p hypercomp-decoder --target riscv32im-unknown-none-elf --no-default-features
cargo check -p hypercomp-decoder --target riscv32im-unknown-none-elf --no-default-features --features zstd-nostd
(cd zkvm/riscv-guest && cargo build --release)

# 3. Reproduce live mainnet benchmarks on any EVM RPC with `debug_traceBlockByNumber`
#    using the prebuilt `hypercomp` CLI binary from GitHub Releases:
hypercomp audit-rpc --rpc https://rpc.gnosischain.com --blocks 30 --batch-size 10
```
