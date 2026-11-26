> **ARCHIVED (superseded).** This document predates the November 2026 measurement methodology (real batch sizes, 150-block
> chronological dictionary training, Zstd + Dict control rows, verified on-chain DA costs). Its figures are kept for history only.
> Current, reproducible results: [`benchmarks/README.md`](../../benchmarks/README.md).

# Al-Samawal Rollup HyperCompressor v0.2 — Week 3 Bare-Metal RV32IM Instruction & Proving Cost Report

**Date:** 2026-11-25 (Updated for v0.2 Hardened Wire Format — 32-byte SHA-256 `dict_id` + Mandatory XXH64 Checksum)  
**Primary Target Ecosystem:** **EVM ZK-Rollups** — Bitcoin ZK-Rollups (e.g., **Citrea**, Strata/Alpen) and Ethereum L2 ZK-Rollups (**ZKsync / ZK Stack**, **Scroll**, **Linea**, **SP1 / RISC Zero** custom rollups)  
**Target ISA:** `riscv32im-unknown-none-elf` (same 32-bit RV32IM ISA executed by **Succinct SP1** and **RISC Zero**)  
**Guest Binary:** `zkvm/riscv-guest/target/riscv32im-unknown-none-elf/release/hypercomp-riscv-guest` (**202,424 bytes**, `#![no_std]`, zero C dependencies, pure-Rust `ruzstd`; the `hypercomp-decoder` library crate itself enforces `#![forbid(unsafe_code)]`, while the bare-metal `riscv-guest` startup/MMIO harness uses minimal `unsafe` for `_start` and mailbox I/O)

> **Measurement Methodology Caveat (Important for zkVM Auditors):**  
> The numbers below are **exact bare-metal RV32IM executed instructions (1 instruction = 1 core ISA cycle)** produced by executing the compiled `riscv32im-unknown-none-elf` ELF binary instruction-by-instruction. They measure pure CPU/decoder workload accurately, but **exclude zkVM-specific prover overhead** such as RISC Zero memory paging, SP1 continuation sharding, and host I/O hashing. End-to-end GPU proving benchmarks via native `sp1-sdk` (`ProverClient`) and `risc0-zkvm` (`ExecutorEnv`) are explicitly scoped as **Milestone M2**.

---

## 1. Executive Summary & Incremental Analysis

Every zkVM auditor and grant reviewer rightly asks:
1. *"How many RV32IM instructions does **`Raw Zstd + Dict 112KB` (without HyperComp)** execute compared to **`HyperComp + Zstd + Dict`**?"*
2. *"Does the **incremental** L1 DA byte savings of HyperComp justify its **incremental** instruction overhead?"*

Measured inside the **exact same compiled bare-metal RV32IM ELF binary** on a real 10-block unseen EVM mainnet batch (Gnosis Chain blocks `49443028..=49443037`, 77 contracts, 570 net slots, **38,405 B** raw DA, with full 32-byte SHA-256 `dict_id` verification and mandatory Zstd XXH64 checksum):

- **Stateless `HC Updates + Dict` vs. `Raw Zstd + Dict` (strictly apples-to-apples, `new_val` only):** Saves **-4.1% (-659 B)** while executing **-21,426 FEWER RV32IM instructions (-0.22%)** and using **44 KB less guest RAM** (`514 KB` vs. `558 KB`)!
- **Delta-DA `HC Deltas + Dict` vs. `Raw Zstd + Dict` (`old_val -> new_val`):** Saves **-7.5% (-1,200 B)** incrementally on top of `Raw Zstd + Dict` (**-27.6% / -5,629 B** vs. plain `Raw Zstd`) at only **+271,465 incremental instructions (+2.8%)** and **31 KB less guest RAM** (`527 KB` vs. `558 KB`).
- **Why is HyperComp's incremental cost so small (and negative on `Updates`)?** Shrinking the pre-entropy buffer by 44% cuts `ruzstd` decompression by **-794,199 instructions**, and `OPT-1` (binary trailing-zero pre-filtering in `has_strictly_shorter_rhind`) eliminates software divisions on non-decimal 32-byte hashes (`1,284,838` structural instructions for `HC Deltas`, `910,717` for `HC Updates`).
- **Why do all `+ Dict` modes show ~9.6M–9.9M bare-metal instructions?** Upgrading `dict_id` from 32-bit FNV-1a to cryptographic **SHA-256** (`H-3`) executes pure-software RV32IM SHA-256 over the 112 KB dictionary (`~6.56M` software instructions) + `Dictionary::decode_dict` (`~1.42M` instructions) on every batch. Inside **Succinct SP1** and **RISC Zero**, `zkvm/sp1-guest` and `zkvm/risc0-guest` hash the dictionary **only once** via `PrehashedDict` (`N-5`) and include `[patch.crates-io]` patches for the SP1/RISC Zero native SHA-256 precompile (which activates when compiled with `cargo prove build` / `cargo risczero build` in Milestone M2, making SHA-256 ~20–40× cheaper than pure-software RV32IM).

### Worst-Case Single-Blob Memory & Instruction Envelope (`DecodeLimits::CONSENSUS`, `N-1` / `N-2`)

With unified `DecodeLimits::CONSENSUS` (`max_items = 100,000` slots, `max_decompressed_bytes = 8 MiB`, `max_window_bytes = 8 MiB`, `max_output_bytes = 16 MiB` calibrated at `144 B/slot`), mandatory Zstd `Frame_Content_Size`, and single exact `Vec::with_capacity` allocation:
- **Worst-Case Bump-Allocator Heap (measured, R3-1 / OPT-2):** a non-freeing bump allocator accumulates the decompression buffer, the `ruzstd` window, intermediate columns, and the final output. Measured cumulative totals for consensus-valid adversarial batches stay well under `80 MiB` (`~50 MiB` for 100k random 32-byte slots/values at Zstd lvl 19, `~51 MiB` for 60k random `StateTransitions` after `OPT-2` skips `BTreeMap` allocation when `explicit_old_count == n`, `~36 MiB` for 100k slots via Raw Zstd fallback, `~34 MiB` for 8 MiB zero bomb). The bare-metal benchmark guest therefore provisions a **96 MiB** heap (128 MiB RAM), and zkVM integrations should provision `>= 96 MiB`. `EST_BYTES_PER_SLOT` / `EST_BYTES_PER_TRANSITION` are consensus accounting weights for the net live footprint, not cumulative heap bounds. The bound is enforced by `hypercomp-pro/crates/hypercomp-encoder/tests/bump_envelope.rs`.
- **Worst-Case RV32IM Instruction Upper Bound:** At `~2,254` RV32IM instructions/slot for `HC Deltas` structural decoding (`~1,598`/slot for `HC Updates`) plus `<= 8 MiB` `ruzstd` decompression, a maximal `100,000`-slot batch stays within **`~226M` structural + `~110M` Zstd software RV32IM instructions** (~`0.34B` worst-case; typical 500–2,000 slot L2 batches execute `~9.6M–15M` total instructions).

---

## 2. Exact Bare-Metal RV32IM Instruction Counts (Real 10-Block EVM Mainnet Batch)

**Dataset:** 10 unseen consecutive EVM mainnet blocks (`49443028..=49443037`, 77 contracts, 570 net slots, 38,405 B raw DA).  
**Dictionary:** 112 KB Zstd dictionary trained strictly on earlier blocks `49442959..=49443027` (**zero data leakage**), verified via 32-byte SHA-256 `dict_id`.  
**Parity:** **100% bit-exact 32-bit RV32IM ↔ 64-bit x86_64 commitment parity** verified on every row (`Updates=0x5ca649bc095670a6`, `Deltas=0xd6747d84492cb0fd`).

| Mode (`riscv32im` ELF, `#![no_std]`) | Blob Size | Total RV32IM Instrs | `ruzstd` + SHA-256 Dict Instrs | Parse / HC Instrs | Instrs / Slot | Peak Heap |
|---|---:|---:|---:|---:|---:|---:|
| `Raw Zstd (lvl 9, no HC)` | 20,426 B | 1,671,522 | 1,452,348 | 219,174 | 2,932 | 311 KB |
| `HC Deltas (Entropy=None)` | 21,439 B | 1,284,975 | 137 | 1,284,838 | 2,254 | 121 KB |
| `HC Deltas + Zstd (lvl 9, no dict)` | 18,916 B | 1,924,732 | 639,894 | 1,284,838 | 3,377 | 268 KB |
| **`Raw Zstd + Dict 112KB (no HC)`** | **15,997 B** | **9,633,019** | **9,413,845** | **219,174** | **16,900** | **558 KB** |
| **`HC Updates + Dict 112KB (A2A)`** | **15,338 B (-4.1%)** | **9,611,593 (-0.2%)** | **8,700,876 (-7.6%)** | **910,717** | **16,862** | **514 KB** |
| **`HC Deltas + Dict 112KB`** | **14,797 B (-7.5%)** | **9,904,484 (+2.8%)** | **8,619,646 (-8.4%)** | **1,284,838** | **17,376** | **527 KB** |

- **Microbenchmark — Rhind U256 Decode (1,000 EVM decimal amounts):** Legacy v1 byte-loop `mul10` = `4,530,136` instrs (`4,530/val`) → HyperComp v3 `POW10` 32-bit limb table = **`501,061` instrs (`501/val`)** = **`9.04×` speedup**!
- **Instruction Mix (`HC Deltas + Dict`):** ALU `76.1%` | Memory `18.1%` | Branch `3.9%` | MulDiv `1.9%`.

---

## 3. Illustrative Incremental Proving ROI Sensitivity Matrix

Comparing **`HC Deltas + Dict` vs. `Raw Zstd + Dict`** on the 10-block EVM batch (`-1,200 B` incremental DA saved for `+271,465` incremental RV32IM instructions). Because actual zkVM GPU proving costs and L1 DA markets fluctuate dramatically, we report an explicit sensitivity grid rather than a single fixed price:

| Illustrative L1 DA Price | Incremental DA Saved (`1,200 B`) | Proving @ `\$0.002 / M-instr` (`\$0.00054`) | Proving @ `\$0.005 / M-instr` (`\$0.00136`) | Proving @ `\$0.020 / M-instr` (`\$0.00543`) *(10× overhead buffer)* |
|---|---:|---:|---:|---:|
| **Ethereum Off-Peak Blobs (`\$5/MB`)** | `\$0.0057` | **10.5×** | **4.2×** | **1.05×** *(positive even off-peak!)* |
| **Ethereum Peak Blobs (`\$50/MB`)** | `\$0.0572` | **105×** | **42×** | **10.5×** |
| **Bitcoin L1 DA Low (`\$150/MB`)** | `\$0.1717` | **316×** | **126×** | **32×** |
| **Bitcoin L1 DA High (`\$500/MB`)** | `\$0.5722` | **1,054×** | **422×** | **105×** |

*(Even under a conservative 10× prover-overhead assumption of `\$0.020 / M-instr` to account for zkVM paging/sharding, incremental ROI is **32×–105×** on Bitcoin DA and **10.5×** on Ethereum peak blobs — and stateless `HC Updates + Dict` has **negative** incremental instruction cost (`-21,426` instructions)!)*

---

## 4. Secondary Non-EVM Reference — Starknet Mainnet Batch (164 Net Slots, 11,133 B Raw)

| Mode (`riscv32im` ELF) | Blob Size | Total RV32IM Instrs | Peak Heap |
|---|---:|---:|---:|
| `Raw Zstd (lvl 9, no HC)` | 6,145 B | 442,798 | 93 KB |
| `Raw Zstd + Dict (no HC)` | 3,331 B | 8,221,285 | 343 KB |
| `HC SN Updates + Zstd (no dict)` | 5,988 B | 464,737 | 78 KB |
| `HC SN Updates + Dict` | 3,369 B | 8,331,070 | 332 KB |

*(On tiny 3.3 KB Starknet batches, the +28 B cryptographic SHA-256 `dict_id` header exceeds Starknet's small structural gain, reinforcing our focus on EVM ZK-Rollups.)*
