# Al-Samawal Rollup HyperCompressor v0.2 — Week 3 Bare-Metal RV32IM Instruction & Proving Cost Report

**Date:** 2026-11-25 (Updated for v0.2 Hardened Wire Format — 32-byte SHA-256 `dict_id` + Mandatory XXH64 Checksum)  
**Primary Target Ecosystem:** **EVM ZK-Rollups** — Bitcoin ZK-Rollups (e.g., **Citrea**, Strata/Alpen) and Ethereum L2 ZK-Rollups (**ZKsync / ZK Stack**, **Scroll**, **Linea**, **SP1 / RISC Zero** custom rollups)  
**Target ISA:** `riscv32im-unknown-none-elf` (same 32-bit RV32IM ISA executed by **Succinct SP1** and **RISC Zero**)  
**Guest Binary:** `zkvm/riscv-guest/target/riscv32im-unknown-none-elf/release/hypercomp-riscv-guest` (**200,104 bytes**, `#![no_std]`, zero C dependencies, pure-Rust `ruzstd`; the `hypercomp-decoder` library crate itself enforces `#![forbid(unsafe_code)]`, while the bare-metal `riscv-guest` startup/MMIO harness uses minimal `unsafe` for `_start` and mailbox I/O)

> **Measurement Methodology Caveat (Important for zkVM Auditors):**  
> The numbers below are **exact bare-metal RV32IM executed instructions (1 instruction = 1 core ISA cycle)** produced by executing the compiled `riscv32im-unknown-none-elf` ELF binary instruction-by-instruction. They measure pure CPU/decoder workload accurately, but **exclude zkVM-specific prover overhead** such as RISC Zero memory paging, SP1 continuation sharding, and host I/O hashing. End-to-end GPU proving benchmarks via native `sp1-sdk` (`ProverClient`) and `risc0-zkvm` (`ExecutorEnv`) are explicitly scoped as **Milestone M2**.

---

## 1. Executive Summary & Incremental Analysis

Every zkVM auditor and grant reviewer rightly asks:
1. *"How many RV32IM instructions does **`Raw Zstd + Dict 112KB` (without HyperComp)** execute compared to **`HyperComp + Zstd + Dict`**?"*
2. *"Does the **incremental** L1 DA byte savings of HyperComp justify its **incremental** instruction overhead?"*

Measured inside the **exact same compiled bare-metal RV32IM ELF binary** on a real 10-block unseen EVM mainnet batch (Gnosis Chain blocks `49443028..=49443037`, 77 contracts, 570 net slots, **38,405 B** raw DA, with full 32-byte SHA-256 `dict_id` verification and mandatory Zstd XXH64 checksum):

- **Stateless `HC Updates + Dict` vs. `Raw Zstd + Dict` (strictly apples-to-apples, `new_val` only):** Saves **-4.1% (-659 B)** at practically **zero instruction overhead (+25,021 instructions = +0.26%)** while using **44 KB less guest RAM** (`514 KB` vs. `558 KB`).
- **Delta-DA `HC Deltas + Dict` vs. `Raw Zstd + Dict` (`old_val -> new_val`):** Saves **-7.5% (-1,200 B)** incrementally on top of `Raw Zstd + Dict` (**-27.6% / -5,629 B** vs. plain `Raw Zstd`) at only **+331,508 incremental instructions (+3.4%)** and **31 KB less guest RAM** (`527 KB` vs. `558 KB`).
- **Why is HyperComp's incremental cost so small?** Shrinking the pre-entropy buffer by 44% cuts `ruzstd` decompression by **-794,199 instructions**, offsetting ~70% of HyperComp's structural decode cost (`1,344,881` instructions).
- **Why do all `+ Dict` modes show ~9.6M–9.9M bare-metal instructions?** Upgrading `dict_id` from 32-bit FNV-1a to cryptographic **SHA-256** (`H-3`) executes pure-software RV32IM SHA-256 over the 112 KB dictionary (`~6.56M` software instructions) + `Dictionary::decode_dict` (`~1.42M` instructions) on every batch. Inside **Succinct SP1** and **RISC Zero**, `zkvm/sp1-guest` and `zkvm/risc0-guest` hash the dictionary **only once** via `PrehashedDict` (`N-5`) and include `[patch.crates-io]` patches for the SP1/RISC Zero native SHA-256 precompile (which activates when compiled with `cargo prove build` / `cargo risczero build` in Milestone M2, making SHA-256 ~20–40× cheaper than pure-software RV32IM).

### Worst-Case Single-Blob Memory & Instruction Envelope (`DecodeLimits::CONSENSUS`, `N-1` / `N-2`)

With unified `DecodeLimits::CONSENSUS` (`max_items = 100,000` slots, `max_decompressed_bytes = 8 MiB`, `max_window_bytes = 8 MiB`, `max_output_bytes = 16 MiB` calibrated at `144 B/slot`), mandatory Zstd `Frame_Content_Size`, and single exact `Vec::with_capacity` allocation:
- **Worst-Case Bump-Allocator Heap:** `<= 8 MiB` (pre-entropy buffer, single allocation, zero doubling leaks) + `<= 8.5 MiB` (`ruzstd` window & dictionary buffer) + `<= 16 MiB` (calibrated decoded output + intermediate columns) = **`<= 32.5–34 MiB`**, leaving **>= 14 MiB headroom** inside a 48 MiB zkVM guest heap.
- **Worst-Case RV32IM Instruction Upper Bound:** At `~2,360` RV32IM instructions/slot for `HC Deltas` structural decoding (`~1,680`/slot for `HC Updates`) plus `<= 8 MiB` `ruzstd` decompression, a maximal `100,000`-slot batch stays within **`~236M` structural + `~110M` Zstd software RV32IM instructions** (~`0.35B` worst-case; typical 500–2,000 slot L2 batches execute `~9.6M–15M` total instructions).

---

## 2. Exact Bare-Metal RV32IM Instruction Counts (Real 10-Block EVM Mainnet Batch)

**Dataset:** 10 unseen consecutive EVM mainnet blocks (`49443028..=49443037`, 77 contracts, 570 net slots, 38,405 B raw DA).  
**Dictionary:** 112 KB Zstd dictionary trained strictly on earlier blocks `49442959..=49443027` (**zero data leakage**), verified via 32-byte SHA-256 `dict_id`.  
**Parity:** **100% bit-exact 32-bit RV32IM ↔ 64-bit x86_64 commitment parity** verified on every row (`Updates=0x5ca649bc095670a6`, `Deltas=0xd6747d84492cb0fd`).

| Mode (`riscv32im` ELF, `#![no_std]`) | Blob Size | Total RV32IM Instrs | `ruzstd` + SHA-256 Dict Instrs | Parse / HC Instrs | Instrs / Slot | Peak Heap |
|---|---:|---:|---:|---:|---:|---:|
| `Raw Zstd (lvl 9, no HC)` | 20,426 B | 1,671,522 | 1,452,348 | 219,174 | 2,932 | 311 KB |
| `HC Deltas (Entropy=None)` | 21,439 B | 1,345,017 | 137 | 1,344,880 | 2,360 | 121 KB |
| `HC Deltas + Zstd (lvl 9, no dict)` | 18,916 B | 1,984,774 | 639,894 | 1,344,880 | 3,482 | 268 KB |
| **`Raw Zstd + Dict 112KB (no HC)`** | **15,997 B** | **9,633,019** | **9,413,845** | **219,174** | **16,900** | **558 KB** |
| **`HC Updates + Dict 112KB (A2A)`** | **15,338 B (-4.1%)** | **9,658,039 (+0.3%)** | **8,700,876 (-7.6%)** | **957,163** | **16,944** | **514 KB** |
| **`HC Deltas + Dict 112KB`** | **14,797 B (-7.5%)** | **9,964,526 (+3.4%)** | **8,619,646 (-8.4%)** | **1,344,880** | **17,482** | **527 KB** |

- **Microbenchmark — Rhind U256 Decode (1,000 EVM decimal amounts):** Legacy v1 byte-loop `mul10` = `4,530,136` instrs (`4,530/val`) → HyperComp v2 `POW10` 32-bit limb table = **`501,061` instrs (`501/val`)** = **`9.04×` speedup**!
- **Instruction Mix (`HC Deltas + Dict`):** ALU `76.0%` | Memory `18.2%` | Branch `3.9%` | MulDiv `1.9%`.

---

## 3. Illustrative Incremental Proving ROI Sensitivity Matrix

Comparing **`HC Deltas + Dict` vs. `Raw Zstd + Dict`** on the 10-block EVM batch (`-1,200 B` incremental DA saved for `+331,508` incremental RV32IM instructions). Because actual zkVM GPU proving costs and L1 DA markets fluctuate dramatically, we report an explicit sensitivity grid rather than a single fixed price:

| Illustrative L1 DA Price | Incremental DA Saved (`1,200 B`) | Proving @ `\$0.002 / M-instr` (`\$0.00066`) | Proving @ `\$0.005 / M-instr` (`\$0.00166`) | Proving @ `\$0.020 / M-instr` (`\$0.00663`) *(10× overhead buffer)* |
|---|---:|---:|---:|---:|
| **Ethereum Off-Peak Blobs (`\$5/MB`)** | `\$0.0057` | **8.6×** | **3.4×** | ~0.9× *(break-even)* |
| **Ethereum Peak Blobs (`\$50/MB`)** | `\$0.0572` | **86×** | **35×** | **8.6×** |
| **Bitcoin L1 DA Low (`\$150/MB`)** | `\$0.1717` | **259×** | **104×** | **26×** |
| **Bitcoin L1 DA High (`\$500/MB`)** | `\$0.5722` | **863×** | **345×** | **86×** |

*(Even under a conservative 10× prover-overhead assumption of `\$0.020 / M-instr` to account for zkVM paging/sharding, incremental ROI remains **26×–86×** on Bitcoin DA and **8.6×** on Ethereum peak blobs.)*

---

## 4. Secondary Non-EVM Reference — Starknet Mainnet Batch (164 Net Slots, 11,133 B Raw)

| Mode (`riscv32im` ELF) | Blob Size | Total RV32IM Instrs | Peak Heap |
|---|---:|---:|---:|
| `Raw Zstd (lvl 9, no HC)` | 6,145 B | 441,785 | 93 KB |
| `Raw Zstd + Dict (no HC)` | 3,331 B | 8,220,235 | 343 KB |
| `HC SN Updates + Zstd (no dict)` | 5,988 B | 469,155 | 78 KB |
| `HC SN Updates + Dict` | 3,369 B | 8,335,451 | 332 KB |

*(On tiny 3.3 KB Starknet batches, the +28 B cryptographic SHA-256 `dict_id` header exceeds Starknet's small structural gain, reinforcing our focus on EVM ZK-Rollups.)*
