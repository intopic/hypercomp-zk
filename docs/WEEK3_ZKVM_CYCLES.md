# Al-Samawal Rollup HyperCompressor v0.2 — Week 3 RISC-V (`riscv32im`) zkVM Cycle & Proving Cost Report

**Date:** 2026-11-24  
**Primary Target Ecosystem:** **EVM ZK-Rollups** — Bitcoin ZK-Rollups (e.g., **Citrea**, Strata/Alpen) and Ethereum L2 ZK-Rollups (**ZKsync / ZK Stack**, **Scroll**, **Linea**, **SP1 / RISC Zero** custom rollups)  
**Target ISA:** `riscv32im-unknown-none-elf` (identical 32-bit RV32IM ISA used by **Succinct SP1** and **RISC Zero**)  
**Guest Binary:** `zkvm/riscv-guest/target/riscv32im-unknown-none-elf/release/hypercomp-riscv-guest` (**176,060 bytes**, `#![no_std]`, `#![forbid(unsafe_code)]`, zero C dependencies, pure-Rust `ruzstd`)

---

## 1. Executive Summary & Transparency Note for Grant Reviewers

Every zkVM auditor and grant committee rightly asks two hard questions:
1. *"How many RV32IM cycles does **`Raw Zstd + Trained Dict` (without HyperComp)** cost compared to **`HyperComp + Zstd + Trained Dict`**?"*
2. *"Does the **incremental** L1 DA byte savings of HyperComp on top of `Raw Zstd + Dict` justify its **incremental** proving cycle overhead?"*

This report answers both questions directly by executing the **exact same `ruzstd` `#![no_std]` decompressor** inside the **exact same compiled bare-metal RV32IM ELF binary** on a real 10-block unseen EVM mainnet batch (570 net storage slots, 38,405 B raw DA):

- **`HyperComp Updates + Zstd + Dict` vs. `Raw Zstd + Dict`:** Saves **-4.3% DA bytes** at practically **zero cycle overhead (+0.9% cycles, +27,899 cycles)** while using **44 KB less guest RAM** (`514 KB` vs. `558 KB`).
- **`HyperComp Deltas + Zstd + Dict` vs. `Raw Zstd + Dict`:** Saves **-7.7% incremental DA bytes (-1,228 B)** on top of `Raw Zstd + Dict` (**-27.7% / -5,657 B** vs. standard Zstd without dict) at only **+340,531 incremental cycles (+11.1%)** and **31 KB less guest RAM** (`527 KB` vs. `558 KB`).
- **Why is the cycle overhead so small?** Because HyperComp shrinks the pre-entropy payload by **44%** before Zstd, `ruzstd` runs **-27.8% faster (-794,201 fewer cycles)** on HyperComp than on Raw DA — offsetting nearly two-thirds of the HyperComp structural decode cost!
- **Incremental Proving ROI (strictly comparing HyperComp vs. `Raw Zstd + Dict`):** The `+0.34M` incremental cycles cost **\$0.0007 – \$0.0017 / batch** on SP1 v4 / RISC Zero GPUs, while saving **\$0.5856 / batch** on Bitcoin DA (@ \$500/MB) = **344× – 860× incremental ROI** (**34.4× – 86.0× incremental ROI** on Ethereum peak blobs @ \$50/MB).

---

## 2. Exact RV32IM Cycle Comparison on Real EVM Mainnet (Apples-to-Apples)

**Dataset:** 10 unseen consecutive EVM mainnet blocks (Gnosis Chain blocks `49443028..=49443037`, `prestateTracer diffMode=true`), 77 contracts, 570 net storage slot updates, **38,405 B** canonical uncompressed DA.  
**Dictionary:** 112 KB Zstd dictionary trained strictly on earlier blocks `49442959..=49443027` (**zero data leakage**), trained identically for both `Raw Zstd + Dict` and `HyperComp + Dict`.  
**Fairness:** All modes decode into the exact same Rust `ContractDiff` / `ContractDelta` structs using the exact same `ruzstd` implementation and verify **100% bit-exact 32-bit RV32IM ↔ 64-bit x86_64 commitment parity**.

| Mode (Real 10-Block EVM Mainnet Batch) | Blob Size | vs. Raw Zstd | vs. Raw Zstd+Dict | Total RV32IM Cycles | `ruzstd` Cycles | Parse / HC Cycles | Cycles / Slot | Peak Heap |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **`Raw Zstd (lvl 9, no HC)`** *(baseline today)* | 20,426 B | — | +27.7% | **1,669,839** | 1,451,127 | 218,712 | 2,930 | 311 KB |
| **`Raw Zstd + Dict 112KB (no HC)`** *(strong baseline)* | 15,997 B | -21.7% | — | **3,074,381** | 2,855,669 | 218,712 | 5,394 | 558 KB |
| `HC Deltas` (`Entropy=None`, zero Zstd) | 21,439 B | +5.0% | +34.0% | **1,353,540** | 96 | 1,353,444 | 2,375 | 121 KB |
| `HC Deltas + Zstd (lvl 9)` *(no dict)* | 18,916 B | -7.4% | +18.2% | **1,992,115** | 638,671 | 1,353,444 | 3,495 | 268 KB |
| **`HC Updates + Zstd + Dict 112KB`** | **15,310 B** | **-25.0%** | **-4.3%** | **3,102,280** *(+0.9%)* | **2,142,698** *(-25.0%)* | 959,582 | 5,443 | **514 KB** |
| **`HC Deltas + Zstd + Dict 112KB`** | **14,769 B** | **-27.7%** | **-7.7%** | **3,414,912** *(+11.1%)* | **2,061,468** *(-27.8%)* | 1,353,444 | 5,991 | **527 KB** |

- **32-bit RV32IM ↔ 64-bit x86_64 Commitment Parity:** **100% EXACT MATCH** across all 6 modes (`Updates = 0x5ca649bc095670a6`, `Deltas = 0xd6747d84492cb0fd`).
- **RV32IM Instruction Mix (`HC Deltas + Dict`):** ALU `53.0%` | Memory `25.1%` | Branch/Jump `13.6%` | M-Extension Mul/Div `8.3%`.
- **Multi-Batch Dictionary Amortization:** In both `Raw Zstd + Dict` and `HC + Dict`, `~1.42M` cycles are one-time parsing of the 112 KB dictionary tables (`Dictionary::decode_dict`). When an SP1 or RISC Zero proof aggregates **10 rollup batches** sharing one pre-loaded dictionary, amortized dictionary init drops to **~142k cycles/batch** (~**2.13M total cycles/batch** for `HC Deltas + Dict` vs. **~1.79M** for `Raw Zstd + Dict`).

---

## 3. Transparent Proving Cost vs. L1 DA Economics (Total & Incremental)

Using published SP1 v4 / RISC Zero GPU cluster proving rates (**\$0.002 – \$0.005 per 1M RV32IM cycles**):

| Comparison | DA Bytes Saved | Cycle Delta (`Δ cycles`) | Proving Cost | Bitcoin DA Savings *(Citrea @ \$500/MB)* | Eth Peak Blob Savings *(@ \$50/MB)* |
|---|---:|---:|---:|---:|---:|
| **[A] Total:** `HC Deltas + Dict` vs. **`Raw Zstd (no dict)`** | **-5,657 B (-27.7%)** | +1,745,073 cyc<br>*(3.41M total)* | **\$0.0068 – \$0.0171**<br>*(total decode)* | **\$2.6975 / batch**<br>**(158× – 395× ROI)** | **\$0.2697 / batch**<br>**(15.8× – 39.5× ROI)** |
| **[B] Incremental:** `HC Deltas + Dict` vs. **`Raw Zstd + Dict 112KB`** | **-1,228 B (-7.7%)** | **+340,531 cyc**<br>*(+11.1%)* | **\$0.0007 – \$0.0017**<br>*(incremental)* | **\$0.5856 / batch**<br>**(344× – 860× ROI)** | **\$0.0586 / batch**<br>**(34.4× – 86.0× ROI)** |

### Key Takeaway for Bitcoin ZK-Rollups (Citrea) & Ethereum ZK-Rollups
1. **Even against the hardest possible baseline (`Raw Zstd + 112KB Trained Dict`)**, HyperComp's EVM structural transform (`DeltaOp` + `Rhind` + `Struct-Delta` + `Left-Aligned`) pays for its `+0.34M` incremental RV32IM proving cycles **344×–860× over** on Bitcoin DA and **34×–86× over** during Ethereum blob congestion — while actually **reducing peak guest RAM** (`527 KB` vs. `558 KB`).
2. **Against today's production rollups running plain Zstd/Brotli without trained dictionaries**, deploying HyperComp v2 Pro delivers **23%–28% total EVM DA reduction** across all 14 unseen mainnet batches (see [`WEEK2_MAINNET_BENCHMARK.md`](WEEK2_MAINNET_BENCHMARK.md)).

---

## 4. Native 32-bit RV32IM Optimization Impact

Profiling the real ELF binary exposed LLVM software `u128`/`u64` division (`__udivti3`, `__umoddi3`, `__multi3`) as 95% of `hypercomp-decoder` cycles. Rewriting `U256`/Rhind with native 32-bit `u32` limbs, `u16`-chunk division, and byte-sum mod-5 arithmetic (`256 ≡ 1 mod 5`) achieved:

| Metric | Before (`u64`/`u128` limbs) | After (Native 32-bit RV32IM) | Improvement |
|---|---:|---:|---:|
| Guest ELF Size | 205,692 B | **176,060 B** *(incl. raw baseline)* | **-29.6 KB** |
| Rhind 1,000 EVM Amounts vs. Legacy v1 (`mul10` loop: 4,530,137 cyc) | 566,063 cyc (8.00×) | **501,062 cyc** *(~115 cyc/val net)* | **9.04× vs. Legacy v1** |
| Real EVM Batch — `HC Deltas` structural decode (570 slots) | 4,191,365 cyc | **1,353,444 cyc** | **3.10× fewer cycles** |
| Real EVM Batch — `HC Updates` structural decode (570 slots) | 4,069,800 cyc | **959,582 cyc** | **4.24× fewer cycles** |

---

## 5. Appendix — Secondary Non-EVM Reference (Starknet Mainnet)

For full scientific transparency, we also measured a 25-block unseen Starknet Mainnet batch (17 contracts, 164 net slots, 11,133 B raw DA):

| Mode (25 Unseen Starknet Blocks) | Blob Size | Total RV32IM Cycles | `ruzstd` Cycles | Parse / HC Cycles | Peak Heap |
|---|---:|---:|---:|---:|---:|
| `Raw Zstd (lvl 9, no HC)` | 6,145 B | 441,554 | 380,738 | 60,816 | 93 KB |
| `Raw Zstd + Dict 112KB (no HC)` | 3,331 B | 1,663,086 | 1,602,270 | 60,816 | 343 KB |
| `HC SN Updates + Zstd (no dict)` | 5,988 B | 466,848 | 179,100 | 287,748 | 78 KB |
| `HC SN Updates + Zstd + Dict 112KB` | 3,341 B | 1,776,226 | 1,488,478 | 287,748 | 332 KB |

**Honest engineering conclusion:** On Starknet's 252-bit Cairo `felt252` storage (where few values are decimal ERC-20 amounts or bit-packed Solidity slots), **almost all of the ~35% gain over standard Zstd/Brotli comes from the 112 KB trained Zstd dictionary** (`+1.6%` structural lift across all 300 unseen blocks, flat on this small 25-block slice). By contrast, on **EVM storage** (Solidity packed slots, ERC-20 `U256::MAX` approvals, left-aligned strings, and decimal transfer deltas), HyperComp delivers a **clear, repeatable `+6.0% to +7.7%` incremental reduction on top of `Raw Zstd + Dict`**, making **EVM ZK-Rollups (Bitcoin ZK like Citrea + Ethereum ZK)** the primary product and grant focus.

---

## 6. Drop-In zkVM Guest Templates & Exact Reproduction

- **Bare-Metal RV32IM Benchmark Guest:** [`zkvm/riscv-guest/`](../zkvm/riscv-guest/)
- **Succinct SP1 Guest Template:** [`zkvm/sp1-guest/`](../zkvm/sp1-guest/) (`cargo prove build`)
- **RISC Zero Guest Template:** [`zkvm/risc0-guest/`](../zkvm/risc0-guest/) (`cargo risczero build`)

```bash
rustup target add riscv32im-unknown-none-elf
cargo check -p hypercomp-decoder --target riscv32im-unknown-none-elf --no-default-features
cargo check -p hypercomp-decoder --target riscv32im-unknown-none-elf --no-default-features --features zstd-nostd
cargo build --release --manifest-path zkvm/riscv-guest/Cargo.toml
cargo run --release -- zkvm-cycles
```
