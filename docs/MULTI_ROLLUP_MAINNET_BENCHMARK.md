# Al-Samawal Rollup HyperCompressor v0.2 — Live Multi-Rollup Mainnet Benchmark Report

**Date:** 2026-11-25 (Updated for v0.2 Hardened Wire Format + Brotli `q=11` + End-to-End `op.apply(old) == new` Verification)  
**Engine:** `hypercomp-encoder` v0.2.0 + Open-Source `#![no_std]` `hypercomp-decoder` v0.2.0 (`#![forbid(unsafe_code)]`, pure-Rust `ruzstd` verification)  
**Methodology:** Strict chronological train/test split on live finalized mainnet blocks (**zero data leakage**): earlier blocks train a 112 KB chain-specific Zstd dictionary, and **later unseen blocks** are compressed, benchmarked against plain `Brotli`, `Zstd`, and `Raw Zstd + 112KB Dict`, and **100% lossless verified** via `#![no_std]` decompression + `op.apply(old_val) == Ok(new_val)`.

> **Methodological Transparency & Baseline Scope:**
> - **Baseline layout:** All baselines (`Brotli`, `Zstd`, `Raw Zstd + Dict`) compress canonical uncompressed EVM storage updates (`ContractDiff::to_raw_bytes`, `new_val`-only). They do **not** yet benchmark against partner rollups' internal custom DA encoders (e.g., Citrea's Sovereign-SDK stateful diff encoding before Brotli, or ZKsync Era's L1 pubdata delta compression). Direct comparison against Citrea's live Bitcoin Taproot witnesses is scoped for **Milestone M3**.
> - **Stateless (`Updates`) vs. Delta-DA (`Deltas`):** `HC v2 Updates + Dict` uses **identical `new_val`-only inputs** to `Raw Zstd + Dict` (strictly apples-to-apples). `HC v2 Deltas + Dict` additionally leverages `old_val -> new_val` (similar in principle to ZKsync Era's pubdata delta model). Both are shown transparently below wherever measured.
> - **Wire-format update note:** Gnosis, Citrea, and Starknet below were re-measured on the **hardened v0.2 wire format** (32-byte SHA-256 `dict_id` + mandatory XXH64 checksum + `Brotli q=11`). The 5 live RPC snapshots (`Eth L1`, `Base`, `Optimism`, `Polygon`, `Taiko`) were captured live on `2026-11-25` prior to adding the `+28 B/batch` SHA-256 `dict_id` (`< 0.15%` difference on multi-KB batches; Taiko verified with automatic Raw Zstd fallback).

---

## 1. Unified Multi-Rollup Mainnet Comparison Table

| # | Network | Rollup / Chain Type | Unseen Test Window (Net Slots / Batch) | Raw DA | Brotli `q=6` *(q=11)* | Zstd (lvl 9) | Raw Zstd + Dict | `HC v2` (No Dict) | **`HC v2 Pro + Dict`** *(Deltas)* | vs. Brotli `q=6` *(q=11)* | vs. Zstd | **vs. Raw Zstd+Dict** *(Deltas / A2A Updates)* |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **1** | **Citrea Mainnet** *(ID 4114, hardened v0.2)* | **Bitcoin ZK-Rollup** *(small sample: 157 slots)* | `15729049..=15731331`<br>*(39 active blks · 4×10-blk)* | 10,803 B | 6,438 B *(6,465 B)* | 6,405 B | 5,290 B | 6,168 B | **4,918 B** *(Upd: 4,975 B)* | **+23.6%** *(+23.9%)* | **+23.2%** | **+7.0%** *(A2A Upd: **+6.0%**, Mega: **+10.9%**)* |
| **2** | **Gnosis Mainnet** *(ID 100, hardened v0.2)* | **EVM Mainnet** *(Week 2/3 baseline)* | `49443028..=49443166`<br>*(139 blks · 7,005 slots)* | 473,887 B | 251,305 B *(240,689 B)* | 254,804 B | 206,821 B | 237,521 B | **193,075 B** *(Upd: 198,204 B)* | **+23.2%** *(+19.8%)* | **+24.2%** | **+6.6%** *(A2A Upd: **+4.2%**)* |
| **3** | **Ethereum L1 Mainnet** *(live RPC)* | **High-Density DeFi EVM** | `26488505..=26488516`<br>*(12 blks · 9,541 slots)* | 633,368 B | 312,549 B | 324,045 B | 293,788 B | **252,252 B** | **220,517 B** | **+29.4%** | **+31.9%** | **+24.9%** *(Delta-DA vs Raw)* |
| **4** | **Base Mainnet** *(live RPC)* | **OP Stack EVM L2** *(200ms Denim blocks)* | `61875569..=61875580`<br>*(12 blks · 1,986 slots)* | 134,720 B | 67,280 B | 67,981 B | 55,028 B | 59,317 B | **47,911 B** | **+28.8%** | **+29.5%** | **+12.9%** *(Delta-DA vs Raw)* |
| **5** | **Optimism Mainnet** *(live RPC)* | **OP Stack EVM L2** *(2.0s blocks)* | `159983357..=159983368`<br>*(12 blks · 1,630 slots)* | 110,320 B | 48,786 B | 49,249 B | 41,363 B | 43,689 B | **37,351 B** | **+23.4%** | **+24.2%** | **+9.7%** *(Delta-DA vs Raw)* |
| **6** | **Polygon PoS Mainnet** *(live RPC)* | **High-Volume EVM Chain** | `97906704..=97906713`<br>*(10 blks · 7,812 slots)* | 507,733 B | 195,195 B | 203,692 B | 194,697 B | **175,585 B** | **167,290 B** | **+14.3%** | **+17.9%** | **+14.1%** *(Delta-DA vs Raw)* |
| **7** | **Taiko Mainnet** *(sparse anchor blocks)* | **Type-1 Based zkEVM** *(~1.2 slots/blk)* | `14460618..=14460637`<br>*(20 blks · **24 slots**)* | 1,636 B | 1,536 B | 1,532 B | 1,516 B | 1,532 B | **1,532 B** *(fallback)* | **+0.3%** | **0.0%** | -1.1% vs Zstd+Dict *(0% neg vs plain Zstd)* |
| *App.* | *Starknet Mainnet* *(hardened v0.2)* | *Non-EVM Cairo ZK-Rollup* | `18461423..=18461722`<br>*(300 blks · 1,828 slots)* | 125,788 B | 64,479 B | 64,447 B | 42,460 B | 62,807 B | **42,115 B** *(Upd)* | **+34.7%** | **+34.7%** | **+0.8%** *(dict-dominated)* |

---

## 2. Key Technical Findings & Honest Caveats

### Finding 1 — Citrea Mainnet (Bitcoin ZK-Rollup, Chain ID 4114)
- Across 4,000 scanned Citrea Mainnet blocks (`15727400..=15731331`, 68 non-empty blocks with diffs, 356 transitions; unseen split = 39 active blocks, 157 net slots, 10.8 KB raw, fixture SHA-256 `b1d6e78419a65fb94c35bd508328819bc5658aa15236333a5bad72567206f53a`):
  - **Strictly apples-to-apples (`HC v2 Updates + Dict` vs. `Raw Zstd + Dict`, identical `new_val`-only inputs):** **`4,975 B`** vs. `5,290 B` (**`+6.0%`** incremental lift; **`+23.0%` vs. Brotli `q=11`**; **`+9.1%`** on the collapsed 131-slot mega-batch).
  - **Delta-DA (`HC v2 Deltas + Dict`, `old_val -> new_val`):** **`4,918 B`** (**`+23.9%` vs. Brotli `q=11`**, `+23.2%` vs. Zstd lvl 9, **`+7.0%`** vs. `Raw Zstd + Dict`, rising to **`+10.9%`** on the collapsed mega-batch: `4,291 B` vs. `4,818 B`).
  - **Honest Caveat:** This sample covers 157 net storage slots (~10.8 KB raw, excluding account balances/code/nonces) and compares against plain Brotli `q=6`/`q=11` on uncompressed storage updates — **not** Citrea's internal Sovereign-SDK stateful Taproot witness format. Benchmarking directly against Citrea's posted Bitcoin Taproot witnesses over multi-day windows is our explicit Milestone M3 deliverable.

### Finding 2 — Structural Lift Scales with DeFi Batch Density (Beats `Raw Zstd + Dict` Even Without a Dictionary!)
- On **Ethereum L1 Mainnet** (3,180 net slots/batch) and **Polygon PoS** (3,906 net slots/batch), **`HC v2` without any trained dictionary** (`252,252 B` and `175,585 B`) already beats **`Raw Zstd + 112KB Dict`** (`293,788 B` and `194,697 B`) by **`+14.1%`** and **`+9.8%`**, proving that the algebraic transform layer (`DeltaOp` + `Rhind` + `SLOT_MODE_STRUCT_DELTA` + `TAG_LEFT_BASE`) delivers real compression gains independent of dictionary training.
- On **Base Mainnet** (12 unseen blocks, `61875569..=61875580`, `~0.174s/blk` reflecting Base's 200 ms block cadence post-Denim upgrade; ~2.4 s snapshot with 1s block timestamp resolution `±20%`): `HC v2 Deltas + Dict` achieves **`+28.8%` vs. Brotli `q=6`**, **`+29.5%` vs. Zstd**, and **`+12.9%` vs. `Raw Zstd + Dict`**.
- **Illustrative DA Cost Context:** We intentionally avoid claiming fixed multi-million-dollar monthly USD guarantees from 12-block snapshots, because Ethereum EIP-4844 blob base fees fluctuate by orders of magnitude between quiet periods (`< \$1/MB`) and peak congestion (`\$50/MB+`), and OP Stack L2s also post ECDSA transaction calldata alongside state diffs. On **Bitcoin ZK-Rollups** (where state diffs are posted directly to L1 Taproot witnesses at `\$100–\$500+/MB`), every `10%–24%` state-diff byte reduction translates directly to L1 operating margin.

### Finding 3 — Automatic Raw Zstd Fallback on Sparse Anchor Blocks (Taiko Mainnet)
- On the 40-block **Taiko Mainnet** window (`14460598..=14460637`, ~6 slots/batch of pure 32-byte L1 anchor Keccak hashes), `hypercomp-encoder`'s automatic `< 32` slots & size-guard Raw Zstd fallback drops size from `1,614 B (-5.4%)` to **`1,532 B` (`0.0%` vs. standard Zstd, `+0.3%` vs. Brotli `q=6`)**, with a 1-byte internal `version|kind` domain tag and mandatory XXH64 checksum in hardened v0.2. Note that against `Raw Zstd + Dict` (`1,516 B`) on that tiny window, fallback without dict is `-1.1%`.

---

## 3. Status of Remaining Priority ZK-Rollups (Paid Trace RPC Requirements)

Four additional ZK-Rollups were probed across free endpoints (`*.drpc.org`, `*.publicnode.com`, official RPCs, Alchemy Free Tier). None expose Geth `debug_traceBlockByNumber(prestateTracer, diffMode: true)` on free tiers:

| Priority Rollup | Type | Free-Tier Blocker Observed | Ready-to-Run Command (With Pay-As-You-Go Trace RPC) |
|---|---|---|---|
| **Mantle Mainnet** | EVM ZK-Rollup (SP1) | Free RPCs disable `debug_traceBlockByNumber` (`-32601` / HTTP 400). | `hypercomp audit-rpc --rpc <MANTLE_TRACE_RPC> --blocks 40 --batch-size 10` |
| **Scroll Mainnet** | Ethereum zkEVM | Free RPCs disable `debug_traceBlockByNumber` (`-32601`). | `hypercomp audit-rpc --rpc <SCROLL_TRACE_RPC> --blocks 40 --batch-size 10` |
| **Linea Mainnet** | Ethereum zkEVM | Public Besu nodes ignore `diffMode: true` on `prestateTracer`. | Requires Geth-compatible trace RPC or archive storage diffing |
| **ZKsync Era** | ZK Stack (Delta-DA) | Official RPC supports `callTracer` only; diffs published via L1 pubdata batches. | Dedicated Era L1 pubdata adapter planned for M2/M3 |
