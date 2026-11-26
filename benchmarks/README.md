# HyperCompressor v3 — Measured Benchmarks (Nov 2026)

Everything on this page is **measured on real mainnet data**. Nothing is extrapolated
from synthetic workloads. Each number links to the data file it comes from, and the scripts in
[`scripts/`](scripts/) re-collect the public inputs.

**Measurement window:** Ethereum L1 2026-11-19 → 2026-11-25 (7 full UTC days), Bitcoin heights
977,277 → 977,709 (~3 days), plus L2 captures on 2026-11-26.

| What | Section | Data file |
|---|---|---|
| How often each rollup posts, what it pays, how many L2 blocks per batch | [1](#1-what-rollups-post-and-pay-today-ethereum-7-days) | [`ethereum_rollup_da_profile_2026-11-19_25.json`](data/ethereum_rollup_da_profile_2026-11-19_25.json) |
| What Citrea posts to Bitcoin and what it pays | [2](#2-citrea-what-it-posts-to-bitcoin-and-what-it-pays) | [`citrea_bitcoin_da_cost_1day.json`](data/citrea_bitcoin_da_cost_1day.json) |
| HC vs Brotli / Zstd / Zstd + Dict on Citrea's real DA payloads | [3](#3-hc-on-citreas-real-da-payloads) | [`citrea_hc_vs_brotli.json`](data/citrea_hc_vs_brotli.json) |
| HC vs Brotli / Zstd / Zstd + Dict on EVM state diffs at each rollup's real batch size | [4](#4-hc-on-evm-state-diffs-at-real-batch-sizes) | [`evm_state_diff_compression_summary.json`](data/evm_state_diff_compression_summary.json), [`evm_real_batch_size_results.json`](data/evm_real_batch_size_results.json) |
| SP1 zkVM execution of every fixture | [5](#5-sp1-zkvm-execution) | CI artifact `sp1-execute-report` |

---

## Summary — what HC does and does not do

- **HC wins only on structured EVM state diffs.** These are `(contract address, storage slot, value)` triples.
  On those, at each rollup's real batch size, HC beats the strongest do-it-yourself baseline,
  **Zstd with a trained chain dictionary**, by:
  - **+3.9% to +8.2%** for `StateUpdates` (new values only)
  - **+7.7% to +12.8%** for `StateDeltas` (old → new)

  Against plain Zstd or Brotli q=11 it gains **+8% to +22%** (Section 4).
- **HC does not help on Citrea's current DA format.** Citrea posts hashed storage keys and 256 block
  hashes per proof. There, a trained dictionary does all the work: plain Zstd + Dict beats HC (Section 3).
- **Ethereum blob DA is cheap and volatile.** Base, the largest blob user, paid a mean of
  **$269/day** for blobs (range $19–$840/day). Smaller rollups pay $0.10–$54/day (Section 1).
- **Bitcoin DA is ~1,500× more expensive per MB** than Base's blob cost. Citrea pays **~$242/MB**.
  But its total DA bill is small: **~$155/day** at a median 1 sat/vB (Section 2).
- **Most large rollups post transaction data, not state diffs.** This includes Arbitrum, Base, Optimism,
  Unichain, Scroll and Linea. For them, HC requires switching to state-diff DA, which only works with validity proofs.
  It is an architectural change, not a drop-in codec swap (Section 4.2).

---

## 1. What rollups post and pay today (Ethereum, 7 days)

Source: every blob transaction labelled for each rollup by [Blobscan](https://blobscan.com) between
2026-11-19 00:00 and 2026-11-26 00:00 UTC. ETH/USD comes from the CoinGecko daily close for each day.
L2 blocks per day were measured on 2026-11-25 by binary search over each L2's own RPC.

| Rollup | Posting txs/day | Blobs/day | Blob fill | Blob fee $/day (mean, min–max) | Exec fee $/day | L2 blocks per posting |
|---|---:|---:|---:|---|---:|---:|
| Base | 2,679 | 13,217 | 95.7% | **$269.00** ($18.94–$839.77) | $97.97 | 161 |
| Arbitrum One | 677 | 2,030 | 99.6% | $53.93 ($2.62–$201.02) | $152.50 | 462 |
| OP Mainnet | 684 | 3,417 | 97.4% | $26.86 ($6.81–$72.29) | $15.32 | 63 |
| Unichain | 191 | 582 | 86.5% | $11.47 ($0.65–$33.66) | $17.13 | 452 |
| Taiko | 225 | 225 | 1.4% | $2.51 | $42.00 | 192 |
| Scroll | 16 | 27 | 85.0% | $0.58 | $4.31 | 2,507 |
| Starknet | 34 | 57 | 100.0% | $0.29 | $6.61 | 1,505 |
| Linea | 8 | 24 | 98.2% | $0.10 | $1.69 | 1,152 |

**ZKsync Era** is not labelled by Blobscan, so it was measured from ZKsync's own `zks_*` API and Ethereum receipts.
On 2026-11-25 it sealed **48 batches** (317 L2 blocks per batch) in 48 commit txs carrying 49 blobs.
Its blob fee was $0.13/day, and $5.59/day including the commit-tx gas.

**Cross-checks against raw chain data:**
- Arbitrum `SequencerInbox.batchCount()` read at the day's first and last L1 block gives
  **713** batches, equal to Blobscan's 713.
- Base batcher txs in raw L1 blocks for one hour: **85**, all of them blob txs. The tx-hash set is identical to Blobscan's.
- One receipt's `blobGasUsed × blobGasPrice` equals Blobscan's fee to the wei.

**Batcher and inbox addresses were verified on-chain:**
- OP Stack: `SystemConfig.batcherHash()`. Unichain's registry file is stale; the on-chain batcher is
  `0x9ef649…`.
- Scroll: `layer2ChainId() = 534352`.
- Linea, Starknet, Arbitrum: rollup-specific view calls.

## 2. Citrea: what it posts to Bitcoin and what it pays

**Source:** Citrea's own node, queried with `ledger_getVerifiedBatchProofsBySlotHeight` and
`ledger_getSequencerCommitmentsOnSlotByNumber`. Fees come from the matching Bitcoin transactions, located via
Citrea's documented reveal-WTXID prefix `0x0202` and fetched from mempool.space.

### 2.1 What Citrea posts

- One **batch proof** per **sequencer commitment** (1,000 L2 blocks).
- The proof is `brotli_q11(proof bytes)`, inscribed in Taproot witness data.
  - This was verified on 30 proofs: Bitcoin reveal size = Brotli-11 size + a median 420 B of fixed overhead.
  - The state diff is inside the proof bytes.
- State-diff composition over 116 proofs, by bytes:

| Share | Content |
|---:|---|
| 67.8% | `E/H/` — 256 EVM block hashes per proof (random 32 B values) |
| 22.8% | `E/s/` — storage: a 32 B **hashed** key and a 32 B value. The contract address and the original slot are not present. |
| 4.7% | `E/a/` — accounts |
| 4.7% | other |

### 2.2 What Citrea pays (1 day, Bitcoin heights 977,566–977,709)

| | Value |
|---|---|
| Batch-proof reveals found | **41**, equal to the 41 reported by Citrea's node |
| Sequencer-commitment reveals found | **44**, equal to the 44 reported by the node. 7 unrelated txs that matched the 2-byte prefix by chance were discarded. |
| Proof bytes per day | 537 KB (median 11.9 KB per proof) |
| Fee rate | median 1 sat/vB (0.12–10.6) |
| **DA cost per day** (reveal + commit txs) | **$154.76** ($130 proofs + $25 commitments, at BTC $59,759) |
| Cost per MB of proof data | **$242/MB** |

## 3. HC on Citrea's real DA payloads

**Method:**
- Data: 116 real proofs. Dictionaries were trained only on the earlier 58; results are on the later 58.
- The `E/s/` storage entries are cut out of the proof bytes and encoded separately. The rest stays Brotli-11.
- Every encoded blob is decoded and compared byte-for-byte.

| Codec on the `E/s/` storage part | Bytes (58 proofs) | vs Brotli-11 |
|---|---:|---:|
| Brotli-11 (what Citrea uses) | 158,481 | — |
| Zstd-19 | 157,459 | +0.6% |
| Brotli-11 + 112 KB custom dictionary | 115,092 | +27.4% |
| **Zstd-19 + 112 KB trained dictionary (no HC)** | **108,876** | **+31.3%** |
| HC + 112 KB dictionary | 112,505 | +29.0% |
| HC + dictionary, values byte-reversed | 111,771 | +29.5% |
| HC without dictionary | — | +0.2% of the full payload |

**Full payload:** HC gives **+6.4%**, while Zstd + Dict gives **+6.9%**. At 41 proofs/day, the Zstd + Dict saving is about
$5/day at 1 sat/vB and about $25/day at 5 sat/vB.

**Conclusion:** on Citrea's current format the gain comes entirely from the trained dictionary. HC's
structural coding needs the address and slot that Citrea's hashed keys remove, so HC alone adds nothing.

## 4. HC on EVM state diffs at real batch sizes

**Data and method:**
- State diffs are captured with `debug_traceBlockByNumber` (`prestateTracer`, `diffMode: true`), using
  the batch sizes measured in Section 1.
- Dictionaries: 112 KB each, trained only on the 150 blocks immediately before the test window.
- Compression levels: Zstd level 9 for all Zstd and HC rows, Brotli q=11.
- Verification: every HC blob is decoded with the public decoder under `DecodeLimits::CONSENSUS`.
  - Updates must match exactly.
  - Deltas must satisfy `op.apply(old) == new`.
  - The Raw/HC payload commitments must be equal.
- Arbitrum and Scroll were not captured: their free RPCs do not serve `prestateTracer` diffs.

### 4.1 Compression of the same state diffs

Savings below are aggregates over all batches. The ranges are the per-batch minimum and maximum.

| Chain | Real batch size | Batches | Slots | HC Updates vs Zstd + Dict | HC Deltas vs Zstd + Dict | HC Updates vs Brotli-11 | HC Updates vs Zstd |
|---|---:|---:|---:|---|---|---:|---:|
| Base | 161 blocks | 8 | 79,789 | **+8.2%** [+7.7, +9.5] | **+12.8%** [+12.1, +15.0] | +8.0% | +11.4% |
| OP Mainnet | 63 blocks | 8 | 29,707 | **+6.2%** [+5.4, +6.9] | **+10.1%** [+9.3, +11.1] | +16.2% | +18.3% |
| Unichain | 452 blocks | 4 | 1,564 | **+3.9%** [−0.2, +5.1] | **+7.7%** [+6.1, +8.3] | +14.0% | +16.2% |
| Taiko | 192 blocks | 5 | 990 | +0.4% [+0.2, +1.3] | +0.2% [−0.1, +1.2] | −0.0% | +0.2% |

**Activity references.** These chains are not rollups and have no DA bill. They are shown only to
show behaviour on busy EVM state:

| Chain | Batch | Batches | Slots | HC Updates vs Zstd + Dict | HC Deltas vs Zstd + Dict | HC Updates vs Zstd |
|---|---:|---:|---:|---|---|---:|
| Ethereum L1 | 50 blocks | 3 | 75,011 | +8.8% [+8.4, +9.1] | +12.1% [+11.9, +12.3] | +8.2% |
| Polygon PoS | 100 blocks | 2 | 81,201 | +7.9% [+7.2, +8.5] | +9.4% [+8.8, +9.9] | +7.6% |
| Gnosis | 100 blocks | 2 | 6,568 | +4.8% [+3.9, +5.6] | +4.6% [+3.5, +5.5] | +15.3% |

**Which row applies to you:**
- `StateUpdates` is the like-for-like comparison for a rollup that posts new values only.
- `StateDeltas` additionally needs old values and the `op.apply(old) == new` rule in the verifier.

### 4.2 State diffs vs the transaction data these rollups post today

The table compares HC state-diff bytes per L2 block with the transaction bytes each rollup actually posted
per L2 block, averaged over the 7 days. These are averages, not the same blocks.

| Chain | Posted tx data per L2 block (7-day mean) | Zstd + Dict state diff | HC Updates state diff |
|---|---:|---:|---:|
| Base | 3,836 B | 1,785 B | 1,639 B |
| OP Mainnet | 10,097 B | 1,627 B | 1,527 B |
| Unichain | 763 B | 26 B | 25 B |
| Taiko | 10 B | 66 B | 66 B |

On busy OP Stack chains, state diffs are a fraction of the transaction data. This is true **with or without HC**:
most of the reduction comes from posting state diffs at all. Taiko is the opposite case.

Posting state diffs instead of transactions changes the security model. It requires validity proofs and new
derivation and verification code, so it is a protocol decision for each rollup, not a compression setting.

**Worked example.** Take a Base-sized chain that posts state diffs with Zstd + Dict: 1,785 B × 432,000 blocks
= 771 MB/day. HC Updates saves a further 8.2% = 63 MB/day. At the 7-day mean blob cost of $0.16/MB, that is
about **$10/day**. The figure scales linearly with the blob price, which ranged ~44× within the measured week.

## 5. SP1 zkVM execution

- [`zkvm/sp1-host/fixtures/multichain/`](../zkvm/sp1-host/fixtures/multichain/) holds the first Section 4
  batch of each chain: 7 chains × 4 codecs = **28 fixtures**.
- The `sp1-execute` CI job runs every fixture inside the real SP1 v6.10.0 zkVM. For each fixture it checks:
  - the 107-byte journal matches the manifest
  - `exit_code == 0`
  - HC and Raw payload commitments are identical
- Per-fixture SP1 cycle counts are in the CI artifact `sp1-execute-report` (`sp1_multichain_execute_report.md`).
- Real CUDA proving (`run_sp1_gpu_bench.sh` without flags) needs an NVIDIA GPU and has **not been run yet**.

## Reproduce

| Step | Script / command |
|---|---|
| Blob txs per rollup | `python -I scripts/blobscan_window.py <rollup> <startISO> <endISO> <out.json>` |
| L2 blocks in a window | `python -I scripts/l2_blocks_window.py <name> <rpc> <start_unix> <end_unix>` |
| Profile table | `python -I scripts/rollup_da_profile.py <dir> data/eth_usd_2026-11.txt data/l2_blocks_per_day_2026-11-25.json <out.json>` |
| Citrea proofs | `python -I scripts/citrea_fetch_proofs.py <num_btc_blocks> <out.json>` (raw copy: [`data/raw/`](data/raw/)) |
| Citrea Bitcoin fees | `python -I scripts/citrea_bitcoin_txs.py <heights…>`, then `scripts/citrea_da_cost.py` |
| SP1 fixtures | `cd zkvm/sp1-host && bash run_sp1_gpu_bench.sh --execute-only` |

The Brotli and Zstd baselines can be recomputed by anyone from the raw data. The HC blobs and dictionaries are
produced by the commercial encoder, but every one of them is decodable and checkable with the open-source
[`hypercomp-decoder`](../crates/hypercomp-decoder/).

The documents in [`docs/archive/`](../docs/archive/) predate this methodology: different splits, small batch
sizes and the pre-v3 format. They are kept only for history, and their figures are superseded by this page.
