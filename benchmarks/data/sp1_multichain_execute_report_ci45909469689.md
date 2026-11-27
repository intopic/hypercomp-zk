# Al-Samawal HyperCompressor v3 — Succinct SP1 v6 GPU Verification Report

- **SP1 Prover Backend:** `cpu` | **Wire Format:** `v3` | **Guest ELF:** `268216 bytes` (with `patch-sha2-0.10.9-sp1-6.10.0` hardware SHA-256 precompile)

## 1. Real Mainnet SP1 Cycles & GPU Proving Results

| Fixture | Batch | Slots | Raw DA | Blob Size | SP1 Cycles (w/ SHA-256 Precompile) | SP1 Syscalls | Core Proof (s) | Compressed Proof (s) | Parity & Verify |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| Base Mainnet: HC v3 Deltas + Dict | Base Mainnet (161 blks 62702389..=62702549, 9796 slots) | 9796 | 647028 B | 248348 B | 37924645 | 31994 | — | — | PASS (100%) |
| Base Mainnet: HC v3 Updates + Dict (A2A) | Base Mainnet (161 blks 62702389..=62702549, 9796 slots) | 9796 | 647028 B | 260402 B | 34244857 | 32050 | — | — | PASS (100%) |
| Base Mainnet: Raw Zstd (no HC) | Base Mainnet (161 blks 62702389..=62702549, 9796 slots) | 9796 | 647028 B | 294362 B | 35590019 | 29524 | — | — | PASS (100%) |
| Base Mainnet: Raw Zstd + Dict (no HC) | Base Mainnet (161 blks 62702389..=62702549, 9796 slots) | 9796 | 647028 B | 283310 B | 36061435 | 32766 | — | — | PASS (100%) |
| Ethereum L1: HC v3 Deltas + Dict | Ethereum L1 (50 blks 26501834..=26501883, 21767 slots) | 21767 | 1437432 B | 609644 B | 79960071 | 68478 | — | — | PASS (100%) |
| Ethereum L1: HC v3 Updates + Dict (A2A) | Ethereum L1 (50 blks 26501834..=26501883, 21767 slots) | 21767 | 1437432 B | 633895 B | 69820499 | 68540 | — | — | PASS (100%) |
| Ethereum L1: Raw Zstd (no HC) | Ethereum L1 (50 blks 26501834..=26501883, 21767 slots) | 21767 | 1437432 B | 688467 B | 78137491 | 66658 | — | — | PASS (100%) |
| Ethereum L1: Raw Zstd + Dict (no HC) | Ethereum L1 (50 blks 26501834..=26501883, 21767 slots) | 21767 | 1437432 B | 692072 B | 77255972 | 70358 | — | — | PASS (100%) |
| Gnosis Mainnet: HC v3 Deltas + Dict | Gnosis Mainnet (100 blks 49484823..=49484922, 3045 slots) | 3045 | 201308 B | 85034 B | 12187093 | 12676 | — | — | PASS (100%) |
| Gnosis Mainnet: HC v3 Updates + Dict (A2A) | Gnosis Mainnet (100 blks 49484823..=49484922, 3045 slots) | 3045 | 201308 B | 84725 B | 11114921 | 12564 | — | — | PASS (100%) |
| Gnosis Mainnet: Raw Zstd (no HC) | Gnosis Mainnet (100 blks 49484823..=49484922, 3045 slots) | 3045 | 201308 B | 99752 B | 10253323 | 9446 | — | — | PASS (100%) |
| Gnosis Mainnet: Raw Zstd + Dict (no HC) | Gnosis Mainnet (100 blks 49484823..=49484922, 3045 slots) | 3045 | 201308 B | 88144 B | 11994628 | 12670 | — | — | PASS (100%) |
| Optimism Mainnet: HC v3 Deltas + Dict | Optimism Mainnet (63 blks 160065606..=160065668, 2610 slots) | 2610 | 172734 B | 60810 B | 10680036 | 11004 | — | — | PASS (100%) |
| Optimism Mainnet: HC v3 Updates + Dict (A2A) | Optimism Mainnet (63 blks 160065606..=160065668, 2610 slots) | 2610 | 172734 B | 63414 B | 9512911 | 11002 | — | — | PASS (100%) |
| Optimism Mainnet: Raw Zstd (no HC) | Optimism Mainnet (63 blks 160065606..=160065668, 2610 slots) | 2610 | 172734 B | 77895 B | 8996299 | 7868 | — | — | PASS (100%) |
| Optimism Mainnet: Raw Zstd + Dict (no HC) | Optimism Mainnet (63 blks 160065606..=160065668, 2610 slots) | 2610 | 172734 B | 67524 B | 10179966 | 11130 | — | — | PASS (100%) |
| Polygon PoS: HC v3 Deltas + Dict | Polygon PoS (100 blks 98014971..=98015070, 35326 slots) | 35326 | 2297121 B | 1013063 B | 130802234 | 108318 | — | — | PASS (100%) |
| Polygon PoS: HC v3 Updates + Dict (A2A) | Polygon PoS (100 blks 98014971..=98015070, 35326 slots) | 35326 | 2297121 B | 1031074 B | 114340552 | 107774 | — | — | PASS (100%) |
| Polygon PoS: Raw Zstd (no HC) | Polygon PoS (100 blks 98014971..=98015070, 35326 slots) | 35326 | 2297121 B | 1114093 B | 111790626 | 106780 | — | — | PASS (100%) |
| Polygon PoS: Raw Zstd + Dict (no HC) | Polygon PoS (100 blks 98014971..=98015070, 35326 slots) | 35326 | 2297121 B | 1111073 B | 109556914 | 110274 | — | — | PASS (100%) |
| Taiko Alethia: HC v3 Deltas + Dict | Taiko Alethia (192 blks 14542495..=14542686, 198 slots) | 198 | 12772 B | 12583 B | 1021741 | 1286 | — | — | PASS (100%) |
| Taiko Alethia: HC v3 Updates + Dict (A2A) | Taiko Alethia (192 blks 14542495..=14542686, 198 slots) | 198 | 12772 B | 12580 B | 553949 | 1222 | — | — | PASS (100%) |
| Taiko Alethia: Raw Zstd (no HC) | Taiko Alethia (192 blks 14542495..=14542686, 198 slots) | 198 | 12772 B | 12579 B | 507318 | 800 | — | — | PASS (100%) |
| Taiko Alethia: Raw Zstd + Dict (no HC) | Taiko Alethia (192 blks 14542495..=14542686, 198 slots) | 198 | 12772 B | 12572 B | 803511 | 1456 | — | — | PASS (100%) |
| Unichain Mainnet: HC v3 Deltas + Dict | Unichain Mainnet (452 blks 64980893..=64981344, 176 slots) | 176 | 12064 B | 4651 B | 1058172 | 1110 | — | — | PASS (100%) |
| Unichain Mainnet: HC v3 Updates + Dict (A2A) | Unichain Mainnet (452 blks 64980893..=64981344, 176 slots) | 176 | 12064 B | 4964 B | 1016416 | 1184 | — | — | PASS (100%) |
| Unichain Mainnet: Raw Zstd (no HC) | Unichain Mainnet (452 blks 64980893..=64981344, 176 slots) | 176 | 12064 B | 6836 B | 737489 | 604 | — | — | PASS (100%) |
| Unichain Mainnet: Raw Zstd + Dict (no HC) | Unichain Mainnet (452 blks 64980893..=64981344, 176 slots) | 176 | 12064 B | 4956 B | 1160377 | 1474 | — | — | PASS (100%) |
