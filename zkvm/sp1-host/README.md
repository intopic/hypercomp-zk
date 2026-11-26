# Al-Samawal HyperCompressor v3 — Succinct SP1 v6 RTX 4090 GPU Benchmark & Security Suite

Self-contained engineering verification package running the open-source **`hypercomp-decoder` v3** inside **Succinct SP1 v6.10.0** (with **`patch-sha2-0.10.9-sp1-6.10.0` hardware SHA-256 precompiles** and native **CUDA GPU proving** — no Docker required!).

## What This Suite Tests Automatically

1. **8 Real Mainnet `v3` Fixtures (100% Unseen Chronological Test Splits, Zero Pro Encoder Code Required):**
   - **Gnosis EVM Mainnet** (10 consecutive unseen blocks `49443028..=49443037`, 77 contracts, 570 net slots, `38,405 B` raw DA):
     - `Raw Zstd (lvl 9, no HC)` (`20,426 B`)
     - `Raw Zstd + Dict 112KB (no HC)` (`15,997 B`)
     - `HC v3 Updates + Dict 112KB (A2A)` (`15,338 B`, **-4.1%**)
     - `HC v3 Deltas + Zstd (no dict)` (`18,916 B`)
     - `HC v3 Deltas + Dict 112KB` (`14,797 B`, **-7.5% vs Raw+Dict / -27.6% vs Raw Zstd**)
   - **Citrea Mainnet** (Bitcoin ZK-Rollup, Chain ID 4114 — 39 unseen active blocks, 17 contracts, 131 net slots, `8,865 B` raw DA):
     - `Raw Zstd + Dict` (`4,822 B`) vs. `HC v3 Updates + Dict` (`4,379 B`, **-9.2%**) vs. `HC v3 Deltas + Dict` (`4,291 B`, **-11.0%**)
   - Verifies **100% bit-exact 107-byte public journal parity** against `x86_64` ground truth AND asserts cryptographic lossless equivalence (`HC Updates payload_sha256 == Raw Zstd payload_sha256`).
2. **7 Live Adversarial Security Tests Inside Real SP1:**
   - **`S1` Bit-Flip Corrupt Blob:** Zero panic; cleanly commits `is_valid=false, error_code=19` (+ proves & verifies rejection on GPU).
   - **`S2` `R3-2` Prover Omits Dictionary:** Guest commits `is_valid=false, error_code=17` with `dict_sha256=0x00..`, which the verifier policy (`dict_sha256 == APPROVED`) **rejects** — a malicious prover cannot suppress an honest batch.
   - **`S3` `R3-2` Prover Swaps Wrong Dictionary:** Guest commits `error_code=18` with an unapproved `dict_sha256` → **rejected** by the verifier policy.
   - **`S7` `R3-2` Blob Header References Unapproved Dictionary:** Honest prover with the approved dictionary commits `is_valid=false, error_code=18, dict_sha256 == APPROVED` → **provably invalid** (no liveness halt on permissionless DA).
   - **`S4` `H-1` 71-Byte RLE OOM Bomb:** Cleanly rejected (`error_code=6 UnexpectedEof`) with 0 MiB allocated.
   - **`S5` `N-2` Missing `Frame_Content_Size` (PoC R-3):** Cleanly rejected (`error_code=19`).
   - **`S6` `N-4` Legacy `v2` Frame:** Cleanly rejected (`error_code=2 UnsupportedVersion`).

---

## Quick Start on Windows + RTX 4090 (WSL2 Ubuntu)

### Step 1 — One-Time Setup on the RTX 4090 PC (~5 min)

1. In **Windows PowerShell (Administrator)**, install WSL2 Ubuntu (reboot once if prompted):
   ```powershell
   wsl --install -d Ubuntu
   ```
   *(Your standard Windows NVIDIA driver automatically provides CUDA to WSL2 — do NOT install a Linux NVIDIA driver inside WSL2!)*

2. Open **Ubuntu (WSL2)** and verify your RTX 4090 is visible + install build tools, CUDA 12 runtime libraries, Rust, and SP1 `v6.10.0`:
   ```bash
   nvidia-smi   # should display NVIDIA GeForce RTX 4090 (24564 MiB)

   sudo apt-get update && sudo apt-get install -y build-essential pkg-config libssl-dev curl git clang
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   source "$HOME/.cargo/env"

   curl -L https://sp1up.succinct.xyz | bash
   export PATH="$HOME/.sp1/bin:$PATH"
   sp1up -v v6.10.0
   ```
   *(If `SP1_PROVER=cuda` asks for `libcudart.so.12`, install NVIDIA's WSL2 CUDA 12 runtime toolkit from `developer.nvidia.com/cuda-downloads` -> Linux -> x86_64 -> WSL-Ubuntu -> `cuda-toolkit-12-x`.)*

### Step 2 — Copy Package into WSL2 Home & Run!

> **Tip:** Copy the unzipped `hypercomp-zk` folder into your Linux home directory (`~/hypercomp-zk`), **NOT** `/mnt/c/...`, for 5–10× faster Rust compilation and I/O!

```bash
cp -r /mnt/c/Users/<YOUR_USER>/Desktop/hypercomp-zk ~/hypercomp-zk
cd ~/hypercomp-zk/zkvm/sp1-host
chmod +x run_sp1_gpu_bench.sh

# Full run: Exact SP1 cycles (SHA-256 precompile) + 7/7 live security tests + REAL RTX 4090 Core & Compressed ZK proofs!
./run_sp1_gpu_bench.sh
```

Fast execution-only mode (no GPU proving, ~10 seconds):
```bash
./run_sp1_gpu_bench.sh --execute-only
```

### Step 3 — Collect Results

After completion, two ready-to-share report files are created in `~/hypercomp-zk/zkvm/sp1-host/`:
- `sp1_gpu_bench_report.md` (clean Markdown table ready for `benchmarks/README.md` & grant applications)
- `sp1_gpu_bench_report.json` (full raw JSON telemetry)
