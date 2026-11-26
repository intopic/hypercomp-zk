# GPU Test Plan — `hypercomp-zk` SP1 v6 Verification (for the agent/operator on the GPU PC)

This file is self-contained: it tells whoever runs the test on the NVIDIA GPU machine exactly what to
do, what must pass, and what to report back. No other context is required.

## 0. Environment (one-time)
- Run inside **WSL2 Ubuntu** (or native Linux x86_64) with an NVIDIA GPU visible to `nvidia-smi`.
- Clone into the Linux home directory (NOT `/mnt/c/...`):
  ```bash
  cd ~ && git clone https://github.com/intopic/hypercomp-zk.git && cd hypercomp-zk
  ```
- Install the toolchain exactly as described in [`README.md`](README.md) (Step 1): build tools, Rust,
  `sp1up -v v6.10.0`, and (if CUDA proving asks for `libcudart.so.12`) the WSL CUDA 12 runtime.
- Record versions: `nvidia-smi`, `rustc --version`, `cargo prove --version`.

## 1. Run
```bash
cd ~/hypercomp-zk/zkvm/sp1-host
./run_sp1_gpu_bench.sh --execute-only   # fast: decoder tests + 8 fixtures + 7 security tests
./run_sp1_gpu_bench.sh                  # full: adds real CUDA Core + Compressed proofs
```

## 2. Pass criteria (all must hold)
1. `[2/4]` decoder tests: `cargo test --workspace --all-features --locked` → **10 passed, 0 failed**.
2. All 8 fixtures in `fixtures/expected_manifest.json` execute with **exit_code 0** and a **107-byte
   journal** whose `blob_sha256`, `dict_sha256` and `payload_sha256` match the manifest exactly.
3. Lossless equivalence: `HC Updates` payload SHA-256 == `Raw Zstd` payload SHA-256 for Gnosis and Citrea.
4. Security suite — **7/7 PASS** with these exact outcomes:

| Test | Input | Expected journal | Verifier policy (`dict_sha256 == APPROVED`) |
|---|---|---|---|
| S1 | bit-flipped blob | `is_valid=0`, `error_code=19` | — |
| S2 | prover omits dictionary | `is_valid=0`, `error_code=17`, `dict_sha256=00…` | **rejected** |
| S3 | prover swaps dictionary | `is_valid=0`, `error_code=18`, unapproved `dict_sha256` | **rejected** |
| S4 | 69 B RLE bomb | `is_valid=0`, `error_code=6` | — |
| S5 | Zstd frame without `Frame_Content_Size` | `is_valid=0`, `error_code=19` | — |
| S6 | legacy v2 frame | `is_valid=0`, `error_code=2` | — |
| S7 | blob header references unapproved dictionary, approved dict supplied | `is_valid=0`, `error_code=18`, `dict_sha256` = approved | **accepted** (provably invalid, no halt) |

   **No test may abort/panic the guest** (`exit_code != 0` is a failure for every test, including S2/S3/S7).
5. Full run only: every Core and Compressed proof **verifies** (`PASS (100%)` in the report).
6. Multi-mainnet set (`fixtures/multichain`, 64 fixtures = 8 chains x 2 batch sizes x 4 codecs:
   Ethereum, Base, Optimism, Polygon PoS, Unichain, Taiko, Gnosis, Citrea): every fixture executes
   with `exit_code 0` and a manifest-exact journal, and every `*_hc_updates_dict` payload equals its
   `*_raw_zstd` / `*_raw_zstd_dict` payload. Reports: `sp1_multichain_execute_report.*` and, in a full
   run, `sp1_multichain_gpu_report.*` (commit these too).

## 3. Report back
- Commit the generated reports (do NOT commit `target/`):
  ```bash
  cd ~/hypercomp-zk
  git add zkvm/sp1-host/sp1_execute_report.* zkvm/sp1-host/sp1_gpu_bench_report.* \
          zkvm/sp1-guest/Cargo.lock zkvm/sp1-host/Cargo.lock
  git commit -m "bench(sp1): GPU run on <GPU model>, SP1 v6.10.0"
  git push
  ```
  (Committing the two `Cargo.lock` files makes later runs reproducible.)
- If anything fails: do **not** change thresholds or expected values to make it pass. Save the full
  console output to `zkvm/sp1-host/gpu_run_failure.log`, commit it, and describe which criterion failed.
