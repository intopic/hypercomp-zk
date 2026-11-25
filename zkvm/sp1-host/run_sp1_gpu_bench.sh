#!/usr/bin/env bash
set -euo pipefail

# Al-Samawal Rollup HyperCompressor v3 â€” One-Click Succinct SP1 v6 RTX 4090 CUDA GPU Benchmark
# Run inside WSL2 Ubuntu (Windows RTX 4090) or native Linux x86_64 with NVIDIA CUDA 12 runtime.
#
# Usage:
#   ./run_sp1_gpu_bench.sh                 # Full run: Execute + RTX 4090 CUDA Core & Compressed proofs
#   ./run_sp1_gpu_bench.sh --execute-only  # Fast run (~10s): Exact SP1 cycles + 6/6 live security tests (no GPU proving)
#   ./run_sp1_gpu_bench.sh --core-only     # Execute + RTX 4090 Core STARK proofs only

export PATH="$HOME/.sp1/bin:$HOME/.cargo/bin:$PATH"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="prove"
PROOF_KIND="both"
EXTRA_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --execute-only) MODE="execute" ;;
    --core-only)    MODE="prove"; PROOF_KIND="core" ;;
    --compressed-only) MODE="prove"; PROOF_KIND="compressed" ;;
    *) EXTRA_ARGS+=("$arg") ;;
  esac
done

echo "=========================================================================================="
echo "  Al-Samawal HyperCompressor v3 â€” Succinct SP1 v6 GPU Engineering Test Suite"
echo "=========================================================================================="

echo "[1/4] Checking GPU & Toolchain Environment..."
if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader
else
  echo "WARNING: nvidia-smi not found! Falling back to SP1_PROVER=cpu (or install NVIDIA Windows driver for WSL2)."
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: Rust/Cargo not found. Install with:"
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source \$HOME/.cargo/env"
  exit 1
fi

if ! command -v cargo-prove >/dev/null 2>&1; then
  echo "ERROR: Succinct SP1 toolchain (cargo-prove) not found. Install with:"
  echo "  curl -L https://sp1up.succinct.xyz | bash && source ~/.bashrc && sp1up -v v6.10.0"
  exit 1
fi
echo "  rustc       : $(rustc --version)"
echo "  cargo-prove : $(cargo prove --version)"

echo ""
echo "[2/4] Verifying Open-Source #![no_std] Decoder Tests (hypercomp-decoder v3)..."
(cd ../.. && cargo test --workspace --all-features --locked)

echo ""
echo "[3/4] Running Fast SP1 Execution & 6/6 Live Adversarial Security Tests (SHA-256 Precompile)..."
RUST_LOG=warn SP1_PROVER=cpu cargo run --release -- \
  --mode execute \
  --out-md sp1_execute_report.md \
  --out-json sp1_execute_report.json \
  "${EXTRA_ARGS[@]}"

if [ "$MODE" = "prove" ]; then
  PROVER_BACKEND="cuda"
  if ! command -v nvidia-smi >/dev/null 2>&1; then
    PROVER_BACKEND="cpu"
  fi
  echo ""
  echo "[4/4] Running REAL Cryptographic ZK Proving (SP1_PROVER=$PROVER_BACKEND, proof_kind=$PROOF_KIND)..."
  RUST_LOG=info SP1_PROVER="$PROVER_BACKEND" cargo run --release -- \
    --mode prove \
    --proof-kind "$PROOF_KIND" \
    --out-md sp1_gpu_bench_report.md \
    --out-json sp1_gpu_bench_report.json \
    "${EXTRA_ARGS[@]}"

  echo ""
  echo "=========================================================================================="
  echo "  DONE! Ready-to-publish GPU benchmark report:"
  echo "    - $SCRIPT_DIR/sp1_gpu_bench_report.md"
  echo "    - $SCRIPT_DIR/sp1_gpu_bench_report.json"
  echo "=========================================================================================="
else
  echo ""
  echo "[4/4] Skipping GPU proving (--execute-only). Report saved to sp1_execute_report.md"
fi
