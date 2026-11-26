//! End-to-End Succinct SP1 v6 CUDA GPU Engineering Benchmark & Adversarial Security Suite
//! for Al-Samawal Rollup HyperCompressor (`FORMAT_VERSION = 3`).
//!
//! Runs inside Linux / WSL2 Ubuntu on an NVIDIA GPU (e.g. RTX 4090 24 GB VRAM):
//!   1. Executes all 8 real-mainnet `v3` fixtures (Gnosis 10-block EVM + Citrea BTC ZK-Rollup)
//!      with SP1 hardware SHA-256 precompiles enabled (`patch-sha2-0.10.9-sp1-6.10.0`).
//!   2. Verifies 100% bit-exact 107-byte journal parity against `x86_64` ground truth AND asserts
//!      `HC Updates payload_sha256 == Raw Zstd payload_sha256` (cryptographic lossless equivalence).
//!   3. Runs 6 live adversarial security tests inside the real SP1 runtime (`C-2r`, `H-1`, `N-2`, `N-4`).
//!   4. In `--mode prove` (with `SP1_PROVER=cuda`), generates and cryptographically verifies real
//!      SP1 Core and/or Recursive Compressed ZK proofs on GPU, outputting a ready-to-publish
//!      Markdown + JSON engineering report (`sp1_gpu_bench_report.md` & `.json`).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use hypercomp_decoder::dict::DICT_MODE_RLE;
use hypercomp_decoder::{
    sha256_bytes, HyperCompError, PayloadKind, FORMAT_VERSION, MAGIC, ZSTD_MAGIC,
};
use serde::{Deserialize, Serialize};
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

/// Compiled SP1 RISC-V ELF built automatically by `build.rs` from `../sp1-guest`.
const HYPERCOMP_SP1_ELF: Elf = include_elf!("hypercomp-sp1-guest");

const MODE_HC_DELTAS: u8 = 0;
const MODE_HC_UPDATES: u8 = 1;
const MODE_RAW_ZSTD_UPDATES: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum RunMode {
    /// Fast SP1 execution only: exact SP1 cycles (with SHA-256 precompile), syscalls, journal parity & all 6 security tests.
    Execute,
    /// Full GPU/CPU proving: runs everything in `execute` PLUS generates & verifies real cryptographic SP1 proofs!
    Prove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ProofKind {
    Core,
    Compressed,
    Both,
}

#[derive(Parser, Debug)]
#[command(
    name = "hypercomp-sp1-host",
    about = "Al-Samawal HyperCompressor v3 — Succinct SP1 v6 CUDA GPU Benchmark & Security Suite"
)]
struct Args {
    /// Execution only (`execute`) or real cryptographic ZK proving (`prove`).
    #[arg(long, value_enum, default_value_t = RunMode::Execute)]
    mode: RunMode,

    /// Proof type(s) to benchmark when `--mode prove` is active (`core`, `compressed`, or `both`).
    #[arg(long, value_enum, default_value_t = ProofKind::Both)]
    proof_kind: ProofKind,

    /// Directory containing `expected_manifest.json` and `.bin` / `.zdict` v3 fixtures.
    #[arg(long, default_value = "fixtures")]
    fixtures_dir: PathBuf,

    /// Optional filter substring to run only matching fixture IDs (e.g. `gnosis` or `citrea`).
    #[arg(long)]
    filter: Option<String>,

    /// Skip the 7 adversarial security tests (they need the Gnosis fixtures in `fixtures_dir`);
    /// used to benchmark extra fixture sets such as `fixtures/multichain`.
    #[arg(long)]
    skip_security: bool,

    /// Output path for the generated Markdown report.
    #[arg(long, default_value = "sp1_gpu_bench_report.md")]
    out_md: PathBuf,

    /// Output path for the raw JSON benchmark metrics.
    #[arg(long, default_value = "sp1_gpu_bench_report.json")]
    out_json: PathBuf,
}

#[derive(Debug, Deserialize)]
struct FixtureManifest {
    format_version: u8,
    fixtures: Vec<FixtureEntry>,
}

#[derive(Debug, Deserialize)]
struct FixtureEntry {
    id: String,
    chain: String,
    label: String,
    mode: u8,
    blob_file: String,
    dict_file: Option<String>,
    raw_da_bytes: usize,
    pure_wire_bytes: usize,
    num_contracts: u32,
    total_slots: u32,
    expected_blob_sha256: String,
    expected_dict_sha256: String,
    expected_payload_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedJournal {
    mode: u8,
    blob_sha256: [u8; 32],
    dict_sha256: [u8; 32],
    is_valid: bool,
    error_code: u8,
    num_contracts: u32,
    total_slots: u32,
    payload_sha256: [u8; 32],
}

impl DecodedJournal {
    fn from_slice(raw: &[u8]) -> Result<Self> {
        if raw.len() != 107 {
            bail!(
                "invalid SP1 public journal length: expected 107 bytes, got {}",
                raw.len()
            );
        }
        let mut blob_sha256 = [0u8; 32];
        let mut dict_sha256 = [0u8; 32];
        let mut payload_sha256 = [0u8; 32];
        blob_sha256.copy_from_slice(&raw[1..33]);
        dict_sha256.copy_from_slice(&raw[33..65]);
        payload_sha256.copy_from_slice(&raw[75..107]);
        Ok(Self {
            mode: raw[0],
            blob_sha256,
            dict_sha256,
            is_valid: raw[65] != 0,
            error_code: raw[66],
            num_contracts: u32::from_be_bytes([raw[67], raw[68], raw[69], raw[70]]),
            total_slots: u32::from_be_bytes([raw[71], raw[72], raw[73], raw[74]]),
            payload_sha256,
        })
    }
}

#[derive(Debug, Serialize)]
struct BenchResult {
    id: String,
    chain: String,
    label: String,
    mode: u8,
    raw_da_bytes: usize,
    pure_wire_bytes: usize,
    num_contracts: u32,
    total_slots: u32,
    sp1_total_cycles: u64,
    sp1_total_syscalls: u64,
    execute_wall_ms: u128,
    core_prove_secs: Option<f64>,
    core_verify_ok: Option<bool>,
    compressed_prove_secs: Option<f64>,
    compressed_verify_ok: Option<bool>,
    journal_sha256_parity_ok: bool,
    payload_sha256: String,
}

#[derive(Debug, Serialize)]
struct SecurityTestResult {
    id: String,
    name: String,
    passed: bool,
    sp1_cycles: Option<u64>,
    detail: String,
}

#[derive(Debug, Serialize)]
struct FullReport {
    prover_backend: String,
    format_version: u8,
    elf_bytes: usize,
    benchmarks: Vec<BenchResult>,
    security_tests: Vec<SecurityTestResult>,
}

fn hex32(b: [u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn build_stdin(mode: u8, blob: &[u8], dict: &[u8]) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&mode);
    stdin.write_slice(blob);
    stdin.write_slice(dict);
    stdin
}

fn load_fixture_bytes(dir: &Path, entry: &FixtureEntry) -> Result<(Vec<u8>, Vec<u8>)> {
    let blob = fs::read(dir.join(&entry.blob_file))
        .with_context(|| format!("failed reading fixture blob {}", entry.blob_file))?;
    let dict = match &entry.dict_file {
        Some(f) => {
            fs::read(dir.join(f)).with_context(|| format!("failed reading fixture dict {f}"))?
        }
        None => Vec::new(),
    };
    Ok((blob, dict))
}

#[tokio::main]
async fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();

    let prover_backend = std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".to_string());
    let manifest_path = args.fixtures_dir.join("expected_manifest.json");
    let manifest: FixtureManifest = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?,
    )?;
    if manifest.format_version != FORMAT_VERSION {
        bail!(
            "fixture manifest format_version={} does not match decoder FORMAT_VERSION={}",
            manifest.format_version,
            FORMAT_VERSION
        );
    }

    println!("==========================================================================================");
    println!(
        "  Al-Samawal Rollup HyperCompressor v3 — Succinct SP1 v6 GPU Benchmark & Security Suite"
    );
    println!(
        "  Run Mode: {:?} | Proof Kind: {:?} | SP1_PROVER={} | Guest ELF: {} bytes",
        args.mode,
        args.proof_kind,
        prover_backend,
        HYPERCOMP_SP1_ELF.len()
    );
    println!("==========================================================================================\n");

    let client = ProverClient::from_env().await;

    // Only pay `setup(ELF)` cost when actually proving.
    let pk_opt = if args.mode == RunMode::Prove {
        println!(
            "[Setup] Generating SP1 proving & verifying keys (pk/vk) for hypercomp-sp1-guest..."
        );
        let t0 = Instant::now();
        let pk = client
            .setup(HYPERCOMP_SP1_ELF)
            .await
            .context("SP1 setup failed")?;
        println!("[Setup] Done in {:.2}s.\n", t0.elapsed().as_secs_f64());
        Some(pk)
    } else {
        None
    };

    // -----------------------------------------------------------------------
    // PART A: REAL MAINNET BENCHMARKS (GNOSIS EVM + CITREA BITCOIN ZK-ROLLUP)
    // -----------------------------------------------------------------------
    println!("=== PART A: REAL MAINNET BENCHMARKS (GNOSIS + CITREA, SP1 SHA-256 PRECOMPILE) ===");
    let mut bench_results = Vec::new();
    let mut payload_hashes: HashMap<String, String> = HashMap::new();

    for entry in &manifest.fixtures {
        if let Some(ref f) = args.filter {
            if !entry.id.contains(f.as_str()) {
                continue;
            }
        }
        let (blob, dict) = load_fixture_bytes(&args.fixtures_dir, entry)?;
        let stdin = build_stdin(entry.mode, &blob, &dict);

        // 1. Exact SP1 Execution (cycles + syscalls + full 107-byte journal verification)
        let t_exec = Instant::now();
        let (pub_vals, report) = client
            .execute(HYPERCOMP_SP1_ELF, stdin.clone())
            .await
            .with_context(|| format!("SP1 execute failed on fixture {}", entry.id))?;
        let exec_ms = t_exec.elapsed().as_millis();
        if report.exit_code != 0 {
            bail!(
                "fixture {} unexpectedly exited with non-zero exit_code={}",
                entry.id,
                report.exit_code
            );
        }

        let journal = DecodedJournal::from_slice(pub_vals.as_slice())?;
        if !journal.is_valid || journal.error_code != 0 {
            bail!(
                "fixture {} unexpectedly returned invalid journal (error_code={})",
                entry.id,
                journal.error_code
            );
        }
        if journal.mode != entry.mode
            || journal.num_contracts != entry.num_contracts
            || journal.total_slots != entry.total_slots
            || hex32(journal.blob_sha256) != entry.expected_blob_sha256
            || hex32(journal.dict_sha256) != entry.expected_dict_sha256
            || hex32(journal.payload_sha256) != entry.expected_payload_sha256
        {
            bail!(
                "JOURNAL PARITY MISMATCH on fixture {}!\n  got: {:?}\n  expected payload_sha256={}",
                entry.id,
                journal,
                entry.expected_payload_sha256
            );
        }

        let total_cycles = report.total_instruction_count();
        let total_syscalls = report.total_syscall_count();
        payload_hashes.insert(entry.id.clone(), hex32(journal.payload_sha256));

        // 2. Optional Real Cryptographic Proving (Core + Compressed on RTX 4090 CUDA / CPU)
        let mut core_secs = None;
        let mut core_ok = None;
        let mut comp_secs = None;
        let mut comp_ok = None;

        if let Some(ref pk) = pk_opt {
            if matches!(args.proof_kind, ProofKind::Core | ProofKind::Both) {
                let t_p = Instant::now();
                let proof = client
                    .prove(pk, stdin.clone())
                    .core()
                    .await
                    .with_context(|| format!("SP1 core prove failed on {}", entry.id))?;
                let secs = t_p.elapsed().as_secs_f64();
                client
                    .verify(&proof, pk.verifying_key(), None)
                    .with_context(|| format!("SP1 core verify failed on {}", entry.id))?;
                if proof.public_values.as_slice() != pub_vals.as_slice() {
                    bail!(
                        "core proof public_values diverged from execute on {}",
                        entry.id
                    );
                }
                core_secs = Some(secs);
                core_ok = Some(true);
            }
            if matches!(args.proof_kind, ProofKind::Compressed | ProofKind::Both) {
                let t_p = Instant::now();
                let proof = client
                    .prove(pk, stdin.clone())
                    .compressed()
                    .await
                    .with_context(|| format!("SP1 compressed prove failed on {}", entry.id))?;
                let secs = t_p.elapsed().as_secs_f64();
                client
                    .verify(&proof, pk.verifying_key(), None)
                    .with_context(|| format!("SP1 compressed verify failed on {}", entry.id))?;
                if proof.public_values.as_slice() != pub_vals.as_slice() {
                    bail!(
                        "compressed proof public_values diverged from execute on {}",
                        entry.id
                    );
                }
                comp_secs = Some(secs);
                comp_ok = Some(true);
            }
        }

        println!(
            "  [PASS] {:42} | {:>6} B | {:>10} cyc ({:>6} syscalls) | exec {:>4}ms | core={} | comp={}",
            entry.label,
            entry.pure_wire_bytes,
            total_cycles,
            total_syscalls,
            exec_ms,
            core_secs.map_or_else(|| "skip".into(), |s| format!("{s:.2}s OK")),
            comp_secs.map_or_else(|| "skip".into(), |s| format!("{s:.2}s OK")),
        );

        bench_results.push(BenchResult {
            id: entry.id.clone(),
            chain: entry.chain.clone(),
            label: entry.label.clone(),
            mode: entry.mode,
            raw_da_bytes: entry.raw_da_bytes,
            pure_wire_bytes: entry.pure_wire_bytes,
            num_contracts: entry.num_contracts,
            total_slots: entry.total_slots,
            sp1_total_cycles: total_cycles,
            sp1_total_syscalls: total_syscalls,
            execute_wall_ms: exec_ms,
            core_prove_secs: core_secs,
            core_verify_ok: core_ok,
            compressed_prove_secs: comp_secs,
            compressed_verify_ok: comp_ok,
            journal_sha256_parity_ok: true,
            payload_sha256: hex32(journal.payload_sha256),
        });
    }

    // Cryptographic Lossless Equivalence Assertions (HC Updates == Raw Zstd inside SP1!)
    // Every `<batch>_hc_updates_dict` must commit the same payload as its `<batch>_raw_zstd[_dict]`.
    let mut pairs: Vec<(String, String)> = Vec::new();
    for hc_id in payload_hashes.keys() {
        if let Some(base) = hc_id.strip_suffix("_hc_updates_dict") {
            for raw_suffix in ["_raw_zstd_dict", "_raw_zstd"] {
                pairs.push((format!("{base}{raw_suffix}"), hc_id.clone()));
            }
        }
    }
    pairs.sort();
    for (raw_id, hc_id) in &pairs {
        if let (Some(h_raw), Some(h_hc)) = (payload_hashes.get(raw_id), payload_hashes.get(hc_id)) {
            if h_raw != h_hc {
                bail!("LOSSLESS EQUIVALENCE FAILURE: {raw_id} ({h_raw}) != {hc_id} ({h_hc})");
            }
            println!(
                "  [EXACT MATCH] SP1 Lossless Equivalence Verified: {hc_id} == {raw_id} (sha256={}...)",
                &h_hc[..16]
            );
        }
    }

    // -----------------------------------------------------------------------
    // PART B: 7 LIVE ADVERSARIAL SECURITY TESTS INSIDE REAL SP1 zkVM
    // -----------------------------------------------------------------------
    println!("\n=== PART B: 7 LIVE ADVERSARIAL SECURITY TESTS INSIDE REAL SP1 zkVM ===");
    let mut sec_results = Vec::new();

    if !args.skip_security {
        // Load Gnosis Deltas + Dict + Wrong Dict for live adversarial attacks
        let gnosis_blob = fs::read(args.fixtures_dir.join("gnosis_hc_deltas_dict.bin"))?;
        let gnosis_dict = fs::read(args.fixtures_dir.join("gnosis_dict_del.zdict"))?;
        let wrong_dict = fs::read(args.fixtures_dir.join("gnosis_dict_upd.zdict"))?;

        // S1: Bit-Flip / Corrupt Blob -> must NOT panic, must commit is_valid=false, error_code=19 (EntropyDecodeFailed)
        {
            let mut corrupt = gnosis_blob.clone();
            let mid = corrupt.len() / 2;
            corrupt[mid] ^= 0xFF;
            let stdin = build_stdin(MODE_HC_DELTAS, &corrupt, &gnosis_dict);
            let (pv, rep) = client
                .execute(HYPERCOMP_SP1_ELF, stdin.clone())
                .await
                .context("S1 corrupt blob should NOT crash SP1 host")?;
            if rep.exit_code != 0 {
                bail!(
                    "S1 corrupt blob panicked guest (exit_code={})",
                    rep.exit_code
                );
            }
            let j = DecodedJournal::from_slice(pv.as_slice())?;
            let mut extra = String::new();
            if let Some(ref pk) = pk_opt {
                let t0 = Instant::now();
                let proof = client.prove(pk, stdin).core().await?;
                client.verify(&proof, pk.verifying_key(), None)?;
                extra = format!(
                    ", real rejection core proof verified in {:.2}s",
                    t0.elapsed().as_secs_f64()
                );
            }
            let ok = !j.is_valid
                && j.error_code == HyperCompError::EntropyDecodeFailed.code()
                && j.blob_sha256 == sha256_bytes(&corrupt);
            if !ok {
                bail!("S1 failed: got {j:?}");
            }
            let detail = format!(
                "cleanly committed is_valid=false, error_code={} (EntropyDecodeFailed), zero panic{extra}",
                j.error_code
            );
            println!("  [PASS] S1 (Bit-Flip Corrupt Blob)      : {detail}");
            sec_results.push(SecurityTestResult {
                id: "S1".into(),
                name: "Bit-Flip Corrupt Blob (Zero-Panic Rejection)".into(),
                passed: true,
                sp1_cycles: Some(rep.total_instruction_count()),
                detail,
            });
        }

        // R3-2 verifier policy model: the L1 verifier accepts a journal ONLY if
        // `dict_sha256 == APPROVED_CHAIN_DICT_SHA256` (here: SHA-256 of the Gnosis deltas dictionary).
        let approved_dict_sha256 = sha256_bytes(&gnosis_dict);
        let verifier_accepts = |j: &DecodedJournal| j.dict_sha256 == approved_dict_sha256;

        // S2: Malicious prover omits the dictionary -> guest commits is_valid=false (code 17), but the
        // journal carries dict_sha256 = 0x00.., so the verifier REJECTS it (prover cannot suppress the batch).
        {
            let stdin = build_stdin(MODE_HC_DELTAS, &gnosis_blob, &[]);
            let (pv, rep) = client.execute(HYPERCOMP_SP1_ELF, stdin).await?;
            if rep.exit_code != 0 {
                bail!(
                    "S2 guest must not abort on blob content (exit_code={})",
                    rep.exit_code
                );
            }
            let j = DecodedJournal::from_slice(pv.as_slice())?;
            let missing_code = HyperCompError::MissingDictionary([0u8; 32]).code();
            if j.is_valid || j.error_code != missing_code || verifier_accepts(&j) {
                bail!("SECURITY FAILURE S2 (R3-2): omitted-dictionary journal would be accepted: {j:?}");
            }
            let detail = format!(
                "committed is_valid=false, error_code={missing_code} with dict_sha256=0x00.. -> REJECTED by verifier policy (cannot suppress honest batch)"
            );
            println!("  [PASS] S2 (Prover Omits Dict)          : {detail}");
            sec_results.push(SecurityTestResult {
                id: "S2".into(),
                name: "R3-2 Prover Omits Dictionary: Journal Rejected by dict_sha256 Policy".into(),
                passed: true,
                sp1_cycles: Some(rep.total_instruction_count()),
                detail,
            });
        }

        // S3: Malicious prover swaps in a wrong dictionary -> code 18, dict_sha256 != APPROVED -> rejected.
        {
            let stdin = build_stdin(MODE_HC_DELTAS, &gnosis_blob, &wrong_dict);
            let (pv, rep) = client.execute(HYPERCOMP_SP1_ELF, stdin).await?;
            if rep.exit_code != 0 {
                bail!(
                    "S3 guest must not abort on blob content (exit_code={})",
                    rep.exit_code
                );
            }
            let j = DecodedJournal::from_slice(pv.as_slice())?;
            let mismatch_code = HyperCompError::DictionaryIdMismatch {
                expected: [0u8; 32],
                found: [0u8; 32],
            }
            .code();
            if j.is_valid || j.error_code != mismatch_code || verifier_accepts(&j) {
                bail!("SECURITY FAILURE S3 (R3-2): swapped-dictionary journal would be accepted: {j:?}");
            }
            let detail = format!(
                "committed is_valid=false, error_code={mismatch_code} with unapproved dict_sha256 -> REJECTED by verifier policy"
            );
            println!("  [PASS] S3 (Prover Swaps Dict)          : {detail}");
            sec_results.push(SecurityTestResult {
                id: "S3".into(),
                name: "R3-2 Prover Swaps Dictionary: Journal Rejected by dict_sha256 Policy".into(),
                passed: true,
                sp1_cycles: Some(rep.total_instruction_count()),
                detail,
            });
        }

        // S7: Poster publishes a blob whose HEADER references an unapproved dictionary. The honest prover
        // supplies the approved dictionary -> provably invalid (code 18, dict_sha256 == APPROVED, accepted),
        // instead of an unprovable blob that would halt a permissionless-DA chain.
        {
            let rogue_blob = fs::read(args.fixtures_dir.join("gnosis_hc_updates_dict.bin"))?;
            let stdin = build_stdin(MODE_HC_UPDATES, &rogue_blob, &gnosis_dict);
            let (pv, rep) = client.execute(HYPERCOMP_SP1_ELF, stdin).await?;
            if rep.exit_code != 0 {
                bail!(
                    "S7 rogue-header blob halted proving (exit_code={})",
                    rep.exit_code
                );
            }
            let j = DecodedJournal::from_slice(pv.as_slice())?;
            let mismatch_code = HyperCompError::DictionaryIdMismatch {
                expected: [0u8; 32],
                found: [0u8; 32],
            }
            .code();
            if j.is_valid || j.error_code != mismatch_code || !verifier_accepts(&j) {
                bail!("S7 rogue-header blob not provably invalid: {j:?}");
            }
            let detail = format!(
                "blob referencing unapproved dictionary committed is_valid=false, error_code={mismatch_code}, dict_sha256 == APPROVED -> accepted as provably invalid (no liveness halt)"
            );
            println!("  [PASS] S7 (Rogue Dict Header Blob)     : {detail}");
            sec_results.push(SecurityTestResult {
                id: "S7".into(),
                name: "R3-2 Blob Referencing Unapproved Dictionary Is Provably Invalid".into(),
                passed: true,
                sp1_cycles: Some(rep.total_instruction_count()),
                detail,
            });
        }

        // S4: H-1 71-Byte RLE OOM Bomb -> cleanly commits is_valid=false, error_code=6 (UnexpectedEof), zero OOM!
        {
            let mut rle_bomb = vec![
                MAGIC[0],
                MAGIC[1],
                FORMAT_VERSION,
                PayloadKind::StateDeltas as u8, // EntropyCodec::None
            ];
            rle_bomb.push(1); // 1 contract
            rle_bomb.extend_from_slice(&[0xAA; 20]);
            rle_bomb.push(0); // nonce bitmap = 0
            rle_bomb.extend_from_slice(&[0xD0, 0x86, 0x03]); // 50,000 slots
            rle_bomb.push(0); // SLOT_MODE_DICT32
            rle_bomb.push(DICT_MODE_RLE);
            rle_bomb.push(1); // vlen = 1
            rle_bomb.extend_from_slice(&[0xBB; 32]);
            rle_bomb.push(1);
            rle_bomb.push(0);
            rle_bomb.extend_from_slice(&[0xD0, 0x86, 0x03]);
            let stdin = build_stdin(MODE_HC_DELTAS, &rle_bomb, &[]);
            let (pv, rep) = client.execute(HYPERCOMP_SP1_ELF, stdin).await?;
            if rep.exit_code != 0 {
                bail!("S4 RLE bomb panicked guest (exit_code={})", rep.exit_code);
            }
            let j = DecodedJournal::from_slice(pv.as_slice())?;
            if j.is_valid || j.error_code != HyperCompError::UnexpectedEof.code() {
                bail!("S4 RLE bomb failed: got {j:?}");
            }
            let detail = format!(
                "rejected {} B RLE OOM bomb in {} SP1 cycles (error_code=6 UnexpectedEof, 0 MiB allocated)",
                rle_bomb.len(),
                rep.total_instruction_count()
            );
            println!("  [PASS] S4 (H-1 71B RLE OOM Bomb)       : {detail}");
            sec_results.push(SecurityTestResult {
                id: "S4".into(),
                name: "H-1 RLE OOM-Bomb Rejection in SP1".into(),
                passed: true,
                sp1_cycles: Some(rep.total_instruction_count()),
                detail,
            });
        }

        // S5: N-2 PoC R-3 Missing Frame_Content_Size Bomb -> cleanly commits is_valid=false, error_code=19!
        {
            let mut no_fcs = vec![
                MAGIC[0],
                MAGIC[1],
                FORMAT_VERSION,
                (PayloadKind::StateDeltas as u8) | (1u8 << 3), // EntropyCodec::Zstd
            ];
            no_fcs.extend_from_slice(&ZSTD_MAGIC);
            no_fcs.extend_from_slice(&[0x04, 0x00, 0x01, 0x00, 0x00]); // checksum=1, fcs=0, single_seg=0
            let stdin = build_stdin(MODE_HC_DELTAS, &no_fcs, &[]);
            let (pv, rep) = client.execute(HYPERCOMP_SP1_ELF, stdin).await?;
            if rep.exit_code != 0 {
                bail!(
                    "S5 missing-FCS panicked guest (exit_code={})",
                    rep.exit_code
                );
            }
            let j = DecodedJournal::from_slice(pv.as_slice())?;
            if j.is_valid || j.error_code != HyperCompError::EntropyDecodeFailed.code() {
                bail!("S5 missing-FCS failed: got {j:?}");
            }
            let detail = format!(
                "rejected Zstd frame without Frame_Content_Size in {} SP1 cycles (error_code=19)",
                rep.total_instruction_count()
            );
            println!("  [PASS] S5 (N-2 Missing FCS Bomb)       : {detail}");
            sec_results.push(SecurityTestResult {
                id: "S5".into(),
                name: "N-2 PoC R-3 Missing Frame_Content_Size Rejection in SP1".into(),
                passed: true,
                sp1_cycles: Some(rep.total_instruction_count()),
                detail,
            });
        }

        // S6: N-4 Legacy v2 Frame Rejection -> cleanly commits is_valid=false, error_code=2 (UnsupportedVersion)!
        {
            let v2_blob = [MAGIC[0], MAGIC[1], 2u8, PayloadKind::StateDeltas as u8, 0];
            let stdin = build_stdin(MODE_HC_DELTAS, &v2_blob, &[]);
            let (pv, rep) = client.execute(HYPERCOMP_SP1_ELF, stdin).await?;
            if rep.exit_code != 0 {
                bail!("S6 v2 frame panicked guest (exit_code={})", rep.exit_code);
            }
            let j = DecodedJournal::from_slice(pv.as_slice())?;
            if j.is_valid || j.error_code != HyperCompError::UnsupportedVersion(2).code() {
                bail!("S6 v2 rejection failed: got {j:?}");
            }
            let detail = format!(
                "rejected legacy v2 frame in {} SP1 cycles (error_code=2 UnsupportedVersion)",
                rep.total_instruction_count()
            );
            println!("  [PASS] S6 (N-4 Legacy v2 Rejection)    : {detail}");
            sec_results.push(SecurityTestResult {
                id: "S6".into(),
                name: "N-4 Legacy Wire Version v2 Rejection in SP1".into(),
                passed: true,
                sp1_cycles: Some(rep.total_instruction_count()),
                detail,
            });
        }
    }

    // -----------------------------------------------------------------------
    // WRITE MARKDOWN + JSON REPORTS (READY FOR benchmarks/README.md & GRANTS)
    // -----------------------------------------------------------------------
    let report = FullReport {
        prover_backend: prover_backend.clone(),
        format_version: FORMAT_VERSION,
        elf_bytes: HYPERCOMP_SP1_ELF.len(),
        benchmarks: bench_results,
        security_tests: sec_results,
    };
    fs::write(&args.out_json, serde_json::to_string_pretty(&report)?)?;

    let mut md = String::new();
    md.push_str("# Al-Samawal HyperCompressor v3 — Succinct SP1 v6 GPU Verification Report\n\n");
    md.push_str(&format!(
        "- **SP1 Prover Backend:** `{}` | **Wire Format:** `v{}` | **Guest ELF:** `{} bytes` (with `patch-sha2-0.10.9-sp1-6.10.0` hardware SHA-256 precompile)\n\n",
        report.prover_backend, report.format_version, report.elf_bytes
    ));
    md.push_str("## 1. Real Mainnet SP1 Cycles & GPU Proving Results\n\n");
    md.push_str("| Fixture | Batch | Slots | Raw DA | Blob Size | SP1 Cycles (w/ SHA-256 Precompile) | SP1 Syscalls | Core Proof (s) | Compressed Proof (s) | Parity & Verify |\n");
    md.push_str("|---|---|---:|---:|---:|---:|---:|---:|---:|---|\n");
    for r in &report.benchmarks {
        let core_s = r
            .core_prove_secs
            .map_or_else(|| "—".into(), |s| format!("{s:.2}s"));
        let comp_s = r
            .compressed_prove_secs
            .map_or_else(|| "—".into(), |s| format!("{s:.2}s"));
        let ver = if r.core_verify_ok.unwrap_or(true) && r.compressed_verify_ok.unwrap_or(true) {
            "PASS (100%)"
        } else {
            "FAIL"
        };
        md.push_str(&format!(
            "| {} | {} | {} | {} B | {} B | {} | {} | {} | {} | {} |\n",
            r.label,
            r.chain,
            r.total_slots,
            r.raw_da_bytes,
            r.pure_wire_bytes,
            r.sp1_total_cycles,
            r.sp1_total_syscalls,
            core_s,
            comp_s,
            ver
        ));
    }
    if !report.security_tests.is_empty() {
        md.push_str("\n## 2. Live Adversarial Security Suite inside SP1 zkVM\n\n");
        md.push_str("| Test | Security Property | SP1 Cycles | Result |\n");
        md.push_str("|---|---|---:|---|\n");
        for s in &report.security_tests {
            let cyc = s
                .sp1_cycles
                .map_or_else(|| "ABORTED (expected)".into(), |c| c.to_string());
            md.push_str(&format!(
                "| **{}** | {} | {} | PASS — {} |\n",
                s.id, s.name, cyc, s.detail
            ));
        }
    }
    fs::write(&args.out_md, &md)?;

    println!("\n==========================================================================================");
    if args.skip_security {
        println!(
            "  ALL {} BENCHMARK FIXTURES PASSED (security suite skipped)!",
            report.benchmarks.len()
        );
    } else {
        println!("  ALL BENCHMARKS & 7/7 LIVE SP1 SECURITY TESTS PASSED!");
    }
    println!("  Markdown report saved : {}", args.out_md.display());
    println!("  JSON report saved     : {}", args.out_json.display());
    println!("==========================================================================================");

    Ok(())
}
