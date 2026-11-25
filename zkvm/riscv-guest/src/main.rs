//! Bare-metal RV32IM (`riscv32im-unknown-none-elf`) `#![no_std]` guest binary.
//!
//! Executes the exact same `hypercomp-decoder` library (including pure-Rust `ruzstd`)
//! compiled with LLVM RV32IM (`-C opt-level=3 -C lto=fat`), mirroring Succinct SP1
//! and RISC Zero guest environments (32-bit `usize`, bump allocator, ecall syscalls).

#![no_std]
#![no_main]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::panic::PanicInfo;

use hypercomp_decoder::{
    decode_starknet_deltas_raw, decode_starknet_updates_raw, decode_state_deltas_raw,
    decode_state_transitions_raw, decode_state_updates_raw, unwrap_frame, ContractDelta,
    ContractDiff, DecodeLimits, DeltaOp, PayloadKind, StarknetContractDelta, StarknetContractDiff,
    StateDiff, StorageUpdate, U256,
};

// ---------------------------------------------------------------------------
// MEMORY MAP (128 MiB Flat zkVM RAM: 0x8000_0000 .. 0x8800_0000)
// Heap sized for the measured worst-case bump-allocator footprint under
// `DecodeLimits::CONSENSUS` (~50-57 MiB cumulative, R3-1) with >= 39 MiB headroom.
// ---------------------------------------------------------------------------
const HEAP_START: usize = 0x8040_0000;
const HEAP_END: usize = 0x8640_0000; // 96 MiB guest heap
const INPUT_MAILBOX: usize = 0x8640_0000; // 27 MiB input buffer
const INPUT_MAILBOX_SIZE: usize = OUTPUT_MAILBOX - INPUT_MAILBOX; // 27 MiB hard upper bound
const OUTPUT_MAILBOX: usize = 0x87F0_0000; // output commitment & stats
// Stack starts at 0x87FF_FFF0 (growing downward toward OUTPUT_MAILBOX + 64 KiB)

// Startup assembly: initialize stack pointer, zero .bss, jump to rust_main, then halt.
global_asm!(
    r#"
    .section .text.init
    .globl _start
_start:
    li sp, 0x87FFFFF0
    la t0, __bss_start
    la t1, __bss_end
1:
    bgeu t0, t1, 2f
    sw zero, 0(t0)
    addi t0, t0, 4
    j 1b
2:
    call rust_main
    li a7, 0
    ecall
3:
    j 3b
"#
);

// ---------------------------------------------------------------------------
// MINIMAL ZERO-OVERHEAD BUMP ALLOCATOR (IDENTICAL TO SP1 / RISC0 SINGLE-THREADED RV32IM)
// ---------------------------------------------------------------------------
struct BumpAlloc {
    next: UnsafeCell<usize>,
}

unsafe impl Sync for BumpAlloc {}

#[global_allocator]
static ALLOCATOR: BumpAlloc = BumpAlloc {
    next: UnsafeCell::new(HEAP_START),
};

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(4);
        let size = layout.size();
        let cur = *self.next.get();
        let aligned = (cur + align - 1) & !(align - 1);
        let end = match aligned.checked_add(size) {
            Some(e) if e <= HEAP_END => e,
            _ => return core::ptr::null_mut(),
        };
        *self.next.get() = end;
        aligned as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        write_out(0, 0xDEAD_0001);
        ecall(99);
    }
    loop {}
}

#[inline(always)]
unsafe fn ecall(code: u32) {
    asm!("ecall", in("a7") code, options(nostack));
}

#[inline(always)]
unsafe fn read_in_u32(offset: usize) -> u32 {
    core::ptr::read_volatile((INPUT_MAILBOX + offset) as *const u32)
}

#[inline(always)]
unsafe fn write_out(word_idx: usize, val: u32) {
    core::ptr::write_volatile((OUTPUT_MAILBOX + word_idx * 4) as *mut u32, val);
}

// ---------------------------------------------------------------------------
// DETERMINISTIC 64-BIT FNV-1a COMMITMENT OVER DECODED OUTPUT
// (Verified bit-for-bit against 64-bit x86_64 host!)
// ---------------------------------------------------------------------------
struct Fnv64(u64);

impl Fnv64 {
    const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }

    #[inline]
    fn write_u64(&mut self, v: u64) {
        self.write(&v.to_le_bytes());
    }

    #[inline]
    fn write_delta_op(&mut self, op: &DeltaOp) {
        match op {
            DeltaOp::NoChange => self.write(&[0]),
            DeltaOp::SetNew(v) => {
                self.write(&[1]);
                self.write(&v.0);
            }
            DeltaOp::Add(v) => {
                self.write(&[2]);
                self.write(&v.0);
            }
            DeltaOp::Sub(v) => {
                self.write(&[3]);
                self.write(&v.0);
            }
            DeltaOp::XorShifted { shift, mask } => {
                self.write(&[4, *shift]);
                self.write(&mask.0);
            }
        }
    }
}

fn commit_transitions(diffs: &[StateDiff]) -> (u32, u64) {
    let mut h = Fnv64::new();
    h.write_u64(diffs.len() as u64);
    for d in diffs {
        h.write(&d.address);
        h.write(&d.slot);
        h.write(&d.old_val.0);
        h.write(&d.new_val.0);
    }
    (diffs.len() as u32, h.0)
}

fn commit_updates(contracts: &[ContractDiff]) -> (u32, u64) {
    let mut h = Fnv64::new();
    let mut slots = 0u32;
    h.write_u64(contracts.len() as u64);
    for c in contracts {
        h.write(&c.address);
        h.write_u64(c.nonce.unwrap_or(u64::MAX));
        h.write_u64(c.storage_updates.len() as u64);
        for u in &c.storage_updates {
            h.write(&u.slot);
            h.write(&u.new_val.0);
            slots += 1;
        }
    }
    (slots, h.0)
}

fn commit_deltas(contracts: &[ContractDelta]) -> (u32, u64) {
    let mut h = Fnv64::new();
    let mut slots = 0u32;
    h.write_u64(contracts.len() as u64);
    for c in contracts {
        h.write(&c.address);
        h.write_u64(c.nonce.unwrap_or(u64::MAX));
        h.write_u64(c.storage_deltas.len() as u64);
        for d in &c.storage_deltas {
            h.write(&d.slot);
            h.write_delta_op(&d.op);
            slots += 1;
        }
    }
    (slots, h.0)
}

fn commit_starknet_updates(contracts: &[StarknetContractDiff]) -> (u32, u64) {
    let mut h = Fnv64::new();
    let mut slots = 0u32;
    h.write_u64(contracts.len() as u64);
    for c in contracts {
        h.write(&c.address);
        h.write_u64(c.nonce.unwrap_or(u64::MAX));
        h.write_u64(c.storage_updates.len() as u64);
        for u in &c.storage_updates {
            h.write(&u.slot);
            h.write(&u.new_val.0);
            slots += 1;
        }
    }
    (slots, h.0)
}

fn commit_starknet_deltas(contracts: &[StarknetContractDelta]) -> (u32, u64) {
    let mut h = Fnv64::new();
    let mut slots = 0u32;
    h.write_u64(contracts.len() as u64);
    for c in contracts {
        h.write(&c.address);
        h.write_u64(c.nonce.unwrap_or(u64::MAX));
        h.write_u64(c.storage_deltas.len() as u64);
        for d in &c.storage_deltas {
            h.write(&d.slot);
            h.write_delta_op(&d.op);
            slots += 1;
        }
    }
    (slots, h.0)
}

/// Parses raw uncompressed EVM `ContractDiff::to_raw_bytes` (baseline without HyperComp transform).
fn parse_raw_evm_updates(raw: &[u8]) -> Result<alloc::vec::Vec<ContractDiff>, u32> {
    let mut pos = 0usize;
    let mut contracts = alloc::vec::Vec::new();
    while pos < raw.len() {
        if raw.len() - pos < 21 {
            return Err(60);
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(&raw[pos..pos + 20]);
        pos += 20;
        let has_nonce = raw[pos];
        pos += 1;
        let nonce = if has_nonce == 1 {
            if raw.len() - pos < 8 {
                return Err(61);
            }
            let n = u64::from_be_bytes([
                raw[pos],
                raw[pos + 1],
                raw[pos + 2],
                raw[pos + 3],
                raw[pos + 4],
                raw[pos + 5],
                raw[pos + 6],
                raw[pos + 7],
            ]);
            pos += 8;
            Some(n)
        } else {
            None
        };
        if raw.len() - pos < 4 {
            return Err(62);
        }
        let cnt = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]) as usize;
        pos += 4;
        if raw.len() - pos < cnt.saturating_mul(64) {
            return Err(63);
        }
        let mut storage_updates = alloc::vec::Vec::with_capacity(cnt);
        for _ in 0..cnt {
            let mut slot = [0u8; 32];
            let mut val = [0u8; 32];
            slot.copy_from_slice(&raw[pos..pos + 32]);
            val.copy_from_slice(&raw[pos + 32..pos + 64]);
            pos += 64;
            storage_updates.push(StorageUpdate {
                slot,
                new_val: U256(val),
            });
        }
        contracts.push(ContractDiff {
            address,
            nonce,
            storage_updates,
        });
    }
    Ok(contracts)
}

/// Parses raw uncompressed Starknet `StarknetContractDiff::to_raw_bytes` (baseline without HyperComp).
fn parse_raw_starknet_updates(raw: &[u8]) -> Result<alloc::vec::Vec<StarknetContractDiff>, u32> {
    let mut pos = 0usize;
    let mut contracts = alloc::vec::Vec::new();
    while pos < raw.len() {
        if raw.len() - pos < 33 {
            return Err(70);
        }
        let mut address = [0u8; 32];
        address.copy_from_slice(&raw[pos..pos + 32]);
        pos += 32;
        let has_nonce = raw[pos];
        pos += 1;
        let nonce = if has_nonce == 1 {
            if raw.len() - pos < 8 {
                return Err(71);
            }
            let n = u64::from_be_bytes([
                raw[pos],
                raw[pos + 1],
                raw[pos + 2],
                raw[pos + 3],
                raw[pos + 4],
                raw[pos + 5],
                raw[pos + 6],
                raw[pos + 7],
            ]);
            pos += 8;
            Some(n)
        } else {
            None
        };
        if raw.len() - pos < 4 {
            return Err(72);
        }
        let cnt = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]) as usize;
        pos += 4;
        if raw.len() - pos < cnt.saturating_mul(64) {
            return Err(73);
        }
        let mut storage_updates = alloc::vec::Vec::with_capacity(cnt);
        for _ in 0..cnt {
            let mut slot = [0u8; 32];
            let mut val = [0u8; 32];
            slot.copy_from_slice(&raw[pos..pos + 32]);
            val.copy_from_slice(&raw[pos + 32..pos + 64]);
            pos += 64;
            storage_updates.push(StorageUpdate {
                slot,
                new_val: U256(val),
            });
        }
        contracts.push(StarknetContractDiff {
            address,
            nonce,
            storage_updates,
        });
    }
    Ok(contracts)
}

/// Legacy v1 byte-by-byte `mul10` microbenchmark (mode 11) vs v2 `POW10` limb `mul_u64_pow10_checked` (mode 10).
fn microbench_rhind(blob: &[u8], legacy_byte_loop: bool) -> (u32, u64) {
    // blob contains pairs of (exp: u8, mantissa_u64_le: [u8; 8]) = 9 bytes per record
    let count = blob.len() / 9;
    let mut h = Fnv64::new();
    for i in 0..count {
        let base = i * 9;
        let exp = blob[base];
        let m = u64::from_le_bytes([
            blob[base + 1],
            blob[base + 2],
            blob[base + 3],
            blob[base + 4],
            blob[base + 5],
            blob[base + 6],
            blob[base + 7],
            blob[base + 8],
        ]);
        let val = if legacy_byte_loop {
            let mut b = [0u8; 32];
            b[24..32].copy_from_slice(&m.to_be_bytes());
            for _ in 0..exp {
                let mut carry: u16 = 0;
                for j in (0..32).rev() {
                    let cur = (b[j] as u16) * 10 + carry;
                    b[j] = (cur & 0xFF) as u8;
                    carry = cur >> 8;
                }
            }
            U256(b)
        } else {
            U256::mul_u64_pow10_checked(m, exp).unwrap_or(U256::ZERO)
        };
        h.write(&val.0);
    }
    (count as u32, h.0)
}

#[no_mangle]
pub extern "C" fn rust_main() {
    unsafe {
        let mode = read_in_u32(0);
        let blob_len = read_in_u32(4) as usize;
        let dict_len = read_in_u32(8) as usize;

        // L-1 safety: strictly validate untrusted mailbox lengths with checked 32-bit math
        // BEFORE constructing slices via `from_raw_parts` (eliminates UB / overflow).
        let blob_end = match 12usize.checked_add(blob_len) {
            Some(e) if e <= INPUT_MAILBOX_SIZE => e,
            _ => {
                write_out(0, 0xBAD0_0001);
                return;
            }
        };
        let dict_offset = match blob_end.checked_add(3) {
            Some(v) => v & !3,
            None => {
                write_out(0, 0xBAD0_0002);
                return;
            }
        };
        let dict_end = match dict_offset.checked_add(dict_len) {
            Some(e) if e <= INPUT_MAILBOX_SIZE => e,
            _ => {
                write_out(0, 0xBAD0_0003);
                return;
            }
        };
        let _ = dict_end;

        let blob_ptr = (INPUT_MAILBOX + 12) as *const u8;
        let blob = core::slice::from_raw_parts(blob_ptr, blob_len);

        let dict = if dict_len > 0 {
            let dict_ptr = (INPUT_MAILBOX + dict_offset) as *const u8;
            Some(core::slice::from_raw_parts(dict_ptr, dict_len))
        } else {
            None
        };

        let limits = DecodeLimits::zkvm();

        let result: Result<(u32, u64), u32> = match mode {
            0 => unwrap_frame(blob, PayloadKind::StateUpdates, dict, limits)
                .map_err(|_| 10u32)
                .and_then(|pre| {
                    ecall(1); // Stage 1 complete: Entropy / Zstd decompression
                    let decoded = decode_state_updates_raw(&pre, limits).map_err(|_| 11u32)?;
                    ecall(2); // Stage 2 complete: HyperComp structural decode
                    Ok(commit_updates(&decoded))
                }),
            1 => unwrap_frame(blob, PayloadKind::StateDeltas, dict, limits)
                .map_err(|_| 20u32)
                .and_then(|pre| {
                    ecall(1);
                    let decoded = decode_state_deltas_raw(&pre, limits).map_err(|_| 21u32)?;
                    ecall(2);
                    Ok(commit_deltas(&decoded))
                }),
            2 => unwrap_frame(blob, PayloadKind::StateTransitions, dict, limits)
                .map_err(|_| 30u32)
                .and_then(|pre| {
                    ecall(1);
                    let decoded = decode_state_transitions_raw(&pre, limits).map_err(|_| 31u32)?;
                    ecall(2);
                    Ok(commit_transitions(&decoded))
                }),
            3 => unwrap_frame(blob, PayloadKind::StarknetUpdates, dict, limits)
                .map_err(|_| 40u32)
                .and_then(|pre| {
                    ecall(1);
                    let decoded = decode_starknet_updates_raw(&pre, limits).map_err(|_| 41u32)?;
                    ecall(2);
                    Ok(commit_starknet_updates(&decoded))
                }),
            4 => unwrap_frame(blob, PayloadKind::StarknetDeltas, dict, limits)
                .map_err(|_| 50u32)
                .and_then(|pre| {
                    ecall(1);
                    let decoded = decode_starknet_deltas_raw(&pre, limits).map_err(|_| 51u32)?;
                    ecall(2);
                    Ok(commit_starknet_deltas(&decoded))
                }),
            10 => {
                ecall(1);
                let out = microbench_rhind(blob, false);
                ecall(2);
                Ok(out)
            }
            11 => {
                ecall(1);
                let out = microbench_rhind(blob, true);
                ecall(2);
                Ok(out)
            }
            // Mode 20: Raw EVM Zstd / Raw EVM Zstd+Dict baseline (uses exact same `ruzstd` unwrapper, NO HyperComp!)
            20 => unwrap_frame(blob, PayloadKind::StateUpdates, dict, limits)
                .map_err(|_| 64u32)
                .and_then(|raw| {
                    ecall(1);
                    let decoded = parse_raw_evm_updates(&raw)?;
                    ecall(2);
                    Ok(commit_updates(&decoded))
                }),
            // Mode 21: Raw Starknet Zstd / Raw Starknet Zstd+Dict baseline (NO HyperComp!)
            21 => unwrap_frame(blob, PayloadKind::StarknetUpdates, dict, limits)
                .map_err(|_| 74u32)
                .and_then(|raw| {
                    ecall(1);
                    let decoded = parse_raw_starknet_updates(&raw)?;
                    ecall(2);
                    Ok(commit_starknet_updates(&decoded))
                }),
            _ => Err(99),
        };

        let heap_used = (*ALLOCATOR.next.get() - HEAP_START) as u32;
        match result {
            Ok((items, hash)) => {
                write_out(0, 0); // status = OK
                write_out(1, items);
                write_out(2, hash as u32);
                write_out(3, (hash >> 32) as u32);
                write_out(4, heap_used);
            }
            Err(code) => {
                write_out(0, code);
                write_out(4, heap_used);
            }
        }
    }
}
