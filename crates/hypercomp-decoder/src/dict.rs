use alloc::vec::Vec;

use crate::error::HyperCompError;
use crate::poly::alsamawal_poly_decode_exact;
use crate::u256::U256;
use crate::varint::{decode_count, decode_varint_u32, decode_varint_u64};

/// Dictionary encoding modes for fixed-width byte columns (`[u8; 20]` addresses, `[u8; 32]` slots).
pub const DICT_MODE_EMPTY: u8 = 0;
pub const DICT_MODE_PURE: u8 = 1;
pub const DICT_MODE_HYBRID_ESCAPE: u8 = 2;
pub const DICT_MODE_RLE: u8 = 3;

/// Storage-slot column modes (supports bimodal Solidity/Cairo small-int slots, 256-bit adjacent
/// struct/array/u256 deltas `prev + k`, and 32B Keccak/Poseidon hash slots).
pub const SLOT_MODE_DICT32: u8 = 0;
pub const SLOT_MODE_BIMODAL_POLY: u8 = 1;
pub const SLOT_MODE_STRUCT_DELTA: u8 = 2;

/// Small-slot integer column sub-modes.
pub const SMALL_MODE_VARINT: u8 = 0;
pub const SMALL_MODE_ALSAMAWAL: u8 = 1;

/// Slot kind tags inside `SLOT_MODE_STRUCT_DELTA`:
/// - `0x00`: 32B hash base (from Hybrid Hot-Dict)
/// - `0x01`: Small integer slot `< 2^64` (from `small_slots`)
/// - `0x02..=0xFE`: Adjacent 256-bit struct/array/u256 slot `prev + (tag - 1)` (`1..=253`)
/// - `0xFF`: Wide adjacent delta `prev + varint_u64` (`>= 254`, e.g. sparse Solidity dynamic array)
pub const SLOT_KIND_HASH: u8 = 0x00;
pub const SLOT_KIND_SMALL: u8 = 0x01;
pub const SLOT_KIND_ADJ_BASE: u8 = 0x02;
pub const SLOT_KIND_ADJ_WIDE: u8 = 0xFF;

/// Decodes a fixed-width `[u8; N]` dictionary-compressed column of exact expected length `expected_count`.
/// Fully 32-bit RISC-V safe (`u32` counts/indices, overflow-checked byte bounds).
pub fn dict_decode_fixed<const N: usize>(
    buf: &[u8],
    pos: &mut usize,
    expected_count: usize,
    max_items: u32,
) -> Result<Vec<[u8; N]>, HyperCompError> {
    if *pos >= buf.len() {
        return Err(HyperCompError::UnexpectedEof);
    }
    let mode = buf[*pos];
    *pos += 1;

    match mode {
        DICT_MODE_EMPTY => {
            if expected_count != 0 {
                return Err(HyperCompError::LengthMismatch);
            }
            Ok(Vec::new())
        }
        DICT_MODE_PURE => {
            let vlen = decode_count(buf, pos, max_items)?;
            if vlen == 0 && expected_count > 0 {
                return Err(HyperCompError::LengthMismatch);
            }
            let vocab = read_fixed_table::<N>(buf, pos, vlen)?;
            if buf.len().saturating_sub(*pos) < expected_count {
                return Err(HyperCompError::UnexpectedEof);
            }
            let mut items = Vec::with_capacity(expected_count);
            for _ in 0..expected_count {
                let idx_u32 = decode_varint_u32(buf, pos)?;
                let idx = usize::try_from(idx_u32).map_err(|_| HyperCompError::InvalidIndex(idx_u32))?;
                if idx >= vocab.len() {
                    return Err(HyperCompError::InvalidIndex(idx_u32));
                }
                items.push(vocab[idx]);
            }
            Ok(items)
        }
        DICT_MODE_HYBRID_ESCAPE => {
            // Hot vocabulary (items with freq >= 2); idx == 0 escapes to `literals`, idx >= 1 -> vocab[idx - 1].
            let vlen = decode_count(buf, pos, max_items)?;
            let vocab = read_fixed_table::<N>(buf, pos, vlen)?;
            let lit_len = decode_count(buf, pos, max_items)?;
            if lit_len > expected_count {
                return Err(HyperCompError::LengthMismatch);
            }
            let literals = read_fixed_table::<N>(buf, pos, lit_len)?;
            if buf.len().saturating_sub(*pos) < expected_count {
                return Err(HyperCompError::UnexpectedEof);
            }
            let mut items = Vec::with_capacity(expected_count);
            let mut lit_i = 0usize;
            for _ in 0..expected_count {
                let idx_u32 = decode_varint_u32(buf, pos)?;
                if idx_u32 == 0 {
                    if lit_i >= literals.len() {
                        return Err(HyperCompError::LengthMismatch);
                    }
                    items.push(literals[lit_i]);
                    lit_i += 1;
                } else {
                    let idx = usize::try_from(idx_u32 - 1)
                        .map_err(|_| HyperCompError::InvalidIndex(idx_u32))?;
                    if idx >= vocab.len() {
                        return Err(HyperCompError::InvalidIndex(idx_u32));
                    }
                    items.push(vocab[idx]);
                }
            }
            if lit_i != literals.len() {
                return Err(HyperCompError::LengthMismatch);
            }
            Ok(items)
        }
        DICT_MODE_RLE => {
            // Run-length encoded dictionary indices — collapses sorted/grouped address runs.
            let vlen = decode_count(buf, pos, max_items)?;
            let vocab = read_fixed_table::<N>(buf, pos, vlen)?;
            let num_runs = decode_count(buf, pos, max_items)?;
            if num_runs > expected_count {
                return Err(HyperCompError::LengthMismatch);
            }
            // Each run requires at least 2 bytes (1B idx + 1B run_len).
            if buf.len().saturating_sub(*pos) < num_runs.saturating_mul(2) {
                return Err(HyperCompError::UnexpectedEof);
            }
            // Never eagerly pre-allocate untrusted `expected_count` (prevents RLE OOM bombs).
            let mut items = Vec::with_capacity(expected_count.min(4096));
            for _ in 0..num_runs {
                let idx_u32 = decode_varint_u32(buf, pos)?;
                let idx = usize::try_from(idx_u32).map_err(|_| HyperCompError::InvalidIndex(idx_u32))?;
                if idx >= vocab.len() {
                    return Err(HyperCompError::InvalidIndex(idx_u32));
                }
                let run_len = decode_count(buf, pos, max_items)?;
                if run_len == 0 {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
                let new_len = items
                    .len()
                    .checked_add(run_len)
                    .ok_or(HyperCompError::LimitExceeded)?;
                if new_len > expected_count {
                    return Err(HyperCompError::LengthMismatch);
                }
                let val = vocab[idx];
                items.reserve(run_len);
                for _ in 0..run_len {
                    items.push(val);
                }
            }
            if items.len() != expected_count {
                return Err(HyperCompError::LengthMismatch);
            }
            Ok(items)
        }
        other => Err(HyperCompError::InvalidTag(other)),
    }
}

#[inline]
fn read_fixed_table<const N: usize>(
    buf: &[u8],
    pos: &mut usize,
    len: usize,
) -> Result<Vec<[u8; N]>, HyperCompError> {
    // Enforce 32-bit byte-length bound identically on both 32-bit RISC-V and 64-bit hosts.
    let byte_len_u32 = u32::try_from(len)
        .ok()
        .and_then(|l| u32::try_from(N).ok().and_then(|n| l.checked_mul(n)))
        .ok_or(HyperCompError::LimitExceeded)?;
    let byte_len = usize::try_from(byte_len_u32).map_err(|_| HyperCompError::LimitExceeded)?;
    if buf.len().saturating_sub(*pos) < byte_len {
        return Err(HyperCompError::UnexpectedEof);
    }
    let mut table = Vec::with_capacity(len);
    for _ in 0..len {
        let mut item = [0u8; N];
        item.copy_from_slice(&buf[*pos..*pos + N]);
        *pos += N;
        table.push(item);
    }
    Ok(table)
}

fn decode_small_u64_column(
    buf: &[u8],
    pos: &mut usize,
    count: usize,
) -> Result<Vec<u64>, HyperCompError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if *pos >= buf.len() {
        return Err(HyperCompError::UnexpectedEof);
    }
    let sub_mode = buf[*pos];
    *pos += 1;
    match sub_mode {
        SMALL_MODE_VARINT => {
            if buf.len().saturating_sub(*pos) < count {
                return Err(HyperCompError::UnexpectedEof);
            }
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                out.push(decode_varint_u64(buf, pos)?);
            }
            Ok(out)
        }
        SMALL_MODE_ALSAMAWAL => {
            if count < 2 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            alsamawal_poly_decode_exact(buf, pos, count)
        }
        other => Err(HyperCompError::InvalidTag(other)),
    }
}

/// Decodes a storage slot column (`[u8; 32]`), supporting:
/// - `SLOT_MODE_DICT32`: pure 32-byte dictionary
/// - `SLOT_MODE_BIMODAL_POLY`: small `< 2^64` slots (varint or Al-Samawal) + 32B hash dict
/// - `SLOT_MODE_STRUCT_DELTA`: 256-bit adjacent struct/array/Cairo-u256 delta (`prev + k`) + small slots + 32B hash dict!
pub fn slot_decode_column(
    buf: &[u8],
    pos: &mut usize,
    expected_count: usize,
    max_items: u32,
) -> Result<Vec<[u8; 32]>, HyperCompError> {
    if expected_count == 0 {
        return Ok(Vec::new());
    }
    if *pos >= buf.len() {
        return Err(HyperCompError::UnexpectedEof);
    }
    let mode = buf[*pos];
    *pos += 1;

    match mode {
        SLOT_MODE_DICT32 => dict_decode_fixed::<32>(buf, pos, expected_count, max_items),
        SLOT_MODE_BIMODAL_POLY => {
            let bitmap_bytes = expected_count.div_ceil(8);
            if buf.len().saturating_sub(*pos) < bitmap_bytes {
                return Err(HyperCompError::UnexpectedEof);
            }
            let bitmap = &buf[*pos..*pos + bitmap_bytes];
            *pos += bitmap_bytes;

            let rem_bits = expected_count % 8;
            if rem_bits != 0 {
                let pad_mask = !((1u8 << rem_bits) - 1);
                if (bitmap[bitmap_bytes - 1] & pad_mask) != 0 {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
            }

            let mut small_count = 0usize;
            for i in 0..expected_count {
                if ((bitmap[i >> 3] >> (i & 7)) & 1) == 0 {
                    small_count += 1;
                }
            }
            let hash_count = expected_count - small_count;

            let small_vals = decode_small_u64_column(buf, pos, small_count)?;
            let hash_vals = dict_decode_fixed::<32>(buf, pos, hash_count, max_items)?;

            let mut out = Vec::with_capacity(expected_count);
            let mut s_i = 0usize;
            let mut h_i = 0usize;
            for i in 0..expected_count {
                if ((bitmap[i >> 3] >> (i & 7)) & 1) == 0 {
                    let mut slot = [0u8; 32];
                    slot[24..32].copy_from_slice(&small_vals[s_i].to_be_bytes());
                    s_i += 1;
                    out.push(slot);
                } else {
                    out.push(hash_vals[h_i]);
                    h_i += 1;
                }
            }
            Ok(out)
        }
        SLOT_MODE_STRUCT_DELTA => {
            if buf.len().saturating_sub(*pos) < expected_count {
                return Err(HyperCompError::UnexpectedEof);
            }
            let kinds = &buf[*pos..*pos + expected_count];
            *pos += expected_count;

            let mut hash_count = 0usize;
            let mut small_count = 0usize;
            let mut wide_count = 0usize;
            for (i, &k) in kinds.iter().enumerate() {
                match k {
                    SLOT_KIND_HASH => hash_count += 1,
                    SLOT_KIND_SMALL => small_count += 1,
                    SLOT_KIND_ADJ_BASE..=0xFE => {
                        if i == 0 {
                            return Err(HyperCompError::InvalidTag(k));
                        }
                    }
                    SLOT_KIND_ADJ_WIDE => {
                        if i == 0 {
                            return Err(HyperCompError::InvalidTag(k));
                        }
                        wide_count += 1;
                    }
                }
            }

            let small_vals = decode_small_u64_column(buf, pos, small_count)?;
            let hash_vals = dict_decode_fixed::<32>(buf, pos, hash_count, max_items)?;
            let mut wide_deltas = Vec::with_capacity(wide_count);
            for _ in 0..wide_count {
                let d = decode_varint_u64(buf, pos)?;
                if d < 254 {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
                wide_deltas.push(d);
            }

            let mut out = Vec::with_capacity(expected_count);
            let mut s_i = 0usize;
            let mut h_i = 0usize;
            let mut w_i = 0usize;
            for &k in kinds {
                let slot = match k {
                    SLOT_KIND_HASH => {
                        let s = hash_vals[h_i];
                        h_i += 1;
                        s
                    }
                    SLOT_KIND_SMALL => {
                        let mut s = [0u8; 32];
                        s[24..32].copy_from_slice(&small_vals[s_i].to_be_bytes());
                        s_i += 1;
                        s
                    }
                    SLOT_KIND_ADJ_BASE..=0xFE => {
                        let delta = (k - 1) as u64;
                        let prev = U256(*out.last().ok_or(HyperCompError::InvalidTag(k))?);
                        prev.checked_add(U256::from_u64(delta))
                            .ok_or(HyperCompError::U256Overflow)?
                            .0
                    }
                    SLOT_KIND_ADJ_WIDE => {
                        let delta = wide_deltas[w_i];
                        w_i += 1;
                        let prev = U256(*out.last().ok_or(HyperCompError::InvalidTag(k))?);
                        prev.checked_add(U256::from_u64(delta))
                            .ok_or(HyperCompError::U256Overflow)?
                            .0
                    }
                };
                out.push(slot);
            }
            Ok(out)
        }
        other => Err(HyperCompError::InvalidTag(other)),
    }
}
