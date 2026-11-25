use alloc::vec::Vec;

use crate::error::HyperCompError;
use crate::u256::{MAX_POW10_EXP, U256};

// ---------------------------------------------------------------------------
// CANONICAL BIT-PACKED RHIND U256 TAG SPACE
// ---------------------------------------------------------------------------
// 0x00       : U256::ZERO                     (1 byte total)
// 0x01       : U256::MAX (0xFF * 32)          (1 byte total — ERC-20 unlimited approvals)
// 0x02..=0x11: Small literals 1..=16          (1 byte total — booleans, flags, small counters)
// 0x12..=0x31: Raw minimal BE (len = t-0x11)  (1 + len bytes, len in 1..=32)
// 0x32..=0x39: Rhind m*10^exp (m_len=t-0x31)  (2 + m_len bytes, m_len in 1..=8, exp in 1..=77)
// 0x3A..=0x58: Left-aligned (len = t-0x39)    (1 + len bytes, len in 1..=31, right-padded zeros;
//              ideal for Solidity left-aligned strings/bytes & selectors!)
// ---------------------------------------------------------------------------

pub const TAG_ZERO: u8 = 0x00;
pub const TAG_MAX: u8 = 0x01;
pub const TAG_SMALL_BASE: u8 = 0x02;
pub const TAG_SMALL_END: u8 = 0x11; // value = tag - 0x01 (1..=16)
pub const TAG_RAW_BASE: u8 = 0x12;
pub const TAG_RAW_END: u8 = 0x31; // len = tag - 0x11 (1..=32)
pub const TAG_RHIND_BASE: u8 = 0x32;
pub const TAG_RHIND_END: u8 = 0x39; // m_len = tag - 0x31 (1..=8)
pub const TAG_LEFT_BASE: u8 = 0x3A;
pub const TAG_LEFT_END: u8 = 0x58; // len = tag - 0x39 (1..=31)

/// Returns `Some(left_len)` iff `val` has non-zero MSB (`val.0[0] != 0`) and at least one
/// trailing zero byte (`val.0[31] == 0`), so left-aligned encoding (`1 + left_len`) strictly
/// beats 32-byte Raw minimal BE (`33` bytes).
#[inline]
pub fn left_aligned_len(val: &U256) -> Option<usize> {
    if val.0[0] == 0 || val.0[31] != 0 {
        return None;
    }
    let trailing = val.0.iter().rev().take_while(|&&b| b == 0).count();
    let len = 32 - trailing;
    if (1..=31).contains(&len) {
        Some(len)
    } else {
        None
    }
}

/// Returns `true` iff `val` has a strictly shorter Rhind representation than both Raw minimal BE
/// and Left-Aligned encoding. Used by both encoder and decoder for strict canonical bijection.
#[inline]
pub fn has_strictly_shorter_rhind(val: U256) -> Option<(u64, u8, u8)> {
    if !val.is_divisible_by_10() {
        return None;
    }
    let best_non_rhind_len = left_aligned_len(&val).unwrap_or_else(|| val.minimal_be_len());
    // Rhind requires 2 + m_len < 1 + best_non_rhind_len <=> 1 + m_len < best_non_rhind_len
    if best_non_rhind_len < 3 {
        return None;
    }
    let (mantissa_u256, exp) = val.extract_pow10();
    if exp == 0 {
        return None;
    }
    let m_u64 = mantissa_u256.to_u64_exact()?;
    let m_len = mantissa_u256.minimal_be_len();
    if (1..=8).contains(&m_len) && (1 + m_len) < best_non_rhind_len {
        Some((m_u64, exp, m_len as u8))
    } else {
        None
    }
}

/// Decodes a single value from a tag byte + optional exp byte + payload slice, enforcing
/// strict canonicality (bijection between valid bytes and U256).
#[inline]
fn decode_tagged_parts(tag: u8, exp: Option<u8>, payload: &[u8]) -> Result<U256, HyperCompError> {
    match tag {
        TAG_ZERO => Ok(U256::ZERO),
        TAG_MAX => Ok(U256::MAX),
        TAG_SMALL_BASE..=TAG_SMALL_END => Ok(U256::from_u64((tag - 1) as u64)),
        TAG_RAW_BASE..=TAG_RAW_END => {
            let len = (tag - 0x11) as usize;
            if payload.len() != len {
                return Err(HyperCompError::InvalidU256Length(len as u8));
            }
            // Minimal big-endian: leading byte must be non-zero.
            if payload[0] == 0 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            let mut b = [0u8; 32];
            b[32 - len..32].copy_from_slice(payload);
            let val = U256(b);
            // Must not duplicate 1..=16, U256::MAX, or a strictly shorter Rhind form.
            if len == 1 && payload[0] <= 16 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            if val.is_max() {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            if left_aligned_len(&val).is_some() {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            if has_strictly_shorter_rhind(val).is_some() {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            Ok(val)
        }
        TAG_RHIND_BASE..=TAG_RHIND_END => {
            let m_len = (tag - 0x31) as usize;
            if payload.len() != m_len {
                return Err(HyperCompError::InvalidU256Length(m_len as u8));
            }
            let exp = exp.ok_or(HyperCompError::UnexpectedEof)?;
            if exp == 0 || exp > MAX_POW10_EXP {
                return Err(HyperCompError::InvalidExponent(exp));
            }
            // Minimal big-endian mantissa: first byte must be non-zero.
            if payload[0] == 0 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            let mut m_bytes = [0u8; 8];
            m_bytes[8 - m_len..8].copy_from_slice(payload);
            let mantissa = u64::from_be_bytes(m_bytes);
            // Maximal exponent canonicality: mantissa must not be divisible by 10.
            // Uses pure 32-bit arithmetic (2^32 ≡ 6 (mod 10)) to avoid `__umoddi3` on RV32IM.
            #[allow(clippy::manual_is_multiple_of)]
            let m_div10 = ((mantissa as u32) & 1) == 0
                && ((((mantissa as u32) % 5) + (((mantissa >> 32) as u32) % 5)) % 5) == 0;
            if m_div10 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            let val = U256::mul_u64_pow10_checked(mantissa, exp)
                .ok_or(HyperCompError::U256Overflow)?;
            // Strict optimality canonicality: Rhind must beat Raw and Left-Aligned.
            let best_non_rhind = left_aligned_len(&val).unwrap_or_else(|| val.minimal_be_len());
            if (1 + m_len) >= best_non_rhind {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            Ok(val)
        }
        TAG_LEFT_BASE..=TAG_LEFT_END => {
            let len = (tag - 0x39) as usize;
            if payload.len() != len {
                return Err(HyperCompError::InvalidU256Length(len as u8));
            }
            // Must be strictly left-aligned with non-zero MSB and non-zero final byte.
            if payload[0] == 0 || payload[len - 1] == 0 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            let mut b = [0u8; 32];
            b[0..len].copy_from_slice(payload);
            let val = U256(b);
            if has_strictly_shorter_rhind(val).is_some() {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            Ok(val)
        }
        other => Err(HyperCompError::InvalidTag(other)),
    }
}

/// Decodes a single standalone Rhind-encoded U256 from `buf` at `*pos`.
pub fn rhind_decode_u256(buf: &[u8], pos: &mut usize) -> Result<U256, HyperCompError> {
    if *pos >= buf.len() {
        return Err(HyperCompError::UnexpectedEof);
    }
    let tag = buf[*pos];
    *pos += 1;
    match tag {
        TAG_ZERO | TAG_MAX | TAG_SMALL_BASE..=TAG_SMALL_END => {
            decode_tagged_parts(tag, None, &[])
        }
        TAG_RAW_BASE..=TAG_RAW_END => {
            let len = (tag - 0x11) as usize;
            if buf.len().saturating_sub(*pos) < len {
                return Err(HyperCompError::UnexpectedEof);
            }
            let slice = &buf[*pos..*pos + len];
            *pos += len;
            decode_tagged_parts(tag, None, slice)
        }
        TAG_RHIND_BASE..=TAG_RHIND_END => {
            let m_len = (tag - 0x31) as usize;
            if buf.len().saturating_sub(*pos) < 1 + m_len {
                return Err(HyperCompError::UnexpectedEof);
            }
            let exp = buf[*pos];
            let slice = &buf[*pos + 1..*pos + 1 + m_len];
            *pos += 1 + m_len;
            decode_tagged_parts(tag, Some(exp), slice)
        }
        TAG_LEFT_BASE..=TAG_LEFT_END => {
            let len = (tag - 0x39) as usize;
            if buf.len().saturating_sub(*pos) < len {
                return Err(HyperCompError::UnexpectedEof);
            }
            let slice = &buf[*pos..*pos + len];
            *pos += len;
            decode_tagged_parts(tag, None, slice)
        }
        other => Err(HyperCompError::InvalidTag(other)),
    }
}

/// Decodes a columnar Rhind block of `count` U256 values split into 3 sub-streams:
/// `[tags: count B][exps: rhind_count B][payloads: sum(lens) B]`.
///
/// Splitting tags, exponents, and raw/mantissa payloads exposes homogeneous symbol histograms
/// to the outer Zstd FSE entropy coder with zero extra framing bytes.
pub fn rhind_decode_column(
    buf: &[u8],
    pos: &mut usize,
    count: usize,
) -> Result<Vec<U256>, HyperCompError> {
    if buf.len().saturating_sub(*pos) < count {
        return Err(HyperCompError::UnexpectedEof);
    }
    let tags = &buf[*pos..*pos + count];
    *pos += count;

    // Pre-scan tags once to validate all tags and compute exact sub-stream lengths.
    let mut rhind_count: usize = 0;
    let mut payload_bytes: usize = 0;
    for &t in tags {
        match t {
            TAG_ZERO | TAG_MAX | TAG_SMALL_BASE..=TAG_SMALL_END => {}
            TAG_RAW_BASE..=TAG_RAW_END => {
                let len = (t - 0x11) as usize;
                payload_bytes = payload_bytes
                    .checked_add(len)
                    .ok_or(HyperCompError::LimitExceeded)?;
            }
            TAG_RHIND_BASE..=TAG_RHIND_END => {
                let m_len = (t - 0x31) as usize;
                rhind_count += 1;
                payload_bytes = payload_bytes
                    .checked_add(m_len)
                    .ok_or(HyperCompError::LimitExceeded)?;
            }
            TAG_LEFT_BASE..=TAG_LEFT_END => {
                let len = (t - 0x39) as usize;
                payload_bytes = payload_bytes
                    .checked_add(len)
                    .ok_or(HyperCompError::LimitExceeded)?;
            }
            other => return Err(HyperCompError::InvalidTag(other)),
        }
    }

    let needed = rhind_count
        .checked_add(payload_bytes)
        .ok_or(HyperCompError::LimitExceeded)?;
    if buf.len().saturating_sub(*pos) < needed {
        return Err(HyperCompError::UnexpectedEof);
    }

    let exps = &buf[*pos..*pos + rhind_count];
    *pos += rhind_count;
    let payloads = &buf[*pos..*pos + payload_bytes];
    *pos += payload_bytes;

    let mut out = Vec::with_capacity(count);
    let mut exp_i = 0usize;
    let mut pay_i = 0usize;

    for &t in tags {
        let val = match t {
            TAG_ZERO | TAG_MAX | TAG_SMALL_BASE..=TAG_SMALL_END => {
                decode_tagged_parts(t, None, &[])?
            }
            TAG_RAW_BASE..=TAG_RAW_END => {
                let len = (t - 0x11) as usize;
                let slice = &payloads[pay_i..pay_i + len];
                pay_i += len;
                decode_tagged_parts(t, None, slice)?
            }
            TAG_RHIND_BASE..=TAG_RHIND_END => {
                let m_len = (t - 0x31) as usize;
                let exp = exps[exp_i];
                exp_i += 1;
                let slice = &payloads[pay_i..pay_i + m_len];
                pay_i += m_len;
                decode_tagged_parts(t, Some(exp), slice)?
            }
            TAG_LEFT_BASE..=TAG_LEFT_END => {
                let len = (t - 0x39) as usize;
                let slice = &payloads[pay_i..pay_i + len];
                pay_i += len;
                decode_tagged_parts(t, None, slice)?
            }
            other => return Err(HyperCompError::InvalidTag(other)),
        };
        out.push(val);
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// DELTA / XOR STATE TRANSITION OPERATIONS
// ---------------------------------------------------------------------------

pub const OP_NO_CHANGE: u8 = 0;
pub const OP_SET_NEW: u8 = 1;
pub const OP_ADD: u8 = 2;
pub const OP_SUB: u8 = 3;
pub const OP_XOR_SHIFTED: u8 = 4;

/// A lossless state value transformation (`old_val -> new_val`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaOp {
    /// `new_val == old_val`
    NoChange,
    /// `new_val = v` (full replacement, optimal for 0, 1..=16, U256::MAX, or clean decimals)
    SetNew(U256),
    /// `new_val = old_val + delta` (optimal when transfer delta is a round decimal!)
    Add(U256),
    /// `new_val = old_val - delta` (optimal when withdrawal/swap delta is a round decimal!)
    Sub(U256),
    /// `new_val = old_val ^ (mask << (8 * shift))` (optimal for bit-packed Solidity slots!)
    XorShifted { shift: u8, mask: U256 },
}

impl DeltaOp {
    /// Validates that this `DeltaOp` satisfies all canonical wire invariants:
    /// - `Add(d)` and `Sub(d)` MUST be non-zero.
    /// - `XorShifted { shift, mask }` MUST have `shift < 32`, `mask != 0`, non-zero LSB byte
    ///   (maximal right-shift), and `mask.minimal_be_slice().len() + shift <= 32`.
    #[inline]
    pub fn validate(self) -> Result<(), HyperCompError> {
        match self {
            Self::NoChange | Self::SetNew(_) => Ok(()),
            Self::Add(d) | Self::Sub(d) => {
                if d.is_zero() {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
                Ok(())
            }
            Self::XorShifted { shift, mask } => {
                if shift >= 32 || mask.is_zero() {
                    return Err(HyperCompError::InvalidU256Length(shift));
                }
                let s = mask.minimal_be_slice();
                if s[s.len() - 1] == 0 {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
                if s.len() + (shift as usize) > 32 {
                    return Err(HyperCompError::U256Overflow);
                }
                Ok(())
            }
        }
    }

    /// Applies this delta operation to `old_val` with exact overflow/underflow checks.
    #[inline]
    pub fn apply(self, old_val: U256) -> Result<U256, HyperCompError> {
        self.validate()?;
        match self {
            Self::NoChange => Ok(old_val),
            Self::SetNew(v) => Ok(v),
            Self::Add(d) => old_val.checked_add(d).ok_or(HyperCompError::U256Overflow),
            Self::Sub(d) => old_val.checked_sub(d).ok_or(HyperCompError::U256Overflow),
            Self::XorShifted { shift, mask } => old_val.apply_xor_shifted(shift, mask),
        }
    }
}

/// Decodes a columnar stream of `count` `DeltaOp` instructions:
/// `[op_kinds: count B][xor_shifts: xor_count B][rhind_column(non_noop_count)]`.
pub fn delta_decode_column(
    buf: &[u8],
    pos: &mut usize,
    count: usize,
) -> Result<Vec<DeltaOp>, HyperCompError> {
    if buf.len().saturating_sub(*pos) < count {
        return Err(HyperCompError::UnexpectedEof);
    }
    let op_kinds = &buf[*pos..*pos + count];
    *pos += count;

    let mut value_count = 0usize;
    let mut xor_count = 0usize;
    for &op in op_kinds {
        match op {
            OP_NO_CHANGE => {}
            OP_SET_NEW | OP_ADD | OP_SUB => value_count += 1,
            OP_XOR_SHIFTED => {
                value_count += 1;
                xor_count += 1;
            }
            other => return Err(HyperCompError::InvalidTag(other)),
        }
    }

    if buf.len().saturating_sub(*pos) < xor_count {
        return Err(HyperCompError::UnexpectedEof);
    }
    let xor_shifts = &buf[*pos..*pos + xor_count];
    *pos += xor_count;

    let values = rhind_decode_column(buf, pos, value_count)?;

    let mut ops = Vec::with_capacity(count);
    let mut val_i = 0usize;
    let mut xor_i = 0usize;

    for &op in op_kinds {
        let decoded = match op {
            OP_NO_CHANGE => DeltaOp::NoChange,
            OP_SET_NEW => {
                let v = values[val_i];
                val_i += 1;
                DeltaOp::SetNew(v)
            }
            OP_ADD => {
                let d = values[val_i];
                val_i += 1;
                if d.is_zero() {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
                DeltaOp::Add(d)
            }
            OP_SUB => {
                let d = values[val_i];
                val_i += 1;
                if d.is_zero() {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
                DeltaOp::Sub(d)
            }
            OP_XOR_SHIFTED => {
                let shift = xor_shifts[xor_i];
                xor_i += 1;
                let mask = values[val_i];
                val_i += 1;
                let op = DeltaOp::XorShifted { shift, mask };
                op.validate()?;
                op
            }
            other => return Err(HyperCompError::InvalidTag(other)),
        };
        ops.push(decoded);
    }

    Ok(ops)
}
