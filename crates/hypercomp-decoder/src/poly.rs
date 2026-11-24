use alloc::vec::Vec;

use crate::error::HyperCompError;
use crate::varint::{decode_count, decode_varint_u128, zigzag_decode};

/// Decodes a length-prefixed sequence of `u64` values compressed via Al-Samawal degree-2
/// polynomial residual coding (`pred[i] = 2 * x[i-1] - x[i-2]`).
///
/// Zero-panic guarantee: uses checked `i128` arithmetic so corrupted extreme residuals
/// return `Err(HyperCompError::VarintOverflow)` instead of panicking or wrapping.
pub fn alsamawal_poly_decode(
    buf: &[u8],
    pos: &mut usize,
    max_count: u32,
) -> Result<Vec<u64>, HyperCompError> {
    let count = decode_count(buf, pos, max_count)?;
    alsamawal_poly_decode_exact(buf, pos, count)
}

/// Decodes exactly `count` `u64` values encoded via Al-Samawal degree-2 polynomial residuals
/// without an internal length prefix (used for columnar contract nonces & small storage slots).
pub fn alsamawal_poly_decode_exact(
    buf: &[u8],
    pos: &mut usize,
    count: usize,
) -> Result<Vec<u64>, HyperCompError> {
    // Each element requires at least 1 byte in the varint stream; reject impossible counts early.
    if buf.len().saturating_sub(*pos) < count {
        return Err(HyperCompError::UnexpectedEof);
    }
    let mut seq = Vec::with_capacity(count);
    let mut prev1: i128 = 0;
    let mut prev2: i128 = 0;

    for i in 0..count {
        let z = decode_varint_u128(buf, pos)?;
        let residual = zigzag_decode(z);
        // prev1, prev2 are in [0, u64::MAX], so 2*prev1 - prev2 fits safely in i128.
        let pred: i128 = match i {
            0 => 0,
            1 => prev1,
            _ => 2 * prev1 - prev2,
        };
        let x = pred
            .checked_add(residual)
            .ok_or(HyperCompError::VarintOverflow)?;
        if x < 0 || x > (u64::MAX as i128) {
            return Err(HyperCompError::VarintOverflow);
        }
        seq.push(x as u64);
        prev2 = prev1;
        prev1 = x;
    }
    Ok(seq)
}
