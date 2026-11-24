use crate::error::HyperCompError;

/// Decodes a strictly canonical LEB128 `u32` varint.
///
/// Guarantees:
/// - Rejects values overflowing `u32` (byte 5 must be `<= 0x0F`, no continuation bit).
/// - Rejects overlong/non-canonical encodings (e.g. `[0x80, 0x00]`).
#[inline]
pub fn decode_varint_u32(buf: &[u8], pos: &mut usize) -> Result<u32, HyperCompError> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= buf.len() {
            return Err(HyperCompError::UnexpectedEof);
        }
        let b = buf[*pos];
        *pos += 1;

        if shift == 28 {
            // 5th byte: only 4 bits fit in u32, and continuation bit must be 0.
            if b == 0 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            if b > 0x0F {
                return Err(HyperCompError::VarintOverflow);
            }
            result |= (b as u32) << 28;
            return Ok(result);
        }

        if (b & 0x80) == 0 {
            if shift > 0 && b == 0 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            result |= (b as u32) << shift;
            return Ok(result);
        }

        result |= ((b & 0x7F) as u32) << shift;
        shift += 7;
    }
}

/// Decodes a `u32` count and safely converts it to `usize` with an explicit upper bound.
/// Behaves identically on 32-bit RISC-V (`riscv32im`) and 64-bit (`x86_64`) targets.
#[inline]
pub fn decode_count(buf: &[u8], pos: &mut usize, max: u32) -> Result<usize, HyperCompError> {
    let v = decode_varint_u32(buf, pos)?;
    if v > max {
        return Err(HyperCompError::LimitExceeded);
    }
    usize::try_from(v).map_err(|_| HyperCompError::LimitExceeded)
}

/// Decodes a strictly canonical LEB128 `u64` varint.
///
/// Fixes the silent high-bit truncation bug on byte 10 (`shift == 63`) where only 1 bit remains.
#[inline]
pub fn decode_varint_u64(buf: &[u8], pos: &mut usize) -> Result<u64, HyperCompError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= buf.len() {
            return Err(HyperCompError::UnexpectedEof);
        }
        let b = buf[*pos];
        *pos += 1;

        if shift == 63 {
            // 10th byte: only 1 bit fits in u64, continuation bit must be 0.
            if b == 0 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            if b > 0x01 {
                return Err(HyperCompError::VarintOverflow);
            }
            result |= (b as u64) << 63;
            return Ok(result);
        }

        if (b & 0x80) == 0 {
            if shift > 0 && b == 0 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            result |= (b as u64) << shift;
            return Ok(result);
        }

        result |= ((b & 0x7F) as u64) << shift;
        shift += 7;
    }
}

/// Decodes a strictly canonical LEB128 `u128` varint.
///
/// Fixes the silent high-bit truncation bug on byte 19 (`shift == 126`) where only 2 bits remain.
#[inline]
pub fn decode_varint_u128(buf: &[u8], pos: &mut usize) -> Result<u128, HyperCompError> {
    let mut result: u128 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= buf.len() {
            return Err(HyperCompError::UnexpectedEof);
        }
        let b = buf[*pos];
        *pos += 1;

        if shift == 126 {
            // 19th byte: only 2 bits fit in u128, continuation bit must be 0.
            if b == 0 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            if b > 0x03 {
                return Err(HyperCompError::VarintOverflow);
            }
            result |= (b as u128) << 126;
            return Ok(result);
        }

        if (b & 0x80) == 0 {
            if shift > 0 && b == 0 {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
            result |= (b as u128) << shift;
            return Ok(result);
        }

        result |= ((b & 0x7F) as u128) << shift;
        shift += 7;
    }
}

/// Branchless ZigZag decoding mapping `u128 -> i128` (0->0, 1->-1, 2->1, 3->-2, ...).
#[inline]
pub const fn zigzag_decode(z: u128) -> i128 {
    ((z >> 1) as i128) ^ -((z & 1) as i128)
}

/// Branchless ZigZag encoding mapping `i128 -> u128`.
#[inline]
pub const fn zigzag_encode(n: i128) -> u128 {
    ((n << 1) ^ (n >> 127)) as u128
}
