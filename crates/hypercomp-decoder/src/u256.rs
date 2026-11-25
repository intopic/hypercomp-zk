use crate::error::HyperCompError;

/// Maximum decimal exponent `k` such that `10^k <= 2^256 - 1` (`10^77 < 2^256 < 10^78`).
pub const MAX_POW10_EXP: u8 = 77;

/// Compile-time lookup table of `10^k` in 4 × `u64` little-endian limbs (`k = 0..=77`).
/// Enables O(1) Rhind decoding (4 widening multiplies) instead of up to 75×32 byte loops.
pub const POW10: [[u64; 4]; 78] = build_pow10_table();

const fn build_pow10_table() -> [[u64; 4]; 78] {
    let mut table = [[0u64; 4]; 78];
    table[0] = [1, 0, 0, 0];
    let mut k = 1;
    while k < 78 {
        let prev = table[k - 1];
        let mut cur = [0u64; 4];
        let mut carry: u128 = 0;
        let mut i = 0;
        while i < 4 {
            let prod = (prev[i] as u128) * 10u128 + carry;
            cur[i] = prod as u64;
            carry = prod >> 64;
            i += 1;
        }
        table[k] = cur;
        k += 1;
    }
    table
}

/// EVM 256-bit unsigned integer stored in canonical big-endian wire order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct U256(pub [u8; 32]);

impl U256 {
    pub const ZERO: Self = Self([0u8; 32]);
    pub const MAX: Self = Self([0xFF; 32]);

    #[inline]
    pub const fn zero() -> Self {
        Self::ZERO
    }

    #[inline]
    pub const fn max_value() -> Self {
        Self::MAX
    }

    #[inline]
    pub fn from_u64(v: u64) -> Self {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&v.to_be_bytes());
        Self(b)
    }

    #[inline]
    pub fn from_u128(v: u128) -> Self {
        let mut b = [0u8; 32];
        b[16..32].copy_from_slice(&v.to_be_bytes());
        Self(b)
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    #[inline]
    pub fn is_max(&self) -> bool {
        self.0 == [0xFF; 32]
    }

    /// Converts big-endian bytes to little-endian `[u64; 4]` limbs (`limbs[0]` = LSW).
    #[inline]
    pub fn to_limbs(&self) -> [u64; 4] {
        let b = &self.0;
        [
            u64::from_be_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]),
            u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        ]
    }

    /// Converts little-endian `[u64; 4]` limbs back to big-endian bytes.
    #[inline]
    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&limbs[3].to_be_bytes());
        b[8..16].copy_from_slice(&limbs[2].to_be_bytes());
        b[16..24].copy_from_slice(&limbs[1].to_be_bytes());
        b[24..32].copy_from_slice(&limbs[0].to_be_bytes());
        Self(b)
    }

    /// Returns the minimal big-endian byte slice (no leading zero bytes; empty iff zero).
    #[inline]
    pub fn minimal_be_slice(&self) -> &[u8] {
        let first_nz = self.0.iter().position(|&x| x != 0).unwrap_or(32);
        &self.0[first_nz..]
    }

    /// Returns the number of minimal big-endian bytes (`0` for zero, `1..=32` otherwise).
    #[inline]
    pub fn minimal_be_len(&self) -> usize {
        self.minimal_be_slice().len()
    }

    /// Returns `Some(u64)` if the value fits in 64 bits.
    #[inline]
    pub fn to_u64_exact(&self) -> Option<u64> {
        let l = self.to_limbs();
        if l[1] == 0 && l[2] == 0 && l[3] == 0 {
            Some(l[0])
        } else {
            None
        }
    }

    /// Checked addition in `[0, 2^256 - 1]`. Returns `None` on overflow.
    /// Uses pure carry-flag arithmetic (no `u128`, optimal on 32-bit RV32IM).
    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let a = self.to_limbs();
        let b = rhs.to_limbs();
        let mut out = [0u64; 4];
        let mut carry = false;
        for i in 0..4 {
            let (s1, c1) = a[i].overflowing_add(b[i]);
            let (s2, c2) = s1.overflowing_add(carry as u64);
            out[i] = s2;
            carry = c1 | c2;
        }
        if carry {
            None
        } else {
            Some(Self::from_limbs(out))
        }
    }

    /// Checked subtraction in `[0, 2^256 - 1]`. Returns `None` on underflow (`self < rhs`).
    /// Uses pure borrow-flag arithmetic (no `u128`, optimal on 32-bit RV32IM).
    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        let a = self.to_limbs();
        let b = rhs.to_limbs();
        let mut out = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(borrow as u64);
            out[i] = d2;
            borrow = b1 | b2;
        }
        if borrow {
            None
        } else {
            Some(Self::from_limbs(out))
        }
    }

    /// Bitwise XOR of two 256-bit words.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn bitxor(self, rhs: Self) -> Self {
        let a = self.to_limbs();
        let b = rhs.to_limbs();
        Self::from_limbs([a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]])
    }

    /// Applies `self ^ (mask << (8 * shift_bytes))` with strict overflow & canonical checks.
    /// Used to compress partial updates inside bit-packed Solidity storage slots (e.g. Uniswap V3 `slot0`).
    #[inline]
    pub fn apply_xor_shifted(self, shift_bytes: u8, mask: Self) -> Result<Self, HyperCompError> {
        if shift_bytes >= 32 {
            return Err(HyperCompError::InvalidU256Length(shift_bytes));
        }
        let m_slice = mask.minimal_be_slice();
        if m_slice.is_empty() {
            return Err(HyperCompError::NonCanonicalEncoding);
        }
        let shift = shift_bytes as usize;
        // Canonicality: the least-significant byte of mask MUST ALWAYS be non-zero
        // (even for shift == 0, `{shift: 0, mask: 0xAB00}` is non-canonical vs `{shift: 1, mask: 0xAB}`).
        if m_slice[m_slice.len() - 1] == 0 {
            return Err(HyperCompError::NonCanonicalEncoding);
        }
        if m_slice.len() + shift > 32 {
            return Err(HyperCompError::U256Overflow);
        }
        let mut out = self.0;
        let start = 32 - shift - m_slice.len();
        for (i, &mb) in m_slice.iter().enumerate() {
            out[start + i] ^= mb;
        }
        Ok(Self(out))
    }

    /// Computes `mantissa * 10^exp` using the O(1) `POW10` table with native 32-bit `u32` limbs
    /// and exact overflow detection (compiles to native RV32IM `MUL`/`MULHU`, zero `u128` calls!).
    #[inline]
    pub fn mul_u64_pow10_checked(mantissa: u64, exp: u8) -> Option<Self> {
        if exp > MAX_POW10_EXP {
            return None;
        }
        let p64 = POW10[exp as usize];
        let p = [
            p64[0] as u32,
            (p64[0] >> 32) as u32,
            p64[1] as u32,
            (p64[1] >> 32) as u32,
            p64[2] as u32,
            (p64[2] >> 32) as u32,
            p64[3] as u32,
            (p64[3] >> 32) as u32,
        ];
        let m_lo = mantissa as u32 as u64;
        let m_hi = (mantissa >> 32) as u32 as u64;

        let mut out = [0u32; 8];
        let mut carry: u64 = 0;
        for i in 0..8 {
            let prod = (p[i] as u64) * m_lo + carry;
            out[i] = prod as u32;
            carry = prod >> 32;
        }
        if carry != 0 {
            return None;
        }

        if m_hi != 0 {
            if p[7] != 0 {
                // p >= 2^224 and m_hi >= 1 => product >= 2^256
                return None;
            }
            let mut carry_hi: u64 = 0;
            for i in 0..7 {
                let prod = (p[i] as u64) * m_hi + (out[i + 1] as u64) + carry_hi;
                out[i + 1] = prod as u32;
                carry_hi = prod >> 32;
            }
            if carry_hi != 0 {
                return None;
            }
        }

        let limbs = [
            (out[0] as u64) | ((out[1] as u64) << 32),
            (out[2] as u64) | ((out[3] as u64) << 32),
            (out[4] as u64) | ((out[5] as u64) << 32),
            (out[6] as u64) | ((out[7] as u64) << 32),
        ];
        Some(Self::from_limbs(limbs))
    }

    /// Pure 32-bit big-endian `u16`-chunk division by `divisor <= 10_000`.
    /// Zero 64-bit or 128-bit software division calls on 32-bit RV32IM!
    #[inline]
    fn div_rem_u16_chunks(bytes: [u8; 32], divisor: u32) -> ([u8; 32], u32) {
        let mut q = [0u8; 32];
        let mut rem: u32 = 0;
        for i in 0..16 {
            let hi = bytes[i * 2] as u32;
            let lo = bytes[i * 2 + 1] as u32;
            let cur = (rem << 16) | (hi << 8) | lo;
            let qi = cur / divisor;
            rem = cur - qi * divisor;
            q[i * 2] = (qi >> 8) as u8;
            q[i * 2 + 1] = (qi & 0xFF) as u8;
        }
        (q, rem)
    }

    /// Returns `true` iff `self` is divisible by 10 using pure 32-bit arithmetic (zero `u64` mod!).
    /// Mathematical identity: `256 ≡ 1 (mod 5)`, so `N ≡ sum(bytes[0..32]) (mod 5)`.
    #[inline]
    pub fn is_divisible_by_10(&self) -> bool {
        if (self.0[31] & 1) != 0 {
            return false;
        }
        let mut sum: u32 = 0;
        for &b in &self.0 {
            sum += b as u32;
        }
        #[allow(clippy::manual_is_multiple_of)]
        let div5 = (sum % 5) == 0;
        div5
    }

    /// Extracts the maximal decimal power `exp` such that `self = mantissa * 10^exp`
    /// with `mantissa % 10 != 0` (for non-zero `self`).
    /// Uses pure 32-bit `u16`-chunk division by `10_000` and `10` (zero `u128` software div on RV32IM!).
    pub fn extract_pow10(self) -> (Self, u8) {
        if self.is_zero() || !self.is_divisible_by_10() {
            return (self, 0);
        }
        let mut cur = self.0;
        let mut exp: u8 = 0;

        // Strip 4 decimal zeros at a time (10_000 fits easily in u32 chunk arithmetic)
        while exp + 4 <= MAX_POW10_EXP {
            let (q, r) = Self::div_rem_u16_chunks(cur, 10_000);
            if r == 0 {
                cur = q;
                exp += 4;
            } else {
                break;
            }
        }
        // Strip remaining single decimal zeros (at most 3 iterations)
        while exp < MAX_POW10_EXP {
            let (q, r) = Self::div_rem_u16_chunks(cur, 10);
            if r == 0 {
                cur = q;
                exp += 1;
            } else {
                break;
            }
        }
        (Self(cur), exp)
    }
}
