use crate::error::HyperCompError;

/// Two-byte magic header identifying an Al-Samawal HyperCompressor frame.
pub const MAGIC: [u8; 2] = *b"AS";

/// Current versioned wire format.
pub const FORMAT_VERSION: u8 = 2;

/// Default hard cap on items decoded in a single batch (prevents OOM in zkVM / untrusted nodes).
pub const MAX_DECODE_ITEMS: u32 = 10_000_000;

/// Default hard cap on Zstd-decompressed pre-entropy buffer (256 MiB bomb guard).
pub const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

/// Structured payload schema carried inside the compressed frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadKind {
    /// Ordered `(address[20], slot[32], old_val, new_val)` EVM state transitions.
    StateTransitions = 0,
    /// Contract-grouped EVM ZK-Rollup DA state updates `(address[20], nonce?, [(slot, new_val)])`.
    StateUpdates = 1,
    /// Contract-grouped EVM ZK-Rollup DA state deltas `(address[20], nonce?, [(slot, delta_op)])`.
    StateDeltas = 2,
    /// Contract-grouped Starknet/Cairo ZK-Rollup DA state updates `(address[32], nonce?, [(key, new_val)])`.
    StarknetUpdates = 3,
    /// Contract-grouped Starknet/Cairo ZK-Rollup DA state deltas `(address[32], nonce?, [(key, delta_op)])`.
    StarknetDeltas = 4,
}

impl PayloadKind {
    #[inline]
    pub fn from_u8(v: u8) -> Result<Self, HyperCompError> {
        match v {
            0 => Ok(Self::StateTransitions),
            1 => Ok(Self::StateUpdates),
            2 => Ok(Self::StateDeltas),
            3 => Ok(Self::StarknetUpdates),
            4 => Ok(Self::StarknetDeltas),
            _ => Err(HyperCompError::InvalidFlags(v)),
        }
    }
}

/// Outer entropy compression layer applied on top of the deterministic columnar transform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EntropyCodec {
    /// Raw pre-entropy stream (zero external deps, lowest zkVM cycle count).
    None = 0,
    /// Standard Zstd frame (decodable in `no_std` via `ruzstd`).
    Zstd = 1,
    /// Zstd frame compressed with a pre-shared chain-specific trained dictionary.
    ZstdWithDict = 2,
}

impl EntropyCodec {
    #[inline]
    pub fn from_u8(v: u8) -> Result<Self, HyperCompError> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Zstd),
            2 => Ok(Self::ZstdWithDict),
            other => Err(HyperCompError::UnsupportedEntropyCodec(other)),
        }
    }
}

/// Self-describing 4-byte (or 8-byte when using a trained dictionary) wire header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireHeader {
    pub version: u8,
    pub payload_kind: PayloadKind,
    pub entropy: EntropyCodec,
    pub dict_id: Option<u32>,
}

impl WireHeader {
    pub const BASE_LEN: usize = 4;

    /// Packs `payload_kind` (bits 0..=2) and `entropy` (bits 3..=5) into the flags byte.
    /// Bits 6..=7 are reserved and MUST be 0.
    #[inline]
    pub fn flags_byte(&self) -> u8 {
        (self.payload_kind as u8) | ((self.entropy as u8) << 3)
    }

    /// Parses and strictly validates the wire header, advancing `pos`.
    pub fn decode(buf: &[u8], pos: &mut usize) -> Result<Self, HyperCompError> {
        if buf.len().saturating_sub(*pos) < Self::BASE_LEN {
            return Err(HyperCompError::UnexpectedEof);
        }
        if buf[*pos] != MAGIC[0] || buf[*pos + 1] != MAGIC[1] {
            return Err(HyperCompError::InvalidMagic);
        }
        let version = buf[*pos + 2];
        if version != FORMAT_VERSION {
            return Err(HyperCompError::UnsupportedVersion(version));
        }
        let flags = buf[*pos + 3];
        *pos += Self::BASE_LEN;

        if (flags & 0b1100_0000) != 0 {
            return Err(HyperCompError::InvalidFlags(flags));
        }
        let payload_kind = PayloadKind::from_u8(flags & 0b0000_0111)?;
        let entropy = EntropyCodec::from_u8((flags >> 3) & 0b0000_0111)?;

        let dict_id = match entropy {
            EntropyCodec::ZstdWithDict => {
                if buf.len().saturating_sub(*pos) < 4 {
                    return Err(HyperCompError::UnexpectedEof);
                }
                let id = u32::from_le_bytes([
                    buf[*pos],
                    buf[*pos + 1],
                    buf[*pos + 2],
                    buf[*pos + 3],
                ]);
                *pos += 4;
                Some(id)
            }
            _ => None,
        };

        Ok(Self {
            version,
            payload_kind,
            entropy,
            dict_id,
        })
    }
}

/// Deterministic 32-bit FNV-1a fingerprint used to identify a trained Zstd dictionary
/// identically across `no_std` zkVM guests and host servers.
#[inline]
pub fn compute_dict_id(dict_bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in dict_bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}
