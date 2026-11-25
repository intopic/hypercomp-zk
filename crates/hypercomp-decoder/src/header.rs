use sha2::{Digest, Sha256};

use crate::error::HyperCompError;

/// Cryptographic 32-byte SHA-256 dictionary fingerprint (collision-resistant across zkVMs & sidecars).
pub type DictId = [u8; 32];

/// Two-byte magic header identifying an Al-Samawal HyperCompressor frame.
pub const MAGIC: [u8; 2] = *b"AS";

/// Four-byte RFC 8878 magic identifying an automatic Raw Zstd fallback frame
/// (disjoint from `MAGIC = b"AS"`, domain-separated internally via 1-byte `version|kind` prefix).
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Returns `true` when `blob` is an RFC 8878 Raw Zstd fallback frame.
#[inline]
pub fn is_raw_zstd_fallback(blob: &[u8]) -> bool {
    blob.len() >= ZSTD_MAGIC.len() && blob[..4] == ZSTD_MAGIC
}

/// Current versioned wire format.
pub const FORMAT_VERSION: u8 = 2;

/// Default hard cap on items decoded in a single batch (prevents OOM in zkVMs & untrusted nodes).
pub const MAX_DECODE_ITEMS: u32 = 1_000_000;

/// Default hard cap on Zstd-decompressed pre-entropy buffer (32 MiB bomb guard).
pub const MAX_DECOMPRESSED_BYTES: usize = 32 * 1024 * 1024;

/// Default hard cap on estimated decoded in-memory output size (64 MiB bomb guard).
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

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

/// Encodes the 1-byte domain separator `(FORMAT_VERSION << 4) | (kind as u8)` prepended inside
/// Raw Zstd fallback payloads so fallback frames enforce version and payload-kind separation.
#[inline]
pub const fn raw_fallback_tag(kind: PayloadKind) -> u8 {
    (FORMAT_VERSION << 4) | (kind as u8)
}

/// Validates the 1-byte domain separator at the start of a decompressed Raw Zstd fallback payload.
#[inline]
pub fn parse_raw_fallback_tag(tag: u8, expected: PayloadKind) -> Result<(), HyperCompError> {
    let version = tag >> 4;
    if version != FORMAT_VERSION {
        return Err(HyperCompError::UnsupportedVersion(version));
    }
    let kind = PayloadKind::from_u8(tag & 0x0F)?;
    if kind != expected {
        return Err(HyperCompError::PayloadKindMismatch {
            expected: expected as u8,
            found: kind as u8,
        });
    }
    Ok(())
}

/// Outer entropy compression layer applied on top of the deterministic columnar transform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EntropyCodec {
    /// Raw pre-entropy stream (zero external deps, lowest zkVM cycle count).
    None = 0,
    /// Standard Zstd frame with mandatory XXH64 checksum (decodable in `no_std` via `ruzstd`).
    Zstd = 1,
    /// Zstd frame with mandatory XXH64 checksum compressed using a SHA-256-pinned trained dictionary.
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

/// Self-describing 4-byte (or 36-byte when using a SHA-256-identified dictionary) wire header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireHeader {
    pub version: u8,
    pub payload_kind: PayloadKind,
    pub entropy: EntropyCodec,
    pub dict_id: Option<DictId>,
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
                if buf.len().saturating_sub(*pos) < 32 {
                    return Err(HyperCompError::UnexpectedEof);
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&buf[*pos..*pos + 32]);
                *pos += 32;
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

/// Computes the cryptographic SHA-256 digest of an arbitrary byte slice in `#![no_std]`.
#[inline]
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Cryptographic 32-byte SHA-256 fingerprint identifying a trained Zstd dictionary
/// identically across `no_std` zkVM guests and host sidecars.
#[inline]
pub fn compute_dict_id(dict_bytes: &[u8]) -> DictId {
    sha256_bytes(dict_bytes)
}
