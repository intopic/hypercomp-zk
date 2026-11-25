use core::fmt;

/// All errors that can occur during deterministic, zero-panic decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HyperCompError {
    /// Missing or invalid magic bytes (`b"AS"`).
    InvalidMagic,
    /// Unsupported wire format version.
    UnsupportedVersion(u8),
    /// Reserved flag bits were set or invalid flag combination.
    InvalidFlags(u8),
    /// Unknown or disabled entropy codec ID.
    UnsupportedEntropyCodec(u8),
    /// Payload kind in header does not match the requested decoder.
    PayloadKindMismatch { expected: u8, found: u8 },
    /// Input buffer ended prematurely.
    UnexpectedEof,
    /// Unconsumed trailing bytes left after decoding completed.
    TrailingBytes(usize),
    /// LEB128 varint exceeded target integer bit width or polynomial reconstruction overflowed.
    VarintOverflow,
    /// Input was decodable ambiguously (overlong varint, non-minimal U256, non-optimal Rhind, etc.).
    NonCanonicalEncoding,
    /// Unknown Rhind or DeltaOp tag byte.
    InvalidTag(u8),
    /// Rhind decimal exponent out of valid range (1..=77).
    InvalidExponent(u8),
    /// Mantissa * 10^exp or Delta Add/Sub exceeded U256 range [0, 2^256 - 1].
    U256Overflow,
    /// Dictionary index out of bounds.
    InvalidIndex(u32),
    /// Invalid U256 or shifted-XOR byte length / shift offset.
    InvalidU256Length(u8),
    /// Column lengths do not match header item count.
    LengthMismatch,
    /// Decoded count or decompressed size exceeded configured safety limit.
    LimitExceeded,
    /// Blob requires a pre-shared Zstd dictionary SHA-256 ID that was not provided.
    MissingDictionary([u8; 32]),
    /// Provided Zstd dictionary SHA-256 ID does not match the header's dictionary ID.
    DictionaryIdMismatch { expected: [u8; 32], found: [u8; 32] },
    /// Underlying entropy decompression (e.g., Zstd) failed, lacked a required checksum,
    /// or produced an invalid frame.
    EntropyDecodeFailed,
}

fn fmt_dict_id_prefix(f: &mut fmt::Formatter<'_>, id: &[u8; 32]) -> fmt::Result {
    for &b in &id[..8] {
        write!(f, "{b:02x}")?;
    }
    write!(f, "...")
}

impl fmt::Display for HyperCompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid HyperCompressor magic header"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported wire format version: {v}"),
            Self::InvalidFlags(fl) => write!(f, "invalid header flags byte: 0x{fl:02x}"),
            Self::UnsupportedEntropyCodec(c) => write!(f, "unsupported entropy codec: {c}"),
            Self::PayloadKindMismatch { expected, found } => {
                write!(f, "payload kind mismatch: expected {expected}, found {found}")
            }
            Self::UnexpectedEof => write!(f, "unexpected end of input buffer"),
            Self::TrailingBytes(n) => write!(f, "unexpected trailing bytes: {n}"),
            Self::VarintOverflow => write!(f, "varint or integer arithmetic overflow"),
            Self::NonCanonicalEncoding => write!(f, "non-canonical encoding rejected"),
            Self::InvalidTag(t) => write!(f, "invalid tag byte: 0x{t:02x}"),
            Self::InvalidExponent(e) => write!(f, "invalid Rhind exponent: {e}"),
            Self::U256Overflow => write!(f, "U256 arithmetic overflow or underflow"),
            Self::InvalidIndex(i) => write!(f, "dictionary index out of bounds: {i}"),
            Self::InvalidU256Length(l) => write!(f, "invalid U256 length/shift: {l}"),
            Self::LengthMismatch => write!(f, "column length mismatch"),
            Self::LimitExceeded => write!(f, "safety decode limit exceeded"),
            Self::MissingDictionary(id) => {
                write!(f, "missing required Zstd dictionary sha256=0x")?;
                fmt_dict_id_prefix(f, id)
            }
            Self::DictionaryIdMismatch { expected, found } => {
                write!(f, "dictionary sha256 mismatch: expected 0x")?;
                fmt_dict_id_prefix(f, expected)?;
                write!(f, ", found 0x")?;
                fmt_dict_id_prefix(f, found)
            }
            Self::EntropyDecodeFailed => write!(f, "entropy layer decompression failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HyperCompError {}
