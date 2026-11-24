use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::dict::{dict_decode_fixed, slot_decode_column};
use crate::error::HyperCompError;
use crate::header::{
    compute_dict_id, EntropyCodec, PayloadKind, WireHeader, MAX_DECOMPRESSED_BYTES,
    MAX_DECODE_ITEMS,
};
use crate::poly::alsamawal_poly_decode_exact;
use crate::rhind::{delta_decode_column, rhind_decode_column, DeltaOp};
use crate::u256::U256;
use crate::varint::decode_count;

/// Ordered EVM state transition record (`address, slot, old_val -> new_val`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDiff {
    pub address: [u8; 20],
    pub slot: [u8; 32],
    pub old_val: U256,
    pub new_val: U256,
}

impl StateDiff {
    /// Serializes a slice of `StateDiff` into raw uncompressed 116-byte records
    /// (for baseline Zstd/Brotli comparison).
    pub fn to_raw_bytes(diffs: &[Self]) -> Vec<u8> {
        let mut raw = Vec::with_capacity(diffs.len() * 116);
        for d in diffs {
            raw.extend_from_slice(&d.address);
            raw.extend_from_slice(&d.slot);
            raw.extend_from_slice(&d.old_val.0);
            raw.extend_from_slice(&d.new_val.0);
        }
        raw
    }
}

/// Single storage update within a contract (real ZK-Rollup DA format — no redundant `old_val`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageUpdate {
    pub slot: [u8; 32],
    pub new_val: U256,
}

/// Contract-grouped ZK-Rollup state diff (Starknet / Citrea / canonical EVM DA layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractDiff {
    pub address: [u8; 20],
    pub nonce: Option<u64>,
    pub storage_updates: Vec<StorageUpdate>,
}

impl ContractDiff {
    /// Serializes contract-grouped state updates into raw uncompressed canonical bytes
    /// (20B addr + 1B has_nonce + optional 8B nonce + 4B count + N * 64B (slot + new_val)).
    pub fn to_raw_bytes(contracts: &[Self]) -> Vec<u8> {
        let total_slots: usize = contracts.iter().map(|c| c.storage_updates.len()).sum();
        let mut raw = Vec::with_capacity(contracts.len() * 33 + total_slots * 64);
        for c in contracts {
            raw.extend_from_slice(&c.address);
            match c.nonce {
                Some(n) => {
                    raw.push(1);
                    raw.extend_from_slice(&n.to_be_bytes());
                }
                None => raw.push(0),
            }
            raw.extend_from_slice(&(c.storage_updates.len() as u32).to_be_bytes());
            for u in &c.storage_updates {
                raw.extend_from_slice(&u.slot);
                raw.extend_from_slice(&u.new_val.0);
            }
        }
        raw
    }
}

/// Single storage delta operation within a contract (ZKsync-style delta DA format).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageDelta {
    pub slot: [u8; 32],
    pub op: DeltaOp,
}

/// Contract-grouped ZK-Rollup state delta batch (20-byte EVM addresses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractDelta {
    pub address: [u8; 20],
    pub nonce: Option<u64>,
    pub storage_deltas: Vec<StorageDelta>,
}

/// Contract-grouped Starknet/Cairo ZK-Rollup state diff (32-byte felt252 contract addresses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarknetContractDiff {
    pub address: [u8; 32],
    pub nonce: Option<u64>,
    pub storage_updates: Vec<StorageUpdate>,
}

impl StarknetContractDiff {
    /// Canonical raw serialization matching Starknet felt252 state diff size:
    /// `32B addr + 1B has_nonce + [8B nonce] + 4B count + N * 64B (key + new_val)`.
    pub fn to_raw_bytes(contracts: &[Self]) -> Vec<u8> {
        let total_slots: usize = contracts.iter().map(|c| c.storage_updates.len()).sum();
        let mut raw = Vec::with_capacity(contracts.len() * 45 + total_slots * 64);
        for c in contracts {
            raw.extend_from_slice(&c.address);
            match c.nonce {
                Some(n) => {
                    raw.push(1);
                    raw.extend_from_slice(&n.to_be_bytes());
                }
                None => raw.push(0),
            }
            raw.extend_from_slice(&(c.storage_updates.len() as u32).to_be_bytes());
            for u in &c.storage_updates {
                raw.extend_from_slice(&u.slot);
                raw.extend_from_slice(&u.new_val.0);
            }
        }
        raw
    }
}

/// Contract-grouped Starknet/Cairo ZK-Rollup state delta batch (32-byte felt252 addresses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarknetContractDelta {
    pub address: [u8; 32],
    pub nonce: Option<u64>,
    pub storage_deltas: Vec<StorageDelta>,
}

/// Safety limits enforced during untrusted / zkVM decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_items: u32,
    pub max_decompressed_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_items: MAX_DECODE_ITEMS,
            max_decompressed_bytes: MAX_DECOMPRESSED_BYTES,
        }
    }
}

// ---------------------------------------------------------------------------
// PRE-ENTROPY DETERMINISTIC DECODERS (ZERO EXTERNAL DEPS, PURE no_std)
// ---------------------------------------------------------------------------

/// Decodes a pre-entropy `StateTransitions` stream (`Vec<StateDiff>`), enforcing exact length.
/// Uses causal `old_known_bitmap`: whenever `(addr, slot)` appeared earlier in the batch with
/// `old_val[i] == last_new_val[(addr, slot)]`, `old_val` is reconstructed in 0 bytes!
pub fn decode_state_transitions_raw(
    pre: &[u8],
    limits: DecodeLimits,
) -> Result<Vec<StateDiff>, HyperCompError> {
    let mut pos = 0usize;
    let n = decode_count(pre, &mut pos, limits.max_items)?;
    let addrs = dict_decode_fixed::<20>(pre, &mut pos, n, limits.max_items)?;
    let slots = slot_decode_column(pre, &mut pos, n, limits.max_items)?;

    let bitmap_bytes = (n + 7) / 8;
    if pre.len().saturating_sub(pos) < bitmap_bytes {
        return Err(HyperCompError::UnexpectedEof);
    }
    let old_known_bitmap = &pre[pos..pos + bitmap_bytes];
    pos += bitmap_bytes;
    let rem_bits = n % 8;
    if rem_bits != 0 {
        let pad_mask = !((1u8 << rem_bits) - 1);
        if (old_known_bitmap[bitmap_bytes - 1] & pad_mask) != 0 {
            return Err(HyperCompError::NonCanonicalEncoding);
        }
    }

    let mut explicit_old_count = 0usize;
    for i in 0..n {
        if ((old_known_bitmap[i >> 3] >> (i & 7)) & 1) == 0 {
            explicit_old_count += 1;
        }
    }

    let explicit_olds = rhind_decode_column(pre, &mut pos, explicit_old_count)?;
    let ops = delta_decode_column(pre, &mut pos, n)?;

    if pos != pre.len() {
        return Err(HyperCompError::TrailingBytes(pre.len() - pos));
    }

    let mut last_val: BTreeMap<([u8; 20], [u8; 32]), U256> = BTreeMap::new();
    let mut diffs = Vec::with_capacity(n);
    let mut exp_i = 0usize;

    for i in 0..n {
        let key = (addrs[i], slots[i]);
        let is_known = ((old_known_bitmap[i >> 3] >> (i & 7)) & 1) != 0;
        let old_val = if is_known {
            *last_val
                .get(&key)
                .ok_or(HyperCompError::NonCanonicalEncoding)?
        } else {
            let v = explicit_olds[exp_i];
            exp_i += 1;
            v
        };
        let new_val = ops[i].apply(old_val)?;
        last_val.insert(key, new_val);
        diffs.push(StateDiff {
            address: addrs[i],
            slot: slots[i],
            old_val,
            new_val,
        });
    }
    Ok(diffs)
}

/// Helper decoding the shared contract-grouped header for fixed `ADDR_LEN`-byte addresses:
/// `[num_contracts][addresses: ADDR_LEN*C][nonce_bitmap][nonces: Al-Samawal][counts: C varints]`.
fn decode_contract_skeleton<const ADDR_LEN: usize>(
    pre: &[u8],
    pos: &mut usize,
    limits: DecodeLimits,
) -> Result<(Vec<[u8; ADDR_LEN]>, Vec<Option<u64>>, Vec<usize>, usize), HyperCompError> {
    let num_contracts = decode_count(pre, pos, limits.max_items)?;
    let addr_bytes = num_contracts
        .checked_mul(ADDR_LEN)
        .ok_or(HyperCompError::LimitExceeded)?;
    if pre.len().saturating_sub(*pos) < addr_bytes {
        return Err(HyperCompError::UnexpectedEof);
    }

    let mut addresses = Vec::with_capacity(num_contracts);
    for _ in 0..num_contracts {
        let mut addr = [0u8; ADDR_LEN];
        addr.copy_from_slice(&pre[*pos..*pos + ADDR_LEN]);
        *pos += ADDR_LEN;
        addresses.push(addr);
    }

    // Nonce presence bitmap
    let bitmap_bytes = (num_contracts + 7) / 8;
    if pre.len().saturating_sub(*pos) < bitmap_bytes {
        return Err(HyperCompError::UnexpectedEof);
    }
    let bitmap = &pre[*pos..*pos + bitmap_bytes];
    *pos += bitmap_bytes;

    // Canonicality: padding bits in the final bitmap byte must be 0.
    let rem_bits = num_contracts % 8;
    if rem_bits != 0 {
        let pad_mask = !((1u8 << rem_bits) - 1);
        if (bitmap[bitmap_bytes - 1] & pad_mask) != 0 {
            return Err(HyperCompError::NonCanonicalEncoding);
        }
    }

    let mut nonce_count = 0usize;
    for i in 0..num_contracts {
        if ((bitmap[i >> 3] >> (i & 7)) & 1) != 0 {
            nonce_count += 1;
        }
    }
    let nonce_vals = alsamawal_poly_decode_exact(pre, pos, nonce_count)?;

    let mut nonces = Vec::with_capacity(num_contracts);
    let mut n_i = 0usize;
    for i in 0..num_contracts {
        if ((bitmap[i >> 3] >> (i & 7)) & 1) != 0 {
            nonces.push(Some(nonce_vals[n_i]));
            n_i += 1;
        } else {
            nonces.push(None);
        }
    }

    // Per-contract slot counts
    let mut counts = Vec::with_capacity(num_contracts);
    let mut total_slots = 0usize;
    for _ in 0..num_contracts {
        let c = decode_count(pre, pos, limits.max_items)?;
        total_slots = total_slots
            .checked_add(c)
            .ok_or(HyperCompError::LimitExceeded)?;
        if total_slots > limits.max_items as usize {
            return Err(HyperCompError::LimitExceeded);
        }
        counts.push(c);
    }

    Ok((addresses, nonces, counts, total_slots))
}

/// Decodes a pre-entropy `StateUpdates` stream (`Vec<ContractDiff>`), enforcing exact length.
pub fn decode_state_updates_raw(
    pre: &[u8],
    limits: DecodeLimits,
) -> Result<Vec<ContractDiff>, HyperCompError> {
    let mut pos = 0usize;
    let (addresses, nonces, counts, total_slots) =
        decode_contract_skeleton(pre, &mut pos, limits)?;
    let slots = slot_decode_column(pre, &mut pos, total_slots, limits.max_items)?;
    let vals = rhind_decode_column(pre, &mut pos, total_slots)?;

    if pos != pre.len() {
        return Err(HyperCompError::TrailingBytes(pre.len() - pos));
    }

    let mut contracts = Vec::with_capacity(addresses.len());
    let mut idx = 0usize;
    for c_i in 0..addresses.len() {
        let cnt = counts[c_i];
        let mut updates = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            updates.push(StorageUpdate {
                slot: slots[idx],
                new_val: vals[idx],
            });
            idx += 1;
        }
        contracts.push(ContractDiff {
            address: addresses[c_i],
            nonce: nonces[c_i],
            storage_updates: updates,
        });
    }
    Ok(contracts)
}

/// Decodes a pre-entropy `StateDeltas` stream (`Vec<ContractDelta>`), enforcing exact length.
pub fn decode_state_deltas_raw(
    pre: &[u8],
    limits: DecodeLimits,
) -> Result<Vec<ContractDelta>, HyperCompError> {
    let mut pos = 0usize;
    let (addresses, nonces, counts, total_slots) =
        decode_contract_skeleton::<20>(pre, &mut pos, limits)?;
    let slots = slot_decode_column(pre, &mut pos, total_slots, limits.max_items)?;
    let ops = delta_decode_column(pre, &mut pos, total_slots)?;

    if pos != pre.len() {
        return Err(HyperCompError::TrailingBytes(pre.len() - pos));
    }

    let mut contracts = Vec::with_capacity(addresses.len());
    let mut idx = 0usize;
    for c_i in 0..addresses.len() {
        let cnt = counts[c_i];
        let mut deltas = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            deltas.push(StorageDelta {
                slot: slots[idx],
                op: ops[idx],
            });
            idx += 1;
        }
        contracts.push(ContractDelta {
            address: addresses[c_i],
            nonce: nonces[c_i],
            storage_deltas: deltas,
        });
    }
    Ok(contracts)
}

/// Helper decoding the shared Starknet 32-byte contract skeleton with compact Rhind addresses
/// (compresses system contracts like `0x1`, `0x2` from 32B to 1B and strips leading zero bytes).
fn decode_starknet_skeleton(
    pre: &[u8],
    pos: &mut usize,
    limits: DecodeLimits,
) -> Result<(Vec<[u8; 32]>, Vec<Option<u64>>, Vec<usize>, usize), HyperCompError> {
    let num_contracts = decode_count(pre, pos, limits.max_items)?;
    let addr_u256s = rhind_decode_column(pre, pos, num_contracts)?;
    let addresses: Vec<[u8; 32]> = addr_u256s.into_iter().map(|u| u.0).collect();

    let bitmap_bytes = (num_contracts + 7) / 8;
    if pre.len().saturating_sub(*pos) < bitmap_bytes {
        return Err(HyperCompError::UnexpectedEof);
    }
    let bitmap = &pre[*pos..*pos + bitmap_bytes];
    *pos += bitmap_bytes;

    let rem_bits = num_contracts % 8;
    if rem_bits != 0 {
        let pad_mask = !((1u8 << rem_bits) - 1);
        if (bitmap[bitmap_bytes - 1] & pad_mask) != 0 {
            return Err(HyperCompError::NonCanonicalEncoding);
        }
    }

    let mut nonce_count = 0usize;
    for i in 0..num_contracts {
        if ((bitmap[i >> 3] >> (i & 7)) & 1) != 0 {
            nonce_count += 1;
        }
    }
    let nonce_vals = alsamawal_poly_decode_exact(pre, pos, nonce_count)?;

    let mut nonces = Vec::with_capacity(num_contracts);
    let mut n_i = 0usize;
    for i in 0..num_contracts {
        if ((bitmap[i >> 3] >> (i & 7)) & 1) != 0 {
            nonces.push(Some(nonce_vals[n_i]));
            n_i += 1;
        } else {
            nonces.push(None);
        }
    }

    let mut counts = Vec::with_capacity(num_contracts);
    let mut total_slots = 0usize;
    for _ in 0..num_contracts {
        let c = decode_count(pre, pos, limits.max_items)?;
        total_slots = total_slots
            .checked_add(c)
            .ok_or(HyperCompError::LimitExceeded)?;
        if total_slots > limits.max_items as usize {
            return Err(HyperCompError::LimitExceeded);
        }
        counts.push(c);
    }

    Ok((addresses, nonces, counts, total_slots))
}

/// Decodes a pre-entropy `StarknetUpdates` stream (`Vec<StarknetContractDiff>`).
pub fn decode_starknet_updates_raw(
    pre: &[u8],
    limits: DecodeLimits,
) -> Result<Vec<StarknetContractDiff>, HyperCompError> {
    let mut pos = 0usize;
    let (addresses, nonces, counts, total_slots) =
        decode_starknet_skeleton(pre, &mut pos, limits)?;
    let slots = slot_decode_column(pre, &mut pos, total_slots, limits.max_items)?;
    let vals = rhind_decode_column(pre, &mut pos, total_slots)?;

    if pos != pre.len() {
        return Err(HyperCompError::TrailingBytes(pre.len() - pos));
    }

    let mut contracts = Vec::with_capacity(addresses.len());
    let mut idx = 0usize;
    for c_i in 0..addresses.len() {
        let cnt = counts[c_i];
        let mut updates = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            updates.push(StorageUpdate {
                slot: slots[idx],
                new_val: vals[idx],
            });
            idx += 1;
        }
        contracts.push(StarknetContractDiff {
            address: addresses[c_i],
            nonce: nonces[c_i],
            storage_updates: updates,
        });
    }
    Ok(contracts)
}

/// Decodes a pre-entropy `StarknetDeltas` stream (`Vec<StarknetContractDelta>`).
pub fn decode_starknet_deltas_raw(
    pre: &[u8],
    limits: DecodeLimits,
) -> Result<Vec<StarknetContractDelta>, HyperCompError> {
    let mut pos = 0usize;
    let (addresses, nonces, counts, total_slots) =
        decode_starknet_skeleton(pre, &mut pos, limits)?;
    let slots = slot_decode_column(pre, &mut pos, total_slots, limits.max_items)?;
    let ops = delta_decode_column(pre, &mut pos, total_slots)?;

    if pos != pre.len() {
        return Err(HyperCompError::TrailingBytes(pre.len() - pos));
    }

    let mut contracts = Vec::with_capacity(addresses.len());
    let mut idx = 0usize;
    for c_i in 0..addresses.len() {
        let cnt = counts[c_i];
        let mut deltas = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            deltas.push(StorageDelta {
                slot: slots[idx],
                op: ops[idx],
            });
            idx += 1;
        }
        contracts.push(StarknetContractDelta {
            address: addresses[c_i],
            nonce: nonces[c_i],
            storage_deltas: deltas,
        });
    }
    Ok(contracts)
}

// ---------------------------------------------------------------------------
// FRAMED DECOMPRESSION (HEADER + OPTIONAL PURE-RUST no_std ZSTD VIA ruzstd)
// ---------------------------------------------------------------------------

#[cfg(feature = "zstd-nostd")]
fn decompress_zstd_nostd(
    compressed: &[u8],
    dict_bytes: Option<&[u8]>,
    max_decompressed_bytes: usize,
) -> Result<Vec<u8>, HyperCompError> {
    use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

    let mut decoder = FrameDecoder::new();
    decoder.set_max_window_size(max_decompressed_bytes as u64);

    if let Some(raw_dict) = dict_bytes {
        let dict = ruzstd::decoding::Dictionary::decode_dict(raw_dict)
            .map_err(|_| HyperCompError::EntropyDecodeFailed)?;
        decoder
            .add_dict(dict)
            .map_err(|_| HyperCompError::EntropyDecodeFailed)?;
    }

    let mut cursor = compressed;
    decoder
        .reset(&mut cursor)
        .map_err(|_| HyperCompError::EntropyDecodeFailed)?;

    let declared_size = decoder.content_size();
    if declared_size > max_decompressed_bytes as u64 {
        return Err(HyperCompError::LimitExceeded);
    }

    let initial_cap = usize::try_from(declared_size)
        .unwrap_or(0)
        .min(1024 * 1024);
    let mut out = Vec::with_capacity(initial_cap);

    while !decoder.is_finished() {
        decoder
            .decode_blocks(&mut cursor, BlockDecodingStrategy::UptoBytes(64 * 1024))
            .map_err(|_| HyperCompError::EntropyDecodeFailed)?;
        if let Some(chunk) = decoder.collect() {
            let new_len = out
                .len()
                .checked_add(chunk.len())
                .ok_or(HyperCompError::LimitExceeded)?;
            if new_len > max_decompressed_bytes {
                return Err(HyperCompError::LimitExceeded);
            }
            out.extend_from_slice(&chunk);
        }
    }

    if let Some(chunk) = decoder.collect() {
        let new_len = out
            .len()
            .checked_add(chunk.len())
            .ok_or(HyperCompError::LimitExceeded)?;
        if new_len > max_decompressed_bytes {
            return Err(HyperCompError::LimitExceeded);
        }
        out.extend_from_slice(&chunk);
    }

    // Verify optional Zstd content checksum when present.
    if let Some(expected_cksum) = decoder.get_checksum_from_data() {
        if decoder.get_calculated_checksum() != Some(expected_cksum) {
            return Err(HyperCompError::EntropyDecodeFailed);
        }
    }

    // Reject unconsumed trailing bytes after the Zstd frame.
    if !cursor.is_empty() {
        return Err(HyperCompError::TrailingBytes(cursor.len()));
    }

    Ok(out)
}

/// Unwraps the versioned wire header and entropy layer into the raw pre-entropy payload bytes.
pub fn unwrap_frame<'a>(
    blob: &'a [u8],
    expected_kind: PayloadKind,
    dict_bytes: Option<&[u8]>,
    limits: DecodeLimits,
) -> Result<alloc::borrow::Cow<'a, [u8]>, HyperCompError> {
    let mut pos = 0usize;
    let header = WireHeader::decode(blob, &mut pos)?;
    if header.payload_kind != expected_kind {
        return Err(HyperCompError::PayloadKindMismatch {
            expected: expected_kind as u8,
            found: header.payload_kind as u8,
        });
    }
    let body = &blob[pos..];

    match header.entropy {
        EntropyCodec::None => Ok(alloc::borrow::Cow::Borrowed(body)),
        EntropyCodec::Zstd => {
            #[cfg(feature = "zstd-nostd")]
            {
                let decompressed =
                    decompress_zstd_nostd(body, None, limits.max_decompressed_bytes)?;
                Ok(alloc::borrow::Cow::Owned(decompressed))
            }
            #[cfg(not(feature = "zstd-nostd"))]
            {
                let _ = (body, limits);
                Err(HyperCompError::UnsupportedEntropyCodec(
                    EntropyCodec::Zstd as u8,
                ))
            }
        }
        EntropyCodec::ZstdWithDict => {
            let expected_id = header.dict_id.ok_or(HyperCompError::UnexpectedEof)?;
            let raw_dict = dict_bytes.ok_or(HyperCompError::MissingDictionary(expected_id))?;
            let actual_id = compute_dict_id(raw_dict);
            if actual_id != expected_id {
                return Err(HyperCompError::DictionaryIdMismatch {
                    expected: expected_id,
                    found: actual_id,
                });
            }
            #[cfg(feature = "zstd-nostd")]
            {
                let decompressed =
                    decompress_zstd_nostd(body, Some(raw_dict), limits.max_decompressed_bytes)?;
                Ok(alloc::borrow::Cow::Owned(decompressed))
            }
            #[cfg(not(feature = "zstd-nostd"))]
            {
                let _ = (body, limits);
                Err(HyperCompError::UnsupportedEntropyCodec(
                    EntropyCodec::ZstdWithDict as u8,
                ))
            }
        }
    }
}

/// Decompresses a full framed `StateTransitions` blob (`Vec<StateDiff>`).
pub fn decompress_state_transitions(
    blob: &[u8],
    dict: Option<&[u8]>,
) -> Result<Vec<StateDiff>, HyperCompError> {
    decompress_state_transitions_with_limits(blob, dict, DecodeLimits::default())
}

/// Decompresses a full framed `StateTransitions` blob with custom safety limits.
pub fn decompress_state_transitions_with_limits(
    blob: &[u8],
    dict: Option<&[u8]>,
    limits: DecodeLimits,
) -> Result<Vec<StateDiff>, HyperCompError> {
    let pre = unwrap_frame(blob, PayloadKind::StateTransitions, dict, limits)?;
    decode_state_transitions_raw(&pre, limits)
}

/// Decompresses a full framed `StateUpdates` blob (`Vec<ContractDiff>`).
pub fn decompress_state_updates(
    blob: &[u8],
    dict: Option<&[u8]>,
) -> Result<Vec<ContractDiff>, HyperCompError> {
    decompress_state_updates_with_limits(blob, dict, DecodeLimits::default())
}

/// Decompresses a full framed `StateUpdates` blob with custom safety limits.
pub fn decompress_state_updates_with_limits(
    blob: &[u8],
    dict: Option<&[u8]>,
    limits: DecodeLimits,
) -> Result<Vec<ContractDiff>, HyperCompError> {
    let pre = unwrap_frame(blob, PayloadKind::StateUpdates, dict, limits)?;
    decode_state_updates_raw(&pre, limits)
}

/// Decompresses a full framed `StateDeltas` blob (`Vec<ContractDelta>`).
pub fn decompress_state_deltas(
    blob: &[u8],
    dict: Option<&[u8]>,
) -> Result<Vec<ContractDelta>, HyperCompError> {
    decompress_state_deltas_with_limits(blob, dict, DecodeLimits::default())
}

/// Decompresses a full framed `StateDeltas` blob with custom safety limits.
pub fn decompress_state_deltas_with_limits(
    blob: &[u8],
    dict: Option<&[u8]>,
    limits: DecodeLimits,
) -> Result<Vec<ContractDelta>, HyperCompError> {
    let pre = unwrap_frame(blob, PayloadKind::StateDeltas, dict, limits)?;
    decode_state_deltas_raw(&pre, limits)
}

/// Decompresses a full framed `StarknetUpdates` blob (`Vec<StarknetContractDiff>`).
pub fn decompress_starknet_updates(
    blob: &[u8],
    dict: Option<&[u8]>,
) -> Result<Vec<StarknetContractDiff>, HyperCompError> {
    let limits = DecodeLimits::default();
    let pre = unwrap_frame(blob, PayloadKind::StarknetUpdates, dict, limits)?;
    decode_starknet_updates_raw(&pre, limits)
}

/// Decompresses a full framed `StarknetDeltas` blob (`Vec<StarknetContractDelta>`).
pub fn decompress_starknet_deltas(
    blob: &[u8],
    dict: Option<&[u8]>,
) -> Result<Vec<StarknetContractDelta>, HyperCompError> {
    let limits = DecodeLimits::default();
    let pre = unwrap_frame(blob, PayloadKind::StarknetDeltas, dict, limits)?;
    decode_starknet_deltas_raw(&pre, limits)
}
