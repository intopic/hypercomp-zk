use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::dict::{dict_decode_fixed, slot_decode_column};
use crate::error::HyperCompError;
#[cfg(feature = "zstd-nostd")]
use crate::header::{parse_raw_fallback_tag, ZSTD_MAGIC};
use crate::header::{
    compute_dict_id, is_raw_zstd_fallback, EntropyCodec, PayloadKind, PrehashedDict, WireHeader,
    EST_BYTES_PER_CONTRACT_OVERHEAD, EST_BYTES_PER_SLOT, EST_BYTES_PER_TRANSITION,
    MAX_DECOMPRESSED_BYTES, MAX_DECODE_ITEMS, MAX_OUTPUT_BYTES, MAX_ZSTD_WINDOW_BYTES,
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
    /// (for baseline Zstd/Brotli comparison and automatic Raw Zstd fallback).
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

    /// Decodes canonical raw uncompressed 116-byte `StateDiff` records.
    pub fn from_raw_bytes(raw: &[u8], limits: DecodeLimits) -> Result<Vec<Self>, HyperCompError> {
        const REC_LEN: usize = 116;
        #[allow(clippy::manual_is_multiple_of)]
        if raw.len() % REC_LEN != 0 {
            return Err(HyperCompError::UnexpectedEof);
        }
        let n = raw.len() / REC_LEN;
        limits.check_transitions(n)?;
        let mut out = Vec::with_capacity(n);
        for chunk in raw.chunks_exact(REC_LEN) {
            let mut address = [0u8; 20];
            let mut slot = [0u8; 32];
            let mut old_b = [0u8; 32];
            let mut new_b = [0u8; 32];
            address.copy_from_slice(&chunk[0..20]);
            slot.copy_from_slice(&chunk[20..52]);
            old_b.copy_from_slice(&chunk[52..84]);
            new_b.copy_from_slice(&chunk[84..116]);
            out.push(Self {
                address,
                slot,
                old_val: U256(old_b),
                new_val: U256(new_b),
            });
        }
        Ok(out)
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

type RawContractUpdates<const ADDR_LEN: usize> = ([u8; ADDR_LEN], Option<u64>, Vec<StorageUpdate>);
type RawContractDeltas<const ADDR_LEN: usize> = ([u8; ADDR_LEN], Option<u64>, Vec<StorageDelta>);
type ContractSkeleton<const ADDR_LEN: usize> = (Vec<[u8; ADDR_LEN]>, Vec<Option<u64>>, Vec<usize>, usize);

fn decode_raw_updates_generic<const ADDR_LEN: usize>(
    raw: &[u8],
    limits: DecodeLimits,
) -> Result<Vec<RawContractUpdates<ADDR_LEN>>, HyperCompError> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    let mut total_slots = 0usize;
    let mut total_contracts = 0usize;
    let mut prev_addr: Option<[u8; ADDR_LEN]> = None;

    while pos < raw.len() {
        total_contracts = total_contracts
            .checked_add(1)
            .ok_or(HyperCompError::LimitExceeded)?;
        limits.check_contract_batch(total_contracts, total_slots, ADDR_LEN)?;
        if raw.len().saturating_sub(pos) < ADDR_LEN + 1 {
            return Err(HyperCompError::UnexpectedEof);
        }
        let mut address = [0u8; ADDR_LEN];
        address.copy_from_slice(&raw[pos..pos + ADDR_LEN]);
        pos += ADDR_LEN;

        if let Some(pa) = prev_addr {
            if address <= pa {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
        }
        prev_addr = Some(address);

        let has_nonce = raw[pos];
        pos += 1;
        let nonce = match has_nonce {
            0 => None,
            1 => {
                if raw.len().saturating_sub(pos) < 8 {
                    return Err(HyperCompError::UnexpectedEof);
                }
                let mut nb = [0u8; 8];
                nb.copy_from_slice(&raw[pos..pos + 8]);
                pos += 8;
                Some(u64::from_be_bytes(nb))
            }
            other => return Err(HyperCompError::InvalidTag(other)),
        };

        if raw.len().saturating_sub(pos) < 4 {
            return Err(HyperCompError::UnexpectedEof);
        }
        let cnt_u32 = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
        pos += 4;
        let cnt = usize::try_from(cnt_u32).map_err(|_| HyperCompError::LimitExceeded)?;
        total_slots = total_slots
            .checked_add(cnt)
            .ok_or(HyperCompError::LimitExceeded)?;
        limits.check_contract_batch(total_contracts, total_slots, ADDR_LEN)?;
        let need_bytes = cnt
            .checked_mul(64)
            .ok_or(HyperCompError::LimitExceeded)?;
        if raw.len().saturating_sub(pos) < need_bytes {
            return Err(HyperCompError::UnexpectedEof);
        }

        let mut storage_updates = Vec::with_capacity(cnt);
        let mut prev_slot: Option<[u8; 32]> = None;
        for _ in 0..cnt {
            let mut slot = [0u8; 32];
            let mut val = [0u8; 32];
            slot.copy_from_slice(&raw[pos..pos + 32]);
            val.copy_from_slice(&raw[pos + 32..pos + 64]);
            pos += 64;
            if let Some(ps) = prev_slot {
                if slot <= ps {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
            }
            prev_slot = Some(slot);
            storage_updates.push(StorageUpdate {
                slot,
                new_val: U256(val),
            });
        }
        out.push((address, nonce, storage_updates));
    }
    Ok(out)
}

fn decode_raw_u256_of_len(raw: &[u8], pos: &mut usize, len: usize) -> Result<U256, HyperCompError> {
    if len == 0 {
        return Ok(U256::ZERO);
    }
    if len > 32 {
        return Err(HyperCompError::InvalidU256Length(len as u8));
    }
    if raw.len().saturating_sub(*pos) < len {
        return Err(HyperCompError::UnexpectedEof);
    }
    let slice = &raw[*pos..*pos + len];
    *pos += len;
    if slice[0] == 0 {
        return Err(HyperCompError::NonCanonicalEncoding);
    }
    let mut b = [0u8; 32];
    b[32 - len..32].copy_from_slice(slice);
    Ok(U256(b))
}

fn encode_raw_deltas_generic<const ADDR_LEN: usize>(
    items: &[([u8; ADDR_LEN], Option<u64>, &[StorageDelta])],
) -> Result<Vec<u8>, HyperCompError> {
    let total_slots: usize = items.iter().map(|(_, _, d)| d.len()).sum();
    let mut raw = Vec::with_capacity(items.len() * (ADDR_LEN + 13) + total_slots * 44);
    let mut prev_addr: Option<[u8; ADDR_LEN]> = None;

    for (address, nonce, deltas) in items {
        if let Some(pa) = prev_addr {
            if *address <= pa {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
        }
        prev_addr = Some(*address);

        let mut prev_slot: Option<[u8; 32]> = None;
        for d in *deltas {
            if let Some(ps) = prev_slot {
                if d.slot <= ps {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
            }
            prev_slot = Some(d.slot);
            d.op.validate()?;
        }

        // Check whether pure fixed-32B SetNew layout (bit-identical to `ContractDiff::to_raw_bytes`,
        // ZERO overhead on 32B random hashes!) is at least as compact as packed `(op, len)` deltas.
        let all_set_new = deltas.iter().all(|d| matches!(d.op, DeltaOp::SetNew(_)));
        let compact_val_bytes: usize = deltas
            .iter()
            .map(|d| match d.op {
                DeltaOp::NoChange => 1,
                DeltaOp::SetNew(v) => {
                    1 + if v.is_zero() {
                        0
                    } else {
                        v.minimal_be_slice().len()
                    }
                }
                DeltaOp::Add(v) | DeltaOp::Sub(v) => 1 + v.minimal_be_slice().len(),
                DeltaOp::XorShifted { mask, .. } => 2 + mask.minimal_be_slice().len(),
            })
            .sum();
        let use_fixed32_setnew = all_set_new && compact_val_bytes >= deltas.len() * 32;

        raw.extend_from_slice(address);
        let mode_bit: u8 = if use_fixed32_setnew { 0x00 } else { 0x80 };
        match nonce {
            Some(n) => {
                raw.push(mode_bit | 1);
                raw.extend_from_slice(&n.to_be_bytes());
            }
            None => raw.push(mode_bit),
        }
        let cnt_u32 = u32::try_from(deltas.len()).map_err(|_| HyperCompError::LimitExceeded)?;
        raw.extend_from_slice(&cnt_u32.to_be_bytes());

        if use_fixed32_setnew {
            for d in *deltas {
                raw.extend_from_slice(&d.slot);
                if let DeltaOp::SetNew(v) = d.op {
                    raw.extend_from_slice(&v.0);
                }
            }
        } else {
            for d in *deltas {
                raw.extend_from_slice(&d.slot);
                match d.op {
                    DeltaOp::NoChange => raw.push(0x00),
                    DeltaOp::SetNew(v) => {
                        if v.is_zero() {
                            raw.push(0x01);
                        } else {
                            let s = v.minimal_be_slice();
                            raw.push(0x01 + s.len() as u8);
                            raw.extend_from_slice(s);
                        }
                    }
                    DeltaOp::Add(v) => {
                        let s = v.minimal_be_slice();
                        raw.push(0x21 + s.len() as u8);
                        raw.extend_from_slice(s);
                    }
                    DeltaOp::Sub(v) => {
                        let s = v.minimal_be_slice();
                        raw.push(0x41 + s.len() as u8);
                        raw.extend_from_slice(s);
                    }
                    DeltaOp::XorShifted { shift, mask } => {
                        let s = mask.minimal_be_slice();
                        raw.push(0x61 + s.len() as u8);
                        raw.push(shift);
                        raw.extend_from_slice(s);
                    }
                }
            }
        }
    }
    Ok(raw)
}

fn decode_raw_deltas_generic<const ADDR_LEN: usize>(
    raw: &[u8],
    limits: DecodeLimits,
) -> Result<Vec<RawContractDeltas<ADDR_LEN>>, HyperCompError> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    let mut total_slots = 0usize;
    let mut total_contracts = 0usize;
    let mut prev_addr: Option<[u8; ADDR_LEN]> = None;

    while pos < raw.len() {
        total_contracts = total_contracts
            .checked_add(1)
            .ok_or(HyperCompError::LimitExceeded)?;
        limits.check_contract_batch(total_contracts, total_slots, ADDR_LEN)?;
        if raw.len().saturating_sub(pos) < ADDR_LEN + 1 {
            return Err(HyperCompError::UnexpectedEof);
        }
        let mut address = [0u8; ADDR_LEN];
        address.copy_from_slice(&raw[pos..pos + ADDR_LEN]);
        pos += ADDR_LEN;

        if let Some(pa) = prev_addr {
            if address <= pa {
                return Err(HyperCompError::NonCanonicalEncoding);
            }
        }
        prev_addr = Some(address);

        let flags = raw[pos];
        pos += 1;
        let (is_compact, has_nonce) = match flags {
            0x00 => (false, false),
            0x01 => (false, true),
            0x80 => (true, false),
            0x81 => (true, true),
            other => return Err(HyperCompError::InvalidTag(other)),
        };

        let nonce = if has_nonce {
            if raw.len().saturating_sub(pos) < 8 {
                return Err(HyperCompError::UnexpectedEof);
            }
            let mut nb = [0u8; 8];
            nb.copy_from_slice(&raw[pos..pos + 8]);
            pos += 8;
            Some(u64::from_be_bytes(nb))
        } else {
            None
        };

        if raw.len().saturating_sub(pos) < 4 {
            return Err(HyperCompError::UnexpectedEof);
        }
        let cnt_u32 = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
        pos += 4;
        let cnt = usize::try_from(cnt_u32).map_err(|_| HyperCompError::LimitExceeded)?;
        total_slots = total_slots
            .checked_add(cnt)
            .ok_or(HyperCompError::LimitExceeded)?;
        limits.check_contract_batch(total_contracts, total_slots, ADDR_LEN)?;

        let mut prev_slot: Option<[u8; 32]> = None;
        if !is_compact {
            let need_bytes = cnt.checked_mul(64).ok_or(HyperCompError::LimitExceeded)?;
            if raw.len().saturating_sub(pos) < need_bytes {
                return Err(HyperCompError::UnexpectedEof);
            }
            let mut storage_deltas = Vec::with_capacity(cnt);
            for _ in 0..cnt {
                let mut slot = [0u8; 32];
                let mut val = [0u8; 32];
                slot.copy_from_slice(&raw[pos..pos + 32]);
                val.copy_from_slice(&raw[pos + 32..pos + 64]);
                pos += 64;
                if let Some(ps) = prev_slot {
                    if slot <= ps {
                        return Err(HyperCompError::NonCanonicalEncoding);
                    }
                }
                prev_slot = Some(slot);
                storage_deltas.push(StorageDelta {
                    slot,
                    op: DeltaOp::SetNew(U256(val)),
                });
            }
            out.push((address, nonce, storage_deltas));
            continue;
        }

        let min_bytes = cnt.checked_mul(33).ok_or(HyperCompError::LimitExceeded)?;
        if raw.len().saturating_sub(pos) < min_bytes {
            return Err(HyperCompError::UnexpectedEof);
        }

        let mut storage_deltas = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            if raw.len().saturating_sub(pos) < 33 {
                return Err(HyperCompError::UnexpectedEof);
            }
            let mut slot = [0u8; 32];
            slot.copy_from_slice(&raw[pos..pos + 32]);
            pos += 32;
            if let Some(ps) = prev_slot {
                if slot <= ps {
                    return Err(HyperCompError::NonCanonicalEncoding);
                }
            }
            prev_slot = Some(slot);

            let tag = raw[pos];
            pos += 1;
            let op = match tag {
                0x00 => DeltaOp::NoChange,
                0x01..=0x21 => {
                    let len = (tag - 0x01) as usize;
                    DeltaOp::SetNew(decode_raw_u256_of_len(raw, &mut pos, len)?)
                }
                0x22..=0x41 => {
                    let len = (tag - 0x21) as usize;
                    DeltaOp::Add(decode_raw_u256_of_len(raw, &mut pos, len)?)
                }
                0x42..=0x61 => {
                    let len = (tag - 0x41) as usize;
                    DeltaOp::Sub(decode_raw_u256_of_len(raw, &mut pos, len)?)
                }
                0x62..=0x81 => {
                    let len = (tag - 0x61) as usize;
                    if pos >= raw.len() {
                        return Err(HyperCompError::UnexpectedEof);
                    }
                    let shift = raw[pos];
                    pos += 1;
                    let mask = decode_raw_u256_of_len(raw, &mut pos, len)?;
                    DeltaOp::XorShifted { shift, mask }
                }
                other => return Err(HyperCompError::InvalidTag(other)),
            };
            op.validate()?;
            storage_deltas.push(StorageDelta { slot, op });
        }
        out.push((address, nonce, storage_deltas));
    }
    Ok(out)
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

    /// Decodes canonical raw uncompressed contract-grouped state updates.
    pub fn from_raw_bytes(raw: &[u8], limits: DecodeLimits) -> Result<Vec<Self>, HyperCompError> {
        let decoded = decode_raw_updates_generic::<20>(raw, limits)?;
        Ok(decoded
            .into_iter()
            .map(|(address, nonce, storage_updates)| Self {
                address,
                nonce,
                storage_updates,
            })
            .collect())
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

impl ContractDelta {
    /// Serializes contract-grouped state deltas into compact canonical raw bytes
    /// (validating every `DeltaOp` and strict ascending `(address, slot)` uniqueness).
    pub fn to_raw_bytes(contracts: &[Self]) -> Result<Vec<u8>, HyperCompError> {
        let items: Vec<([u8; 20], Option<u64>, &[StorageDelta])> = contracts
            .iter()
            .map(|c| (c.address, c.nonce, c.storage_deltas.as_slice()))
            .collect();
        encode_raw_deltas_generic::<20>(&items)
    }

    /// Decodes compact canonical raw contract-grouped state deltas.
    pub fn from_raw_bytes(raw: &[u8], limits: DecodeLimits) -> Result<Vec<Self>, HyperCompError> {
        let decoded = decode_raw_deltas_generic::<20>(raw, limits)?;
        Ok(decoded
            .into_iter()
            .map(|(address, nonce, storage_deltas)| Self {
                address,
                nonce,
                storage_deltas,
            })
            .collect())
    }
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

    /// Decodes canonical raw uncompressed Starknet state updates.
    pub fn from_raw_bytes(raw: &[u8], limits: DecodeLimits) -> Result<Vec<Self>, HyperCompError> {
        let decoded = decode_raw_updates_generic::<32>(raw, limits)?;
        Ok(decoded
            .into_iter()
            .map(|(address, nonce, storage_updates)| Self {
                address,
                nonce,
                storage_updates,
            })
            .collect())
    }
}

/// Contract-grouped Starknet/Cairo ZK-Rollup state delta batch (32-byte felt252 addresses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarknetContractDelta {
    pub address: [u8; 32],
    pub nonce: Option<u64>,
    pub storage_deltas: Vec<StorageDelta>,
}

impl StarknetContractDelta {
    /// Serializes Starknet state deltas into compact canonical raw bytes
    /// (validating every `DeltaOp` and strict ascending `(address, slot)` uniqueness).
    pub fn to_raw_bytes(contracts: &[Self]) -> Result<Vec<u8>, HyperCompError> {
        let items: Vec<([u8; 32], Option<u64>, &[StorageDelta])> = contracts
            .iter()
            .map(|c| (c.address, c.nonce, c.storage_deltas.as_slice()))
            .collect();
        encode_raw_deltas_generic::<32>(&items)
    }

    /// Decodes compact canonical raw Starknet state deltas.
    pub fn from_raw_bytes(raw: &[u8], limits: DecodeLimits) -> Result<Vec<Self>, HyperCompError> {
        let decoded = decode_raw_deltas_generic::<32>(raw, limits)?;
        Ok(decoded
            .into_iter()
            .map(|(address, nonce, storage_deltas)| Self {
                address,
                nonce,
                storage_deltas,
            })
            .collect())
    }
}

/// Safety limits enforced identically across encoder, sidecar, full nodes, and zkVM guests (`N-1`).
///
/// Using a single canonical consensus profile (`DecodeLimits::CONSENSUS`) guarantees that every
/// batch accepted by the encoder & L2 full nodes also decodes inside a 48 MiB bump-allocator
/// 32-bit RISC-V zkVM guest without OOM or consensus divergence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_items: u32,
    pub max_decompressed_bytes: usize,
    pub max_output_bytes: usize,
    pub max_window_bytes: usize,
}

impl DecodeLimits {
    /// Single canonical consensus profile enforced identically by `Default`, `zkvm()`, encoder,
    /// and sidecar (`100k` items, `8 MiB` pre-entropy, `8 MiB` Zstd window, `16 MiB` calibrated output).
    pub const CONSENSUS: Self = Self {
        max_items: MAX_DECODE_ITEMS,
        max_decompressed_bytes: MAX_DECOMPRESSED_BYTES,
        max_output_bytes: MAX_OUTPUT_BYTES,
        max_window_bytes: MAX_ZSTD_WINDOW_BYTES,
    };

    /// Alias for [`Self::CONSENSUS`] tailored for 32-bit RISC-V zkVM guests (SP1 / RISC Zero).
    #[inline]
    pub const fn zkvm() -> Self {
        Self::CONSENSUS
    }

    /// Validates an ordered `StateDiff` transition batch against `max_items` and calibrated
    /// `max_output_bytes` (`EST_BYTES_PER_TRANSITION`).
    #[inline]
    pub fn check_transitions(&self, count: usize) -> Result<(), HyperCompError> {
        if u32::try_from(count).map_or(true, |v| v > self.max_items) {
            return Err(HyperCompError::LimitExceeded);
        }
        let est = count
            .checked_mul(EST_BYTES_PER_TRANSITION)
            .ok_or(HyperCompError::LimitExceeded)?;
        if est > self.max_output_bytes {
            return Err(HyperCompError::LimitExceeded);
        }
        Ok(())
    }

    /// Validates a contract-grouped DA batch (`num_contracts`, `total_slots`, `addr_len`) against
    /// `max_items` and calibrated bump-allocator `max_output_bytes` (`EST_BYTES_PER_SLOT = 144`).
    #[inline]
    pub fn check_contract_batch(
        &self,
        num_contracts: usize,
        total_slots: usize,
        addr_len: usize,
    ) -> Result<(), HyperCompError> {
        if u32::try_from(num_contracts).map_or(true, |v| v > self.max_items)
            || u32::try_from(total_slots).map_or(true, |v| v > self.max_items)
        {
            return Err(HyperCompError::LimitExceeded);
        }
        let est = num_contracts
            .checked_mul(addr_len.saturating_add(EST_BYTES_PER_CONTRACT_OVERHEAD))
            .and_then(|c| {
                total_slots
                    .checked_mul(EST_BYTES_PER_SLOT)
                    .and_then(|s| c.checked_add(s))
            })
            .ok_or(HyperCompError::LimitExceeded)?;
        if est > self.max_output_bytes {
            return Err(HyperCompError::LimitExceeded);
        }
        Ok(())
    }
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self::CONSENSUS
    }
}

/// Validates that contract addresses are strictly ascending (no duplicates / ambiguous ordering).
#[inline]
fn validate_strictly_ascending<const N: usize>(keys: &[[u8; N]]) -> Result<(), HyperCompError> {
    for w in keys.windows(2) {
        if w[1] <= w[0] {
            return Err(HyperCompError::NonCanonicalEncoding);
        }
    }
    Ok(())
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
    // H-1 RLE OOM-bomb guard: every transition requires at least 1 op-kind byte in `delta_decode_column`.
    if n > pre.len().saturating_sub(pos) {
        return Err(HyperCompError::UnexpectedEof);
    }
    limits.check_transitions(n)?;
    let addrs = dict_decode_fixed::<20>(pre, &mut pos, n, limits.max_items)?;
    let slots = slot_decode_column(pre, &mut pos, n, limits.max_items)?;

    let bitmap_bytes = n.div_ceil(8);
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
) -> Result<ContractSkeleton<ADDR_LEN>, HyperCompError> {
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
    let bitmap_bytes = num_contracts.div_ceil(8);
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

    // H-1 RLE OOM-bomb guard & calibrated bump-allocator output bound (N-1 / N-2).
    if total_slots > pre.len().saturating_sub(*pos) {
        return Err(HyperCompError::UnexpectedEof);
    }
    limits.check_contract_batch(num_contracts, total_slots, ADDR_LEN)?;
    validate_strictly_ascending(&addresses)?;

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
        validate_strictly_ascending(&slots[idx..idx + cnt])?;
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
        validate_strictly_ascending(&slots[idx..idx + cnt])?;
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
) -> Result<ContractSkeleton<32>, HyperCompError> {
    let num_contracts = decode_count(pre, pos, limits.max_items)?;
    let addr_u256s = rhind_decode_column(pre, pos, num_contracts)?;
    let addresses: Vec<[u8; 32]> = addr_u256s.into_iter().map(|u| u.0).collect();

    let bitmap_bytes = num_contracts.div_ceil(8);
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

    // H-1 RLE OOM-bomb guard & calibrated bump-allocator output bound (N-1 / N-2).
    if total_slots > pre.len().saturating_sub(*pos) {
        return Err(HyperCompError::UnexpectedEof);
    }
    limits.check_contract_batch(num_contracts, total_slots, 32)?;
    validate_strictly_ascending(&addresses)?;

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
        validate_strictly_ascending(&slots[idx..idx + cnt])?;
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
        validate_strictly_ascending(&slots[idx..idx + cnt])?;
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
    limits: DecodeLimits,
) -> Result<Vec<u8>, HyperCompError> {
    use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

    // RFC 8878 header pre-check before any allocation (`N-2` / `M-2`):
    // require both `Frame_Content_Size` (fcs_flag != 0 || single_segment == 1)
    // and `Content_Checksum_Flag` (bit 2) to be present on every HyperComp Zstd frame.
    if compressed.len() < 5 || compressed[..4] != ZSTD_MAGIC {
        return Err(HyperCompError::EntropyDecodeFailed);
    }
    let fhd = compressed[4];
    let fcs_present = ((fhd >> 6) != 0) || (((fhd >> 5) & 1) != 0);
    let checksum_present = ((fhd >> 2) & 1) != 0;
    if !fcs_present || !checksum_present {
        return Err(HyperCompError::EntropyDecodeFailed);
    }

    let mut decoder = FrameDecoder::new();
    let max_window = limits.max_window_bytes.min(limits.max_decompressed_bytes);
    decoder.set_max_window_size(max_window as u64);

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

    let declared_size =
        usize::try_from(decoder.content_size()).map_err(|_| HyperCompError::LimitExceeded)?;
    if declared_size > limits.max_decompressed_bytes {
        return Err(HyperCompError::LimitExceeded);
    }

    // Reserve exact declared size ONCE to eliminate Vec doubling leaks in bump-allocator zkVMs (`N-2`).
    let mut out = Vec::with_capacity(declared_size);

    while !decoder.is_finished() {
        decoder
            .decode_blocks(&mut cursor, BlockDecodingStrategy::UptoBytes(64 * 1024))
            .map_err(|_| HyperCompError::EntropyDecodeFailed)?;
        if let Some(chunk) = decoder.collect() {
            let new_len = out
                .len()
                .checked_add(chunk.len())
                .ok_or(HyperCompError::LimitExceeded)?;
            if new_len > declared_size {
                return Err(HyperCompError::EntropyDecodeFailed);
            }
            out.extend_from_slice(&chunk);
        }
    }

    if let Some(chunk) = decoder.collect() {
        let new_len = out
            .len()
            .checked_add(chunk.len())
            .ok_or(HyperCompError::LimitExceeded)?;
        if new_len > declared_size {
            return Err(HyperCompError::EntropyDecodeFailed);
        }
        out.extend_from_slice(&chunk);
    }

    if out.len() != declared_size {
        return Err(HyperCompError::EntropyDecodeFailed);
    }

    // Verify mandatory Zstd XXH64 content checksum on all HyperComp Zstd frames (H-3 / M-2).
    let expected_cksum = decoder
        .get_checksum_from_data()
        .ok_or(HyperCompError::EntropyDecodeFailed)?;
    if decoder.get_calculated_checksum() != Some(expected_cksum) {
        return Err(HyperCompError::EntropyDecodeFailed);
    }

    // Reject unconsumed trailing bytes after the Zstd frame.
    if !cursor.is_empty() {
        return Err(HyperCompError::TrailingBytes(cursor.len()));
    }

    Ok(out)
}

fn unwrap_frame_inner<'a>(
    blob: &'a [u8],
    expected_kind: PayloadKind,
    dict_bytes: Option<&[u8]>,
    prehashed_id: Option<[u8; 32]>,
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
        EntropyCodec::None => {
            if body.len() > limits.max_decompressed_bytes {
                return Err(HyperCompError::LimitExceeded);
            }
            Ok(alloc::borrow::Cow::Borrowed(body))
        }
        EntropyCodec::Zstd => {
            #[cfg(feature = "zstd-nostd")]
            {
                let decompressed = decompress_zstd_nostd(body, None, limits)?;
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
            let actual_id = prehashed_id.unwrap_or_else(|| compute_dict_id(raw_dict));
            if actual_id != expected_id {
                return Err(HyperCompError::DictionaryIdMismatch {
                    expected: expected_id,
                    found: actual_id,
                });
            }
            #[cfg(feature = "zstd-nostd")]
            {
                let decompressed = decompress_zstd_nostd(body, Some(raw_dict), limits)?;
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

/// Unwraps the versioned wire header and entropy layer into the raw pre-entropy payload bytes.
pub fn unwrap_frame<'a>(
    blob: &'a [u8],
    expected_kind: PayloadKind,
    dict_bytes: Option<&[u8]>,
    limits: DecodeLimits,
) -> Result<alloc::borrow::Cow<'a, [u8]>, HyperCompError> {
    unwrap_frame_inner(blob, expected_kind, dict_bytes, None, limits)
}

/// Unwraps a versioned frame using a [`PrehashedDict`], avoiding duplicate dictionary SHA-256
/// hashing in zkVM guests (`N-5`).
pub fn unwrap_frame_with_prehashed_dict<'a>(
    blob: &'a [u8],
    expected_kind: PayloadKind,
    dict: Option<PrehashedDict<'_>>,
    limits: DecodeLimits,
) -> Result<alloc::borrow::Cow<'a, [u8]>, HyperCompError> {
    unwrap_frame_inner(
        blob,
        expected_kind,
        dict.map(|d| d.bytes()),
        dict.map(|d| d.id()),
        limits,
    )
}

/// Decompresses a domain-separated Raw Zstd fallback frame without cloning the payload (`N-2`).
/// Caller reads payload bytes starting at `&raw[1..]` (byte 0 is the validated `version|kind` tag).
fn decompress_raw_zstd_fallback_tagged(
    blob: &[u8],
    expected_kind: PayloadKind,
    limits: DecodeLimits,
) -> Result<Vec<u8>, HyperCompError> {
    #[cfg(feature = "zstd-nostd")]
    {
        let raw = decompress_zstd_nostd(blob, None, limits)?;
        if raw.is_empty() {
            return Err(HyperCompError::UnexpectedEof);
        }
        parse_raw_fallback_tag(raw[0], expected_kind)?;
        Ok(raw)
    }
    #[cfg(not(feature = "zstd-nostd"))]
    {
        let _ = (blob, expected_kind, limits);
        Err(HyperCompError::UnsupportedEntropyCodec(
            EntropyCodec::Zstd as u8,
        ))
    }
}

/// Decompresses a full framed `StateTransitions` blob (`Vec<StateDiff>`).
/// Transparently decodes both HyperComp `"AS"` frames and domain-separated Raw Zstd fallback frames.
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
    if is_raw_zstd_fallback(blob) {
        let raw = decompress_raw_zstd_fallback_tagged(blob, PayloadKind::StateTransitions, limits)?;
        return StateDiff::from_raw_bytes(&raw[1..], limits);
    }
    let pre = unwrap_frame(blob, PayloadKind::StateTransitions, dict, limits)?;
    decode_state_transitions_raw(&pre, limits)
}

/// Decompresses a full framed `StateUpdates` blob (`Vec<ContractDiff>`).
/// Transparently decodes both HyperComp `"AS"` frames and domain-separated Raw Zstd fallback frames.
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
    if is_raw_zstd_fallback(blob) {
        let raw = decompress_raw_zstd_fallback_tagged(blob, PayloadKind::StateUpdates, limits)?;
        return ContractDiff::from_raw_bytes(&raw[1..], limits);
    }
    let pre = unwrap_frame(blob, PayloadKind::StateUpdates, dict, limits)?;
    decode_state_updates_raw(&pre, limits)
}

/// Decompresses a full framed `StateUpdates` blob using a [`PrehashedDict`] (`N-5`).
pub fn decompress_state_updates_with_prehashed_dict(
    blob: &[u8],
    dict: Option<PrehashedDict<'_>>,
    limits: DecodeLimits,
) -> Result<Vec<ContractDiff>, HyperCompError> {
    if is_raw_zstd_fallback(blob) {
        let raw = decompress_raw_zstd_fallback_tagged(blob, PayloadKind::StateUpdates, limits)?;
        return ContractDiff::from_raw_bytes(&raw[1..], limits);
    }
    let pre = unwrap_frame_with_prehashed_dict(blob, PayloadKind::StateUpdates, dict, limits)?;
    decode_state_updates_raw(&pre, limits)
}

/// Decompresses a full framed `StateDeltas` blob (`Vec<ContractDelta>`).
/// Transparently decodes both HyperComp `"AS"` frames and domain-separated Raw Zstd fallback frames.
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
    if is_raw_zstd_fallback(blob) {
        let raw = decompress_raw_zstd_fallback_tagged(blob, PayloadKind::StateDeltas, limits)?;
        return ContractDelta::from_raw_bytes(&raw[1..], limits);
    }
    let pre = unwrap_frame(blob, PayloadKind::StateDeltas, dict, limits)?;
    decode_state_deltas_raw(&pre, limits)
}

/// Decompresses a full framed `StateDeltas` blob using a [`PrehashedDict`] (`N-5`).
pub fn decompress_state_deltas_with_prehashed_dict(
    blob: &[u8],
    dict: Option<PrehashedDict<'_>>,
    limits: DecodeLimits,
) -> Result<Vec<ContractDelta>, HyperCompError> {
    if is_raw_zstd_fallback(blob) {
        let raw = decompress_raw_zstd_fallback_tagged(blob, PayloadKind::StateDeltas, limits)?;
        return ContractDelta::from_raw_bytes(&raw[1..], limits);
    }
    let pre = unwrap_frame_with_prehashed_dict(blob, PayloadKind::StateDeltas, dict, limits)?;
    decode_state_deltas_raw(&pre, limits)
}

/// Decompresses a full framed `StarknetUpdates` blob (`Vec<StarknetContractDiff>`).
pub fn decompress_starknet_updates(
    blob: &[u8],
    dict: Option<&[u8]>,
) -> Result<Vec<StarknetContractDiff>, HyperCompError> {
    decompress_starknet_updates_with_limits(blob, dict, DecodeLimits::default())
}

/// Decompresses a full framed `StarknetUpdates` blob with custom safety limits.
pub fn decompress_starknet_updates_with_limits(
    blob: &[u8],
    dict: Option<&[u8]>,
    limits: DecodeLimits,
) -> Result<Vec<StarknetContractDiff>, HyperCompError> {
    if is_raw_zstd_fallback(blob) {
        let raw = decompress_raw_zstd_fallback_tagged(blob, PayloadKind::StarknetUpdates, limits)?;
        return StarknetContractDiff::from_raw_bytes(&raw[1..], limits);
    }
    let pre = unwrap_frame(blob, PayloadKind::StarknetUpdates, dict, limits)?;
    decode_starknet_updates_raw(&pre, limits)
}

/// Decompresses a full framed `StarknetDeltas` blob (`Vec<StarknetContractDelta>`).
pub fn decompress_starknet_deltas(
    blob: &[u8],
    dict: Option<&[u8]>,
) -> Result<Vec<StarknetContractDelta>, HyperCompError> {
    decompress_starknet_deltas_with_limits(blob, dict, DecodeLimits::default())
}

/// Decompresses a full framed `StarknetDeltas` blob with custom safety limits.
pub fn decompress_starknet_deltas_with_limits(
    blob: &[u8],
    dict: Option<&[u8]>,
    limits: DecodeLimits,
) -> Result<Vec<StarknetContractDelta>, HyperCompError> {
    if is_raw_zstd_fallback(blob) {
        let raw = decompress_raw_zstd_fallback_tagged(blob, PayloadKind::StarknetDeltas, limits)?;
        return StarknetContractDelta::from_raw_bytes(&raw[1..], limits);
    }
    let pre = unwrap_frame(blob, PayloadKind::StarknetDeltas, dict, limits)?;
    decode_starknet_deltas_raw(&pre, limits)
}

// ---------------------------------------------------------------------------
// CRYPTOGRAPHIC SHA-256 COMMITMENTS FOR zkVM GUEST JOURNALS (C-2)
// ---------------------------------------------------------------------------

/// Computes a collision-resistant, domain-separated, length-prefixed SHA-256 commitment
/// covering EVERY field of `Vec<ContractDelta>` (contract count, addresses, nonces, slot counts,
/// slots, `DeltaOp` tags, full 32B operand values, and `XorShifted` shifts/masks).
pub fn commit_state_deltas_sha256(contracts: &[ContractDelta]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"HYPERCOMP-DELTAS-COMMIT-V3:");
    h.update((contracts.len() as u64).to_be_bytes());
    for c in contracts {
        h.update(c.address);
        match c.nonce {
            Some(n) => {
                h.update([1u8]);
                h.update(n.to_be_bytes());
            }
            None => h.update([0u8]),
        }
        h.update((c.storage_deltas.len() as u64).to_be_bytes());
        for d in &c.storage_deltas {
            h.update(d.slot);
            match d.op {
                DeltaOp::NoChange => h.update([0u8]),
                DeltaOp::SetNew(v) => {
                    h.update([1u8]);
                    h.update(v.0);
                }
                DeltaOp::Add(v) => {
                    h.update([2u8]);
                    h.update(v.0);
                }
                DeltaOp::Sub(v) => {
                    h.update([3u8]);
                    h.update(v.0);
                }
                DeltaOp::XorShifted { shift, mask } => {
                    h.update([4u8, shift]);
                    h.update(mask.0);
                }
            }
        }
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes a collision-resistant, domain-separated, length-prefixed SHA-256 commitment
/// covering EVERY field of `Vec<ContractDiff>`.
pub fn commit_state_updates_sha256(contracts: &[ContractDiff]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"HYPERCOMP-UPDATES-COMMIT-V3:");
    h.update((contracts.len() as u64).to_be_bytes());
    for c in contracts {
        h.update(c.address);
        match c.nonce {
            Some(n) => {
                h.update([1u8]);
                h.update(n.to_be_bytes());
            }
            None => h.update([0u8]),
        }
        h.update((c.storage_updates.len() as u64).to_be_bytes());
        for u in &c.storage_updates {
            h.update(u.slot);
            h.update(u.new_val.0);
        }
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
