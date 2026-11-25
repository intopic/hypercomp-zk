//! Adversarial, security, canonicality, 32-bit safety, and zero-panic fuzz tests
//! for the Open-Source `#![no_std]` `hypercomp-decoder` crate.

use hypercomp_decoder::dict::{
    dict_decode_fixed, slot_decode_column, DICT_MODE_HYBRID_ESCAPE, DICT_MODE_PURE, DICT_MODE_RLE,
    SLOT_MODE_BIMODAL_POLY,
};
use hypercomp_decoder::rhind::{
    TAG_MAX, TAG_RAW_BASE, TAG_RHIND_BASE, TAG_SMALL_BASE, TAG_ZERO,
};
use hypercomp_decoder::{
    alsamawal_poly_decode, commit_state_deltas_sha256, compute_dict_id, decode_state_deltas_raw,
    decode_state_transitions_raw, decode_state_updates_raw, decode_varint_u128, decode_varint_u32,
    decode_varint_u64, decompress_starknet_deltas_with_limits,
    decompress_starknet_updates_with_limits, decompress_state_deltas_with_limits,
    decompress_state_transitions, decompress_state_transitions_with_limits,
    decompress_state_updates_with_limits, is_raw_zstd_fallback, parse_raw_fallback_tag,
    raw_fallback_tag, rhind_decode_u256, ContractDelta, ContractDiff, DecodeLimits, DeltaOp,
    HyperCompError, PayloadKind, PrehashedDict, StateDiff, StorageDelta, StorageUpdate,
    WireHeader, FORMAT_VERSION, MAGIC, POW10, U256, ZSTD_MAGIC,
};

#[test]
fn test_varint_rejects_high_bit_truncation_and_overlong() {
    // u32: 5th byte > 0x0F must overflow, never silently truncate!
    assert_eq!(
        decode_varint_u32(&[0x80, 0x80, 0x80, 0x80, 0x10], &mut 0),
        Err(HyperCompError::VarintOverflow)
    );
    assert_eq!(
        decode_varint_u32(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F], &mut 0),
        Ok(u32::MAX)
    );
    // Overlong u32 (non-canonical)
    assert_eq!(
        decode_varint_u32(&[0x80, 0x00], &mut 0),
        Err(HyperCompError::NonCanonicalEncoding)
    );

    // u64: 10th byte > 0x01 must overflow! (Caught real bug in v1)
    assert_eq!(
        decode_varint_u64(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02], &mut 0),
        Err(HyperCompError::VarintOverflow)
    );
    assert_eq!(
        decode_varint_u64(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01], &mut 0),
        Ok(u64::MAX)
    );
    assert_eq!(
        decode_varint_u64(&[0x81, 0x00], &mut 0),
        Err(HyperCompError::NonCanonicalEncoding)
    );

    // u128: 19th byte > 0x03 must overflow! (Caught real bug in v1)
    let mut overflow_u128 = [0x80u8; 19];
    overflow_u128[18] = 0x04;
    assert_eq!(
        decode_varint_u128(&overflow_u128, &mut 0),
        Err(HyperCompError::VarintOverflow)
    );
    let mut max_u128 = [0xFFu8; 19];
    max_u128[18] = 0x03;
    assert_eq!(decode_varint_u128(&max_u128, &mut 0), Ok(u128::MAX));
}

#[test]
fn test_alsamawal_poly_never_panics_on_i128_overflow() {
    // Regression test for v1 panic: `let x = pred + residual;` overflowed i128 when z = u128::MAX!
    // Sequence of length 3: [u64::MAX, u64::MAX, z=u128::MAX - 1 (residual = +i128::MAX)]
    let mut payload = Vec::new();
    payload.push(3); // count = 3
    // x[0] = u64::MAX -> zigzag(u64::MAX) = u64::MAX * 2
    let mut z0 = (u64::MAX as u128) << 1;
    while z0 >= 0x80 {
        payload.push(((z0 as u8) & 0x7F) | 0x80);
        z0 >>= 7;
    }
    payload.push(z0 as u8);
    payload.push(0); // x[1] residual = 0 -> pred = u64::MAX -> x[1] = u64::MAX
    // x[2]: z = u128::MAX - 1 -> residual = i128::MAX -> pred + residual overflows i128!
    let mut z2 = u128::MAX - 1;
    while z2 >= 0x80 {
        payload.push(((z2 as u8) & 0x7F) | 0x80);
        z2 >>= 7;
    }
    payload.push(z2 as u8);

    let res = alsamawal_poly_decode(&payload, &mut 0, 100);
    assert_eq!(res, Err(HyperCompError::VarintOverflow));
}

#[test]
fn test_pow10_table_exactness_and_overflow_bounds() {
    assert_eq!(U256::from_limbs(POW10[0]), U256::from_u64(1));
    assert_eq!(
        U256::from_limbs(POW10[18]),
        U256::from_u128(1_000_000_000_000_000_000)
    );
    assert_eq!(
        U256::from_limbs(POW10[38]),
        U256::from_u128(10u128.pow(38))
    );
    // 1 * 10^77 fits in U256; 2 * 10^77 overflows U256!
    assert!(U256::mul_u64_pow10_checked(1, 77).is_some());
    assert!(U256::mul_u64_pow10_checked(2, 77).is_none());
    assert!(U256::mul_u64_pow10_checked(1, 78).is_none());
    assert!(U256::mul_u64_pow10_checked(1, 255).is_none());
}

#[test]
fn test_rhind_strict_canonicality_and_overflow_rejection() {
    // Valid 0, MAX, small 1..=16
    assert_eq!(rhind_decode_u256(&[TAG_ZERO], &mut 0), Ok(U256::ZERO));
    assert_eq!(rhind_decode_u256(&[TAG_MAX], &mut 0), Ok(U256::MAX));
    assert_eq!(
        rhind_decode_u256(&[TAG_SMALL_BASE], &mut 0),
        Ok(U256::from_u64(1))
    );

    // Reject exp = 255 (v1 silent overflow + cycle DoS!)
    assert_eq!(
        rhind_decode_u256(&[TAG_RHIND_BASE, 255, 1], &mut 0),
        Err(HyperCompError::InvalidExponent(255))
    );
    // Reject exp = 0
    assert_eq!(
        rhind_decode_u256(&[TAG_RHIND_BASE, 0, 1], &mut 0),
        Err(HyperCompError::InvalidExponent(0))
    );
    // Reject U256 overflow: 2 * 10^77 > 2^256 - 1
    assert_eq!(
        rhind_decode_u256(&[TAG_RHIND_BASE, 77, 2], &mut 0),
        Err(HyperCompError::U256Overflow)
    );
    // Reject non-canonical mantissa divisible by 10 (10 * 10^17 instead of 1 * 10^18)
    assert_eq!(
        rhind_decode_u256(&[TAG_RHIND_BASE, 17, 10], &mut 0),
        Err(HyperCompError::NonCanonicalEncoding)
    );
    // Reject leading zero byte in Rhind mantissa
    assert_eq!(
        rhind_decode_u256(&[TAG_RHIND_BASE + 1, 18, 0x00, 0x01], &mut 0),
        Err(HyperCompError::NonCanonicalEncoding)
    );
    // Reject non-optimal Rhind: 1 * 10^2 = 100 (Raw takes 2B, Rhind takes 3B)
    assert_eq!(
        rhind_decode_u256(&[TAG_RHIND_BASE, 2, 1], &mut 0),
        Err(HyperCompError::NonCanonicalEncoding)
    );
    // Reject Raw duplicating small literal (value 5 encoded with TAG_RAW_BASE)
    assert_eq!(
        rhind_decode_u256(&[TAG_RAW_BASE, 5], &mut 0),
        Err(HyperCompError::NonCanonicalEncoding)
    );
    // Reject Raw with leading zero byte
    assert_eq!(
        rhind_decode_u256(&[TAG_RAW_BASE + 1, 0x00, 0x20], &mut 0),
        Err(HyperCompError::NonCanonicalEncoding)
    );
    // Reject Raw duplicating U256::MAX
    let mut raw_max = vec![TAG_RAW_BASE + 31];
    raw_max.extend_from_slice(&[0xFF; 32]);
    assert_eq!(
        rhind_decode_u256(&raw_max, &mut 0),
        Err(HyperCompError::NonCanonicalEncoding)
    );
    // Reject Raw duplicating 1 ETH (which has strictly shorter Rhind [0x32, 18, 1])
    let eth = U256::from_u128(1_000_000_000_000_000_000);
    let eth_be = eth.minimal_be_slice();
    let mut raw_eth = vec![TAG_RAW_BASE + (eth_be.len() as u8 - 1)];
    raw_eth.extend_from_slice(eth_be);
    assert_eq!(
        rhind_decode_u256(&raw_eth, &mut 0),
        Err(HyperCompError::NonCanonicalEncoding)
    );
}

#[test]
fn test_dict_32bit_overflow_and_malformed_modes() {
    // Huge vlen that would overflow byte_len = vlen * 32 on 32-bit targets
    let huge_vlen = [DICT_MODE_PURE, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
    assert_eq!(
        dict_decode_fixed::<32>(&huge_vlen, &mut 0, 1, u32::MAX),
        Err(HyperCompError::LimitExceeded)
    );

    // RLE with run_len = 0 is non-canonical
    let mut bad_rle = vec![DICT_MODE_RLE, 1];
    bad_rle.extend_from_slice(&[7u8; 20]);
    bad_rle.push(1); // num_runs = 1
    bad_rle.push(0); // idx = 0
    bad_rle.push(0); // run_len = 0!
    assert_eq!(
        dict_decode_fixed::<20>(&bad_rle, &mut 0, 1, 100),
        Err(HyperCompError::NonCanonicalEncoding)
    );

    // Hybrid escape referencing missing literal
    let bad_hybrid = [DICT_MODE_HYBRID_ESCAPE, 0, 0, 0]; // vlen=0, lit_len=0, idx=0 (escape!)
    assert_eq!(
        dict_decode_fixed::<20>(&bad_hybrid, &mut 0, 1, 100),
        Err(HyperCompError::LengthMismatch)
    );

    // Bimodal slot bitmap with non-zero unused padding bits (count = 3 -> bits 3..7 must be 0)
    let bad_bitmap = [SLOT_MODE_BIMODAL_POLY, 0b1000_0000];
    assert_eq!(
        slot_decode_column(&bad_bitmap, &mut 0, 3, 100),
        Err(HyperCompError::NonCanonicalEncoding)
    );
}

#[test]
fn test_header_validation_and_trailing_bytes() {
    // Bad magic
    assert_eq!(
        WireHeader::decode(b"XX\x02\x00", &mut 0),
        Err(HyperCompError::InvalidMagic)
    );
    // Unsupported version
    assert_eq!(
        WireHeader::decode(&[MAGIC[0], MAGIC[1], 99, 0], &mut 0),
        Err(HyperCompError::UnsupportedVersion(99))
    );
    // Reserved flags set (bits 6..7)
    assert_eq!(
        WireHeader::decode(&[MAGIC[0], MAGIC[1], FORMAT_VERSION, 0x80], &mut 0),
        Err(HyperCompError::InvalidFlags(0x80))
    );
    // Payload kind mismatch
    let valid_empty_updates = [MAGIC[0], MAGIC[1], FORMAT_VERSION, PayloadKind::StateUpdates as u8, 0];
    assert_eq!(
        decompress_state_transitions(&valid_empty_updates, None),
        Err(HyperCompError::PayloadKindMismatch {
            expected: PayloadKind::StateTransitions as u8,
            found: PayloadKind::StateUpdates as u8,
        })
    );
    // Trailing byte on valid empty transitions stream (`n = 0`, `addr_mode = EMPTY(0)`, plus extra `0xAA`)
    let trailing = [0u8, 0u8, 0xAA];
    assert_eq!(
        decode_state_transitions_raw(&trailing, DecodeLimits::default()),
        Err(HyperCompError::TrailingBytes(1))
    );
}

#[test]
fn test_adversarial_zero_panic_fuzz_10000_random_blobs() {
    let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let next_u64 = |s: &mut u64| -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    };

    let tight_limits = DecodeLimits {
        max_items: 4096,
        max_decompressed_bytes: 128 * 1024,
        max_output_bytes: 256 * 1024,
        max_window_bytes: 128 * 1024,
    };

    for case in 0..10_000usize {
        let len = (next_u64(&mut state) % 128) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (next_u64(&mut state) & 0xFF) as u8;
        }
        // Inject valid header prefixes across ALL 5 PayloadKinds (0..=4) and ZSTD_MAGIC (fixes L-3).
        if len >= 4 && (case % 3 == 0) {
            buf[0] = MAGIC[0];
            buf[1] = MAGIC[1];
            buf[2] = FORMAT_VERSION;
            buf[3] = ((case / 3) % 5) as u8; // EntropyCodec::None with kinds 0..=4
        } else if len >= 4 && (case % 3 == 1) {
            buf[0..4].copy_from_slice(&ZSTD_MAGIC);
        }

        // None of these calls may EVER panic!
        let _ = decode_state_transitions_raw(&buf, tight_limits);
        let _ = decode_state_updates_raw(&buf, tight_limits);
        let _ = decode_state_deltas_raw(&buf, tight_limits);
        let _ = StateDiff::from_raw_bytes(&buf, tight_limits);
        let _ = ContractDiff::from_raw_bytes(&buf, tight_limits);
        let _ = ContractDelta::from_raw_bytes(&buf, tight_limits);
        let _ = decompress_state_transitions_with_limits(&buf, None, tight_limits);
        let _ = decompress_state_updates_with_limits(&buf, None, tight_limits);
        let _ = decompress_state_deltas_with_limits(&buf, None, tight_limits);
        let _ = decompress_starknet_updates_with_limits(&buf, None, tight_limits);
        let _ = decompress_starknet_deltas_with_limits(&buf, None, tight_limits);
        let _ = rhind_decode_u256(&buf, &mut 0);
        let _ = alsamawal_poly_decode(&buf, &mut 0, 4096);
    }
}

#[test]
fn test_raw_fallback_canonicality_and_bounds() {
    assert!(is_raw_zstd_fallback(&ZSTD_MAGIC));
    assert!(!is_raw_zstd_fallback(&[MAGIC[0], MAGIC[1], FORMAT_VERSION, 0]));

    // Exact roundtrip of ContractDiff & ContractDelta canonical raw bytes
    let upd = vec![ContractDiff {
        address: [0x11; 20],
        nonce: Some(7),
        storage_updates: vec![StorageUpdate {
            slot: [0x22; 32],
            new_val: U256::from_u64(12345),
        }],
    }];
    let raw_u = ContractDiff::to_raw_bytes(&upd);
    assert_eq!(
        ContractDiff::from_raw_bytes(&raw_u, DecodeLimits::default()).unwrap(),
        upd
    );

    let del = vec![ContractDelta {
        address: [0x33; 20],
        nonce: None,
        storage_deltas: vec![
            StorageDelta {
                slot: [0x01; 32],
                op: DeltaOp::NoChange,
            },
            StorageDelta {
                slot: [0x02; 32],
                op: DeltaOp::SetNew(U256::ZERO),
            },
            StorageDelta {
                slot: [0x03; 32],
                op: DeltaOp::Add(U256::from_u128(10u128.pow(18))),
            },
            StorageDelta {
                slot: [0x04; 32],
                op: DeltaOp::Sub(U256::from_u64(99)),
            },
            StorageDelta {
                slot: [0x05; 32],
                op: DeltaOp::XorShifted {
                    shift: 4,
                    mask: U256::from_u64(0x1234),
                },
            },
        ],
    }];
    let raw_d = ContractDelta::to_raw_bytes(&del).unwrap();
    assert_eq!(
        ContractDelta::from_raw_bytes(&raw_d, DecodeLimits::default()).unwrap(),
        del
    );

    // Verify pure-SetNew 32B-hash ContractDelta::to_raw_bytes is bit-identical to ContractDiff::to_raw_bytes (0 B overhead!)
    let hash_val = U256([0xAB; 32]);
    let hash_upd = vec![ContractDiff {
        address: [0x16; 20],
        nonce: None,
        storage_updates: vec![StorageUpdate {
            slot: [0x01; 32],
            new_val: hash_val,
        }],
    }];
    let hash_del = vec![ContractDelta {
        address: [0x16; 20],
        nonce: None,
        storage_deltas: vec![StorageDelta {
            slot: [0x01; 32],
            op: DeltaOp::SetNew(hash_val),
        }],
    }];
    let raw_hash_del = ContractDelta::to_raw_bytes(&hash_del).unwrap();
    assert_eq!(raw_hash_del, ContractDiff::to_raw_bytes(&hash_upd));
    assert_eq!(
        ContractDelta::from_raw_bytes(&raw_hash_del, DecodeLimits::default()).unwrap(),
        hash_del
    );

    // Reject invalid packed op tag (> 0x81) in compact raw delta mode (flags = 0x80)
    let mut bad_tag = Vec::new();
    bad_tag.extend_from_slice(&[0x33; 20]);
    bad_tag.push(0x80); // compact mode, has_nonce = 0
    bad_tag.extend_from_slice(&1u32.to_be_bytes());
    bad_tag.extend_from_slice(&[0x01; 32]); // slot
    bad_tag.push(0x82); // invalid tag > 0x81!
    assert_eq!(
        ContractDelta::from_raw_bytes(&bad_tag, DecodeLimits::default()),
        Err(HyperCompError::InvalidTag(0x82))
    );

    // Reject leading zero byte in packed compact raw delta SetNew (tag 0x03 = SetNew len 2)
    let mut bad_leading_zero = Vec::new();
    bad_leading_zero.extend_from_slice(&[0x33; 20]);
    bad_leading_zero.push(0x80);
    bad_leading_zero.extend_from_slice(&1u32.to_be_bytes());
    bad_leading_zero.extend_from_slice(&[0x01; 32]);
    bad_leading_zero.push(0x03); // SetNew with len = 2
    bad_leading_zero.extend_from_slice(&[0x00, 0x05]); // non-minimal leading zero!
    assert_eq!(
        ContractDelta::from_raw_bytes(&bad_leading_zero, DecodeLimits::default()),
        Err(HyperCompError::NonCanonicalEncoding)
    );

    // Reject invalid has_nonce flag (> 1)
    let mut bad_nonce_flag = raw_u.clone();
    bad_nonce_flag[20] = 2;
    assert_eq!(
        ContractDiff::from_raw_bytes(&bad_nonce_flag, DecodeLimits::default()),
        Err(HyperCompError::InvalidTag(2))
    );

    // Reject slot count exceeding DecodeLimits
    let tight = DecodeLimits {
        max_items: 2,
        max_decompressed_bytes: 1024,
        max_output_bytes: 1024,
        max_window_bytes: 1024,
    };
    assert_eq!(
        ContractDelta::from_raw_bytes(&raw_d, tight),
        Err(HyperCompError::LimitExceeded)
    );
}

#[test]
fn test_audit_poc_regressions_h1_h2_h3_h4_m2_l2_c2() {
    // --- PoC-2 (H-1): 71-byte DICT_MODE_RLE OOM bomb must be rejected IMMEDIATELY without allocating! ---
    // 50_000 slots stays under `max_items = 100_000` so the remaining-byte RLE guard is specifically exercised.
    // varint(50_000): 50_000 = 0xC350 -> [0xD0, 0x86, 0x03]
    let mut rle_bomb = Vec::new();
    rle_bomb.push(1); // num_contracts = 1
    rle_bomb.extend_from_slice(&[0xAA; 20]); // address
    rle_bomb.push(0); // nonce bitmap = 0
    rle_bomb.extend_from_slice(&[0xD0, 0x86, 0x03]); // slot count = 50_000
    rle_bomb.push(0); // SLOT_MODE_DICT32
    rle_bomb.push(DICT_MODE_RLE);
    rle_bomb.push(1); // vlen = 1
    rle_bomb.extend_from_slice(&[0xBB; 32]); // 1 vocab entry
    rle_bomb.push(1); // num_runs = 1
    rle_bomb.push(0); // idx = 0
    rle_bomb.extend_from_slice(&[0xD0, 0x86, 0x03]); // run_len = 50_000
    assert_eq!(
        decode_state_deltas_raw(&rle_bomb, DecodeLimits::default()),
        Err(HyperCompError::UnexpectedEof)
    );
    assert_eq!(
        decode_state_updates_raw(&rle_bomb, DecodeLimits::zkvm()),
        Err(HyperCompError::UnexpectedEof)
    );

    // Same RLE bomb for StateTransitions (50_000 transitions)
    let mut trans_bomb = Vec::new();
    trans_bomb.extend_from_slice(&[0xD0, 0x86, 0x03]); // n = 50_000
    trans_bomb.push(DICT_MODE_RLE);
    trans_bomb.push(1); // vlen = 1
    trans_bomb.extend_from_slice(&[0xAA; 20]);
    trans_bomb.push(1);
    trans_bomb.push(0);
    trans_bomb.extend_from_slice(&[0xD0, 0x86, 0x03]);
    assert_eq!(
        decode_state_transitions_raw(&trans_bomb, DecodeLimits::zkvm()),
        Err(HyperCompError::UnexpectedEof)
    );

    // --- PoC-4 (H-2): XorShifted { shift: 0, mask: 0xAB00 } must be rejected as non-canonical ---
    let non_canon_xor = DeltaOp::XorShifted {
        shift: 0,
        mask: U256::from_u64(0xAB00),
    };
    assert_eq!(non_canon_xor.validate(), Err(HyperCompError::NonCanonicalEncoding));
    assert_eq!(
        non_canon_xor.apply(U256::ZERO),
        Err(HyperCompError::NonCanonicalEncoding)
    );

    // --- PoC-5 (H-4): Add(0), Sub(0), XorShifted{mask:0} must NEVER silently corrupt to_raw_bytes ---
    for bad_op in [
        DeltaOp::Add(U256::ZERO),
        DeltaOp::Sub(U256::ZERO),
        DeltaOp::XorShifted {
            shift: 0,
            mask: U256::ZERO,
        },
        DeltaOp::XorShifted {
            shift: 32,
            mask: U256::from_u64(1),
        },
    ] {
        assert!(bad_op.validate().is_err());
        let bad_batch = vec![ContractDelta {
            address: [0x01; 20],
            nonce: None,
            storage_deltas: vec![StorageDelta {
                slot: [0x01; 32],
                op: bad_op,
            }],
        }];
        assert!(ContractDelta::to_raw_bytes(&bad_batch).is_err());
    }

    // --- PoC-6 (H-3): dict_id is full 32-byte SHA-256 ---
    let d1 = compute_dict_id(b"dictionary-alpha");
    let d2 = compute_dict_id(b"dictionary-beta");
    assert_eq!(d1.len(), 32);
    assert_ne!(d1, d2);

    // --- M-2: Raw Zstd fallback domain tag enforces version & payload kind ---
    let tag_u = raw_fallback_tag(PayloadKind::StateUpdates);
    assert_eq!(parse_raw_fallback_tag(tag_u, PayloadKind::StateUpdates), Ok(()));
    assert_eq!(
        parse_raw_fallback_tag(tag_u, PayloadKind::StateDeltas),
        Err(HyperCompError::PayloadKindMismatch {
            expected: PayloadKind::StateDeltas as u8,
            found: PayloadKind::StateUpdates as u8,
        })
    );
    assert_eq!(
        parse_raw_fallback_tag(0x91, PayloadKind::StateUpdates),
        Err(HyperCompError::UnsupportedVersion(9))
    );

    // --- L-2: Unsorted or duplicate (address, slot) rejected ---
    let dup_contracts = vec![
        ContractDiff {
            address: [0x22; 20],
            nonce: None,
            storage_updates: vec![],
        },
        ContractDiff {
            address: [0x11; 20], // out of order!
            nonce: None,
            storage_updates: vec![],
        },
    ];
    let raw_dup_c = ContractDiff::to_raw_bytes(&dup_contracts);
    assert_eq!(
        ContractDiff::from_raw_bytes(&raw_dup_c, DecodeLimits::default()),
        Err(HyperCompError::NonCanonicalEncoding)
    );

    let dup_slots = vec![ContractDiff {
        address: [0x11; 20],
        nonce: None,
        storage_updates: vec![
            StorageUpdate {
                slot: [0x05; 32],
                new_val: U256::from_u64(1),
            },
            StorageUpdate {
                slot: [0x05; 32], // duplicate slot!
                new_val: U256::from_u64(2),
            },
        ],
    }];
    let raw_dup_s = ContractDiff::to_raw_bytes(&dup_slots);
    assert_eq!(
        ContractDiff::from_raw_bytes(&raw_dup_s, DecodeLimits::default()),
        Err(HyperCompError::NonCanonicalEncoding)
    );

    // --- C-2: SHA-256 zkVM commitment binds EVERY field (value, nonce, shift/mask) ---
    let base = vec![ContractDelta {
        address: [0x11; 20],
        nonce: Some(10),
        storage_deltas: vec![StorageDelta {
            slot: [0x01; 32],
            op: DeltaOp::Add(U256::from_u64(100)),
        }],
    }];
    let mut diff_val = base.clone();
    diff_val[0].storage_deltas[0].op = DeltaOp::Add(U256::from_u64(101));
    let mut diff_nonce = base.clone();
    diff_nonce[0].nonce = Some(11);
    assert_ne!(
        commit_state_deltas_sha256(&base),
        commit_state_deltas_sha256(&diff_val),
        "SHA-256 commitment MUST bind DeltaOp values!"
    );
    assert_ne!(
        commit_state_deltas_sha256(&base),
        commit_state_deltas_sha256(&diff_nonce),
        "SHA-256 commitment MUST bind contract nonces!"
    );
}

#[test]
fn test_round2_audit_regressions_n1_n2_n4_n5_c2r() {
    // --- N-1: Single canonical consensus profile everywhere (no encoder/node/zkVM divergence) ---
    assert_eq!(DecodeLimits::default(), DecodeLimits::CONSENSUS);
    assert_eq!(DecodeLimits::zkvm(), DecodeLimits::CONSENSUS);

    // --- N-2: Calibrated 144 B/slot & 100k-item cap blocks PoC R-7 (240k-slot heap bomb) ---
    assert_eq!(
        DecodeLimits::CONSENSUS.check_contract_batch(1, 240_000, 20),
        Err(HyperCompError::LimitExceeded)
    );
    assert!(DecodeLimits::CONSENSUS
        .check_contract_batch(1, 100_000, 20)
        .is_ok());

    // --- N-2 (PoC R-3): Zstd frame WITHOUT Frame_Content_Size (fcs_flag=0, single_segment=0)
    // must be rejected BEFORE any decompression allocation! ---
    // Magic (4B) + FHD=0x04 (checksum=1, fcs=0, single_seg=0) + window_desc=0x00 + empty last block
    let no_fcs_zstd = [
        ZSTD_MAGIC[0],
        ZSTD_MAGIC[1],
        ZSTD_MAGIC[2],
        ZSTD_MAGIC[3],
        0x04, // checksum bit set, but NO Frame_Content_Size!
        0x00,
        0x01,
        0x00,
        0x00,
    ];
    let mut hc_no_fcs = vec![
        MAGIC[0],
        MAGIC[1],
        FORMAT_VERSION,
        (PayloadKind::StateDeltas as u8) | (1u8 << 3), // EntropyCodec::Zstd
    ];
    hc_no_fcs.extend_from_slice(&no_fcs_zstd);
    assert_eq!(
        decompress_state_deltas_with_limits(&hc_no_fcs, None, DecodeLimits::CONSENSUS),
        Err(HyperCompError::EntropyDecodeFailed)
    );
    assert_eq!(
        decompress_state_deltas_with_limits(&no_fcs_zstd, None, DecodeLimits::CONSENSUS),
        Err(HyperCompError::EntropyDecodeFailed)
    );

    // --- N-4: Wire format version bumped to v3; legacy v2 headers & fallback tags rejected ---
    assert_eq!(FORMAT_VERSION, 3);
    assert_eq!(
        WireHeader::decode(&[MAGIC[0], MAGIC[1], 2, 0], &mut 0),
        Err(HyperCompError::UnsupportedVersion(2))
    );
    assert_eq!(
        parse_raw_fallback_tag((2u8 << 4) | (PayloadKind::StateDeltas as u8), PayloadKind::StateDeltas),
        Err(HyperCompError::UnsupportedVersion(2))
    );

    // --- N-5: PrehashedDict computes SHA-256 once and matches compute_dict_id ---
    let raw_dict = b"prehashed-zkvm-dictionary-bytes";
    let pre = PrehashedDict::new(raw_dict);
    assert_eq!(pre.bytes(), raw_dict);
    assert_eq!(pre.id(), compute_dict_id(raw_dict));

    // --- C-2r: Error classification distinguishes prover witness faults from blob defects ---
    assert!(HyperCompError::MissingDictionary([0u8; 32]).is_prover_witness_error());
    assert!(HyperCompError::DictionaryIdMismatch {
        expected: [1u8; 32],
        found: [2u8; 32],
    }
    .is_prover_witness_error());
    assert!(!HyperCompError::LimitExceeded.is_prover_witness_error());
    assert!(!HyperCompError::EntropyDecodeFailed.is_prover_witness_error());
    assert!(!HyperCompError::InvalidMagic.is_prover_witness_error());
    assert_ne!(HyperCompError::LimitExceeded.code(), 0);
    assert_ne!(HyperCompError::EntropyDecodeFailed.code(), 0);
}
