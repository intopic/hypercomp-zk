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
    alsamawal_poly_decode, decode_state_deltas_raw, decode_state_transitions_raw,
    decode_state_updates_raw, decode_varint_u128, decode_varint_u32, decode_varint_u64,
    decompress_state_deltas, decompress_state_transitions, decompress_state_updates,
    rhind_decode_u256, DecodeLimits, HyperCompError, PayloadKind, WireHeader, FORMAT_VERSION,
    MAGIC, POW10, U256,
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
    };

    for case in 0..10_000usize {
        let len = (next_u64(&mut state) % 128) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (next_u64(&mut state) & 0xFF) as u8;
        }
        // Half the time inject a valid header prefix to stress deeper decoder paths!
        if len >= 4 && (case % 2 == 0) {
            buf[0] = MAGIC[0];
            buf[1] = MAGIC[1];
            buf[2] = FORMAT_VERSION;
            buf[3] = (case % 3) as u8; // EntropyCodec::None with kinds 0, 1, 2
        }

        // None of these calls may EVER panic!
        let _ = decode_state_transitions_raw(&buf, tight_limits);
        let _ = decode_state_updates_raw(&buf, tight_limits);
        let _ = decode_state_deltas_raw(&buf, tight_limits);
        let _ = decompress_state_transitions(&buf, None);
        let _ = decompress_state_updates(&buf, None);
        let _ = decompress_state_deltas(&buf, None);
        let _ = rhind_decode_u256(&buf, &mut 0);
        let _ = alsamawal_poly_decode(&buf, &mut 0, 4096);
    }
}
