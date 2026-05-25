//! Example: consume a &[u8] digest, unpack to u32s, and feed into an xorpl circuit.
//!
//! Expected production callsite pattern:
//!   1. Compute SHA-256 of the raw event data outside the circuit.
//!   2. Unpack the 32-byte digest to 8 little-endian u32s.
//!   3. Pass each u32 as one circuit input (INGEST wire).
//!   4. Receive a single u32 checksum.
//!
//! `sha256_qr` takes exactly 8 × u32 = 32 bytes, matching a SHA-256 digest.

include!("fixtures/sha256_qr.rs");

/// Unpack a 32-byte digest into 8 little-endian u32s and checksum them.
///
/// Panics if `data.len() != 32`.
fn checksum_bytes(data: &[u8]) -> u32 {
    assert_eq!(data.len(), 32, "sha256_qr takes 8 × u32 = 32 bytes");
    let words: [u32; 8] = std::array::from_fn(|i| {
        u32::from_le_bytes(data[i * 4..][..4].try_into().unwrap())
    });
    sha256_qr(words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7])
}

#[test]
fn roundtrip_matches_direct_call() {
    let cases: &[[u32; 8]] = &[
        [0x0000_0000; 8],
        [0xFFFF_FFFF; 8],
        [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,
         0xDEAD_BEEF, 0xCAFE_BABE, 0x1234_5678, 0x8765_4321],
    ];
    for &w in cases {
        let mut bytes = [0u8; 32];
        for (i, word) in w.iter().enumerate() {
            bytes[i * 4..][..4].copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            checksum_bytes(&bytes),
            sha256_qr(w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]),
            "byte ingestion must match direct call for {w:08x?}",
        );
    }
}

#[test]
fn sha256_hello_digest() {
    // SHA-256("hello") — hard-coded, no external crate needed.
    // In production: sha256(event_bytes) runs before calling checksum_bytes.
    let digest: [u8; 32] = [
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
        0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
        0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
        0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
    ];

    let result = checksum_bytes(&digest);

    let words: [u32; 8] = std::array::from_fn(|i| {
        u32::from_le_bytes(digest[i * 4..][..4].try_into().unwrap())
    });
    assert_eq!(result, sha256_qr(
        words[0], words[1], words[2], words[3],
        words[4], words[5], words[6], words[7],
    ));
}
