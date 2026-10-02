//! F03-AF-22: test malformed CBOR and COSE inputs.
//! Use fixed inputs of a few KiB with limited nesting.
//! These cases test rejection and panic handling, not all possible inputs.

use attestation_verify::{verify_attestation, ExpectedPcrs};

/// Generate the same test bytes on each run without an external dependency.
fn lcg_byte(state: &mut u64) -> u8 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*state >> 33) as u8
}

/// Build fixed cases for empty data, invalid types, truncation, and nesting.
fn malformed_corpus() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();

    // empty + every single byte
    out.push(Vec::new());
    for b in 0u16..=255 {
        out.push(vec![b as u8]);
    }

    // deterministic garbage of assorted lengths
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for len in [2usize, 3, 7, 16, 31, 64, 127, 256, 1024, 4096] {
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(lcg_byte(&mut state));
        }
        out.push(v);
    }

    // well-formed CBOR, wrong shape (must be rejected as not-a-COSE-Sign1)
    out.push(vec![0x00]); // unsigned 0
    out.push(vec![0xf6]); // null
    out.push(vec![0xf5]); // true
    out.push(vec![0x60]); // empty text string
    out.push(vec![0x40]); // empty byte string
    out.push(vec![0x80]); // empty array (COSE needs exactly 4 items)
    out.push(vec![0xa0]); // empty map
    out.push(vec![0x83, 0x00, 0x00, 0x00]); // 3-item array (COSE needs 4)
    out.push(vec![0x85, 0x00, 0x00, 0x00, 0x00, 0x00]); // 5-item array
    out.push(vec![0xc1, 0x00]); // wrong CBOR tag (1) instead of 18
    out.push(vec![0xd2, 0x80]); // tag 18 wrapping an empty array (not 4 items)

    // Claim up to 4 KiB without a body to test truncated length headers.
    out.push(vec![0x5a, 0x00, 0x00, 0x10, 0x00]); // byte string, len 4096, empty body
    out.push(vec![0x7a, 0x00, 0x00, 0x10, 0x00]); // text string, len 4096, empty body
    out.push(vec![0x9a, 0x00, 0x00, 0x10, 0x00]); // array, 4096 items, none present
    out.push(vec![0xba, 0x00, 0x00, 0x10, 0x00]); // map, 4096 pairs, none present

    // Use nested arrays to test recursive decoding with limited depth.
    for depth in [16usize, 128] {
        let mut v = vec![0x81u8; depth]; // `depth` nested 1-element arrays
        v.push(0x00); // innermost element = integer 0
        out.push(v);
    }

    out
}

/// Reject each malformed input without a panic.
/// No input has a valid Nitro certificate chain and signature.
#[test]
fn af22_real_verifier_rejects_every_malformed_input_gracefully() {
    let pcrs = ExpectedPcrs::zero();
    let nonce = [0u8; 32];

    for (i, input) in malformed_corpus().iter().enumerate() {
        // Test with and without an expected nonce.
        let r1 = verify_attestation(input, &pcrs, None);
        assert!(
            r1.is_err(),
            "corpus[{i}] ({} bytes) unexpectedly verified (nonce=None)",
            input.len()
        );
        let r2 = verify_attestation(input, &pcrs, Some(&nonce));
        assert!(
            r2.is_err(),
            "corpus[{i}] ({} bytes) unexpectedly verified (nonce=Some)",
            input.len()
        );
    }
}

/// Verify the valid mock document.
/// Reject truncated documents.
/// Mutated inputs can pass, but must not cause a panic.
#[cfg(feature = "mock")]
mod mock_path {
    use super::*;
    use attestation_verify::{build_mock_document, verify_mock_attestation};

    #[test]
    fn af22_mock_control_verifies_and_corruptions_are_bounded() {
        let nonce = [0x11u8; 32];
        let pubkey = [0x22u8; 32];
        let pcrs = ExpectedPcrs::zero();

        let doc = build_mock_document(&nonce, Some(&pubkey), None).expect("valid mock document");

        // Control: an untouched valid document verifies against its nonce.
        assert!(
            verify_mock_attestation(&doc, &pcrs, Some(&nonce)).is_ok(),
            "valid mock control failed to verify"
        );

        // Every proper prefix breaks the definite-length CBOR structure → Err.
        for cut in 0..doc.len() {
            let r = verify_mock_attestation(&doc[..cut], &pcrs, Some(&nonce));
            assert!(
                r.is_err(),
                "truncation to {cut} bytes unexpectedly verified"
            );
        }

        // Single-byte mutations: must not panic (result intentionally ignored).
        for i in 0..doc.len() {
            let mut m = doc.clone();
            m[i] ^= 0xff;
            let _ = verify_mock_attestation(&m, &pcrs, Some(&nonce));
        }

        // The shared malformed corpus must also be handled without panicking.
        for input in malformed_corpus() {
            let _ = verify_mock_attestation(&input, &pcrs, Some(&nonce));
            let _ = verify_mock_attestation(&input, &pcrs, None);
        }
    }
}
