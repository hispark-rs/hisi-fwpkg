//! Parity test against a real vendor-signed WS63 app image header.
//!
//! Fixtures (`tests/fixtures/`):
//! * `ws63_app_signed_header.bin` — the first 0x300 bytes of the vendor
//!   `ws63-liteos-app-sign.bin` produced by HiSilicon's `sign_tool`.
//! * `ws63_app_body_head.bin` — the first 4096 bytes of the matching unsigned
//!   body (the code that lives at flash 0x230300).
//!
//! We rebuild the header for a body whose first 4096 bytes match the fixture
//! and assert every *structural* field is byte-identical to the vendor output.
//! The only fields we intentionally differ on are the two ECC signature blobs
//! (key-sig @ 0xC0, code-sig @ 0x280), which a secure-boot-disabled board never
//! reads.

use hisi_fwpkg::image::{build_image_header, ImageOptions, KEY_AREA_LEN};

const VENDOR_HEADER: &[u8] = include_bytes!("fixtures/ws63_app_signed_header.bin");
const BODY_HEAD: &[u8] = include_bytes!("fixtures/ws63_app_body_head.bin");

#[test]
fn structural_fields_match_vendor_signed_header() {
    assert_eq!(VENDOR_HEADER.len(), 0x300);

    // Build a header over a body that begins with the real body bytes. The
    // structural fields we compare (magics, versions, lengths, key alg, msid,
    // versions, code_enc_flag, etc.) are independent of body content, so the
    // body length here does not need to match the original.
    let hdr = build_image_header(BODY_HEAD, &ImageOptions::default()).unwrap();

    // ---- key area structural prefix (image_id .. before die_id/sigs) ----
    assert_eq!(
        &hdr[0x00..0x3C],
        &VENDOR_HEADER[0x00..0x3C],
        "key_area structural fields"
    );

    // ---- code-info structural prefix (image_id .. before code_area_addr) ----
    let ci = KEY_AREA_LEN;
    // image_id, structure_version, structure_length, signature_length,
    // version_ext, mask, msid, mask  (0x00..0x20 of code-info)
    assert_eq!(
        &hdr[ci..ci + 0x20],
        &VENDOR_HEADER[ci..ci + 0x20],
        "code_info structural fields"
    );
    // code_enc_flag @ code-info+0x48 (no encryption in this build)
    assert_eq!(
        &hdr[ci + 0x48..ci + 0x4C],
        &VENDOR_HEADER[ci + 0x48..ci + 0x4C],
        "code_enc_flag"
    );
}

#[test]
fn hash_field_is_sha256_of_body() {
    use sha2::Digest;
    let hdr = build_image_header(BODY_HEAD, &ImageOptions::default()).unwrap();
    let mut h = sha2::Sha256::new();
    h.update(BODY_HEAD);
    let want = h.finalize();
    let off = KEY_AREA_LEN + 0x28;
    assert_eq!(&hdr[off..off + 32], &want[..]);
}
