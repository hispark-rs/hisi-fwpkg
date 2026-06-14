//! WS63 application **image header** construction.
//!
//! A signed WS63 app image (the thing flashboot loads from flash `0x230000`)
//! is laid out as:
//!
//! ```text
//! +--------------------------------------+ 0x000
//! | image_key_area_t   (0x100 bytes)     |  ImageId = 0x4B0F2D1E
//! +--------------------------------------+ 0x100
//! | image_code_info_t  (0x200 bytes)     |  ImageId = 0x4B0F2D2D
//! +--------------------------------------+ 0x300  = APP_IMAGE_HEADER_LEN
//! | code body (raw .text/.rodata/...)    |
//! +--------------------------------------+
//! ```
//!
//! The 0x300-byte prefix is a **fixed-size** header. On a board with secure
//! boot **disabled** (efuse `SEC_VERIFY_ENABLE == 0`), flashboot's
//! `verify_image_*` functions short-circuit to success *before* checking any
//! signature or even the body hash — so the cryptographic signature fields are
//! never read. What matters is purely:
//!
//! * the header is exactly `0x300` bytes (flashboot jumps unconditionally to
//!   `image_addr + 0x300`), and
//! * the body that follows is real code linked to run at `0x230300`.
//!
//! This module fills in the structurally-correct header (matching the vendor
//! `sign_tool` output field-for-field: ImageIds, structure versions/lengths,
//! ECC key algorithm id, the real SHA-256 of the body in `code_area_hash`),
//! leaving the ECC signature blobs zero ("dummy"). That reproduces a valid
//! image for secure-boot-disabled boards. See the crate README for the full
//! reverse-engineering writeup.

use {crate::error::Result, sha2::Digest};

/// `APPBOOT_KEY_AREA_IMAGE_ID` — magic of the key area (offset 0x000).
pub const APP_KEY_AREA_IMAGE_ID: u32 = 0x4B0F_2D1E;
/// `APPBOOT_CODE_INFO_IMAGE_ID` — magic of the code-info area (offset 0x100).
pub const APP_CODE_INFO_IMAGE_ID: u32 = 0x4B0F_2D2D;

/// Length of the key area, `KEY_AREA_STRUCTURE_LENGTH` (ECC/SM2 build).
pub const KEY_AREA_LEN: usize = 0x100;
/// Length of the code-info area, `CODE_INFO_STRUCTURE_LENGTH` (ECC/SM2 build).
pub const CODE_INFO_LEN: usize = 0x200;
/// Total fixed image header length, `APP_IMAGE_HEADER_LEN`.
pub const IMAGE_HEADER_LEN: usize = KEY_AREA_LEN + CODE_INFO_LEN; // 0x300

/// `structure_version`, vendor uses `0x00010000`.
pub const STRUCTURE_VERSION: u32 = 0x0001_0000;
/// ECC-bp256 signature length in bytes (`BOOT_SIG_LEN`).
pub const SIG_LEN: u32 = 0x40;
/// `KeyAlg` for ECC256 / brainpoolP256r1 (`0x2A13C812`).
pub const KEY_ALG_ECC256: u32 = 0x2A13_C812;
/// `ecc_curve_type` for brainpoolP256r1 (`0x2A13C812`).
pub const ECC_CURVE_BP256R1: u32 = 0x2A13_C812;
/// ECC-bp256 public key length in bytes (`BOOT_PUBLIC_KEY_LEN`).
pub const PUB_KEY_LEN: u32 = 0x40;

/// `FLASH_NO_ENCRY_FLAG` — value of `code_enc_flag` meaning "**not** encrypted".
///
/// Counterintuitively this is a non-zero sentinel. flashboot's
/// `ws63_flash_encrypt_config()` does `if (code_enc_flag == FLASH_NO_ENCRY_FLAG)
/// return;` — so a *zero* `code_enc_flag` would make flashboot try to configure
/// on-the-fly flash decryption and fail to boot a plaintext image. Always use
/// this value for unencrypted images.
pub const FLASH_NO_ENCRY_FLAG: u32 = 0x3C78_96E1;

/// SHA-256 digest length.
pub const HASH_LEN: usize = 32;

/// Parameters controlling how the app image header is built.
///
/// Defaults match the vendor `liteos_app_bin_ecc.cfg` for a
/// secure-boot-disabled board: ECC256/brainpoolP256r1 algorithm ids, zero
/// versions/msid, no encryption, dummy (zero) signatures.
#[derive(Debug, Clone)]
pub struct ImageOptions {
    /// `KeyOwnerId`.
    pub key_owner_id: u32,
    /// `KeyId`.
    pub key_id: u32,
    /// `KeyVersion` extension (efuse anti-rollback; 0 for disabled boards).
    pub key_version_ext: u32,
    /// `KeyVersionMask`.
    pub key_version_mask: u32,
    /// `Version` extension (code anti-rollback).
    pub version_ext: u32,
    /// `VersionMask`.
    pub version_mask: u32,
    /// `Msid`.
    pub msid: u32,
    /// `MsidMask`.
    pub msid_mask: u32,
    /// `code_enc_flag` (defaults to [`FLASH_NO_ENCRY_FLAG`]).
    pub code_enc_flag: u32,
    /// `text_segment_size` (informational; vendor cfg `TextSegmentSize`).
    pub text_segment_size: u32,
}

impl Default for ImageOptions {
    fn default() -> Self {
        Self {
            key_owner_id: 1,
            key_id: 1,
            key_version_ext: 0,
            key_version_mask: 0,
            version_ext: 0,
            version_mask: 0,
            msid: 0,
            msid_mask: 0,
            code_enc_flag: FLASH_NO_ENCRY_FLAG,
            text_segment_size: 0x0001_0000,
        }
    }
}

/// Little-endian byte writer into a fixed-size buffer at explicit offsets.
struct Field<'a>(&'a mut [u8]);
impl Field<'_> {
    fn u32(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, off: usize, v: &[u8]) {
        self.0[off..off + v.len()].copy_from_slice(v);
    }
}

/// Build the `0x300`-byte WS63 app image header for a given code body.
///
/// `body` is the raw code that will live at flash `0x230300` (i.e. the result
/// of `objcopy -O binary`, or [`crate::elf::flatten_elf`]). The returned header
/// is meant to be written immediately followed by `body`.
///
/// `code_area_len` is set to `body.len()` and `code_area_hash` to its SHA-256,
/// exactly as the vendor `sign_tool` does. Signature fields are left zero.
pub fn build_image_header(body: &[u8], opts: &ImageOptions) -> Result<[u8; IMAGE_HEADER_LEN]> {
    let mut hdr = [0u8; IMAGE_HEADER_LEN];

    // ---- Key area (image_key_area_t), offset 0x000, length 0x100 ----
    {
        let (ka, _) = hdr.split_at_mut(KEY_AREA_LEN);
        let mut f = Field(ka);
        f.u32(0x00, APP_KEY_AREA_IMAGE_ID); // image_id
        f.u32(0x04, STRUCTURE_VERSION); // structure_version
        f.u32(0x08, KEY_AREA_LEN as u32); // structure_length (0x100)
        f.u32(0x0C, SIG_LEN); // signature_length (0x40)
        f.u32(0x10, opts.key_owner_id); // key_owner_id
        f.u32(0x14, opts.key_id); // key_id
        f.u32(0x18, KEY_ALG_ECC256); // key_alg
        f.u32(0x1C, ECC_CURVE_BP256R1); // ecc_curve_type
        f.u32(0x20, PUB_KEY_LEN); // key_length (0x40)
        f.u32(0x24, opts.key_version_ext); // key_version_ext
        f.u32(0x28, opts.key_version_mask); // mask_key_version_ext
        f.u32(0x2C, opts.msid); // msid_ext
        f.u32(0x30, opts.msid_mask); // mask_msid_ext
        f.u32(0x34, 0); // maintenance_mode (disabled)
                        // die_id[16] @ 0x38..0x48 — left zero (only checked in maintenance mode)
        f.u32(0x48, 0); // code_info_addr (0 = immediately follows)
                        // ext_public_key_area[0x40] @ 0x40 region of reserved/key — dummy zero
                        // sig_key_area[0x40] — dummy zero
    }

    // ---- Code info area (image_code_info_t), offset 0x100, length 0x200 ----
    {
        let ci = &mut hdr[KEY_AREA_LEN..KEY_AREA_LEN + CODE_INFO_LEN];
        let mut f = Field(ci);
        f.u32(0x00, APP_CODE_INFO_IMAGE_ID); // image_id
        f.u32(0x04, STRUCTURE_VERSION); // structure_version
        f.u32(0x08, CODE_INFO_LEN as u32); // structure_length (0x200)
        f.u32(0x0C, SIG_LEN); // signature_length (0x40)
        f.u32(0x10, opts.version_ext); // version_ext
        f.u32(0x14, opts.version_mask); // mask_version_ext
        f.u32(0x18, opts.msid); // msid_ext
        f.u32(0x1C, opts.msid_mask); // mask_msid_ext
        f.u32(0x20, 0); // code_area_addr (0 = immediately follows header)
        let code_len = u32::try_from(body.len()).map_err(|_| {
            crate::error::Error::OutOfRange(format!("body length {} exceeds u32", body.len()))
        })?;
        f.u32(0x24, code_len); // code_area_len

        // code_area_hash[32] @ 0x28
        let mut hasher = sha2::Sha256::new();
        hasher.update(body);
        let digest = hasher.finalize();
        f.bytes(0x28, &digest);

        f.u32(0x48, opts.code_enc_flag); // code_enc_flag
                                         // protection_key_l1[16] @ 0x4C, protection_key_l2[16] @ 0x5C,
                                         // iv[16] @ 0x6C — all zero (encryption disabled)
        f.u32(0x7C, 0); // code_compress_flag (0 = not compressed)
        f.u32(0x80, code_len); // code_uncompress_len (== code_area_len)
        f.u32(0x84, opts.text_segment_size); // text_segment_size
                                             // sig_code_info[0x40] + sig_code_info_ext[0x40] — dummy zero
    }

    Ok(hdr)
}

/// Build a complete app image: `header (0x300) || body`.
///
/// The result is what gets burned to the app partition at flash `0x230000`.
pub fn build_app_image(body: &[u8], opts: &ImageOptions) -> Result<Vec<u8>> {
    let header = build_image_header(body, opts)?;
    let mut out = Vec::with_capacity(IMAGE_HEADER_LEN + body.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_fixed_size() {
        let body = vec![0xAA; 100];
        let hdr = build_image_header(&body, &ImageOptions::default()).unwrap();
        assert_eq!(hdr.len(), 0x300);
    }

    #[test]
    fn magics_and_lengths() {
        let body = vec![0x11; 64];
        let hdr = build_image_header(&body, &ImageOptions::default()).unwrap();
        assert_eq!(
            u32::from_le_bytes(hdr[0x00..0x04].try_into().unwrap()),
            APP_KEY_AREA_IMAGE_ID
        );
        assert_eq!(
            u32::from_le_bytes(hdr[0x08..0x0C].try_into().unwrap()),
            0x100
        );
        assert_eq!(
            u32::from_le_bytes(hdr[0x100..0x104].try_into().unwrap()),
            APP_CODE_INFO_IMAGE_ID
        );
        assert_eq!(
            u32::from_le_bytes(hdr[0x108..0x10C].try_into().unwrap()),
            0x200
        );
        // code_area_len at code_info+0x24 == body length
        let off = KEY_AREA_LEN + 0x24;
        assert_eq!(
            u32::from_le_bytes(hdr[off..off + 4].try_into().unwrap()),
            64
        );
    }

    #[test]
    fn hash_matches_body() {
        let body = vec![0x42; 4096];
        let hdr = build_image_header(&body, &ImageOptions::default()).unwrap();
        let mut h = sha2::Sha256::new();
        h.update(&body);
        let want = h.finalize();
        let off = KEY_AREA_LEN + 0x28;
        assert_eq!(&hdr[off..off + HASH_LEN], &want[..]);
    }
}
