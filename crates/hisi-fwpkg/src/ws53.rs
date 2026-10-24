//! Experimental WS53 image inspection, independent of WS63 address defaults.
//!
//! This validates the SDK LoaderBoot envelope and body hash, not chip identity
//! or a signature. Flash application packaging needs the actual partition
//! table and preservation of the existing control-core image; it is not yet
//! offered through `Chip` or `pack_app_fwpkg`.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
mod application;
pub use application::{plan_unsigned_application, ApplicationPlan, ApplicationSector};

/// Root public-key header bytes before the LoaderBoot key and code-info areas.
pub const LOADER_ROOT_LEN: usize = 0x80;
/// Body offset in a WS53 SDK LoaderBoot download package.
pub const LOADER_BODY_OFFSET: usize = 0x380;
/// Body size explicitly produced by the SDK WS53 signing script.
pub const SDK_LOADER_BODY_LEN: usize = 28 * 1024;

/// Parsed SDK LoaderBoot envelope. This is not permission to flash or run it.
#[derive(Debug)]
pub struct LoaderBoot<'a> {
    /// Complete package for the ROM YMODEM transfer.
    pub package: &'a [u8],
    /// Code body, whose SHA-256 was compared with its header.
    pub body: &'a [u8],
    /// Hash verified against the code-info area.
    pub body_sha256: [u8; 32],
    /// True for the SDK's missing-root-key fallback of 128 FF bytes.
    pub has_placeholder_root: bool,
    /// Raw encryption flag; interpretation differs between loader and app.
    pub code_encryption_flag: u32,
}

fn invalid(message: &str) -> Error {
    Error::InvalidFwpkg(format!("WS53 LoaderBoot: {message}"))
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    // Only called after the exact envelope length has been validated.
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// Validate the 28 KiB WS53 SDK LoaderBoot envelope without invoking vendor tools.
///
/// Sources: `fbb_ws53` 163d9150 `params_and_bin_sign.py`,
/// `loaderboot_ws53_ecc.cfg`, and `secure_verify_boot_v1/secure_verify_boot.h`.
/// Unknown root formats, nonlocal code pointers, compression, wrong structure
/// lengths, truncation, trailing bytes and corrupted code hashes are rejected.
/// Root/key signatures are not verified; callers must separately qualify the
/// package source/hash and select the target. A header is not a chip ID.
pub fn inspect_loader(package: &[u8]) -> Result<LoaderBoot<'_>> {
    if package.len() != LOADER_BODY_OFFSET + SDK_LOADER_BODY_LEN {
        return Err(invalid("expected 0x380-byte envelope and 28 KiB body"));
    }
    let placeholder = package[..LOADER_ROOT_LEN].iter().all(|&b| b == 0xff);
    if !placeholder && word(package, 0) != 0x4ba5c31e {
        return Err(invalid("unknown root header"));
    }
    for (offset, expected) in [
        (0x80, 0x4bd2f01e),
        (0x84, 0x10000),
        (0x88, 0x100),
        (0xc8, 0), // code-info follows key area, not an external pointer
        (0x180, 0x4bd2f02d),
        (0x184, 0x10000),
        (0x188, 0x200),
        (0x1a0, 0),
        (0x1a4, SDK_LOADER_BODY_LEN as u32),
        (0x1fc, 0),       // no compression in this profile
        (0x204, 0x10000), // SDK text-segment bound
    ] {
        if word(package, offset) != expected {
            return Err(invalid("unsupported envelope field"));
        }
    }
    let body = &package[LOADER_BODY_OFFSET..];
    let hash: [u8; 32] = Sha256::digest(body).into();
    if package[0x1a8..0x1c8] != hash {
        return Err(invalid("body SHA-256 mismatch"));
    }
    Ok(LoaderBoot {
        package,
        body,
        body_sha256: hash,
        has_placeholder_root: placeholder,
        code_encryption_flag: word(package, 0x1c8),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; LOADER_BODY_OFFSET + SDK_LOADER_BODY_LEN];
        bytes[..0x80].fill(0xff);
        for (offset, value) in [
            (0x80, 0x4bd2f01eu32),
            (0x84, 0x10000),
            (0x88, 0x100),
            (0x180, 0x4bd2f02d),
            (0x184, 0x10000),
            (0x188, 0x200),
            (0x1a4, 0x7000),
            (0x204, 0x10000),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[LOADER_BODY_OFFSET..].fill(0x42);
        let hash = Sha256::digest(&bytes[LOADER_BODY_OFFSET..]);
        bytes[0x1a8..0x1c8].copy_from_slice(&hash);
        bytes
    }
    #[test]
    fn loader_views_and_negative_envelopes() {
        let bytes = fixture();
        let image = inspect_loader(&bytes).unwrap();
        assert!(image.has_placeholder_root);
        assert_eq!(image.body.len(), SDK_LOADER_BODY_LEN);
        for offset in [
            0,
            0x80,
            0x84,
            0x88,
            0xc8,
            0x180,
            0x184,
            0x188,
            0x1a0,
            0x1a4,
            0x1a8,
            0x1fc,
            0x204,
            LOADER_BODY_OFFSET,
        ] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(inspect_loader(&bad).is_err(), "offset {offset:#x}");
        }
        for len in [0, 0x80, LOADER_BODY_OFFSET, bytes.len() - 1] {
            assert!(inspect_loader(&bytes[..len]).is_err());
        }
        let mut extra = bytes;
        extra.push(0);
        assert!(inspect_loader(&extra).is_err());
    }
}
