//! `hisi-fwpkg` — build HiSilicon application **images** and **fwpkg** packages.
//!
//! This crate turns a compiled program (ELF or raw `.bin`) or vendor `.fwpkg`
//! into the on-flash
//! format that a HiSilicon flashboot expects, for chips in the WS63 / BS2X
//! family. It does two layered jobs:
//!
//! 1. [`plan`] — the canonical flash plan used by transports. It returns the
//!    complete image bytes, base address, body range, hash, erase range, write
//!    chunks, and source fwpkg metadata when present.
//! 2. [`image`] — wrap raw code in the fixed `0x300`-byte **app image header**
//!    (key area `0x4B0F2D1E` + code-info area `0x4B0F2D2D`, with the real
//!    SHA-256 of the body). This is what flashboot loads from the app
//!    partition.
//! 3. [`fwpkg`] — pack one or more partitions (loaderboot / flashboot / nv /
//!    app …) into a **fwpkg V1** container with the partition table + CRC that
//!    `hisiflash` flashes.
//!
//! ## Secure boot
//!
//! On boards with secure boot **disabled** (efuse `SEC_VERIFY_ENABLE == 0`,
//! the common case for dev boards that print `secure verify disable!`), the
//! ECC signatures are never checked — flashboot jumps unconditionally to
//! `app_partition + 0x300`. So the header here uses **dummy (zero)**
//! signatures and is sufficient to boot. Real cryptographic signing requires
//! the vendor's closed `sign_tool` signing server and is out of scope; see the
//! README for the full reverse-engineering writeup.
//!
//! ## Quick start
//!
//! ```no_run
//! use hisi_fwpkg::{Chip, pack_app_fwpkg, PackOptions};
//!
//! let elf = std::fs::read("blinky")?;
//! let fwpkg = pack_app_fwpkg(&elf, Chip::Ws63, &PackOptions::default())?;
//! std::fs::write("blinky.fwpkg", fwpkg)?;
//! # Ok::<(), hisi_fwpkg::Error>(())
//! ```

#![warn(missing_docs)]

pub mod error;
pub mod fwpkg;
pub mod image;
pub mod plan;

#[cfg(feature = "elf")]
pub mod elf;

#[cfg(feature = "elf")]
pub mod patch;

pub use {
    error::{Error, Result},
    fwpkg::{
        build_fwpkg, Fwpkg, FwpkgBinInfo, FwpkgHeader, FwpkgVersion, Partition, PartitionType,
    },
    image::{build_app_image, build_image_header, ImageOptions, IMAGE_HEADER_LEN},
    plan::{
        plan_app_flash, BodyRange, FlashPlan, FlashRange, FwpkgPartitionInfo, FwpkgSourceInfo,
        ImagePlanOptions, WriteChunk,
    },
};

#[cfg(feature = "elf")]
pub use patch::{patch_hash, patched_hash};

/// A supported chip family, carrying its flash-layout constants.
///
/// These presets capture the per-chip app partition base address (the flash
/// offset whose first `0x300` bytes are the image header and whose `+0x300`
/// byte is the entry point flashboot jumps to). They are derived from each
/// chip's vendor partition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum Chip {
    /// WS63 (Wi-Fi 6 + SLE). App partition at flash `0x230000`.
    Ws63,
    /// BS21 / BS2X (SLE/BLE). App partition at flash `0x90000`.
    Bs21,
}

impl Chip {
    /// Flash burn address of the app partition (where the image header starts).
    pub fn app_partition_addr(self) -> u32 {
        match self {
            Self::Ws63 => 0x0023_0000,
            Self::Bs21 => 0x0009_0000,
        }
    }

    /// Parse a chip name (case-insensitive). Accepts `ws63`, `bs21`, `bs2x`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "ws63" => Some(Self::Ws63),
            "bs21" | "bs2x" | "bs20" => Some(Self::Bs21),
            _ => None,
        }
    }
}

/// Options for [`pack_app_fwpkg`] / [`build_app_image_from_input`].
#[derive(Debug, Clone, Default)]
pub struct PackOptions {
    /// Image-header field overrides (defaults suit secure-boot-disabled boards).
    pub image: ImageOptions,
    /// Override the app partition burn address (defaults to the chip preset).
    pub app_addr: Option<u32>,
    /// Name for the app partition inside the fwpkg.
    pub app_name: Option<String>,
}

const ELF_MAGIC: &[u8] = &[0x7F, b'E', b'L', b'F'];

#[cfg(feature = "elf")]
pub(crate) fn headered_elf_to_app_image(input: &[u8]) -> Result<Vec<u8>> {
    let patched = patch_hash(input)?;
    let (hdr_off, body) = patch::locate_elf(&patched)?;
    let header = patched
        .get(hdr_off..hdr_off + IMAGE_HEADER_LEN)
        .ok_or_else(|| Error::Elf(".boot_header section truncated in file".to_string()))?;
    let mut image = Vec::with_capacity(IMAGE_HEADER_LEN + body.len());
    image.extend_from_slice(header);
    image.extend_from_slice(&body);
    pad_image_to_code_area_len(image)
}

#[cfg(not(feature = "elf"))]
pub(crate) fn headered_elf_to_app_image(_input: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Elf(
        "input is ELF but crate built without `elf` feature".into(),
    ))
}

/// Materialize any linker-aligned verified tail as erased flash bytes.
///
/// Flashboot hashes `code_area_len` contiguous bytes even when the ELF's final
/// file-backed segment ends before that aligned boundary. Every image-producing
/// path must therefore write the missing tail as `0xFF`, not merely include it
/// in the patched hash.
pub(crate) fn pad_image_to_code_area_len(mut image: Vec<u8>) -> Result<Vec<u8>> {
    if image.len() < IMAGE_HEADER_LEN {
        return Err(Error::OutOfRange(format!(
            "app image is {} bytes, smaller than header length {IMAGE_HEADER_LEN}",
            image.len()
        )));
    }
    let code_area_len = u32::from_le_bytes(
        image[image::CODE_AREA_LEN_OFF..image::CODE_AREA_LEN_OFF + 4]
            .try_into()
            .expect("fixed-size header field"),
    ) as usize;
    if code_area_len != 0 {
        let required_len = IMAGE_HEADER_LEN
            .checked_add(code_area_len)
            .ok_or_else(|| Error::OutOfRange("verified image length overflows usize".into()))?;
        if image.len() < required_len {
            image.resize(required_len, 0xFF);
        }
    }
    Ok(image)
}

/// Detect whether `input` is an ELF (by magic) and flatten it; otherwise treat
/// it as an already-flat raw binary. Returns the code body to wrap.
pub fn input_to_body(input: &[u8]) -> Result<Vec<u8>> {
    if input.starts_with(ELF_MAGIC) {
        #[cfg(feature = "elf")]
        {
            let (body, _base) = elf::flatten_elf(input)?;
            return Ok(body);
        }
        #[cfg(not(feature = "elf"))]
        {
            return Err(Error::Elf(
                "input is ELF but crate built without `elf` feature".into(),
            ));
        }
    }
    Ok(input.to_vec())
}

/// Build just the app image (`0x300` header || body) from ELF or raw body input.
pub fn build_app_image_from_input(input: &[u8], opts: &PackOptions) -> Result<Vec<u8>> {
    let body = input_to_body(input)?;
    build_app_image(&body, &opts.image)
}

fn is_headered_app_image(input: &[u8]) -> bool {
    if input.len() < IMAGE_HEADER_LEN {
        return false;
    }
    let key_id = u32::from_le_bytes(input[0..4].try_into().expect("slice length checked"));
    let code_id = u32::from_le_bytes(
        input[0x100..0x104]
            .try_into()
            .expect("slice length checked"),
    );

    key_id == image::APP_KEY_AREA_IMAGE_ID && code_id == image::APP_CODE_INFO_IMAGE_ID
}

/// Convert ELF/raw/headered input into a complete app image.
///
/// `hisi-fwpkg image` already produces a FlashBoot-ready image. Feeding that
/// image back into `hisi-fwpkg pack` must not add a second 0x300-byte header.
pub fn input_to_app_image(input: &[u8], opts: &PackOptions) -> Result<Vec<u8>> {
    if input.starts_with(ELF_MAGIC) {
        match headered_elf_to_app_image(input) {
            Ok(image) => Ok(image),
            Err(Error::Elf(msg)) if msg.contains("no `.boot_header` section found") => {
                build_app_image_from_input(input, opts)
            }
            Err(err) => Err(err),
        }
    } else if is_headered_app_image(input) {
        pad_image_to_code_area_len(patch_hash(input)?)
    } else {
        build_app_image_from_input(input, opts)
    }
}

/// End-to-end: ELF/bin → app image → single-partition fwpkg.
///
/// Produces a fwpkg containing only the app partition (burned at the chip's
/// app partition address). This is the minimal package to update an app on a
/// board that already has a working boot chain (loaderboot/flashboot/nv) in
/// flash. To produce a full first-flash package, add the vendor boot
/// partitions with [`build_fwpkg`] directly.
pub fn pack_app_fwpkg(input: &[u8], chip: Chip, opts: &PackOptions) -> Result<Vec<u8>> {
    let image_opts = ImagePlanOptions { pack: opts.clone() };
    let plan = plan_app_flash(input, chip, &image_opts)?;
    let image = plan.image_bytes;
    let addr = plan.base_addr;
    let name = opts.app_name.clone().unwrap_or_else(|| "app".to_string());
    let part = Partition::new(name, image, addr, PartitionType::Normal);
    build_fwpkg(&[part])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chip_addrs() {
        assert_eq!(Chip::Ws63.app_partition_addr(), 0x230000);
        assert_eq!(Chip::from_name("WS63"), Some(Chip::Ws63));
        assert_eq!(Chip::from_name("bs2x"), Some(Chip::Bs21));
        assert_eq!(Chip::from_name("nope"), None);
    }

    #[test]
    fn raw_bin_passthrough() {
        let raw = vec![0x13, 0x00, 0x00, 0x00]; // not ELF
        let body = input_to_body(&raw).unwrap();
        assert_eq!(body, raw);
    }

    #[test]
    fn pack_app_produces_valid_fwpkg() {
        let raw = vec![0x55u8; 200];
        let pkg = pack_app_fwpkg(&raw, Chip::Ws63, &PackOptions::default()).unwrap();
        // magic + cnt
        assert_eq!(
            u32::from_le_bytes(pkg[0..4].try_into().unwrap()),
            fwpkg::FWPKG_MAGIC_V1
        );
        assert_eq!(u16::from_le_bytes(pkg[6..8].try_into().unwrap()), 1);
    }

    #[test]
    fn pack_app_does_not_double_wrap_headered_image() {
        let raw = vec![0x55u8; 200];
        let image = build_app_image_from_input(&raw, &PackOptions::default()).unwrap();
        let pkg = pack_app_fwpkg(&image, Chip::Ws63, &PackOptions::default()).unwrap();
        let parsed = fwpkg::Fwpkg::from_bytes(pkg).unwrap();
        let app = parsed.normal_bins().next().unwrap();

        assert_eq!(app.length as usize, image.len());
        assert_eq!(parsed.bin_data(app).unwrap(), image.as_slice());
    }
}
