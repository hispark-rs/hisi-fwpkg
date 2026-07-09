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

/// Detect whether `input` is an ELF (by magic) and flatten it; otherwise treat
/// it as an already-flat raw binary. Returns the code body to wrap.
pub fn input_to_body(input: &[u8]) -> Result<Vec<u8>> {
    const ELF_MAGIC: &[u8] = &[0x7F, b'E', b'L', b'F'];
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

/// Build just the app image (`0x300` header || body) from ELF or raw bin input.
pub fn build_app_image_from_input(input: &[u8], opts: &PackOptions) -> Result<Vec<u8>> {
    let body = input_to_body(input)?;
    build_app_image(&body, &opts.image)
}

/// End-to-end: ELF/bin → app image → single-partition fwpkg.
///
/// Produces a fwpkg containing only the app partition (burned at the chip's
/// app partition address). This is the minimal package to update an app on a
/// board that already has a working boot chain (loaderboot/flashboot/nv) in
/// flash. To produce a full first-flash package, add the vendor boot
/// partitions with [`build_fwpkg`] directly.
pub fn pack_app_fwpkg(input: &[u8], chip: Chip, opts: &PackOptions) -> Result<Vec<u8>> {
    let image = build_app_image_from_input(input, opts)?;
    let addr = opts.app_addr.unwrap_or_else(|| chip.app_partition_addr());
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
}
