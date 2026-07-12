//! Canonical flash-image planning for HiSilicon application images.
//!
//! This module is the library boundary that flashing transports should consume:
//! it owns the header/hash/body layout and returns a complete byte image plus
//! the address/range metadata needed by probe-rs, hisiflash, or a J-Link runner.

use crate::{
    build_app_image_from_input,
    error::{Error, Result},
    fwpkg::{
        Fwpkg, FwpkgBinInfo, FwpkgVersion, PartitionType, FWPKG_MAGIC_V1, FWPKG_MAGIC_V2_MAX,
        FWPKG_MAGIC_V2_MIN,
    },
    image::{
        APP_KEY_AREA_IMAGE_ID, CODE_AREA_HASH_OFF, CODE_AREA_LEN_OFF, HASH_LEN, IMAGE_HEADER_LEN,
    },
    Chip, PackOptions,
};

const ELF_MAGIC: &[u8] = &[0x7F, b'E', b'L', b'F'];

/// A half-open flash address range `[start, start + len)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FlashRange {
    /// Start flash address.
    pub start: u32,
    /// Length in bytes.
    pub len: u32,
}

/// Body range that flashboot hashes, relative to the full image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BodyRange {
    /// Offset inside `image_bytes` where the body starts.
    pub image_offset: u32,
    /// Flash address where the body starts.
    pub flash_addr: u32,
    /// Number of body bytes flashboot verifies.
    pub len: u32,
}

/// One write operation for transports that accept chunked writes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct WriteChunk {
    /// Flash address of this chunk.
    pub addr: u32,
    /// Offset inside `image_bytes`.
    pub image_offset: u32,
    /// Length in bytes.
    pub len: u32,
}

/// Source FWPKG metadata, present when the plan input was a `.fwpkg`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FwpkgSourceInfo {
    /// Parsed FWPKG format version.
    pub format: FwpkgVersion,
    /// V2 package name, or empty for V1 packages.
    pub package_name: String,
    /// Number of partition descriptors.
    pub partition_count: usize,
    /// Header total size field.
    pub total_size: u32,
    /// Header CRC16/XMODEM field.
    pub crc: u16,
    /// Whether the header CRC verifies.
    pub crc_valid: bool,
    /// Partition descriptors using the same interpretation as `hisiflash info`.
    pub partitions: Vec<FwpkgPartitionInfo>,
}

/// One FWPKG partition descriptor as interpreted by [`Fwpkg`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FwpkgPartitionInfo {
    /// Partition name.
    pub name: String,
    /// Partition type.
    pub partition_type: PartitionType,
    /// Payload offset inside the fwpkg file.
    pub offset: u32,
    /// Payload length.
    pub length: u32,
    /// Flash burn address.
    pub burn_addr: u32,
    /// Flash burn size / reserved erase region.
    pub burn_size: u32,
    /// Whether this partition is LoaderBoot.
    pub is_loaderboot: bool,
}

/// Options for [`plan_app_flash`].
#[derive(Debug, Clone, Default)]
pub struct ImagePlanOptions {
    /// Existing image/header options and optional address override.
    pub pack: PackOptions,
}

/// The canonical app-image flash plan.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FlashPlan {
    /// Chip preset used to resolve default addresses.
    pub chip: Chip,
    /// Flash address where `image_bytes[0]` must be written.
    pub base_addr: u32,
    /// Complete flash image: `0x300` header followed by the body as flashboot sees it.
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    pub image_bytes: Vec<u8>,
    /// Length of `image_bytes`.
    pub image_len: u32,
    /// Flashboot-verified body range.
    pub body_range: BodyRange,
    /// Header `code_area_len` value.
    pub code_area_len: u32,
    /// Header `code_area_hash` value.
    pub code_area_hash: [u8; HASH_LEN],
    /// Logical erase range required for this image. Flash transports may align it
    /// outward to their hardware sector size, but must not shrink it.
    pub erase_range: FlashRange,
    /// Canonical write chunks. The default is one full image chunk so old bytes
    /// cannot survive inside the verified body range.
    pub write_chunks: Vec<WriteChunk>,
    /// Source package metadata when input was a FWPKG.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub source_fwpkg: Option<FwpkgSourceInfo>,
}

/// Build the canonical app-image flash plan from ELF, headered ELF, raw image,
/// or raw body bytes.
pub fn plan_app_flash(input: &[u8], chip: Chip, opts: &ImagePlanOptions) -> Result<FlashPlan> {
    let (image_bytes, fwpkg_addr, fwpkg_burn_size, source_fwpkg) = if is_fwpkg(input) {
        let (image, addr, burn_size, source) = fwpkg_to_app_image(input, opts)?;
        (image, Some(addr), Some(burn_size), Some(source))
    } else if input.starts_with(ELF_MAGIC) {
        match crate::headered_elf_to_app_image(input) {
            Ok(image) => (image, None, None, None),
            Err(Error::Elf(msg)) if msg.contains("no `.boot_header` section found") => (
                build_app_image_from_input(input, &opts.pack)?,
                None,
                None,
                None,
            ),
            Err(err) => return Err(err),
        }
    } else if is_headered_image(input) {
        #[cfg(feature = "elf")]
        {
            (crate::patch::patch_hash(input)?, None, None, None)
        }
        #[cfg(not(feature = "elf"))]
        {
            (input.to_vec(), None, None, None)
        }
    } else {
        (
            build_app_image_from_input(input, &opts.pack)?,
            None,
            None,
            None,
        )
    };

    let mut plan = build_plan_from_image(image_bytes, chip, opts.pack.app_addr.or(fwpkg_addr))?;
    if let Some(burn_size) = fwpkg_burn_size {
        plan.erase_range.len = plan.erase_range.len.max(burn_size);
    }
    plan.source_fwpkg = source_fwpkg;
    Ok(plan)
}

fn build_plan_from_image(
    image_bytes: Vec<u8>,
    chip: Chip,
    app_addr: Option<u32>,
) -> Result<FlashPlan> {
    let image_bytes = crate::pad_image_to_code_area_len(image_bytes)?;
    if image_bytes.len() < IMAGE_HEADER_LEN {
        return Err(Error::InvalidFwpkg(format!(
            "app image is {} bytes, smaller than header length {IMAGE_HEADER_LEN}",
            image_bytes.len()
        )));
    }
    if !is_headered_image(&image_bytes) {
        let magic = u32::from_le_bytes(image_bytes[0..4].try_into().unwrap());
        return Err(Error::InvalidFwpkg(format!(
            "app image magic 0x{magic:08X} != 0x{APP_KEY_AREA_IMAGE_ID:08X}"
        )));
    }

    let image_len = u32::try_from(image_bytes.len()).map_err(|_| {
        Error::OutOfRange(format!("image length {} exceeds u32", image_bytes.len()))
    })?;
    let base_addr = app_addr.unwrap_or_else(|| chip.app_partition_addr());
    let code_area_len = read_u32(&image_bytes, CODE_AREA_LEN_OFF)?;
    let body_len = if code_area_len == 0 {
        image_len
            .checked_sub(IMAGE_HEADER_LEN as u32)
            .ok_or_else(|| {
                Error::OutOfRange("image length is smaller than the header".to_string())
            })?
    } else {
        code_area_len
    };
    let body_end = IMAGE_HEADER_LEN
        .checked_add(body_len as usize)
        .ok_or_else(|| Error::OutOfRange("body range overflows usize".to_string()))?;
    if body_end > image_bytes.len() {
        return Err(Error::OutOfRange(format!(
            "code_area_len 0x{body_len:X} exceeds image body length 0x{:X}",
            image_bytes.len() - IMAGE_HEADER_LEN
        )));
    }
    let code_area_hash = image_bytes[CODE_AREA_HASH_OFF..CODE_AREA_HASH_OFF + HASH_LEN]
        .try_into()
        .unwrap();

    Ok(FlashPlan {
        chip,
        base_addr,
        image_len,
        body_range: BodyRange {
            image_offset: IMAGE_HEADER_LEN as u32,
            flash_addr: base_addr + IMAGE_HEADER_LEN as u32,
            len: body_len,
        },
        code_area_len: body_len,
        code_area_hash,
        erase_range: FlashRange {
            start: base_addr,
            len: image_len,
        },
        write_chunks: vec![WriteChunk {
            addr: base_addr,
            image_offset: 0,
            len: image_len,
        }],
        source_fwpkg: None,
        image_bytes,
    })
}

fn is_headered_image(input: &[u8]) -> bool {
    input.len() >= IMAGE_HEADER_LEN
        && u32::from_le_bytes(input[0..4].try_into().unwrap()) == APP_KEY_AREA_IMAGE_ID
}

fn is_fwpkg(input: &[u8]) -> bool {
    input.len() >= 4 && {
        let magic = u32::from_le_bytes(input[0..4].try_into().unwrap());
        magic == FWPKG_MAGIC_V1 || (FWPKG_MAGIC_V2_MIN..=FWPKG_MAGIC_V2_MAX).contains(&magic)
    }
}

fn fwpkg_to_app_image(
    input: &[u8],
    opts: &ImagePlanOptions,
) -> Result<(Vec<u8>, u32, u32, FwpkgSourceInfo)> {
    let package = Fwpkg::from_bytes(input.to_vec())?;
    let source = fwpkg_source_info(&package);
    let requested_name = opts.pack.app_name.as_deref().unwrap_or("app");
    let selected = package
        .find_by_name(requested_name)
        .or_else(|| {
            package.normal_bins().find(|bin| {
                let name = bin.name.to_ascii_lowercase();
                name.contains("app")
                    || matches!(
                        bin.partition_type,
                        PartitionType::AppsA | PartitionType::App | PartitionType::AppSign
                    )
            })
        })
        .or_else(|| {
            let mut normal = package.normal_bins();
            let only = normal.next()?;
            if normal.next().is_none() {
                Some(only)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            Error::InvalidFwpkg(format!(
                "could not identify app partition {requested_name:?}; pass a single-app fwpkg or use a partition named app"
            ))
        })?;

    let image = package.bin_data(selected)?.to_vec();
    Ok((image, selected.burn_addr, selected.burn_size, source))
}

fn fwpkg_source_info(package: &Fwpkg) -> FwpkgSourceInfo {
    FwpkgSourceInfo {
        format: package.version(),
        package_name: package.package_name().to_string(),
        partition_count: package.partition_count(),
        total_size: package.header.len,
        crc: package.header.crc,
        crc_valid: package.verify_crc().is_ok(),
        partitions: package.bins.iter().map(partition_info).collect(),
    }
}

fn partition_info(bin: &FwpkgBinInfo) -> FwpkgPartitionInfo {
    FwpkgPartitionInfo {
        name: bin.name.clone(),
        partition_type: bin.partition_type,
        offset: bin.offset,
        length: bin.length,
        burn_addr: bin.burn_addr,
        burn_size: bin.burn_size,
        is_loaderboot: bin.is_loaderboot(),
    }
}

fn read_u32(buf: &[u8], offset: usize) -> Result<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or_else(|| Error::InvalidFwpkg(format!("missing u32 at header offset 0x{offset:X}")))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fwpkg::{build_fwpkg, Partition};
    use crate::{image::build_app_image, ImageOptions};

    #[test]
    fn raw_body_plan_writes_one_complete_image_chunk() {
        let plan = plan_app_flash(b"abc", Chip::Ws63, &ImagePlanOptions::default()).unwrap();
        assert_eq!(plan.base_addr, 0x230000);
        assert_eq!(plan.body_range.flash_addr, 0x230300);
        assert_eq!(plan.body_range.len, 3);
        assert_eq!(plan.write_chunks.len(), 1);
        assert_eq!(plan.write_chunks[0].len, plan.image_len);
    }

    #[test]
    fn headered_bin_is_patched_and_planned() {
        let mut image = build_app_image(b"body", &ImageOptions::default()).unwrap();
        image[CODE_AREA_HASH_OFF..CODE_AREA_HASH_OFF + HASH_LEN].fill(0);
        let plan = plan_app_flash(&image, Chip::Ws63, &ImagePlanOptions::default()).unwrap();
        assert_ne!(plan.code_area_hash, [0; HASH_LEN]);
        assert_eq!(plan.code_area_len, 4);
    }

    #[test]
    fn headered_bin_materializes_linker_aligned_erased_tail() {
        use sha2::Digest;

        let body = [0x11, 0x22, 0x33];
        let mut image = build_app_image(&body, &ImageOptions::default()).unwrap();
        image[CODE_AREA_LEN_OFF..CODE_AREA_LEN_OFF + 4].copy_from_slice(&4u32.to_le_bytes());
        image[CODE_AREA_HASH_OFF..CODE_AREA_HASH_OFF + HASH_LEN].fill(0);

        let plan = plan_app_flash(&image, Chip::Ws63, &ImagePlanOptions::default()).unwrap();

        assert_eq!(plan.code_area_len, 4);
        assert_eq!(plan.image_bytes.len(), IMAGE_HEADER_LEN + 4);
        assert_eq!(plan.image_bytes.last(), Some(&0xFF));
        assert_eq!(plan.image_len, (IMAGE_HEADER_LEN + 4) as u32);
        assert_eq!(plan.erase_range.len, plan.image_len);
        assert_eq!(plan.write_chunks[0].len, plan.image_len);

        let mut expected = body.to_vec();
        expected.push(0xFF);
        let expected_hash: [u8; HASH_LEN] = sha2::Sha256::digest(&expected).into();
        assert_eq!(plan.code_area_hash, expected_hash);
    }

    #[test]
    fn fwpkg_plan_uses_app_partition_burn_addr() {
        let image = build_app_image(b"body", &ImageOptions::default()).unwrap();
        let package = build_fwpkg(&[
            Partition::new(
                "ssb_sign.bin",
                vec![0xAA; 8],
                0x202000,
                PartitionType::Normal,
            ),
            Partition::new(
                "ws63-liteos-app-sign.bin",
                image,
                0x230000,
                PartitionType::Normal,
            )
            .with_burn_size(0x4000),
        ])
        .unwrap();

        let plan = plan_app_flash(&package, Chip::Ws63, &ImagePlanOptions::default()).unwrap();
        assert_eq!(plan.base_addr, 0x230000);
        assert_eq!(plan.body_range.flash_addr, 0x230300);
        assert_eq!(plan.code_area_len, 4);
        assert_eq!(plan.erase_range.len, 0x4000);
        let source = plan.source_fwpkg.unwrap();
        assert_eq!(source.partition_count, 2);
        assert_eq!(source.partitions[0].name, "ssb_sign.bin");
        assert_eq!(source.partitions[1].burn_addr, 0x230000);
        assert_eq!(source.partitions[1].burn_size, 0x4000);
    }
}
