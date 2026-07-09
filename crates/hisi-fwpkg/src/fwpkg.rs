//! HiSilicon **fwpkg V1** container construction.
//!
//! A fwpkg is an "all-in-one" firmware package: a small header, a table of
//! per-partition descriptors, then the concatenated partition payloads. This
//! module *produces* V1 packages; the layout is the exact inverse of the
//! parser in `hisiflash` and matches the vendor `packet_create.py`
//! `create_allinone()`:
//!
//! ```text
//! +----------------------------------+ 0x000
//! | FWPKG_HEAD (12 bytes)            |  flag(4) crc(2) cnt(2) total_len(4)
//! +----------------------------------+ 0x00C
//! | IMAGE_INFO[0] (52 bytes)         |  name[32] off(4) len(4) burn_addr(4)
//! | IMAGE_INFO[1] ...                |           burn_size(4) type(4)
//! +----------------------------------+
//! | payload[0]  || 16 zero bytes     |
//! | payload[1]  || 16 zero bytes     |
//! +----------------------------------+
//! ```
//!
//! Notes that match the vendor tool byte-for-byte:
//! * `flag` (magic) is `0xEFBEADDF`.
//! * Each payload is followed by **16 zero bytes** of separator padding, which
//!   are counted in `total_len` but **not** in the descriptor `length`.
//! * `crc` is CRC16/XMODEM (poly 0x1021, init 0x0000) over the bytes from
//!   offset 6 (the `cnt` field) through the end of the descriptor table only.

use {
    crate::error::{Error, Result},
    std::{fs::File, io::Read, path::Path},
};

/// fwpkg V1 magic (`flag`), little-endian on disk.
pub const FWPKG_MAGIC_V1: u32 = 0xEFBE_ADDF;
/// `FWPKG_HEAD` size in bytes.
pub const HEADER_SIZE: usize = 12;
/// `IMAGE_INFO` (per-partition descriptor) size in bytes.
pub const BIN_INFO_SIZE: usize = 52;
/// V1 partition-name field width.
pub const NAME_SIZE: usize = 32;
/// Zero-byte separator appended after each payload.
pub const PAYLOAD_SEPARATOR: usize = 16;
/// Maximum number of partitions accepted by the parser.
pub const MAX_PARTITIONS: usize = 255;
/// FWPKG V2 magic minimum.
pub const FWPKG_MAGIC_V2_MIN: u32 = 0xEFBE_ADD0;
/// FWPKG V2 magic maximum.
pub const FWPKG_MAGIC_V2_MAX: u32 = 0xEFBE_ADDE;
/// FWPKG V2 header size in bytes.
pub const HEADER_SIZE_V2: usize = 272;
/// FWPKG V2 per-partition descriptor size in bytes.
pub const BIN_INFO_SIZE_V2: usize = 284;
/// V2 partition-name field width.
pub const NAME_SIZE_V2: usize = 260;

/// Partition burn type (the `type` field of `IMAGE_INFO`).
///
/// Mirrors the vendor packer's per-partition `type` value: loaderboot is `0`,
/// ordinary partitions (ssb / flashboot / nv / app / params) are `1`, KV is
/// `2`, efuse is `3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum PartitionType {
    /// LoaderBoot (first-stage loader) — type 0.
    Loader,
    /// Ordinary partition — type 1 (ssb, flashboot, nv, params, app, ...).
    Normal,
    /// Key-Value NV — type 2.
    KvNv,
    /// eFuse config — type 3.
    Efuse,
    /// OTP data — type 4.
    Otp,
    /// FlashBoot — type 5.
    Flashboot,
    /// Factory data — type 6.
    Factory,
    /// Version information — type 7.
    Version,
    /// Security partition A — type 8.
    SecurityA,
    /// Security partition B — type 9.
    SecurityB,
    /// Security partition C — type 10.
    SecurityC,
    /// Protocol partition A — type 11.
    ProtocolA,
    /// Apps partition A — type 12.
    AppsA,
    /// Radio configuration — type 13.
    RadioConfig,
    /// ROM image — type 14.
    Rom,
    /// eMMC image — type 15.
    Emmc,
    /// Database partition — type 16.
    Database,
    /// 3892 FlashBoot — type 17.
    Flashboot3892,
    /// App image — type 18.
    App,
    /// Signed app image — type 19.
    AppSign,
    /// BT image — type 20.
    Bt,
    /// Signed BT image — type 21.
    BtSign,
    /// DSP image — type 22.
    Dsp,
    /// Signed DSP image — type 23.
    DspSign,
    /// SSB SHA image — type 24.
    SsbSha,
    /// Signed SSB image — type 25.
    SsbSign,
    /// DSP1 image — type 26.
    Dsp1,
    /// Signed DSP1 image — type 27.
    Dsp1Sign,
    /// Small image — type 28.
    Small,
    /// Small SHA image — type 29.
    SmallSha,
    /// Raw flash binary — type 100.
    FlashBin,
    /// Raw eMMC binary — type 101.
    EmmcBin,
    /// SHA sidecar — type 102.
    Sha,
    /// Unknown/raw type code.
    Unknown(u32),
}

impl PartitionType {
    /// Numeric value written to the `type` field.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Loader => 0,
            Self::Normal => 1,
            Self::KvNv => 2,
            Self::Efuse => 3,
            Self::Otp => 4,
            Self::Flashboot => 5,
            Self::Factory => 6,
            Self::Version => 7,
            Self::SecurityA => 8,
            Self::SecurityB => 9,
            Self::SecurityC => 10,
            Self::ProtocolA => 11,
            Self::AppsA => 12,
            Self::RadioConfig => 13,
            Self::Rom => 14,
            Self::Emmc => 15,
            Self::Database => 16,
            Self::Flashboot3892 => 17,
            Self::App => 18,
            Self::AppSign => 19,
            Self::Bt => 20,
            Self::BtSign => 21,
            Self::Dsp => 22,
            Self::DspSign => 23,
            Self::SsbSha => 24,
            Self::SsbSign => 25,
            Self::Dsp1 => 26,
            Self::Dsp1Sign => 27,
            Self::Small => 28,
            Self::SmallSha => 29,
            Self::FlashBin => 100,
            Self::EmmcBin => 101,
            Self::Sha => 102,
            Self::Unknown(v) => v,
        }
    }
}

impl From<u32> for PartitionType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Loader,
            1 => Self::Normal,
            2 => Self::KvNv,
            3 => Self::Efuse,
            4 => Self::Otp,
            5 => Self::Flashboot,
            6 => Self::Factory,
            7 => Self::Version,
            8 => Self::SecurityA,
            9 => Self::SecurityB,
            10 => Self::SecurityC,
            11 => Self::ProtocolA,
            12 => Self::AppsA,
            13 => Self::RadioConfig,
            14 => Self::Rom,
            15 => Self::Emmc,
            16 => Self::Database,
            17 => Self::Flashboot3892,
            18 => Self::App,
            19 => Self::AppSign,
            20 => Self::Bt,
            21 => Self::BtSign,
            22 => Self::Dsp,
            23 => Self::DspSign,
            24 => Self::SsbSha,
            25 => Self::SsbSign,
            26 => Self::Dsp1,
            27 => Self::Dsp1Sign,
            28 => Self::Small,
            29 => Self::SmallSha,
            100 => Self::FlashBin,
            101 => Self::EmmcBin,
            102 => Self::Sha,
            v => Self::Unknown(v),
        }
    }
}

/// Parsed FWPKG format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum FwpkgVersion {
    /// V1: 12-byte header, 32-byte partition names.
    V1,
    /// V2: 272-byte header, 260-byte UTF-8 package and partition names.
    V2,
}

/// Parsed FWPKG header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FwpkgHeader {
    /// Magic number.
    pub magic: u32,
    /// Header CRC16/XMODEM.
    pub crc: u16,
    /// Partition count.
    pub cnt: u16,
    /// Total firmware file size recorded in the header.
    pub len: u32,
    /// Package name, only present in V2.
    pub name: String,
    /// Parsed format version.
    pub version: FwpkgVersion,
}

impl FwpkgHeader {
    fn is_valid(&self) -> bool {
        let valid_magic = self.magic == FWPKG_MAGIC_V1
            || (FWPKG_MAGIC_V2_MIN..=FWPKG_MAGIC_V2_MAX).contains(&self.magic);
        valid_magic && usize::from(self.cnt) <= MAX_PARTITIONS
    }

    /// Header size for this version.
    pub fn header_size(&self) -> usize {
        match self.version {
            FwpkgVersion::V1 => HEADER_SIZE,
            FwpkgVersion::V2 => HEADER_SIZE_V2,
        }
    }

    /// Per-partition descriptor size for this version.
    pub fn bin_info_size(&self) -> usize {
        match self.version {
            FwpkgVersion::V1 => BIN_INFO_SIZE,
            FwpkgVersion::V2 => BIN_INFO_SIZE_V2,
        }
    }
}

/// Parsed FWPKG partition descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FwpkgBinInfo {
    /// Partition name.
    pub name: String,
    /// Payload offset inside the fwpkg file.
    pub offset: u32,
    /// Payload length.
    pub length: u32,
    /// Flash burn address.
    pub burn_addr: u32,
    /// Flash burn size / reserved erase region.
    pub burn_size: u32,
    /// Partition type.
    pub partition_type: PartitionType,
}

impl FwpkgBinInfo {
    /// Check if this partition is LoaderBoot.
    pub fn is_loaderboot(&self) -> bool {
        self.partition_type == PartitionType::Loader
    }
}

/// Parsed FWPKG package.
#[derive(Clone)]
pub struct Fwpkg {
    /// File header.
    pub header: FwpkgHeader,
    /// Partition descriptors.
    pub bins: Vec<FwpkgBinInfo>,
    data: Vec<u8>,
}

impl Fwpkg {
    /// Load a FWPKG from a file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut data = Vec::new();
        File::open(path)?.read_to_end(&mut data)?;
        Self::from_bytes(data)
    }

    /// Parse a FWPKG from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::InvalidFwpkg(
                "file too small for FWPKG header".into(),
            ));
        }

        let magic = read_u32(&data, 0)?;
        let crc = read_u16(&data, 4)?;
        let cnt = read_u16(&data, 6)?;
        let len = read_u32(&data, 8)?;
        let (version, name) = if magic == FWPKG_MAGIC_V1 {
            (FwpkgVersion::V1, String::new())
        } else if (FWPKG_MAGIC_V2_MIN..=FWPKG_MAGIC_V2_MAX).contains(&magic) {
            (
                FwpkgVersion::V2,
                read_name(&data, HEADER_SIZE, NAME_SIZE_V2)?,
            )
        } else {
            return Err(Error::InvalidFwpkg(format!(
                "invalid magic 0x{magic:08X}; expected 0x{FWPKG_MAGIC_V1:08X} or 0x{FWPKG_MAGIC_V2_MIN:08X}..=0x{FWPKG_MAGIC_V2_MAX:08X}"
            )));
        };
        let header = FwpkgHeader {
            magic,
            crc,
            cnt,
            len,
            name,
            version,
        };
        if !header.is_valid() {
            return Err(Error::InvalidFwpkg(format!(
                "invalid partition count {}",
                header.cnt
            )));
        }
        let table_end = header.header_size() + usize::from(header.cnt) * header.bin_info_size();
        if data.len() < table_end {
            return Err(Error::InvalidFwpkg(format!(
                "file too small for descriptor table: need {table_end}, got {}",
                data.len()
            )));
        }

        let mut bins = Vec::with_capacity(usize::from(header.cnt));
        for index in 0..usize::from(header.cnt) {
            let off = header.header_size() + index * header.bin_info_size();
            let (name_len, padding) = match header.version {
                FwpkgVersion::V1 => (NAME_SIZE, 0),
                FwpkgVersion::V2 => (NAME_SIZE_V2, 4),
            };
            let name = read_name(&data, off, name_len)?;
            let fields = off + name_len;
            bins.push(FwpkgBinInfo {
                name,
                offset: read_u32(&data, fields)?,
                length: read_u32(&data, fields + 4)?,
                burn_addr: read_u32(&data, fields + 8)?,
                burn_size: read_u32(&data, fields + 12)?,
                partition_type: read_u32(&data, fields + 16)?.into(),
            });
            let desc_end = fields + 20 + padding;
            if desc_end > off + header.bin_info_size() {
                return Err(Error::InvalidFwpkg("descriptor size overflow".into()));
            }
        }

        for bin in &bins {
            let start = bin.offset as usize;
            let end = start
                .checked_add(bin.length as usize)
                .ok_or_else(|| Error::InvalidFwpkg("partition range overflows usize".into()))?;
            if end > data.len() {
                return Err(Error::InvalidFwpkg(format!(
                    "partition {} data out of bounds (offset {}, length {}, file size {})",
                    bin.name,
                    bin.offset,
                    bin.length,
                    data.len()
                )));
            }
        }

        Ok(Self { header, bins, data })
    }

    /// Return the parsed version.
    pub fn version(&self) -> FwpkgVersion {
        self.header.version
    }

    /// Return the number of partitions.
    pub fn partition_count(&self) -> usize {
        self.bins.len()
    }

    /// Return the V2 package name, or an empty string for V1 packages.
    pub fn package_name(&self) -> &str {
        &self.header.name
    }

    /// Verify the header CRC.
    pub fn verify_crc(&self) -> Result<()> {
        let table_end = self.header.header_size() + self.bins.len() * self.header.bin_info_size();
        let computed = crc16_xmodem(&self.data[6..table_end]);
        if computed != self.header.crc {
            return Err(Error::InvalidFwpkg(format!(
                "crc mismatch: expected 0x{:04X}, computed 0x{computed:04X}",
                self.header.crc
            )));
        }
        Ok(())
    }

    /// Find LoaderBoot partition.
    pub fn loaderboot(&self) -> Option<&FwpkgBinInfo> {
        self.bins.iter().find(|bin| bin.is_loaderboot())
    }

    /// Iterate non-LoaderBoot partitions.
    pub fn normal_bins(&self) -> impl Iterator<Item = &FwpkgBinInfo> {
        self.bins.iter().filter(|bin| !bin.is_loaderboot())
    }

    /// Return payload bytes for a partition descriptor.
    pub fn bin_data(&self, bin: &FwpkgBinInfo) -> Result<&[u8]> {
        let start = bin.offset as usize;
        let end = start
            .checked_add(bin.length as usize)
            .ok_or_else(|| Error::InvalidFwpkg("partition range overflows usize".into()))?;
        self.data.get(start..end).ok_or_else(|| {
            Error::InvalidFwpkg(format!(
                "partition {} data out of bounds (offset {}, length {}, file size {})",
                bin.name,
                bin.offset,
                bin.length,
                self.data.len()
            ))
        })
    }

    /// Find a partition by name.
    pub fn find_by_name(&self, name: &str) -> Option<&FwpkgBinInfo> {
        self.bins.iter().find(|bin| bin.name == name)
    }
}

impl std::fmt::Debug for Fwpkg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fwpkg")
            .field("header", &self.header)
            .field("bins", &self.bins)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// One partition to be packed into a fwpkg.
#[derive(Debug, Clone)]
pub struct Partition {
    /// Name stored in the 32-byte name field (must be < 32 bytes).
    pub name: String,
    /// Raw payload bytes.
    pub data: Vec<u8>,
    /// Flash burn address (`burn_addr`).
    pub burn_addr: u32,
    /// Flash burn size (`burn_size`) — region erased/reserved on the device.
    pub burn_size: u32,
    /// Partition burn type.
    pub partition_type: PartitionType,
}

impl Partition {
    /// Convenience constructor; `burn_size` defaults to the payload length.
    pub fn new(
        name: impl Into<String>,
        data: Vec<u8>,
        burn_addr: u32,
        partition_type: PartitionType,
    ) -> Self {
        let len = data.len() as u32;
        Self {
            name: name.into(),
            data,
            burn_addr,
            burn_size: len,
            partition_type,
        }
    }

    /// Set an explicit burn size (e.g. a reserved region larger than payload).
    pub fn with_burn_size(mut self, burn_size: u32) -> Self {
        self.burn_size = burn_size;
        self
    }
}

/// CRC16/XMODEM (poly 0x1021, init 0x0000) — matches the vendor `crc16` class.
pub fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Serialise the given partitions into a fwpkg V1 byte buffer.
///
/// The output is binary-identical in structure to the vendor
/// `packet_create.py` output and parses cleanly with `hisiflash info`.
pub fn build_fwpkg(parts: &[Partition]) -> Result<Vec<u8>> {
    if parts.is_empty() {
        return Err(Error::EmptyPackage);
    }
    for p in parts {
        if p.name.len() >= NAME_SIZE {
            return Err(Error::NameTooLong {
                name: p.name.clone(),
                len: p.name.len(),
                max: NAME_SIZE - 1,
            });
        }
    }

    let head_len = HEADER_SIZE + parts.len() * BIN_INFO_SIZE;
    let pad_len = PAYLOAD_SEPARATOR * parts.len();
    let payload_len: usize = parts.iter().map(|p| p.data.len()).sum();
    let total_len = head_len + payload_len + pad_len;

    let mut out = Vec::with_capacity(total_len);

    // ---- FWPKG_HEAD ---- (crc placeholder, fixed up below)
    out.extend_from_slice(&FWPKG_MAGIC_V1.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // crc placeholder
    out.extend_from_slice(&(parts.len() as u16).to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(total_len)
            .map_err(|_| Error::OutOfRange(format!("total package size {total_len} exceeds u32")))?
            .to_le_bytes(),
    );

    // ---- IMAGE_INFO[] ----
    let mut start_index = head_len;
    for p in parts {
        let mut name = [0u8; NAME_SIZE];
        let nb = p.name.as_bytes();
        name[..nb.len()].copy_from_slice(nb);
        out.extend_from_slice(&name);
        out.extend_from_slice(&(start_index as u32).to_le_bytes()); // offset
        out.extend_from_slice(&(p.data.len() as u32).to_le_bytes()); // length
        out.extend_from_slice(&p.burn_addr.to_le_bytes()); // burn_addr
        out.extend_from_slice(&p.burn_size.to_le_bytes()); // burn_size
        out.extend_from_slice(&p.partition_type.as_u32().to_le_bytes()); // type
        start_index += p.data.len() + PAYLOAD_SEPARATOR;
    }

    // ---- payloads (each followed by 16 zero bytes) ----
    for p in parts {
        out.extend_from_slice(&p.data);
        out.extend_from_slice(&[0u8; PAYLOAD_SEPARATOR]);
    }

    // ---- CRC fix-up: CRC16 over bytes [6 .. head_len) ----
    let crc = crc16_xmodem(&out[6..head_len]);
    out[4..6].copy_from_slice(&crc.to_le_bytes());

    debug_assert_eq!(out.len(), total_len);
    Ok(out)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| Error::InvalidFwpkg(format!("missing u16 at offset {offset}")))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::InvalidFwpkg(format!("missing u32 at offset {offset}")))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_name(data: &[u8], offset: usize, len: usize) -> Result<String> {
    let bytes = data
        .get(offset..offset + len)
        .ok_or_else(|| Error::InvalidFwpkg(format!("missing name at offset {offset}")))?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(len);
    Ok(String::from_utf8_lossy(&bytes[..end]).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_known_vector() {
        // CRC16/XMODEM of "123456789" is 0x31C3.
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }

    #[test]
    fn single_partition_layout() {
        let parts = vec![Partition::new(
            "app",
            vec![0xAB; 10],
            0x230000,
            PartitionType::Normal,
        )];
        let pkg = build_fwpkg(&parts).unwrap();
        assert_eq!(
            u32::from_le_bytes(pkg[0..4].try_into().unwrap()),
            FWPKG_MAGIC_V1
        );
        assert_eq!(u16::from_le_bytes(pkg[6..8].try_into().unwrap()), 1); // cnt
        let head_len = HEADER_SIZE + BIN_INFO_SIZE;
        let expect_total = head_len + 10 + PAYLOAD_SEPARATOR;
        assert_eq!(
            u32::from_le_bytes(pkg[8..12].try_into().unwrap()) as usize,
            expect_total
        );
        assert_eq!(pkg.len(), expect_total);
        // descriptor offset points right after the table
        assert_eq!(
            u32::from_le_bytes(pkg[44..48].try_into().unwrap()) as usize,
            head_len
        );
    }

    #[test]
    fn parses_built_v1_package() {
        let pkg = build_fwpkg(&[
            Partition::new("root_loaderboot", vec![0x11; 8], 0, PartitionType::Loader),
            Partition::new("app", vec![0x22; 10], 0x230000, PartitionType::Normal)
                .with_burn_size(0x20000),
        ])
        .unwrap();
        let parsed = Fwpkg::from_bytes(pkg).unwrap();
        assert_eq!(parsed.version(), FwpkgVersion::V1);
        assert_eq!(parsed.partition_count(), 2);
        let loader = parsed.loaderboot().unwrap();
        assert_eq!(loader.name, "root_loaderboot");
        assert_eq!(parsed.bin_data(loader).unwrap(), &[0x11; 8]);
        let app = parsed.find_by_name("app").unwrap();
        assert_eq!(app.burn_addr, 0x230000);
        assert_eq!(app.burn_size, 0x20000);
        assert_eq!(parsed.bin_data(app).unwrap(), &[0x22; 10]);
    }

    #[test]
    fn rejects_long_name() {
        let parts = vec![Partition::new(
            "x".repeat(40),
            vec![0u8; 4],
            0,
            PartitionType::Normal,
        )];
        assert!(matches!(
            build_fwpkg(&parts),
            Err(Error::NameTooLong { .. })
        ));
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(build_fwpkg(&[]), Err(Error::EmptyPackage)));
    }
}
