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

use crate::error::{Error, Result};

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

/// Partition burn type (the `type` field of `IMAGE_INFO`).
///
/// Mirrors the vendor packer's per-partition `type` value: loaderboot is `0`,
/// ordinary partitions (ssb / flashboot / nv / app / params) are `1`, KV is
/// `2`, efuse is `3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    /// LoaderBoot (first-stage loader) — type 0.
    Loader,
    /// Ordinary partition — type 1 (ssb, flashboot, nv, params, app, ...).
    Normal,
    /// Key-Value NV — type 2.
    KvNv,
    /// eFuse config — type 3.
    Efuse,
    /// Any other raw type code.
    Other(u32),
}

impl PartitionType {
    /// Numeric value written to the `type` field.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Loader => 0,
            Self::Normal => 1,
            Self::KvNv => 2,
            Self::Efuse => 3,
            Self::Other(v) => v,
        }
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
