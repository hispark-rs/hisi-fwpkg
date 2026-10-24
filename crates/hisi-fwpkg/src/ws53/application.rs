//! Combined-control/application image planning from an existing WS53 backup.
use super::word;
use crate::{Error, Result};
use sha2::{Digest, Sha256};

/// One complete sector, with the original bytes needed for explicit recovery.
#[derive(Debug)]
pub struct ApplicationSector {
    /// Physical Flash offset, not CPU-mapped address.
    pub offset: u32,
    /// Original full-sector contents; persist before programming.
    pub original: Vec<u8>,
    /// Replacement full-sector contents.
    pub replacement: Vec<u8>,
}

/// Experimental plaintext application replacement. No device access occurs.
#[derive(Debug)]
pub struct ApplicationPlan {
    /// CPU entry address expected by the existing vendor flashboot.
    pub entry: u32,
    /// App sectors first, combined-header sector last. No control payload edit.
    pub sectors: Vec<ApplicationSector>,
    /// SHA-256 of the complete input backup, including untouched NV.
    pub backup_sha256: [u8; 32],
    /// SHA-256 of the resulting combined code body.
    pub combined_body_sha256: [u8; 32],
    /// Always true: this function does not regenerate cryptographic signatures.
    pub requires_secure_boot_disabled: bool,
}

fn invalid(message: &str) -> Error {
    Error::InvalidFwpkg(format!("WS53 application: {message}"))
}

/// Plan a plaintext XIP application at0x45d300, preserving the original control
/// payload, partition table, application placeholder, calibration/NV, key and
/// security policy bytes. Only changed whole sectors are emitted. The original
/// combined body length and unused old application tail remain unchanged.
///
/// Qualified layout:4MiB, combined0x30000+0x240000, app0x5d000+0x213000.
/// Rejects encrypted/compressed input, malformed/overlapping partitions, bad
/// body hash and applications exceeding the original signed-body envelope.
/// This is NOT a signer: updating the hash invalidates any original code-info
/// signature. Before using this plan, caller must establish that secure boot
/// is disabled without changing eFuse/security settings, validate ELF entry,
/// ABI/segments/startup, and qualify the actual device and raw backup mapping.
/// The bytes must be a Flash-linked app, never a RAM takeover binary. Hardware
/// reset/cold boot and restoration must be tested separately.
pub fn plan_unsigned_application(backup: &[u8], application: &[u8]) -> Result<ApplicationPlan> {
    if backup.len() != 0x400000 || application.is_empty() {
        return Err(invalid("requires full4MiB backup and nonempty application"));
    }
    let table = 0x380;
    if word(backup, table) != 0x4b87a52d || word(backup, table + 4) != 0x10000 {
        return Err(invalid("unrecognized partition table"));
    }
    let count = usize::from(backup[table + 14]);
    let items = usize::from(u16::from_le_bytes([backup[table + 12], backup[table + 13]]));
    if count == 0
        || count > 32
        || items < 15 + count
        || items % 4 != 0
        || table + items + count * 8 > 0x800
    {
        return Err(invalid("invalid partition record bounds"));
    }
    let mut parts = Vec::new();
    for index in 0..count {
        let id = backup[table + 15 + index];
        let start = word(backup, table + items + index * 8) as usize;
        let len = word(backup, table + items + index * 8 + 4) as usize;
        if start > backup.len()
            || len > backup.len() - start
            || parts.iter().any(|&(i, _, _)| i == id)
        {
            return Err(invalid("duplicate or out-of-range partition"));
        }
        parts.push((id, start, len));
    }
    if !parts.contains(&(0x20, 0x30000, 0x240000)) || !parts.contains(&(0x21, 0x5d000, 0x213000)) {
        return Err(invalid("unsupported combined/application layout"));
    }
    for (index, &(id, start, len)) in parts.iter().enumerate() {
        for &(other, other_start, other_len) in &parts[index + 1..] {
            if len != 0
                && other_len != 0
                && start.max(other_start) < (start + len).min(other_start + other_len)
                && !((id == 0x20 && other == 0x21) || (id == 0x21 && other == 0x20))
            {
                return Err(invalid("unexpected overlapping partitions"));
            }
        }
    }
    let base = 0x30000;
    for (offset, expected) in [
        (0, 0x4b0f2d1e),
        (4, 0x10000),
        (8, 0x100),
        (0x48, 0),
        (0x100, 0x4b0f2d2d),
        (0x104, 0x10000),
        (0x108, 0x200),
        (0x120, 0),
        (0x148, 0x3c7896e1),
        (0x17c, 0),
    ] {
        if word(backup, base + offset) != expected {
            return Err(invalid("unsupported combined header/policy"));
        }
    }
    let length = word(backup, base + 0x124) as usize;
    if !(0x2d000..=0x23fd00).contains(&length) {
        return Err(invalid(
            "combined body does not include application or exceeds partition",
        ));
    }
    let body_end = base + 0x300 + length;
    let body = &backup[base + 0x300..body_end];
    let digest: [u8; 32] = Sha256::digest(body).into();
    if backup[base + 0x128..base + 0x148] != digest {
        return Err(invalid("original combined body hash mismatch"));
    }
    if backup[0x5d000..0x5d300].iter().any(|&b| b != 0) || application.len() > body_end - 0x5d300 {
        return Err(invalid(
            "unsupported application placeholder or payload size",
        ));
    }
    let mut changed = backup[..body_end].to_vec();
    changed[0x5d300..0x5d300 + application.len()].copy_from_slice(application);
    let combined_body_sha256: [u8; 32] = Sha256::digest(&changed[base + 0x300..]).into();
    changed[base + 0x128..base + 0x148].copy_from_slice(&combined_body_sha256);
    let mut sectors = Vec::new();
    for offset in (0x5d000..0x5d300 + application.len())
        .step_by(4096)
        .chain(std::iter::once(base))
    {
        let mut replacement = backup[offset..offset + 4096].to_vec();
        let end = (offset + 4096).min(changed.len());
        replacement[..end - offset].copy_from_slice(&changed[offset..end]);
        if replacement != backup[offset..offset + 4096] {
            sectors.push(ApplicationSector {
                offset: offset as u32,
                original: backup[offset..offset + 4096].to_vec(),
                replacement,
            });
        }
    }
    Ok(ApplicationPlan {
        entry: 0x45d300,
        sectors,
        backup_sha256: Sha256::digest(backup).into(),
        combined_body_sha256,
        requires_secure_boot_disabled: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(b: &mut [u8], offset: usize, value: u32) {
        b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> Vec<u8> {
        let mut b = vec![0xff; 0x400000];
        put(&mut b, 0x380, 0x4b87a52d);
        put(&mut b, 0x384, 0x10000);
        b[0x38c..0x38f].copy_from_slice(&[20, 0, 3]);
        b[0x38f..0x392].copy_from_slice(&[0x20, 0x21, 0x10]);
        for (i, (start, len)) in [(0x30000, 0x240000), (0x5d000, 0x213000), (0x3fc000, 0x4000)]
            .into_iter()
            .enumerate()
        {
            put(&mut b, 0x394 + 8 * i, start);
            put(&mut b, 0x398 + 8 * i, len);
        }
        for (offset, value) in [
            (0, 0x4b0f2d1e),
            (4, 0x10000),
            (8, 0x100),
            (0x48, 0),
            (0x100, 0x4b0f2d2d),
            (0x104, 0x10000),
            (0x108, 0x200),
            (0x120, 0),
            (0x124, 0x40000),
            (0x148, 0x3c7896e1),
            (0x17c, 0),
        ] {
            put(&mut b, 0x30000 + offset, value);
        }
        b[0x30300..0x5d000].fill(0x42);
        b[0x5d000..0x5d300].fill(0);
        let hash = Sha256::digest(&b[0x30300..0x70300]);
        b[0x30128..0x30148].copy_from_slice(&hash);
        b
    }
    #[test]
    fn preserve_control_and_all_nontarget_bytes_with_recovery_sectors() {
        let b = fixture();
        let app = vec![0x33; 8192];
        let plan = plan_unsigned_application(&b, &app).unwrap();
        assert_eq!(plan.entry, 0x45d300);
        assert!(plan.requires_secure_boot_disabled);
        assert_eq!(plan.sectors.last().unwrap().offset, 0x30000);
        let mut after = b.clone();
        for sector in &plan.sectors {
            let start = sector.offset as usize;
            assert_eq!(sector.original, &b[start..start + 4096]);
            after[start..start + 4096].copy_from_slice(&sector.replacement);
        }
        assert_eq!(&after[0x5d300..0x5d300 + app.len()], app);
        for (index, (&old, &new)) in b.iter().zip(&after).enumerate() {
            if old != new {
                assert!(
                    (0x30128..0x30148).contains(&index)
                        || (0x5d300..0x5d300 + app.len()).contains(&index)
                );
            }
        }
        assert!(plan_unsigned_application(&after, &app)
            .unwrap()
            .sectors
            .is_empty());
        for sector in &plan.sectors {
            let start = sector.offset as usize;
            after[start..start + 4096].copy_from_slice(&sector.original);
        }
        assert_eq!(after, b);
    }
    #[test]
    fn malformed_tables_hash_and_security_policy_are_rejected() {
        let b = fixture();
        for offset in [
            0x380, 0x38c, 0x390, 0x39c, 0x30000, 0x30120, 0x30124, 0x30148, 0x3017c, 0x5d000,
            0x61000,
        ] {
            let mut damaged = b.clone();
            damaged[offset] ^= 1;
            assert!(
                plan_unsigned_application(&damaged, &[1; 4]).is_err(),
                "offset {offset:x}"
            );
        }
        for count in [0, 33, 255] {
            let mut damaged = b.clone();
            damaged[0x38e] = count;
            assert!(plan_unsigned_application(&damaged, &[1; 4]).is_err());
        }
        let mut overlap = b.clone();
        put(&mut overlap, 0x3a4, 0x60000);
        assert!(plan_unsigned_application(&overlap, &[1; 4]).is_err());
        assert!(plan_unsigned_application(&b[..1000], &[1; 4]).is_err());
        assert!(plan_unsigned_application(&b, &[]).is_err());
        assert!(plan_unsigned_application(&b, &vec![1; 0x20000]).is_err());
    }
}
