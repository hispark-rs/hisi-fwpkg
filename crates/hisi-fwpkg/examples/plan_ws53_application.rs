//! Development planner only. No device I/O, signing or hardware qualification.
use hisi_fwpkg::ws53::plan_unsigned_application;
use sha2::{Digest, Sha256};
use std::{io::Write, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err(
            "usage: plan_ws53_application RAW_FULL_BACKUP FLASH_LINKED_APP_BIN NEW_OUTPUT_DIR"
                .into(),
        );
    }
    let backup = std::fs::read(&args[1])?;
    let app = std::fs::read(&args[2])?;
    // This raw-bin planner does not infer entry/segments from a RAM ELF.
    if app.starts_with(b"\x7fELF") {
        return Err("expected validated Flash-linked raw bytes, not ELF".into());
    }
    let plan = plan_unsigned_application(&backup, &app)?;
    let out = PathBuf::from(&args[3]);
    std::fs::create_dir(&out)?;
    let mut manifest = String::from("offset\tlength\toriginal_sha256\treplacement_sha256\n");
    for sector in &plan.sectors {
        for (suffix, bytes) in [
            ("original", &sector.original),
            ("replacement", &sector.replacement),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out.join(format!("{:06x}-{suffix}.bin", sector.offset)))?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        manifest += &format!(
            "{:#x}\t{}\t{:x}\t{:x}\n",
            sector.offset,
            sector.original.len(),
            Sha256::digest(&sector.original),
            Sha256::digest(&sector.replacement)
        );
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join("sectors.tsv"))?;
    file.write_all(manifest.as_bytes())?;
    file.sync_all()?;
    println!("entry={:#x} sectors={} backup_sha256={:x} requires_secure_boot_disabled=true signatures_regenerated=false hardware_verified=false",plan.entry,plan.sectors.len(),Sha256::digest(&backup));
    Ok(())
}
