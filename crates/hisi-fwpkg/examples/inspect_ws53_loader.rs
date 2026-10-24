//! Inspect a local vendor package; no serial/device I/O.
use sha2::{Digest, Sha256};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: inspect_ws53_loader package.bin")?;
    let bytes = std::fs::read(path)?;
    let loader = hisi_fwpkg::ws53::inspect_loader(&bytes)?;
    println!("size={} body={} sha256={:x} placeholder_root={} enc_flag={:#x} signature_verified=false chip_identity_verified=false",
        loader.package.len(), loader.body.len(), Sha256::digest(loader.package),
        loader.has_placeholder_root, loader.code_encryption_flag);
    Ok(())
}
