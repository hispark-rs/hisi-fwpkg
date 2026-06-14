//! Post-link **body-hash patching** ("route 2", Part B).
//!
//! With the `hisi-riscv-rt` `boot-header` feature, the linker bakes a complete
//! `0x300`-byte image header into the ELF at flash `0x230000`, including the
//! real `code_area_len` (a linker symbol). The one field the linker *cannot*
//! compute is `code_area_hash` — the SHA-256 of the body — which on-silicon
//! measurement shows flashboot checks even with secure-verify disabled. This
//! module fills it post-link, in place, so a `boot-header` ELF (or an
//! already-headered raw bin) becomes directly bootable.
//!
//! ```text
//! cargo build --features hisi-riscv-rt/boot-header   # bakes header + code_area_len
//! hisi-fwpkg patch-hash <elf>                         # fills code_area_hash
//! probe-rs download <elf>                             # flash the bootable ELF
//! ```

use {
    crate::{
        error::{Error, Result},
        image::{
            APP_KEY_AREA_IMAGE_ID, CODE_AREA_HASH_OFF, CODE_AREA_LEN_OFF, CODE_UNCOMPRESS_LEN_OFF,
            HASH_LEN, IMAGE_HEADER_LEN,
        },
    },
    object::{
        elf::FileHeader32,
        read::elf::{FileHeader, ProgramHeader, SectionHeader},
        Endianness,
    },
    sha2::Digest,
};

/// WS63 app body flash address (header `0x230000` + `0x300`).
const BODY_VADDR: u64 = 0x0023_0300;

const ELF_MAGIC: &[u8] = &[0x7F, b'E', b'L', b'F'];

/// Patch the `code_area_hash` (and, if needed, the length fields) of an
/// already-headered image so flashboot accepts it.
///
/// `input` is either a `boot-header` **ELF** (preferred — patched in place so
/// `probe-rs download`/`cargo flash` work directly) or a raw **bin** whose
/// header sits at offset 0. Returns the patched bytes.
pub fn patch_hash(input: &[u8]) -> Result<Vec<u8>> {
    if input.starts_with(ELF_MAGIC) {
        patch_hash_elf(input)
    } else {
        patch_hash_bin(input)
    }
}

/// Read back the `code_area_hash` (32 bytes) from a patched ELF or bin, for
/// verification/echo. Returns `None` if no header can be located.
pub fn patched_hash(input: &[u8]) -> Option<[u8; HASH_LEN]> {
    let hdr_off = if input.starts_with(ELF_MAGIC) {
        locate_elf(input).ok()?.0
    } else {
        0
    };
    let pos = hdr_off + CODE_AREA_HASH_OFF;
    input.get(pos..pos + HASH_LEN)?.try_into().ok()
}

/// Resolve the header file-offset and the body bytes inside an ELF.
///
/// The header is the `.boot_header` section at flash `0x230000`; the body is the
/// flash-resident `PT_LOAD` content at vaddr `>= 0x230300`. Returns
/// `(header_file_offset, body)` where `body` is flattened (gaps zero-filled),
/// the same way [`crate::elf::flatten_elf`] / `objcopy -O binary` lay it out.
fn locate_elf(elf_bytes: &[u8]) -> Result<(usize, Vec<u8>)> {
    let header =
        FileHeader32::<Endianness>::parse(elf_bytes).map_err(|e| Error::Elf(e.to_string()))?;
    let endian = header.endian().map_err(|e| Error::Elf(e.to_string()))?;

    // --- find the .boot_header section's file offset (= where to write the hash) ---
    let sections = header
        .sections(endian, elf_bytes)
        .map_err(|e| Error::Elf(e.to_string()))?;
    let mut hdr_off: Option<usize> = None;
    for section in sections.iter() {
        let name = sections
            .section_name(endian, section)
            .map_err(|e| Error::Elf(e.to_string()))?;
        if name == b".boot_header" {
            hdr_off = Some(section.sh_offset(endian) as usize);
            break;
        }
    }
    let hdr_off = hdr_off.ok_or_else(|| {
        Error::Elf(
            "no `.boot_header` section found — build with the `boot-header` feature".into(),
        )
    })?;
    if hdr_off + IMAGE_HEADER_LEN > elf_bytes.len() {
        return Err(Error::Elf(".boot_header section truncated in file".into()));
    }

    // --- flatten the body: PT_LOAD content at vaddr >= 0x230300 ---
    let segments = header
        .program_headers(endian, elf_bytes)
        .map_err(|e| Error::Elf(e.to_string()))?;
    let mut loads: Vec<(u64, &[u8])> = Vec::new();
    for ph in segments {
        if ph.p_type(endian) != object::elf::PT_LOAD {
            continue;
        }
        let filesz = ph.p_filesz(endian) as usize;
        if filesz == 0 {
            continue;
        }
        let vaddr = u64::from(ph.p_vaddr(endian));
        if vaddr < BODY_VADDR {
            continue; // header / TCM / non-body LOAD content
        }
        let offset = ph.p_offset(endian) as usize;
        let data = elf_bytes
            .get(offset..offset + filesz)
            .ok_or_else(|| Error::Elf("segment data out of file bounds".into()))?;
        loads.push((vaddr, data));
    }
    if loads.is_empty() {
        return Err(Error::Elf(
            "no app body (PT_LOAD at vaddr >= 0x230300) found".into(),
        ));
    }
    loads.sort_by_key(|(v, _)| *v);
    let end = loads.iter().map(|(v, d)| v + d.len() as u64).max().unwrap();
    let size = usize::try_from(end - BODY_VADDR)
        .map_err(|_| Error::Elf("flattened body too large".into()))?;
    let mut body = vec![0u8; size];
    for (vaddr, data) in loads {
        let start = (vaddr - BODY_VADDR) as usize;
        body[start..start + data.len()].copy_from_slice(data);
    }
    Ok((hdr_off, body))
}

/// Patch a `boot-header` ELF in place: write the body SHA-256 into the
/// `.boot_header` section's `code_area_hash`.
fn patch_hash_elf(elf_bytes: &[u8]) -> Result<Vec<u8>> {
    let (hdr_off, body) = locate_elf(elf_bytes)?;
    let mut out = elf_bytes.to_vec();
    patch_header(&mut out, hdr_off, &body)?;
    Ok(out)
}

/// Patch a raw headered bin in place: header at offset 0, body at `0x300`.
fn patch_hash_bin(bin: &[u8]) -> Result<Vec<u8>> {
    if bin.len() < IMAGE_HEADER_LEN {
        return Err(Error::Elf(format!(
            "bin is {} bytes, smaller than the {IMAGE_HEADER_LEN}-byte header",
            bin.len()
        )));
    }
    // Sanity: the key-area magic should be present at offset 0.
    let magic = u32::from_le_bytes(bin[0..4].try_into().unwrap());
    if magic != APP_KEY_AREA_IMAGE_ID {
        return Err(Error::Elf(format!(
            "bin offset 0 magic 0x{magic:08X} != key-area magic 0x{APP_KEY_AREA_IMAGE_ID:08X}"
        )));
    }
    let mut out = bin.to_vec();
    let body = out[IMAGE_HEADER_LEN..].to_vec();
    patch_header(&mut out, 0, &body)?;
    Ok(out)
}

/// Core patch: given a buffer, the header's file offset, and the full body
/// bytes, read `code_area_len` from the header; the hashed body is its first
/// `code_area_len` bytes (or the whole body if the header length is 0, in which
/// case the length + uncompress-length fields are also filled). Writes the
/// SHA-256 into `code_area_hash`.
fn patch_header(buf: &mut [u8], hdr_off: usize, body: &[u8]) -> Result<()> {
    let len_pos = hdr_off + CODE_AREA_LEN_OFF;
    let code_area_len = u32::from_le_bytes(buf[len_pos..len_pos + 4].try_into().unwrap()) as usize;

    let hashed_len = if code_area_len == 0 {
        // Fall back: header length is unset; hash the whole body and fill the
        // length fields (code_area_len @0x124, code_uncompress_len @0x180).
        let len = u32::try_from(body.len())
            .map_err(|_| Error::OutOfRange(format!("body length {} exceeds u32", body.len())))?;
        buf[len_pos..len_pos + 4].copy_from_slice(&len.to_le_bytes());
        let unc_pos = hdr_off + CODE_UNCOMPRESS_LEN_OFF;
        buf[unc_pos..unc_pos + 4].copy_from_slice(&len.to_le_bytes());
        body.len()
    } else {
        if code_area_len > body.len() {
            return Err(Error::OutOfRange(format!(
                "code_area_len 0x{code_area_len:X} exceeds body length 0x{:X}",
                body.len()
            )));
        }
        code_area_len
    };

    let mut hasher = sha2::Sha256::new();
    hasher.update(&body[..hashed_len]);
    let digest = hasher.finalize();

    let hash_pos = hdr_off + CODE_AREA_HASH_OFF;
    buf[hash_pos..hash_pos + HASH_LEN].copy_from_slice(&digest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::image::{build_app_image, ImageOptions, CODE_AREA_LEN_OFF, CODE_UNCOMPRESS_LEN_OFF},
        sha2::Digest,
    };

    fn sha256(b: &[u8]) -> [u8; HASH_LEN] {
        let mut h = sha2::Sha256::new();
        h.update(b);
        h.finalize().into()
    }

    #[test]
    fn bin_patch_fills_real_hash() {
        let body = vec![0x42u8; 4096];
        // A fully-built image already has the right hash; zero it then re-patch.
        let mut img = build_app_image(&body, &ImageOptions::default()).unwrap();
        img[CODE_AREA_HASH_OFF..CODE_AREA_HASH_OFF + HASH_LEN].fill(0);
        let out = patch_hash(&img).unwrap();
        assert_eq!(
            &out[CODE_AREA_HASH_OFF..CODE_AREA_HASH_OFF + HASH_LEN],
            &sha256(&body)
        );
    }

    #[test]
    fn bin_patch_fallback_fills_lengths() {
        let body = vec![0x11u8; 1000];
        let mut img = build_app_image(&body, &ImageOptions::default()).unwrap();
        // Zero the length fields and the hash to exercise the fallback path.
        img[CODE_AREA_LEN_OFF..CODE_AREA_LEN_OFF + 4].fill(0);
        img[CODE_UNCOMPRESS_LEN_OFF..CODE_UNCOMPRESS_LEN_OFF + 4].fill(0);
        img[CODE_AREA_HASH_OFF..CODE_AREA_HASH_OFF + HASH_LEN].fill(0);
        let out = patch_hash(&img).unwrap();
        let len = u32::from_le_bytes(
            out[CODE_AREA_LEN_OFF..CODE_AREA_LEN_OFF + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(len as usize, body.len());
        assert_eq!(
            u32::from_le_bytes(
                out[CODE_UNCOMPRESS_LEN_OFF..CODE_UNCOMPRESS_LEN_OFF + 4]
                    .try_into()
                    .unwrap()
            ) as usize,
            body.len()
        );
        assert_eq!(
            &out[CODE_AREA_HASH_OFF..CODE_AREA_HASH_OFF + HASH_LEN],
            &sha256(&body)
        );
    }
}
