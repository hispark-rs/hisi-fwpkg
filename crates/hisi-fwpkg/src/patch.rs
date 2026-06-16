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
/// `(header_file_offset, body)` where `body` is flattened (gaps 0xFF-filled to
/// match erased flash, so the hash agrees with flashboot's contiguous read),
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
        Error::Elf("no `.boot_header` section found — build with the `boot-header` feature".into())
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
        // Lay the body out by PHYSICAL (load) address, NOT virtual address. The
        // flash image is programmed at each segment's LMA (`p_paddr`) and flashboot
        // reads it back contiguously from flash, so the hashed body must mirror the
        // flash layout. They differ for any segment that runs from RAM but is
        // initialized from flash — e.g. `.data` has `p_vaddr` in SRAM (0xa0c000)
        // but `p_paddr` at its flash LMA (~0x23ba60). Using `p_vaddr` here misplaces
        // `.data` to a huge offset and leaves its real flash position as fill, so the
        // hash disagrees with flashboot over those bytes → boot ROM "VE" (verify
        // error). This is latent for gap-free, all-flash binaries (where vaddr==paddr).
        let paddr = u64::from(ph.p_paddr(endian));
        if paddr < BODY_VADDR {
            continue; // header / pre-body LOAD content
        }
        let offset = ph.p_offset(endian) as usize;
        let data = elf_bytes
            .get(offset..offset + filesz)
            .ok_or_else(|| Error::Elf("segment data out of file bounds".into()))?;
        loads.push((paddr, data));
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
    // Fill inter-segment gaps with the ERASED-flash value (0xFF), NOT 0x00.
    // flashboot verifies the body by SHA-256'ing `code_area_len` CONTIGUOUS bytes
    // straight from flash, where any alignment gap between flash-resident sections
    // (e.g. between `.init.trap` and an initialized `.data`'s LMA) is left erased
    // (0xFF) — the flash loader erases the sector and only programs the segments,
    // never the gaps. Zero-filling gaps here makes our hash disagree with
    // flashboot's over those bytes, so the boot ROM rejects the image ("VE",
    // verify error) and never starts the app — but ONLY for binaries that have
    // such a gap (i.e. an initialized `.data` section); a gap-free body hashes the
    // same either way, which is why this stayed latent until a `.data`-carrying
    // image was flashed. 0xFF matches the algorithm's `empty_value`.
    let mut body = vec![0xFFu8; size];
    for (paddr, data) in loads {
        let start = (paddr - BODY_VADDR) as usize;
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

    /// Hand-build a minimal ELF32-LE executable with a `.boot_header` section and
    /// two PT_LOAD segments: a flash-resident `.text` (vaddr==paddr) and a
    /// `.data`-like segment whose `p_vaddr` is in RAM but whose `p_paddr` (flash
    /// LMA) sits inside the body, just past an alignment gap. Returns the ELF bytes
    /// plus the parameters needed to compute the expected body.
    ///
    /// `code_area_len` covers `[0x230300, data_lma + data.len())`, so the body
    /// includes the inter-segment gap.
    fn build_elf_with_data_segment() -> Vec<u8> {
        const PT_LOAD: u32 = 1;
        let text = vec![0xAAu8; 0x40]; // .text @ vaddr=paddr=0x230300
        let data = vec![0xCCu8; 0x20]; // .data @ vaddr=0xa0c000, paddr=0x230360
        let text_lma: u32 = BODY_VADDR as u32; // 0x230300
        let data_lma: u32 = 0x230360; // gap [0x230340, 0x230360) before it
        let code_area_len: u32 = (data_lma + data.len() as u32) - BODY_VADDR as u32; // 0x80

        // boot header: zeros except code_area_len @ 0x124; hash @0x128 stays zero.
        let mut hdr = vec![0u8; IMAGE_HEADER_LEN];
        hdr[CODE_AREA_LEN_OFF..CODE_AREA_LEN_OFF + 4].copy_from_slice(&code_area_len.to_le_bytes());

        let shstrtab = b"\0.boot_header\0.shstrtab\0"; // names @1 and @14

        // File layout (sequential).
        let ehdr_len = 52usize;
        let phentsize = 32usize;
        let phnum = 2usize;
        let phoff = ehdr_len;
        let hdr_off = phoff + phentsize * phnum; // 0x74
        let text_off = hdr_off + hdr.len();
        let data_off = text_off + text.len();
        let shstr_off = data_off + data.len();
        let shoff = shstr_off + shstrtab.len();
        let shentsize = 40usize;
        let shnum = 3usize;

        let mut e = Vec::new();
        let p16 = |e: &mut Vec<u8>, v: u16| e.extend_from_slice(&v.to_le_bytes());
        let p32 = |e: &mut Vec<u8>, v: u32| e.extend_from_slice(&v.to_le_bytes());

        // --- ELF header (e_ident + fields) ---
        e.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]); // magic, class32, LE, ver, sysv
        e.extend_from_slice(&[0u8; 8]); // abiversion + pad
        p16(&mut e, 2); // e_type ET_EXEC
        p16(&mut e, 0xF3); // e_machine EM_RISCV
        p32(&mut e, 1); // e_version
        p32(&mut e, text_lma); // e_entry
        p32(&mut e, phoff as u32);
        p32(&mut e, shoff as u32);
        p32(&mut e, 0); // e_flags
        p16(&mut e, ehdr_len as u16);
        p16(&mut e, phentsize as u16);
        p16(&mut e, phnum as u16);
        p16(&mut e, shentsize as u16);
        p16(&mut e, shnum as u16);
        p16(&mut e, 2); // e_shstrndx (.shstrtab)
        assert_eq!(e.len(), ehdr_len);

        // --- program headers ---
        // .text: vaddr == paddr (flash-resident, like real .text/.rodata)
        p32(&mut e, PT_LOAD);
        p32(&mut e, text_off as u32);
        p32(&mut e, text_lma); // p_vaddr
        p32(&mut e, text_lma); // p_paddr
        p32(&mut e, text.len() as u32); // p_filesz
        p32(&mut e, text.len() as u32); // p_memsz
        p32(&mut e, 5); // R+X
        p32(&mut e, 0x1000);
        // .data: vaddr in RAM, paddr (LMA) in flash — THE case the bug mishandled.
        p32(&mut e, PT_LOAD);
        p32(&mut e, data_off as u32);
        p32(&mut e, 0x00a0_c000); // p_vaddr (SRAM) — must NOT be used for layout
        p32(&mut e, data_lma); // p_paddr (flash LMA) — the correct layout key
        p32(&mut e, data.len() as u32);
        p32(&mut e, data.len() as u32);
        p32(&mut e, 6); // R+W
        p32(&mut e, 8);
        assert_eq!(e.len(), hdr_off);

        // --- section/segment data blobs ---
        e.extend_from_slice(&hdr);
        e.extend_from_slice(&text);
        e.extend_from_slice(&data);
        e.extend_from_slice(shstrtab);
        assert_eq!(e.len(), shoff);

        // --- section headers (null, .boot_header, .shstrtab) ---
        let push_shdr =
            |e: &mut Vec<u8>, name: u32, ty: u32, flags: u32, addr: u32, off: u32, size: u32| {
                p32(e, name);
                p32(e, ty);
                p32(e, flags);
                p32(e, addr);
                p32(e, off);
                p32(e, size);
                p32(e, 0); // sh_link
                p32(e, 0); // sh_info
                p32(e, 1); // sh_addralign
                p32(e, 0); // sh_entsize
            };
        push_shdr(&mut e, 0, 0, 0, 0, 0, 0); // SHT_NULL
        push_shdr(&mut e, 1, 1, 2, 0x230000, hdr_off as u32, hdr.len() as u32); // .boot_header PROGBITS/ALLOC
        push_shdr(&mut e, 14, 3, 0, 0, shstr_off as u32, shstrtab.len() as u32); // .shstrtab STRTAB
        e
    }

    /// Regression: an ELF carrying an initialized `.data` (p_vaddr in RAM, p_paddr
    /// in flash) plus an alignment gap must hash the body the way flashboot reads it
    /// — segments placed by FLASH (load) address, gaps left at the erased value
    /// 0xFF. Laying the body out by `p_vaddr` (the old bug) or zero-filling gaps
    /// would mishash and the boot ROM would reject the image ("VE"). Verified on
    /// real WS63 silicon (19/19 HAL HIL driver tests) once this was fixed.
    #[test]
    fn elf_data_segment_hashed_by_load_address_with_ff_gaps() {
        let elf = build_elf_with_data_segment();
        let out = patch_hash(&elf).unwrap();

        // Expected body = the exact flash image flashboot verifies:
        //   [0x00..0x40) .text 0xAA | [0x40..0x60) gap 0xFF | [0x60..0x80) .data 0xCC
        let mut expected = vec![0xFFu8; 0x80];
        expected[0x00..0x40].fill(0xAA);
        expected[0x60..0x80].fill(0xCC);
        let expected_hash = sha256(&expected);

        // The hash is written into the .boot_header section, whose file offset we
        // re-resolve via the same path patch_hash uses.
        let (hdr_off, _) = locate_elf(&out).unwrap();
        let got = &out[hdr_off + CODE_AREA_HASH_OFF..hdr_off + CODE_AREA_HASH_OFF + HASH_LEN];
        assert_eq!(
            got, &expected_hash,
            "body must be hashed by p_paddr with 0xFF gaps"
        );

        // Guard the guard: the buggy reconstructions (0x00 gaps, or .data missing
        // from its flash position) must NOT collide with the correct hash.
        let mut zero_gap = expected.clone();
        zero_gap[0x40..0x60].fill(0x00);
        assert_ne!(got, &sha256(&zero_gap)[..], "0x00 gap fill must differ");
        let mut no_data = vec![0xFFu8; 0x80];
        no_data[0x00..0x40].fill(0xAA); // .data left as fill (vaddr-misplaced)
        assert_ne!(
            got,
            &sha256(&no_data)[..],
            "vaddr-misplaced .data must differ"
        );
    }
}
