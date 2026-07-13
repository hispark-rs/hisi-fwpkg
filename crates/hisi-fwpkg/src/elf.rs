//! ELF → raw binary flattening (the `objcopy -O binary` equivalent).
//!
//! Embedded segments can execute from RAM while being loaded from flash. The
//! flash image must therefore be laid out by each `PT_LOAD` segment's physical
//! address (`p_paddr`, the LMA), not its virtual address (`p_vaddr`, the VMA).
//! Gaps are materialized as erased flash (`0xFF`) so the output matches the
//! bytes flashboot hashes over its contiguous code area.

use {
    crate::error::{Error, Result},
    object::{
        elf::FileHeader32,
        read::elf::{FileHeader, ProgramHeader},
        Endianness,
    },
};

/// Flatten an ELF executable's `PT_LOAD` segments into a contiguous binary
/// image, returning `(image, base_paddr)`.
///
/// `base_paddr` is the lowest segment load address — the flash address the
/// image's first byte corresponds to. Gaps between segments are filled with
/// `0xFF`, the erased NOR value.
pub fn flatten_elf(elf_bytes: &[u8]) -> Result<(Vec<u8>, u64)> {
    let header =
        FileHeader32::<Endianness>::parse(elf_bytes).map_err(|e| Error::Elf(e.to_string()))?;
    let endian = header.endian().map_err(|e| Error::Elf(e.to_string()))?;
    let segments = header
        .program_headers(endian, elf_bytes)
        .map_err(|e| Error::Elf(e.to_string()))?;

    // Collect loadable segments with on-disk data (filesz > 0).
    let mut loads: Vec<(u64, &[u8])> = Vec::new();
    for ph in segments {
        if ph.p_type(endian) != object::elf::PT_LOAD {
            continue;
        }
        let filesz = ph.p_filesz(endian) as usize;
        if filesz == 0 {
            continue; // .bss-like: no on-disk bytes to emit
        }
        let paddr = u64::from(ph.p_paddr(endian));
        let offset = ph.p_offset(endian) as usize;
        let data = elf_bytes
            .get(offset..offset + filesz)
            .ok_or_else(|| Error::Elf("segment data out of file bounds".into()))?;
        loads.push((paddr, data));
    }

    if loads.is_empty() {
        return Err(Error::Elf("no loadable PT_LOAD segments with data".into()));
    }

    loads.sort_by_key(|(v, _)| *v);
    let base = loads[0].0;
    let end = loads.iter().map(|(v, d)| v + d.len() as u64).max().unwrap();
    let size =
        usize::try_from(end - base).map_err(|_| Error::Elf("flattened image too large".into()))?;

    let mut image = vec![0xFFu8; size];
    for (paddr, data) in loads {
        let start = (paddr - base) as usize;
        image[start..start + data.len()].copy_from_slice(data);
    }
    Ok((image, base))
}

#[cfg(test)]
mod tests {
    use super::flatten_elf;

    fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_load(
        elf: &mut [u8],
        ph_offset: usize,
        file_offset: u32,
        vaddr: u32,
        paddr: u32,
        file_size: u32,
    ) {
        put_u32(elf, ph_offset, 1); // PT_LOAD
        put_u32(elf, ph_offset + 4, file_offset);
        put_u32(elf, ph_offset + 8, vaddr);
        put_u32(elf, ph_offset + 12, paddr);
        put_u32(elf, ph_offset + 16, file_size);
        put_u32(elf, ph_offset + 20, file_size);
        put_u32(elf, ph_offset + 24, 5); // PF_R | PF_X
        put_u32(elf, ph_offset + 28, 4);
    }

    #[test]
    fn flattens_by_load_address_and_materializes_erased_gaps() {
        let mut elf = vec![0u8; 0x120];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 1; // ELFCLASS32
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        put_u16(&mut elf, 16, 2); // ET_EXEC
        put_u16(&mut elf, 18, 243); // EM_RISCV
        put_u32(&mut elf, 20, 1);
        put_u32(&mut elf, 28, 52); // e_phoff
        put_u16(&mut elf, 40, 52); // e_ehsize
        put_u16(&mut elf, 42, 32); // e_phentsize
        put_u16(&mut elf, 44, 3); // e_phnum

        // The VMAs are far apart and out of flash order. Their LMAs are close
        // and define the emitted image layout.
        put_load(&mut elf, 52, 0x100, 0x00A0_0000, 0x0023_0300, 3);
        put_load(&mut elf, 84, 0x110, 0x0014_C000, 0x0023_0310, 2);
        // A NOLOAD/BSS segment at a remote LMA must not extend the image.
        put_load(&mut elf, 116, 0, 0x00A8_0000, 0x00A8_0000, 0);
        elf[0x100..0x103].copy_from_slice(&[1, 2, 3]);
        elf[0x110..0x112].copy_from_slice(&[4, 5]);

        let (image, base) = flatten_elf(&elf).unwrap();
        assert_eq!(base, 0x0023_0300);
        assert_eq!(image.len(), 0x12);
        assert_eq!(&image[..3], &[1, 2, 3]);
        assert!(image[3..0x10].iter().all(|byte| *byte == 0xFF));
        assert_eq!(&image[0x10..], &[4, 5]);
    }
}
