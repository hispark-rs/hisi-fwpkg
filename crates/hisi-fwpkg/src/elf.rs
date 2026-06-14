//! ELF → raw binary flattening (the `objcopy -O binary` equivalent).
//!
//! WS63/BS2X apps are linked to run execute-in-place from flash. The runtime
//! linker script already places `.text` at the post-header address (e.g.
//! `0x230300` for WS63). Flattening therefore just concatenates the loadable
//! (`PT_LOAD`) segments in ascending virtual-address order, zero-filling the
//! gaps between them — identical to what `objcopy -O binary` emits and to the
//! raw `.bin` the existing `hil/flash.sh` produces.

use {
    crate::error::{Error, Result},
    object::{
        elf::FileHeader32,
        read::elf::{FileHeader, ProgramHeader},
        Endianness,
    },
};

/// Flatten an ELF executable's `PT_LOAD` segments into a contiguous binary
/// image, returning `(image, base_vaddr)`.
///
/// `base_vaddr` is the lowest segment virtual address — the flash address the
/// image's first byte corresponds to. Gaps between segments are zero-filled.
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
        let vaddr = u64::from(ph.p_vaddr(endian));
        let offset = ph.p_offset(endian) as usize;
        let data = elf_bytes
            .get(offset..offset + filesz)
            .ok_or_else(|| Error::Elf("segment data out of file bounds".into()))?;
        loads.push((vaddr, data));
    }

    if loads.is_empty() {
        return Err(Error::Elf("no loadable PT_LOAD segments with data".into()));
    }

    loads.sort_by_key(|(v, _)| *v);
    let base = loads[0].0;
    let end = loads.iter().map(|(v, d)| v + d.len() as u64).max().unwrap();
    let size =
        usize::try_from(end - base).map_err(|_| Error::Elf("flattened image too large".into()))?;

    let mut image = vec![0u8; size];
    for (vaddr, data) in loads {
        let start = (vaddr - base) as usize;
        image[start..start + data.len()].copy_from_slice(data);
    }
    Ok((image, base))
}
