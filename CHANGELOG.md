# Changelog

## 0.3.0 — 2026-07-09

### Added

- Added the library-level `FlashPlan` API and `hisi-fwpkg plan` CLI path as the canonical image semantics source for smoke/download tooling. Plans expose the flash base address, image length, body range, code-area length/hash, erase range, write chunks, and optional source fwpkg partition metadata.
- Added `--image-output` for `plan`, producing the complete flash image that generic downloaders can write with `probe-rs download --binary-format bin --base-address <plan.base_addr>`.
- Added fwpkg parsing metadata so downstream tools can report partition layout and CRC status through the same parser semantics.

### Changed

- ELF planning now expands `PT_LOAD` segments by physical load address with `0xFF` gaps, matching the flashboot continuous-read hash model.
- Documented `patch-hash` as the ELF `probe-rs run` / embedded-test exception path; ordinary smoke/download flows should use `plan --image-output`.

## 0.2.1 — 2026-06-16

### Fixed

- `patch-hash`: lay the verified body out by each PT_LOAD's **physical (load)
  address** (`p_paddr`), not its virtual address, and fill inter-segment gaps
  with the erased-flash value **`0xFF`** (not `0x00`). flashboot verifies a
  `boot-header` image by SHA-256'ing `code_area_len` bytes read **contiguously
  from flash** — each section at its flash LMA, alignment gaps left erased — so
  the hash we patch in must mirror that exact image. The old `p_vaddr` layout
  misplaced any segment that *runs* from RAM but is *initialized* from flash
  (an `.data` whose `p_vaddr` is in SRAM but whose `p_paddr` is its flash LMA),
  leaving its real flash position as fill, and zero-filling the gaps; either
  makes the body hash disagree with flashboot, so the boot ROM rejects the image
  (UART `VE`, verify error) and the app never starts. This was latent because a
  gap-free, all-flash binary (no initialized `.data`) has `vaddr == paddr` and no
  gaps, hashing the same either way. Now any `.data`-carrying boot-header ELF
  boots. **Verified on real WS63 silicon**: the hisi-riscv-hal on-target HIL
  driver suite (19/19) passes once images are patched with the fixed tool.

## 0.2.0 — 2026-06-14

- `patch-hash` subcommand: fills `code_area_hash` (the body SHA-256) into an
  already-headered image/ELF post-link. Companion to hisi-riscv-rt's
  `boot-header` feature — flashboot checks the body hash even with secure-verify
  disabled, so a link-time header needs the hash patched after linking. Handles
  ELF (finds `.boot_header` + body from PT_LOAD ≥ `0x230300`) and raw bin.
- Published to crates.io as `hisi-fwpkg` + `hisi-fwpkg-cli` 0.2.0 (first
  crates.io release of this tool).

## 0.1.0

Initial release.

- `hisi-fwpkg` library: build WS63/BS2X app image headers (key area
  `0x4B0F2D1E` + code-info `0x4B0F2D2D`, SHA-256 body hash, dummy ECC
  signatures) and fwpkg V1 containers (partition table + CRC16/XMODEM).
- ELF flattening (`objcopy -O binary` equivalent) behind the `elf` feature.
- `hisi-fwpkg` CLI: `image` (ELF/bin -> app image) and `pack` (ELF/bin ->
  app-only fwpkg), with `--chip ws63|bs21` and `--app-addr` overrides.
- Vendor parity test: rebuilt header is byte-identical to the official
  `ws63-liteos-app-sign.bin` except the two ECC signature blobs.
