# Changelog

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
