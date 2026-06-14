# Changelog

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
