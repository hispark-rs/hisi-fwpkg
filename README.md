# hisi-fwpkg

Build HiSilicon **application images** and **fwpkg** firmware packages from a
compiled program (ELF or raw `.bin`), for chips in the WS63 / BS2X family.

`probe-rs` / `hisiflash` can write bytes to a WS63's flash, but flashboot does
**not** boot a bare ELF/bin: it expects the app partition (flash `0x230000` on
WS63) to hold a HiSilicon *app image* — a fixed `0x300`-byte header followed by
the code. This crate produces that image and wraps it in the `fwpkg` container
that `hisiflash` flashes.

It is the **producer** counterpart to
[`hisiflash`](https://github.com/hispark-rs/hisiflash)'s fwpkg **parser**.

```text
ELF / .bin ──▶ flatten (objcopy) ──▶ 0x300 image header + body ──▶ fwpkg (V1)
              hisi_fwpkg::elf        hisi_fwpkg::image            hisi_fwpkg::fwpkg
```

## CLI

```bash
cargo install --path crates/hisi-fwpkg-cli      # installs `hisi-fwpkg`

# ELF/bin -> app image -> single-partition fwpkg (app only):
hisi-fwpkg pack blinky -o blinky.fwpkg --chip ws63

# Just the raw app image (0x300 header || body), e.g. to burn at 0x230000:
hisi-fwpkg image blinky -o blinky.img

# Override the app partition address / chip:
hisi-fwpkg pack app.elf -o app.fwpkg --chip bs21
hisi-fwpkg pack app.bin -o app.fwpkg --app-addr 0x230000
```

Validate the result statically with `hisiflash`:

```console
$ hisiflash info blinky.fwpkg
  格式: V1 (32-byte names)
  分区数: 1
  CRC 有效: 是
  [ 0] app   烧录地址: 0x00230000   长度: 5984 字节
```

## Library

```rust
use hisi_fwpkg::{Chip, pack_app_fwpkg, PackOptions, build_app_image, ImageOptions};

// End-to-end: ELF/bin -> fwpkg
let elf = std::fs::read("blinky")?;
let fwpkg = pack_app_fwpkg(&elf, Chip::Ws63, &PackOptions::default())?;
std::fs::write("blinky.fwpkg", fwpkg)?;

// Or just the image header + body (for a full first-flash package you build
// yourself with build_fwpkg, prepending the vendor boot partitions):
let body = std::fs::read("blinky.bin")?;
let image = build_app_image(&body, &ImageOptions::default())?;
```

---

## Format reference (reverse-engineered from fbb_ws63)

### App image header (`0x300` bytes)

The app image burned at `0x230000` is a fixed-size header followed by the code:

```text
+--------------------------------------+ 0x000
| image_key_area_t   (0x100 bytes)     |  image_id = 0x4B0F2D1E
+--------------------------------------+ 0x100
| image_code_info_t  (0x200 bytes)     |  image_id = 0x4B0F2D2D
+--------------------------------------+ 0x300  = APP_IMAGE_HEADER_LEN
| code body (.text/.rodata/...)        |  linked to run at 0x230300
+--------------------------------------+
```

Key fields (little-endian), matching the vendor `sign_tool` output:

| area | off | field | value |
|------|-----|-------|-------|
| key  | 0x00 | `image_id` | `0x4B0F2D1E` |
| key  | 0x08 | `structure_length` | `0x100` |
| key  | 0x18 | `key_alg` | `0x2A13C812` (ECC256/bp256r1) |
| code | 0x00 | `image_id` | `0x4B0F2D2D` |
| code | 0x08 | `structure_length` | `0x200` |
| code | 0x24 | `code_area_len` | body length |
| code | 0x28 | `code_area_hash[32]` | SHA-256 of body |
| code | 0x48 | `code_enc_flag` | `0x3C7896E1` = **not** encrypted |

> ⚠️ `code_enc_flag` is a non-zero "no-encryption" sentinel
> (`FLASH_NO_ENCRY_FLAG = 0x3C7896E1`). A *zero* value makes flashboot try to
> configure on-the-fly flash decryption and fail to boot a plaintext image.

The ECC signature blobs (key-sig @ `0xC0`, code-sig @ `0x280`) are left **zero**
("dummy"). See "Is the signature real?" below.

### Why dummy signatures boot (secure boot disabled)

flashboot's `verify_image_*` (`bootloader/commonboot/src/secure_verify_boot.c`)
each call `check_verify_enable()` first; when the efuse
`SEC_VERIFY_ENABLE == 0` it returns `ERRCODE_NOT_SUPPORT` and the verify
function **returns success immediately**, before reading any signature *or even
the body hash*. Then `start_fastboot()` (`bootloader/flashboot_ws63/startup/main.c`)
ends with:

```c
jump_to_execute_addr(image_addr + APP_IMAGE_HEADER_LEN);   // 0x230000 + 0x300
```

i.e. flashboot jumps **unconditionally** to `app_partition + 0x300`. So on a
secure-boot-disabled board (the ones that print `secure verify disable!`), the
only thing that matters is that the header is exactly `0x300` bytes and the body
that follows is real code linked at `0x230300`. The signatures and even the
`code_area_hash` are never checked.

### Is the signature real or dummy?

The vendor `sign_tool_pltuni` is a **closed remote signing server** (the
`sign_client_cfbb.py` script just sends the cfg + bin over a socket and gets the
signed bin back). It uses ECDSA-SHA256 over brainpoolP256r1 with a private key
we do not have. We therefore produce a **structurally-identical, dummy-signed**
image. Verified parity: rebuilding the header over the vendor's own unsigned
`ws63-liteos-app.bin` body yields a file **byte-identical to the official
`ws63-liteos-app-sign.bin` in all 3 areas except 63 bytes — all inside the two
ECC signature regions**. (See `crates/hisi-fwpkg/tests/vendor_parity.rs`.) On a
board with secure boot enabled this image would be rejected; with it disabled it
boots.

### fwpkg V1 container

```text
+----------------------------------+ 0x000
| FWPKG_HEAD (12 B)                |  flag=0xEFBEADDF  crc16  cnt  total_len
+----------------------------------+ 0x00C
| IMAGE_INFO[i] (52 B each)        |  name[32] offset len burn_addr burn_size type
+----------------------------------+
| payload[i] || 16 zero bytes      |  (separator padding, counted in total_len)
+----------------------------------+
```

`crc` is CRC16/XMODEM (poly `0x1021`, init `0x0000`) over bytes `[6 .. end of
descriptor table)`. Partition `type`: loader=0, normal=1, kv=2, efuse=3.

A full first-flash WS63 package has 7 partitions (loaderboot/params/ssb/
flashboot/flashboot_backup/nv/app); a `pack` here produces an **app-only**
package, sufficient to re-flash the app on a board that already has a working
boot chain.

### "Can a bare bin boot? What's missing?"

No. A bare `.bin`/ELF at `0x230000` is missing the `0x300` image header, so
flashboot jumps to `0x230300` and lands `0x300` bytes into your code (or into
stale SRAM). The **only** missing piece is this header — which is exactly what
`hisi-fwpkg image` / `pack` adds. With it (and secure boot disabled), the app
boots; no real signature is required.

## License

Dual-licensed under MIT or Apache-2.0.
