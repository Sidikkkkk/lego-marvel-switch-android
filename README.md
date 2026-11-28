# LEGO Marvel Switch on Android

An open-source Android compatibility project targeting the Switch edition of LEGO Marvel Super Heroes. This project is unofficial and independent of the game publishers and IP owners.

**Current milestone:** verify and stage the original `exefs/main` in an Android heap buffer, then inspect its `MOD0` loading metadata and test `R_AARCH64_RELATIVE` entries with a simulated base. The ExeFS folder report compares referenced import names in `main` with exported names in sibling NSOs. Runtime import binding, host page mapping, guest execution, RomFS access, Horizon services, NVN translation, and Vulkan presentation are pending.

## Use the diagnostic app

1. In GitHub Actions, open a successful **Android CI** run and download the `switch-port-debug` artifact. Extract and install the debug APK.
2. Tap **Pilih file main dari ExeFS** and select the original `exefs/main` from your own Switch copy.
3. The app displays the NSO build ID, segment ranges, hash results, logical memory layout, and whether the temporary RAM load succeeded. When staging succeeds, it also reports whether the `MOD0` header and its dynamic table were readable. Range ends are exclusive. The span uses byte offsets before host page alignment.
4. For the import report, tap **Pilih folder ExeFS**, open `exefs` and tap **Use this folder**. The selected folder must directly contain the file named `main`. The report lists candidate counts and how many names each sibling NSO matched.
5. Tap **Simpan log** after the report appears. Choose a destination for `switch-port.log`. It contains the displayed diagnostics as UTF-8 text and can be attached to a message.

Keep the full ExeFS and matching RomFS on your device for future runtime testing. The diagnostic reads the selected NSO in chunks and uses a 64 KiB history buffer for LZ4. It attempts the temporary allocation within half the remaining app heap limit and continues verification when the buffer is unavailable.

## Develop

- CI builds on Ubuntu 24.04 with JDK 17, Gradle 8.7, Android SDK platform 34 and Build Tools 34.0.0. From Termux, use Git to submit code and use Actions for the SDK build.
- Run `sh tools/test-nso.sh` with JDK 17+ for the host tests. All fixtures are synthetic.
- Inspect a local module with the same parser by running `sh tools/test-nso.sh /path/to/exefs/main`. In this mode, it streams verification without allocating a module image.
- See [AGENTS.md](AGENTS.md) for verification, bug fixes and upgrades.

The verifier follows [hactool's NSO header](https://github.com/SciresM/hactool/blob/master/nso.h), [its reader](https://github.com/SciresM/hactool/blob/master/nso.c), and the [LZ4 block format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md). Hashes are checked against the decoded bytes when present. Executable validity requires separate checks.

The metadata reader follows the [libnx startup header](https://github.com/switchbrew/libnx/blob/master/nx/source/runtime/switch_crt0.s) and the [ELF dynamic table format](https://gabi.xinuos.com/elf/08-dynamic.html). RELR counts describe packed table entries. A missing or malformed `MOD0` is reported separately from successful segment verification.

The relocation report uses [ELF relocation and symbol layouts](https://gabi.xinuos.com/elf/06-reloc.html) and [Arm's AArch64 ELF ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst). Import names require a verifiable symbol table range from the NSO header or SysV `DT_HASH` and a valid dynamic string table. The report caps the number of type rows and displayed names. Import reference counts include repeats.

The simulation supports modules with `.text` at offset zero. It verifies that each relative destination is aligned, within a segment or `.bss`, and outside the source table before writing the simulated base plus the explicit addend. The original file is opened read-only.

The ExeFS report compares exact printable ASCII names up to 1,024 bytes and tracks up to 4,096 distinct referenced import indices. It counts global and weak definitions with default or protected visibility in readable sibling NSOs. These name matches do not establish a provider's module identity, search order, symbol version, or runtime address.

The folder report also simulates `ABS64`, `GLOB_DAT`, and zero-addend `JUMP_SLOT` for a single eligible definition at a time. It assigns disjoint virtual bases to sibling modules and computes `S + A` in copies of aligned `.data` slots from `main`. A `STT_NOTYPE` export can be used for the numerical `JUMP_SLOT` simulation when it points to a word-aligned location in `.text` with at least four bytes available. The report counts such entries. It captures up to 16,384 import references and reports how many references with a single candidate could be tested, with examples explaining skipped entries.

The startup report shows the simulated module segment ranges and models up to 1024 AArch64 instructions from the start of `rtld`'s `.text`, with `X0=0` for ordinary process entry. It supports `B`, `BL`, `BR`, `B.cond`, `CBZ`/`CBNZ`, `RET`, 32- and 64-bit immediate `CMP`, 64-bit immediate `ADD` and `SUB`, 64-bit unshifted register `CMP`, 64-bit `BFI`, `ADR`/`ADRP`, register `MOV`, `MOVZ`, `MOVK`, `SXTW`, unshifted register `ADD` and `SUB` and their 64-bit `LSL` forms, immediate `AND` and `ORR`, and `MUL`. Aligned word and doubleword loads support unsigned scaled offsets (`LDR`), signed post-index offsets (`LDR`), and signed unscaled offsets (`LDUR`). `LDRB` supports an unshifted 64-bit register offset. Post-index loads update the address register after a valid read and stop if the address register and destination overlap. Unsigned-offset and unscaled byte and aligned word stores, and signed-offset word and doubleword register pair stores (`STP`), write to a temporary `.bss` overlay. Aligned 64-bit `STR` with an unshifted 64-bit register offset can also write to the `.data` overlay. Signed-offset `STP`, unsigned-offset `LDR`, and unsigned-offset 64-bit `STR` can access unaligned addresses when the full access fits in the simulated `.bss`. The 64-bit pre-index `STR` stores at the adjusted address and updates its base register after a valid write. Subsequent loads read these writes without modifying the input image. The probe tracks `SP` with a separate, synthetic 64 KiB stack. Immediate `ADD` and `SUB` keep `SP` inside that range and 16-byte aligned. Supported loads and stores can access only the active part of the stack, where unwritten bytes and saves of unknown registers remain unknown. Register branches and returns require a known address aligned inside `rtld`'s `.text`. The diagnostic performs no native guest execution or system calls.

For the four observed imports `__rel_dyn_start`, `__rel_dyn_end`, `__rel_plt_start`, and `__rel_plt_end`, the report shows dynamic symbol attributes, the first reference, and validated relocation table spans. It can simulate a zero ELF value on copies of aligned 64-bit `.data` slots when the only missing definitions are weak references of this observed form and the scanned sibling symbol tables are readable. This does not establish the Horizon loader's runtime values.

Code is licensed under [MIT](LICENSE). Original game files remain on your device.
