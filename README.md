# LEGO Marvel Switch on Android

An open-source Android compatibility project targeting the Switch edition of LEGO Marvel Super Heroes. This project is unofficial and independent of the game publishers and IP owners.

**Current milestone:** verify and stage the original `exefs/main` in an Android heap buffer, then inspect its `MOD0` loading metadata when present. The app tests `R_AARCH64_RELATIVE` entries in `DT_RELA` with a simulated base and reports how many it writes to the temporary buffer. Import resolution, host page mapping, guest execution, RomFS access, Horizon services, NVN translation, and Vulkan presentation are pending.

## Use the diagnostic app

1. In GitHub Actions, open a successful **Android CI** run and download the `switch-port-debug` artifact. Extract and install the debug APK.
2. Tap **Pilih file main dari ExeFS** and select the original `exefs/main` from your own Switch copy.
3. The app displays the NSO build ID, segment ranges, hash results, logical memory layout, and whether the temporary RAM load succeeded. When staging succeeds, it also reports whether the `MOD0` header and its dynamic table were readable. Range ends are exclusive. The span uses byte offsets before host page alignment.

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

Code is licensed under [MIT](LICENSE). Original game files remain on your device.
