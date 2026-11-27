# LEGO Marvel Switch on Android

An open-source Android compatibility project targeting the Switch edition of LEGO Marvel Super Heroes. This project is unofficial and independent of the game publishers and IP owners.

**Current milestone:** verify the original `exefs/main` directly on Android or on a host. The diagnostic checks NSO0 segment ranges and decoded sizes, and compares each SHA-256 hash supplied by the header. Guest execution, RomFS access, Horizon services, NVN translation, and Vulkan presentation are pending.

## Use the diagnostic app

1. In GitHub Actions, open a successful **Android CI** run and download the `switch-port-debug` artifact. Extract and install the debug APK.
2. Tap **Pilih file main dari ExeFS** and select the original `exefs/main` from your own Switch copy.
3. The app displays the NSO build ID, segment metadata, and hash results. A malformed or truncated segment is identified by name.

Keep the full ExeFS and matching RomFS on your device for future runtime testing. The diagnostic reads the selected NSO in chunks and uses a 64 KiB history buffer for LZ4. It works directly with the NSO file.

## Develop

- CI builds on Ubuntu 24.04 with JDK 17, Gradle 8.7, Android SDK platform 34 and Build Tools 34.0.0. From Termux, use Git to submit code and use Actions for the SDK build.
- Run `sh tools/test-nso.sh` with JDK 17+ for the host tests. All fixtures are synthetic.
- Inspect a local module with the same parser by running `sh tools/test-nso.sh /path/to/exefs/main`.
- See [AGENTS.md](AGENTS.md) for verification, bug fixes and upgrades.

The verifier follows [hactool's NSO header](https://github.com/SciresM/hactool/blob/master/nso.h), [its reader](https://github.com/SciresM/hactool/blob/master/nso.c), and the [LZ4 block format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md). Hashes are checked against the decoded bytes when present. Executable validity requires separate checks.

Code is licensed under [MIT](LICENSE). Original game files remain on your device.
