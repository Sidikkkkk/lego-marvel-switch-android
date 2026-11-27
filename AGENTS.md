# Engineering instructions for contributors and AI agents

## Scope

- Use the original Switch ExeFS modules and the matching RomFS as local inputs. The runtime must accept the original `exefs/main` NSO. Keep ELF conversion out of build, installation, and runtime requirements.
- Commit project code, documentation, and synthetic fixtures only. Keep original game files, generated game code, keys, and personal logs out of the repository, issues, releases, and CI artifacts.
- Keep ARM64 Android and the Termux plus GitHub Actions workflow usable. State the tested device, Android version, GPU, and driver whenever making compatibility or performance claims.

## Verify before editing

1. Read the relevant entry point, its callers, existing tests, and current project status in `README.md`. Identify the exact file, symbol, and game build that any diagnosis relies on.
2. Record a short context check, first-principles analysis, and assumption audit before changing code. For low-level changes, check memory layout, width, alignment, ownership, calling convention, thread affinity, and graphics object lifetime as applicable.
3. Verify Android, Vulkan, ARM64, and build-tool behavior against version-appropriate official headers or documentation. For Switch behavior, record the exact observed module, build ID, call site or offset, and provenance of each reference. Distinguish observed facts from inference.
4. Mark missing evidence `[UNVERIFIED]`. Name the file, header, trace, or test required to resolve it. Leave the affected behavior unimplemented until its contract is verified. Never invent signatures, enum values, object sizes, return values, translations, or test results.

## Changes and review

- Keep diffs focused. Preserve existing entry points, error semantics, and supported inputs unless the change explicitly requires otherwise.
- For a bug fix, capture the reproduction and root cause. Add a focused regression check when existing tests would miss it.
- For upgrades, verify the compatibility matrix and note changed versions in the PR. Keep dependency-only changes separate from unrelated behavior where practical.
- Handle unsupported guest behavior explicitly. Before executing guest code, verify relocations, import and calling convention handling, permissions, and unsupported operations. Never route unknown functions through a generic success stub.
- Check Vulkan results, queue and presentation support, synchronization, surface loss, and destruction order when modifying graphics code. Only claim a game frame after confirmed presentation of game output.
- Run `sh tools/test-nso.sh` and `gradle assembleDebug --no-daemon` when applicable. Record actual commands and results in the PR. Distinguish host tests, APK compilation, and physical-device verification.
- Update the README when a milestone or a supported workflow changes. Carry forward current blockers and the evidence needed to resolve them.
