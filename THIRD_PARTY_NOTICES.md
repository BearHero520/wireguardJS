# Third-party material

## Bundled wg executable

`resources/bin/wg` was extracted byte-for-byte from the user-provided original
`wireguard.js` embedded archive. Its ELF header identifies an AArch64 (ARM64),
64-bit executable. Embedded strings refer to wireguard-tools and the Android
Clang toolchain.

Upstream project: https://git.zx2c4.com/wireguard-tools/

The exact upstream commit, build recipe, original distributor, and corresponding
source for this particular executable have not been verified. This repository
does not claim to have built or audited the binary. Its SHA-256 is recorded in
`dist/manifest.json` so changes can be detected.

Do not interpret the presence of this file as a new license grant for the
executable or the original imported script. Before public redistribution,
establish the applicable license and corresponding-source obligations for the
original material, or replace the binary with a verified build and publish its
source/build instructions as required.

## Development dependencies

Playwright is used only for local and CI browser tests. It is not included in the
runtime plugin. Dependency versions are locked in `package-lock.json`; upstream
license information is included with the installed package.
