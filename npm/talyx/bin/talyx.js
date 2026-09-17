#!/usr/bin/env node
// Launcher for the `talyx` npm package.
//
// There is deliberately NO postinstall script here. The native binaries
// ship inside per-platform packages (`@talyx/linux-x64` and friends),
// declared as optionalDependencies with `os`/`cpu` constraints, so npm
// downloads exactly one of them for the current machine and none of the
// others. This is the model esbuild uses, and it is the right one for a
// security product:
//
//   - A postinstall that downloads and executes a binary is the exact
//     pattern Socket, Snyk and Talyx itself flag as a supply-chain risk.
//     Shipping one from a supply-chain security tool would be indefensible.
//   - `npm install --ignore-scripts` is increasingly common in hardened
//     CI. With a postinstall, that silently yields a broken install; here
//     it works, because there is no script to skip.
//   - The bytes npm resolves are the bytes that run. Nothing is fetched
//     at install time from anywhere npm cannot see, so the package's
//     integrity hashes actually cover the binary.
//
// npm's `bin` mechanism wraps a JS file with `node` on every platform,
// which is what makes one global shim work identically on Windows, macOS
// and Linux. So this file's only job is to find the real binary and hand
// off to it.

"use strict";

const path = require("path");
const { spawnSync } = require("child_process");

// (npm platform, npm arch) -> package name. Keys match process.platform
// and process.arch exactly.
const PACKAGES = {
  "linux x64": "@talyx/linux-x64",
  "linux arm64": "@talyx/linux-arm64",
  "darwin x64": "@talyx/darwin-x64",
  "darwin arm64": "@talyx/darwin-arm64",
  "win32 x64": "@talyx/win32-x64",
};

function binaryPath(name) {
  const pkg = PACKAGES[`${process.platform} ${process.arch}`];
  if (!pkg) {
    return {
      error:
        `talyx: unsupported platform ${process.platform}/${process.arch}.\n` +
        `Supported: ${Object.keys(PACKAGES).join(", ")}.\n` +
        `See https://gettalyx.dev/docs for installing from source.`,
    };
  }

  const exe = process.platform === "win32" ? ".exe" : "";
  try {
    // Resolve through the package's own manifest rather than guessing a
    // node_modules layout — npm, pnpm and yarn all place these
    // differently, and require.resolve is the only thing that knows.
    const manifest = require.resolve(`${pkg}/package.json`);
    return { path: path.join(path.dirname(manifest), "bin", `${name}${exe}`) };
  } catch {
    return {
      error:
        `talyx: the platform package ${pkg} is not installed.\n` +
        `This usually means npm skipped optional dependencies. Try:\n` +
        `  npm install ${pkg}\n` +
        `or reinstall talyx without --no-optional.\n` +
        `Alternatively install directly: curl -fsSL https://gettalyx.dev/install.sh | sh`,
    };
  }
}

// Exposed so talyx-shim can be resolved the same way — `talyx init`
// needs to know where the shim lives, and it asks the binary, not this
// script. Kept here so there is one definition of the layout.
module.exports = { binaryPath, PACKAGES };

if (require.main === module) {
  const resolved = binaryPath("talyx");
  if (resolved.error) {
    console.error(resolved.error);
    process.exit(1);
  }

  const result = spawnSync(resolved.path, process.argv.slice(2), {
    stdio: "inherit",
  });

  if (result.error) {
    console.error(
      `talyx: failed to launch ${resolved.path}: ${result.error.message}`
    );
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}
