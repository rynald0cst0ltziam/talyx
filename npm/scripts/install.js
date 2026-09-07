#!/usr/bin/env node
// postinstall — downloads the talyx + talyx-shim native binaries
// matching this npm package's own version, and (unless
// TALYX_SKIP_INIT is set) runs `talyx init` against the user's
// home directory to activate protection immediately, mirroring
// scripts/install.sh and install.ps1 in the main repo.
//
// Deliberately zero npm dependencies — no fetch/tar library — for a
// postinstall script specifically, because "a package's postinstall
// script downloads a binary from the network and executes it" is exactly
// the kind of behavior Talyx exists to scrutinize in OTHER packages.
// Fewer dependencies here means less to audit and less supply-chain
// surface for this package's own postinstall step. Uses only Node's
// built-in https/zlib/child_process, and shells out to the system's `tar`
// (present by default on macOS, Linux, and Windows 10 1803+) for archive
// extraction rather than bundling a tar/zip parser.
//
// NOT wired to a real release yet — see the root .github/workflows/
// release.yml and the TODO on TALYX_REPO below. Until a real release
// exists at that repo, this fails at the download step with a clear
// error, on purpose, rather than silently doing nothing.

"use strict";

const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync, spawnSync } = require("child_process");

const REPO = process.env.TALYX_REPO || "your-org/talyx"; // TODO: real repo
const PKG_VERSION = require("../package.json").version;
const VERSION = process.env.TALYX_VERSION || `v${PKG_VERSION}`;
const NATIVE_DIR = path.join(__dirname, "..", ".bin-native");

function targetTriple() {
  const platform = process.platform;
  const arch = process.arch;

  let osPart;
  let archiveExt;
  if (platform === "darwin") {
    osPart = "apple-darwin";
    archiveExt = "tar.gz";
  } else if (platform === "linux") {
    osPart = "unknown-linux-gnu";
    archiveExt = "tar.gz";
  } else if (platform === "win32") {
    osPart = "pc-windows-msvc";
    archiveExt = "zip";
  } else {
    throw new Error(`unsupported platform: ${platform}`);
  }

  let archPart;
  if (arch === "x64") archPart = "x86_64";
  else if (arch === "arm64") archPart = "aarch64";
  else throw new Error(`unsupported architecture: ${arch}`);

  if (platform === "win32" && archPart !== "x86_64") {
    throw new Error("v0 only ships x86_64-pc-windows-msvc — Windows on ARM isn't built yet");
  }

  return { triple: `${archPart}-${osPart}`, archiveExt };
}

function download(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);
    const request = (currentUrl, redirectsLeft) => {
      https
        .get(currentUrl, (res) => {
          if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
            if (redirectsLeft <= 0) return reject(new Error("too many redirects"));
            res.resume();
            return request(res.headers.location, redirectsLeft - 1);
          }
          if (res.statusCode !== 200) {
            res.resume();
            return reject(new Error(`download failed: HTTP ${res.statusCode} for ${currentUrl}`));
          }
          res.pipe(file);
          file.on("finish", () => file.close(resolve));
        })
        .on("error", reject);
    };
    request(url, 5);
  });
}

function extract(archivePath, destDir, archiveExt) {
  // Windows' built-in tar.exe (bsdtar, present since 1803) auto-detects
  // zip vs tar.gz, so `tar xf` works for both without branching on
  // archiveExt at the extraction step itself.
  execFileSync("tar", ["xf", archivePath, "-C", destDir], { stdio: "inherit" });
}

async function main() {
  const { triple, archiveExt } = targetTriple();
  const assetName = `talyx-${triple}.${archiveExt}`;
  const url = `https://github.com/${REPO}/releases/download/${VERSION}/${assetName}`;

  console.log(`talyx: downloading ${assetName} from ${REPO}@${VERSION}`);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "talyx-npm-install-"));
  const archivePath = path.join(tmpDir, assetName);

  try {
    await download(url, archivePath);
  } catch (err) {
    console.error(`talyx: postinstall download failed: ${err.message}`);
    console.error(
      `Is ${REPO} a real repo with a published release for tag ${VERSION} yet? If you're testing this before any release exists, that's expected.`
    );
    process.exit(1);
  }

  extract(archivePath, tmpDir, archiveExt);

  const extractedDir = fs
    .readdirSync(tmpDir, { withFileTypes: true })
    .find((e) => e.isDirectory() && e.name.startsWith("talyx-"));
  if (!extractedDir) {
    console.error("talyx: unexpected archive layout");
    process.exit(1);
  }
  const srcDir = path.join(tmpDir, extractedDir.name);

  fs.rmSync(NATIVE_DIR, { recursive: true, force: true });
  fs.mkdirSync(NATIVE_DIR, { recursive: true });

  const exeSuffix = process.platform === "win32" ? ".exe" : "";
  for (const name of ["talyx", "talyx-shim"]) {
    const file = `${name}${exeSuffix}`;
    fs.copyFileSync(path.join(srcDir, file), path.join(NATIVE_DIR, file));
    if (process.platform !== "win32") {
      fs.chmodSync(path.join(NATIVE_DIR, file), 0o755);
    }
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
  console.log(`talyx: installed native binaries to ${NATIVE_DIR}`);

  if (process.env.TALYX_SKIP_INIT) {
    console.log("talyx: TALYX_SKIP_INIT set — skipping automatic activation.");
    console.log(`Run \`talyx init --project "${os.homedir()}"\` yourself when ready.`);
    return;
  }

  console.log("talyx: activating protection for every Claude Code MCP server config under your home directory...");
  const talyxBin = path.join(NATIVE_DIR, `talyx${exeSuffix}`);
  const result = spawnSync(talyxBin, ["init", "--project", os.homedir()], { stdio: "inherit" });
  if (result.status !== 0) {
    console.error("talyx: `talyx init` did not exit cleanly — binaries are installed, but activation may be incomplete.");
    console.error(`Re-run manually: talyx init --project "${os.homedir()}"`);
  }
}

main().catch((err) => {
  console.error(`talyx: postinstall failed: ${err.stack || err.message}`);
  process.exit(1);
});
