// Builds the npm publish tree: one package per platform, each carrying
// the native binaries for exactly that platform, plus the `talyx`
// launcher package that depends on all of them optionally.
//
// Run AFTER the release archives exist, pointing at a directory holding
// them (the ones the release workflow uploads):
//
//   node npm/build-packages.mjs --artifacts ./dist --out ./npm-dist
//   for d in npm-dist/*/ ; do (cd "$d" && npm publish --access public); done
//
// The per-platform packages declare `os` and `cpu`, so npm installs the
// one matching the machine and silently skips the rest — that is what
// makes this work without a postinstall script. See npm/talyx/bin/talyx.js
// for why avoiding a postinstall matters for this product specifically.

import { createWriteStream } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { execFileSync } from "node:child_process";

// target triple -> npm platform package. `os`/`cpu` are npm's own
// vocabulary (process.platform / process.arch), not Rust's.
const TARGETS = [
  { triple: "x86_64-unknown-linux-musl", pkg: "linux-x64", os: "linux", cpu: "x64", ext: "tar.gz" },
  { triple: "aarch64-unknown-linux-musl", pkg: "linux-arm64", os: "linux", cpu: "arm64", ext: "tar.gz" },
  { triple: "x86_64-apple-darwin", pkg: "darwin-x64", os: "darwin", cpu: "x64", ext: "tar.gz" },
  { triple: "aarch64-apple-darwin", pkg: "darwin-arm64", os: "darwin", cpu: "arm64", ext: "tar.gz" },
  { triple: "x86_64-pc-windows-msvc", pkg: "win32-x64", os: "win32", cpu: "x64", ext: "zip" },
];

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i === -1 ? fallback : process.argv[i + 1];
}

const artifactsDir = path.resolve(arg("--artifacts", "dist"));
const outDir = path.resolve(arg("--out", "npm-dist"));
const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Za-z]:)/, "$1"), "..");

const rootPkg = JSON.parse(
  await fs.readFile(path.join(repoRoot, "npm", "talyx", "package.json"), "utf8")
);
const version = rootPkg.version;

async function extract(archive, dest) {
  await fs.mkdir(dest, { recursive: true });

  // The archive is named by BASENAME with cwd set to its directory,
  // never by absolute path: GNU tar reads `C:\...` as host `C` plus a
  // path and tries to resolve it over the network ("C: resolve
  // failed"). Keeping the name colon-free sidesteps that on every
  // platform without needing tar-flavour-specific flags.
  const dir = path.dirname(archive);
  const name = path.basename(archive);
  // Forward slashes for the destination too: the MSYS tar that ships
  // with Git for Windows mangles backslash-separated paths. Harmless on
  // Linux and macOS, where this normally runs.
  const destArg = dest.replace(/\\/g, "/");

  if (name.endsWith(".zip")) {
    // PowerShell ships on every Windows runner; `unzip` does not.
    if (process.platform === "win32") {
      execFileSync("powershell", [
        "-NoProfile",
        "-Command",
        `Expand-Archive -LiteralPath '${archive}' -DestinationPath '${dest}' -Force`,
      ]);
    } else {
      execFileSync("unzip", ["-q", "-o", name, "-d", destArg], { cwd: dir });
    }
  } else {
    execFileSync("tar", ["xzf", name, "-C", destArg], { cwd: dir });
  }
}

await fs.rm(outDir, { recursive: true, force: true });
await fs.mkdir(outDir, { recursive: true });

const built = [];

for (const t of TARGETS) {
  const archive = path.join(artifactsDir, `talyx-${t.triple}.${t.ext}`);
  try {
    await fs.access(archive);
  } catch {
    console.error(`MISSING artifact: ${archive}`);
    process.exitCode = 1;
    continue;
  }

  const staging = path.join(outDir, `.staging-${t.pkg}`);
  await extract(archive, staging);

  // Archives unpack to a single talyx-<triple>/ directory.
  const inner = path.join(staging, `talyx-${t.triple}`);
  const exe = t.os === "win32" ? ".exe" : "";

  const pkgDir = path.join(outDir, `talyx-${t.pkg}`);
  const binDir = path.join(pkgDir, "bin");
  await fs.mkdir(binDir, { recursive: true });

  for (const name of ["talyx", "talyx-shim"]) {
    const from = path.join(inner, `${name}${exe}`);
    const to = path.join(binDir, `${name}${exe}`);
    await fs.copyFile(from, to);
    if (t.os !== "win32") await fs.chmod(to, 0o755);
  }

  // Licence notices travel with the binaries — the bundled crates'
  // MIT/BSD/Apache terms require it, and an npm package is a
  // distribution like any other.
  for (const f of ["LICENSE", "THIRD-PARTY-LICENSES.txt"]) {
    await fs.copyFile(path.join(repoRoot, f), path.join(pkgDir, f));
  }

  await fs.writeFile(
    path.join(pkgDir, "package.json"),
    JSON.stringify(
      {
        name: `@talyx/${t.pkg}`,
        version,
        description: `Talyx native binaries for ${t.os}/${t.cpu}. Installed automatically by the \`talyx\` package; not meant to be depended on directly.`,
        license: "SEE LICENSE IN LICENSE",
        homepage: "https://gettalyx.dev",
        repository: rootPkg.repository,
        // npm refuses to install a package whose os/cpu do not match the
        // host, which is exactly what makes the optionalDependencies
        // approach fetch one platform's binaries and skip the rest.
        os: [t.os],
        cpu: [t.cpu],
        files: ["bin/", "LICENSE", "THIRD-PARTY-LICENSES.txt"],
      },
      null,
      2
    ) + "\n"
  );

  await fs.writeFile(
    path.join(pkgDir, "README.md"),
    `# @talyx/${t.pkg}\n\nNative Talyx binaries for ${t.os}/${t.cpu}.\n\n` +
      `This package is an implementation detail of [\`talyx\`](https://www.npmjs.com/package/talyx)` +
      ` and is installed automatically for your platform. Install \`talyx\` instead:\n\n` +
      "```\nnpm install -g talyx\n```\n\nhttps://gettalyx.dev\n"
  );

  await fs.rm(staging, { recursive: true, force: true });
  built.push(`@talyx/${t.pkg}`);
  console.log(`built @talyx/${t.pkg}`);
}

// The launcher package last, so a failure above stops before it.
const launcherDir = path.join(outDir, "talyx");
await fs.mkdir(path.join(launcherDir, "bin"), { recursive: true });
await fs.copyFile(
  path.join(repoRoot, "npm", "talyx", "bin", "talyx.js"),
  path.join(launcherDir, "bin", "talyx.js")
);
await fs.copyFile(
  path.join(repoRoot, "npm", "talyx", "package.json"),
  path.join(launcherDir, "package.json")
);
for (const f of ["LICENSE", "THIRD-PARTY-LICENSES.txt"]) {
  await fs.copyFile(path.join(repoRoot, f), path.join(launcherDir, f));
}
await fs.copyFile(path.join(repoRoot, "README.md"), path.join(launcherDir, "README.md"));
console.log("built talyx");

console.log(
  `\n${built.length + 1} package(s) staged in ${outDir} at version ${version}.`
);
if (process.exitCode === 1) {
  console.error("One or more artifacts were missing — do NOT publish this tree.");
}
