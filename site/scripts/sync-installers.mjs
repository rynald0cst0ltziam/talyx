// Copies the real installers (single source of truth: /scripts/ at the
// repo root, tested against dash/Debian, real Windows PowerShell, etc.)
// into site/public/, where they're served as static files at
// https://gettalyx.dev/install.sh and /install.ps1 — no separate `get.`
// subdomain needed.
//
// MANUAL step, not a build hook: an earlier version ran this as an npm
// `prebuild` hook so it re-synced on every build automatically, but that
// reads ../scripts/ — one level ABOVE site/, which doesn't exist in
// Vercel's build sandbox (it uploads only the linked project directory,
// site/, not its parent). Confirmed live: the build failed with ENOENT
// on exactly that path. site/public/install.sh and install.ps1 are real,
// committed files — the actual source Vercel serves — and this script is
// just a convenience to re-run BY HAND after editing /scripts/install.sh
// or /scripts/install.ps1, so the two copies don't drift:
//
//   npm run sync-installers   (from site/), then commit the result.

import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const siteDir = dirname(dirname(fileURLToPath(import.meta.url)));
const repoRoot = dirname(siteDir);
const publicDir = join(siteDir, "public");

mkdirSync(publicDir, { recursive: true });

for (const name of ["install.sh", "install.ps1"]) {
  const src = join(repoRoot, "scripts", name);
  const dest = join(publicDir, name);
  copyFileSync(src, dest);
  console.log(`synced ${name} -> site/public/${name}`);
}
