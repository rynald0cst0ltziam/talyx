// Copies the real installers (single source of truth: /scripts/ at the
// repo root, tested against dash/Debian, real Windows PowerShell, etc.)
// into site/public/ so they get served as static files at
// https://gettalyx.dev/install.sh and /install.ps1 — no separate `get.`
// subdomain needed, and no hand-maintained duplicate to drift out of sync.
// Runs as an npm `prebuild` hook (npm's lifecycle runs it automatically
// before `build`), so both local `npm run build` and Vercel's build step
// pick it up without extra configuration.

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
