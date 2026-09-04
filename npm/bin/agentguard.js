#!/usr/bin/env node
// Thin launcher — npm's `bin` mechanism always wraps a JS file with `node`
// on every platform (that's what makes the resulting global shim work
// identically on Windows/macOS/Linux), so this just forwards straight
// through to the real native binary that scripts/install.js downloaded.

"use strict";

const path = require("path");
const { spawnSync } = require("child_process");

const exeSuffix = process.platform === "win32" ? ".exe" : "";
const binPath = path.join(__dirname, "..", ".bin-native", `agentguard${exeSuffix}`);

const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  console.error(`agentguard: failed to launch native binary at ${binPath}: ${result.error.message}`);
  console.error("If this is a fresh install, the postinstall download may have failed — check the install log above, or try reinstalling.");
  process.exit(1);
}

process.exit(result.status === null ? 1 : result.status);
