// Copies the exact set of files `firebase deploy --only functions` will upload into an output folder,
// so the security scanner can scan the real deploy payload (tree mode) before any deploy.
//
// It calls the installed firebase-tools' own file lister (lib/fsAsync readdirRecursive) with the same
// ignore list prepareFunctionsUpload uses: firebase.json functions[0].ignore plus the fixed names
// firebase-tools appends. firebase-tools matches ignore patterns against absolute paths, so run it from
// the same folder the deploy runs from. The installed version must be the pinned one: the lister's
// option name differs between major versions (14: `ignore`, 15: `ignoreStrings`).
//
// Usage: node payload.js <firebase-tools root> <pinned version> <source dir> <empty output dir>
"use strict";
const fs = require("fs");
const path = require("path");

async function main() {
  const [ftRoot, pinned, srcArg, outArg] = process.argv.slice(2);
  if (!ftRoot || !pinned || !srcArg || !outArg) {
    throw new Error("usage: payload.js <firebase-tools root> <pinned version> <source dir> <output dir>");
  }
  const version = JSON.parse(fs.readFileSync(path.join(ftRoot, "package.json"), "utf8")).version;
  if (version !== pinned) throw new Error(`firebase-tools ${version} installed, ${pinned} pinned`);
  const major = Number(version.split(".")[0]);
  if (major !== 14 && major !== 15) throw new Error(`unsupported firebase-tools major version ${major}`);

  const src = path.resolve(srcArg);
  const out = path.resolve(outArg);
  if (fs.existsSync(out) && fs.readdirSync(out).length) throw new Error(`output dir not empty: ${out}`);

  const config = JSON.parse(fs.readFileSync(path.join(src, "firebase.json"), "utf8"));
  const fns = config.functions;
  const fn = Array.isArray(fns) ? fns[0] : fns;
  if (!fn || (Array.isArray(fns) && fns.length !== 1)) throw new Error("expected exactly one functions entry");
  if ((fn.source || ".") !== ".") throw new Error("expected functions source '.'");
  for (const key of ["additionalSources", "predeploy", "prebuild"]) {
    if (fn[key] !== undefined) throw new Error(`functions.${key} is not supported by this check`);
  }
  if (fs.existsSync(path.join(src, ".runtimeconfig.json"))) throw new Error(".runtimeconfig.json present");

  const ignore = [...(fn.ignore || ["node_modules", ".git"]), "firebase-debug.log", "firebase-debug.*.log", ".runtimeconfig.json"];
  const { readdirRecursive } = require(path.join(ftRoot, "lib", "fsAsync"));
  const opts = major >= 15 ? { path: src, ignoreStrings: ignore } : { path: src, ignore };
  const files = await readdirRecursive(opts);

  for (const f of files) {
    const rel = path.relative(src, f.name);
    if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error(`file outside source: ${f.name}`);
    // the ignore list must have been applied: these never belong in the upload
    if (/(^|[\\/])(\.git|venv|node_modules)([\\/]|$)/.test(rel)) throw new Error(`ignore list not applied: ${rel}`);
    const dst = path.join(out, rel);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.copyFileSync(f.name, dst); // follows links, so the scan sees the bytes that are uploaded
  }
  console.log(`${files.length} files in the deploy payload (firebase-tools ${version})`);
}

main().catch((err) => { console.error(`payload: ${err.message}`); process.exit(2); });
