// Checks a Firebase functions manifest (functions.yaml, as served by the Python SDK's discovery) before it is
// deployed. With functions.yaml in the source folder, firebase-tools reads it instead of running the app's
// Python, so the credentialed deploy step never executes application code.
//
// The manifest must (1) fit a strict profile: one or more gcfv2 HTTPS endpoints only, no invoker list that makes
// a function public, no secrets, service-account override, extra required APIs, parameters or Data Connect
// triggers (whose schema files Firebase would upload outside the scanned payload); and (2) equal the reviewed
// copy committed in the repository, so any change to deployed function settings is a reviewed change.
//
// Usage: node manifest-check.js <firebase-tools root> <generated functions.yaml> <reviewed functions.yaml>
"use strict";
const fs = require("fs");
const path = require("path");
const assert = require("assert");

function fail(msg) { throw new Error(msg); }

function main() {
  const [ftRoot, genPath, revPath] = process.argv.slice(2);
  if (!ftRoot || !genPath || !revPath) fail("usage: manifest-check.js <firebase-tools root> <generated> <reviewed>");
  const yaml = require(require.resolve("yaml", { paths: [ftRoot] }));
  const gen = yaml.parse(fs.readFileSync(genPath, "utf8"));
  const rev = yaml.parse(fs.readFileSync(revPath, "utf8"));

  const top = new Set(["specVersion", "endpoints", "params", "requiredAPIs"]);
  if (!gen || typeof gen !== "object" || Array.isArray(gen)) fail("manifest is not a mapping");
  for (const k of Object.keys(gen)) if (!top.has(k)) fail(`unexpected top-level key: ${k}`);
  if (gen.specVersion !== "v1alpha1") fail(`unexpected specVersion: ${gen.specVersion}`);
  if ((gen.params || []).length) fail("parameters are not allowed");
  if ((gen.requiredAPIs || []).length) fail("extra required APIs are not allowed");
  const eps = gen.endpoints || {};
  if (!Object.keys(eps).length) fail("no endpoints");
  const triggers = ["httpsTrigger", "callableTrigger", "eventTrigger", "scheduleTrigger", "taskQueueTrigger",
    "blockingTrigger", "dataConnectGraphqlTrigger"];
  for (const [name, ep] of Object.entries(eps)) {
    const present = triggers.filter((t) => ep[t] !== undefined);
    if (present.length !== 1 || present[0] !== "httpsTrigger") fail(`${name}: only an HTTPS trigger is allowed (${present})`);
    const inv = ep.httpsTrigger.invoker;
    if (inv !== undefined && inv !== null) {
      if (!Array.isArray(inv) || inv.some((m) => m === "public" || /allUsers|allAuthenticatedUsers/.test(m))) {
        fail(`${name}: public invoker is not allowed`);
      }
    }
    if (ep.platform !== "gcfv2") fail(`${name}: platform must be gcfv2`);
    if ((ep.secretEnvironmentVariables || []).length) fail(`${name}: secret environment variables are not allowed`);
    if (ep.serviceAccountEmail) fail(`${name}: service account override is not allowed`);
    if (ep.environmentVariables && Object.keys(ep.environmentVariables).length) fail(`${name}: inline environment variables are not allowed`);
  }
  try { assert.deepStrictEqual(gen, rev); }
  catch { fail("generated manifest differs from the reviewed copy (update the reviewed functions.yaml in a reviewed commit)"); }
  console.log(`manifest ok: ${Object.keys(eps).join(", ")}`);
}

try { main(); } catch (err) { console.error(`manifest-check: ${err.message}`); process.exit(2); }
