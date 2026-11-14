// Checks a Firebase functions manifest (functions.yaml, as served by the Python SDK's discovery) before it is
// deployed. With functions.yaml in the source folder, firebase-tools reads it instead of running the app's
// Python, so the credentialed deploy step never executes application code.
//
// The manifest must (1) fit a strict profile: gcfv2 HTTPS endpoints only, with an allowlist of typed fields: invoker omitted
// (keeps existing invoker IAM on update), no secrets, service-account fields (other than the default or a same-project
// "name@" account), VPC,
// env vars, parameters, extra required APIs or other triggers (Data Connect schema files would be uploaded
// outside the scanned payload); and (2) equal the reviewed
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
  // Endpoint fields are an allowlist with typed values. Invoker must be omitted: Firebase then keeps the
  // function's existing invoker IAM on update (null or a list would replace it; null means public).
  const epAllowed = {
    availableMemoryMb: "number", concurrency: "number|null", cpu: "number|null", entryPoint: "string",
    httpsTrigger: "object", ingressSettings: "null|ALLOW_ALL|ALLOW_INTERNAL_ONLY|ALLOW_INTERNAL_AND_GCLB",
    labels: "object", maxInstances: "number|null", minInstances: "number|null", platform: "gcfv2",
    region: "array", secretEnvironmentVariables: "emptyarray", serviceAccountEmail: "null|sameproject",
    timeoutSeconds: "number",
  };
  const typeOk = (v, spec) => spec.split("|").some((t) =>
    t === "null" ? v === null : t === "number" ? typeof v === "number" && Number.isFinite(v)
    : t === "string" ? typeof v === "string" : t === "object" ? v !== null && typeof v === "object" && !Array.isArray(v)
    : t === "array" ? Array.isArray(v) : t === "emptyarray" ? Array.isArray(v) && v.length === 0
    // a dedicated runtime account in the deploying project only: "name@" (Firebase appends the project)
    : t === "sameproject" ? typeof v === "string" && /^[a-z][a-z0-9-]{4,28}[a-z0-9]@$/.test(v) : v === t);
  for (const [name, ep] of Object.entries(eps)) {
    if (ep === null || typeof ep !== "object" || Array.isArray(ep)) fail(`${name}: endpoint must be a mapping`);
    for (const [k, v] of Object.entries(ep)) {
      if (!(k in epAllowed)) fail(`${name}: field "${k}" is not allowed (triggers other than HTTPS, service accounts, VPC, env vars, ...)`);
      if (!typeOk(v, epAllowed[k])) fail(`${name}: field "${k}" has a disallowed value`);
    }
    for (const k of ["entryPoint", "httpsTrigger", "platform", "region"]) if (!(k in ep)) fail(`${name}: missing ${k}`);
    if (Object.keys(ep.httpsTrigger).length) fail(`${name}: httpsTrigger must be empty (invoker omitted keeps existing invoker IAM)`);
    if (!ep.region.every((r) => typeof r === "string")) fail(`${name}: region must be a list of strings`);
    if (Object.values(ep.labels || {}).some((v) => typeof v !== "string")) fail(`${name}: labels must be strings`);
  }
  try { assert.deepStrictEqual(gen, rev); }
  catch { fail("generated manifest differs from the reviewed copy (update the reviewed functions.yaml in a reviewed commit)"); }
  console.log(`manifest ok: ${Object.keys(eps).join(", ")}`);
}

try { main(); } catch (err) { console.error(`manifest-check: ${err.message}`); process.exit(2); }
