#!/usr/bin/env bash
# Tests for the Firebase deploy helpers: the lister matches firebase-tools' own packaging exactly, refuses a wrong
# CLI version or an unapplied ignore list, and the manifest check accepts only the reviewed HTTPS-only manifest.
set -Eeuo pipefail
trap 'echo "TEST SETUP FAILED at line $LINENO" >&2; exit 2' ERR
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/fb-tests.XXXXXX"); trap 'rm -rf "$WORK"' EXIT
pass=0; failn=0
ok()  { pass=$((pass+1)); echo "PASS  $1"; }
bad() { failn=$((failn+1)); echo "FAIL  $1"; }
expect() { local want=$1 label=$2 got=0; shift 2; "$@" >"$WORK/out" 2>&1 || got=$?; if [ "$got" -eq "$want" ]; then ok "$label"; else bad "$label (got $got, want $want): $(head -c 300 "$WORK/out")"; fi; }

cp "$HERE/package.json" "$HERE/package-lock.json" "$WORK/"
(cd "$WORK" && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error >/dev/null)
FT="$WORK/node_modules/firebase-tools"
VER=$(node -p "require('$FT/package.json').version")

# fixture project: code, files the ignore list must drop, a nested dir matched by basename, a venv and .git
P="$WORK/proj"; mkdir -p "$P/src/tests" "$P/docs" "$P/venv/lib" "$P/.git" "$P/companies/ACME/Ref" "$P/pkg"
cat >"$P/firebase.json" <<'JSON'
{ "functions": [ { "source": ".", "runtime": "python313",
  "ignore": ["venv", ".git", "docs", "**/tests/**", "*.md", "**/companies/**/*.txt", ".env.*", ".env[0-9]*", "**/*.[xX][lL][sS][xX]"] } ] }
JSON
echo 'print(1)' >"$P/main.py"; echo 'x=1' >"$P/pkg/mod.py"; echo flask >"$P/requirements.txt"; echo 'A=1' >"$P/.env"
echo 'A=2' >"$P/.env.dev"; echo 'A=3' >"$P/.env1"; echo t >"$P/src/tests/t.py"; echo d >"$P/docs/x.py"; echo r >"$P/README.md"
echo m >"$P/companies/ACME/Ref/manual.txt"; echo w >"$P/companies/ACME/Book.XLSX"; echo v >"$P/venv/lib/v.py"; echo g >"$P/.git/config"

expect 0 "lister: runs with the pinned CLI" node "$HERE/payload.js" "$FT" "$VER" "$P" "$WORK/payload"
(cd "$WORK/payload" && find . -type f | sed 's|^\./||' | LC_ALL=C sort) >"$WORK/lister.txt"
node -e '
  const p = require(process.argv[1] + "/lib/deploy/functions/prepareFunctionsUpload.js");
  const cfg = JSON.parse(require("fs").readFileSync(process.argv[2] + "/firebase.json", "utf8")).functions[0];
  p.prepareFunctionsUpload(process.argv[2], process.argv[2], cfg, []).then(r => console.log(r.pathToSource));
' "$FT" "$P" >"$WORK/zip.path"
python3 -c "import zipfile,sys; [print(n) for n in sorted(i.filename for i in zipfile.ZipFile(sys.argv[1]).infolist() if not i.filename.endswith('/'))]" "$(tail -1 "$WORK/zip.path")" >"$WORK/zip.txt"
if cmp -s "$WORK/lister.txt" "$WORK/zip.txt"; then ok "lister: identical to firebase-tools $VER packaging"; else bad "lister: differs from firebase-tools packaging"; diff "$WORK/lister.txt" "$WORK/zip.txt" || true; fi
if [ "$(cat "$WORK/lister.txt")" = "$(printf '%s\n' .env firebase.json main.py pkg/mod.py requirements.txt)" ]; then ok "lister: expected files only"; else bad "lister: unexpected file set: $(tr '\n' ' ' <"$WORK/lister.txt")"; fi
expect 2 "lister: wrong pinned version refused" node "$HERE/payload.js" "$FT" 0.0.1 "$P" "$WORK/p2"
sed 's/"ignore": \[/"ignoreX": [/' "$P/firebase.json" >"$WORK/fb.json"; cp -r "$P" "$WORK/proj2"; cp "$WORK/fb.json" "$WORK/proj2/firebase.json"
expect 2 "lister: default ignore list (venv uploaded) refused" node "$HERE/payload.js" "$FT" "$VER" "$WORK/proj2" "$WORK/p3"
sed 's/"source": "."/"source": ".", "predeploy": ["x"]/' "$P/firebase.json" >"$WORK/proj2/firebase.json"
expect 2 "lister: predeploy hooks refused" node "$HERE/payload.js" "$FT" "$VER" "$WORK/proj2" "$WORK/p4"

cfgcase() {  # cfgcase <label> <perl substitution on firebase.json>
  rm -rf "$WORK/proj3"; cp -r "$P" "$WORK/proj3"; perl -0pi -e "$2" "$WORK/proj3/firebase.json"
  expect 2 "lister: $1 refused" node "$HERE/payload.js" "$FT" "$VER" "$WORK/proj3" "$WORK/p-$RANDOM"
}
cfgcase "postdeploy hook" 's/"source": "."/"source": ".", "postdeploy": ["node hook.js"]/'
cfgcase "imported (string) functions config" 's/"functions": \[.*\]\s*\}\s*\z/"functions": "functions-config.json" }\n/s'
cfgcase "unknown functions key" 's/"source": "."/"source": ".", "remoteSource": {}/'
cfgcase "unknown top-level key" 's/^\{/{ "hosting": {"predeploy": ["x"]},/'
cfgcase "non-Python runtime" 's/"python313"/"nodejs22"/'

# manifest check
M="$WORK/m.yaml"
cat >"$M" <<'YAML'
endpoints:
  fn:
    availableMemoryMb: 512
    entryPoint: fn
    httpsTrigger: {}
    platform: gcfv2
    region: [asia-northeast1]
    secretEnvironmentVariables: []
    serviceAccountEmail: null
params: []
requiredAPIs: []
specVersion: v1alpha1
YAML
mut() { perl -pe "$1" "$M" >"$WORK/$2.yaml"; }
expect 0 "manifest: reviewed HTTPS manifest accepted" node "$HERE/manifest-check.js" "$FT" "$M" "$M"
mut 's/availableMemoryMb: 512/availableMemoryMb: 1024/' changed
expect 2 "manifest: differs from the reviewed copy" node "$HERE/manifest-check.js" "$FT" "$WORK/changed.yaml" "$M"
mut 's/httpsTrigger: \{\}/httpsTrigger: {invoker: [public]}/' public
expect 2 "manifest: public invoker refused" node "$HERE/manifest-check.js" "$FT" "$WORK/public.yaml" "$WORK/public.yaml"
mut 's/httpsTrigger: \{\}/httpsTrigger: {}\n    dataConnectGraphqlTrigger: {schemaFilePath: venv\/pyvenv.cfg}/' dc
expect 2 "manifest: Data Connect trigger (extra uploaded file) refused" node "$HERE/manifest-check.js" "$FT" "$WORK/dc.yaml" "$WORK/dc.yaml"
mut 's/httpsTrigger: \{\}/eventTrigger: {eventType: x, eventFilters: {}}/' event
expect 2 "manifest: non-HTTPS trigger refused" node "$HERE/manifest-check.js" "$FT" "$WORK/event.yaml" "$WORK/event.yaml"
mut 's/secretEnvironmentVariables: \[\]/secretEnvironmentVariables: [{key: K, secret: S}]/' secret
expect 2 "manifest: secret environment variables refused" node "$HERE/manifest-check.js" "$FT" "$WORK/secret.yaml" "$WORK/secret.yaml"
mut 's/serviceAccountEmail: null/serviceAccountEmail: x\@y.iam.gserviceaccount.com/' sa
expect 2 "manifest: service-account override refused" node "$HERE/manifest-check.js" "$FT" "$WORK/sa.yaml" "$WORK/sa.yaml"
mut 's/^params: \[\]/params: [{name: P}]/' params
expect 2 "manifest: parameters refused" node "$HERE/manifest-check.js" "$FT" "$WORK/params.yaml" "$WORK/params.yaml"
mut 's/serviceAccountEmail: null/serviceAccountEmail: null\n    serviceAccount: x\@y.iam.gserviceaccount.com/' sa2
expect 2 "manifest: canonical serviceAccount field refused" node "$HERE/manifest-check.js" "$FT" "$WORK/sa2.yaml" "$WORK/sa2.yaml"
mut 's/httpsTrigger: \{\}/httpsTrigger: {invoker: null}/' invnull
expect 2 "manifest: invoker null (public on update) refused" node "$HERE/manifest-check.js" "$FT" "$WORK/invnull.yaml" "$WORK/invnull.yaml"
mut 's/httpsTrigger: \{\}/httpsTrigger: {invoker: [a\@b.iam.gserviceaccount.com, c\@d.iam.gserviceaccount.com]}/' invlist
expect 2 "manifest: explicit invoker list (replaces IAM) refused" node "$HERE/manifest-check.js" "$FT" "$WORK/invlist.yaml" "$WORK/invlist.yaml"
mut 's/platform: gcfv2/platform: gcfv2\n    vpc: {connector: x}/' vpc
expect 2 "manifest: unknown endpoint field refused" node "$HERE/manifest-check.js" "$FT" "$WORK/vpc.yaml" "$WORK/vpc.yaml"
mut 's/availableMemoryMb: 512/availableMemoryMb: "512"/' badtype
expect 2 "manifest: wrongly typed field refused" node "$HERE/manifest-check.js" "$FT" "$WORK/badtype.yaml" "$WORK/badtype.yaml"
printf 'extra: 1\n' >>"$WORK/changed.yaml"; cp "$WORK/changed.yaml" "$WORK/extra.yaml"
expect 2 "manifest: unknown top-level key refused" node "$HERE/manifest-check.js" "$FT" "$WORK/extra.yaml" "$WORK/extra.yaml"

# containment check, with stand-in gcloud and curl
FB="$WORK/fakebin"; mkdir -p "$FB"
cat >"$FB/gcloud" <<'SH'
#!/bin/sh
case "$*" in
  *"functions describe"*serviceConfig.service*) [ -n "$FAKE_SVC" ] && echo "$FAKE_SVC" ;;
  *"functions describe"*serviceConfig.uri*) echo "https://fn.example.invalid" ;;
  *"get-iam-policy"*) cat "$FAKE_POLICY" ;;
esac
SH
printf '#!/bin/sh\nprintf %%s "$FAKE_CODE"\n' >"$FB/curl"; chmod +x "$FB/gcloud" "$FB/curl"
printf '{"bindings":[{"role":"roles/run.invoker","members":["serviceAccount:site@p.iam.gserviceaccount.com"]}]}' >"$WORK/private.json"
perl -e 'print q({"bindings":[{"role":"roles/run.invoker","members":["all) . q(Users"]}]})' >"$WORK/public.json"
run_c() { env PATH="$FB:$PATH" FAKE_SVC="$1" FAKE_POLICY="$2" FAKE_CODE="$3" bash "$HERE/containment.sh" fn asia-northeast1 proj /x; }
expect 0 "containment: private service, anonymous 403" run_c projects/p/locations/r/services/fn "$WORK/private.json" 403
expect 1 "containment: public invoker fails" run_c projects/p/locations/r/services/fn "$WORK/public.json" 403
expect 1 "containment: anonymous 200 fails" run_c projects/p/locations/r/services/fn "$WORK/private.json" 200
printf 'not json' >"$WORK/bad.json"; printf '{"bindings": "x"}' >"$WORK/bad2.json"; printf '{"etag": "BwX"}' >"$WORK/empty.json"
expect 1 "containment: malformed policy fails" run_c projects/p/locations/r/services/fn "$WORK/bad.json" 403
expect 1 "containment: non-policy JSON fails" run_c projects/p/locations/r/services/fn "$WORK/bad2.json" 403
expect 0 "containment: policy with no bindings (no invokers) passes" run_c projects/p/locations/r/services/fn "$WORK/empty.json" 403
expect 1 "containment: unreadable function fails" run_c "" "$WORK/private.json" 403

echo; echo "$pass passed, $failn failed"
exit $(( failn > 0 ? 1 : 0 ))
