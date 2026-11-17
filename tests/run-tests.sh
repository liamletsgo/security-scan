#!/usr/bin/env bash
# Tests for security-scan.sh. Builds throwaway repositories and checks exit codes:
# 0 clean, 1 blocked, 2 scanner error. Fixture commits are created with git plumbing
# (write-tree / commit-tree), which never runs hooks.
# Fixture setup fails fast: any error outside a scanner run aborts the whole suite (exit 2),
# so a broken fixture can never be counted as a passing regression test.
set -Eeuo pipefail
trap 'echo "TEST SETUP FAILED at line $LINENO" >&2; exit 2' ERR
HERE=$(cd "$(dirname "$0")/.." && pwd)
pass=0; failn=0
WORK=$(mktemp -d "${TMPDIR:-/tmp}/scan-tests.XXXXXX"); trap 'rm -rf "$WORK"' EXIT
# run the scanner with the same bash that runs this suite (CI uses macOS /bin/bash 3.2), not the shebang's
SCAN="$WORK/scan"
printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$BASH" "$HERE/security-scan.sh" >"$SCAN"; chmod +x "$SCAN"
echo "scanner shell: $BASH ($BASH_VERSION)"

expect() {  # expect <code> <label> <command...>
  local want=$1 label=$2 got=0; shift 2
  "$@" >/dev/null 2>&1 || got=$?
  if [ "$got" -eq "$want" ]; then pass=$((pass+1)); echo "PASS  $label"; else failn=$((failn+1)); echo "FAIL  $label (got $got, want $want)"; fi
}

newrepo() {
  local d="$WORK/$1"; mkdir -p "$d"; git -C "$d" init -q
  git -C "$d" config user.email test@example.invalid; git -C "$d" config user.name test
  echo "$d"
}
commit() {  # commit <repo> <message>: snapshot the index as a new commit on HEAD, no hooks
  local d=$1 msg=$2 tree parent c
  tree=$(git -C "$d" write-tree)
  parent=$(git -C "$d" rev-parse -q --verify HEAD 2>/dev/null || true)
  if [ -n "$parent" ]; then c=$(git -C "$d" commit-tree "$tree" -p "$parent" -m "$msg")
  else c=$(git -C "$d" commit-tree "$tree" -m "$msg"); fi
  git -C "$d" update-ref HEAD "$c"
}
put() { mkdir -p "$(dirname "$1/$2")"; printf '%s\n' "$3" >"$1/$2"; git -C "$1" add -- "$2"; }

R=$(newrepo base); put "$R" README.txt "hello"; commit "$R" init; BASE=$(git -C "$R" rev-parse HEAD)

# clean change
put "$R" app.py "print('ok')"; commit "$R" clean
expect 0 "range: clean change passes" bash -c "cd '$R' && '$SCAN' range $BASE HEAD"

# each risky pattern in its own repo
risky() {  # risky <name> <file> <content>
  local d; d=$(newrepo "$1"); put "$d" README.txt base; commit "$d" init; local b; b=$(git -C "$d" rev-parse HEAD)
  put "$d" "$2" "$3"; commit "$d" bad
  expect 1 "range: blocks $1" bash -c "cd '$d' && '$SCAN' range $b HEAD"
}
risky public-object storage.py 'blob.make_public()'
risky open-rules firestore.rules 'allow read, write: if true;'
risky key-loading app.py 'cred = credentials.Certificate("key.json")'
risky browser-secret .env.local.example2 'NEXT_PUBLIC_API_SECRET=1'
risky deploy-token deploy.sh 'firebase login:ci'
risky postinstall package.json '{ "scripts": { "postinstall": "sh x.sh" } }'
risky key-file creds/service-account-prod.json '{}'
risky env-secret .env 'API_KEY=abc'
risky data-file exports/clients.xlsx 'x'

# a secret added then removed inside the range is still caught (every commit is scanned)
D=$(newrepo removed); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" app.py 'blob.make_public()'; commit "$D" add; put "$D" app.py 'print(1)'; commit "$D" remove
expect 1 "range: change added then removed is still blocked" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# markdown documenting the rules is not a finding
D=$(newrepo docs); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" RULES.md 'Never call make_public() or use allUsers.'; commit "$D" docs
expect 0 "range: markdown docs are not pattern findings" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# data files allowed explicitly
D=$(newrepo fixtures); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" fixtures/sample.csv 'a,b'; commit "$D" fixture
expect 0 "range: data files allowed with SCAN_ALLOW_DATA_FILES" bash -c "cd '$D' && SCAN_ALLOW_DATA_FILES=true '$SCAN' range $B HEAD"

# filenames with spaces and non-ASCII characters
D=$(newrepo names); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" "在庫 報告/my file.pem" 'x'; commit "$D" weird
expect 1 "range: odd filenames are handled (key file with spaces/Japanese)" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# staged mode
D=$(newrepo staged); put "$D" README.txt base; commit "$D" init
put "$D" s.py 'x = "allUsers"'
expect 1 "staged: blocks a staged risky line" bash -c "cd '$D' && '$SCAN' staged"
git -C "$D" reset -q
put "$D" ok.py 'x = 1'
expect 0 "staged: clean staged change passes" bash -c "cd '$D' && '$SCAN' staged"

# tree mode (release folder)
T="$WORK/tree-clean"; mkdir -p "$T"; echo "print(1)" >"$T/main.py"
expect 0 "tree: clean folder passes" "$SCAN" tree "$T"
T="$WORK/tree-bad"; mkdir -p "$T/companies/ACME"; echo x >"$T/companies/ACME/stock.xlsx"
expect 1 "tree: client workbook in the release folder is blocked" "$SCAN" tree "$T"

# fail closed
expect 2 "error: unknown base revision" bash -c "cd '$R' && '$SCAN' range deadbeefdeadbeef HEAD"
expect 2 "error: bad arguments" "$SCAN" range
expect 2 "error: unknown mode" "$SCAN" nonsense
expect 2 "error: not a git repository" bash -c "cd '$WORK' && mkdir -p plain && cd plain && '$SCAN' staged"
expect 2 "error: gitleaks missing" bash -c "cd '$R' && GITLEAKS=/nonexistent/gitleaks '$SCAN' range $BASE HEAD"


# ---------------- regression tests for the Codex review findings ----------------
FAKE="$WORK/fake"; mkdir -p "$FAKE"
printf '#!/bin/sh\necho "12:00PM ERR failed to read git history"\nexit 0\n' >"$FAKE/gitleaks-err0"; chmod +x "$FAKE/gitleaks-err0"
printf '#!/bin/sh\necho "fatal: something broke"\nexit 1\n' >"$FAKE/gitleaks-exit1"; chmod +x "$FAKE/gitleaks-exit1"
expect 2 "gitleaks logs an error but exits 0 -> incomplete scan, error" bash -c "cd '$R' && GITLEAKS='$FAKE/gitleaks-err0' '$SCAN' range $BASE HEAD"
expect 2 "gitleaks error exit (not findings) -> error" bash -c "cd '$R' && GITLEAKS='$FAKE/gitleaks-exit1' '$SCAN' range $BASE HEAD"

# real provider-style secret is caught by gitleaks itself (synthetic token)
TOKEN="ghp_$(printf 'Zq8Lm3Rt7Vx2Bn6Kp4Wd9Hs1Fg5Jc0Ya7Ue3To')"
D=$(newrepo provider); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" config.txt "token = \"$TOKEN\""; commit "$D" add
expect 1 "gitleaks: provider-style token detected" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# the scanned repository cannot weaken gitleaks (own config, ignore file, inline allow)
D=$(newrepo policy); put "$D" .gitleaks.toml '[allowlist]
paths = [".*"]'; put "$D" .gitleaksignore '*'; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" config.txt "token = \"$TOKEN\" # gitleaks:allow"; commit "$D" add
expect 1 "gitleaks: repo config, ignore file and inline allow are ignored" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# a secret introduced only while resolving a merge
D=$(newrepo mergeonly); put "$D" a.txt one; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" a.txt left; commit "$D" left; L=$(git -C "$D" rev-parse HEAD)
git -C "$D" update-ref HEAD "$B"; git -C "$D" read-tree "$B"; put "$D" a.txt right; commit "$D" right; RR=$(git -C "$D" rev-parse HEAD)
put "$D" a.txt "resolved"; put "$D" config.txt "token = \"$TOKEN\""
T=$(git -C "$D" write-tree); M=$(git -C "$D" commit-tree "$T" -p "$L" -p "$RR" -m merge); git -C "$D" update-ref HEAD "$M"
expect 1 "merge: secret added only in the merge resolution is caught" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# .env variants
envcase() {  # envcase <label> <file> <content> <want>
  local d; d=$(newrepo "env-$1"); put "$d" README.txt base; commit "$d" init; local b; b=$(git -C "$d" rev-parse HEAD)
  put "$d" "$2" "$3"; commit "$d" env
  expect "$4" ".env: $1" bash -c "cd '$d' && '$SCAN' range $b HEAD"
}
envcase "production.local name" .env.production.local 'API_KEY=abc' 1
envcase "export and spaces" .env 'export  DB_PASSWORD = hunter2' 1
envcase "example file ignored" .env.example 'API_KEY=placeholder' 0
envcase "non-secret values pass" .env 'STORAGE_BUCKET=my-bucket' 0
envcase "sample file is checked" .env.sample 'API_TOKEN=abc' 1
envcase "template file is checked" .env.template 'DB_PASSWORD=abc' 1
envcase "a value starting with # is a value" .env 'API_TOKEN=#abc' 1
envcase "a comment after spaces is not a value" .env 'API_TOKEN= # set in the secret manager' 0
D=$(newrepo env-history); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" .env 'API_SECRET=abc'; commit "$D" add; put "$D" .env 'STORAGE_BUCKET=x'; commit "$D" fix
expect 1 ".env: secret in an earlier version of the range is caught" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# file name containing a newline
D=$(newrepo newline); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
NL="dir
name"; mkdir -p "$D/$NL"; printf 'API_KEY=abc\n' >"$D/$NL/.env"; git -C "$D" add -- "$NL/.env"; commit "$D" nl
expect 1 "names: .env inside a directory whose name contains a newline" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# type change: symlink replaced by a real file with risky content
D=$(newrepo typechange); put "$D" target.txt x; ln -s target.txt "$D/storage.py"; git -C "$D" add storage.py; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
rm "$D/storage.py"; put "$D" storage.py 'blob.make_public()'; commit "$D" tc
expect 1 "type change: symlink turned into a file is scanned" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# content line that itself starts with '+'
D=$(newrepo plusline); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" app.js '+blob.make_public()'; commit "$D" plus
expect 1 "diff: added line starting with + is still checked" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# file marked -diff / binary in .gitattributes is still read as text
D=$(newrepo attrs); put "$D" .gitattributes '*.cfg -diff'; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" deploy.cfg 'x = make_public()'; commit "$D" cfg
expect 1 "diff: -diff attribute does not hide content" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# divergent branches: a risky line removed on the base branch after divergence is not blamed on head
D=$(newrepo divergent); put "$D" old.py 'x = "allUsers"'; commit "$D" init
git -C "$D" rev-parse HEAD >/dev/null; ROOT=$(git -C "$D" rev-parse HEAD)
put "$D" feature.py 'print(1)'; commit "$D" feature; HEADC=$(git -C "$D" rev-parse HEAD)
git -C "$D" update-ref HEAD "$ROOT"; git -C "$D" read-tree "$ROOT"; git -C "$D" rm -q --cached old.py; rm -f "$D/old.py"; commit "$D" cleanup; BASEC=$(git -C "$D" rev-parse HEAD)
expect 0 "range: changes made only on the base branch are not blamed on head" bash -c "cd '$D' && '$SCAN' range $BASEC $HEADC"

# shallow clone refuses to scan
SH="$WORK/shallow"; git clone -q --depth 1 "file://$R" "$SH" 2>/dev/null
expect 2 "history: shallow clone is an error" bash -c "cd '$SH' && '$SCAN' range HEAD HEAD"

# tree: symlink and unreadable file
T="$WORK/tree-link"; mkdir -p "$T"; echo ok >"$T/a.py"; ln -s /etc/hosts "$T/hosts"
expect 1 "tree: symlink in a deploy payload is blocked" "$SCAN" tree "$T"
if [ "$(id -u)" != 0 ]; then
  T="$WORK/tree-unreadable"; mkdir -p "$T"; echo secret >"$T/locked.py"; chmod 000 "$T/locked.py"
  expect 2 "tree: unreadable file is an error, not clean" "$SCAN" tree "$T"
  chmod 600 "$T/locked.py"
fi
expect 2 "tree: missing directory argument" "$SCAN" tree

# ---------------- v3 regression tests (Codex review of v2) ----------------
slug() { printf '%s' "$1" | tr '/.' '__'; }

# P1-1: provider secrets in paths that gitleaks' default policy excludes are still found
for p in logo.svg package-lock.json node_modules/lib/index.js vendor/x/y.go gitleaks.toml; do
  D=$(newrepo "excl-$(slug "$p")"); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
  put "$D" "$p" "token = \"$TOKEN\""; commit "$D" add
  expect 1 "range: provider token in default-excluded path $p" bash -c "cd '$D' && '$SCAN' range $B HEAD"
  T="$WORK/tree-excl-$(slug "$p")"; mkdir -p "$(dirname "$T/$p")"; printf 'token = "%s"\n' "$TOKEN" >"$T/$p"
  expect 1 "tree: provider token in default-excluded path $p" "$SCAN" tree "$T"
done

# P1-2: provider secrets in binary-marked or binary files, including added-then-removed
D=$(newrepo bin-attr); put "$D" .gitattributes '*.cfg -diff'; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" deploy.cfg "token = \"$TOKEN\""; commit "$D" add
expect 1 "range: provider token in a -diff file" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(newrepo bin-removed); put "$D" .gitattributes '*.cfg binary'; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" deploy.cfg "token = \"$TOKEN\""; commit "$D" add; put "$D" deploy.cfg 'x = 1'; commit "$D" remove
expect 1 "range: provider token added then removed in a binary-marked file" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(newrepo bin-staged); put "$D" .gitattributes '*.cfg -diff'; commit "$D" init
put "$D" deploy.cfg "token = \"$TOKEN\""
expect 1 "staged: provider token in a -diff file" bash -c "cd '$D' && '$SCAN' staged"
D=$(newrepo bin-nul); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
printf 'BIN\000\001\002token = "%s"\000\n' "$TOKEN" >"$D/blob.dat"; git -C "$D" add blob.dat; commit "$D" add
expect 1 "range: provider token inside a file with NUL bytes" bash -c "cd '$D' && '$SCAN' range $B HEAD"
T="$WORK/tree-nul"; mkdir -p "$T"; printf 'BIN\000\001token = "%s"\000\n' "$TOKEN" >"$T/blob.dat"
expect 1 "tree: provider token inside a file with NUL bytes" "$SCAN" tree "$T"

# P1-3: a failing git or gitleaks child is an error even after partial output
REALGIT=$(command -v git)
mkdir -p "$FAKE/git-log-fails" "$FAKE/git-diff-fails" "$FAKE/git-truncated"
printf '#!/bin/sh\n"%s" "$@"; rc=$?\ncase " $* " in *" log "*) exit 1 ;; esac\nexit $rc\n' "$REALGIT" >"$FAKE/git-log-fails/git"
printf '#!/bin/sh\n"%s" "$@"; rc=$?\ncase " $* " in *" diff "*) exit 141 ;; esac\nexit $rc\n' "$REALGIT" >"$FAKE/git-diff-fails/git"
printf '#!/bin/sh\ncase " $* " in *" diff "*--cached*-U0*) printf "diff --git a/x b/x\\n--- a/x\\n+++ b/x\\n@@ -0,0 +1,5 @@\\n+partial\\n"; exit 0 ;; esac\nexec "%s" "$@"\n' "$REALGIT" >"$FAKE/git-truncated/git"
chmod +x "$FAKE"/git-*/git
expect 2 "git log fails after writing output -> error" bash -c "cd '$R' && PATH='$FAKE/git-log-fails':\$PATH '$SCAN' range $BASE HEAD"
D=$(newrepo gitfail-staged); put "$D" README.txt base; commit "$D" init; put "$D" ok.py 'x = 1'
expect 2 "git diff killed (SIGPIPE-style exit) -> error" bash -c "cd '$D' && PATH='$FAKE/git-diff-fails':\$PATH '$SCAN' staged"
expect 2 "truncated diff from git -> error, never clean" bash -c "cd '$D' && PATH='$FAKE/git-truncated':\$PATH '$SCAN' staged"
printf '#!/bin/sh\necho "partial output"\nkill -9 $$\n' >"$FAKE/gitleaks-killed"; chmod +x "$FAKE/gitleaks-killed"
expect 2 "gitleaks killed by a signal -> error" bash -c "cd '$R' && GITLEAKS='$FAKE/gitleaks-killed' '$SCAN' range $BASE HEAD"

# P2-4: content that looks like a patch header is still checked (range and tree)
D=$(newrepo headerlike); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" app.js '++ b/ blob.make_public();'; commit "$D" add
expect 1 "diff: content that becomes '+++ b/' after the diff marker is still checked" bash -c "cd '$D' && '$SCAN' range $B HEAD"
T="$WORK/tree-headerlike"; mkdir -p "$T"; printf '%s\n' '++ b/ blob.make_public();' >"$T/app.js"
expect 1 "tree: file content that looks like a patch header is still checked" "$SCAN" tree "$T"

# only added lines count: removing an old secret is not blocked
D=$(newrepo removal); put "$D" config.txt "token = \"$TOKEN\""; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" config.txt 'x = 1'; commit "$D" fix
expect 0 "range: removing an existing secret is not blocked" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# deploy payload: archives are blocked (contents are not unpacked)
T="$WORK/tree-archive"; mkdir -p "$T"; echo ok >"$T/main.py"; printf 'PK\003\004' >"$T/bundle.zip"
expect 1 "tree: archive in a deploy payload is blocked" "$SCAN" tree "$T"

# must run from the repository root
mkdir -p "$R/sub"
expect 2 "error: run from a subdirectory" bash -c "cd '$R/sub' && '$SCAN' range $BASE HEAD"

# ---------------- v4 regression tests (Codex review of v3) ----------------
# expect_msg: exit code AND the expected diagnostic, so an unrelated finding cannot hide a missed one
expect_msg() {  # expect_msg <code> <ERE> <label> <command...>
  local want=$1 re=$2 label=$3 got=0; shift 3
  "$@" >"$WORK/msg.out" 2>&1 || got=$?
  if [ "$got" -eq "$want" ] && grep -qE -- "$re" "$WORK/msg.out"; then pass=$((pass+1)); echo "PASS  $label"
  else failn=$((failn+1)); echo "FAIL  $label (got $got, want $want /$re/): $(tr '\n' ' ' <"$WORK/msg.out" | cut -c1-200)"; fi
}
SECRET='secrets detected'
rangerepo() {  # rangerepo <name>: new repo with one base commit; prints the repo path
  local d; d=$(newrepo "$1"); put "$d" README.txt base; commit "$d" init; echo "$d"
}
filler() { perl -e 'print "x" x $ARGV[0]' "$1"; }

# P1-1: binary file-type signatures do not stop the secret scan (same file and a later file)
D=$(rangerepo v4-pdf); B=$(git -C "$D" rev-parse HEAD)
printf '%%PDF-1.4\ntoken = "%s"\n' "$TOKEN" >"$D/a.txt"; git -C "$D" add a.txt; commit "$D" pdf
expect_msg 1 "$SECRET" "range: PDF signature then a token in the same file" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(rangerepo v4-pdf2); B=$(git -C "$D" rev-parse HEAD)
printf '%%PDF-1.4\nnothing here\n' >"$D/a.txt"; printf 'token = "%s"\n' "$TOKEN" >"$D/b.txt"; git -C "$D" add a.txt b.txt; commit "$D" pdf2
expect_msg 1 "$SECRET" "range: PDF signature file followed by a token in a later file" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(rangerepo v4-tar); B=$(git -C "$D" rev-parse HEAD)
{ filler 257; printf 'ustar\ntoken = "%s"\n' "$TOKEN"; } >"$D/t.txt"; git -C "$D" add t.txt; commit "$D" tar
expect_msg 1 "$SECRET" "range: tar signature at offset 257 then a token" bash -c "cd '$D' && '$SCAN' range $B HEAD"
T="$WORK/tree-v4-pdf"; mkdir -p "$T"; printf '%%PDF-1.4\ntoken = "%s"\n' "$TOKEN" >"$T/a.txt"
expect_msg 1 "$SECRET" "tree: PDF signature then a token" "$SCAN" tree "$T"
D=$(newrepo v4-pdf-staged); put "$D" README.txt base; commit "$D" init
printf '%%PDF-1.4\ntoken = "%s"\n' "$TOKEN" >"$D/a.txt"; git -C "$D" add a.txt
expect_msg 1 "$SECRET" "staged: PDF signature then a token" bash -c "cd '$D' && '$SCAN' staged"

# P1-2: a token across gitleaks' 100 KB buffer and across the scanner's own piece boundaries
# gitleaks cuts a long line at byte 125,000 (100 KB buffer + 25 KB peek): 124980 straddles it for raw
# input, 123956 straddles it after the 1 KB guard; 24570 and 40950 straddle the scanner's own pieces.
for off in 124980 123956 24570 40950; do
  D=$(rangerepo "v4-long-$off"); B=$(git -C "$D" rev-parse HEAD)
  { filler "$off"; printf '%s' "$TOKEN"; filler 60000; printf '\n'; } >"$D/min.js"; git -C "$D" add min.js; commit "$D" long
  expect_msg 1 "$SECRET" "range: token at byte $off of a long minified line" bash -c "cd '$D' && '$SCAN' range $B HEAD"
  T="$WORK/tree-v4-long-$off"; mkdir -p "$T"; cp "$D/min.js" "$T/min.js"
  expect_msg 1 "$SECRET" "tree: token at byte $off of a long minified line" "$SCAN" tree "$T"
done
D=$(newrepo v4-long-staged); put "$D" README.txt base; commit "$D" init
{ filler 124980; printf '%s' "$TOKEN"; filler 60000; printf '\n'; } >"$D/min.js"; git -C "$D" add min.js
expect_msg 1 "$SECRET" "staged: token across gitleaks' 125 KB cut" bash -c "cd '$D' && '$SCAN' staged"

# P1-3: path-gated gitleaks rules still apply (Terraform, Kubernetes Secret YAML, nuget.config)
TF='resource "x" "y" {
  password = "Kq7vRt2mZp"
}'
K8='apiVersion: v1
kind: Secret
metadata:
  name: app
data:
  dbpass: cGFzc3dvcmQxMjM0NTY3OA=='
NU='<configuration><packageSourceCredentials><feed><add key="ClearTextPassword" value="Zx9vQ2mLp4Rt" /></feed></packageSourceCredentials></configuration>'
for spec in "infra/main.tf|$TF" "k8s/secret.yml|$K8" "NuGet.Config|$NU"; do
  p=${spec%%|*}; body=${spec#*|}
  D=$(rangerepo "v4-gated-$(slug "$p")"); B=$(git -C "$D" rev-parse HEAD)
  put "$D" "$p" "$body"; commit "$D" gated
  expect_msg 1 "$SECRET" "range: path-gated rule fires for $p" bash -c "cd '$D' && '$SCAN' range $B HEAD"
  T="$WORK/tree-v4-gated-$(slug "$p")"; mkdir -p "$(dirname "$T/$p")"; printf '%s\n' "$body" >"$T/$p"
  expect_msg 1 "$SECRET" "tree: path-gated rule fires for $p" "$SCAN" tree "$T"
done

# P1-4: history semantics are pinned (merge config, root commits, replace refs, grafts)
D=$(newrepo v4-merge-removed); put "$D" a.txt one; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
put "$D" a.txt left; commit "$D" left; L=$(git -C "$D" rev-parse HEAD)
git -C "$D" update-ref HEAD "$B"; git -C "$D" read-tree "$B"; put "$D" a.txt right; commit "$D" right; RR=$(git -C "$D" rev-parse HEAD)
put "$D" a.txt resolved; put "$D" config.txt "token = \"$TOKEN\""
T=$(git -C "$D" write-tree); M=$(git -C "$D" commit-tree "$T" -p "$L" -p "$RR" -m merge); git -C "$D" update-ref HEAD "$M"
git -C "$D" rm -q --cached config.txt; rm -f "$D/config.txt"; commit "$D" "remove again"
git -C "$D" config log.diffMerges off; git -C "$D" config log.showRoot false; git -C "$D" config diff.renames copies
expect_msg 1 "$SECRET" "history: merge-only secret later removed, with log.diffMerges=off" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(newrepo v4-unrelated); put "$D" README.txt base; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
git -C "$D" rm -q --cached README.txt; put "$D" other.txt "token = \"$TOKEN\""
T=$(git -C "$D" write-tree); ROOT2=$(git -C "$D" commit-tree "$T" -m "unrelated root")
git -C "$D" read-tree "$B"
T=$(git -C "$D" write-tree); M=$(git -C "$D" commit-tree "$T" -p "$B" -p "$ROOT2" -m "merge unrelated, drop its file"); git -C "$D" update-ref HEAD "$M"
git -C "$D" config log.showRoot false
expect_msg 1 "$SECRET" "history: secret in an unrelated root merged then dropped, log.showRoot=false" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(rangerepo v4-replace); B=$(git -C "$D" rev-parse HEAD)
put "$D" config.txt "token = \"$TOKEN\""; commit "$D" bad; BAD=$(git -C "$D" rev-parse HEAD)
put "$D" config.txt "x = 1"; T=$(git -C "$D" write-tree); CLEAN=$(git -C "$D" commit-tree "$T" -p "$B" -m clean)
git -C "$D" replace "$BAD" "$CLEAN"
expect_msg 1 "$SECRET" "history: replace refs cannot hide a commit" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(rangerepo v4-grafts); B=$(git -C "$D" rev-parse HEAD); put "$D" x.txt 1; commit "$D" two
mkdir -p "$D/.git/info"; git -C "$D" rev-parse HEAD >"$D/.git/info/grafts"
expect_msg 2 'grafted' "history: grafted repositories are refused" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# P1-5: git metadata inside a deploy payload is blocked, not skipped
T="$WORK/tree-v4-gitdir"; mkdir -p "$T/.git"; echo ok >"$T/main.py"; printf '[remote "origin"]\n\turl = x\n' >"$T/.git/config"
expect_msg 1 'git metadata' "tree: .git inside a deploy payload is blocked" "$SCAN" tree "$T"

# P2: metadata failures are errors, not "absent"; repository identity; dependency failures
mkdir -p "$FAKE/git-lstree-fails"
printf '#!/bin/sh\ncase " $* " in *" ls-tree "*) exit 128 ;; esac\nexec "%s" "$@"\n' "$REALGIT" >"$FAKE/git-lstree-fails/git"; chmod +x "$FAKE/git-lstree-fails/git"
D=$(rangerepo v4-envmeta); B=$(git -C "$D" rev-parse HEAD); put "$D" .env 'STORAGE_BUCKET=x'; commit "$D" env
expect_msg 2 'ERROR' "env: failing tree lookup is an error, not a deleted file" bash -c "cd '$D' && PATH='$FAKE/git-lstree-fails':\$PATH '$SCAN' range $B HEAD"
expect_msg 2 'root of the repository' "identity: GIT_WORK_TREE pointing elsewhere is refused" bash -c "cd '$R' && GIT_WORK_TREE='$WORK' '$SCAN' range $BASE HEAD"
mkdir -p "$FAKE/perl-fails"; printf '#!/bin/sh\nexit 1\n' >"$FAKE/perl-fails/perl"; chmod +x "$FAKE/perl-fails/perl"
expect_msg 2 'ERROR' "perl failing is an error" bash -c "cd '$R' && PATH='$FAKE/perl-fails':\$PATH '$SCAN' range $BASE HEAD"
printf '#!/bin/sh\necho "1:00PM INF scanned ~1 bytes (1 bytes) in 1ms"\nexit 0\n' >"$FAKE/gitleaks-short"; chmod +x "$FAKE/gitleaks-short"
expect_msg 2 'incomplete scan' "gitleaks scanning fewer bytes than written is an error" bash -c "cd '$R' && GITLEAKS='$FAKE/gitleaks-short' '$SCAN' range $BASE HEAD"
printf '#!/bin/sh\nexit 0\n' >"$FAKE/gitleaks-silent"; chmod +x "$FAKE/gitleaks-silent"
expect_msg 2 'did not report' "gitleaks reporting nothing is an error" bash -c "cd '$R' && GITLEAKS='$FAKE/gitleaks-silent' '$SCAN' range $BASE HEAD"
if [ "$(id -u)" != 0 ]; then
  T="$WORK/tree-v4-unreadable-dir"; mkdir -p "$T/locked"; echo x >"$T/locked/a.py"; echo ok >"$T/b.py"; chmod 000 "$T/locked"
  expect 2 "tree: unreadable subdirectory is an error" "$SCAN" tree "$T"
  chmod 700 "$T/locked"
fi

# submodules, renames, archives by content
D=$(rangerepo v4-gitlink); B=$(git -C "$D" rev-parse HEAD)
git -C "$D" update-index --add --cacheinfo "160000,$B,vendor/lib"; commit "$D" sub
expect_msg 1 'submodules' "range: a submodule (gitlink) is blocked" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(newrepo v4-rename); put "$D" RULES.md 'Never call blob.make_public() in code.'; commit "$D" init; B=$(git -C "$D" rev-parse HEAD)
git -C "$D" mv RULES.md storage.py; commit "$D" rename
expect_msg 1 'public storage objects' "range: content renamed from .md into code is checked" bash -c "cd '$D' && '$SCAN' range $B HEAD"
T="$WORK/tree-v4-zipdata"; mkdir -p "$T"; echo ok >"$T/main.py"; printf 'PK\003\004rest' >"$T/notes.dat"
expect_msg 1 'archives' "tree: archive detected by content despite its name" "$SCAN" tree "$T"

# parser edge cases: CRLF, no final newline, odd names, markdown classification
D=$(rangerepo v4-crlf); B=$(git -C "$D" rev-parse HEAD)
printf 'a = 1\r\nblob.make_public()\r\n' >"$D/w.py"; git -C "$D" add w.py; commit "$D" crlf
expect_msg 1 'public storage objects' "parser: CRLF line is checked" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(rangerepo v4-nonl); B=$(git -C "$D" rev-parse HEAD); printf 'x = "allUsers"' >"$D/nonl.py"; git -C "$D" add nonl.py; commit "$D" nonl
expect_msg 1 'public storage objects' "parser: last line without a newline is checked" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(rangerepo v4-mdname); B=$(git -C "$D" rev-parse HEAD)
printf 'blob.make_public()\n' >"$D/my notes.md"; printf 'x = 1\n' >"$D/q\"uote.py"; git -C "$D" add "my notes.md" "q\"uote.py"; commit "$D" md
expect 0 "parser: quoted/space names parse; markdown with a space in its name is docs" bash -c "cd '$D' && '$SCAN' range $B HEAD"
D=$(rangerepo v4-quoted-code); B=$(git -C "$D" rev-parse HEAD)
printf 'blob.make_public()\n' >"$D/q\"uote.py"; git -C "$D" add "q\"uote.py"; commit "$D" q
expect_msg 1 'public storage objects' "parser: code file with a quote in its name is checked" bash -c "cd '$D' && '$SCAN' range $B HEAD"

# ---------------- v5 regression tests (Codex review of v4) ----------------
afill() { perl -e 'print "a" x $ARGV[0]' "$1"; }
SGTOK="3fa85f64$(printf %s 57174562b3fc2c963f66afa61c9e8b2d)"   # assembled at run time: no literal in this file
ctxcase() {  # ctxcase <name> <file>: range, staged and tree runs must all report a secret
  local d; d=$(rangerepo "v5-$1"); local b; b=$(git -C "$d" rev-parse HEAD)
  cp "$2" "$d/$1.txt"; git -C "$d" add "$1.txt"; commit "$d" ctx
  expect_msg 1 "$SECRET" "range: $1" bash -c "cd '$d' && '$SCAN' range $b HEAD"
  d=$(newrepo "v5-$1-staged"); put "$d" README.txt base; commit "$d" init; cp "$2" "$d/$1.txt"; git -C "$d" add "$1.txt"
  expect_msg 1 "$SECRET" "staged: $1" bash -c "cd '$d' && '$SCAN' staged"
  local t="$WORK/tree-v5-$1"; mkdir -p "$t"; cp "$2" "$t/$1.txt"
  expect_msg 1 "$SECRET" "tree: $1" "$SCAN" tree "$t"
}
# P1-1: rules whose context spans more than a piece (curl credentials after a 26 KB URL; a bare token whose
# keyword is 26 KB away; the same 40 KB away inside a 150 KB file)
F="$WORK/ctx-curl"; { printf 'curl "https://example.com/'; afill 26000; printf '" -u "admin:%s"\n' "Kq7v$(printf %s Rt2mZpXw9Lb3)"; } >"$F"
ctxcase curl-long-url "$F"
# (a bare 40-hex token only counts when "sourcegraph" is in the same gitleaks fragment)
F="$WORK/ctx-sg"; { printf '%s\n' "$SGTOK"; afill 26000; printf '\nsourcegraph\n'; } >"$F"
ctxcase keyword-26kb-away "$F"
# caught only by the whole-unit run: keyword 110 KB after the token in a 120 KB file (native context)
F="$WORK/ctx-whole"; { printf '%s\n' "$SGTOK"; afill 110000; printf '\nsourcegraph\n'; afill 8000; printf '\n'; } >"$F"
ctxcase keyword-110kb-away-in-120kb "$F"
# caught only by the windows: gitleaks alone cuts at 125 KB between keyword (118 KB) and token (130 KB)
F="$WORK/ctx-window"; { afill 118000; printf '\nsourcegraph\n'; afill 12000; printf '\n%s\n' "$SGTOK"; afill 30000; printf '\n'; } >"$F"
ctxcase keyword-across-gitleaks-cut "$F"
# 30 KB between keyword (110 KB) and token (140 KB), across gitleaks' cut: needs the 98 KB windows
F="$WORK/ctx-window30"; { afill 110000; printf '\nsourcegraph\n'; afill 30000; printf '\n%s\n' "$SGTOK"; afill 20000; printf '\n'; } >"$F"
ctxcase keyword-30kb-before-token-across-cut "$F"

# P1-2: archives with a prefix and an innocent name are still recognised
T="$WORK/tree-v5-prefixzip"; mkdir -p "$T"; echo ok >"$T/main.py"
{ printf 'XX'; git -C "$R" archive --format=zip HEAD; } >"$T/payload.dat"
expect_msg 1 'archives' "tree: zip with a leading prefix and a .dat name is blocked" "$SCAN" tree "$T"
T="$WORK/tree-v5-prefixgz"; mkdir -p "$T"; echo ok >"$T/main.py"
{ printf 'header\n'; git -C "$R" archive --format=tar.gz HEAD; } >"$T/blob.bin"
expect_msg 1 'archives' "tree: gzip after a text header is blocked" "$SCAN" tree "$T"

# ---------------- v6 regression tests (Codex final review) ----------------
# a pre-POSIX tar (no "ustar"), space-padded so it has no NUL bytes, named innocently: caught by its header checksum
legacy_tar() { perl -e '
  my $data = "a,b\n1,2\n"; my $f = sub { my ($v, $w) = @_; substr($v . (" " x $w), 0, $w) };
  my $h = $f->("clients.csv", 100) . $f->("0000644", 8) . $f->("0000000", 8) . $f->("0000000", 8)
        . $f->(sprintf("%011o", length $data), 12) . $f->("14000000000", 12) . (" " x 8) . "0" . (" " x 355);
  my $sum = unpack("%32C*", $h); substr($h, 148, 8) = sprintf("%06o ", $sum) . " ";
  print $h, $f->($data, 512);'; }
T="$WORK/tree-v6-legacytar"; mkdir -p "$T"; echo ok >"$T/main.py"; legacy_tar >"$T/payload.dat"
expect_msg 1 'archives' "tree: legacy tar without ustar or NUL bytes, innocently named, is blocked" "$SCAN" tree "$T"
T="$WORK/tree-v6-binary"; mkdir -p "$T"; echo ok >"$T/main.py"; printf 'abc\000def\n' >"$T/data.bin"
expect_msg 1 'binary files' "tree: a binary file (NUL bytes) in a deploy payload is blocked" "$SCAN" tree "$T"
# risky patterns in other valid spellings, including across lines
for spec in "rules1|firestore.rules|allow get, list: if true;" \
            "rules2|firestore.rules|allow create, update, delete: if true;" \
            "rules3|storage.rules|allow read, write: if
  true;" \
            "keyspace|app.py|cred = credentials.Certificate (\"key.json\")" \
            "infospace|app.py|c = service_account.Credentials.from_service_account_info (d)"; do
  name=${spec%%|*}; rest=${spec#*|}; file=${rest%%|*}; body=${rest#*|}
  D=$(rangerepo "v6-$name"); B=$(git -C "$D" rev-parse HEAD); put "$D" "$file" "$body"; commit "$D" risky
  expect 1 "range: risky pattern variant $name" bash -c "cd '$D' && '$SCAN' range $B HEAD"
done

# merges that touch .env files (range mode lists each .env version; a merge's diff must not be read as commit ids)
envmerge() {  # envmerge <name> <merge .env content>: two branches both edit .env, merged with the given resolution
  local d; d=$(newrepo "$1"); put "$d" .env 'STORAGE_BUCKET=base'; commit "$d" init; local EB; EB=$(git -C "$d" rev-parse HEAD)
  put "$d" .env 'STORAGE_BUCKET=left'; commit "$d" left; local l; l=$(git -C "$d" rev-parse HEAD)
  git -C "$d" update-ref HEAD "$EB"; git -C "$d" read-tree "$EB"; put "$d" .env 'STORAGE_BUCKET=right'; commit "$d" right
  local r t m; r=$(git -C "$d" rev-parse HEAD); put "$d" .env "$2"
  t=$(git -C "$d" write-tree); m=$(git -C "$d" commit-tree "$t" -p "$l" -p "$r" -m merge); git -C "$d" update-ref HEAD "$m"
  echo "$d"
}
D=$(envmerge v7-envmerge-clean 'STORAGE_BUCKET=merged'); EB=$(git -C "$D" rev-list --max-parents=0 HEAD)
expect_msg 0 'security\] clean' "env: a merge commit that edits .env scans cleanly" bash -c "cd '$D' && '$SCAN' range $EB HEAD"
D=$(envmerge v7-envmerge-secret 'API_SECRET=abc'); EB=$(git -C "$D" rev-list --max-parents=0 HEAD)
expect_msg 1 '\.env file with secret-like values' "env: secret introduced only by a merge's .env resolution" bash -c "cd '$D' && '$SCAN' range $EB HEAD"
D=$(envmerge v7-envmerge-removed 'API_SECRET=abc'); EB=$(git -C "$D" rev-list --max-parents=0 HEAD); put "$D" .env 'STORAGE_BUCKET=fixed'; commit "$D" fix
expect_msg 1 '\.env file with secret-like values' "env: merge-only .env secret later removed is still caught" bash -c "cd '$D' && '$SCAN' range $EB HEAD"

# ---------------- v8: history and new modes, coverage, pattern report, exemption, old-commit guard ----------------
# The caller-only options are refused under CI, so this section clears the CI indicators that GitHub
# Actions sets; the refusal tests set them explicitly.
unset GITHUB_ACTIONS CI
# A syntactically valid commit id that names no object, assembled at run time (gitleaks would read a
# literal 40-hex string as a token).
FAKEID=$(printf '%s' 0123456789abcdef 0123456789abcdef 01234567)
# Secret-shaped fixtures are assembled at run time so this file never contains them literally.
PKM="-----BEGIN PRIV""ATE KEY-----"
ENTRA="ab$(printf 'c')8Q~$(printf 'k%.0s' $(seq 1 34))"
mkrepo() {  # mkrepo <name> <path> <content> [<path> <content>]...: one commit per pair; prints the repo path
  local d; d=$(newrepo "$1"); shift
  while [ $# -ge 2 ]; do put "$d" "$1" "$2"; commit "$d" "add $1"; shift 2; done
  echo "$d"
}
sha256() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; }

# history mode
D=$(mkrepo v8-hist-clean README.txt base app.py "print('ok')")
expect_msg 0 'scanned 2 commits \(history\)' "history: clean history passes and reports its coverage" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v8-hist-root storage.py 'blob.make_public()')
expect 1 "history: the root commit's additions are scanned" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v8-hist-removed README.txt base app.py "token = '$TOKEN'" app.py "token = None")
expect_msg 1 "$SECRET" "history: a secret added and later removed is caught" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v8-hist-ja README.txt base "顧客/在庫表.xlsx" x)
git -C "$D" rm -q --cached -- "顧客/在庫表.xlsx"; commit "$D" "remove the data file"
expect_msg 1 'client data files' "history: a Japanese-named data file in an old commit blocks" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(envmerge v8-hist-envmerge 'API_SECRET=abc')
expect_msg 1 '\.env file with secret-like values' "history: a merge-only .env secret is caught" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v8-hist-args README.txt base)
expect 2 "history: unknown head is an error" bash -c "cd '$D' && '$SCAN' history $FAKEID"
expect 2 "history: data-file allowance is refused" bash -c "cd '$D' && SCAN_ALLOW_DATA_FILES=true '$SCAN' history HEAD"
expect 2 "history: wrong argument count is an error" bash -c "cd '$D' && '$SCAN' history"

# new mode: the caller lists the commits the destination has
D=$(mkrepo v8-new storage.py 'blob.make_public()'); NB=$(git -C "$D" rev-parse HEAD)
put "$D" app.py "print('ok')"; commit "$D" clean
printf '%s\n' "$NB" >"$WORK/v8.has"
expect_msg 0 'scanned 1 commits \(new\)' "new: commits the destination has are not scanned" bash -c "cd '$D' && '$SCAN' new HEAD '$WORK/v8.has'"
put "$D" more.py 'blob.make_public()'; commit "$D" risky
expect_msg 1 'public storage objects' "new: a risky new commit blocks" bash -c "cd '$D' && '$SCAN' new HEAD '$WORK/v8.has'"
git -C "$D" rev-parse HEAD >"$WORK/v8.has2"
expect_msg 0 'scanned 0 commits \(new\)' "new: nothing new is clean" bash -c "cd '$D' && '$SCAN' new HEAD '$WORK/v8.has2'"
printf '%s\n' "$FAKEID" >"$WORK/v8.has3"
expect_msg 1 'scanned 3 commits \(new\).*public storage objects' "new: ids missing locally only widen the scan" bash -c "cd '$D' && '$SCAN' new HEAD '$WORK/v8.has3' 2>&1 | tr '\n' ' '; exit \${PIPESTATUS[0]}"
: >"$WORK/v8.has4"
expect_msg 1 'scanned 3 commits \(new\)' "new: an empty list scans everything" bash -c "cd '$D' && '$SCAN' new HEAD '$WORK/v8.has4' 2>&1 | tr '\n' ' '; exit \${PIPESTATUS[0]}"
printf 'origin/main\n' >"$WORK/v8.has5"
expect 2 "new: a list entry that is not a full commit id is an error" bash -c "cd '$D' && '$SCAN' new HEAD '$WORK/v8.has5'"
expect 2 "new: a missing list is an error" bash -c "cd '$D' && '$SCAN' new HEAD '$WORK/none'"
R2=$(rangerepo v8-range-count); put "$R2" app.py "print('ok')"; commit "$R2" one; RB=$(git -C "$R2" rev-list --max-parents=0 HEAD)
expect_msg 0 'scanned 1 commits \(range\)' "range: reports its coverage" bash -c "cd '$R2' && '$SCAN' range $RB HEAD"

# pattern report (history mode only, never under CI)
D=$(mkrepo v8-report storage.py 'blob.make_public()' rules/firestore.rules "$(printf 'allow read,\n  write: if true;')" other.py 'a.make_public(); b.make_public()')
C1=$(git -C "$D" rev-list --reverse HEAD | sed -n 1p); C3=$(git -C "$D" rev-parse HEAD)
expect 0 "report: code patterns are reported, not blocked" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.report' '$SCAN' history HEAD"
H1=$(sha256 'make_public(')
expect 0 "report: commit, path, label and span hash are attributed" perl -MJSON::PP -e '
  my ($f, $c, $h) = @ARGV; open(my $x, "<", $f) or exit 1; my $ok = 0;
  while (<$x>) { my $j = decode_json($_); $ok = 1 if $j->{commit} eq $c && $j->{path} eq "storage.py"
    && $j->{label} =~ /^public storage objects/ && $j->{span_sha256} eq $h && $j->{count} == 1 }
  exit($ok ? 0 : 1)' "$WORK/v8.report" "$C1" "$H1"
expect 0 "report: a multi-line match is reported once with its file" perl -MJSON::PP -e '
  open(my $x, "<", shift) or exit 1; my $n = 0;
  while (<$x>) { my $j = decode_json($_); $n++ if $j->{path} eq "rules/firestore.rules" && $j->{label} =~ /^open Firebase rules/ }
  exit($n == 1 ? 0 : 1)' "$WORK/v8.report"
expect 0 "report: repeated matches in one unit are counted" perl -MJSON::PP -e '
  my ($f, $c) = @ARGV; open(my $x, "<", $f) or exit 1; my $ok = 0;
  while (<$x>) { my $j = decode_json($_); $ok = 1 if $j->{commit} eq $c && $j->{path} eq "other.py" && $j->{count} == 2 }
  exit($ok ? 0 : 1)' "$WORK/v8.report" "$C3"
HML=$(sha256 "$(printf 'allow read,\n  write: if true')")
expect 0 "report: a multi-line match carries the hash of its whole span" perl -MJSON::PP -e '
  my ($f, $h) = @ARGV; open(my $x, "<", $f) or exit 1; my $ok = 0;
  while (<$x>) { my $j = decode_json($_); $ok = 1 if $j->{path} eq "rules/firestore.rules" && $j->{span_sha256} eq $h }
  exit($ok ? 0 : 1)' "$WORK/v8.report" "$HML"
# merge parents: a merge that adds a risky file is reported once per parent, with that parent
D=$(newrepo v8-report-merge); put "$D" README.txt base; commit "$D" base; MBASE=$(git -C "$D" rev-parse HEAD)
put "$D" a.py 'a = 1'; commit "$D" left; ML=$(git -C "$D" rev-parse HEAD)
git -C "$D" update-ref HEAD "$MBASE"; git -C "$D" read-tree "$MBASE"; put "$D" b.py 'b = 1'; commit "$D" right; MR=$(git -C "$D" rev-parse HEAD)
git -C "$D" read-tree "$ML"; put "$D" b.py 'b = 1'; put "$D" m.py 'm.make_public()'
MT=$(git -C "$D" write-tree); MM=$(git -C "$D" commit-tree "$MT" -p "$ML" -p "$MR" -m merge); git -C "$D" update-ref HEAD "$MM"; git -C "$D" read-tree "$MM"
expect 0 "report: merge history scans without blocking in report mode" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.rm' '$SCAN' history HEAD"
expect 0 "report: a merge's hit is attributed to each parent separately" perl -MJSON::PP -e '
  my ($f, $m, $l, $r) = @ARGV; open(my $x, "<", $f) or exit 1; my %p;
  while (<$x>) { my $j = decode_json($_); $p{$j->{parent}}++ if $j->{commit} eq $m && $j->{path} eq "m.py" }
  exit(($p{$l} && $p{$r} && keys %p == 2) ? 0 : 1)' "$WORK/v8.rm" "$MM" "$ML" "$MR"
# unusual path bytes round-trip exactly (git C-quotes tabs and quotes)
UP=$'q/a"b\tc 顧客.py'
D=$(newrepo v8-report-path); put "$D" README.txt base; commit "$D" base; put "$D" "$UP" 'x.make_public()'; commit "$D" odd
expect 0 "report: an unusual path scans in report mode" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.rp' '$SCAN' history HEAD"
expect 0 "report: path_hex holds the exact path bytes" perl -MJSON::PP -e '
  my ($f, $p) = @ARGV; open(my $x, "<", $f) or exit 1; my $ok = 0;
  while (<$x>) { my $j = decode_json($_); $ok = 1 if $j->{path_hex} eq unpack("H*", $p) }
  exit($ok ? 0 : 1)' "$WORK/v8.rp" "$UP"
# a merge whose tree equals its first parent: git omits that empty diff; the hit belongs to the second
D=$(newrepo v8-merge-empty); put "$D" f.txt a; commit "$D" base; EB0=$(git -C "$D" rev-parse HEAD)
put "$D" r.py 'r.make_public()'; commit "$D" left; EL=$(git -C "$D" rev-parse HEAD)
git -C "$D" update-ref HEAD "$EB0"; git -C "$D" read-tree "$EB0"; put "$D" o.txt o; commit "$D" right; ER=$(git -C "$D" rev-parse HEAD)
EM=$(git -C "$D" commit-tree "$(git -C "$D" rev-parse "$EL^{tree}")" -p "$EL" -p "$ER" -m merge); git -C "$D" update-ref HEAD "$EM"; git -C "$D" read-tree "$EM"
expect 0 "report: a merge equal to its first parent scans in report mode" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.rme' '$SCAN' history HEAD"
expect 0 "report: its hit is attributed to the second parent, not the first" perl -MJSON::PP -e '
  my ($f, $m, $l, $r) = @ARGV; open(my $x, "<", $f) or exit 1; my %p;
  while (<$x>) { my $j = decode_json($_); $p{$j->{parent}}++ if $j->{commit} eq $m }
  exit(($p{$r} && !$p{$l}) ? 0 : 1)' "$WORK/v8.rme" "$EM" "$EL" "$ER"
# Markdown: secret material blocks, prose about a PEM header does not
KEYBODY=$(printf 'QUJDRA%.0s' $(seq 1 12))
D=$(mkrepo v8-md-key README.txt base notes.md "$(printf '%s\n%s\n' "$PKM" "$KEYBODY")")
expect_msg 1 'private key material|secrets detected' "markdown: a key header with a body blocks" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v8-md-key-escaped README.txt base notes.md "key: \"$PKM\\n$KEYBODY\\n\"")
expect_msg 1 'private key material|secrets detected' "markdown: an escaped key body blocks" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v8-md-entra README.txt base notes.md "The old secret was $ENTRA in the app.")
expect_msg 1 'Entra client secret|secrets detected' "markdown: an Entra secret value blocks" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v8-md-prose README.txt base notes.md "The review found the $PKM header named nine times, without a key.")
expect_msg 0 'clean' "markdown: prose that names a PEM header passes" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v8-md-report storage.py 'blob.make_public()' notes.md "The old secret was $ENTRA.")
expect_msg 1 'Entra client secret|secrets detected' "markdown: secret material blocks in report mode too" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.rmd' '$SCAN' history HEAD"
# Markdown units are checked one by one: a header in one file and a digest in another never combine
DIGEST=$(printf 'ab12cd34%.0s' $(seq 1 6))
D=$(newrepo v9-md-split-files); put "$D" a.md "Rotate the key whose file starts $PKM"; put "$D" b.md "$DIGEST"; commit "$D" both
expect_msg 0 'clean' "markdown: a header in one file and a digest in another (same commit) do not combine" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v9-md-split-commits a.md "Rotate the key whose file starts $PKM" a.md "$(printf 'Rotate the key whose file starts %s\n%s' "$PKM" "")" c.md "$DIGEST")
expect_msg 0 'clean' "markdown: a header and a digest added in different commits do not combine" bash -c "cd '$D' && '$SCAN' history HEAD"
T="$WORK/v9-md-tree"; mkdir -p "$T"; printf 'Rotate the key whose file starts %s\n' "$PKM" >"$T/a.md"; printf '%s\n' "$DIGEST" >"$T/b.md"
expect_msg 0 'clean' "markdown: tree mode checks each file on its own" "$SCAN" tree "$T"
printf '%s\n%s\n' "$PKM" "$KEYBODY" >"$T/c.md"
expect_msg 1 'key body in Markdown' "markdown: tree mode still blocks a key in one file" "$SCAN" tree "$T"
D=$(mkrepo v9-md-quoted README.txt base notes.md "$(printf '> %s\n> %s\n' "$PKM" "$KEYBODY")")
expect_msg 1 'key body in Markdown|secrets detected' "markdown: a blockquoted key (truncated, no end line) blocks" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v9-md-crlf README.txt base notes.md "key: \"$PKM\\r\\n$KEYBODY\"")
expect_msg 1 'key body in Markdown|secrets detected' "markdown: a key body after an escaped CRLF blocks" bash -c "cd '$D' && '$SCAN' history HEAD"
D=$(mkrepo v8-report-pk storage.py 'blob.make_public()' k.txt "$PKM")
expect_msg 1 'private key material' "report: private-key material still blocks" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.r2' '$SCAN' history HEAD"
D=$(mkrepo v8-report-entra storage.py 'blob.make_public()' cfg.js "const s = '$ENTRA';")
expect_msg 1 'Entra client secret' "report: an Entra secret still blocks" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.r3' '$SCAN' history HEAD"
D=$(mkrepo v8-report-gl storage.py 'blob.make_public()' app.py "token = '$TOKEN'")
expect_msg 1 "$SECRET" "report: gitleaks findings still block" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.r4' '$SCAN' history HEAD"
D=$(mkrepo v8-report-key storage.py 'blob.make_public()' creds/service-account-x.json '{}')
expect_msg 1 'credential/key files' "report: key files still block" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.r5' '$SCAN' history HEAD"
D=$(mkrepo v8-report-data storage.py 'blob.make_public()' exports/a.csv 'x')
expect_msg 1 'client data files' "report: data files still block" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.r6' '$SCAN' history HEAD"
D=$(mkrepo v8-report-env storage.py 'blob.make_public()' .env 'API_KEY=abc')
expect_msg 1 '\.env file with secret-like values' "report: .env secrets still block" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.r7' '$SCAN' history HEAD"
D=$(mkrepo v8-report-modes README.txt base app.py "print('ok')"); DB=$(git -C "$D" rev-list --max-parents=0 HEAD)
expect 2 "report: refused in range mode" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.r8' '$SCAN' range $DB HEAD"
expect 2 "report: refused in staged mode" bash -c "cd '$D' && SCAN_PATTERN_REPORT='$WORK/v8.r8' '$SCAN' staged"
expect 2 "report: refused in tree mode" bash -c "SCAN_PATTERN_REPORT='$WORK/v8.r8' '$SCAN' tree '$D'"
expect 2 "report: refused under GitHub Actions" bash -c "cd '$D' && GITHUB_ACTIONS=true SCAN_PATTERN_REPORT='$WORK/v8.r8' '$SCAN' history HEAD"
expect 2 "report: refused under CI" bash -c "cd '$D' && CI=true SCAN_PATTERN_REPORT='$WORK/v8.r8' '$SCAN' history HEAD"
D=$(mkrepo v8-report-off storage.py 'blob.make_public()')
expect_msg 1 'public storage objects' "history without a report blocks on code patterns" bash -c "cd '$D' && '$SCAN' history HEAD"

# pattern exemption (exact paths; code patterns only; never under CI)
printf '# test list\nscanner/rules.sh\n' >"$WORK/v8.exempt"
D=$(newrepo v8-exempt); put "$D" README.txt base; commit "$D" init
put "$D" scanner/rules.sh "check 'make_public\\s*\\(|allUsers'"
expect 0 "exempt: an exempt path may contain code-pattern text" bash -c "cd '$D' && SCAN_PATTERN_EXEMPT_FILE='$WORK/v8.exempt' '$SCAN' staged"
put "$D" app.py 'blob.make_public()'
expect_msg 1 'public storage objects' "exempt: other paths are still checked" bash -c "cd '$D' && SCAN_PATTERN_EXEMPT_FILE='$WORK/v8.exempt' '$SCAN' staged"
git -C "$D" rm -q --cached app.py
put "$D" scanner/rules.sh "$PKM"
expect_msg 1 'private key material' "exempt: secret material in an exempt path still blocks" bash -c "cd '$D' && SCAN_PATTERN_EXEMPT_FILE='$WORK/v8.exempt' '$SCAN' staged"
expect 2 "exempt: refused under CI" bash -c "cd '$D' && CI=true SCAN_PATTERN_EXEMPT_FILE='$WORK/v8.exempt' '$SCAN' staged"
expect 2 "exempt: a missing list is an error" bash -c "cd '$D' && SCAN_PATTERN_EXEMPT_FILE='$WORK/none' '$SCAN' staged"
expect 2 "exempt: cannot be combined with a report" bash -c "cd '$D' && SCAN_PATTERN_EXEMPT_FILE='$WORK/v8.exempt' SCAN_PATTERN_REPORT='$WORK/v8.r9' '$SCAN' history HEAD"
expect 2 "exempt: not supported in tree mode" bash -c "SCAN_PATTERN_EXEMPT_FILE='$WORK/v8.exempt' '$SCAN' tree '$D'"

# old-commit guard
GUARD="$WORK/guard"
printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$BASH" "$HERE/old-commit-guard.sh" >"$GUARD"; chmod +x "$GUARD"
D=$(mkrepo v8-guard README.txt base a.py 1 b.py 2); OLD=$(git -C "$D" rev-parse HEAD~1)
printf '# first changed\n%s\n' "$OLD" >"$WORK/v8.deny"
expect_msg 1 'BLOCKED' "guard: a listed reachable commit blocks" bash -c "cd '$D' && '$GUARD' '$WORK/v8.deny' HEAD"
expect_msg 0 'checked 1 commits against 1 listed' "guard: history before the listed commit passes" bash -c "cd '$D' && '$GUARD' '$WORK/v8.deny' HEAD~2"
printf '%s\n' "$FAKEID" >"$WORK/v8.deny2"
expect 0 "guard: listed commits missing locally are fine" bash -c "cd '$D' && '$GUARD' '$WORK/v8.deny2' HEAD"
printf '%s\n' "${OLD:0:12}" >"$WORK/v8.deny3"
expect 2 "guard: a short commit id is refused" bash -c "cd '$D' && '$GUARD' '$WORK/v8.deny3' HEAD"
printf 'not-a-commit\n' >"$WORK/v8.deny4"
expect 2 "guard: a malformed line is an error" bash -c "cd '$D' && '$GUARD' '$WORK/v8.deny4' HEAD"
printf '# nothing\n' >"$WORK/v8.deny5"
expect 2 "guard: an empty denylist is an error" bash -c "cd '$D' && '$GUARD' '$WORK/v8.deny5' HEAD"
expect 2 "guard: an unknown revision is an error" bash -c "cd '$D' && '$GUARD' '$WORK/v8.deny2' $FAKEID"
expect 2 "guard: a missing denylist is an error" bash -c "cd '$D' && '$GUARD' '$WORK/none' HEAD"
git clone -q --depth 1 "file://$D" "$WORK/v8-guard-shallow"
expect_msg 2 'shallow repository' "guard: a shallow clone is refused" bash -c "cd '$WORK/v8-guard-shallow' && '$GUARD' '$WORK/v8.deny2' HEAD"
git clone -q --bare "file://$D" "$WORK/v8-guard-grafts.git"; printf '%s\n' "$(git -C "$D" rev-parse HEAD)" >"$WORK/v8-guard-grafts.git/info/grafts"
expect_msg 2 'grafted history' "guard: a grafted (bare) repository is refused" bash -c "cd '$WORK/v8-guard-grafts.git' && '$GUARD' '$WORK/v8.deny' HEAD"
D2=$(mkrepo v8-guard-other other.txt x); git -C "$D" fetch -q "$D2" HEAD; OTHER=$(git -C "$D2" rev-parse HEAD)
printf '%s\n' "$OTHER" >"$WORK/v8.deny6"
expect 0 "guard: a listed commit in a disconnected history does not affect this history" bash -c "cd '$D' && '$GUARD' '$WORK/v8.deny6' HEAD"
expect 1 "guard: several revisions are checked together" bash -c "cd '$D' && '$GUARD' '$WORK/v8.deny6' HEAD '$OTHER'"

echo; echo "$pass passed, $failn failed"
exit $(( failn > 0 ? 1 : 0 ))
