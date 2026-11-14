#!/usr/bin/env bash
# Tests for security-scan.sh. Builds throwaway repositories and checks exit codes:
# 0 clean, 1 blocked, 2 scanner error. Fixture commits are created with git plumbing
# (write-tree / commit-tree), which never runs hooks.
# Fixture setup fails fast: any error outside a scanner run aborts the whole suite (exit 2),
# so a broken fixture can never be counted as a passing regression test.
set -Eeuo pipefail
trap 'echo "TEST SETUP FAILED at line $LINENO" >&2; exit 2' ERR
HERE=$(cd "$(dirname "$0")/.." && pwd)
SCAN="$HERE/security-scan.sh"
pass=0; failn=0
WORK=$(mktemp -d "${TMPDIR:-/tmp}/scan-tests.XXXXXX"); trap 'rm -rf "$WORK"' EXIT

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
  if parent=$(git -C "$d" rev-parse -q --verify HEAD); then c=$(git -C "$d" commit-tree "$tree" -p "$parent" -m "$msg")
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

echo; echo "$pass passed, $failn failed"
exit $(( failn > 0 ? 1 : 0 ))
