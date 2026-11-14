#!/usr/bin/env bash
# Tests for security-scan.sh. Builds throwaway repositories and checks exit codes:
# 0 clean, 1 blocked, 2 scanner error. Fixture commits are created with git plumbing
# (write-tree / commit-tree), which never runs hooks.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
SCAN="$HERE/security-scan.sh"
pass=0; failn=0
WORK=$(mktemp -d "${TMPDIR:-/tmp}/scan-tests.XXXXXX"); trap 'rm -rf "$WORK"' EXIT

expect() {  # expect <code> <label> <command...>
  local want=$1 label=$2; shift 2
  "$@" >/dev/null 2>&1; local got=$?
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

echo; echo "$pass passed, $failn failed"; [ "$failn" -eq 0 ]
