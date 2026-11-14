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

echo; echo "$pass passed, $failn failed"; [ "$failn" -eq 0 ]
