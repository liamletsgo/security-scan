#!/usr/bin/env bash
# security-scan.sh — a small, fail-closed pre-commit / pre-push / CI scanner.
#
# Usage:
#   security-scan.sh staged                 scan staged changes (pre-commit hook)
#   security-scan.sh range <base> <head>    scan every commit in base..head and the net diff (pre-push, CI)
#   security-scan.sh tree [dir]             scan files in a directory as they are (CI release tree)
#
# Checks: secrets (gitleaks, required), credential/key files, .env files with secret-like values,
# client data files (spreadsheets, exports, dumps) and risky code patterns (public storage access,
# open database rules, service-account key loading, secrets exposed to browsers, personal deploy
# tokens, install-script hooks).
#
# Exit codes: 0 = clean, 1 = findings (blocked), 2 = scanner error (also blocks; never "clean").
# Environment:
#   SCAN_ALLOW_DATA_FILES=true    allow data files (synthetic fixtures), reported as warnings
#   GITLEAKS                      path to gitleaks (default: first on PATH)
# Markdown files (*.md) are excluded from the risky-pattern check only (they document rules);
# secrets in them are still caught by gitleaks.
set -euo pipefail

RED=$'\033[31m'; YEL=$'\033[33m'; NC=$'\033[0m'
[ -t 2 ] || { RED=""; YEL=""; NC=""; }
fail=0
TMP=$(mktemp -d "${TMPDIR:-/tmp}/security-scan.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

die()   { echo "${RED}[security] ERROR:${NC} $*" >&2; exit 2; }
block() { echo "${RED}[security] BLOCKED:${NC} $*" >&2; fail=1; }
warn()  { echo "${YEL}[security] warning:${NC} $*" >&2; }

MODE=${1:-}
GITLEAKS=${GITLEAKS:-$(command -v gitleaks || true)}
[ -n "$GITLEAKS" ] && [ -x "$GITLEAKS" ] || die "gitleaks is required (install a pinned release) — refusing to report clean without a secret scan"

case "$MODE" in
  staged)
    git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"
    ;;
  range)
    [ $# -eq 3 ] || die "usage: security-scan.sh range <base> <head>"
    git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"
    BASE=$2; HEAD_REF=$3
    git rev-parse --verify --quiet "$HEAD_REF^{commit}" >/dev/null || die "unknown head revision: $HEAD_REF"
    git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null || die "unknown base revision: $BASE (fetch enough history)"
    RANGE="$BASE..$HEAD_REF"
    ;;
  tree)
    DIR=${2:-.}
    [ -d "$DIR" ] || die "no such directory: $DIR"
    ;;
  *) die "usage: security-scan.sh staged | range <base> <head> | tree [dir]" ;;
esac

# ---- 1. secrets (gitleaks; values are always redacted) -----------------------------------------
case "$MODE" in
  staged) "$GITLEAKS" git --pre-commit --staged --redact --no-banner --exit-code 1 . >"$TMP/gl" 2>&1 || { rc=$?; cat "$TMP/gl" >&2; [ $rc -eq 1 ] && block "secrets detected in staged changes" || die "gitleaks failed (exit $rc)"; } ;;
  range)  "$GITLEAKS" git --log-opts="$RANGE" --redact --no-banner --exit-code 1 . >"$TMP/gl" 2>&1 || { rc=$?; cat "$TMP/gl" >&2; [ $rc -eq 1 ] && block "secrets detected in $RANGE" || die "gitleaks failed (exit $rc)"; } ;;
  tree)   "$GITLEAKS" dir --redact --no-banner --exit-code 1 "$DIR" >"$TMP/gl" 2>&1 || { rc=$?; cat "$TMP/gl" >&2; [ $rc -eq 1 ] && block "secrets detected in $DIR" || die "gitleaks failed (exit $rc)"; } ;;
esac

# ---- collect file names (NUL-safe) and added lines ----------------------------------------------
: >"$TMP/files"; : >"$TMP/added"
case "$MODE" in
  staged)
    git diff --cached --name-only -z --diff-filter=ACMR >"$TMP/files" || die "git diff failed"
    git diff --cached -U0 --diff-filter=ACMR -- . ':(exclude)*.md' >"$TMP/diff" || die "git diff failed"
    ;;
  range)
    # every file added or changed by any commit in the range (merge commits included)
    git log -m --name-only -z --format= --diff-filter=ACMR "$RANGE" >"$TMP/files" || die "git log failed"
    # added lines from every commit (merges compared with each parent) plus the net range diff
    { git log -m -p --format= --diff-filter=ACMR "$RANGE" -- . ':(exclude)*.md' && git diff -U0 "$BASE" "$HEAD_REF" -- . ':(exclude)*.md'; } >"$TMP/diff" || die "git log/diff failed"
    ;;
  tree)
    (cd "$DIR" && find . -type f -not -path './.git/*' -print0) >"$TMP/files" || die "listing $DIR failed"
    (cd "$DIR" && find . -type f -not -path './.git/*' -not -name '*.md' -print0 |
       while IFS= read -r -d '' f; do sed 's/^/+/' "$f" 2>/dev/null || true; done) >"$TMP/diff" || die "reading $DIR failed"
    ;;
esac
grep -aE '^\+[^+]' "$TMP/diff" >"$TMP/added" || true

# ---- 2. credential / key files by name -----------------------------------------------------------
CRED_RE='(firebase-adminsdk-.*\.json|service[-_]?account.*\.json|gha-creds-.*\.json|\.pem$|\.p12$|\.pfx$|\.key$|(^|/)id_(rsa|ed25519|ecdsa)$|credentials\.json$)'
tr '\0' '\n' <"$TMP/files" | sort -u | grep -iE "$CRED_RE" >"$TMP/cred" || true
[ -s "$TMP/cred" ] && { block "credential/key files must never be committed or deployed:"; sed 's/^/    /' "$TMP/cred" >&2; }

# ---- 3. .env files with secret-like values (every version in the range) ---------------------------
ENV_SECRET_RE='^[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDS|CREDENTIAL|API_KEY|CLIENT_SECRET)[A-Z0-9_]*=.+'
tr '\0' '\n' <"$TMP/files" | sort -u | grep -E '(^|/)\.env(\.[A-Za-z0-9_-]+)?$' | grep -vE '\.env\.example$' >"$TMP/envs" || true
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$MODE" in
    staged) content=$(git show ":$f" 2>/dev/null || true) ;;
    tree)   content=$(cat "$DIR/$f" 2>/dev/null || true) ;;
    range)  content=$(git log --format=%H "$RANGE" -- "$f" | while read -r c; do git show "$c:$f" 2>/dev/null || true; done) ;;
  esac
  if printf '%s\n' "$content" | grep -qiE "$ENV_SECRET_RE"; then block "$f contains secret-like values. Use a secret manager; commit only .env.example with placeholders."; fi
done <"$TMP/envs"

# ---- 4. client data files ------------------------------------------------------------------------
tr '\0' '\n' <"$TMP/files" | sort -u | grep -iE '\.(xlsx|xlsm|xls|csv|tsv|parquet|sqlite|db|dump|bak)$' >"$TMP/data" || true
if [ -s "$TMP/data" ]; then
  if [ "${SCAN_ALLOW_DATA_FILES:-false}" = true ]; then warn "data files present (allowed by SCAN_ALLOW_DATA_FILES):"; sed 's/^/    /' "$TMP/data" >&2
  else block "client data files must not go into git or deploy packages:"; sed 's/^/    /' "$TMP/data" >&2; fi
fi

# ---- 5. risky code patterns in added lines ---------------------------------------------------------
check() { if grep -qaE -- "$2" "$TMP/added"; then block "$1"; fi; }
check "private key material"                                  'BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY'
check "Microsoft Entra client secret"                         '[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}'
check "public storage objects (make_public / allUsers)"       'make_public\(|allUsers|allAuthenticatedUsers'
check "open Firebase rules (if true)"                         'allow[^;]*(read|write)[^;]*:[[:space:]]*if[[:space:]]+true'
check "secret exposed to the browser via NEXT_PUBLIC_"        'NEXT_PUBLIC_[A-Z0-9_]*(PRIVATE|SECRET|PASSWORD|CLIENT_EMAIL)'
check "service-account key loading (use workload identity)"   'credentials\.Certificate\(|from_service_account_file\(|from_service_account_info\(|GOOGLE_APPLICATION_CREDENTIALS[[:space:]]*='
check "personal deploy token (use keyless federation)"        'firebase[[:space:]]+login:ci|--token[[:space:]]+"?\$\{?\{?[[:space:]]*(secrets\.)?FIREBASE_TOKEN'
check "install-script hook added (review supply-chain risk)"  '"(pre|post)install"[[:space:]]*:'

if [ $fail -ne 0 ]; then
  echo "${RED}[security] Stopped by security checks.${NC} Fix the items above; do not bypass the scan." >&2
  exit 1
fi
echo "[security] clean ($MODE)" >&2
exit 0
