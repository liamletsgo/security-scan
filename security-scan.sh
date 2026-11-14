#!/usr/bin/env bash
# security-scan.sh — a small, fail-closed pre-commit / pre-push / CI scanner.
#
# Usage:
#   security-scan.sh staged                 scan staged changes (pre-commit hook)
#   security-scan.sh range <base> <head>    scan what <head> adds relative to <base>: every commit in
#                                           base..head (merges against each parent) and the net diff
#                                           from merge-base(base, head) to head (pre-push, CI)
#   security-scan.sh tree <dir>             scan the files of a directory as they are (deploy payload)
# Run from the repository root (staged and range modes).
#
# Checks: secrets (gitleaks, required, with a policy the scanned repository cannot change), credential
# and key files, .env files with secret-like values, client data files (spreadsheets, exports, dumps),
# symlinks and archives in a deploy payload, and risky code patterns (public storage objects, open
# Firebase rules, service-account key loading, secrets exposed via NEXT_PUBLIC_, personal deploy tokens,
# install hooks).
#
# How input is produced: the scanner runs git itself (text diffs; no textconv or external diff; config
# that could change the output is pinned), checks git's exit status, and extracts added lines with a
# strict patch parser that fails on anything it cannot account for. gitleaks only reads that text on
# stdin, so its git integration, path-based exclusions and binary-diff skipping are never involved.
#
# Exit codes: 0 = clean, 1 = findings (blocked), 2 = scanner error (blocks; never reported as clean).
# Environment (set by the caller, not by the scanned repository):
#   SCAN_ALLOW_DATA_FILES=true    report data files as warnings instead of findings (synthetic fixtures)
#   GITLEAKS                      gitleaks binary (default: first on PATH)
# Markdown files (*.md) are excluded from the risky-pattern check only; gitleaks still scans them.
set -Eeuo pipefail
export LC_ALL=C
unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML GIT_EXTERNAL_DIFF GIT_DIFF_OPTS 2>/dev/null || true

RED=$'\033[31m'; YEL=$'\033[33m'; NC=$'\033[0m'
[ -t 2 ] || { RED=""; YEL=""; NC=""; }
fail=0
TMP=$(mktemp -d "${TMPDIR:-/tmp}/security-scan.XXXXXX") || { echo "[security] ERROR: mktemp failed" >&2; exit 2; }
trap 'rm -rf "$TMP"' EXIT
trap 'echo "[security] ERROR: unexpected failure at line $LINENO" >&2; exit 2' ERR

die()   { echo "${RED}[security] ERROR:${NC} $*" >&2; exit 2; }
block() { echo "${RED}[security] BLOCKED:${NC} $*" >&2; fail=1; }
warn()  { echo "${YEL}[security] warning:${NC} $*" >&2; }

# grep wrapper: 0 = match, 1 = no match, anything else = error (never treated as "no match")
grepq() { local rc=0; grep "$@" >/dev/null 2>"$TMP/grep.err" || rc=$?; [ $rc -le 1 ] || die "grep failed: $(cat "$TMP/grep.err")"; return $rc; }

MODE=${1:-}
GITLEAKS=${GITLEAKS:-$(command -v gitleaks || true)}
[ -n "$GITLEAKS" ] && [ -x "$GITLEAKS" ] || die "gitleaks is required (install a pinned release); refusing to report clean without a secret scan"
command -v perl >/dev/null 2>&1 || die "perl is required (patch parser)"

# git with every setting that could alter diff output pinned
G=(git -c core.quotePath=false -c diff.noprefix=false -c diff.mnemonicPrefix=false -c diff.relative=false
       -c color.ui=never -c log.showSignature=false -c core.attributesFile=/dev/null)
DIFF=(--text --no-textconv --no-ext-diff --no-color -U0)

need_complete_git() {
  git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"
  [ "$(git rev-parse --is-shallow-repository)" = false ] || die "shallow clone: fetch the full history (fetch-depth: 0) so the whole range can be scanned"
  [ -z "$(git rev-parse --show-cdup)" ] || die "run from the repository root"
}

case "$MODE" in
  staged) [ $# -eq 1 ] || die "usage: security-scan.sh staged"; need_complete_git ;;
  range)
    [ $# -eq 3 ] || die "usage: security-scan.sh range <base> <head>"
    need_complete_git
    BASE=$2; HEAD_REF=$3
    git rev-parse --verify --quiet "$HEAD_REF^{commit}" >/dev/null || die "unknown head revision: $HEAD_REF"
    git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null || die "unknown base revision: $BASE (fetch it)"
    MB=$(git merge-base "$BASE" "$HEAD_REF") || die "no merge base between $BASE and $HEAD_REF"
    RANGE="$BASE..$HEAD_REF"
    ;;
  tree)
    [ $# -eq 2 ] || die "usage: security-scan.sh tree <dir>"
    DIR=$2; [ -d "$DIR" ] || die "no such directory: $DIR"
    ;;
  *) die "usage: security-scan.sh staged | range <base> <head> | tree <dir>" ;;
esac

# ---- patch parser ---------------------------------------------------------------------------------------
# Reads a unified diff (git diff / git log -p) and writes every added line to $1 (all files) and to $2
# (all files except *.md). Hunk boundaries come from the @@ line counts, so a content line that looks
# like a header can never be dropped. Anything unexpected, or a truncated hunk, is an error.
parse_patch() {
  perl -e '
    use strict; use warnings;
    open(my $all, ">", $ARGV[0]) or die "open: $!\n"; open(my $code, ">", $ARGV[1]) or die "open: $!\n";
    binmode STDIN; binmode $all; binmode $code;
    my ($old, $new, $md) = (0, 0, 0);
    while (defined(my $l = <STDIN>)) {
      if ($old > 0 || $new > 0) {
        my $c = substr($l, 0, 1);
        if    ($c eq "+") { my $t = substr($l, 1); $t .= "\n" unless $t =~ /\n\z/;
                            print $all $t; print $code $t unless $md; $new--; }
        elsif ($c eq "-") { $old--; }
        elsif ($c eq " " || $l eq "\n") { $old--; $new--; }
        elsif ($c eq "\\") { }
        else  { die "unparseable line inside a hunk\n"; }
        die "hunk longer than its header\n" if $old < 0 || $new < 0;
        next;
      }
      if ($l =~ /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/) { $old = $1 // 1; $new = $2 // 1; next; }
      if ($l =~ /^@@@/) { die "combined diff not supported\n"; }
      if ($l =~ /^\+\+\+ (.*?)\t?\r?\n?\z/s) { $md = ($1 =~ /\.md"?\z/) ? 1 : 0; next; }
      if ($l =~ /^[+-]/ && $l !~ /^--- /) { die "diff line outside a hunk\n"; }
    }
    die "truncated hunk\n" if $old > 0 || $new > 0;
    close $all or die "close: $!\n"; close $code or die "close: $!\n";
  ' "$1" "$2" <"$3" 2>"$TMP/parse.err" || die "could not parse the diff: $(cat "$TMP/parse.err")"
}

# ---- 1. collect file names, added lines and the text to scan for secrets ---------------------------------
: >"$TMP/files"; : >"$TMP/secret_input"; : >"$TMP/added"
case "$MODE" in
  staged)
    "${G[@]}" diff --cached --name-only -z --diff-filter=ACMRT >"$TMP/files"
    "${G[@]}" diff --cached "${DIFF[@]}" --diff-filter=ACMRT >"$TMP/patch"
    parse_patch "$TMP/secret_input" "$TMP/added" "$TMP/patch"
    ;;
  range)
    "${G[@]}" log -m --full-history --name-only -z --format= --diff-filter=ACMRT "$RANGE" >"$TMP/files"
    # every commit in the range (merges against each parent), then the net change from the merge base
    "${G[@]}" log -m -p --full-history "${DIFF[@]}" --format='commit %H' --diff-filter=ACMRT "$RANGE" >"$TMP/patch"
    "${G[@]}" diff "${DIFF[@]}" --diff-filter=ACMRT "$MB" "$HEAD_REF" >>"$TMP/patch"
    parse_patch "$TMP/secret_input" "$TMP/added" "$TMP/patch"
    ;;
  tree)
    (cd "$DIR" && find . \( -type f -o -type l \) -not -path './.git/*' -print0) >"$TMP/files"
    : >"$TMP/links"
    while IFS= read -r -d '' f; do
      if [ -L "$DIR/$f" ]; then printf '%s\n' "$f" >>"$TMP/links"; continue; fi
      [ -r "$DIR/$f" ] || die "cannot read $f"
      cat -- "$DIR/$f" >>"$TMP/secret_input" || die "cannot read $f"
      printf '\n' >>"$TMP/secret_input"
      case "$f" in
        *.md) ;;
        *) cat -- "$DIR/$f" >>"$TMP/added" || die "cannot read $f"; printf '\n' >>"$TMP/added" ;;
      esac
    done <"$TMP/files"
    if [ -s "$TMP/links" ]; then block "symlinks are not allowed in a deploy payload (their targets are not scanned):"; sed 's/^/    /' "$TMP/links" >&2; fi
    ;;
esac

# ---- 2. secrets: gitleaks with a fixed policy, stdin only -------------------------------------------
# Built-in rules only; the scanned repository's .gitleaks.toml, .gitleaksignore and inline
# "gitleaks:allow" comments are ignored, and stdin input carries no file path, so the default policy's
# path exclusions (lockfiles, images, vendored code, ...) cannot hide anything. Findings use exit code 3
# so they cannot be confused with errors.
printf '[extend]\nuseDefault = true\n' >"$TMP/gitleaks.toml"
mkdir -p "$TMP/noignore"
rc=0
"$GITLEAKS" stdin --config "$TMP/gitleaks.toml" --gitleaks-ignore-path "$TMP/noignore" --ignore-gitleaks-allow \
  --redact --no-banner --exit-code 3 --log-level warn <"$TMP/secret_input" >"$TMP/gl.out" 2>&1 || rc=$?
if [ $rc -eq 3 ]; then cat "$TMP/gl.out" >&2; block "secrets detected"
elif [ $rc -ne 0 ]; then cat "$TMP/gl.out" >&2; die "gitleaks failed (exit $rc)"
elif grepq -aiE '(^|[[:space:]])(ERR|ERROR|FTL|FATAL)([[:space:]]|$)|level=(error|fatal)|(WRN|WARN).*(fail|error|unable|skip|could not|cannot)' "$TMP/gl.out"; then
  cat "$TMP/gl.out" >&2; die "gitleaks reported errors but exited 0: treating the scan as incomplete"
fi

# helper: run a regex test on every file name, NUL-safe (names may contain spaces, newlines, Japanese)
names_matching() {  # names_matching <ERE> <outfile>: case-insensitive, in-process (no pipeline to hide errors)
  local re=$1 f; : >"$2"
  shopt -s nocasematch
  while IFS= read -r -d '' f; do
    if [[ $f =~ $re ]]; then printf '%s\0' "$f" >>"$2"; fi
  done <"$TMP/files"
  shopt -u nocasematch
}
show_names() { tr '\0' '\n' <"$1" | sort -u | sed 's/^/    /' >&2; }

# ---- 3. credential / key files by name ---------------------------------------------------------------
names_matching '(firebase-adminsdk-.*\.json|service[-_]?account.*\.json|gha-creds-.*\.json|\.pem$|\.p12$|\.pfx$|\.key$|(^|/)id_(rsa|ed25519|ecdsa)$|credentials\.json$)' "$TMP/cred"
if [ -s "$TMP/cred" ]; then block "credential/key files must never be committed or deployed:"; show_names "$TMP/cred"; fi

# ---- 4. .env files with secret-like values: every version, each checked on its own ------------------
ENV_SECRET_RE='^[[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDS|CREDENTIAL|API_KEY|APIKEY|CLIENT_SECRET)[A-Za-z0-9_]*[[:space:]]*=[[:space:]]*[^[:space:]#]'
names_matching '(^|/)\.env([.][A-Za-z0-9_.-]+)?$' "$TMP/envs"
n=0
while IFS= read -r -d '' f; do
  case "$f" in *.env.example|*.env.sample|*.env.template) continue ;; esac
  case "$MODE" in
    staged) n=$((n+1)); git show ":$f" >"$TMP/env.$n" 2>/dev/null || die "cannot read staged $f" ;;
    tree)   n=$((n+1)); cat "$DIR/$f" >"$TMP/env.$n" 2>/dev/null || die "cannot read $f" ;;
    range)
      git log -m --full-history --format=%H "$RANGE" -- ":(literal)$f" >"$TMP/env.commits"
      while IFS= read -r c; do
        n=$((n+1))
        git cat-file -e "$c:$f" 2>/dev/null || { : >"$TMP/env.$n"; continue; }   # deleted in this commit
        git show "$c:$f" >"$TMP/env.$n" 2>/dev/null || die "cannot read $f at $c"
      done <"$TMP/env.commits"
      ;;
  esac
done <"$TMP/envs"
for ((i = 1; i <= n; i++)); do
  if grepq -aiE "$ENV_SECRET_RE" "$TMP/env.$i"; then block ".env file with secret-like values (use a secret manager; commit only .env.example):"; show_names "$TMP/envs"; break; fi
done

# ---- 5. client data files; archives in a deploy payload -----------------------------------------------
names_matching '\.(xlsx|xlsm|xls|csv|tsv|parquet|sqlite|db|dump|bak)$' "$TMP/data"
if [ -s "$TMP/data" ]; then
  if [ "${SCAN_ALLOW_DATA_FILES:-false}" = true ]; then warn "data files present (allowed by SCAN_ALLOW_DATA_FILES):"; show_names "$TMP/data"
  else block "client data files must not go into git or deploy packages:"; show_names "$TMP/data"; fi
fi
if [ "$MODE" = tree ]; then
  names_matching '\.(zip|tar|tgz|gz|bz2|xz|zst|7z|rar|jar|war|whl|egg)$' "$TMP/archives"
  if [ -s "$TMP/archives" ]; then block "archives are not allowed in a deploy payload (their contents are not scanned):"; show_names "$TMP/archives"; fi
fi

# ---- 6. risky code patterns in added lines -------------------------------------------------------------
check() { if grepq -aE -- "$2" "$TMP/added"; then block "$1"; fi; }
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
