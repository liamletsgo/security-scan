#!/usr/bin/env bash
# security-scan.sh — a small, fail-closed pre-commit / pre-push / CI scanner.
#
# Usage:
#   security-scan.sh staged                 scan staged changes (pre-commit hook)
#   security-scan.sh range <base> <head>    scan what <head> adds relative to <base>: every commit in
#                                           base..head (merges against each parent) and the net diff
#                                           from merge-base(base, head) to head (pre-push, CI)
#   security-scan.sh tree <dir>             scan the files of a directory as they are (deploy payload)
# Run staged and range mode from the root of the repository's work tree.
#
# Checks: secrets (gitleaks, required, with a policy the scanned repository cannot change), credential
# and key files, .env files with secret-like values, client data files (spreadsheets, exports, dumps),
# submodules, symlinks, git metadata and archives in a deploy payload, and risky code patterns (public
# storage objects, open Firebase rules, service-account key loading, secrets exposed via NEXT_PUBLIC_,
# personal deploy tokens, install hooks).
#
# How input is produced: the scanner runs git itself (text diffs; no renames, textconv or external diff;
# history and output settings pinned; replace refs disabled; grafts refused), checks git's exit status,
# and extracts added lines with a strict patch parser that fails on anything it cannot account for.
# Secret scanning: the content is written as small pieces (under 26 KB, overlapping by 8 KB, each led by
# a 1 KB text guard, named only by file-type class) and gitleaks scans that folder. Pieces are too small
# for gitleaks to split, the guard stops binary file-type detection from skipping a piece, the names keep
# path-gated rules (PHP, Terraform/HCL, YAML, nuget.config) working and cannot match path exclusions, and
# the scan fails unless gitleaks reports exactly the number of bytes written.
#
# Exit codes: 0 = clean, 1 = findings (blocked), 2 = scanner error (blocks; never reported as clean).
# Environment (set by the caller, not by the scanned repository):
#   SCAN_ALLOW_DATA_FILES=true    report data files as warnings instead of findings (synthetic fixtures)
#   GITLEAKS                      gitleaks binary (default: first on PATH)
# Markdown files (*.md) are excluded from the risky-pattern check only; gitleaks still scans them.
set -Eeuo pipefail
export LC_ALL=C GIT_NO_REPLACE_OBJECTS=1
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
command -v perl >/dev/null 2>&1 || die "perl is required"

# Every git call goes through G: settings that change history traversal or diff output are pinned.
G=(git --no-replace-objects
   -c core.quotePath=false -c core.attributesFile=/dev/null -c color.ui=never
   -c diff.noprefix=false -c diff.mnemonicPrefix=false -c diff.relative=false -c diff.renames=false
   -c diff.ignoreSubmodules=none -c log.showRoot=true -c log.diffMerges=separate -c log.showSignature=false)
DIFF=(--text --no-textconv --no-ext-diff --no-color --no-renames -U0)
HIST=(--diff-merges=separate --full-history --no-renames)

need_repo_root() {
  local inside shallow top grafts
  inside=$("${G[@]}" rev-parse --is-inside-work-tree 2>/dev/null) || die "not inside a git work tree"
  [ "$inside" = true ] || die "not inside a git work tree"
  shallow=$("${G[@]}" rev-parse --is-shallow-repository)
  [ "$shallow" = false ] || die "shallow clone: fetch the full history (fetch-depth: 0) so the whole range can be scanned"
  top=$("${G[@]}" rev-parse --show-toplevel)
  [ "$top" = "$(pwd -P)" ] || die "run from the root of the repository's work tree ($top)"
  grafts=$("${G[@]}" rev-parse --git-path info/grafts)
  [ ! -e "$grafts" ] || die "grafted history (info/grafts) is not supported: it rewrites ancestry"
}

case "$MODE" in
  staged) [ $# -eq 1 ] || die "usage: security-scan.sh staged"; need_repo_root ;;
  range)
    [ $# -eq 3 ] || die "usage: security-scan.sh range <base> <head>"
    need_repo_root
    HEAD_C=$("${G[@]}" rev-parse --verify --quiet "$3^{commit}") || die "unknown head revision: $3"
    BASE_C=$("${G[@]}" rev-parse --verify --quiet "$2^{commit}") || die "unknown base revision: $2 (fetch it)"
    MB=$("${G[@]}" merge-base "$BASE_C" "$HEAD_C") || die "no merge base between $2 and $3"
    RANGE="$BASE_C..$HEAD_C"
    ;;
  tree)
    [ $# -eq 2 ] || die "usage: security-scan.sh tree <dir>"
    DIR=$2; [ -d "$DIR" ] || die "no such directory: $DIR"
    ;;
  *) die "usage: security-scan.sh staged | range <base> <head> | tree <dir>" ;;
esac

# ---- perl helpers -----------------------------------------------------------------------------------------
# pieces(): writes one unit of content (a file, or the lines one commit adds to one file) as guarded,
# overlapping pieces named by file-type class, and counts the bytes written.
PL_PIECES='
  use strict; use warnings;
  my $GUARD = ("#" x 1023) . "\n";
  my ($PIECE, $STEP) = (24576, 16384);   # 8 KB overlap; guard + piece < 32773 (largest matcher offset)
  my ($n, $bytes) = (0, 0);
  sub cls { my $p = shift;
    return ".php" if $p =~ /\.php\z/i;  return ".tf" if $p =~ /\.(?:tf|hcl)\z/i;
    return ".yaml" if $p =~ /\.ya?ml\z/i; return ".nuget.config" if $p =~ /nuget\.config\z/i;
    return ".txt"; }
  sub pieces { my ($dir, $data, $path) = @_;
    my $len = length $data; return if $len == 0;
    my $sfx = cls($path);
    for (my $off = 0; ; $off += $STEP) {
      my $chunk = substr($data, $off, $PIECE);
      $n++; my $f = sprintf("%s/%07d%s", $dir, $n, $sfx);
      open(my $fh, ">", $f) or die "open $f: $!\n"; binmode $fh;
      print {$fh} $GUARD, $chunk or die "write $f: $!\n"; close $fh or die "close $f: $!\n";
      $bytes += length($GUARD) + length($chunk);
      last if $off + $PIECE >= $len;
    } }
  sub done { my $bf = shift; open(my $b, ">", $bf) or die "open: $!\n"; print {$b} "$bytes\n"; close $b or die "close: $!\n"; }
'

# parse_patch <patch> : added lines -> pieces ($TMP/pieces) and, except *.md, $TMP/added.
# Hunk boundaries come from the @@ line counts, so a content line that looks like a header is never
# dropped. Anything unexpected, or a truncated hunk, is an error.
parse_patch() {
  perl -e "$PL_PIECES"'
    my ($dir, $codef, $bytesf) = @ARGV;
    open(my $code, ">", $codef) or die "open: $!\n"; binmode STDIN; binmode $code;
    my ($old, $new, $md, $path, $unit) = (0, 0, 0, "", "");
    while (defined(my $l = <STDIN>)) {
      if ($old > 0 || $new > 0) {
        my $c = substr($l, 0, 1);
        if    ($c eq "+") { my $t = substr($l, 1); $t .= "\n" unless $t =~ /\n\z/;
                            $unit .= $t; print {$code} $t unless $md; $new--; }
        elsif ($c eq "-") { $old--; }
        elsif ($c eq " " || $l eq "\n") { $old--; $new--; }
        elsif ($c eq "\\") { }
        else  { die "unparseable line inside a hunk\n"; }
        die "hunk longer than its header\n" if $old < 0 || $new < 0;
        next;
      }
      if ($l =~ /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/) { $old = $1 // 1; $new = $2 // 1; next; }
      if ($l =~ /^@@@/) { die "combined diff not supported\n"; }
      if ($l =~ /^\+\+\+ (.*?)\t?\r?\n?\z/s) {
        pieces($dir, $unit, $path); $unit = "";
        ($path = $1) =~ s/^"(.*)"\z/$1/s; $path =~ s{^b/}{};
        $md = ($path =~ /\.md\z/) ? 1 : 0; next; }
      if ($l =~ /^[+-]/ && $l !~ /^--- /) { die "diff line outside a hunk\n"; }
    }
    die "truncated hunk\n" if $old > 0 || $new > 0;
    pieces($dir, $unit, $path); done($bytesf);
    close $code or die "close: $!\n";
  ' "$TMP/pieces" "$TMP/added" "$TMP/bytes" <"$1" 2>"$TMP/perl.err" || die "could not parse the diff: $(cat "$TMP/perl.err")"
}

# read_tree : every regular file in $DIR -> pieces, $TMP/added (except *.md), archive detection by content.
read_tree() {
  perl -e "$PL_PIECES"'
    my ($root, $dir, $codef, $bytesf, $arcf) = @ARGV;
    open(my $code, ">", $codef) or die "open: $!\n"; binmode $code;
    open(my $arc, ">", $arcf) or die "open: $!\n"; binmode $arc;
    local $/ = "\0";
    while (defined(my $rel = <STDIN>)) {
      chomp $rel; my $f = "$root/$rel";
      next if -l $f;
      open(my $fh, "<", $f) or die "cannot read $rel: $!\n"; binmode $fh;
      my $data = do { local $/; <$fh> }; die "cannot read $rel: $!\n" unless defined $data;
      close $fh or die "cannot read $rel: $!\n";
      pieces($dir, $data, $rel);
      print {$code} $data, "\n" unless $rel =~ /\.md\z/;
      if ($data =~ /\A(?:PK\x03\x04|PK\x05\x06|PK\x07\x08|\x1f\x8b|BZh[1-9]|\xfd7zXZ\x00|7z\xbc\xaf\x27\x1c|Rar!\x1a\x07|\x28\xb5\x2f\xfd)/
          || (length($data) > 262 && substr($data, 257, 5) eq "ustar")) { print {$arc} $rel, "\0"; }
    }
    done($bytesf); close $code or die "close: $!\n"; close $arc or die "close: $!\n";
  ' "$DIR" "$TMP/pieces" "$TMP/added" "$TMP/bytes" "$TMP/arc_content" <"$TMP/files" 2>"$TMP/perl.err" || die "$(cat "$TMP/perl.err")"
}

# ---- 1. collect file names, added lines, and the pieces to scan for secrets -----------------------------
mkdir "$TMP/pieces"; : >"$TMP/files"; : >"$TMP/added"; : >"$TMP/raw"
case "$MODE" in
  staged)
    "${G[@]}" diff --cached --name-only -z --no-renames --diff-filter=ACMRT >"$TMP/files"
    "${G[@]}" diff --cached --raw -z --no-renames --diff-filter=ACMRT >"$TMP/raw"
    "${G[@]}" diff --cached "${DIFF[@]}" --diff-filter=ACMRT >"$TMP/patch"
    parse_patch "$TMP/patch"
    ;;
  range)
    "${G[@]}" log "${HIST[@]}" --name-only -z --format= --diff-filter=ACMRT "$RANGE" >"$TMP/files"
    "${G[@]}" log "${HIST[@]}" --raw -z --format= --diff-filter=ACMRT "$RANGE" >"$TMP/raw"
    "${G[@]}" diff --raw -z --no-renames --diff-filter=ACMRT "$MB" "$HEAD_C" >>"$TMP/raw"
    # every commit in the range (merges against each parent), then the net change from the merge base
    "${G[@]}" log -p "${HIST[@]}" "${DIFF[@]}" --format='commit %H' --diff-filter=ACMRT "$RANGE" >"$TMP/patch"
    "${G[@]}" diff "${DIFF[@]}" --diff-filter=ACMRT "$MB" "$HEAD_C" >>"$TMP/patch"
    parse_patch "$TMP/patch"
    ;;
  tree)
    (cd "$DIR" && find . \( -type f -o -type l \) -print0) >"$TMP/files"
    : >"$TMP/links"
    while IFS= read -r -d '' f; do [ -L "$DIR/$f" ] && printf '%s\n' "$f" >>"$TMP/links"; done <"$TMP/files"
    if [ -s "$TMP/links" ]; then block "symlinks are not allowed in a deploy payload (their targets are not scanned):"; sed 's/^/    /' "$TMP/links" >&2; fi
    read_tree
    ;;
esac

# ---- 2. secrets: gitleaks with a fixed policy over the pieces --------------------------------------------
# Built-in rules only; the scanned repository's .gitleaks.toml, .gitleaksignore and inline "gitleaks:allow"
# comments are ignored. Findings use exit code 3 so they cannot be confused with errors.
printf '[extend]\nuseDefault = true\n' >"$TMP/gitleaks.toml"
mkdir -p "$TMP/noignore"
rc=0
"$GITLEAKS" dir "$TMP/pieces" --config "$TMP/gitleaks.toml" --gitleaks-ignore-path "$TMP/noignore" --ignore-gitleaks-allow \
  --max-archive-depth 0 --redact --no-banner --exit-code 3 --log-level info >"$TMP/gl.out" 2>&1 || rc=$?
if [ $rc -eq 3 ]; then cat "$TMP/gl.out" >&2; block "secrets detected"
elif [ $rc -ne 0 ]; then cat "$TMP/gl.out" >&2; die "gitleaks failed (exit $rc)"
fi
if grepq -aiE '(^|[[:space:]])(ERR|ERROR|FTL|FATAL)([[:space:]]|$)|level=(error|fatal)|(WRN|WARN).*(fail|error|unable|skip|could not|cannot)' "$TMP/gl.out"; then
  cat "$TMP/gl.out" >&2; die "gitleaks reported errors: treating the scan as incomplete"
fi
want=$(cat "$TMP/bytes")
got=$(perl -ne 'if (/scanned ~(\d+) bytes/) { print $1; $f = 1 } END { exit($f ? 0 : 1) }' "$TMP/gl.out") \
  || { cat "$TMP/gl.out" >&2; die "gitleaks did not report how much it scanned"; }
[ "$got" = "$want" ] || { cat "$TMP/gl.out" >&2; die "gitleaks scanned $got of $want bytes: incomplete scan"; }

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

# ---- 3. credential / key files by name; submodules ---------------------------------------------------------
names_matching '(firebase-adminsdk-.*\.json|service[-_]?account.*\.json|gha-creds-.*\.json|\.pem$|\.p12$|\.pfx$|\.key$|(^|/)id_(rsa|ed25519|ecdsa)$|credentials\.json$)' "$TMP/cred"
if [ -s "$TMP/cred" ]; then block "credential/key files must never be committed or deployed:"; show_names "$TMP/cred"; fi
if grepq -aE ':[0-7]{6} 160000 ' "$TMP/raw"; then block "submodules (gitlinks) are not allowed: their contents are not scanned"; fi

# ---- 4. .env files with secret-like values: every version, each checked on its own ------------------
ENV_SECRET_RE='^[[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDS|CREDENTIAL|API_KEY|APIKEY|CLIENT_SECRET)[A-Za-z0-9_]*[[:space:]]*=[[:space:]]*[^[:space:]#]'
names_matching '(^|/)\.env([.][A-Za-z0-9_.-]+)?$' "$TMP/envs"
n=0
in_tree() {  # in_tree <commit> <path>: 0 = path exists in the commit, 1 = it does not; errors exit 2
  # explicit checks: this function runs inside "||", where set -e does not apply
  "${G[@]}" ls-tree -r -z --name-only --full-tree "$1" >"$TMP/tree.list" || die "cannot list commit $1"
  local rc=0
  perl -e 'local $/ = "\0"; my $t = shift; while (<STDIN>) { chomp; exit 0 if $_ eq $t } exit 1' "$2" <"$TMP/tree.list" || rc=$?
  [ $rc -le 1 ] || die "cannot list commit $1"
  return $rc
}
while IFS= read -r -d '' f; do
  case "$f" in *.env.example|*.env.sample|*.env.template) continue ;; esac
  case "$MODE" in
    staged) n=$((n+1)); "${G[@]}" show ":$f" >"$TMP/env.$n" || die "cannot read staged $f" ;;
    tree)   n=$((n+1)); cat -- "$DIR/$f" >"$TMP/env.$n" || die "cannot read $f" ;;
    range)
      "${G[@]}" log "${HIST[@]}" --format=%H "$RANGE" -- ":(literal)$f" >"$TMP/env.commits"
      echo "$HEAD_C" >>"$TMP/env.commits"
      while IFS= read -r c; do
        in_tree "$c" "$f" || continue          # deleted in this commit
        n=$((n+1)); "${G[@]}" show "$c:$f" >"$TMP/env.$n" || die "cannot read $f at $c"
      done <"$TMP/env.commits"
      ;;
  esac
done <"$TMP/envs"
for ((i = 1; i <= n; i++)); do
  if grepq -aiE "$ENV_SECRET_RE" "$TMP/env.$i"; then block ".env file with secret-like values (use a secret manager; commit only .env.example):"; show_names "$TMP/envs"; break; fi
done

# ---- 5. client data files; deploy-payload hygiene ---------------------------------------------------------
names_matching '\.(xlsx|xlsm|xls|csv|tsv|parquet|sqlite|db|dump|bak)$' "$TMP/data"
if [ -s "$TMP/data" ]; then
  if [ "${SCAN_ALLOW_DATA_FILES:-false}" = true ]; then warn "data files present (allowed by SCAN_ALLOW_DATA_FILES):"; show_names "$TMP/data"
  else block "client data files must not go into git or deploy packages:"; show_names "$TMP/data"; fi
fi
if [ "$MODE" = tree ]; then
  names_matching '(^|/)\.git(/|$)' "$TMP/gitmeta"
  if [ -s "$TMP/gitmeta" ]; then block "git metadata is not allowed in a deploy payload:"; show_names "$TMP/gitmeta"; fi
  names_matching '\.(zip|tar|tgz|gz|bz2|xz|zst|7z|rar|jar|war|whl|egg|gem|apk|docx|pptx|odt|ods|epub)$' "$TMP/archives"
  cat "$TMP/arc_content" >>"$TMP/archives"
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
