#!/usr/bin/env bash
# security-scan.sh — a small, fail-closed pre-commit / pre-push / CI scanner.
#
# Usage:
#   security-scan.sh staged                 scan staged changes (pre-commit hook)
#   security-scan.sh range <base> <head>    scan what <head> adds relative to <base>: every commit in
#                                           base..head (merges against each parent) and the net diff
#                                           from merge-base(base, head) to head (pre-push, CI)
#   security-scan.sh tree <dir>             scan the files of a directory as they are (deploy payload)
#   security-scan.sh history <head>         scan every commit reachable from <head>, root commits included
#                                           (merges against each parent); for a push whose remote tip is
#                                           unknown or unrelated, such as after a history rewrite
#   security-scan.sh new <head> <has-file>  scan the commits reachable from <head> but not from the commit
#                                           ids listed in <has-file>, which the push destination is known
#                                           to have (a new branch; ids missing locally are skipped)
# Run staged, range, history and new mode from the root of the repository's work tree. range, history
# and new print "[security] scanned <N> commits (<mode>)"; history with no commit is an error.
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
# Secret scanning (gitleaks never reads the repository; files are named only by file-type class, so
# path-gated rules work and the default policy's path exclusions cannot match):
#   1. each unit (a file, or the lines one commit adds to one file) is scanned as it is, so the scan finds
#      at least what gitleaks alone finds in that unit;
#   2. guarded windows close gitleaks' own blind spots: each starts with a 1 KB text guard so a unit that
#      begins like a binary file is still scanned; units up to 98,000 bytes are scanned whole (full
#      context), larger ones as 98,000-byte windows overlapping by 49,000, each under gitleaks' 100 KB
#      buffer, so its chunk cut can never split a match of up to 49,000 bytes. The scan fails unless
#      gitleaks reports exactly the bytes written for the windows (the only matcher that could still
#      skip a window, ISO-9660 at byte 32,769, therefore causes an error, never a silent pass).
#
# Exit codes: 0 = clean, 1 = findings (blocked), 2 = scanner error (blocks; never reported as clean).
# Environment (set by the caller, not by the scanned repository):
#   SCAN_ALLOW_DATA_FILES=true    report data files as warnings instead of findings (synthetic fixtures);
#                                 refused in history mode
#   GITLEAKS                      gitleaks binary (default: first on PATH)
#   SCAN_PATTERN_REPORT=<file>    history mode only, never under CI: write code-pattern hits (not secret
#                                 material) to <file> as JSON lines with commit, parent (each merge parent
#                                 separately), path_hex (exact path bytes), path, label, span hash and
#                                 count, instead of blocking on them; every other check still blocks. Used
#                                 only by the local pre-push hook to compare with an approved baseline.
#   SCAN_PATTERN_EXEMPT_FILE=<f>  never under CI: units whose path is listed exactly in <f> (one per line)
#                                 skip the code-pattern checks only (the scanner's own repository).
# Risky patterns come in two groups: secret material (private-key markers, Entra client secrets), which
# always blocks, and code patterns, which block unless reported or exempt as above. Both groups apply
# to added non-Markdown content. In Markdown (*.md), gitleaks runs as everywhere, plus material-aware
# checks: a private-key header followed by a key body, or an Entra secret value, blocks; prose that only
# names a PEM header does not. Code patterns are not checked in Markdown.
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
    REVS=("$BASE_C..$HEAD_C")
    ;;
  history)
    [ $# -eq 2 ] || die "usage: security-scan.sh history <head>"
    need_repo_root
    HEAD_C=$("${G[@]}" rev-parse --verify --quiet "$2^{commit}") || die "unknown head revision: $2"
    REVS=("$HEAD_C")
    ;;
  new)
    # <has>: full commit ids the push destination is known to have (for example from git ls-remote of the
    # destination itself); their history is not scanned again. Ids not present locally are skipped, which
    # only widens the scan.
    [ $# -eq 3 ] || die "usage: security-scan.sh new <head> <file of commit ids the destination has>"
    need_repo_root
    HEAD_C=$("${G[@]}" rev-parse --verify --quiet "$2^{commit}") || die "unknown head revision: $2"
    [ -f "$3" ] && [ -r "$3" ] || die "cannot read the list of commits the destination has: $3"
    REVS=("$HEAD_C")
    nhas=0
    while IFS= read -r h || [ -n "$h" ]; do
      h=${h%$'\r'}
      [ -n "$h" ] || continue
      [[ $h =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "invalid commit id in $3: $h"
      if c=$("${G[@]}" rev-parse --verify --quiet "$h^{commit}"); then
        [ $nhas -gt 0 ] || REVS+=(--not)
        REVS+=("$c"); nhas=$((nhas+1))
      fi
    done <"$3"
    ;;
  tree)
    [ $# -eq 2 ] || die "usage: security-scan.sh tree <dir>"
    DIR=$2; [ -d "$DIR" ] || die "no such directory: $DIR"
    ;;
  *) die "usage: security-scan.sh staged | range <base> <head> | history <head> | new <head> <has-file> | tree <dir>" ;;
esac

# Caller-set options (never taken from the scanned repository)
REPORT=${SCAN_PATTERN_REPORT:-}; EXEMPT=${SCAN_PATTERN_EXEMPT_FILE:-}
under_ci() { [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${CI:-}" ]; }
if [ -n "$REPORT" ]; then
  [ "$MODE" = history ] || die "SCAN_PATTERN_REPORT is only allowed in history mode"
  ! under_ci || die "SCAN_PATTERN_REPORT is refused under CI"
  : >"$REPORT" || die "cannot write the pattern report: $REPORT"
fi
if [ -n "$EXEMPT" ]; then
  ! under_ci || die "SCAN_PATTERN_EXEMPT_FILE is refused under CI"
  [ -f "$EXEMPT" ] && [ -r "$EXEMPT" ] || die "cannot read the pattern exemption list: $EXEMPT"
fi
if [ "$MODE" = history ] && [ "${SCAN_ALLOW_DATA_FILES:-false}" = true ]; then
  die "SCAN_ALLOW_DATA_FILES is refused in history mode"
fi

# Coverage: how many commits this scan reads (range, history, new)
case "$MODE" in
  range|history|new)
    NCOMMITS=$("${G[@]}" rev-list --count "${REVS[@]}") || die "cannot count the commits to scan"
    [[ $NCOMMITS =~ ^[0-9]+$ ]] || die "unexpected commit count: $NCOMMITS"
    if [ "$MODE" = history ] && [ "$NCOMMITS" -eq 0 ]; then die "history mode found no commit to scan"; fi
    echo "[security] scanned $NCOMMITS commits ($MODE)" >&2
    ;;
esac

# ---- perl helpers -----------------------------------------------------------------------------------------
# pieces(): writes one unit of content (a file, or the lines one commit adds to one file) for two gitleaks
# runs, named by file-type class:
#   $TMP/whole   the unit as it is: exactly what gitleaks alone would scan for that unit
#   $TMP/pieces  guarded windows whose every byte must be scanned (byte count checked): 98,000 bytes,
#                overlapping by 49,000, so a unit up to 98,000 bytes is one window with full context and any
#                span up to 49,000 bytes lies inside one window; with the guard a window stays under
#                gitleaks' 100,000-byte buffer, so gitleaks never cuts it.
PL_PIECES='
  use strict; use warnings;
  my $GUARD = ("#" x 1023) . "\n";
  my ($n, $bytes) = (0, 0);
  sub cls { my $p = shift;
    return ".php" if $p =~ /\.php\z/i;  return ".tf" if $p =~ /\.(?:tf|hcl)\z/i;
    return ".yaml" if $p =~ /\.ya?ml\z/i; return ".nuget.config" if $p =~ /nuget\.config\z/i;
    return ".txt"; }
  sub wfile { my ($f, $guard, $data) = @_;
    open(my $fh, ">", $f) or die "open $f: $!\n"; binmode $fh;
    print {$fh} $guard, $data or die "write $f: $!\n"; close $fh or die "close $f: $!\n"; }
  sub windows { my ($dir, $tag, $data, $sfx, $size, $step) = @_;
    my $len = length $data;
    for (my $off = 0; ; $off += $step) {
      my $chunk = substr($data, $off, $size);
      $n++; wfile(sprintf("%s/%s%07d%s", $dir, $tag, $n, $sfx), $GUARD, $chunk);
      $bytes += length($GUARD) + length($chunk);
      last if $off + $size >= $len;
    } }
  sub pieces { my ($dir, $data, $path) = @_;
    return if length($data) == 0;
    my $sfx = cls($path);
    $n++; wfile(sprintf("%s/../whole/u%07d%s", $dir, $n, $sfx), "", $data);
    windows($dir, "w", $data, $sfx, 98000, 49000);
  }
  sub done { my $bf = shift; open(my $b, ">", $bf) or die "open: $!\n"; print {$b} "$bytes\n"; close $b or die "close: $!\n"; }
'

# parse_patch <patch> : added lines -> pieces ($TMP/pieces); non-.md lines -> $TMP/added; .md lines -> one
# file per unit, $TMP/units/mNNNNNNN, listed in $TMP/md.idx (so Markdown checks never match across files or
# commits). Hunk boundaries come from the @@ line counts, so a content line that looks like a header is
# never dropped. Anything unexpected, or a truncated hunk, is an error.
#   Each unit is also attributed: its added non-.md text goes to $TMP/units/cNNNNNNN, and $TMP/units.idx
#   gets "cNNNNNNN\0<commit>\0<parent>\0<path>\0". Headers name the commit and the parent explicitly:
#   "commit <id> <parent or nothing>" for non-merge commits (git log --no-merges; ROOT for a root commit),
#   "commit <id> parent <parent>" before each of a merge's per-parent diffs (written by this script, so an
#   empty per-parent diff that git would omit can never shift the attribution), "commit NET" for range
#   mode's net diff; STAGED in staged mode. <path> is the exact path (git C-quoting decoded).
parse_patch() {
  perl -e "$PL_PIECES"'
    my ($dir, $codef, $bytesf, $udir, $idxf, $mdf) = @ARGV;
    open(my $code, ">", $codef) or die "open: $!\n"; binmode STDIN; binmode $code;
    open(my $mdo, ">", $mdf) or die "open: $!\n"; binmode $mdo;
    open(my $idx, ">", $idxf) or die "open: $!\n"; binmode $idx;
    my ($old, $new, $md, $path, $unit, $ucode, $umd, $commit, $parent, $un, $mn) = (0, 0, 0, "", "", "", "", "STAGED", "STAGED", 0, 0);
    my $ID = qr/[0-9a-f]{40}(?:[0-9a-f]{24})?/;
    sub flush { pieces($dir, $unit, $path);
      if (length $ucode) { $un++; my $f = sprintf("%s/c%07d", $udir, $un);
        open(my $u, ">", $f) or die "open $f: $!\n"; binmode $u; print {$u} $ucode or die "write: $!\n"; close $u or die "close: $!\n";
        print {$idx} sprintf("c%07d", $un), "\0", $commit, "\0", $parent, "\0", $path, "\0" or die "write: $!\n"; }
      if (length $umd) { $mn++; my $f = sprintf("%s/m%07d", $udir, $mn);
        open(my $u, ">", $f) or die "open $f: $!\n"; binmode $u; print {$u} $umd or die "write: $!\n"; close $u or die "close: $!\n";
        print {$mdo} sprintf("m%07d", $mn), "\0", $path, "\0" or die "write: $!\n"; }
      $unit = ""; $ucode = ""; $umd = ""; }
    # git C-quotes unusual paths ("a\tb", octal bytes); decode to the exact path bytes
    my %esc = (a => "\a", b => "\b", t => "\t", n => "\n", v => "\x0b", f => "\f", r => "\r", q{"} => q{"}, "\\" => "\\");
    sub cunq { my $s = shift;
      $s =~ s/\\([0-7]{3}|[abtnvfr"\\])/ length($1) == 3 ? chr(oct $1) : $esc{$1} /ge; return $s; }
    while (defined(my $l = <STDIN>)) {
      if ($old > 0 || $new > 0) {
        my $c = substr($l, 0, 1);
        if    ($c eq "+") { my $t = substr($l, 1); $t .= "\n" unless $t =~ /\n\z/;
                            $unit .= $t; if ($md) { $umd .= $t } else { print {$code} $t; $ucode .= $t; } $new--; }
        elsif ($c eq "-") { $old--; }
        elsif ($c eq " " || $l eq "\n") { $old--; $new--; }
        elsif ($c eq "\\") { }
        else  { die "unparseable line inside a hunk\n"; }
        die "hunk longer than its header\n" if $old < 0 || $new < 0;
        next;
      }
      # one per-parent diff of a merge, labelled by this script
      if ($l =~ /^commit ($ID) parent ($ID)\n\z/) { flush(); ($commit, $parent) = ($1, $2); $path = ""; $md = 0; next; }
      # a non-merge commit from git log: "commit <id> <parent>", or "commit <id> " (trailing space) for a root
      if ($l =~ /^commit ($ID)( $ID)? ?\n\z/) {
        flush(); $commit = $1; $parent = defined $2 ? substr($2, 1) : "ROOT"; $path = ""; $md = 0; next; }
      if ($l eq "commit NET\n") { flush(); ($commit, $parent) = ("NET", "NET"); $path = ""; $md = 0; next; }
      die "unexpected commit header\n" if $l =~ /^commit /;   # never attribute units to the wrong commit
      if ($l =~ /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/) { $old = $1 // 1; $new = $2 // 1; next; }
      if ($l =~ /^@@@/) { die "combined diff not supported\n"; }
      if ($l =~ /^\+\+\+ (.*?)\t?\r?\n?\z/s) {
        flush();
        $path = $1; $path = cunq($1) if $path =~ /\A"(.*)"\z/s; $path =~ s{^b/}{};
        $md = ($path =~ /\.md\z/) ? 1 : 0; next; }
      if ($l =~ /^[+-]/ && $l !~ /^--- /) { die "diff line outside a hunk\n"; }
    }
    die "truncated hunk\n" if $old > 0 || $new > 0;
    flush(); done($bytesf);
    close $code or die "close: $!\n"; close $idx or die "close: $!\n"; close $mdo or die "close: $!\n";
  ' "$TMP/pieces" "$TMP/added" "$TMP/bytes" "$TMP/units" "$TMP/units.idx" "$TMP/md.idx" <"$1" 2>"$TMP/perl.err" || die "could not parse the diff: $(cat "$TMP/perl.err")"
}

# read_tree : every regular file in $DIR -> pieces, $TMP/added (non-.md) or its own Markdown unit file
# ($TMP/units/mNNNNNNN, listed in $TMP/md.idx), archive detection by content.
read_tree() {
  perl -e "$PL_PIECES"'
    my ($root, $dir, $codef, $bytesf, $arcf, $binf, $mdf, $udir) = @ARGV;
    open(my $bin, ">", $binf) or die "open: $!\n"; binmode $bin;
    open(my $code, ">", $codef) or die "open: $!\n"; binmode $code;
    open(my $mdo, ">", $mdf) or die "open: $!\n"; binmode $mdo;
    my $mn = 0;
    open(my $arc, ">", $arcf) or die "open: $!\n"; binmode $arc;
    local $/ = "\0";
    while (defined(my $rel = <STDIN>)) {
      chomp $rel; my $f = "$root/$rel";
      next if -l $f;
      open(my $fh, "<", $f) or die "cannot read $rel: $!\n"; binmode $fh;
      my $data = do { local $/; <$fh> }; die "cannot read $rel: $!\n" unless defined $data;
      close $fh or die "cannot read $rel: $!\n";
      pieces($dir, $data, $rel);
      if ($rel =~ /\.md\z/) {
        $mn++; my $u = sprintf("%s/m%07d", $udir, $mn);
        open(my $uh, ">", $u) or die "open $u: $!\n"; binmode $uh; print {$uh} $data or die "write: $!\n"; close $uh or die "close: $!\n";
        print {$mdo} sprintf("m%07d", $mn), "\0", $rel, "\0" or die "write: $!\n";
      } else { print {$code} $data, "\n" }
      # archive signatures anywhere in the file: archives can carry a prefix (self-extracting, padded)
      if ($data =~ /PK\x03\x04|PK\x05\x06|PK\x07\x08|PK\x06\x06|Rar!\x1a\x07|7z\xbc\xaf\x27\x1c|\xfd7zXZ\x00|\x28\xb5\x2f\xfd|\x1f\x8b\x08|BZh[1-9]1AY&SY|MSCF\x00\x00\x00\x00|ustar(?:\x00|  \x00)/) {
        print {$arc} $rel, "\0"; }
      elsif (tar_header($data)) { print {$arc} $rel, "\0"; }
      # a deploy payload is code and configuration: any file with NUL bytes is binary and blocked
      print {$bin} $rel, "\0" if index($data, "\0") >= 0;
    }
    done($bytesf); close $code or die "close: $!\n"; close $arc or die "close: $!\n"; close $bin or die "close: $!\n";
    close $mdo or die "close: $!\n";
    # tar header (any variant, including pre-POSIX without "ustar"): its checksum field matches the header
    sub tar_header { my $d = shift;
      for (my $p = 0; $p + 512 <= length($d); $p += 512) {
        my $h = substr($d, $p, 512);
        next unless substr($h, 148, 8) =~ /\A[ \x00]*([0-7]{1,8})[ \x00]*\z/;
        my $want = oct($1); next if $want < 256;
        my $sum = unpack("%32C*", substr($h, 0, 148) . (" " x 8) . substr($h, 156));
        return 1 if $sum == $want;
      }
      return 0; }
  ' "$DIR" "$TMP/pieces" "$TMP/added" "$TMP/bytes" "$TMP/arc_content" "$TMP/binary" "$TMP/md.idx" "$TMP/units" <"$TMP/files" 2>"$TMP/perl.err" || die "$(cat "$TMP/perl.err")"
}

# ---- 1. collect file names, added lines, and the pieces to scan for secrets -----------------------------
mkdir "$TMP/pieces" "$TMP/whole" "$TMP/units"; : >"$TMP/files"; : >"$TMP/added"; : >"$TMP/raw"; : >"$TMP/units.idx"; : >"$TMP/md.idx"
[ "$MODE" != tree ] || [ -z "$EXEMPT" ] || die "SCAN_PATTERN_EXEMPT_FILE is not supported in tree mode"
case "$MODE" in
  staged)
    "${G[@]}" diff --cached --name-only -z --no-renames --diff-filter=ACMRT >"$TMP/files"
    "${G[@]}" diff --cached --raw -z --no-renames --diff-filter=ACMRT >"$TMP/raw"
    "${G[@]}" diff --cached "${DIFF[@]}" --diff-filter=ACMRT >"$TMP/patch"
    parse_patch "$TMP/patch"
    ;;
  range|history|new)
    "${G[@]}" log "${HIST[@]}" --name-only -z --format= --diff-filter=ACMRT "${REVS[@]}" >"$TMP/files"
    "${G[@]}" log "${HIST[@]}" --raw -z --format= --diff-filter=ACMRT "${REVS[@]}" >"$TMP/raw"
    # every non-merge commit in the set (root commits in full), then every merge against each of its
    # parents, each diff labelled with that parent (git would omit an empty per-parent diff, so position
    # cannot be trusted to name the parent)
    "${G[@]}" log -p "${HIST[@]}" "${DIFF[@]}" --no-merges --format='commit %H %P' --diff-filter=ACMRT "${REVS[@]}" >"$TMP/patch"
    "${G[@]}" rev-list --merges "${REVS[@]}" >"$TMP/merges" || die "cannot list the merges to scan"
    while IFS= read -r m; do
      [[ $m =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "unexpected merge id: $m"
      "${G[@]}" rev-list --parents -n 1 "$m" >"$TMP/mparents" || die "cannot read the parents of $m"
      read -r -a mp <"$TMP/mparents" || die "cannot read the parents of $m"
      [ "${#mp[@]}" -ge 3 ] && [ "${mp[0]}" = "$m" ] || die "unexpected parent list for $m"
      for ((pi = 1; pi < ${#mp[@]}; pi++)); do
        [[ ${mp[$pi]} =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "unexpected parent id of $m"
        printf 'commit %s parent %s\n' "$m" "${mp[$pi]}" >>"$TMP/patch"
        "${G[@]}" diff "${DIFF[@]}" --diff-filter=ACMRT "${mp[$pi]}" "$m" >>"$TMP/patch" || die "cannot diff $m against ${mp[$pi]}"
      done
    done <"$TMP/merges"
    if [ "$MODE" = range ]; then
      # then the net change from the merge base (history and new: every line was added by a scanned commit)
      "${G[@]}" diff --raw -z --no-renames --diff-filter=ACMRT "$MB" "$HEAD_C" >>"$TMP/raw"
      printf 'commit NET\n' >>"$TMP/patch"
      "${G[@]}" diff "${DIFF[@]}" --diff-filter=ACMRT "$MB" "$HEAD_C" >>"$TMP/patch"
    fi
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

# ---- 2. secrets: gitleaks with a fixed policy, two runs ---------------------------------------------------
# Built-in rules only; the scanned repository's .gitleaks.toml, .gitleaksignore and inline "gitleaks:allow"
# comments are ignored. Findings use exit code 3 so they cannot be confused with errors.
#   whole:  each unit as it is, so nothing gitleaks would find on its own is lost (no byte check: gitleaks
#           may legitimately skip a unit that starts like a binary file, exactly as it would on its own)
#   pieces: guarded windows; gitleaks must report exactly the bytes written
printf '[extend]\nuseDefault = true\n' >"$TMP/gitleaks.toml"
mkdir -p "$TMP/noignore"
gl_dir() {  # gl_dir <folder> <label>: runs gitleaks; findings -> block; errors -> exit 2; prints bytes scanned
  local rc=0
  "$GITLEAKS" dir "$1" --config "$TMP/gitleaks.toml" --gitleaks-ignore-path "$TMP/noignore" --ignore-gitleaks-allow \
    --max-archive-depth 0 --redact --no-banner --exit-code 3 --log-level info >"$TMP/gl.$2" 2>&1 || rc=$?
  if [ $rc -eq 3 ]; then cat "$TMP/gl.$2" >&2; block "secrets detected ($2 scan)"
  elif [ $rc -ne 0 ]; then cat "$TMP/gl.$2" >&2; die "gitleaks failed ($2 scan, exit $rc)"
  fi
  if grepq -aiE '(^|[[:space:]])(ERR|ERROR|FTL|FATAL)([[:space:]]|$)|level=(error|fatal)|(WRN|WARN).*(fail|error|unable|could not|cannot)' "$TMP/gl.$2"; then
    cat "$TMP/gl.$2" >&2; die "gitleaks reported errors ($2 scan): treating the scan as incomplete"
  fi
}
gl_dir "$TMP/whole" whole
gl_dir "$TMP/pieces" pieces
want=$(cat "$TMP/bytes")
got=$(perl -ne 'if (/scanned ~(\d+) bytes/) { print $1; $f = 1 } END { exit($f ? 0 : 1) }' "$TMP/gl.pieces") \
  || { cat "$TMP/gl.pieces" >&2; die "gitleaks did not report how much it scanned"; }
[ "$got" = "$want" ] || { cat "$TMP/gl.pieces" >&2; die "gitleaks scanned $got of $want bytes: incomplete scan"; }

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
# a value is anything directly after "=" (a leading "#" included); after spaces, "#" starts a comment
ENV_SECRET_RE='^[[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDS|CREDENTIAL|API_KEY|APIKEY|CLIENT_SECRET)[A-Za-z0-9_]*[[:space:]]*=([^[:space:]]|[[:space:]]+[^[:space:]#])'
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
  case "$f" in *.env.example) continue ;; esac   # only .env.example may hold placeholders (as the old hook)
  case "$MODE" in
    staged) n=$((n+1)); "${G[@]}" show ":$f" >"$TMP/env.$n" || die "cannot read staged $f" ;;
    tree)   n=$((n+1)); cat -- "$DIR/$f" >"$TMP/env.$n" || die "cannot read $f" ;;
    range|history|new)
      # --no-patch: with --diff-merges=separate, git log also prints a merge commit's diff, which must not
      # be read as commit names. Every line is still checked to be a full commit id before use.
      "${G[@]}" log "${HIST[@]}" --no-patch --format=%H "${REVS[@]}" -- ":(literal)$f" >"$TMP/env.commits" \
        || die "cannot list the history of $f"
      echo "$HEAD_C" >>"$TMP/env.commits"
      while IFS= read -r c; do
        [[ $c =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "unexpected commit id in the history of $f: $c"
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
  if [ -s "$TMP/binary" ]; then block "binary files (NUL bytes) are not allowed in a deploy payload:"; show_names "$TMP/binary"; fi
fi

# ---- 6. risky patterns in added content (whole text: matches may span lines) --------------------------
# Secret material always blocks, over all added content. Code patterns block too, unless the caller asked
# for a report (history mode: hits go to SCAN_PATTERN_REPORT for comparison with an approved baseline) or
# exempted exact paths (SCAN_PATTERN_EXEMPT_FILE); those two are checked per unit (one commit, one file).
check() {  # check <label> <perl regex> [<file>]: default file is the added non-Markdown content
  local rc=0
  perl -0777 -ne 'BEGIN { $re = shift @ARGV } exit(/$re/ ? 0 : 1)' "$2" "${3:-$TMP/added}" 2>"$TMP/perl.err" || rc=$?
  [ $rc -le 1 ] || die "pattern check failed: $(cat "$TMP/perl.err")"
  if [ $rc -eq 0 ]; then block "$1"; fi
}
check "private key material"                                  'BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY'
check "Microsoft Entra client secret"                         '[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}'
# Markdown: secret material, not prose. A key header followed by a key body (literal or \n-escaped lines),
# or an Entra secret value, blocks; a sentence that only names a PEM header does not. Each Markdown unit
# (one file in one commit or parent diff; one file in tree mode) is checked on its own, so text from
# different files or commits can never combine into a match.
perl -e '
  use strict; use warnings;
  my ($idxf, $udir) = @ARGV;
  my @rules = (
    # between header and body: whitespace, escaped \r or \n, and Markdown line prefixes (quote, list, table)
    ["private key material (key body in Markdown)", qr/BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----(?:\s|\\[rn]|[>|*+-])*[A-Za-z0-9+\/]{40,}/],
    ["Microsoft Entra client secret (in Markdown)", qr/[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}/]);
  open(my $i, "<", $idxf) or die "open $idxf: $!\n"; binmode $i;
  local $/ = "\0"; my %hit;
  while (defined(my $id = <$i>)) {
    my $path = <$i>; die "truncated Markdown index\n" unless defined $path && $path =~ /\0\z/;
    chomp $id; chomp $path; die "bad Markdown unit id\n" unless $id =~ /\Am[0-9]+\z/;
    open(my $u, "<", "$udir/$id") or die "open $id: $!\n"; binmode $u;
    my $t = do { local $/; <$u> }; die "read $id: $!\n" unless defined $t; close $u or die "close: $!\n";
    for my $r (@rules) { $hit{$r->[0]}{$path} = 1 if $t =~ $r->[1]; }
  }
  close $i or die "close: $!\n";
  for my $label (sort keys %hit) { print "$label\t$_\n" for sort keys %{ $hit{$label} }; }
' "$TMP/md.idx" "$TMP/units" >"$TMP/md.hits" 2>"$TMP/perl.err" || die "Markdown check failed: $(cat "$TMP/perl.err")"
if [ -s "$TMP/md.hits" ]; then
  cut -f1 "$TMP/md.hits" | sort -u >"$TMP/md.labels"
  while IFS= read -r label; do block "$label"; done <"$TMP/md.labels"
  sed 's/^/    /' "$TMP/md.hits" >&2
fi

CODE_RULES=(
  "public storage objects (make_public / allUsers)"       'make_public\s*\(|allUsers|allAuthenticatedUsers'
  "open Firebase rules (if true)"                         '\ballow\b[^;{}]*?:\s*if\s*\(?\s*true\b'
  "secret exposed to the browser via NEXT_PUBLIC_"        'NEXT_PUBLIC_[A-Z0-9_]*(?:PRIVATE|SECRET|PASSWORD|CLIENT_EMAIL)'
  "service-account key loading (use workload identity)"   'credentials\s*\.\s*Certificate\s*\(|from_service_account_(?:file|info)\s*\(|GOOGLE_APPLICATION_CREDENTIALS\s*='
  "personal deploy token (use keyless federation)"        'firebase\s+login:ci|--token\s+"?\$\{?\{?\s*(?:secrets\.)?FIREBASE_TOKEN'
  "install-script hook added (review supply-chain risk)"  '"(?:pre|post)install"\s*:'
)
[ -z "$REPORT" ] || [ -z "$EXEMPT" ] || die "SCAN_PATTERN_REPORT and SCAN_PATTERN_EXEMPT_FILE cannot be combined"
if [ -z "$REPORT" ] && [ -z "$EXEMPT" ]; then
  for ((i = 0; i < ${#CODE_RULES[@]}; i += 2)); do check "${CODE_RULES[$i]}" "${CODE_RULES[$((i+1))]}"; done
else
  if [ -n "$REPORT" ]; then UMODE=report; UOUT=$REPORT; else UMODE=exempt; UOUT="$TMP/unit.hits"; fi
  perl -e '
    use strict; use warnings; use Digest::SHA qw(sha256_hex); use JSON::PP (); use Encode ();
    my ($idxf, $udir, $mode, $out, $exf, @spec) = @ARGV;
    my %ex;
    if ($mode eq "exempt") {
      open(my $e, "<", $exf) or die "open $exf: $!\n";
      while (my $l = <$e>) { chomp $l; $l =~ s/\r\z//; next if $l eq "" || $l =~ /^#/; $ex{$l} = 1; }
      close $e or die "close: $!\n"; }
    my @rules; while (@spec) { my $l = shift @spec; my $r = shift @spec; push @rules, [$l, qr/$r/]; }
    open(my $o, ">", $out) or die "open $out: $!\n"; binmode $o;
    open(my $i, "<", $idxf) or die "open $idxf: $!\n"; binmode $i;
    my %agg; my $units = 0;
    { local $/ = "\0";
      while (defined(my $id = <$i>)) {
        my $commit = <$i>; my $parent = <$i>; my $path = <$i>;
        die "truncated unit index\n" unless defined $path && $path =~ /\0\z/;
        chomp $id; chomp $commit; chomp $parent; chomp $path; $units++;
        die "bad unit id\n" unless $id =~ /\Ac[0-9]+\z/;
        next if $mode eq "exempt" && $ex{$path};
        open(my $u, "<", "$udir/$id") or die "open $id: $!\n"; binmode $u;
        my $t = do { local $/; <$u> }; die "read $id: $!\n" unless defined $t; close $u or die "close: $!\n";
        for my $r (@rules) {
          my ($label, $re) = @$r;
          while ($t =~ /$re/g) {
            if ($mode eq "report") { $agg{join("\0", $commit, $parent, unpack("H*", $path), $label, sha256_hex($&))}++; }
            else { print {$o} "$label\t$path\n" or die "write: $!\n"; }
          } } } }
    if ($mode eq "report") {
      # identity: commit, parent, path_hex (the exact path bytes), label, span hash; "path" is for reading only
      my $js = JSON::PP->new->canonical->utf8;
      for my $k (sort keys %agg) {
        my ($c, $p, $ph, $l, $h) = split /\0/, $k, 5;
        my $disp = Encode::decode("UTF-8", pack("H*", $ph), Encode::FB_DEFAULT);
        print {$o} $js->encode({commit => $c, parent => $p, path_hex => $ph, path => $disp, label => $l,
                                span_sha256 => $h, count => $agg{$k}}), "\n" or die "write: $!\n"; } }
    close $o or die "close: $!\n"; close $i or die "close: $!\n";
  ' "$TMP/units.idx" "$TMP/units" "$UMODE" "$UOUT" "$EXEMPT" "${CODE_RULES[@]}" 2>"$TMP/perl.err" \
    || die "per-unit pattern check failed: $(cat "$TMP/perl.err")"
  if [ "$UMODE" = exempt ] && [ -s "$UOUT" ]; then
    cut -f1 "$UOUT" | sort -u | while IFS= read -r label; do block "$label"; done
    # block() above ran in a subshell: record the failure here as well
    fail=1; sed 's/^/    /' "$UOUT" | sort -u >&2
  fi
fi

if [ $fail -ne 0 ]; then
  echo "${RED}[security] Stopped by security checks.${NC} Fix the items above; do not bypass the scan." >&2
  exit 1
fi
if [ -n "$REPORT" ]; then
  echo "[security] clean apart from reported code patterns ($MODE): $(wc -l <"$REPORT" | tr -d ' ') distinct hits written to the report" >&2
else
  echo "[security] clean ($MODE)" >&2
fi
exit 0
