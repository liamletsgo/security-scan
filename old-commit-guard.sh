#!/usr/bin/env bash
# old-commit-guard.sh — refuse history that still contains commits a history rewrite replaced.
#
# Usage: old-commit-guard.sh <denylist> <rev>...
#   <denylist>  full commit ids (40 or 64 hex digits), one per line; blank lines and lines starting with #
#               are ignored; anything else is an error. These are the first commits a rewrite changed.
#   <rev>       one or more revisions (refs or commit ids) whose whole history is checked.
# Exit codes: 0 = no listed commit is reachable, 1 = a listed commit is reachable (blocked), 2 = error.
# Prints "[guard] checked <N> commits against <M> listed". The listed commits need not exist locally:
# the check compares the ids git rev-list prints, so a clean clone without the old objects passes.
set -Eeuo pipefail
export LC_ALL=C GIT_NO_REPLACE_OBJECTS=1
TMP=$(mktemp -d "${TMPDIR:-/tmp}/old-commit-guard.XXXXXX") || { echo "[guard] ERROR: mktemp failed" >&2; exit 2; }
trap 'rm -rf "$TMP"' EXIT
trap 'echo "[guard] ERROR: unexpected failure at line $LINENO" >&2; exit 2' ERR
die() { echo "[guard] ERROR: $*" >&2; exit 2; }

[ $# -ge 2 ] || die "usage: old-commit-guard.sh <denylist> <rev>..."
LIST=$1; shift
[ -f "$LIST" ] && [ -r "$LIST" ] || die "cannot read the denylist: $LIST"
G=(git --no-replace-objects -c core.quotePath=false)

# the whole ancestry must be present and unaltered: refuse shallow and grafted repositories (bare included)
shallow=$("${G[@]}" rev-parse --is-shallow-repository) || die "not a git repository"
[ "$shallow" = false ] || die "shallow repository: its history is truncated, so old commits could be missed"
grafts=$("${G[@]}" rev-parse --git-path info/grafts) || die "cannot locate info/grafts"
[ ! -e "$grafts" ] || die "grafted history (info/grafts) is not supported: it rewrites ancestry"

revs=()
for r in "$@"; do
  c=$("${G[@]}" rev-parse --verify --quiet "$r^{commit}") || die "unknown revision: $r"
  revs+=("$c")
done
"${G[@]}" rev-list "${revs[@]}" >"$TMP/reachable" || die "git rev-list failed"

perl -e '
  use strict; use warnings;
  $SIG{__DIE__} = sub { print STDERR "[guard] ERROR: ", @_; exit 2; };   # errors are 2, never 1 (blocked)
  my ($list, $reach) = @ARGV;
  my %deny; my $m = 0;
  open(my $l, "<", $list) or die "open denylist: $!\n";
  while (my $x = <$l>) {
    chomp $x; $x =~ s/\r\z//;
    next if $x =~ /\A\s*\z/ || $x =~ /\A#/;
    die "invalid denylist line $.: not a full commit id\n" unless $x =~ /\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z/;
    $m++ unless $deny{$x}++;
  }
  close $l or die "close: $!\n";
  die "empty denylist\n" if $m == 0;
  open(my $r, "<", $reach) or die "open: $!\n";
  my ($n, @hits) = (0);
  while (my $c = <$r>) {
    chomp $c; die "unexpected rev-list output\n" unless $c =~ /\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z/;
    $n++; push @hits, $c if $deny{$c};
  }
  close $r or die "close: $!\n";
  print STDERR "[guard] checked $n commits against $m listed\n";
  if (@hits) { print STDERR "[guard] BLOCKED: this history contains commits that a history rewrite replaced:\n";
               print STDERR "    $_\n" for @hits; exit 1; }
  exit 0;
' "$LIST" "$TMP/reachable" 2>"$TMP/perl.err" || { rc=$?; cat "$TMP/perl.err" >&2; if [ $rc -eq 1 ]; then exit 1; fi; die "guard check failed"; }
cat "$TMP/perl.err" >&2
exit 0
