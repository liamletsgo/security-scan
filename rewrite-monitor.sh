#!/usr/bin/env bash
# rewrite-monitor.sh — after a history rewrite, check the remote itself: fetch every branch and tag tip
# into a bare monitor repository and refuse if any old (replaced) commit is reachable from them.
#
# Usage: rewrite-monitor.sh <git-url> <denylist> <workdir>
#   <git-url>  https://, ssh://, git://, file:// or scp-like URL, or a local path (resolved from the
#              caller's folder before use). URLs that carry user information (credentials) are refused,
#              and the URL is never printed: output names the repository by host and path only.
#   Pull request refs (refs/pull/*) are not fetched: they are read-only on GitHub and are removed by
#   GitHub Support, which is verified separately. A clean result is not proof of that purge.
#   The workdir holds whatever history the remote serves (possibly the old, contaminated one): keep it in
#   the protected work folder and delete it when done.
# Exit codes: 0 = clean, 1 = an old commit is reachable from a branch or tag, 2 = error.
set -Eeuo pipefail
export LC_ALL=C GIT_NO_REPLACE_OBJECTS=1
trap 'echo "[monitor] ERROR: unexpected failure at line $LINENO" >&2; exit 2' ERR
die() { echo "[monitor] ERROR: $*" >&2; exit 2; }

[ $# -eq 3 ] || die "usage: rewrite-monitor.sh <git-url> <denylist> <workdir>"
URL=$1; LIST=$2; W=$3
HERE=$(cd "$(dirname "$0")" && pwd -P) || die "cannot locate the script folder"
[ -x "$HERE/old-commit-guard.sh" ] || die "old-commit-guard.sh not found next to this script"
[ -f "$LIST" ] && [ -r "$LIST" ] || die "cannot read the denylist: $LIST"
LIST="$(cd "$(dirname "$LIST")" && pwd -P)/$(basename "$LIST")" || die "cannot resolve the denylist path"

# the URL: refuse credentials; resolve local paths from the caller's folder; a display form without secrets
case "$URL" in
  *://*:*@*) die "URLs with a password are refused (user:password@ carries a credential)" ;;
  file://*) P=${URL#file://}; [[ $P == /* ]] || die "file:// URLs must be absolute"; FETCH=$URL; SHOW="local$P" ;;
  *://*) FETCH=$URL; SHOW=$(printf '%s' "$URL" | perl -pe 's{\A[a-z]+://}{}i; s{\A[^@/]+@}{}; s{\?.*\z}{}') ;;
  /*) FETCH=$URL; SHOW="local$URL" ;;
  *)
    if [[ $URL =~ ^[^/]*: ]]; then FETCH=$URL; SHOW=$(printf '%s' "$URL" | perl -pe 's{\A[^@/]+@}{}')   # scp-like
    else
      [ -e "$URL" ] || die "local path not found: $URL"
      FETCH="$(cd "$URL" && pwd -P)" || die "cannot resolve the local path"; SHOW="local$FETCH"
    fi ;;
esac

if [ ! -d "$W" ]; then git init -q --bare "$W" || die "cannot create $W"; fi
[ "$(git -C "$W" rev-parse --is-bare-repository)" = true ] || die "$W is not a bare repository"
git -C "$W" fetch -q --prune --no-tags "$FETCH" '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*' \
  2>"$W/monitor.fetch.err" || die "fetch from the remote failed"
git -C "$W" for-each-ref --format='%(refname)' refs/heads refs/tags >"$W/monitor.refs" || die "cannot list refs"
n=$(wc -l <"$W/monitor.refs" | tr -d ' ')
[ "$n" -gt 0 ] || die "the remote has no branch or tag"
refs=()
while IFS= read -r r; do refs+=("$r"); done <"$W/monitor.refs"
rc=0
(cd "$W" && "$HERE/old-commit-guard.sh" "$LIST" "${refs[@]}") || rc=$?
case $rc in 0|1) ;; *) rc=2 ;; esac   # anything other than clean (0) or blocked (1) is an error
echo "[monitor] $SHOW: $n branch and tag refs checked; guard exit $rc" >&2
exit $rc
