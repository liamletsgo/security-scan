# security-scan

A small, fail-closed scanner for pre-commit hooks, pre-push hooks and CI.

```
security-scan.sh staged                 # staged changes (pre-commit)
security-scan.sh range <base> <head>    # what <head> adds relative to <base> (pre-push, CI)
security-scan.sh tree <dir>             # the files of a directory as they are (deploy payload)
```

**Checks:** secrets (gitleaks, required), credential/key files, `.env` files with secret-like values
(every version in a range, including `export` and spaced assignments; `.env.example`, `.env.sample` and
`.env.template` are skipped), client data files (spreadsheets, exports, dumps), symlinks in a deploy
payload, and risky code patterns (public storage objects, open Firebase rules, service-account key loading,
secrets exposed via `NEXT_PUBLIC_`, personal deploy tokens, install-script hooks).

**Range semantics:** every commit in `base..head` is scanned (merge commits against each parent, with
`--full-history`), plus the net diff from `merge-base(base, head)` to `head`. Changes made only on the base
branch are not attributed to `head`. A shallow clone is refused.

**Secret policy:** gitleaks runs with its built-in rules only. The scanned repository's `.gitleaks.toml`,
`.gitleaksignore` and inline `gitleaks:allow` comments are ignored, so a change cannot weaken detection.
If gitleaks logs an error or a skipped/unreadable input but exits 0, the scan is treated as incomplete.

**Exit codes:** `0` clean, `1` findings (blocked), `2` scanner error (also blocks). Unreadable files,
git errors, a missing gitleaks and bad arguments exit `2`; nothing is ever reported clean after an error.

**Environment (set by the caller):** `SCAN_ALLOW_DATA_FILES=true` turns data-file findings into warnings
(synthetic fixtures); `GITLEAKS` sets the gitleaks binary. Markdown files are excluded from the
risky-pattern check only; gitleaks still scans them.

## Using it in CI

- Download it by **exact commit SHA** (never a branch) into `$RUNNER_TEMP`, verify its SHA-256 against a
  value reviewed into your workflow, and run it from the repository root. Treat a download failure or
  checksum mismatch as a failed check.
- Install a pinned, checksum-verified gitleaks release first.
- Check out with `fetch-depth: 0`.
- Ranges: `pull_request` → merge-base of the PR base and head; `push` → `before..after` (a new branch has
  no `before`: choose an explicit trusted baseline); `workflow_dispatch` → an explicit trusted baseline such
  as the last deployed commit. Also run `tree` over the exact payload you deploy.
- Scan before any cloud credentials are issued, in a job without secrets for pull requests from forks.

## Tests

`tests/run-tests.sh` (bash, git, gitleaks). CI runs them on Linux and macOS.
