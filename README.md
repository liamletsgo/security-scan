# security-scan

A small, fail-closed scanner for pre-commit hooks, pre-push hooks and CI.

```
security-scan.sh staged                 # staged changes (pre-commit)
security-scan.sh range <base> <head>    # what <head> adds relative to <base> (pre-push, CI)
security-scan.sh tree <dir>             # the files of a directory as they are (deploy payload)
```

Run `staged` and `range` from the repository root. Requires bash, git, perl and gitleaks.

**Checks:** secrets (gitleaks, required), credential/key files, `.env` files with secret-like values
(every version in a range, including `export` and spaced assignments; `.env.example`, `.env.sample` and
`.env.template` are skipped), client data files (spreadsheets, exports, dumps), symlinks and archives in a
deploy payload, and risky code patterns (public storage objects, open Firebase rules, service-account key
loading, secrets exposed via `NEXT_PUBLIC_`, personal deploy tokens, install-script hooks).

**What is scanned:** in `staged` and `range` mode, the lines a change *adds* (removing an existing secret is
never blocked). The scanner produces the diffs itself as text (`--text`, no textconv or external diff
drivers, output-affecting git settings pinned), checks git's exit status, and extracts added lines with a
strict patch parser that uses each hunk's line counts; anything it cannot account for, or a truncated hunk,
is an error. In `tree` mode every regular file is read directly. Binary files and files marked `-diff` or
`binary` in `.gitattributes` are scanned like any other file.

**Range semantics:** every commit in `base..head` is scanned (merge commits against each parent, with
`--full-history`), plus the net diff from `merge-base(base, head)` to `head`. The net diff never attributes
base-branch changes to `head`. Comparing a merge with each parent is deliberately conservative: when `head`
contains a merge *from* the base branch, content that came from the base side can be reported again. That can
block, but never hides anything. Choose a reviewed baseline (below) to avoid re-reporting old content.
A shallow clone is refused.

**Secret policy:** gitleaks runs with its built-in rules only, and only ever on text the scanner hands it on
stdin. The scanned repository's `.gitleaks.toml`, `.gitleaksignore` and inline `gitleaks:allow` comments are
ignored, and because stdin input carries no file path, the default policy's path exclusions (lockfiles,
images, `node_modules`, files named like `gitleaks.toml`, ...) cannot hide a secret. Path-only rules (which
match a file name rather than content) therefore do not fire; key and credential file names are covered by
the scanner's own file-name check. If gitleaks exits with anything other than 0 or the findings code, is
killed, or logs an error or skipped input, the scan is treated as incomplete (exit 2).

**Archives:** archives are not unpacked. `tree` mode blocks archives (`.zip`, `.tar`, `.tgz`, `.gz`, `.7z`,
`.jar`, `.whl`, ...) in a deploy payload because their contents would go unscanned. In `staged`/`range` mode
an archive's bytes are scanned as text, which does not reach compressed content.

**Exit codes:** `0` clean, `1` findings (blocked), `2` scanner error (also blocks). Unreadable files,
git errors (including git exiting non-zero after partial output), a malformed diff, a missing gitleaks or perl
and bad arguments exit `2`; nothing is ever reported clean after an error.

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

`tests/run-tests.sh` (bash, git, perl, gitleaks). CI runs them on Linux and macOS. Fixture setup fails fast:
an error while building a fixture aborts the suite with exit 2 instead of counting as a pass.
