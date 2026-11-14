# security-scan

A small, fail-closed scanner for pre-commit hooks, pre-push hooks and CI.

```
security-scan.sh staged                 # staged changes (pre-commit)
security-scan.sh range <base> <head>    # what <head> adds relative to <base> (pre-push, CI)
security-scan.sh tree <dir>             # the files of a directory as they are (deploy payload)
```

Run `staged` and `range` from the root of the repository's work tree (checked against
`git rev-parse --show-toplevel`). Requires bash 3.2+, git 2.31+, perl 5.10+ and gitleaks 8.30.1.

**Checks:** secrets (gitleaks, required), credential/key files, `.env` files with secret-like values
(every version in a range, including `export` and spaced assignments; `.env.example`, `.env.sample` and
`.env.template` are skipped), client data files (spreadsheets, exports, dumps), submodules (gitlinks), and
risky code patterns (public storage objects, open Firebase rules, service-account key loading, secrets exposed
via `NEXT_PUBLIC_`, personal deploy tokens, install-script hooks). In a deploy payload (`tree`), symlinks, git
metadata (`.git`) and archives are blocked too.

## What is scanned

- **staged / range:** the lines a change *adds*. The scanner runs git itself and checks its exit status:
  text diffs (`--text`, no textconv or external diff drivers), no rename or copy detection (a renamed file is
  scanned in full, so content moved from a `.md` file into code is checked), merges compared with each parent
  (`--diff-merges=separate`), root commits shown, replace refs disabled, grafted repositories refused, and the
  git settings that change this output pinned on the command line. A strict patch parser uses each hunk's line
  counts; anything it cannot account for, or a truncated hunk, is an error.
- **tree:** every regular file is read directly, including binary files.
- **Not scanned:** unchanged context. Detection that needs lines a change did not touch (a multi-line secret
  only partly edited) can be missed in `staged`/`range` mode; the `tree` scan of the deploy payload covers whole
  files. Mode-only changes have no content. Submodule contents are not scanned, which is why gitlinks block.

Removing a secret is not blocked by the secret scan (only added lines count). Name-based checks still apply:
a change that touches a key file or a `.env` file with secret-like values blocks while such a file remains.

## Secret policy and completeness

gitleaks runs with its built-in rules only; the scanned repository's `.gitleaks.toml`, `.gitleaksignore` and
inline `gitleaks:allow` comments are ignored. gitleaks never reads the repository: the scanner writes the
content to scan as small pieces in a private folder and gitleaks scans that folder.

- Each piece holds at most 24 KB of content, overlapping the previous piece by 8 KB, so any match up to 8 KB long
  lies wholly inside one piece. gitleaks only splits input above 100 KB, so it never cuts a piece.
- Each piece starts with a 1 KB text guard. gitleaks skips input whose first bytes look like a binary file
  type (PDF, archives, executables, fonts, Office files; up to byte 32,773 for ISO images), so without the guard
  a file starting with such bytes would go unscanned. With the guard and pieces under 32,773 bytes, no file-type
  signature can match.
- Pieces are named by file-type class only (`.php`, `.tf`, `.yaml`, `nuget.config`, otherwise `.txt`). The four
  content rules that gitleaks applies only to matching paths (Freemius/PHP, Terraform/HCL, Kubernetes Secret
  YAML, nuget.config) therefore still run, while path exclusions in the default policy (lockfiles, images,
  `node_modules`, `vendor/...`, files named like `gitleaks.toml`) can never match. The one path-only rule
  (`.p12`/`.pfx` files) is covered by the scanner's own key-file check.
- The scan fails (exit 2) unless gitleaks reports exactly the number of bytes the scanner wrote, so a skipped
  piece cannot pass silently. Any gitleaks error, warning about skipped input, non-zero exit other than the
  findings code, or death by signal also exits 2.

## Archives

Archives are not unpacked. `tree` mode blocks them by name (`.zip`, `.tar`, `.gz`, `.7z`, `.jar`, `.whl`,
`.gem`, `.docx`, `.pptx`, ...) and by content (zip, gzip, bzip2, xz, 7z, rar, zstd and tar signatures), because
their contents would go unscanned. In `staged`/`range` mode an archive's bytes are scanned as text, which does
not reach compressed content; spreadsheets are blocked by the data-file check.

## Range semantics

Every commit in `base..head` is scanned (merges against each parent), plus the net diff from
`merge-base(base, head)` to `head`. The net diff never attributes base-branch changes to `head`. Comparing a
merge with each parent is deliberately conservative: when `head` contains a merge *from* the base branch,
content from the base side can be reported again. That can block, but never hides anything. A shallow clone is
refused. Range arguments are resolved to commit IDs once, so every step scans the same objects.

A reviewed baseline (the last deployed commit) keeps old content from being reported again; everything before
the baseline is then outside the range, so keep scanning the full deploy payload with `tree`.

## Exit codes and environment

`0` clean, `1` findings (blocked), `2` scanner error (also blocks). Unreadable files or directories, git
errors (including git exiting non-zero after partial output, and failed lookups that could otherwise look like
an absent file), a malformed diff, an incomplete gitleaks scan, a missing gitleaks or perl and bad arguments
exit `2`.

Set by the caller: `SCAN_ALLOW_DATA_FILES=true` turns data-file findings into warnings (synthetic fixtures);
`GITLEAKS` sets the gitleaks binary. Markdown files are excluded from the risky-pattern check only; gitleaks
still scans them. `GIT_DIR`, `GIT_INDEX_FILE` and similar variables are honoured as git defines them (hooks
use them); the work-tree root check confirms which checkout is scanned.

## Using it in CI

- Download it by **exact commit SHA** (never a branch) into `$RUNNER_TEMP`, verify its SHA-256 against a
  value reviewed into your workflow, and run it from the repository root. Treat a download failure or
  checksum mismatch as a failed check.
- Install a pinned, checksum-verified gitleaks release first.
- Check out with `fetch-depth: 0`.
- Ranges: `pull_request` → the PR base and head; `push` → `before..after` (a new branch has no `before`: use an
  explicit reviewed baseline); `workflow_dispatch` → an explicit reviewed baseline such as the last deployed
  commit. Also run `tree` over the exact, fully assembled payload you deploy, before cloud credentials exist.
- Scan in a job without secrets for pull requests from forks.

## Tests

`tests/run-tests.sh` (bash, git, perl, gitleaks). CI runs them on Linux and on macOS with the system
`/bin/bash` 3.2. Fixture setup fails fast: an error while building a fixture aborts the suite with exit 2
instead of counting as a pass. Key regressions assert the expected diagnostic as well as the exit code.
