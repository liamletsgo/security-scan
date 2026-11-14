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
inline `gitleaks:allow` comments are ignored. gitleaks never reads the repository: the scanner writes each
*unit* (a file in `tree` mode; the lines one commit adds to one file otherwise) into a private folder, named
only by file-type class (`.php`, `.tf`, `.yaml`, `nuget.config`, otherwise `.txt`), and gitleaks scans two
folders:

1. **Each unit as it is.** This is exactly what gitleaks alone would scan for that unit, so the scan finds at
   least everything gitleaks itself finds there, with the same context.
2. **Guarded windows.** Each copy starts with a 1 KB text guard and holds at most 98,000 bytes of the unit,
   overlapping the previous window by 49,000 bytes. They close three gitleaks blind spots:
   - gitleaks skips input whose first bytes look like a binary file type (PDF, archives, executables, fonts,
     Office files), logging that only at debug level; the guard stops that;
   - gitleaks cuts long input at about 125 KB with no overlap; a window stays under its 100 KB buffer, so it is
     never cut, and any span up to 49,000 bytes lies wholly inside one window;
   - a unit up to 98,000 bytes is one window, scanned whole with full context however it starts.
   The scan fails (exit 2) unless gitleaks reports exactly the bytes written for the windows. The only file-type
   matcher that can still reach past the guard, ISO-9660 at byte 32,769, therefore causes an error, never a
   silent pass.

Class names keep the four content rules gitleaks applies only to matching paths (Freemius/PHP, Terraform/HCL,
Kubernetes Secret YAML, nuget.config), while the default policy's path exclusions (lockfiles, images,
`node_modules`, `vendor/...`, files named like `gitleaks.toml`) never match. The one path-only rule
(`.p12`/`.pfx` files) is covered by the scanner's own key-file check.

**Byte coverage is not detection completeness.** The byte check proves every byte of every window reached
gitleaks; it cannot prove that every rule would match. Limits that remain:
- a rule whose evidence is spread over more than 49,000 bytes of a unit larger than 98,000 bytes is only found
  where gitleaks' own scan of that unit (run 1) happens to keep the evidence together;
- in `staged`/`range` mode only added lines are units, so evidence split between changed and unchanged lines
  can be missed there (the `tree` scan of the payload sees whole files);
- detection is only as good as gitleaks 8.30.1's rules.

Any gitleaks error, warning about failures, non-zero exit other than the findings code, or death by signal
exits 2.

## Archives and binary files

Archives are not unpacked. `tree` mode blocks them by name (`.zip`, `.tar`, `.gz`, `.7z`, `.jar`, `.whl`,
`.gem`, `.docx`, `.pptx`, ...) and by content: a zip, gzip, bzip2, xz, 7z, rar, zstd, cab or tar signature
*anywhere* in a file, or any 512-byte block whose tar header checksum is valid (pre-POSIX tar has no signature).
A deploy payload is code and configuration, so `tree` mode also blocks any file containing a NUL byte: binary
files are opaque to the text checks. In `staged`/`range` mode an archive's bytes are scanned as text, which does
not reach compressed content; spreadsheets are blocked by the data-file check.

## Risky-pattern checks

The risky-pattern checks run over the whole added text (or, in `tree` mode, the files), so a statement split
across lines is still matched, and common spacing variants are covered (`credentials.Certificate (...)`,
`allow get, list: if true`). They are tripwires for known dangerous constructs, not a parser: unusual
constructions (string concatenation, indirection) can avoid them, and file-name checks cannot prove that an
arbitrary text file holds no client data.

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
still scans them.

**The caller is trusted.** `PATH`, `GITLEAKS`, `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE` and bash/perl startup
settings all control what runs and which repository is read (hooks rely on some of them). The work-tree root
check confirms the current folder is the work tree being scanned; it does not bind an arbitrary `GIT_DIR` to
it. Run the scanner from a clean, known environment (in CI: a fresh runner).

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

## Firebase deploy helpers (`firebase/`)

Used by keyless Firebase Functions (Python) deploy workflows, downloaded at the same pinned commit as the scanner
and verified by SHA-256 each:

- `payload.js` copies the exact files `firebase deploy --only functions` uploads, using the installed
  firebase-tools' own lister and ignore list. It requires the pinned CLI version, refuses `predeploy`/`prebuild`
  hooks and `additionalSources`, and fails if `.git`, `venv` or `node_modules` would be uploaded.
- `discover.sh` produces the functions manifest (`functions.yaml`) the way firebase-tools does, by running the
  app's Python SDK server. Run it only where no cloud credentials exist, on a throwaway copy.
- `manifest-check.js` accepts a manifest only if it fits a strict profile (gcfv2 HTTPS endpoints only; no public
  invoker, secrets, service-account override, parameters, extra APIs or Data Connect triggers, whose schema files
  Firebase would upload outside the scanned payload) and equals the reviewed copy in the repository. With
  `functions.yaml` in the source folder, firebase-tools reads it instead of running the app, so the credentialed
  deploy step never executes application code.
- `containment.sh` runs after a deploy: it fails unless the function's Cloud Run service has no public invoker
  and an anonymous request is refused (401/403).
- `package.json` / `package-lock.json` pin firebase-tools 15.18.0 and its whole dependency tree with integrity
  hashes; install with `npm ci --ignore-scripts`.

`firebase/test.sh` checks the lister against firebase-tools' own packaging on a fixture project and exercises the
manifest profile (CI job "firebase helpers").

## Reusable deploy workflow (`.github/workflows/firebase-deploy.yml`)

A Firebase Functions (Python) backend calls it with
`uses: liamletsgo/security-scan/.github/workflows/firebase-deploy.yml@main`, passing only the environment chosen for a
manual run and the baseline. Every policy decision is made inside the workflow: each calling repository has a fixed
profile here (target projects, environment files, function, region, tests, reviewed manifest path, runtime account),
and the event, branch and actor decide whether and where to deploy (production only by a manual run on `main`). One
tools commit is resolved per run and used by every job; the run summary records it with the target and payload hash.
Jobs: plan → scan (range scan + mandatory tests) → discover (runs the app once on a throwaway copy, no cloud access) →
build (manifest checked against the committed reviewed copy and the profile's runtime account; exact payload; tree
scan) → deploy (the only job that can request a Google token; runs no repository code or Python; branch-tip check;
containment check). A baseline is the owner's statement of the last deployed commit; an empty range still gets the
full payload scan. A red run after the deploy step means the new version may be live: read the run summary.

Bind deploy credentials to it in each project's Workload Identity provider condition, for example:

```
assertion.repository == 'OWNER/BACKEND' && assertion.actor == 'OWNER' &&
assertion.ref in ['refs/heads/main', 'refs/heads/DEV_BRANCH'] &&
assertion.job_workflow_ref == 'liamletsgo/security-scan/.github/workflows/firebase-deploy.yml@refs/heads/main'
```

Google then issues deploy credentials only to this reviewed workflow from this repository's protected `main`,
whatever the backend repository's own workflow file says: a useful control where the backend repository cannot have
branch protection (private repositories on GitHub Free).

## Tests

`tests/run-tests.sh` (bash, git, perl, gitleaks). CI runs them on Linux and on macOS with the system
`/bin/bash` 3.2. Fixture setup fails fast: an error while building a fixture aborts the suite with exit 2
instead of counting as a pass. Key regressions assert the expected diagnostic as well as the exit code, and
each safeguard has at least one test that fails without it (checked by mutation).
