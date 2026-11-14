# security-scan

A small, fail-closed scanner for pre-commit hooks, pre-push hooks and CI.

```
security-scan.sh staged                 # staged changes (pre-commit)
security-scan.sh range <base> <head>    # every commit in base..head plus the net diff (pre-push, CI)
security-scan.sh tree [dir]             # files in a directory as they are (release/deploy folder)
```

Checks: secrets (gitleaks, required), credential/key files, `.env` files with secret-like values,
client data files (spreadsheets, exports, dumps) and risky code patterns (public storage objects,
open Firebase rules, service-account key loading, secrets exposed via `NEXT_PUBLIC_`, personal deploy
tokens, install-script hooks).

Exit codes: `0` clean, `1` findings (blocked), `2` scanner error (also blocks — never reported as clean).

Environment: `SCAN_ALLOW_DATA_FILES=true` turns data-file findings into warnings (synthetic fixtures);
`GITLEAKS` sets the gitleaks binary. Markdown files are excluded from the risky-pattern check only.

## Using it in CI

Download it by **exact commit SHA** (never a branch), verify its SHA-256 against a value reviewed into
your workflow, and run it from outside the deploy folder. Install a pinned gitleaks release first.
Treat a download failure or checksum mismatch as a failed check.

## Tests

`tests/run-tests.sh` (needs bash, git and gitleaks).
