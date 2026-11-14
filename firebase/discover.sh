#!/usr/bin/env bash
# Prints the functions manifest the Firebase Python SDK serves for a source folder, the same way firebase-tools
# discovers it (serving.py with ADMIN_PORT, GET /__/functions.yaml). It runs the application's Python, so run it
# only where no cloud credentials exist, on a disposable copy of the source.
# Usage: discover.sh <source dir with venv/> <project id>   (environment from <source dir>/.env is loaded)
set -euo pipefail
SRC=$1; PROJECT=$2; PORT=${ADMIN_PORT_FOR_DISCOVERY:-8765}
cd "$SRC"
[ -x venv/bin/python ] || { echo "discover: no venv in $SRC" >&2; exit 2; }
SERVING=$(venv/bin/python -c 'import firebase_functions, os; print(os.path.join(os.path.dirname(firebase_functions.__file__), "private", "serving.py"))')
LOG=$(mktemp)
(
  if [ -f .env ]; then set -a; . ./.env; set +a; fi
  unset GOOGLE_APPLICATION_CREDENTIALS CLOUDSDK_AUTH_ACCESS_TOKEN_FILE ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN
  export GCLOUD_PROJECT="$PROJECT" FIREBASE_CONFIG="{\"projectId\":\"$PROJECT\"}" ADMIN_PORT="$PORT"
  exec venv/bin/python "$SERVING"
) >"$LOG" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; rm -f "$LOG"' EXIT
for _ in $(seq 1 60); do
  if OUT=$(curl -sf "http://127.0.0.1:$PORT/__/functions.yaml"); then
    curl -sf "http://127.0.0.1:$PORT/__/quitquitquit" >/dev/null 2>&1 || true
    printf '%s\n' "$OUT"; exit 0
  fi
  kill -0 "$PID" 2>/dev/null || { cat "$LOG" >&2; echo "discover: serving.py exited" >&2; exit 2; }
  sleep 0.5
done
cat "$LOG" >&2; echo "discover: no manifest after 30 s" >&2; exit 2
